/* Copyright (C) 2005, 2006 by Eugene Kurmanin <me@kurmanin.info>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _REENTRANT
#error Compile with -D_REENTRANT flag
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libmilter/mfapi.h>
#include <netinet/in.h>
#include <pwd.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "smf-config.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0
#endif

#define MAXLINE		128
#define ADD_HEADER	1
#define PASS_ON_ERROR	0
#define CLAMD_TIMEOUT	55

#define WORK_SPACE	"/var/smfs"
#define OCONN		"unix:" WORK_SPACE "/smf-clamd.sock"
#define USER		"smfs"

#ifdef __sun__
int daemon(int nochdir, int noclose) {
    pid_t pid;
    int fd = 0;

    if ((pid = fork()) < 0) {
	fprintf(stderr, "fork: %s\n", strerror(errno));
	return 1;
    }
    else
	if (pid > 0) _exit(0);
    if ((pid = setsid()) == -1) {
	fprintf(stderr, "setsid: %s\n", strerror(errno));
	return 1;
    }
    if ((pid = fork()) < 0) {
	fprintf(stderr, "fork: %s\n", strerror(errno));
	return 1;
    }
    else
	if (pid > 0) _exit(0);
    if (!nochdir && chdir("/")) {
	fprintf(stderr, "chdir: %s\n", strerror(errno));
	return 1;
    }
    if (!noclose) {
	dup2(fd, fileno(stdout));
	dup2(fd, fileno(stderr));
	dup2(open("/dev/null", O_RDONLY, 0), fileno(stdin));
    }
    return 0;
}
#endif

static const char *ignore_connect = WHITE_LIST;
static regex_t re_ignore_connect;

struct context {
    char fqdn[MAXLINE];
    char from[MAXLINE];
    char rcpt[MAXLINE];
    char virus[MAXLINE];
    struct timeval tstart;
    struct timeval tend;
    int sock;
    int streamsock;
    unsigned long body_size;
};

static sfsistat smf_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat smf_envfrom(SMFICTX *, char **);
static sfsistat smf_envrcpt(SMFICTX *, char **);
static sfsistat smf_header(SMFICTX *, char *, char *);
static sfsistat smf_eoh(SMFICTX *);
static sfsistat smf_body(SMFICTX *, u_char *, size_t);
static sfsistat smf_eom(SMFICTX *);
static sfsistat smf_abort(SMFICTX *);
static sfsistat smf_close(SMFICTX *);

static void strscpy(register char *dst, register const char *src, size_t size) {
    register size_t i;

    for (i = 0; i < size && (dst[i] = src[i]) != 0; i++) continue;
    dst[i] = '\0';
}

static void close_socket(int sock) {
    int ret;

    if (sock < 0) return;
    shutdown(sock, SHUT_RDWR);
    do {
	ret = close(sock);
    } while (ret < 0 && errno == EINTR);
}

static int block_socket(int sock, int block) {
    int flags;

    if (sock < 0) return -1;
    if ((flags = fcntl(sock, F_GETFL)) < 0) return -1;
    if (block)
	flags &= ~O_NONBLOCK;
    else
	flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0) return -1;
    return 0;
}

static int clamd_connect(int sock, struct sockaddr *address, int addrlen) {
    int optval, ret;
    fd_set wfds;
    struct timeval tv;
    socklen_t optlen = sizeof(optval);

    if (sock < 0) return -1;
    if (block_socket(sock, 0) < 0) return -1;
    if ((ret = connect(sock, address, addrlen)) < 0)
	if (errno != EINPROGRESS) return -1;
    if (ret == 0) goto done;
    do {
	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);
	tv.tv_sec = CLAMD_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, NULL, &wfds, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &wfds)) return -1;
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0) return -1;
    if (optval) return -1;
done:
    if (block_socket(sock, 1) < 0) return -1;
    return 0;
}

static int clamd_send(int sock, const char *buffer, size_t size) {
    int ret;
    fd_set wfds;
    struct timeval tv;

    if (sock < 0) return -1;
    do {
	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);
	tv.tv_sec = CLAMD_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, NULL, &wfds, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &wfds)) return -1;
    do {
	ret = send(sock, buffer, size, MSG_NOSIGNAL);
    } while (ret < 0 && errno == EINTR);
    if (ret < size) return -1;
    return 0;
}

static int clamd_recv(int sock, char *buffer, size_t size) {
    int ret;
    fd_set rfds;
    struct timeval tv;

    if (sock < 0) return -1;
    do {
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tv.tv_sec = CLAMD_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, &rfds, NULL, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &rfds)) return -1;
    do {
	ret = recv(sock, buffer, size - 1, MSG_NOSIGNAL);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    return 0;
}

static sfsistat smf_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa) {
    struct context *context = NULL;
    char host[64];

    strscpy(host, "undefined", sizeof(host) - 1);
    switch (sa->sa_family) {
	case AF_INET: {
	    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	    inet_ntop(AF_INET, &sin->sin_addr.s_addr, host, sizeof(host));
	    break;
	}
	case AF_INET6: {
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

	    inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
	    break;
	}
    }
    if (ignore_connect[0] && !regexec(&re_ignore_connect, host, 0, NULL, 0)) return SMFIS_ACCEPT;
    if (!(context = calloc(1, sizeof(*context)))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	return SMFIS_ACCEPT;
    }
    smfi_setpriv(ctx, context);
    context->sock = -1;
    context->streamsock = -1;
    strscpy(context->fqdn, name, sizeof(context->fqdn) - 1);
    return SMFIS_CONTINUE;
}

static sfsistat smf_envfrom(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    const char *msg_size = smfi_getsymval(ctx, "{msg_size}");

    if (msg_size && atol(msg_size) > MAX_SIZE) return SMFIS_ACCEPT;
    if (*args) strscpy(context->from, *args, sizeof(context->from) - 1);
    return SMFIS_CONTINUE;
}

static sfsistat smf_envrcpt(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (*args) strscpy(context->rcpt, *args, sizeof(context->rcpt) - 1);
    return SMFIS_CONTINUE;
}

static int get_clamd_control(struct context *context) {
    struct sockaddr_in address, streamaddress;
    struct sockaddr_un unixaddress;
    char buffer[MAXLINE];
    int sock, streamsock;
    int optval = 1;
    socklen_t optlen = sizeof(optval);
    unsigned int port;

    if (UNIX_SOCKET) {
	memset(&unixaddress, 0, sizeof(unixaddress));
	strscpy(unixaddress.sun_path, UNIX_PATH, sizeof(unixaddress.sun_path) - 1);
	unixaddress.sun_family = AF_UNIX;
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
    }
    else {
	memset(&address, 0, sizeof(address));
	address.sin_addr.s_addr = inet_addr(CLAMD_ADDRESS);
	address.sin_family = AF_INET;
	address.sin_port = htons(CLAMD_PORT);
	sock = socket(AF_INET, SOCK_STREAM, 0);
    }
    if (sock < 0) return -1;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) goto quit_fail;
    if (UNIX_SOCKET) {
        if (clamd_connect(sock, (struct sockaddr *) &unixaddress, sizeof(unixaddress)) < 0) goto quit_fail;
    }
    else
        if (clamd_connect(sock, (struct sockaddr *) &address, sizeof(address)) < 0) goto quit_fail;
    strscpy(buffer, "STREAM\r\n", sizeof(buffer) - 1);
    if (clamd_send(sock, buffer, strlen(buffer)) < 0) goto quit_fail;
    memset(&buffer, 0, sizeof(buffer));
    if (clamd_recv(sock, buffer, sizeof(buffer)) < 0) goto quit_fail;
    if (sscanf(buffer, "PORT %u", &port) == 0) goto quit_fail;
    memset(&streamaddress, 0, sizeof(streamaddress));
    streamaddress.sin_addr.s_addr = inet_addr(CLAMD_ADDRESS);
    streamaddress.sin_family = AF_INET;
    streamaddress.sin_port = htons(port);
    streamsock = socket(AF_INET, SOCK_STREAM, 0);
    if (streamsock < 0) goto quit_fail;
    if (setsockopt(streamsock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
	close_socket(streamsock);
	goto quit_fail;
    }
    if (clamd_connect(streamsock, (struct sockaddr *) &streamaddress, sizeof(streamaddress)) < 0) {
	close_socket(streamsock);
	goto quit_fail;
    }
    context->sock = sock;
    context->streamsock = streamsock;
    return 0;
quit_fail:
    close_socket(sock);
    return -1;
}

static sfsistat smf_header(SMFICTX *ctx, char *name, char *value) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    char *buffer = NULL;

    if (context->sock < 0 && get_clamd_control(context) < 0) {
	syslog(LOG_ERR, "[ERROR] ClamAV is out of service (connect failed)");
	if (PASS_ON_ERROR)
	    return SMFIS_ACCEPT;
	else {
	    smfi_setreply(ctx, "451", "4.3.2", "AV system is not available now, try again later");
	    return SMFIS_TEMPFAIL;
	}
    }
    if (!(buffer = calloc(1, 2048))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	smf_abort(ctx);
	if (PASS_ON_ERROR)
	    return SMFIS_ACCEPT;
	else {
	    smfi_setreply(ctx, "451", "4.3.2", "AV system is not available now, try again later");
	    return SMFIS_TEMPFAIL;
	}
    }
    snprintf(buffer, 2048, "%s: %s\r\n", name, value);
    if (clamd_send(context->streamsock, buffer, strlen(buffer)) < 0) {
	syslog(LOG_ERR, "[ERROR] ClamAV is out of service (headers transfer failed)");
	free(buffer);
	smf_abort(ctx);
	if (PASS_ON_ERROR)
	    return SMFIS_ACCEPT;
	else {
	    smfi_setreply(ctx, "451", "4.3.2", "AV system is not available now, try again later");
	    return SMFIS_TEMPFAIL;
	}
    }
    free(buffer);
    return SMFIS_CONTINUE;
}

static sfsistat smf_eoh(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    char cmd[4];

    strscpy(cmd, "\r\n", 2);
    if (clamd_send(context->streamsock, cmd, strlen(cmd)) < 0) {
	syslog(LOG_ERR, "[ERROR] ClamAV is out of service (end of headers transfer failed)");
	smf_abort(ctx);
	if (PASS_ON_ERROR)
	    return SMFIS_ACCEPT;
	else {
	    smfi_setreply(ctx, "451", "4.3.2", "AV system is not available now, try again later");
	    return SMFIS_TEMPFAIL;
	}
    }
    context->body_size = 0;
    return SMFIS_CONTINUE;
}

static sfsistat smf_body(SMFICTX *ctx, u_char *chunk, size_t size) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    context->body_size += size;
    if (context->body_size > MAX_SIZE) {
	smf_abort(ctx);
	return SMFIS_ACCEPT;
    }
    if (clamd_send(context->streamsock, chunk, size) < 0) {
	syslog(LOG_ERR, "[ERROR] ClamAV is out of service (body transfer failed)");
	smf_abort(ctx);
	if (PASS_ON_ERROR)
	    return SMFIS_ACCEPT;
	else {
	    smfi_setreply(ctx, "451", "4.3.2", "AV system is not available now, try again later");
	    return SMFIS_TEMPFAIL;
	}
    }
    return SMFIS_CONTINUE;
}

static int get_clamd_reply(struct context *context) {
    char buffer[MAXLINE];
    char *p = NULL;

    close_socket(context->streamsock);
    context->streamsock = -1;
    memset(&buffer, 0, sizeof(buffer));
    gettimeofday(&context->tstart, NULL);
    if (clamd_recv(context->sock, buffer, sizeof(buffer)) < 0) goto quit_fail;
    gettimeofday(&context->tend, NULL);
    if (strstr(buffer, "stream: ")) {
	close_socket(context->sock);
	context->sock = -1;
	if (strstr(buffer, "stream: OK\n")) return 0;
	if ((p = strstr(buffer, " FOUND\n"))) {
	    *p = '\0';
	    strscpy(context->virus, buffer + 8, sizeof(context->virus) - 1);
	    return 1;
	}
	return -1;
    }
quit_fail:
    close_socket(context->sock);
    context->sock = -1;
    return -1;
}

static sfsistat smf_eom(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    float elapsed;
    int ret;

    ret = get_clamd_reply(context);
    if (ret < 0) {
	syslog(LOG_ERR, "[ERROR] ClamAV is out of service (answer is not received)");
	if (PASS_ON_ERROR)
	    return SMFIS_ACCEPT;
	else {
	    smfi_setreply(ctx, "451", "4.3.2", "AV system is not available now, try again later");
	    return SMFIS_TEMPFAIL;
	}
    }
    elapsed = context->tend.tv_sec - context->tstart.tv_sec + (context->tend.tv_usec - context->tstart.tv_usec) / 1.0e6;
    if (ret == 1) {
	char reject[MAXLINE];

	syslog(LOG_NOTICE, "%s, %.3fsec, %s, %s -> %s", context->virus, elapsed, context->fqdn, context->from, context->rcpt);
	snprintf(reject, sizeof(reject), "Virus %s detected by the ClamAV AntiVirus", context->virus);
	smfi_setreply(ctx, "554", "5.7.1", reject);
	return SMFIS_REJECT;
    }
    if (ADD_HEADER) {
	char header[2 * MAXLINE];
	const char *site = NULL, *interface = NULL;

	if (!(site = smfi_getsymval(ctx, "j"))) site = "localhost";
	if (!(interface = smfi_getsymval(ctx, "{if_addr}"))) interface = "127.0.0.1";
	snprintf(header, sizeof(header), "checked in %.3fsec at %s ([%s])\n\tby smf-clamd v1.2.1 - http://smfs.sf.net/", elapsed, site, interface);
	smfi_addheader(ctx, "X-Antivirus", header);
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_abort(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (context->streamsock != -1) {
	close_socket(context->streamsock);
	context->streamsock = -1;
    }
    if (context->sock != -1) {
	close_socket(context->sock);
	context->sock = -1;
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_close(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (context) {
	free(context);
	smfi_setpriv(ctx, NULL);
    }
    return SMFIS_CONTINUE;
}

struct smfiDesc smfilter = {
    "smf-clamd",
    SMFI_VERSION,
    SMFIF_ADDHDRS,
    smf_connect,
    NULL,
    smf_envfrom,
    smf_envrcpt,
    smf_header,
    smf_eoh,
    smf_body,
    smf_eom,
    smf_abort,
    smf_close
};

int main(int argc, char **argv) {
    const char *oconn = OCONN;
    const char *user = USER;
    const char *ofile = NULL;
    int ret = 0;

    regcomp(&re_ignore_connect, ignore_connect, REG_EXTENDED|REG_ICASE);
    tzset();
    openlog("smf-clamd", LOG_PID|LOG_NDELAY, SYSLOG_FACILITY);
    if (!strncmp(oconn, "unix:", 5))
	ofile = oconn + 5;
    else
	if (!strncmp(oconn, "local:", 6)) ofile = oconn + 6;
    if (ofile) unlink(ofile);
    if (!getuid()) {
	struct passwd *pw;

	if (!(pw = getpwnam(user))) {
	    fprintf(stderr, "%s: %s\n", user, strerror(errno));
	    return 1;
	}
	setgroups(1, &pw->pw_gid);
	if (setgid(pw->pw_gid)) {
	    fprintf(stderr, "setgid: %s\n", strerror(errno));
	    return 1;
	}
	if (setuid(pw->pw_uid)) {
	    fprintf(stderr, "setuid: %s\n", strerror(errno));
	    return 1;
	}
    }
    if (smfi_setconn((char *)oconn) != MI_SUCCESS) {
	fprintf(stderr, "smfi_setconn failed: %s\n", oconn);
	goto done;
    }
    if (smfi_register(smfilter) != MI_SUCCESS) {
	fprintf(stderr, "smfi_register failed\n");
	goto done;
    }
    if (daemon(0, 0)) {
	fprintf(stderr, "daemonize failed: %s\n", strerror(errno));
	goto done;
    }
    umask(0177);
    signal(SIGPIPE, SIG_IGN);
    ret = smfi_main();
    if (ret != MI_SUCCESS) syslog(LOG_ERR, "[ERROR] terminated due to a fatal error");
done:
    return ret;
}

