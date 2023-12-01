/* Copyright (C) 2005-2007 by Eugene Kurmanin <me@kurmanin.info>
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
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "smf-config.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0
#endif

#define MAXLINE		128
#define ADD_HEADER	1
#define SPAMD_TIMEOUT	50
#define SPAMD_RETRIES	10

#define WORK_SPACE	"/var/smfs"
#define OCONN		"unix:" WORK_SPACE "/smf-spamd.sock"
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
    char addr[64];
    char fqdn[MAXLINE];
    char site[MAXLINE];
    char helo[MAXLINE];
    char from[MAXLINE];
    char qid[16];
    char rcpt[MAXLINE];
    char *rcpts;
    char hdr_subject[2 * MAXLINE];
    time_t arrival;
    struct timeval tstart;
    struct timeval tend;
    int sock;
    int msg_id;
    int subject;
    unsigned long body_size;
    double score, threshold;
};

static sfsistat smf_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat smf_helo(SMFICTX *, char *);
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

static void strscat(register char *dst, register const char *src, size_t size) {
    register size_t i, j, o;

    o = strlen(dst);
    if (size < o + 1) return;
    size -= o + 1;
    for (i = 0, j = o; i < size && (dst[j] = src[i]) != 0; i++, j++) continue;
    dst[j] = '\0';
}

static int add_rcpt(struct context *context) {
    char *p = NULL;
    size_t i;

    if (!context->rcpts) {
	if (!(context->rcpts = calloc(1, strlen(context->rcpt) + 1))) return -1;
	strscpy(context->rcpts, context->rcpt, strlen(context->rcpt) + 1);
	return 0;
    }
    if (!(p = calloc(1, (i = strlen(context->rcpts) + strlen(context->rcpt) + 2)))) return -1;
    memcpy(p, context->rcpts, strlen(context->rcpts) + 1);
    free(context->rcpts);
    context->rcpts = p;
    strscat(context->rcpts, "|", i);
    strscat(context->rcpts, context->rcpt, i);
    return 0;
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

static int spamd_connect(int sock, struct sockaddr *address, int addrlen) {
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
	tv.tv_sec = SPAMD_TIMEOUT;
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

static int spamd_send(int sock, const char *buffer, size_t size) {
    int ret;
    fd_set wfds;
    struct timeval tv;

    if (sock < 0) return -1;
    do {
	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);
	tv.tv_sec = SPAMD_TIMEOUT;
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

static int spamd_recv(int sock, char *buffer, size_t size) {
    int ret;
    fd_set rfds;
    struct timeval tv;

    if (sock < 0) return -1;
    do {
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tv.tv_sec = SPAMD_TIMEOUT / SPAMD_RETRIES;
	tv.tv_usec = 0;
	ret = select(sock + 1, &rfds, NULL, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret == 0) return 0;
    if (ret < 0) return -1;
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
    context->rcpts = NULL;
    strscpy(context->addr, host, sizeof(context->addr) - 1);
    strscpy(context->fqdn, name, sizeof(context->fqdn) - 1);
    strscpy(context->helo, "undefined", sizeof(context->helo) - 1);
    return SMFIS_CONTINUE;
}

static sfsistat smf_helo(SMFICTX *ctx, char *arg) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    strscpy(context->helo, arg, sizeof(context->helo) - 1);
    return SMFIS_CONTINUE;
}

static sfsistat smf_envfrom(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    const char *msg_size = smfi_getsymval(ctx, "{msg_size}");
    const char *verify = smfi_getsymval(ctx, "{verify}");
    const char *site = NULL, *qid = NULL;

    if (smfi_getsymval(ctx, "{auth_authen}")) return SMFIS_ACCEPT;
    if (verify && strcmp(verify, "OK") == 0) return SMFIS_ACCEPT;
    if (msg_size && atol(msg_size) > MAX_SIZE) return SMFIS_ACCEPT;
    if (*args) strscpy(context->from, *args, sizeof(context->from) - 1);
    if ((site = smfi_getsymval(ctx, "j")))
	strscpy(context->site, site, sizeof(context->site) - 1);
    else
	strscpy(context->site, "localhost", sizeof(context->site) - 1);
    if ((qid = smfi_getsymval(ctx, "i")))
	strscpy(context->qid, qid, sizeof(context->qid) - 1);
    else
	strscpy(context->qid, "noqueue", sizeof(context->qid) - 1);
    context->arrival = time(NULL);
    context->msg_id = 0;
    context->subject = 0;
    if (context->rcpts) {
	free(context->rcpts);
	context->rcpts = NULL;
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_envrcpt(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (*args) strscpy(context->rcpt, *args, sizeof(context->rcpt) - 1);
    if (REDIRECT_SPAM && add_rcpt(context) < 0) syslog(LOG_ERR, "[ERROR] Recipients table memory allocation failure");
    return SMFIS_CONTINUE;
}

static int get_spamd_control(struct context *context) {
    struct sockaddr_in address;
    struct tm localtm;
    char cmd[512];
    char date[MAXLINE];
    int sock;
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = inet_addr(SPAMD_ADDRESS);
    address.sin_family = AF_INET;
    address.sin_port = htons(SPAMD_PORT);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) goto quit_fail;
    if (spamd_connect(sock, (struct sockaddr *) &address, sizeof(address)) < 0) goto quit_fail;
    strscpy(cmd, "CHECK SPAMC/1.2\r\n\r\n", sizeof(cmd) - 1);
    if (spamd_send(sock, cmd, strlen(cmd)) < 0) goto quit_fail;
    localtime_r((const time_t *) &context->arrival, &localtm);
    if (!strftime(date, sizeof(date), "%a, %e %b %Y %H:%M:%S %z", &localtm))
	strscpy(date, "", sizeof(date) - 1);
    snprintf(cmd, sizeof(cmd), "Return-Path: %s\r\nReceived: from %s (%s [%s])\r\n\tby %s (smf-spamd) with ESMTP id %s\r\n\tfor %s; %s\r\n",
	context->from, context->helo, context->fqdn, context->addr, context->site, context->qid, context->rcpt, date);
    if (spamd_send(sock, cmd, strlen(cmd)) < 0) goto quit_fail;
    context->sock = sock;
    return 0;
quit_fail:
    close_socket(sock);
    return -1;
}

static sfsistat smf_header(SMFICTX *ctx, char *name, char *value) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    char *buffer = NULL;

    if (context->sock < 0 && get_spamd_control(context) < 0) {
	syslog(LOG_ERR, "[ERROR] SpamAssassin is out of service (connect failed)");
	return SMFIS_ACCEPT;
    }
    if (!(buffer = calloc(1, 2048))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	smf_abort(ctx);
	return SMFIS_ACCEPT;
    }
    snprintf(buffer, 2048, "%s: %s\r\n", name, value);
    if (spamd_send(context->sock, buffer, strlen(buffer)) < 0) {
	syslog(LOG_ERR, "[ERROR] SpamAssassin is out of service (headers transfer failed)");
	free(buffer);
	smf_abort(ctx);
	return SMFIS_ACCEPT;
    }
    free(buffer);
    if (!strcasecmp(name, "Message-Id")) context->msg_id = 1;
    if (!strcasecmp(name, "Subject")) {
	context->subject = 1;
	strscpy(context->hdr_subject, value, sizeof(context->hdr_subject) - 1);
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_eoh(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    char cmd[MAXLINE];

    if (context->msg_id)
	strscpy(cmd, "\r\n", 2);
    else {
	struct tm gmtm;
	char date[16];

	gmtime_r((const time_t *) &context->arrival, &gmtm);
	if (!strftime(date, sizeof(date), "%Y%m%d%H%M", &gmtm))
	    strscpy(date, "200601011200", sizeof(date) - 1);
	snprintf(cmd, sizeof(cmd), "Message-Id: <%s.%s@%s>\r\n\r\n", date, context->qid, context->site);
    }
    if (spamd_send(context->sock, cmd, strlen(cmd)) < 0) {
	syslog(LOG_ERR, "[ERROR] SpamAssassin is out of service (end of headers transfer failed)");
	smf_abort(ctx);
	return SMFIS_ACCEPT;
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
    if (spamd_send(context->sock, chunk, size) < 0) {
	syslog(LOG_ERR, "[ERROR] SpamAssassin is out of service (body transfer failed)");
	smf_abort(ctx);
	return SMFIS_ACCEPT;
    }
    return SMFIS_CONTINUE;
}

static int get_spamd_reply(struct context *context) {
    char buffer[MAXLINE];
    char spam[6];
    int i = 0;
    double s, t;
    char *p = NULL;

    if (shutdown(context->sock, SHUT_WR) < 0) goto quit_fail;
    gettimeofday(&context->tstart, NULL);
    while (i++ < SPAMD_RETRIES) {
	memset(&buffer, 0, sizeof(buffer));
	if (spamd_recv(context->sock, buffer, sizeof(buffer)) < 0) goto quit_fail;
	if ((p = strstr(buffer, "Spam:")) && sscanf(p + 6, "%5s ; %lf / %lf", spam, &s, &t) == 3) {
	    gettimeofday(&context->tend, NULL);
	    close_socket(context->sock);
	    context->sock = -1;
	    context->score = s;
	    context->threshold = t;
	    if (strstr(spam, "True")) return 1;
	    return 0;
	}
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

    ret = get_spamd_reply(context);
    if (ret < 0) {
	syslog(LOG_ERR, "[ERROR] SpamAssassin is out of service (answer is not received)");
	return SMFIS_ACCEPT;
    }
    elapsed = context->tend.tv_sec - context->tstart.tv_sec + (context->tend.tv_usec - context->tstart.tv_usec) / 1.0e6;
    if (ret == 1) {
	if (context->score >= EXTRA_SPAM) {
	    char reject[MAXLINE];

	    syslog(LOG_NOTICE, "EXTRA SPAM (%.1f/%.1f), %.3fsec, %s, %s -> %s", context->score, context->threshold, elapsed, context->fqdn, context->from, context->rcpt);
	    snprintf(reject, sizeof(reject), "Sorry, looks like spam. Contact %s to resolve this issue", CONTACT_ADDRESS);
	    smfi_setreply(ctx, "554", "5.7.1", reject);
	    return SMFIS_REJECT;
	}
	if (REDIRECT_SPAM) {
	    if (context->rcpts) {
		char **bp = &context->rcpts;
		char *tok;

		while ((tok = strsep(bp, "|"))) {
		    smfi_delrcpt(ctx, tok);
		    smfi_addheader(ctx, "X-Original-To", tok);
		}
	    }
	    smfi_addrcpt(ctx, SPAM_BOX);
	}
	else
	    if (COPY_SPAM) smfi_addrcpt(ctx, SPAM_BOX);
	if (TAG_SUBJECT) {
	    char subject[2 * MAXLINE];

	    if (context->subject) {
		snprintf(subject, sizeof(subject), "[spam?] %s", context->hdr_subject);
		smfi_chgheader(ctx, "Subject", 1, subject);
	    }
	    else {
		strscpy(subject, "[spam?]", sizeof(subject) - 1);
		smfi_addheader(ctx, "Subject", subject);
	    }
	}
	if (ADD_HEADER) {
	    char header[2 * MAXLINE];
	    const char *interface = NULL;

	    if (!(interface = smfi_getsymval(ctx, "{if_addr}"))) interface = "127.0.0.1";
	    snprintf(header, sizeof(header), "Yes, score=%.1f/%.1f, scanned in %.3fsec at (%s [%s])\n\tby smf-spamd v1.3.1 - http://smfs.sf.net/",
		context->score, context->threshold, elapsed, context->site, interface);
	    smfi_addheader(ctx, "X-Antispam", header);
	}
	syslog(LOG_NOTICE, "SPAM (%.1f/%.1f), %.3fsec, %s, %s -> %s", context->score, context->threshold, elapsed, context->fqdn, context->from, context->rcpt);
	return SMFIS_CONTINUE;
    }
    if (ADD_HEADER) {
	char header[2 * MAXLINE];
	const char *interface = NULL;

	if (!(interface = smfi_getsymval(ctx, "{if_addr}"))) interface = "127.0.0.1";
	snprintf(header, sizeof(header), "No, score=%.1f/%.1f, scanned in %.3fsec at (%s [%s])\n\tby smf-spamd v1.3.1 - http://smfs.sf.net/",
	    context->score, context->threshold, elapsed, context->site, interface);
	smfi_addheader(ctx, "X-Antispam", header);
    }
    syslog(LOG_INFO, "ham (%.1f/%.1f), %.3fsec, %s, %s -> %s", context->score, context->threshold, elapsed, context->fqdn, context->from, context->rcpt);
    return SMFIS_CONTINUE;
}

static sfsistat smf_abort(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (context->sock != -1) {
	close_socket(context->sock);
	context->sock = -1;
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_close(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (context) {
	if (context->rcpts) free(context->rcpts);
	free(context);
	smfi_setpriv(ctx, NULL);
    }
    return SMFIS_CONTINUE;
}

struct smfiDesc smfilter = {
    "smf-spamd",
    SMFI_VERSION,
    SMFIF_ADDHDRS|SMFIF_CHGHDRS|SMFIF_ADDRCPT|SMFIF_DELRCPT,
    smf_connect,
    smf_helo,
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
    openlog("smf-spamd", LOG_PID|LOG_NDELAY, SYSLOG_FACILITY);
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
