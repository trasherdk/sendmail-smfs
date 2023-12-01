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
#include <grp.h>
#include <libmilter/mfapi.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "smf-config.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL		0
#endif

#define DELAY_SMTP_GREET	1
#define CHECK_RBL		1
#define REJECT_HELO		1
#define REJECT_BOUNCES		1
#define REJECT_UNDISCLOSED	1
#define REJECT_HARMFUL		1

#define MAXLINE			128
#define SMTP_GREET_PAUSE	28 /* seconds */
#define MAX_MESSAGE_SIZE	262144 /* bytes */
#define UNDISCLOSED		"(undisclosed-recipient|unlisted-recipient)"
#define BOGUS_HELO		"([0-9]+\\.[0-9]+\\.[0-9]+|[0-9]+-[0-9]+-[0-9]+|[0-9]{8}|^localhost$)"
#define HARMFUL			"^(Content-Disposition:.*;)?[ 	]*filename=\"?.*\\.(pif|exe|com|scr|lnk|cpl|vbs|hta|bat)\"?$"
#define WORK_SPACE		"/var/smfs"
#define OCONN			"unix:" WORK_SPACE "/smf-zombie.sock"
#define USER			"smfs"

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
static const char *fake_helo = FAKE_HELO;
static const char *bogus_helo = BOGUS_HELO;
static const char *undisclosed = UNDISCLOSED;
static const char *harmful = HARMFUL;
static regex_t re_ignore_connect, re_fake_helo, re_bogus_helo, re_undisclosed, re_harmful;

struct context {
    char addr[64];
    char fqdn[MAXLINE];
    char helo[MAXLINE];
    char from[MAXLINE];
    char rcpt[MAXLINE];
    char buf[2048];
    unsigned int pos;
    unsigned long body_size;
    unsigned long address;
    int hdr_to;
    int hdr_cc;
};

static sfsistat smf_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat smf_helo(SMFICTX *, char *);
static sfsistat smf_envfrom(SMFICTX *, char **);
static sfsistat smf_envrcpt(SMFICTX *, char **);
static sfsistat smf_header(SMFICTX *, char *, char *);
static sfsistat smf_eoh(SMFICTX *);
static sfsistat smf_body(SMFICTX *, u_char *, size_t);
static sfsistat smf_close(SMFICTX *);

static void strscpy(register char *dst, register const char *src, size_t size) {
    register size_t i;

    for (i = 0; i < size && (dst[i] = src[i]) != 0; i++) continue;
    dst[i] = '\0';
}

static int check_rbl(struct context *context, const char *rbl) {
    char lookup_name[64];
    struct addrinfo *ai = NULL;

    snprintf(lookup_name, sizeof(lookup_name), "%lu.%lu.%lu.%lu.%s.",
	(context->address & 0x000000ff) >> 0,
	(context->address & 0x0000ff00) >> 8,
	(context->address & 0x00ff0000) >> 16,
	(context->address & 0xff000000) >> 24,
	rbl);
    if (getaddrinfo(lookup_name, NULL, NULL, &ai)) {
	if (ai) freeaddrinfo(ai);
	return 0;
    }
    freeaddrinfo(ai);
    return 1;
}

static void do_sleep(int sec) {
    struct timespec req, rem;

    req.tv_sec = sec;
    req.tv_nsec = 0;
    nanosleep(&req, &rem);
}

static sfsistat smf_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa) {
    struct context *context = NULL;
    unsigned long address = 0;
    char host[64];

    strscpy(host, "undefined", sizeof(host) - 1);
    switch (sa->sa_family) {
	case AF_INET: {
	    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	    inet_ntop(AF_INET, &sin->sin_addr.s_addr, host, sizeof(host));
	    address = ntohl(sin->sin_addr.s_addr);
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
    context->address = address;
    strscpy(context->addr, host, sizeof(context->addr) - 1);
    strscpy(context->fqdn, name, sizeof(context->fqdn) - 1);
    if (DELAY_SMTP_GREET) {
	const char *interface = smfi_getsymval(ctx, "{if_addr}");

	if (interface && strcmp(interface, context->addr) == 0) return SMFIS_CONTINUE;
	do_sleep(SMTP_GREET_PAUSE);
    }
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

    if (msg_size && atol(msg_size) > MAX_MESSAGE_SIZE) return SMFIS_ACCEPT;
    if (smfi_getsymval(ctx, "{auth_authen}")) return SMFIS_ACCEPT;
    if (verify && strcmp(verify, "OK") == 0) return SMFIS_ACCEPT;
    if (*args) strscpy(context->from, *args, sizeof(context->from) - 1);
    if (REJECT_HELO && context->helo[0] != '[' && bogus_helo[0] && !regexec(&re_bogus_helo, context->helo, 0, NULL, 0)) {
	syslog(LOG_NOTICE, "malformed HELO: %s, %s, %s", context->helo, context->fqdn, context->from);
	smfi_setreply(ctx, "550", "5.7.1", "Unwanted contents of the HELO command");
	return SMFIS_REJECT;
    }
    if (REJECT_HELO && fake_helo[0] && !regexec(&re_fake_helo, context->helo, 0, NULL, 0)) {
	syslog(LOG_NOTICE, "malformed HELO: %s, %s, %s", context->helo, context->fqdn, context->from);
	smfi_setreply(ctx, "550", "5.7.1", "Unwanted contents of the HELO command");
	return SMFIS_REJECT;
    }
    if (CHECK_RBL && check_rbl(context, "cbl.abuseat.org")) {
	char reject[MAXLINE];

	syslog(LOG_NOTICE, "CBL: %s, %s, %s", context->addr, context->fqdn, context->from);
	snprintf(reject, sizeof(reject), "Blocked, look at http://cbl.abuseat.org/lookup.cgi?ip=%s", context->addr);
	smfi_setreply(ctx, "550", "5.7.1", reject);
	return SMFIS_REJECT;
    }
    context->hdr_to = 0;
    context->hdr_cc = 0;
    return SMFIS_CONTINUE;
}

static sfsistat smf_envrcpt(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (*args) strscpy(context->rcpt, *args, sizeof(context->rcpt) - 1);
    return SMFIS_CONTINUE;
}

static sfsistat smf_header(SMFICTX *ctx, char *name, char *value) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (!strcasecmp(name, "To")) {
	if (REJECT_UNDISCLOSED && undisclosed[0] && !regexec(&re_undisclosed, value, 0, NULL, 0)) {
	    syslog(LOG_NOTICE, "undisclosed recipients: %s, %s -> %s", context->fqdn, context->from, context->rcpt);
	    smfi_setreply(ctx, "554", "5.7.1", "Message for undisclosed recipients");
	    return SMFIS_REJECT;
	}
	context->hdr_to = 1;
    }
    if (!strcasecmp(name, "CC")) context->hdr_cc = 1;
    return SMFIS_CONTINUE;
}

static sfsistat smf_eoh(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (REJECT_BOUNCES && strstr(context->from, "<>")) {
	syslog(LOG_NOTICE, "bounce message: %s, %s -> %s", context->fqdn, context->from, context->rcpt);
	smfi_setreply(ctx, "554", "5.7.1", "Rejected due to the reasons of our security policy");
	return SMFIS_REJECT;
    }
    if (REJECT_UNDISCLOSED && !context->hdr_to && !context->hdr_cc) {
	syslog(LOG_NOTICE, "To: and CC: are not filled: %s, %s -> %s", context->fqdn, context->from, context->rcpt);
	smfi_setreply(ctx, "554", "5.7.1", "To: and CC: are not filled");
	return SMFIS_REJECT;
    }
    if (!REJECT_HARMFUL) return SMFIS_ACCEPT;
    memset(context->buf, 0, sizeof(context->buf));
    context->pos = 0;
    context->body_size = 0;
    return SMFIS_CONTINUE;
}

static sfsistat smf_body(SMFICTX *ctx, u_char *chunk, size_t size) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    context->body_size += size;
    if (context->body_size > MAX_MESSAGE_SIZE) return SMFIS_ACCEPT;
    for (; size > 0; size--, chunk++) {
	context->buf[context->pos] = *chunk;
	if (context->buf[context->pos] == '\n' || context->pos == sizeof(context->buf) - 1) {
	    if (context->pos > 0 && context->buf[context->pos - 1] == '\r')
		context->buf[context->pos - 1] = 0;
	    else
		context->buf[context->pos] = 0;
	    context->pos = 0;
	    if (harmful[0] && !regexec(&re_harmful, context->buf, 0, NULL, 0)) {
		syslog(LOG_NOTICE, "harmful attachment: %s, %s -> %s", context->fqdn, context->from, context->rcpt);
		smfi_setreply(ctx, "554", "5.7.1", "Executable attachments are not allowed. Compress it and retry once again");
		return SMFIS_REJECT;
	    }
	}
	else
	    context->pos++;
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
    "smf-zombie",
    SMFI_VERSION,
    0,
    smf_connect,
    smf_helo,
    smf_envfrom,
    smf_envrcpt,
    smf_header,
    smf_eoh,
    smf_body,
    NULL,
    NULL,
    smf_close
};

int main(int argc, char **argv) {
    const char *oconn = OCONN;
    const char *user = USER;
    const char *ofile = NULL;
    int ret = 0;

    regcomp(&re_ignore_connect, ignore_connect, REG_EXTENDED|REG_ICASE);
    regcomp(&re_fake_helo, fake_helo, REG_EXTENDED|REG_ICASE);
    regcomp(&re_bogus_helo, bogus_helo, REG_EXTENDED|REG_ICASE);
    regcomp(&re_undisclosed, undisclosed, REG_EXTENDED|REG_ICASE);
    regcomp(&re_harmful, harmful, REG_EXTENDED|REG_ICASE);
    tzset();
    openlog("smf-zombie", LOG_PID|LOG_NDELAY, SYSLOG_FACILITY);
    if (!strncmp(oconn, "unix:", 5))
	ofile = oconn + 5;
    else
	if (!strncmp(oconn, "local:", 6)) ofile = oconn + 6;
    if (ofile) unlink(ofile);
    if (!getuid()) {
	struct passwd *pw;

	if ((pw = getpwnam(user)) == NULL) {
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
    ret = smfi_main();
    if (ret != MI_SUCCESS) syslog(LOG_ERR, "[ERROR] terminated due to a fatal error");
done:
    return ret;
}
