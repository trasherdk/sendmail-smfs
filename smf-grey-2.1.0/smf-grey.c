/*  Copyright (C) 2005-2007 by Eugene Kurmanin <me@kurmanin.info>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _REENTRANT
#error Compile with -D_REENTRANT flag
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#ifndef __sun__
#include <getopt.h>
#endif
#include <grp.h>
#include <libmilter/mfapi.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define CONFIG_FILE		"/etc/mail/smfs/smf-grey.conf"
#define WORK_SPACE		"/var/run/smfs"
#define DUMP_FILE		"/var/smf-grey/smf-grey.data"
#define OCONN			"unix:" WORK_SPACE "/smf-grey.sock"
#define USER			"smfs"
#define SYSLOG_FACILITY		LOG_MAIL
#define RECONFIG_TIME		10
#define DUMP_TIME		900
#define GREY_TIME		1500
#define GREY_TIMEOUT		43200
#define GREY_WHITELIST		604800
#define DUMP_BUFFER		1048576
#define ADD_HEADER		1

#define MAXLINE			128
#define HASH_POWER		16
#define FACILITIES_AMOUNT	10
#define IPV4_DOT_DECIMAL	"^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}$"

#define SAFE_FREE(x)		if (x) { free(x); x = NULL; }

#define hash_size(x)		((unsigned long) 1 << x)
#define hash_mask(x)		(hash_size(x) - 1)

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

typedef enum cache_put_mode {
    CACHE_KEEP = 0,
    CACHE_OVER
} cache_put_mode;

typedef enum cache_item_status {
    ST_NONE = 0,
    ST_GREY,
    ST_WHITE
} cache_item_status;

typedef struct cache_item {
    char *item;
    unsigned long hash;
    cache_item_status status;
    time_t exptime;
    struct cache_item *next;
} cache_item;

typedef struct dump_item {
    char *item;
    time_t exptime;
    struct dump_item *next;
} dump_item;

typedef struct CIDR {
    unsigned long ip;
    unsigned short int mask;
    struct CIDR *next;
} CIDR;

typedef struct STR {
    char *str;
    struct STR *next;
} STR;

typedef struct config {
    char *dump_file;
    char *run_as_user;
    char *sendmail_socket;
    CIDR *cidrs;
    STR *ptrs;
    STR *froms;
    STR *tos;
    int add_header;
    int syslog_facility;
    unsigned long dump_time;
    unsigned long grey_time;
    unsigned long grey_timeout;
    unsigned long grey_whitelist;
} config;

typedef struct facilities {
    char *name;
    int facility;
} facilities;

struct context {
    char addr[64];
    char fqdn[MAXLINE];
    char interface[16];
    char site[MAXLINE];
    char from[MAXLINE];
    char sender[MAXLINE];
    char rcpt[MAXLINE];
    char recipient[MAXLINE];
    char key[2 * MAXLINE];
    char hdr[3 * MAXLINE];
    STR *hdrs;
};

static regex_t re_ipv4;
static int dump_stale = 0;
static cache_item **cache = NULL;
static const char *config_file = CONFIG_FILE;
static config conf;
static pthread_mutex_t config_mutex, cache_mutex;
static facilities syslog_facilities[] = {
    { "daemon", LOG_DAEMON },
    { "mail", LOG_MAIL },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 }
};

static sfsistat smf_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat smf_envfrom(SMFICTX *, char **);
static sfsistat smf_envrcpt(SMFICTX *, char **);
static sfsistat smf_eoh(SMFICTX *);
static sfsistat smf_eom(SMFICTX *);
static sfsistat smf_close(SMFICTX *);

static void strscpy(register char *dst, register const char *src, size_t size) {
    register size_t i;

    for (i = 0; i < size && (dst[i] = src[i]) != 0; i++) continue;
    dst[i] = '\0';
}

static void strtolower(register char *str) {

    for (; *str; str++)
	if (isascii(*str) && isupper(*str)) *str = tolower(*str);
}

static void time_humanize(register char *dst, time_t tm) {
    register int h, m, s;

    h = tm / 3600;
    tm = tm % 3600;
    m = tm / 60;
    tm = tm % 60;
    s = tm;
    snprintf(dst, 10, "%02d:%02d:%02d", h, m, s);
}

static unsigned long translate(char *value) {
    unsigned long unit;
    size_t len = strlen(value);

    switch (value[len - 1]) {
	case 'm':
	case 'M':
	    unit = 60;
	    value[len - 1] = '\0';
	    break;
	case 'h':
	case 'H':
	    unit = 3600;
	    value[len - 1] = '\0';
	    break;
	case 'd':
	case 'D':
	    unit = 86400;
	    value[len - 1] = '\0';
	    break;
	default:
	    return atol(value);
    }
    return (atol(value) * unit);
}

static unsigned long hash_code(register const unsigned char *key) {
    register unsigned long hash = 0;
    register size_t i, len = strlen(key);

    for (i = 0; i < len; i++) {
	hash += key[i];
	hash += (hash << 10);
	hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static int cache_init(void) {

    if (!(cache = calloc(1, hash_size(HASH_POWER) * sizeof(void *)))) return 0;
    return 1;
}

static void cache_destroy(void) {
    unsigned long i, size = hash_size(HASH_POWER);
    cache_item *it, *it_next;

    for (i = 0; i < size; i++) {
	it = cache[i];
	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->item);
	    SAFE_FREE(it);
	    it = it_next;
	}
    }
    SAFE_FREE(cache);
}

static cache_item_status cache_get(const char *key, time_t *exptime) {
    unsigned long hash = hash_code(key);
    cache_item *it = cache[hash & hash_mask(HASH_POWER)];
    time_t curtime = time(NULL);

    while (it) {
	if (it->hash == hash && it->exptime > curtime && it->item && !strcmp(key, it->item)) {
	    *exptime = it->exptime;
	    return it->status;
	}
	it = it->next;
    }
    return ST_NONE;
}

static void cache_put(const char *key, unsigned long ttl, cache_item_status status, cache_put_mode mode) {
    unsigned long hash = hash_code(key);
    time_t curtime = time(NULL);
    cache_item *it, *parent = NULL;

    it = cache[hash & hash_mask(HASH_POWER)];
    while (it) {
	if (it->hash == hash && it->exptime > curtime && it->item && !strcmp(key, it->item)) {
	    if (mode == CACHE_OVER) {
		it->status = status;
		it->exptime = curtime + ttl;
	    }
	    return;
	}
	it = it->next;
    }
    it = cache[hash & hash_mask(HASH_POWER)];
    while (it) {
	if (it->exptime < curtime) {
	    SAFE_FREE(it->item);
	    it->item = strdup(key);
	    it->hash = hash;
	    it->status = status;
	    it->exptime = curtime + ttl;
	    return;
	}
	parent = it;
	it = it->next;
    }
    if ((it = (cache_item *) calloc(1, sizeof(cache_item)))) {
	it->item = strdup(key);
	it->hash = hash;
	it->status = status;
	it->exptime = curtime + ttl;
	if (parent)
	    parent->next = it;
	else
	    cache[hash & hash_mask(HASH_POWER)] = it;
    }
}

static void clear_whitelists(void) {

    if (conf.cidrs) {
	CIDR *it = conf.cidrs, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it);
	    it = it_next;
	}
	conf.cidrs = NULL;
    }
    if (conf.ptrs) {
	STR *it = conf.ptrs, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    SAFE_FREE(it);
	    it = it_next;
	}
	conf.ptrs = NULL;
    }
    if (conf.froms) {
	STR *it = conf.froms, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    SAFE_FREE(it);
	    it = it_next;
	}
	conf.froms = NULL;
    }
    if (conf.tos) {
	STR *it = conf.tos, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    SAFE_FREE(it);
	    it = it_next;
	}
	conf.tos = NULL;
    }
}

static void free_config(void) {

    clear_whitelists();
    SAFE_FREE(conf.dump_file);
    SAFE_FREE(conf.run_as_user);
    SAFE_FREE(conf.sendmail_socket);
}

static int load_config(void) {
    FILE *fp;
    char buf[2 * MAXLINE], key[MAXLINE], val[MAXLINE], *p = NULL;

    conf.dump_file = strdup(DUMP_FILE);
    conf.run_as_user = strdup(USER);
    conf.sendmail_socket = strdup(OCONN);
    conf.syslog_facility = SYSLOG_FACILITY;
    conf.add_header = ADD_HEADER;
    conf.grey_time = GREY_TIME;
    conf.grey_timeout = GREY_TIMEOUT;
    conf.grey_whitelist = GREY_WHITELIST;
    conf.dump_time = DUMP_TIME;
    if (!(fp = fopen(config_file, "r"))) return 0;
    while (fgets(buf, sizeof(buf) - 1, fp)) {
	if ((p = strchr(buf, '#'))) *p = '\0';
	if (!(strlen(buf))) continue;
	if (sscanf(buf, "%127s %127s", key, val) != 2) continue;
	if (!strcasecmp(key, "whitelistip")) {
	    char *slash = NULL;
	    unsigned short int mask = 32;

	    if ((slash = strchr(val, '/'))) {
		*slash = '\0';
		if ((mask = atoi(++slash)) > 32) mask = 32;
	    }
	    if (val[0] && !regexec(&re_ipv4, val, 0, NULL, 0)) {
		CIDR *it = NULL;
		unsigned long ip;

		if ((ip = inet_addr(val)) == 0xffffffff) continue;
		if (!conf.cidrs)
		    conf.cidrs = (CIDR *) calloc(1, sizeof(CIDR));
		else
		    if ((it = (CIDR *) calloc(1, sizeof(CIDR)))) {
			it->next = conf.cidrs;
			conf.cidrs = it;
		    }
		if (conf.cidrs) {
		    conf.cidrs->ip = ip;
		    conf.cidrs->mask = mask;
		}
	    }
	    continue;
	}
	if (!strcasecmp(key, "whitelistptr")) {
	    STR *it = NULL;

	    if (!conf.ptrs)
		conf.ptrs = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.ptrs;
		    conf.ptrs = it;
		}
	    if (conf.ptrs && !conf.ptrs->str) conf.ptrs->str = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "whitelistfrom")) {
	    STR *it = NULL;

	    if (!conf.froms)
		conf.froms = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.froms;
		    conf.froms = it;
		}
	    if (conf.froms && !conf.froms->str) {
		strtolower(val);
		conf.froms->str = strdup(val);
	    }
	    continue;
	}
	if (!strcasecmp(key, "whitelistto")) {
	    STR *it = NULL;

	    if (!conf.tos)
		conf.tos = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.tos;
		    conf.tos = it;
		}
	    if (conf.tos && !conf.tos->str) {
		strtolower(val);
		conf.tos->str = strdup(val);
	    }
	    continue;
	}
	if (!strcasecmp(key, "addheader") && !strcasecmp(val, "off")) {
	    conf.add_header = 0;
	    continue;
	}
	if (!strcasecmp(key, "greytime")) {
	    conf.grey_time = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "greytimeout")) {
	    conf.grey_timeout = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "greywhitelist")) {
	    conf.grey_whitelist = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "dumptime")) {
	    conf.dump_time = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "dumpfile")) {
	    SAFE_FREE(conf.dump_file);
	    conf.dump_file = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "user")) {
	    SAFE_FREE(conf.run_as_user);
	    conf.run_as_user = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "socket")) {
	    SAFE_FREE(conf.sendmail_socket);
	    conf.sendmail_socket = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "syslog")) {
	    int i;

	    for (i = 0; i < FACILITIES_AMOUNT; i++)
		if (!strcasecmp(val, syslog_facilities[i].name))
		    conf.syslog_facility = syslog_facilities[i].facility;
	    continue;
	}
    }
    fclose(fp);
    return 1;
}

static int ip_cidr(const unsigned long ip, const short int mask, const unsigned long checkip) {
    unsigned long ipaddr = 0;
    unsigned long cidrip = 0;
    unsigned long subnet = 0;

    subnet = ~0;
    subnet = subnet << (32 - mask);
    cidrip = htonl(ip) & subnet;
    ipaddr = ntohl(checkip) & subnet;
    if (cidrip == ipaddr) return 1;
    return 0;
}

static int ip_check(const unsigned long checkip) {
    CIDR *it = conf.cidrs;

    while (it) {
	if (ip_cidr(it->ip, it->mask, checkip)) return 1;
	it = it->next;
    }
    return 0;
}

static int ptr_check(const char *ptr) {
    STR *it = conf.ptrs;

    while (it) {
	if (it->str && strlen(it->str) <= strlen(ptr) && !strcasecmp(ptr + strlen(ptr) - strlen(it->str), it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static int from_check(const char *from) {
    STR *it = conf.froms;

    while (it) {
	if (it->str && strstr(from, it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static int to_check(const char *to) {
    STR *it = conf.tos;

    while (it) {
	if (it->str && strstr(to, it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static void do_sleep(int sec) {
    struct timeval req;
    int ret = 0;

    req.tv_sec = sec;
    req.tv_usec = 0;
    do {
	ret = select(0, NULL, NULL, NULL, &req);
    } while (ret < 0 && errno == EINTR);
}

static void die(const char *reason) {

    syslog(LOG_ERR, "[ERROR] die: %s", reason);
    smfi_stop();
    do_sleep(60);
    abort();
}

static void mutex_lock(pthread_mutex_t *mutex) {

    if (pthread_mutex_lock(mutex)) die("pthread_mutex_lock");
}

static void mutex_unlock(pthread_mutex_t *mutex) {

    if (pthread_mutex_unlock(mutex)) die("pthread_mutex_unlock");
}

static int address_preparation(register char *dst, register const char *src) {
    register const char *start = NULL, *stop = NULL;
    int tail;

    if (!(start = strchr(src, '<'))) return 0;
    if (!(stop = strrchr(src, '>'))) return 0;
    if (++start >= --stop) return 0;
    strscpy(dst, start, stop - start + 1);
    tail = strlen(dst) - 1;
    if ((dst[0] >= 0x07 && dst[0] <= 0x0d) || dst[0] == 0x20) return 0;
    if ((dst[tail] >= 0x07 && dst[tail] <= 0x0d) || dst[tail] == 0x20) return 0;
    if (!strchr(dst, '@')) return 0;
    return 1;
}

static void build_key(struct context *context) {
    char subnet[16], *p = NULL;

    strscpy(subnet, context->addr, sizeof(subnet) - 1);
    if ((p = strrchr(subnet, '.'))) *p = '\0';
    if (!(p = strrchr(context->sender, '='))) p = context->sender;
    snprintf(context->key, sizeof(context->key), "%s|%s|%s", subnet, p, context->recipient);
}

static void add_hdr(struct context *context) {
    STR *it = NULL;

    if (!context->hdrs)
	context->hdrs = (STR *) calloc(1, sizeof(STR));
    else
	if ((it = (STR *) calloc(1, sizeof(STR)))) {
	    it->next = context->hdrs;
	    context->hdrs = it;
	}
    if (context->hdrs && !context->hdrs->str) context->hdrs->str = strdup(context->hdr);
}

static int greylist(struct context *context) {
    cache_item_status status;
    time_t curtime = time(NULL), cachetime;

    if (!cache) return 0;
    build_key(context);
    mutex_lock(&cache_mutex);
    status = cache_get(context->key, &cachetime);
    mutex_unlock(&cache_mutex);
    if (status == ST_NONE) {
	char human_time[10];

	time_humanize(human_time, conf.grey_time);
	syslog(LOG_NOTICE, "delay for %s, %s, %s, %s -> %s", human_time, context->addr, context->fqdn, context->from, context->rcpt);
	mutex_lock(&cache_mutex);
	cache_put(context->key, conf.grey_timeout, ST_GREY, CACHE_KEEP);
	mutex_unlock(&cache_mutex);
	return 1;
    }
    else if (status == ST_GREY) {
	char human_time[10];

	if (curtime - (cachetime - conf.grey_timeout) >= conf.grey_time) {
	    time_humanize(human_time, curtime - (cachetime - conf.grey_timeout));
	    syslog(LOG_NOTICE, "awl (delayed for %s), %s, %s, %s -> %s", human_time, context->addr, context->fqdn, context->from, context->rcpt);
	    mutex_lock(&cache_mutex);
	    cache_put(context->key, conf.grey_whitelist, ST_WHITE, CACHE_OVER);
	    dump_stale++;
	    mutex_unlock(&cache_mutex);
	    if (conf.add_header) {
		snprintf(context->hdr, sizeof(context->hdr), "delayed for %s at (%s [%s])\n\tfor %s by smf-grey v2.1.0 - http://smfs.sf.net/",
		    human_time, context->site, context->interface, context->rcpt);
		add_hdr(context);
	    }
	    return 0;
	}
	time_humanize(human_time, conf.grey_time - (curtime - (cachetime - conf.grey_timeout)));
	syslog(LOG_INFO, "delay for %s, %s, %s, %s -> %s", human_time, context->addr, context->fqdn, context->from, context->rcpt);
	return 1;
    }
    mutex_lock(&cache_mutex);
    cache_put(context->key, conf.grey_whitelist, ST_WHITE, CACHE_OVER);
    dump_stale++;
    mutex_unlock(&cache_mutex);
    return 0;
}

static int dump_load(void) {
    FILE *dump;
    char buf[3 * MAXLINE];
    char key[2 * MAXLINE];
    unsigned long val;
    time_t curtime;

    if (!(dump = fopen(conf.dump_file, "r"))) return 0;
    while (fgets(buf, sizeof(buf) - 1, dump)) {
	if (!(strlen(buf))) continue;
	if (sscanf(buf, "%255s %lu", key, &val) != 2) continue;
	if ((curtime = time(NULL)) < val) cache_put(key, val - curtime, ST_WHITE, CACHE_KEEP);
    }
    fclose(dump);
    return 1;
}

static void dump_perform(FILE *dump) {
    unsigned long i, size = hash_size(HASH_POWER);
    dump_item *dump_it, *dump_it_next, *dump_array = NULL;
    cache_item *it;
    time_t curtime = time(NULL);

    mutex_lock(&cache_mutex);
    for (i = 0; i < size; i++) {
	it = cache[i];
	while (it) {
	    if (it->exptime > curtime && it->status == ST_WHITE && it->item) {
		if (!dump_array)
		    dump_array = (dump_item *) calloc(1, sizeof(dump_item));
		else
		    if ((dump_it = (dump_item *) calloc(1, sizeof(dump_item)))) {
			dump_it->next = dump_array;
			dump_array = dump_it;
		    }
		if (dump_array && !dump_array->item) {
		    dump_array->item = strdup(it->item);
		    dump_array->exptime = it->exptime;
		}
	    }
	    it = it->next;
	}
    }
    dump_stale = 0;
    mutex_unlock(&cache_mutex);
    if ((dump_it = dump_array))
	while (dump_it) {
	    if (dump_it->item) fprintf(dump, "%s\t%lu\n", dump_it->item, (unsigned long) dump_it->exptime);
	    dump_it = dump_it->next;
	}
    if ((dump_it = dump_array))
	while (dump_it) {
	    dump_it_next = dump_it->next;
	    SAFE_FREE(dump_it->item);
	    SAFE_FREE(dump_it);
	    dump_it = dump_it_next;
	}
}

static int dump_save(void) {
    FILE *dump;
    char dump_file[MAXLINE];
    char *buffer = NULL;
    int dumpfd;

    snprintf(dump_file, sizeof(dump_file), "%s.XXXXXX", conf.dump_file);
    if ((dumpfd = mkstemp(dump_file)) == -1) return 0;
    if (!(dump = fdopen(dumpfd, "w"))) return 0;
    if ((buffer = calloc(1, DUMP_BUFFER + 1))) setvbuf(dump, buffer, _IOFBF, DUMP_BUFFER);
    dump_perform(dump);
    fclose(dump);
    SAFE_FREE(buffer);
    if (!rename(dump_file, conf.dump_file)) return 1;
    return 0;
}

static void *dumper(void *ptr) {

    for (;;) {
	do_sleep(conf.dump_time);
	if (!dump_stale) continue;
	if (!dump_save()) syslog(LOG_ERR, "[ERROR] dump save failed");
    }
    return NULL;
}

static int dumper_start(void) {
    pthread_attr_t attr;
    pthread_t tid;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (!pthread_create(&tid, &attr, dumper, NULL)) {
	pthread_attr_destroy(&attr);
	return 1;
    }
    pthread_attr_destroy(&attr);
    return 0;
}

static int reconfig_perform(void) {
    FILE *fp;
    char buf[2 * MAXLINE], key[MAXLINE], val[MAXLINE], *p = NULL;

    if (!(fp = fopen(config_file, "r"))) return 0;
    clear_whitelists();
    while (fgets(buf, sizeof(buf) - 1, fp)) {
	if ((p = strchr(buf, '#'))) *p = '\0';
	if (!(strlen(buf))) continue;
	if (sscanf(buf, "%127s %127s", key, val) != 2) continue;
	if (!strcasecmp(key, "whitelistip")) {
	    char *slash = NULL;
	    unsigned short int mask = 32;

	    if ((slash = strchr(val, '/'))) {
		*slash = '\0';
		if ((mask = atoi(++slash)) > 32) mask = 32;
	    }
	    if (val[0] && !regexec(&re_ipv4, val, 0, NULL, 0)) {
		CIDR *it = NULL;
		unsigned long ip;

		if ((ip = inet_addr(val)) == 0xffffffff) continue;
		if (!conf.cidrs)
		    conf.cidrs = (CIDR *) calloc(1, sizeof(CIDR));
		else
		    if ((it = (CIDR *) calloc(1, sizeof(CIDR)))) {
			it->next = conf.cidrs;
			conf.cidrs = it;
		    }
		if (conf.cidrs) {
		    conf.cidrs->ip = ip;
		    conf.cidrs->mask = mask;
		}
	    }
	    continue;
	}
	if (!strcasecmp(key, "whitelistptr")) {
	    STR *it = NULL;

	    if (!conf.ptrs)
		conf.ptrs = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.ptrs;
		    conf.ptrs = it;
		}
	    if (conf.ptrs && !conf.ptrs->str) conf.ptrs->str = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "whitelistfrom")) {
	    STR *it = NULL;

	    if (!conf.froms)
		conf.froms = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.froms;
		    conf.froms = it;
		}
	    if (conf.froms && !conf.froms->str) {
		strtolower(val);
		conf.froms->str = strdup(val);
	    }
	    continue;
	}
	if (!strcasecmp(key, "whitelistto")) {
	    STR *it = NULL;

	    if (!conf.tos)
		conf.tos = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.tos;
		    conf.tos = it;
		}
	    if (conf.tos && !conf.tos->str) {
		strtolower(val);
		conf.tos->str = strdup(val);
	    }
	    continue;
	}
    }
    fclose(fp);
    return 1;
}

static void *configurator(void *ptr) {
    struct stat stb;
    time_t last_mtime = 0;

    if (!stat(config_file, &stb)) last_mtime = stb.st_mtime;
    for (;;) {
	do_sleep(RECONFIG_TIME);
	if (!stat(config_file, &stb) && stb.st_mtime > last_mtime) {
	    last_mtime = stb.st_mtime;
	    mutex_lock(&config_mutex);
	    if (reconfig_perform()) syslog(LOG_NOTICE, "[INFO] whitelists were reloaded successfully");
	    mutex_unlock(&config_mutex);
	}
    }
    return NULL;
}

static int reconfig_start(void) {
    pthread_attr_t attr;
    pthread_t tid;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (!pthread_create(&tid, &attr, configurator, NULL)) {
	pthread_attr_destroy(&attr);
	return 1;
    }
    pthread_attr_destroy(&attr);
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
    mutex_lock(&config_mutex);
    if ((conf.cidrs && ip_check(inet_addr(host))) || (conf.ptrs && ptr_check(name))) {
	mutex_unlock(&config_mutex);
	return SMFIS_ACCEPT;
    }
    mutex_unlock(&config_mutex);
    if (!(context = calloc(1, sizeof(*context)))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	return SMFIS_ACCEPT;
    }
    smfi_setpriv(ctx, context);
    strscpy(context->addr, host, sizeof(context->addr) - 1);
    strscpy(context->fqdn, name, sizeof(context->fqdn) - 1);
    return SMFIS_CONTINUE;
}

static sfsistat smf_envfrom(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    const char *verify = smfi_getsymval(ctx, "{verify}");
    const char *site = NULL, *interface = NULL;

    if (smfi_getsymval(ctx, "{auth_authen}")) return SMFIS_ACCEPT;
    if (verify && strcmp(verify, "OK") == 0) return SMFIS_ACCEPT;
    if (*args) strscpy(context->from, *args, sizeof(context->from) - 1);
    if (strstr(context->from, "<>")) return SMFIS_ACCEPT;
    if (!address_preparation(context->sender, context->from)) {
	smfi_setreply(ctx, "550", "5.1.7", "Sender address does not conform to RFC-2821 syntax");
	return SMFIS_REJECT;
    }
    strtolower(context->sender);
    mutex_lock(&config_mutex);
    if (conf.froms && from_check(context->sender)) {
	mutex_unlock(&config_mutex);
	return SMFIS_ACCEPT;
    }
    mutex_unlock(&config_mutex);
    if (context->hdrs) {
	STR *it = context->hdrs, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    SAFE_FREE(it);
	    it = it_next;
	}
	context->hdrs = NULL;
    }
    if ((interface = smfi_getsymval(ctx, "{if_addr}")))
	strscpy(context->interface, interface, sizeof(context->interface) - 1);
    else
	strscpy(context->interface, "127.0.0.1", sizeof(context->interface) - 1);
    if ((site = smfi_getsymval(ctx, "j")))
	strscpy(context->site, site, sizeof(context->site) - 1);
    else
	strscpy(context->site, "localhost", sizeof(context->site) - 1);
    return SMFIS_CONTINUE;
}

static sfsistat smf_envrcpt(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (*args) strscpy(context->rcpt, *args, sizeof(context->rcpt) - 1);
    if (!address_preparation(context->recipient, context->rcpt)) {
	smfi_setreply(ctx, "550", "5.1.3", "Recipient address does not conform to RFC-2821 syntax");
	return SMFIS_REJECT;
    }
    strtolower(context->recipient);
    mutex_lock(&config_mutex);
    if (conf.tos && to_check(context->recipient)) {
	mutex_unlock(&config_mutex);
	return SMFIS_CONTINUE;
    }
    mutex_unlock(&config_mutex);
    if (greylist(context)) {
	do_sleep(1);
	smfi_setreply(ctx, "451", "4.2.1", "Mailbox busy, try again later");
	return SMFIS_TEMPFAIL;
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_eoh(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (!context->hdrs) return SMFIS_ACCEPT;
    return SMFIS_CONTINUE;
}

static sfsistat smf_eom(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (context->hdrs) {
	STR *it = context->hdrs;

	while (it) {
	    if (it->str) smfi_addheader(ctx, "X-Greylist", it->str);
	    it = it->next;
	}
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_close(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (context) {
	if (context->hdrs) {
	    STR *it = context->hdrs, *it_next;

	    while (it) {
		it_next = it->next;
		SAFE_FREE(it->str);
		SAFE_FREE(it);
		it = it_next;
	    }
	}
	free(context);
	smfi_setpriv(ctx, NULL);
    }
    return SMFIS_CONTINUE;
}

struct smfiDesc smfilter = {
    "smf-grey",
    SMFI_VERSION,
    SMFIF_ADDHDRS,
    smf_connect,
    NULL,
    smf_envfrom,
    smf_envrcpt,
    NULL,
    smf_eoh,
    NULL,
    smf_eom,
    NULL,
    smf_close
};

int main(int argc, char **argv) {
    const char *ofile = NULL;
    int ch, ret = 0;

    while ((ch = getopt(argc, argv, "hc:")) != -1) {
	switch (ch) {
	    case 'h':
		fprintf(stderr, "Usage: smf-grey -c <config file>\n");
		return 0;
	    case 'c':
		if (optarg) config_file = optarg;
		break;
	    default:
		break;
	}
    }
    memset(&conf, 0, sizeof(conf));
    regcomp(&re_ipv4, IPV4_DOT_DECIMAL, REG_EXTENDED|REG_ICASE);
    if (!load_config()) fprintf(stderr, "Warning: smf-grey configuration file load failed\n");
    tzset();
    openlog("smf-grey", LOG_PID|LOG_NDELAY, conf.syslog_facility);
    if (!strncmp(conf.sendmail_socket, "unix:", 5))
	ofile = conf.sendmail_socket + 5;
    else
	if (!strncmp(conf.sendmail_socket, "local:", 6)) ofile = conf.sendmail_socket + 6;
    if (ofile) unlink(ofile);
    if (!getuid()) {
	struct passwd *pw;

	if ((pw = getpwnam(conf.run_as_user)) == NULL) {
	    fprintf(stderr, "%s: %s\n", conf.run_as_user, strerror(errno));
	    goto done;
	}
	setgroups(1, &pw->pw_gid);
	if (setgid(pw->pw_gid)) {
	    fprintf(stderr, "setgid: %s\n", strerror(errno));
	    goto done;
	}
	if (setuid(pw->pw_uid)) {
	    fprintf(stderr, "setuid: %s\n", strerror(errno));
	    goto done;
	}
    }
    if (smfi_setconn((char *)conf.sendmail_socket) != MI_SUCCESS) {
	fprintf(stderr, "smfi_setconn failed: %s\n", conf.sendmail_socket);
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
    if (pthread_mutex_init(&config_mutex, 0)) {
	fprintf(stderr, "pthread_mutex_init failed\n");
	goto done;
    }
    if (pthread_mutex_init(&cache_mutex, 0)) {
	fprintf(stderr, "pthread_mutex_init failed\n");
	pthread_mutex_destroy(&config_mutex);
	goto done;
    }
    umask(0177);
    if (!cache_init()) syslog(LOG_ERR, "[ERROR] cache engine init failed");
    if (conf.dump_time && cache && !dump_load()) syslog(LOG_NOTICE, "[NOTICE] dump was not loaded");
    if (conf.dump_time && cache && !dumper_start()) syslog(LOG_ERR, "[ERROR] dumper engine init failed");
    if (!reconfig_start()) syslog(LOG_ERR, "[ERROR] reconfiguration engine init failed");
    ret = smfi_main();
    if (ret != MI_SUCCESS) syslog(LOG_ERR, "[ERROR] terminated due to a fatal error");
    if (conf.dump_time && dump_stale && cache && !dump_save()) syslog(LOG_ERR, "[ERROR] dump save failed");
    if (cache) cache_destroy();
    pthread_mutex_destroy(&config_mutex);
    pthread_mutex_destroy(&cache_mutex);
done:
    free_config();
    closelog();
    return ret;
}

