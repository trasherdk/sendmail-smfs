/* Copyright (C) 2005, 2006 by Eugene Kurmanin <me@kurmanin.info> */

/* Correct these parameters according to your needs.
 * Do not remove the leading '#' symbols.
 */

/* Hosts/Networks whitelist (extended regex format) */
#define WHITE_LIST	"(^127\\.0\\.0\\.1$|^192\\.168\\.[0-9]+\\.[0-9]+$)"

/* Your owned domain(s) (extended regex format) */
#define FAKE_HELO	"(^domain1\\.tld$|^domain2\\.tld$)"

/* Syslog facility */
#define SYSLOG_FACILITY	LOG_LOCAL1
