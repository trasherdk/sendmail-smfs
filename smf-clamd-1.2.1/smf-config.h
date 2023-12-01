/* Copyright (C) 2005, 2006 by Eugene Kurmanin <me@kurmanin.info> */

/* Correct these parameters according to your needs.
 * Do not remove the leading '#' symbols.
 */

/* Hosts/Networks whitelist (extended regex format) */
#define WHITE_LIST	"^127\\.0\\.0\\.1$"

/* Maximal message size */
#define MAX_SIZE	262144 /* bytes */

/* ClamAV daemon listen here (Local socket mode) */
#define UNIX_SOCKET	1 /* set 0 for disable */
#define UNIX_PATH	"/var/clamav/clamav.sock" /* LocalSocket from your ClamAV clamd.conf */

/* ClamAV daemon listen here (TCP socket mode) */
#define CLAMD_PORT	3310
#define CLAMD_ADDRESS	"127.0.0.1"

/* Syslog facility */
#define SYSLOG_FACILITY	LOG_LOCAL7
