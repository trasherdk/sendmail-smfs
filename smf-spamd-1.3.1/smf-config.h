/* Copyright (C) 2005-2007 by Eugene Kurmanin <me@kurmanin.info> */

/* Correct these parameters according to your needs.
 * Do not remove the leading '#' symbols.
 */

/* Hosts/Networks whitelist (extended regex format) */
#define WHITE_LIST	"(^127\\.|^192\\.168\\.|^10\\.)"

/* Maximal message size */
#define MAX_SIZE	131072 /* bytes */

/* Probable SPAM e-Mail messages Subject tagging */
#define TAG_SUBJECT	1 /* set 0 to disable */

/* Extra SPAM e-Mail messages */
#define EXTRA_SPAM	10 /* SpamAssassin SPAM score value */

/* Contact e-Mail address for rejected extra SPAM e-Mail messages */
#define CONTACT_ADDRESS	"notspam@yourdomain.tld" /* "all_spam_to" from your SpamAssassin local.cf */

/* Probable SPAM e-Mail messages quarantine */
#define REDIRECT_SPAM	0 /* set 1 to enable */

/* Probable SPAM e-Mail messages collector (if quarantine is not active) */
#define COPY_SPAM	0 /* set 1 to enable */

/* Quarantine/Collector mailbox */
#define SPAM_BOX	"spam@yourdomain.tld" /* should be corrected carefully */

/* SpamAssassin daemon listen here */
#define SPAMD_PORT	783
#define SPAMD_ADDRESS	"127.0.0.1"

/* Syslog facility */
#define SYSLOG_FACILITY	LOG_LOCAL3

