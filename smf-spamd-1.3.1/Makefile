CC = gcc
INSTALL = install -c
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
DATADIR = /var/smfs
CFLAGS = -O2 -D_REENTRANT

# Linux
LDFLAGS = -lmilter -lpthread

# FreeBSD
#LDFLAGS = -lmilter -pthread

# Solaris
#LDFLAGS = -lmilter -lpthread -lsocket -lnsl -lresolv

# Sendmail v8.11
#LDFLAGS += -lsmutil

all: smf-spamd

smf-spamd: smf-spamd.o
	$(CC) -o smf-spamd smf-spamd.o $(LDFLAGS)
	strip smf-spamd

smf-spamd.o: smf-spamd.c
	$(CC) $(CFLAGS) -c smf-spamd.c

clean:
	rm -f smf-spamd.o smf-spamd

install:
	./install.sh
	$(INSTALL) -m 755 smf-spamd $(SBINDIR)
	@if test ! -d $(DATADIR); then \
	mkdir -m 700 $(DATADIR); \
	chown smfs:smfs $(DATADIR); \
	fi

