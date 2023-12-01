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

all: smf-clamd

smf-clamd: smf-clamd.o
	$(CC) -o smf-clamd smf-clamd.o $(LDFLAGS)
	strip smf-clamd

smf-clamd.o: smf-clamd.c
	$(CC) $(CFLAGS) -c smf-clamd.c

clean:
	rm -f smf-clamd.o smf-clamd

install:
	./install.sh
	$(INSTALL) -m 755 smf-clamd $(SBINDIR)
	@if test ! -d $(DATADIR); then \
	mkdir -m 700 $(DATADIR); \
	chown smfs:smfs $(DATADIR); \
	fi

