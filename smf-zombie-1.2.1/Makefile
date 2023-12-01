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

all: smf-zombie

smf-zombie: smf-zombie.o
	$(CC) -o smf-zombie smf-zombie.o $(LDFLAGS)
	strip smf-zombie

smf-zombie.o: smf-zombie.c
	$(CC) $(CFLAGS) -c smf-zombie.c

clean:
	rm -f smf-zombie.o smf-zombie

install:
	./install.sh
	$(INSTALL) -m 755 smf-zombie $(SBINDIR)
	@if test ! -d $(DATADIR); then \
	mkdir -m 700 $(DATADIR); \
	chown smfs:smfs $(DATADIR); \
	fi

