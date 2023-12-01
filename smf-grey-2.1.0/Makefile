CC = gcc
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
DATADIR = /var/run/smfs
DUMPDIR = /var/smf-grey
CONFDIR = /etc/mail/smfs
USER = smfs
GROUP = smfs
CFLAGS = -O2 -D_REENTRANT -fomit-frame-pointer -I/usr/local/include

# Linux
LDFLAGS = -lmilter -lpthread -L/usr/local/lib

# FreeBSD
#LDFLAGS = -lmilter -pthread -L/usr/local/lib

# Solaris
#LDFLAGS = -lmilter -lpthread -lsocket -lnsl -lresolv

# Sendmail v8.11
#LDFLAGS += -lsmutil

all: smf-grey

smf-grey: smf-grey.o
	$(CC) -o smf-grey smf-grey.o $(LDFLAGS)
	strip smf-grey

smf-grey.o: smf-grey.c
	$(CC) $(CFLAGS) -c smf-grey.c

clean:
	rm -f smf-grey.o smf-grey

install:
	@./install.sh
	@cp -f -p smf-grey $(SBINDIR)
	@if test ! -d $(DATADIR); then \
	mkdir -m 700 $(DATADIR); \
	chown $(USER):$(GROUP) $(DATADIR); \
	fi
	@if test ! -d $(DUMPDIR); then \
	mkdir -m 700 $(DUMPDIR); \
	chown $(USER):$(GROUP) $(DUMPDIR); \
	fi
	@if test ! -d $(CONFDIR); then \
	mkdir -m 755 $(CONFDIR); \
	fi
	@if test ! -f $(CONFDIR)/smf-grey.conf; then \
	cp -p smf-grey.conf $(CONFDIR)/smf-grey.conf; \
	else \
	cp -p smf-grey.conf $(CONFDIR)/smf-grey.conf.new; \
	fi
	@echo Please, inspect and edit the $(CONFDIR)/smf-grey.conf file.

