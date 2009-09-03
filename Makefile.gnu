# scamper Makefile for use with GNU make
# $Id: Makefile.gnu,v 1.79 2009/03/30 19:58:55 mjl Exp $

CFLAGS+=		-Wall
LDFLAGS+=		-Wall
OBJS=			scamper.o scamper_debug.o utils.o \
			scamper_tlv.o scamper_icmpext.o \
			scamper_do_ping.o scamper_ping.o \
			scamper_udp4.o scamper_udp6.o \
			scamper_icmp4.o scamper_icmp6.o scamper_icmp_resp.o \
			scamper_tcp4.o scamper_tcp6.o \
			scamper_ip6.o scamper_if.o \
			scamper_rtsock.o scamper_dl.o scamper_addr2mac.o \
			scamper_fds.o scamper_linepoll.o scamper_writebuf.o \
			scamper_privsep.o scamper_getsrc.o \
			mjl_list.o mjl_splaytree.o mjl_heap.o \
			scamper_control.o scamper_firewall.o \
			scamper_addr.o scamper_probe.o \
			scamper_target.o scamper_task.o scamper_queue.o \
			scamper_options.o scamper_sources.o \
			mper_base64.o mper_keywords.o mper_msg_reader.o

UNAME := $(shell uname)
ifeq ($(UNAME),SunOS)
			LDFLAGS+=	-lsocket -lnsl
endif

ifdef WITH_DEBUG
CFLAGS+=		-g
else
CFLAGS+=		-DNDEBUG
endif

ifdef WITHOUT_PRIVSEP
CFLAGS+=		-DWITHOUT_PRIVSEP
endif

ifdef WITHOUT_DEBUGFILE
CFLAGS+=		-DWITHOUT_DEBUGFILE
endif

# assumes that dmalloc library and includes are in the path already
ifdef WITH_DMALLOC
CFLAGS+=		-DDMALLOC
LDFLAGS+=		-ldmalloc
endif

ifdef WITH_UNIVERSAL
CFLAGS+=		-arch ppc -arch i386
LDFLAGS+=		-arch ppc -arch i386
AR=			libtool -o
endif

PROGS=			mper test-msg-reader test-msg-writer

all:			${PROGS}

mper:			${OBJS}
			${CC} -o mper ${LDFLAGS} ${OBJS} 

test-msg-reader:	mper_base64.o mper_keywords.o mper_msg_reader.o \
			test-msg-reader.o
			${CC} -o $@ ${LDFLAGS} mper_base64.o mper_keywords.o \
				mper_msg_reader.o test-msg-reader.o

test-msg-writer:	mper_base64.o mper_keywords.o mper_msg_reader.o \
			mper_msg_writer.o test-msg-writer.o
			${CC} -o $@ ${LDFLAGS} mper_base64.o mper_keywords.o \
				mper_msg_reader.o mper_msg_writer.o \
				test-msg-writer.o

mper_keywords.c:	mper_keywords.gperf
			gperf mper_keywords.gperf >mper_keywords.c

ifdef WITH_LISTDEBUG
mjl_list.o:		mjl_list.c mjl_list.h
			${CC} ${CFLAGS} -DMJLLIST_DEBUG -c mjl_list.c
endif

ifdef WITH_TREEDEBUG
mjl_splaytree.o:	mjl_splaytree.c mjl_splaytree.h
			${CC} ${CFLAGS} -DMJLSPLAYTREE_DEBUG -c mjl_splaytree.c
endif

ifdef WITH_HEAPDEBUG
mjl_heap.o:		mjl_heap.c mjl_heap.h
			${CC} ${CFLAGS} -DMJLHEAP_DEBUG -c mjl_heap.c
endif

clean:
			rm -f ${OBJS} ${PROGS} *~ \
				$(PROGS:%=%.o) $(PROGS:%=%.core) \
				test-msg-reader.o test-msg-writer.o TODO~
