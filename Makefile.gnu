# scamper Makefile for use with GNU make
# $Id: Makefile.gnu,v 1.79 2009/03/30 19:58:55 mjl Exp $

CFLAGS+=		-Wall
LDFLAGS+=		-Wall
OBJS=			scamper.o scamper_debug.o utils.o \
			scamper_list.o scamper_tlv.o scamper_icmpext.o \
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
			scamper_outfiles.o scamper_addr.o scamper_probe.o \
			scamper_target.o scamper_task.o scamper_queue.o \
			scamper_cyclemon.o scamper_options.o \
			scamper_sources.o scamper_source_cmdline.o \
			scamper_source_control.o scamper_source_file.o

HDRS=			scamper.h scamper_addr.h utils.h

LIBSCAMPERFILE_OBJS=	mjl_splaytree.o utils.o scamper_addr.o \
			scamper_list.o  scamper_tlv.o scamper_icmpext.o \
			scamper_ping.o

AR=			ar cq

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

PROGS=			scamper

all:			${PROGS}

scamper:		${OBJS}
			${CC} -o scamper ${LDFLAGS} ${OBJS} 

libscamperfile.a:	${LIBSCAMPERFILE_OBJS}
			rm -f $@
			${AR} $@ ${LIBSCAMPERFILE_OBJS}

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
			rm -f ${OBJS} libscamperfile.a \
			   ${PROGS} $(PROGS:%=%.o) $(PROGS:%=%.core)

install:		scamper
			mv scamper scamper.bin
			install -m 4755 -o root scamper.bin scamper
			rm scamper.bin
