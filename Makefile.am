# $Id: Makefile.am,v 1.12 2011/06/23 19:06:55 mjl Exp $

ACLOCAL_AMFLAGS = -I m4

INCLUDES = -I$(top_srcdir)

bin_PROGRAMS = mper test-msg-reader test-msg-writer

mper_SOURCES = \
	scamper.c \
	scamper_debug.c \
	utils.c \
	scamper_tlv.c \
	scamper_icmpext.c \
	scamper_do_ping.c \
	scamper_ping.c \
	scamper_udp4.c \
	scamper_udp6.c \
	scamper_icmp4.c \
	scamper_icmp6.c \
	scamper_icmp_resp.c \
	scamper_tcp4.c \
	scamper_tcp6.c \
	scamper_ip4.c \
	scamper_ip6.c \
	scamper_if.c \
	scamper_rtsock.c \
	scamper_dl.c \
	scamper_addr2mac.c \
	scamper_fds.c \
	scamper_linepoll.c \
	scamper_writebuf.c \
	scamper_privsep.c \
	scamper_getsrc.c \
	mjl_heap.c \
	mjl_list.c \
	mjl_splaytree.c \
	scamper_control.c \
	scamper_firewall.c \
	scamper_addr.c \
	scamper_probe.c \
	scamper_target.c \
	scamper_task.c \
	scamper_queue.c \
	scamper_options.c \
	mper_base64.c \
	mper_keywords.c \
	mper_msg_reader.c \
	mper_msg_writer.c

include_HEADERS = \
	internal.h \
	mjl_heap.h \
	mjl_list.h \
	mjl_splaytree.h \
	mper_base64.h \
	mper_keywords.h \
	mper_keywords.gperf \
	mper_msg.h \
	mper_msg_reader.h \
	mper_msg_writer.h \
	scamper.h \
	scamper_addr.h \
	scamper_addr2mac.h \
	scamper_control.h \
	scamper_debug.h \
	scamper_dl.h \
	scamper_do_ping.h \
	scamper_fds.h \
	scamper_firewall.h \
	scamper_getsrc.h \
	scamper_icmp4.h \
	scamper_icmp6.h \
	scamper_icmp_resp.h \
	scamper_icmpext.h \
	scamper_if.h \
	scamper_ip4.h \
	scamper_ip6.h \
	scamper_linepoll.h \
	scamper_options.h \
	scamper_ping.h \
	scamper_privsep.h \
	scamper_probe.h \
	scamper_queue.h \
	scamper_rtsock.h \
	scamper_target.h \
	scamper_task.h \
	scamper_tcp4.h \
	scamper_tcp6.h \
	scamper_tlv.h \
	scamper_udp4.h \
	scamper_udp6.h \
	scamper_writebuf.h \
	systypes.h \
	utils.h

test_msg_reader_SOURCES = \
	mper_base64.c \
	mper_keywords.c \
	mper_msg_reader.c \
	test-msg-reader.c

test_msg_writer_SOURCES = \
	mper_base64.c \
	mper_keywords.c \
	mper_msg_reader.c \
	mper_msg_writer.c \
	test-msg-writer.c

BUILT_SOURCES = mper_keywords.c

mper_keywords.c: Makefile mper_keywords.h mper_keywords.gperf
	if $(GPERF) $(GPERFFLAGS) \
                mper_keywords.gperf >$@~; then \
               mv $@~ $@; \
             elif $(GPERF) --version >/dev/null 2>&1; then \
               rm $@~; \
               exit 0; \
             else \
               rm $@~; \
               touch $@; \
             fi

CLEANFILES = *~
