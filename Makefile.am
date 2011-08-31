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
	gperf mper_keywords.gperf >$@

CLEANFILES = *~ mper_keywords.c
