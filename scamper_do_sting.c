/*
 * scamper_do_sting.c
 *
 * $Id: scamper_do_sting.c,v 1.15 2009/04/03 03:03:19 mjl Exp $
 *
 * Copyright (C) 2008-2009 The University of Waikato
 * Author: Matthew Luckie
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

#include <sys/types.h>

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#define __func__ __FUNCTION__
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#endif

#if defined(__linux__)
#define __FAVOR_BSD
#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_sting.h"
#include "scamper_task.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_firewall.h"
#include "scamper_rtsock.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_tcp4.h"
#include "scamper_tcp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "scamper_do_sting.h"
#include "utils.h"
#include "mjl_list.h"

#ifndef TH_FIN
#define TH_FIN 0x01
#endif

#ifndef TH_SYN
#define TH_SYN 0x02
#endif

#ifndef TH_RST
#define TH_RST 0x04
#endif

#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif

#ifndef TH_ACK
#define TH_ACK 0x10
#endif

/*
 * how many packets to send in data phase:
 *   freebsd net.inet.tcp.reass.maxqlen = 48
 *   note that this value is different to the hard-coded sting-0.7 default
 *   of 100.
 */
#define SCAMPER_DO_STING_COUNT_MIN 2
#define SCAMPER_DO_STING_COUNT_DEF 48
#define SCAMPER_DO_STING_COUNT_MAX 65535

/*
 * mean rate at which to send packets in data phase:
 *   100ms is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_MEAN_MIN  1
#define SCAMPER_DO_STING_MEAN_DEF  100
#define SCAMPER_DO_STING_MEAN_MAX  1000

/*
 * inter-phase delay between data seeding and hole filling.
 *   2000ms is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_INTER_MIN  1
#define SCAMPER_DO_STING_INTER_DEF  2000
#define SCAMPER_DO_STING_INTER_MAX  10000

/*
 * distribution to apply when determining when to send the next packet
 *  3 corresponds to uniform distribution
 */
#define SCAMPER_DO_STING_DIST_MIN  1
#define SCAMPER_DO_STING_DIST_DEF  3
#define SCAMPER_DO_STING_DIST_MAX  3

/*
 * how many times to retransmit a syn packet before deciding the host is down
 *  3 is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_SYNRETX_MIN 0
#define SCAMPER_DO_STING_SYNRETX_DEF 3
#define SCAMPER_DO_STING_SYNRETX_MAX 5

/*
 * number of times to retransmit data packets
 *  5 is the default number in sting-0.7
 */
#define SCAMPER_DO_STING_DATARETX_MIN 0
#define SCAMPER_DO_STING_DATARETX_DEF 5
#define SCAMPER_DO_STING_DATARETX_MAX 10

/*
 * size of the first hole in the sequence number space
 *  3 is the default number in sting-0.7
 */
#define SCAMPER_DO_STING_SEQSKIP_MIN 1
#define SCAMPER_DO_STING_SEQSKIP_DEF 3
#define SCAMPER_DO_STING_SEQSKIP_MAX 255

typedef struct sting_state
{
  uint8_t                   mode;
  struct timeval            next_tx;

#ifndef _WIN32
  scamper_fd_t             *rt;
#endif

  scamper_fd_t             *dl;
  scamper_firewall_entry_t *fw;
  scamper_dl_hdr_t         *dl_hdr;
  uint32_t                  isn;     /* initial sequence number */
  uint32_t                  ack;     /* acknowledgement number to use */
  uint32_t                  off;     /* which byte to tx next */
  uint8_t                   attempt;
} sting_state_t;

#ifndef _WIN32
static const uint8_t MODE_RTSOCK = 0;
#endif

static const uint8_t MODE_SYN    = 1;
static const uint8_t MODE_ACK    = 2;
static const uint8_t MODE_DATA   = 3;
static const uint8_t MODE_INTER  = 4;
static const uint8_t MODE_HOLE   = 5;
static const uint8_t MODE_RST    = 6;

/* the callback functions registered with the sting task */
static scamper_task_funcs_t sting_funcs;

/* the default source port to use */
static uint16_t default_sport;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define STING_OPT_COUNT  1
#define STING_OPT_DPORT  2
#define STING_OPT_DIST   3
#define STING_OPT_REQ    4
#define STING_OPT_HOLE   5
#define STING_OPT_INTER  6
#define STING_OPT_MEAN   7
#define STING_OPT_SPORT  8

static const scamper_option_in_t opts[] = {
  {'c', NULL, STING_OPT_COUNT,  SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, STING_OPT_DPORT,  SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, STING_OPT_DIST,   SCAMPER_OPTION_TYPE_STR},
  {'h', NULL, STING_OPT_REQ,    SCAMPER_OPTION_TYPE_STR},
  {'H', NULL, STING_OPT_HOLE,   SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, STING_OPT_INTER,  SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, STING_OPT_MEAN,   SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, STING_OPT_SPORT,  SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_sting_usage(void)
{
  return "sting [-c count] [-d dport] [-f distribution] [-h request]\n"
         "      [-H hole] [-i inter] [-m mean] [-s sport]";
}

/*
 * this is the default request used when none is specified.  it is the same
 * default request found in sting-0.7
 */
static const char *defaultrequest =
  "GET / HTTP/1.0\n"
  "Accept: text/plain\n"
  "Accept: */*\n"
  "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; Sting)\n"
  "\n";

static void sting_handleerror(scamper_task_t *task, int error)
{
  scamper_queue_done(task->queue, 0);
  return;
}

/*
 * handletimeout_syn
 *
 * retransmit a syn up to a specified number of times.
 */
static void handletimeout_syn(scamper_task_t *task)
{
  scamper_sting_t *sting = task->data;
  sting_state_t *state = task->state;
  if(state->attempt == sting->synretx)
    {
      scamper_queue_done(task->queue, 0);
    }
  else
    {
      scamper_queue_probe(task->queue);
    }
  return;
}

/*
 * handletimeout_inter
 *
 * this function is called to signal the end of the inter-phase wait time.
 * the only point of this function is to shift the sting into the hole-filling
 * phase.
 */
static void handletimeout_inter(scamper_task_t *task)
{
  sting_state_t *state = task->state;
  state->attempt = 0;
  state->off     = 0;
  state->mode    = MODE_HOLE;
  scamper_queue_probe(task->queue);
  return;
}

/*
 * handletimeout_hole
 *
 * this function is called when a timeout occurs when in the hole-filling
 * state.  it allows a packet in a hole to be retransmitted a number of times
 * before giving up.
 */
static void handletimeout_hole(scamper_task_t *task)
{
  scamper_sting_t *sting = task->data;
  sting_state_t *state = task->state;

  /*
   * when we reach the maximum number of retranmissions, send a reset
   * and give up
   */
  if(state->attempt == sting->dataretx)
    {
      state->mode = MODE_RST;
    }

  scamper_queue_probe(task->queue);
  return;
}

/*
 * handletimeout_rst
 *
 * this function exists solely to ensure a task makes its way into the
 * done queue after a reset has been transmitted.
 */
static void handletimeout_rst(scamper_task_t *task)
{
  scamper_queue_done(task->queue, 0);
  return;
}

/*
 * do_sting_handle_timeout
 *
 * this function ensures an appropriate action is taken when a timeout
 * occurs.
 */
static void do_sting_handle_timeout(scamper_task_t *task)
{
  static void (* const func[])(scamper_task_t *) =
  {
    NULL,                /* MODE_RTSOCK */
    handletimeout_syn,   /* MODE_SYN */
    NULL,                /* MODE_ACK */
    NULL,                /* MODE_DATA */
    handletimeout_inter, /* MODE_INTER */
    handletimeout_hole,  /* MODE_HOLE */
    handletimeout_rst,   /* MODE_RST */
  };
  sting_state_t *state = task->state;

  if(func[state->mode] != NULL)
    {
      func[state->mode](task);
    }

  return;
}

/*
 * handletcp_syn
 *
 * this function checks the response to a syn
 */
static void handletcp_syn(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_sting_t *sting = task->data;
  sting_state_t *state = task->state;
  struct timeval tv;

  /*
   * wait for the SYN/ACK to come in; make a note of the sequence number
   * used by the receiver, and take an RTT measurement if possible.
   */
  if((dl->dl_tcp_flags & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK))
    {
      /* we got a reply, but it was not a SYN/ACK; halt the measurement */
      scamper_queue_done(task->queue, 0);
      return;
    }

  /*
   * the initial syn occupies one byte in the sequence space; data is
   * going to have this offset
   */
  state->isn++;

  /* if the sequence number in response did not make sense, abandon */
  if(dl->dl_tcp_ack != state->isn)
    {
      scamper_queue_done(task->queue, 0);
      return;
    }

  /* if we get a syn/ack on the first probe, take an RTT measurement */
  if(state->attempt == 1)
    {
      tv.tv_sec  = state->next_tx.tv_sec - 5;
      tv.tv_usec = state->next_tx.tv_usec;
      timeval_diff_tv(&sting->hsrtt, &tv, &dl->dl_tv);
    }

  /* send a token acknowledgement */
  state->ack  = dl->dl_tcp_seq + 1;
  state->mode = MODE_ACK;

  /* leave a hole in the sequence space */
  state->off  = sting->seqskip;

  scamper_queue_probe(task->queue);
  return;
}

/*
 * handletcp_data
 *
 * for each acknowledgement received, check that it makes sense.
 * count the number of acknowledgements received in the data phase
 */
static void handletcp_data(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_sting_t *sting = task->data;
  sting_state_t *state = task->state;

  /* if the acknowledgement number is not what is expected, abandon */
  if(dl->dl_tcp_ack != state->isn)
    {
      scamper_queue_done(task->queue, 0);
      return;
    }

  sting->dataackc++;
  return;
}

/*
 * handletcp_hole
 *
 * for each acknowledgement received in the hole-filling phase, figure out
 * if all probes have been accounted for
 */
static void handletcp_hole(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_sting_t *sting = task->data;
  sting_state_t *state = task->state;
  uint16_t u16;

  /* check to see if all holes are now full */
  if(state->isn + sting->seqskip + sting->count == dl->dl_tcp_ack)
    {
      state->off  = sting->seqskip + sting->count - 1;
      state->mode = MODE_RST;
      scamper_queue_probe(task->queue);
      return;
    }

  /* figure out which byte to send next, handling sequence space wrapping */
  if(state->isn < dl->dl_tcp_ack)
    {
      state->off = dl->dl_tcp_ack - state->isn;
    }
  else
    {
      state->off = (0xffffffff - state->isn) + dl->dl_tcp_ack + 1;
    }

  u16 = state->off - sting->seqskip;
  sting->probes[u16].flags |= SCAMPER_STING_PROBE_FLAG_HOLE;
  sting->holec++;

  state->attempt = 0;
  scamper_queue_probe(task->queue);
  return;
}

/*
 * do_sting_handle_dl
 *
 * for each packet received, check that the addresses and ports make sense,
 * and that the packet is not a reset
 */
static void do_sting_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (* const func[])(scamper_task_t *, scamper_dl_rec_t *) =
  {
    NULL,           /* MODE_RTSOCK */
    handletcp_syn,  /* MODE_SYN */
    NULL,           /* MODE_ACK */
    handletcp_data, /* MODE_DATA */
    handletcp_data, /* MODE_INTER */
    handletcp_hole, /* MODE_HOLE */
  };
  scamper_sting_t *sting = task->data;
  sting_state_t *state = task->state;

  /* unless the packet is an inbound TCP packet for the flow, ignore it */
  if(dl->dl_ip_proto != IPPROTO_TCP ||
     dl->dl_tcp_sport != sting->dport ||
     dl->dl_tcp_dport != sting->sport ||
     scamper_addr_raw_cmp(sting->src, dl->dl_ip_dst) != 0 ||
     scamper_addr_raw_cmp(sting->dst, dl->dl_ip_src) != 0)
    {
      return;
    }

  scamper_dl_rec_tcp_print(dl);

  /* if a reset packet is received, abandon the measurement */
  if((dl->dl_tcp_flags & TH_RST) != 0)
    {
      scamper_queue_done(task->queue, 0);
      return;
    }

  if(func[state->mode] != NULL)
    {
      func[state->mode](task, dl);
    }
  return;
}

static int sting_handle_rt(scamper_task_t *task, scamper_rt_rec_t *rt)
{
  scamper_firewall_rule_t sfw;
  scamper_sting_t *sting = task->data;
  sting_state_t *state = task->state;

  /*
   * scamper needs the datalink to transmit packets; try and get a
   * datalink on the ifindex specified.
   */
  if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      return -1;
    }

  /*
   * determine the underlying framing to use with each probe packet that will
   * be sent on the datalink.
   */
  if((state->dl_hdr = scamper_dl_hdr_alloc(state->dl, sting->src, sting->dst,
					   rt->gwaddr)) == NULL)
    {
      return -1;
    }

  /*
   * add a firewall rule to block the kernel from interfering with the
   * measurement
   */
  sfw.type = SCAMPER_FIREWALL_RULE_TYPE_5TUPLE;
  sfw.sfw_5tuple_proto = IPPROTO_TCP;
  sfw.sfw_5tuple_src   = sting->dst;
  sfw.sfw_5tuple_dst   = sting->src;
  sfw.sfw_5tuple_sport = sting->dport;
  sfw.sfw_5tuple_dport = sting->sport;

  if((state->fw = scamper_firewall_entry_get(&sfw)) == NULL)
    {
      return -1;
    }

  state->mode = MODE_SYN;
  return 0;
}

#ifndef _WIN32
static void do_sting_handle_rt(scamper_task_t *task, scamper_rt_rec_t *rt)
{
  sting_state_t *state = task->state;

  if(state->mode != MODE_RTSOCK)
    {
      return;
    }

  assert(state->rt != NULL);
  scamper_fd_free(state->rt);
  state->rt = NULL;

  /* if there was a problem getting the ifindex, handle that */
  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(errno, strerror, __func__, "could not get ifindex");
      goto err;
    }

  if(sting_handle_rt(task, rt) != 0)
    goto err;

  scamper_queue_probe(task->queue);
  return;

 err:
  sting_handleerror(task, errno);
  return;
}
#endif

static void do_sting_write(scamper_task_t *task)
{
  const char *outfile_name;
  scamper_outfile_t *outfile;
  scamper_file_t *sf;

  outfile_name = scamper_source_getoutfile(task->source);
  assert(outfile_name != NULL);

  if((outfile = scamper_outfiles_get(outfile_name)) != NULL)
    {
      sf = scamper_outfile_getfile(outfile);
      scamper_file_write_sting(sf, (scamper_sting_t *)task->data);
    }

  return;
}

static void sting_state_free(sting_state_t *state)
{
  if(state != NULL)
    {
      if(state->fw != NULL)     scamper_firewall_entry_free(state->fw);
#ifndef _WIN32
      if(state->rt != NULL)     scamper_fd_free(state->rt);
#endif
      if(state->dl != NULL)     scamper_fd_free(state->dl);
      if(state->dl_hdr != NULL) scamper_dl_hdr_free(state->dl_hdr);
      free(state);
    }
  return;
}

static int sting_state_alloc(scamper_task_t *task)
{
  sting_state_t *state;

#ifdef _WIN32
  scamper_sting_t *sting = task->data;
  scamper_rt_rec_t rr;
#endif

  if((state = malloc_zero(sizeof(sting_state_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc state");
      goto err;
    }
  task->state = state;

  if(random_u32(&state->isn) != 0)
    {
      printerror(errno, strerror, __func__, "could not get random isn");
      goto err;
    }

#ifndef _WIN32
  state->mode = MODE_RTSOCK;
  if((state->rt = scamper_fd_rtsock()) == NULL)
    {
      goto err;
    }
#else
  if(scamper_rtsock_getroute(sting->dst, &rr) != 0 ||
     sting_handle_rt(task, &rr) != 0)
    {
      goto err;
    }
#endif

  return 0;

 err:
  return -1;
}

static void do_sting_free(scamper_task_t *task)
{
  scamper_sting_t *sting;
  sting_state_t *state;

  /* free any state kept */
  if((state = task->state) != NULL)
    {
      sting_state_free(state);
    }

  /* free any sting data collected */
  if((sting = task->data) != NULL)
    {
      scamper_sting_free(sting);
    }

  return;
}

static void do_sting_probe(scamper_task_t *task)
{
  scamper_sting_t *sting = task->data;
  sting_state_t   *state = task->state;
  scamper_probe_t  probe;
  uint32_t         wait;
  uint8_t          data[3];

  if(state == NULL)
    {
      gettimeofday_wrap(&sting->start);

      if((sting->src = scamper_getsrc(sting->dst)) == NULL)
	goto err;

      if(scamper_sting_probes(sting, sting->seqskip + sting->count) != 0)
	goto err;

      if(sting_state_alloc(task) != 0)
	goto err;

      state = task->state;
    }

#ifndef _WIN32
  if(state->mode == MODE_RTSOCK)
    {
      if(scamper_rtsock_getroute(state->rt, sting->dst) == 0)
	{
	  scamper_queue_wait(task->queue, 1000);
	  return;
	}
      else goto err;
    }
#endif

  memset(&probe, 0, sizeof(probe));
  probe.pr_dl        = scamper_fd_write_state(state->dl);
  probe.pr_dl_hdr    = state->dl_hdr->dl_hdr;
  probe.pr_dl_size   = state->dl_hdr->dl_size;
  probe.pr_ip_src    = sting->src;
  probe.pr_ip_dst    = sting->dst;
  probe.pr_ip_ttl    = 255;
  probe.pr_ip_proto  = IPPROTO_TCP;
  probe.pr_tcp_sport = sting->sport;
  probe.pr_tcp_dport = sting->dport;

  if(state->mode == MODE_SYN)
    {
      probe.pr_tcp_seq   = state->isn;
      probe.pr_tcp_ack   = 0;
      probe.pr_tcp_flags = TH_SYN;
      probe.pr_tcp_win   = 0;
      probe.pr_len       = 0;

      /* wait five seconds */
      wait = 5000;
    }
  else if(state->mode == MODE_ACK)
    {
      probe.pr_tcp_seq   = state->isn;
      probe.pr_tcp_ack   = state->ack;
      probe.pr_tcp_flags = TH_ACK;
      probe.pr_tcp_win   = 0;
      probe.pr_len       = 0;

      /* wait for 50 msec until sending the first data probe */
      wait = 50;
      state->mode = MODE_DATA;
    }
  else if(state->mode == MODE_DATA)
    {
      data[0] = sting->data[state->off];

      probe.pr_tcp_seq   = state->isn + state->off;
      probe.pr_tcp_ack   = state->ack;
      probe.pr_tcp_flags = TH_PUSH | TH_ACK;
      probe.pr_tcp_win   = 0;
      probe.pr_len       = 1;
      probe.pr_data      = data;

      state->off++;

      wait = sting->mean;
    }
  else if(state->mode == MODE_HOLE)
    {
      data[0] = sting->data[state->off];

      probe.pr_tcp_seq   = state->isn + state->off;
      probe.pr_tcp_ack   = state->ack;
      probe.pr_tcp_flags = TH_PUSH | TH_ACK;
      probe.pr_tcp_win   = 0;
      probe.pr_data      = data;

      if(state->off == 0)
	{
	  data[1]      = sting->data[state->off+1];
	  data[2]      = sting->data[state->off+2];
	  probe.pr_len = 3;
	}
      else
	{
	  probe.pr_len = 1;
	}

      /* wait 2 seconds before trying to retransmit */
      wait = 2000;
    }
  else if(state->mode == MODE_RST)
    {
      probe.pr_tcp_seq   = state->isn + state->off;
      probe.pr_tcp_ack   = state->ack;
      probe.pr_tcp_flags = TH_RST;
      probe.pr_tcp_win   = 0;
      probe.pr_len       = 0;

      /* wait a second */
      wait = 1000;
    }
  else
    {
      goto err;
    }

  /* send the probe */
  if(scamper_probe(&probe) == -1)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* make a note of the time the probe was transmitted */
  if(state->mode == MODE_DATA)
    {
      timeval_cpy(&sting->probes[sting->probec].tx, &probe.pr_tx);
      if(sting->probec == sting->count)
	{
	  /* wait 2 seconds */
	  wait = sting->inter;
	  state->mode = MODE_INTER;
	}
      sting->probec++;
    }

  /* figure out when the next probe may be sent */
  timeval_add_ms(&state->next_tx, &probe.pr_tx, wait);

  /* put in the queue for waiting */
  scamper_queue_wait(task->queue, wait);

  state->attempt++;
  return;

 err:
  scamper_debug(__func__, "error mode %d", state != NULL ? state->mode : -1);
  sting_handleerror(task, errno);
  return;
}

static int sting_arg_param_validate(int optid, char *param, long *out)
{
  long tmp;

  switch(optid)
    {
    case STING_OPT_COUNT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_COUNT_MIN ||
	 tmp > SCAMPER_DO_STING_COUNT_MAX)
	{
	  goto err;
	}
      break;

    case STING_OPT_SPORT:
    case STING_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 65535)
	goto err;
      break;

    case STING_OPT_DIST:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_DIST_MIN ||
	 tmp > SCAMPER_DO_STING_DIST_MAX)
	goto err;
      break;

    case STING_OPT_REQ:
      return -1;

    case STING_OPT_MEAN:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_MEAN_MIN ||
	 tmp > SCAMPER_DO_STING_MEAN_MAX)
	goto err;
      break;

    case STING_OPT_HOLE:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_SEQSKIP_MIN ||
	 tmp > SCAMPER_DO_STING_SEQSKIP_MAX)
	goto err;
      break;

    case STING_OPT_INTER:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_INTER_MIN ||
	 tmp > SCAMPER_DO_STING_INTER_MAX)
	goto err;
      break;

    default:
      return -1;
    }

  /* valid parameter */
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  return -1;
}

/*
 * scamper_do_sting_alloc
 *
 * given a string representing a sting task, parse the parameters and
 * assemble a sting.  return the sting structure so that it is all ready to
 * go.
 */
void *scamper_do_sting_alloc(char *str)
{
  uint16_t sport    = default_sport;
  uint16_t dport    = 80;
  uint16_t count    = SCAMPER_DO_STING_COUNT_DEF;
  uint16_t mean     = SCAMPER_DO_STING_MEAN_DEF;
  uint16_t inter    = SCAMPER_DO_STING_INTER_DEF;
  uint8_t  seqskip  = SCAMPER_DO_STING_SEQSKIP_DEF;
  uint8_t  dist     = SCAMPER_DO_STING_DIST_DEF;
  uint8_t  synretx  = SCAMPER_DO_STING_SYNRETX_DEF;
  uint8_t  dataretx = SCAMPER_DO_STING_DATARETX_DEF;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_sting_t *sting = NULL;
  char *addr;
  long tmp;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      scamper_debug(__func__, "no address parameter");
      goto err;
    }

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 sting_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case STING_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case STING_OPT_SPORT:
	  sport = (uint16_t)tmp;
	  break;

	case STING_OPT_COUNT:
	  count = (uint16_t)tmp;
	  break;

	case STING_OPT_MEAN:
	  mean = (uint16_t)tmp;
	  break;

	case STING_OPT_DIST:
	  dist = (uint8_t)tmp;
	  break;

	case STING_OPT_HOLE:
	  seqskip = (uint8_t)tmp;
	  break;

	case STING_OPT_INTER:
	  inter = (uint16_t)tmp;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if((sting = scamper_sting_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc sting");
      goto err;
    }
  if((sting->dst=scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not resolve %s", addr);
      goto err;
    }

  sting->sport    = sport;
  sting->dport    = dport;
  sting->count    = count;
  sting->mean     = mean;
  sting->inter    = inter;
  sting->dist     = dist;
  sting->synretx  = synretx;
  sting->dataretx = dataretx;
  sting->seqskip  = seqskip;

  /* take a copy of the data to be used in the measurement */
  if(scamper_sting_data(sting, (const uint8_t *)defaultrequest) != 0)
    {
      goto err;
    }

  return sting;

 err:
  if(sting != NULL) scamper_sting_free(sting);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

/*
 * scamper_do_sting_arg_validate
 *
 *
 */
int scamper_do_sting_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  sting_arg_param_validate);
}

int scamper_do_sting_dstaddr(void *data, void *param,
			     int (*foreach)(struct scamper_addr *, void *))
{
  scamper_sting_t *sting = (scamper_sting_t *)data;
  return foreach(sting->dst, param);
}

void scamper_do_sting_free(void *data)
{
  scamper_sting_free((scamper_sting_t *)data);
  return;
}

/*
 * scamper_do_sting_alloctask
 *
 */
scamper_task_t *scamper_do_sting_alloctask(void *data,
					   scamper_list_t *list,
					   scamper_cycle_t *cycle)
{
  scamper_sting_t *sting = (scamper_sting_t *)data;

  /* associate the list and cycle with the sting */
  sting->list  = scamper_list_use(list);
  sting->cycle = scamper_cycle_use(cycle);

  /* allocate a task structure and store the sting with it */
  return scamper_task_alloc(data, &sting_funcs);
}

void scamper_do_sting_cleanup(void)
{
  return;
}

int scamper_do_sting_init(void)
{
#ifndef _WIN32
  pid_t pid = getpid();
#else
  DWORD pid = GetCurrentProcessId();
#endif
  default_sport = (pid & 0x7fff) + 0x8000;

  sting_funcs.probe          = do_sting_probe;
  sting_funcs.handle_icmp    = NULL;
  sting_funcs.handle_dl      = do_sting_handle_dl;
  sting_funcs.handle_timeout = do_sting_handle_timeout;
  sting_funcs.write          = do_sting_write;
  sting_funcs.task_free      = do_sting_free;
  sting_funcs.task_addrs     = scamper_do_sting_dstaddr;

#ifndef _WIN32
  sting_funcs.handle_rt      = do_sting_handle_rt;
#endif

  return 0;
}
