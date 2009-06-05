/*
 * scamper_do_ping.c
 *
 * $Id: scamper_do_ping.c,v 1.72 2009/05/19 04:40:39 mjl Exp $
 *
 * Copyright (C) 2005-2009 The University of Waikato
 * Author: Matthew Luckie
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

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef __int16 int16_t;
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <sys/types.h>

#if defined(__linux__)
#define __FAVOR_BSD
#endif

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <stdlib.h>
#include <errno.h>

#include <string.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include <assert.h>

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_getsrc.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_debug.h"
#include "scamper_do_ping.h"
#include "scamper_options.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "utils.h"

#define SCAMPER_DO_PING_PROBECOUNT_MIN    1
#define SCAMPER_DO_PING_PROBECOUNT_DEF    4
#define SCAMPER_DO_PING_PROBECOUNT_MAX    65535

#define SCAMPER_DO_PING_PROBESIZE_V4_MIN  28
#define SCAMPER_DO_PING_PROBESIZE_V4_DEF  (28+56)
#define SCAMPER_DO_PING_PROBESIZE_V4_MAX  65535

#define SCAMPER_DO_PING_PROBESIZE_V6_MIN  48
#define SCAMPER_DO_PING_PROBESIZE_V6_DEF  (48+8)
#define SCAMPER_DO_PING_PROBESIZE_V6_MAX  65535

#define SCAMPER_DO_PING_PROBEWAIT_MIN     1
#define SCAMPER_DO_PING_PROBEWAIT_DEF     1
#define SCAMPER_DO_PING_PROBEWAIT_MAX     20

#define SCAMPER_DO_PING_PROBETTL_MIN      1
#define SCAMPER_DO_PING_PROBETTL_DEF      64
#define SCAMPER_DO_PING_PROBETTL_MAX      255

#define SCAMPER_DO_PING_PROBETOS_MIN      0
#define SCAMPER_DO_PING_PROBETOS_DEF      0
#define SCAMPER_DO_PING_PROBETOS_MAX      255

#define SCAMPER_DO_PING_PROBEMETHOD_MIN   0
#define SCAMPER_DO_PING_PROBEMETHOD_DEF   0
#define SCAMPER_DO_PING_PROBEMETHOD_MAX   4

#define SCAMPER_DO_PING_PROBEDPORT_MIN    0
#define SCAMPER_DO_PING_PROBEDPORT_MAX    65535

#define SCAMPER_DO_PING_REPLYCOUNT_MIN    0
#define SCAMPER_DO_PING_REPLYCOUNT_DEF    0
#define SCAMPER_DO_PING_REPLYCOUNT_MAX    65535

#define SCAMPER_DO_PING_PATTERN_MIN       1
#define SCAMPER_DO_PING_PATTERN_DEF       0
#define SCAMPER_DO_PING_PATTERN_MAX       32

/* the callback functions registered with the ping task */
static scamper_task_funcs_t ping_funcs;

/* ICMP ping probes are marked with the process' ID */
#ifndef _WIN32
static pid_t pid;
#else
static DWORD pid;
#endif

/* packet buffer for generating the payload of an ICMP packet */
static uint8_t *pktbuf     = NULL;
static size_t   pktbuf_len = 0;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

typedef struct ping_probe
{
  struct timeval     tx;
  uint16_t           seq;
  uint16_t           ipid;
} ping_probe_t;

typedef struct ping_state
{
#ifndef _WIN32
  scamper_fd_t      *rt;
#endif

  scamper_fd_t      *icmp;
  scamper_fd_t      *pr;
  scamper_dl_hdr_t  *dl_hdr;
  ping_probe_t     **probes;
  uint16_t           replies;
  uint16_t           seq_min;
  uint16_t           seq_cur;
  uint16_t           seq_max;
  scamper_addr_t    *src;
  uint32_t           tcp_seq;
  uint32_t           tcp_ack;
} ping_state_t;

#define PING_OPT_PROBECOUNT    1
#define PING_OPT_PROBEDPORT    2
#define PING_OPT_PROBEWAIT     3
#define PING_OPT_PROBETTL      4
#define PING_OPT_REPLYCOUNT    5
#define PING_OPT_PATTERN       6
#define PING_OPT_PROBEMETHOD   7
#define PING_OPT_USERID        8
#define PING_OPT_PROBESIZE     9
#define PING_OPT_PROBETOS      10
#define PING_OPT_SRCADDR       11

static const scamper_option_in_t opts[] = {
  {'c', NULL, PING_OPT_PROBECOUNT,   SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, PING_OPT_PROBEDPORT,   SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, PING_OPT_PROBEWAIT,    SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, PING_OPT_PROBETTL,     SCAMPER_OPTION_TYPE_NUM},
  {'o', NULL, PING_OPT_REPLYCOUNT,   SCAMPER_OPTION_TYPE_NUM},
  {'p', NULL, PING_OPT_PATTERN,      SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, PING_OPT_PROBEMETHOD,  SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, PING_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, PING_OPT_PROBESIZE,    SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, PING_OPT_SRCADDR,      SCAMPER_OPTION_TYPE_STR},
  {'z', NULL, PING_OPT_PROBETOS,     SCAMPER_OPTION_TYPE_NUM},
};

static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_ping_usage(void)
{
  return "ping [-c count] [-d dport] [-i wait-probe] [-m ttl]\n"
         "     [-o reply-count] [-p pattern] [-P method] [-U userid]\n"
         "     [-s probe-size] [-S srcaddr] [-z tos]";
}

/*
 * ping_abort
 *
 * some internal consistency check failed
 */
static void ping_abort(scamper_task_t *task)
{
  scamper_task_free(task);
  return;
}

static void ping_stop(scamper_task_t *task, uint8_t reason, uint8_t data)
{
  scamper_ping_t *ping = task->data;

  ping->stop_reason = reason;
  ping->stop_data   = data;

  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);

  return;  
}

static void ping_handleerror(scamper_task_t *task, int error)
{
  ping_stop(task, SCAMPER_PING_STOP_ERROR, error);
  return;
}

static uint16_t match_ipid(scamper_task_t *task, uint16_t ipid)
{
  scamper_ping_t *ping  = task->data;
  ping_state_t   *state = task->state;
  uint16_t        seq;

  for(seq = state->seq_cur-1; state->probes[seq]->ipid != ipid; seq--)
    {
      if(seq == 0 || ping->ping_sent - 5 == seq)
	{
	  seq = state->seq_cur - 1;
	  break;
	}
    }

  return seq;
}

static void do_ping_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_ping_t       *ping  = task->data;
  ping_state_t         *state = task->state;
  scamper_ping_reply_t *reply = NULL;
  ping_probe_t         *probe;
  uint16_t              seq;

  if(state->seq_cur == 0)
    return;

  if(dl->dl_ip_proto != IPPROTO_TCP)
    return;

  if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
    {
      if(dl->dl_tcp_dport != ping->probe_sport)
	return;

      /*
       * for TCP targets that might echo the IPID, use that to match probes.
       * note that there exists the possibility that replies might be associated
       * with the wrong probe by random chance.
       */
      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	seq = match_ipid(task, dl->dl_ip_id);
      else
	seq = state->seq_cur - 1;
    }
  else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT)
    {
      if(dl->dl_tcp_dport > ping->probe_sport + state->seq_cur ||
	 dl->dl_tcp_dport < ping->probe_sport)
	return;
      seq = dl->dl_tcp_dport - ping->probe_sport;
    }
  else
    {
      return;
    }

  if(dl->dl_tcp_sport != ping->probe_dport)
    return;

  /* this is probably the probe which goes with the reply */
  probe = state->probes[seq];

  scamper_dl_rec_tcp_print(dl);

  /* allocate a reply structure for the response */
  if((reply = scamper_ping_reply_alloc()) == NULL)
    {
      goto err;
    }

  /* figure out where the response came from */
  if((reply->addr = scamper_addrcache_get(addrcache, ping->dst->type,
					  dl->dl_ip_src)) == NULL)
    {
      goto err;
    }

  /* put together details of the reply */
  timeval_diff_tv(&reply->rtt, &probe->tx, &dl->dl_tv);
  reply->reply_size  = dl->dl_ip_size;
  reply->reply_proto = dl->dl_ip_proto;
  reply->probe_id    = state->seq_cur-1;
  reply->tcp_flags   = dl->dl_tcp_flags;

  if(dl->dl_af == AF_INET)
    {
      reply->reply_ipid = dl->dl_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;

      reply->probe_ipid = probe->ipid;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_PROBE_IPID;
    }

  reply->reply_ttl = dl->dl_ip_ttl;
  reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;

  /*
   * if this is the first reply we have for this hop, then increment
   * the replies counter we keep state with
   */
  if(ping->ping_replies[state->seq_cur-1] == NULL)
    {
      state->replies++;
    }

  /* put the reply into the ping table */
  scamper_ping_reply_append(ping, reply);

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  if(ping->reply_count != 0 && state->replies >= ping->reply_count)
    {
      ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);
    }

  return;

 err:
  ping_handleerror(task, errno);
  return;
}

static int ping_handle_rt(scamper_task_t *task, scamper_rt_rec_t *rt)
{
  scamper_ping_t *ping = task->data;
  ping_state_t *state  = task->state;

  if(SCAMPER_PING_METHOD_IS_TCP(ping) == 0)
    {
      return 0;
    }

  if((state->pr = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      return -1;
    }

  if((state->dl_hdr = scamper_dl_hdr_alloc(state->pr, ping->src, ping->dst,
					   rt->gwaddr)) == NULL)
    {
      return -1;
    }

  if(random_u32(&state->tcp_seq) != 0 || random_u32(&state->tcp_ack) != 0)
    return -1;

  return 0;
}

#ifndef _WIN32
static void do_ping_handle_rt(scamper_task_t *task, scamper_rt_rec_t *rt)
{
  ping_state_t *state = task->state;

  /* don't need the route socket now */
  assert(state->rt != NULL);
  scamper_fd_free(state->rt);
  state->rt = NULL;

  /* if there was a problem getting the ifindex, handle that */
  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(errno, strerror, __func__, "could not get ifindex");
      ping_handleerror(task, errno);
      return;
    }

  if(ping_handle_rt(task, rt) != 0)
    {
      ping_handleerror(task, errno);
    }
  else
    {
      scamper_queue_probe(task->queue);
    }

  return;
}
#endif

/*
 * do_ping_probe
 *
 * it is time to send a probe for this task.  figure out the form of the
 * probe to send, and then send it.
 */
static void do_ping_probe(scamper_task_t *task)
{
  scamper_ping_t  *ping  = task->data;
  ping_state_t    *state = task->state;
  ping_probe_t    *pp = NULL;
  scamper_probe_t  probe;
  uint8_t         *buf;
  size_t           payload_len;
  size_t           hdr_len;
  int              i;
  uint16_t         ipid = 0;

#ifndef _WIN32
  if(state->rt != NULL)
    {
      if(scamper_rtsock_getroute(state->rt, ping->dst) != 0)
	{
	  ping_handleerror(task, errno);
	  goto err;
	}
      scamper_queue_wait(task->queue, 5000);
      return;
    }
#endif

  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      /* sizeof(struct ip) */
      hdr_len = 20;

      /* select a random IPID value that is not zero. try up to three times */
      for(i=0; i<3; i++)
	{
	  if(random_u16(&ipid) != 0)
	    {
	      printerror(errno, strerror, __func__, "could not rand ipid");
	      ping_handleerror(task, errno);
	      goto err;
	    }

	  if(ipid != 0)
	    break;
	}

      if(ipid == 0)
	{
	  ping_handleerror(task, errno);
	  goto err;
	}
    }
  else if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      hdr_len = 40; /* sizeof(struct ip6_hdr) */
    }
  else
    {
      ping_abort(task);
      goto err;
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    payload_len = ping->probe_size - hdr_len - 8;
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    payload_len = 0;
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    payload_len = ping->probe_size - hdr_len - 8;
  else
    {
      ping_abort(task);
      goto err;
    }

  /* make sure the global pktbuf is big enough for the probe we send */
  if(pktbuf_len < payload_len)
    {
      if((buf = realloc(pktbuf, payload_len)) == NULL)
	{
	  printerror(errno, strerror, __func__, "could not realloc");
	  ping_handleerror(task, errno);
	  goto err;
	}
      pktbuf     = buf;
      pktbuf_len = payload_len;
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_ip_src    = ping->src;
  probe.pr_ip_dst    = ping->dst;
  probe.pr_ip_ttl    = ping->probe_ttl;
  probe.pr_ip_id     = ipid;
  probe.pr_data      = pktbuf;
  probe.pr_len       = payload_len;

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	{
	  probe.pr_ip_proto  = IPPROTO_ICMP;
	  probe.pr_icmp_type = ICMP_ECHO;
	}
      else
	{
	  probe.pr_ip_proto  = IPPROTO_ICMPV6;
	  probe.pr_icmp_type = ICMP6_ECHO_REQUEST;
	}
      probe.pr_icmp_id   = pid & 0xffff;
      probe.pr_icmp_seq  = state->seq_cur;
      probe.pr_fd        = scamper_fd_fd_get(state->icmp);
    }
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    {
      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_dport = ping->probe_dport;
      probe.pr_tcp_flags = TH_ACK;
      probe.pr_dl        = scamper_fd_write_state(state->pr);
      probe.pr_dl_hdr    = state->dl_hdr->dl_hdr;
      probe.pr_dl_size   = state->dl_hdr->dl_size;

      if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
	{
	  probe.pr_tcp_sport = ping->probe_sport;
	  probe.pr_tcp_seq   = state->tcp_seq;
	  probe.pr_tcp_ack   = state->tcp_ack;
	}
      else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT)
	{
	  probe.pr_tcp_sport = ping->probe_sport + state->seq_cur;
	  if(random_u32(&probe.pr_tcp_seq) != 0 ||
	     random_u32(&probe.pr_tcp_ack) != 0)
	    goto err;
	}
    }
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    {
      probe.pr_ip_proto  = IPPROTO_UDP;
      probe.pr_udp_sport = ping->probe_sport;
      probe.pr_fd        = scamper_fd_fd_get(state->pr);

      if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
	probe.pr_udp_dport = ping->probe_dport;
      else if(ping->probe_method == SCAMPER_PING_METHOD_UDP_DPORT)
	probe.pr_udp_dport = ping->probe_dport + state->seq_cur;
    }

  /* if the ping has to hold some pattern, then generate it now */  
  if(ping->pattern_bytes == NULL)
    {
      memset(pktbuf, 0, payload_len);
    }
  else
    {
      i = 0;
      while((size_t)(i + ping->pattern_len) < payload_len)
	{
	  memcpy(pktbuf+i, ping->pattern_bytes, ping->pattern_len);
	  i += ping->pattern_len;
	}
      memcpy(pktbuf+i, ping->pattern_bytes, payload_len - i);
    }

  /*
   * allocate a ping probe state record before we try and send the probe
   * as there is no point sending something into the wild that we can't
   * record
   */
  if((pp = malloc(sizeof(ping_probe_t))) == NULL)
    {
      ping_handleerror(task, errno);
      goto err;
    }

  if(scamper_probe(&probe) == -1)
    {
      ping_handleerror(task, probe.pr_errno);
      goto err;
    }

  /* fill out the details of the probe sent */
  pp->seq  = state->seq_cur;
  pp->ipid = ipid;
  timeval_cpy(&pp->tx, &probe.pr_tx);

  /* record the probe in the probes table */
  state->probes[state->seq_cur - state->seq_min] = pp;

  /* we've sent this sequence number now, so move to the next one */
  state->seq_cur++;

  /* increment the number of probes sent... */
  ping->ping_sent++;

  /* re-queue the ping task */
  scamper_queue_wait(task->queue, ping->probe_wait * 1000);

  return;

 err:
  if(pp != NULL) free(pp);
  return;
}

static void do_ping_handle_icmp(scamper_task_t *task, scamper_icmp_resp_t *ir)
{
  scamper_ping_t       *ping  = task->data;
  ping_state_t         *state = task->state;
  scamper_ping_reply_t *reply = NULL;
  ping_probe_t         *probe;
  uint16_t              seq;
  scamper_addr_t        addr;

  /*
   * ignore the message if it is received on an fd that we didn't use to send
   * it.  this is to avoid recording duplicate replies if an unbound socket
   * is in use.
   */
  if(ir->ir_fd != scamper_fd_fd_get(state->icmp))
    return;

  /* if we haven't sent a probe yet */
  if(state->seq_cur == 0)
    return;

  scamper_icmp_resp_print(ir);

  /* if this is an echo reply packet, then check the id and sequence */
  if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir))
    {
      /* if the response is not for us, then move on */
      if(ping->probe_method != SCAMPER_PING_METHOD_ICMP_ECHO ||
	 ir->ir_icmp_id != (pid & 0xffff) ||
	 ir->ir_icmp_seq < state->seq_min ||
	 ir->ir_icmp_seq > state->seq_max)
	{
	  return;
	}

      seq = ir->ir_icmp_seq - state->seq_min;
    }
  else if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir))
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_ICMP_ECHO_REQ(ir) == 0 ||
	     ir->ir_inner_icmp_id != (pid & 0xffff) ||
	     ir->ir_inner_icmp_seq < state->seq_min ||
	     ir->ir_inner_icmp_seq > state->seq_max)
	    {
	      return;
	    }

	  seq = ir->ir_inner_icmp_seq - state->seq_min;
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_TCP(ir) == 0 ||
	     SCAMPER_ICMP_RESP_IS_UNREACH(ir) == 0 ||
	     ir->ir_inner_tcp_dport != ping->probe_dport)
	    {
	      return;
	    }

	  if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
	    {
	      if(ir->ir_inner_tcp_sport != ping->probe_sport)
		return;

	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq_cur - 1;
	    }
	  else
	    {
	      if(ir->ir_inner_tcp_sport > ping->probe_sport + state->seq_cur ||
		 ir->ir_inner_tcp_sport < ping->probe_sport)
		return;

	      seq = ir->ir_inner_tcp_sport - ping->probe_sport;
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_UDP(ir) == 0 ||
	     SCAMPER_ICMP_RESP_IS_UNREACH(ir) == 0 ||
	     ir->ir_inner_udp_sport != ping->probe_sport)
	    {
	      return;
	    }

	  if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
	    {
	      if(ir->ir_inner_udp_dport != ping->probe_dport)
		return;

	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq_cur - 1;
	    }
	  else if(ping->probe_method == SCAMPER_PING_METHOD_UDP_DPORT)
	    {
	      if(ir->ir_inner_udp_dport > ping->probe_dport + state->seq_cur ||
		 ir->ir_inner_udp_dport < ping->probe_dport)
		return;

	      seq = ir->ir_inner_udp_dport - ping->probe_dport;
	    }
	  else
	    {
	      return;
	    }
	}
      else
	{
	  return;
	}
    }
  else return;

  /*
   * if the sequence number was in our range, but we have no record of the
   * probe, then just ignore the response
   */
  if((probe = state->probes[seq]) == NULL)
    {
      return;
    }

  /* allocate a reply structure for the response */
  if((reply = scamper_ping_reply_alloc()) == NULL)
    {
      goto err;
    }

  /* figure out where the response came from */
  if(scamper_icmp_resp_src(ir, &addr) != 0 ||
     (reply->addr = scamper_addrcache_get(addrcache,
					  addr.type, addr.addr)) == NULL)
    {
      goto err;
    }

  /* put together details of the reply */
  timeval_diff_tv(&reply->rtt, &probe->tx, &ir->ir_rx);
  reply->reply_size  = ir->ir_ip_size;
  reply->probe_id    = seq;
  reply->icmp_type   = ir->ir_icmp_type;
  reply->icmp_code   = ir->ir_icmp_code;

  if(ir->ir_af == AF_INET)
    {
      reply->reply_ipid = ir->ir_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;

      reply->probe_ipid = probe->ipid;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_PROBE_IPID;

      reply->reply_proto = IPPROTO_ICMP;
    }
  else if(ir->ir_af == AF_INET6)
    {
      reply->reply_proto = IPPROTO_ICMPV6;
    }

  if(ir->ir_ip_ttl != -1)
    {
      reply->reply_ttl = (uint8_t)ir->ir_ip_ttl;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;
    }

  /*
   * if this is the first reply we have for this hop, then increment
   * the replies counter we keep state with
   */
  if(ping->ping_replies[seq] == NULL)
    {
      state->replies++;
    }

  /* put the reply into the ping table */
  scamper_ping_reply_append(ping, reply);

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  if(ping->reply_count != 0 && state->replies >= ping->reply_count)
    {
      ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);
    }

  return;

 err:
  if(reply != NULL) scamper_ping_reply_free(reply);
  ping_handleerror(task, errno);
  return;
}

/*
 * do_ping_handle_timeout
 *
 * the ping object expired on the pending queue
 * that means it is either time to send the next probe, or write the
 * task out
 */
static void do_ping_handle_timeout(scamper_task_t *task)
{
  ping_state_t *state = task->state;

#ifndef _WIN32
  if(state->rt != NULL)
    {
      ping_handleerror(task, 0);
      return;
    }
#endif

  if(state->seq_cur == state->seq_max)
    {
      ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);
    }

  return;
}

static void do_ping_write(scamper_task_t *task)
{
  const char *outfile_name;
  scamper_outfile_t *outfile;
  scamper_file_t *sf;

  outfile_name = scamper_source_getoutfile(task->source);
  assert(outfile_name != NULL);

  if((outfile = scamper_outfiles_get(outfile_name)) != NULL)
    {
      sf = scamper_outfile_getfile(outfile);
      scamper_file_write_ping(sf, (scamper_ping_t *)task->data);
    }

  return;
}

static void do_ping_free(scamper_task_t *task)
{
  scamper_ping_t *ping;
  ping_state_t *state;
  int i;

  /* free any ping data collected */
  if((ping = task->data) != NULL)
    {
      scamper_ping_free(ping);
    }

  if((state = task->state) != NULL)
    {
      /* close icmp fd */
      if(state->icmp != NULL)
	scamper_fd_free(state->icmp);

      /* close probe fd; datalink (tcp) or udp */
      if(state->pr != NULL)
	scamper_fd_free(state->pr);

      /* free header used in datalink probes */
      if(state->dl_hdr != NULL)
	scamper_dl_hdr_free(state->dl_hdr);

#ifndef _WIN32
      if(state->rt != NULL)
	scamper_fd_free(state->rt);
#endif

      if(state->probes != NULL)
	{
	  for(i=0; i<state->seq_max - state->seq_min; i++)
	    {
	      if(state->probes[i] != NULL)
		{
		  free(state->probes[i]);
		}
	    }
	  free(state->probes);
	}
      free(state);
    }

  return;
}

static int ping_arg_param_validate(int optid, char *param, long *out)
{
  int i;
  long tmp;

  switch(optid)
    {
    /* number of probes to send */
    case PING_OPT_PROBECOUNT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBECOUNT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBECOUNT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBEDPORT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBEDPORT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBEDPORT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBEMETHOD:
      if(strcasecmp(param, "icmp-echo") == 0)
	tmp = SCAMPER_PING_METHOD_ICMP_ECHO;
      else if(strcasecmp(param, "tcp-ack") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_ACK;
      else if(strcasecmp(param, "tcp-ack-sport") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_ACK_SPORT;
      else if(strcasecmp(param, "udp") == 0)
	tmp = SCAMPER_PING_METHOD_UDP;
      else if(strcasecmp(param, "udp-dport") == 0)
	tmp = SCAMPER_PING_METHOD_UDP_DPORT;
      else
	goto err;
      break;

    /* how long to wait between sending probes */
    case PING_OPT_PROBEWAIT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBEWAIT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBEWAIT_MAX)
	{
	  goto err;
	}
      break;

    /* the ttl to probe with */
    case PING_OPT_PROBETTL:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBETTL_MIN  ||
	 tmp > SCAMPER_DO_PING_PROBETTL_MAX)
	{
	  goto err;
	}
      break;

    /* how many unique replies are required before the ping completes */
    case PING_OPT_REPLYCOUNT:
      if(string_tolong(param, &tmp) == -1  ||
	 tmp < SCAMPER_DO_PING_REPLYCOUNT_MIN ||
	 tmp > SCAMPER_DO_PING_REPLYCOUNT_MAX)
	{
	  goto err;
	}
      break;

    /* the pattern to fill each probe with */
    case PING_OPT_PATTERN:
      /*
       * sanity check that only hex characters are present, and that
       * the pattern string is not too long.  then, compose the pattern
       * bytes into the local array.
       */
      for(i=0; i<SCAMPER_DO_PING_PATTERN_MAX; i++)
	{
	  if(param[i] == '\0') break;
	  if(ishex(param[i]) == 0) goto err;
	}
      if(i == SCAMPER_DO_PING_PATTERN_MAX) goto err;
      break;

    /* the size of each probe */
    case PING_OPT_PROBESIZE:
      if(string_tolong(param, &tmp) == -1 || tmp < 0 || tmp > 65535)
	{
	  goto err;
	}
      break;

    case PING_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
      break;

    case PING_OPT_SRCADDR:
      break;

    /* the tos bits to include in each probe */
    case PING_OPT_PROBETOS:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBETOS_MIN  ||
	 tmp > SCAMPER_DO_PING_PROBETOS_MAX)
	{
	  goto err;
	}
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
 * scamper_do_ping_arg_validate
 *
 *
 */
int scamper_do_ping_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  ping_arg_param_validate);
}

/*
 * scamper_do_ping_alloc
 *
 * given a string representing a ping task, parse the parameters and assemble
 * a ping.  return the ping structure so that it is all ready to go.
 *
 */
void *scamper_do_ping_alloc(char *str)
{
  uint16_t  probe_count   = SCAMPER_DO_PING_PROBECOUNT_DEF;
  uint8_t   probe_wait    = SCAMPER_DO_PING_PROBEWAIT_DEF;
  uint8_t   probe_ttl     = SCAMPER_DO_PING_PROBETTL_DEF;
  uint8_t   probe_tos     = SCAMPER_DO_PING_PROBETOS_DEF;
  uint8_t   probe_method  = SCAMPER_DO_PING_PROBEMETHOD_DEF;
  uint16_t  probe_sport   = (pid & 0xffff) | 0x8000;
  uint16_t  probe_dport   = 33435;
  uint16_t  reply_count   = SCAMPER_DO_PING_REPLYCOUNT_DEF;
  uint16_t  probe_size    = 0; /* unset */
  uint16_t  pattern_len   = 0;
  uint8_t   pattern_bytes[SCAMPER_DO_PING_PATTERN_MAX/2];
  uint32_t  userid        = 0;
  char     *src           = NULL;
  int       af;

  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_ping_t *ping = NULL;
  char *addr;
  long tmp;
  int i;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      goto err;
    }

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 ping_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	/* number of probes to send */
	case PING_OPT_PROBECOUNT:
	  probe_count = (uint16_t)tmp;
	  break;

	case PING_OPT_PROBEDPORT:
	  probe_dport = (uint16_t)tmp;
	  break;

	case PING_OPT_PROBEMETHOD:
	  probe_method = (uint8_t)tmp;
	  break;

	/* how long to wait between sending probes */
	case PING_OPT_PROBEWAIT:
	  probe_wait = (uint8_t)tmp;
	  break;

	/* the ttl to probe with */
	case PING_OPT_PROBETTL:
	  probe_ttl = (uint8_t)tmp;
	  break;

	/* how many unique replies are required before the ping completes */
	case PING_OPT_REPLYCOUNT:
	  reply_count = (uint16_t)tmp;
	  break;

	/* the pattern to fill each probe with */
	case PING_OPT_PATTERN:
	  i = strlen(opt->str);
	  if((i % 2) == 0)
	    {
	      pattern_len = i/2;
	      for(i=0; i<pattern_len; i++)
		{
		  pattern_bytes[i] = hex2byte(opt->str[i*2],opt->str[(i*2)+1]);
		}
	    }
	  else
	    {
	      pattern_len = (i/2) + 1;
	      pattern_bytes[0] = hex2byte('0', opt->str[0]);
	      for(i=1; i<pattern_len; i++)
		{
		  pattern_bytes[i] = hex2byte(opt->str[(i*2)-1],opt->str[i*2]);
		}
	    }
	  break;

	/* the size of each probe */
	case PING_OPT_PROBESIZE:
	  probe_size = (uint16_t)tmp;
	  break;

	case PING_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case PING_OPT_SRCADDR:
	  if(src != NULL)
	    goto err;
	  src = opt->str;
	  break;

	/* the tos bits to include in each probe */
	case PING_OPT_PROBETOS:
	  probe_tos = (uint8_t)tmp;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  /* allocate the ping object and determine the address to probe */
  if((ping = scamper_ping_alloc()) == NULL)
    {
      goto err;
    }
  if((ping->dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      goto err;
    }
  ping->probe_method = probe_method;

  /* ensure the probe size specified is suitable */
  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  if(probe_size == 0)
	    probe_size = SCAMPER_DO_PING_PROBESIZE_V4_DEF;
	  else if(probe_size < SCAMPER_DO_PING_PROBESIZE_V4_MIN)
	    goto err;
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  if(probe_size != 0 && probe_size != 40)
	    goto err;
	  probe_size = 40;
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  /* this is the same probe size used for UDP traceroute; 20+8+12 */
	  if(probe_size != 0 && probe_size != 40)
	    goto err;
	  probe_size = 40;
	}
    }
  else if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  if(probe_size == 0)
	    probe_size = SCAMPER_DO_PING_PROBESIZE_V6_DEF;
	  else if(probe_size < SCAMPER_DO_PING_PROBESIZE_V6_MIN)
	    goto err;
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  if(probe_size != 0 && probe_size != 60)
	    goto err;
	  probe_size = 60;
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  /* this is the same probe size used for UDP traceroute; 40+8+12 */
	  if(probe_size != 0 && probe_size != 60)
	    goto err;
	  probe_size = 60;
	}
    }
  else goto err;

  if(src != NULL)
    {
      af = scamper_addr_af(ping->dst);
      if(af != AF_INET && af != AF_INET6)
	goto err;

      if((ping->src = scamper_addrcache_resolve(addrcache, af, src)) == NULL)
	goto err;
    }

  /* copy in the pad bytes, if any */
  if(scamper_ping_setpattern(ping, pattern_bytes, pattern_len) != 0)
    {
      goto err;
    }

  ping->probe_count  = probe_count;
  ping->probe_size   = probe_size;
  ping->probe_wait   = probe_wait;
  ping->probe_ttl    = probe_ttl;
  ping->probe_tos    = probe_tos;
  ping->probe_sport  = probe_sport;
  ping->probe_dport  = probe_dport;
  ping->reply_count  = reply_count;
  ping->userid       = userid;

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

scamper_task_t *scamper_do_ping_alloctask(void *data,
					  scamper_list_t *list,
					  scamper_cycle_t *cycle)
{
  scamper_ping_t *ping = (scamper_ping_t *)data;
  scamper_task_t *task;
  ping_state_t   *state;
  size_t          size;
  void           *addr;

#ifdef _WIN32
  scamper_rt_rec_t rr;
#endif

  /* firstly, allocate the task structure */
  if((task = scamper_task_alloc(data, &ping_funcs)) == NULL)
    {
      goto err;
    }

  /* now, associate the list and cycle with the ping */
  ping->list  = scamper_list_use(list);
  ping->cycle = scamper_cycle_use(cycle);

  /* determine the source address used for sending probes */
  if(ping->src == NULL)
    {
      if((ping->src = scamper_getsrc(ping->dst)) == NULL)
	goto err;
      addr = NULL;
    }
  else
    {
      addr = ping->src->addr;
    }

  /* allocate the memory for ping replies */
  if(scamper_ping_replies_alloc(ping, ping->probe_count) == -1)
    {
      goto err;
    }

  /* allocate the necessary state to keep track of probes */
  if((task->state = malloc_zero(sizeof(ping_state_t))) == NULL)
    {
      goto err;
    }
  state = task->state;
  size = ping->probe_count * sizeof(ping_probe_t *);
  if((state->probes = malloc_zero(size)) == NULL)
    {
      goto err;
    }
  state->seq_max = state->seq_min + ping->probe_count;

  /* get the icmp file descriptor */
  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    state->icmp = scamper_fd_icmp4(addr);
  else if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    state->icmp = scamper_fd_icmp6(addr);
  else
    goto err;
  if(state->icmp == NULL)
    goto err;

  if(SCAMPER_PING_METHOD_IS_TCP(ping))
    {
#ifdef _WIN32
      if(scamper_rtsock_getroute(ping->dst, &rr) != 0 ||
	 ping_handle_rt(task, &rr) != 0)
	{
	  goto err;
	}
#else
      if((state->rt = scamper_fd_rtsock()) == NULL)
	goto err;
#endif
    }
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    {
      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	state->pr = scamper_fd_udp4(addr, ping->probe_sport);
      else
	state->pr = scamper_fd_udp6(addr, ping->probe_sport);
      if(state->pr == NULL)
	goto err;
    }

  /* timestamp the start time of the ping */
  gettimeofday_wrap(&ping->start);

  return task;

 err:
  if(task != NULL) scamper_task_free(task);
  return NULL;
}

int scamper_do_ping_dstaddr(void *data, void *param,
			    int (*foreach)(struct scamper_addr *, void *))
{
  scamper_ping_t *ping = (scamper_ping_t *)data;
  return foreach(ping->dst, param);
}

void scamper_do_ping_free(void *data)
{
  scamper_ping_free((scamper_ping_t *)data);
  return;
}

void scamper_do_ping_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

int scamper_do_ping_init()
{
  ping_funcs.probe          = do_ping_probe;
  ping_funcs.handle_icmp    = do_ping_handle_icmp;
  ping_funcs.handle_timeout = do_ping_handle_timeout;
  ping_funcs.handle_dl      = do_ping_handle_dl;
  ping_funcs.write          = do_ping_write;
  ping_funcs.task_free      = do_ping_free;
  ping_funcs.task_addrs     = scamper_do_ping_dstaddr;

#ifndef _WIN32
  ping_funcs.handle_rt      = do_ping_handle_rt;
  pid = getpid();
#else
  pid = GetCurrentProcessId();
#endif

  return 0;
}
