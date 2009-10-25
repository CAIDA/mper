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
#define snprintf _snprintf
#define strcasecmp _stricmp
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
#include <stdio.h>
#include <errno.h>

#include <string.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include <assert.h>

#include "mper_keywords.h"
#include "mper_msg.h"
#include "mper_msg_reader.h"
#include "mper_msg_writer.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_ping.h"
#include "scamper_getsrc.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_writebuf.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_debug.h"
#include "scamper_do_ping.h"
#include "scamper_options.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "utils.h"

/* ---------------------------------------------------------------------- */

/* XXX probably should use the code in scamper_control */

static control_word_t resp_words[MPER_MSG_MAX_WORDS];

static void send_response(scamper_task_t *task, const char *message)
{
  /* XXX somewhat inefficient to do a separate send for just the newline */
  scamper_writebuf_send(task->wb, message, strlen(message));
  scamper_writebuf_send(task->wb, "\n", 1);
}

/* ---------------------------------------------------------------------- */

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
#define SCAMPER_DO_PING_REPLYCOUNT_DEF    1
#define SCAMPER_DO_PING_REPLYCOUNT_MAX    65535

#define SCAMPER_DO_PING_PATTERN_MIN       1
#define SCAMPER_DO_PING_PATTERN_DEF       0
#define SCAMPER_DO_PING_PATTERN_MAX       32

extern scamper_addr_t *g_gateway_sa;  /* in scamper.c */
extern int g_interface;  /* in scamper.c */

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

typedef struct ping_state
{
#ifndef _WIN32
  scamper_fd_t      *rt;
#endif

  scamper_fd_t      *icmp;
  scamper_fd_t      *pr;
  scamper_dl_hdr_t  *dl_hdr;

  uint8_t            sent_probe;  /* whether we've sent a probe yet */
  struct timeval     tx;          /* probe transmit time, seq, & ipid */
  uint16_t           seq;
  uint16_t           ipid;
  uint16_t           replies;

  scamper_addr_t    *src;
  uint32_t           tcp_seq;
  uint32_t           tcp_ack;
} ping_state_t;

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

  scamper_queue_done(task->queue, 0);

  return;  
}

static void ping_handleerror(scamper_task_t *task, int error)
{
  ping_stop(task, SCAMPER_PING_STOP_ERROR, error);
  return;
}

static void do_ping_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_ping_t       *ping  = task->data;
  ping_state_t         *state = task->state;
  scamper_ping_reply_t *reply = NULL;

  if(!state->sent_probe)
    return;

  if(dl->dl_ip_proto != IPPROTO_TCP)
    return;

  if(ping->probe_method != SCAMPER_PING_METHOD_TCP_ACK)
    return;

  if(dl->dl_tcp_dport != ping->probe_sport
     || dl->dl_tcp_sport != ping->probe_dport)
    return;

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
  /* timeval_diff_tv(&reply->rtt, &state->tx, &dl->dl_tv); */
  reply->tx = state->tx;
  reply->rx = dl->dl_tv;
  reply->reply_size  = dl->dl_ip_size;
  reply->reply_proto = dl->dl_ip_proto;
  reply->tcp_flags   = dl->dl_tcp_flags;

  if(dl->dl_af == AF_INET)
    {
      reply->reply_ipid = dl->dl_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;

      reply->probe_ipid = state->ipid;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_PROBE_IPID;
    }

  reply->reply_ttl = dl->dl_ip_ttl;
  reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;

  /* put the reply into the ping table */
  scamper_ping_reply_append(ping, reply);

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  state->replies++;
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
  scamper_probe_t  probe;
  uint8_t         *buf;
  size_t           payload_len;
  size_t           hdr_len;
  int              i;
  uint16_t         ipid = 0, u16;

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

  /*
  ** Note: We ensure in scamper_do_ping_alloc() that there is enough room
  **       in the payload for the checksum if the user has requested a
  **       specific checksum for ICMP.  (The user can't set the TCP/UDP
  **       checksum.)
  */
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

  /* if the ping has to hold some pattern, then generate it now */  

  /*
  ** Note: There is no direct way of setting the ICMP checksum of a probe
  **       packet.  If a user requests a specific ICMP checksum, then
  **       we employ a hack that requires storing 2 bytes in the payload.
  **       Thus, the user shouldn't really request both a specific checksum
  **       and a payload pattern, although we allow it, because the payload
  **       pattern will be partially overwritten to ensure to we achieve
  **       the requested checksum.
  */
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
      probe.pr_icmp_seq  = state->seq;
      probe.pr_fd        = scamper_fd_fd_get(state->icmp);

      /* hack to get the icmp csum to be a particular value, and be valid */
      if(ping->opt_set_cksum)  /* XXX not supported with IPv6 */
        {
	  u16 = htons(ping->probe_cksum);
	  memcpy(probe.pr_data, &u16, 2);
	  u16 = scamper_icmp4_cksum(&probe);
	  memcpy(probe.pr_data, &u16, 2);
	}
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
    }
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    {
      probe.pr_ip_proto  = IPPROTO_UDP;
      probe.pr_udp_sport = ping->probe_sport;
      probe.pr_fd        = scamper_fd_fd_get(state->pr);

      if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
	probe.pr_udp_dport = ping->probe_dport;

#if 0
      /* hack to get the udp csum to be a particular value, and be valid */
      if(ping->opt_set_cksum)  /* XXX not supported with IPv6 */
        {
	  u16 = htons(ping->probe_cksum);
	  memcpy(probe.pr_data, &u16, 2);
	  u16 = scamper_udp4_cksum(&probe);
	  memcpy(probe.pr_data, &u16, 2);
	}
#endif
    }

  if(scamper_probe(&probe) == -1)
    {
      ping_handleerror(task, probe.pr_errno);
      goto err;
    }

  /* fill out the details of the probe sent */
  state->sent_probe = 1;
  state->ipid = ipid;
  timeval_cpy(&state->tx, &probe.pr_tx);

  /* re-queue the ping task */
  scamper_queue_wait(task->queue, ping->probe_wait * 1000);

  return;

 err:
  return;
}

static void do_ping_handle_icmp(scamper_task_t *task, scamper_icmp_resp_t *ir)
{
  scamper_ping_t       *ping  = task->data;
  ping_state_t         *state = task->state;
  scamper_ping_reply_t *reply = NULL;
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
  if(!state->sent_probe)
    return;

  scamper_icmp_resp_print(ir);

  /* if this is an echo reply packet, then check the id and sequence */
  if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir))
    {
      /* if the response is not for us, then move on */
      if(ping->probe_method != SCAMPER_PING_METHOD_ICMP_ECHO ||
	 ir->ir_icmp_id != (pid & 0xffff) ||
	 ir->ir_icmp_seq != state->seq)
	{
	  return;
	}

      seq = ir->ir_icmp_seq;
    }
  else if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir))
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_ICMP_ECHO_REQ(ir) == 0 ||
	     ir->ir_inner_icmp_id != (pid & 0xffff) ||
	     ir->ir_inner_icmp_seq != state->seq)
	    {
	      return;
	    }

	  seq = ir->ir_inner_icmp_seq;
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

	      /*
	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq_cur - 1;
	      */

	      seq = state->seq;
	    }
	  else return;
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

	      /*
	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq_cur - 1;
	      */

	      seq = state->seq;
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
  /* timeval_diff_tv(&reply->rtt, &state->tx, &ir->ir_rx); */
  reply->tx = state->tx;
  reply->rx = ir->ir_rx;
  reply->reply_size  = ir->ir_ip_size;
  reply->icmp_type   = ir->ir_icmp_type;
  reply->icmp_code   = ir->ir_icmp_code;
  reply->icmp_q_ip_ttl = ir->ir_inner_ip_ttl;  /* == zero if not available */

  if(ir->ir_af == AF_INET)
    {
      reply->reply_ipid = ir->ir_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;

      reply->probe_ipid = state->ipid;
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

  /* put the reply into the ping table */
  scamper_ping_reply_append(ping, reply);

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  state->replies++;
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

  ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);
  return;
}

static void do_ping_write_reply(scamper_task_t *task, scamper_ping_t *ping,
				scamper_ping_reply_t *reply)
{
  const char *msg = NULL;
  size_t msg_len = 0;
  char src_addr[40], dest_addr[40], reply_addr[40];
  size_t opts;

  scamper_addr_tostr(ping->src, src_addr, 40);
  scamper_addr_tostr(ping->dst, dest_addr, 40);
  scamper_addr_tostr(reply->addr, reply_addr, 40);

  INIT_CMESSAGE(resp_words, ping->reqnum, PING_RESP);
  SET_ADDRESS_CWORD(resp_words, 1, SRC, src_addr);
  SET_ADDRESS_CWORD(resp_words, 2, DEST, dest_addr);
  SET_UINT_CWORD(resp_words, 3, UDATA, ping->user_data);
  SET_TIMEVAL_CWORD(resp_words, 4, TX, &reply->tx);
  SET_TIMEVAL_CWORD(resp_words, 5, RX, &reply->rx);
  SET_UINT_CWORD(resp_words, 6, PROBE_TTL, ping->probe_ttl);
  SET_UINT_CWORD(resp_words, 7, PROBE_IPID, reply->probe_ipid);
  SET_ADDRESS_CWORD(resp_words, 8, REPLY_SRC, reply_addr);
  SET_UINT_CWORD(resp_words, 9, REPLY_TTL, reply->reply_ttl);
  SET_UINT_CWORD(resp_words, 10, REPLY_IPID, reply->reply_ipid);

  opts = 11;
  if(SCAMPER_PING_REPLY_IS_ICMP(reply))
    {
      uint32_t icmp_value = (reply->icmp_type << 8) | reply->icmp_code;
      SET_UINT_CWORD(resp_words, 11, REPLY_ICMP, icmp_value);

      if(!SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply))
        {
	  opts = 12;
	  SET_UINT_CWORD(resp_words, 12, REPLY_QTTL, reply->icmp_q_ip_ttl);
	}
    }
  else /* tcp */
    {
      SET_UINT_CWORD(resp_words, 11, REPLY_TCP, reply->tcp_flags);
    }

  msg = create_control_message(resp_words, CMESSAGE_LEN(opts), &msg_len);
  assert(msg_len != 0);
  send_response(task, msg);
}

static void do_ping_write_nonresponse(scamper_task_t *task,scamper_ping_t *ping)
{
  const char *msg = NULL;
  size_t msg_len = 0;
  char src_addr[40], dest_addr[40];

  scamper_addr_tostr(ping->src, src_addr, 40);
  scamper_addr_tostr(ping->dst, dest_addr, 40);

  INIT_CMESSAGE(resp_words, ping->reqnum, RESP_TIMEOUT);
  SET_ADDRESS_CWORD(resp_words, 1, SRC, src_addr);
  SET_ADDRESS_CWORD(resp_words, 2, DEST, dest_addr);
  SET_UINT_CWORD(resp_words, 3, UDATA, ping->user_data);
  SET_TIMEVAL_CWORD(resp_words, 4, TX, &ping->start);
  SET_UINT_CWORD(resp_words, 5, PROBE_TTL, ping->probe_ttl);

  msg = create_control_message(resp_words, CMESSAGE_LEN(5), &msg_len);
  assert(msg_len != 0);
  send_response(task, msg);
}

static void do_ping_write_error(scamper_task_t *task, scamper_ping_t *ping,
				const char *txt)
{
  const char *msg = NULL;
  size_t msg_len = 0;

  INIT_CMESSAGE(resp_words, ping->reqnum, SEND_ERROR);
  SET_STR_CWORD(resp_words, 1, TXT, txt, strlen(txt));
  SET_UINT_CWORD(resp_words, 2, STOP_REASON, ping->stop_reason);
  SET_UINT_CWORD(resp_words, 3, STOP_DATA, ping->stop_data);
  msg = create_control_message(resp_words, CMESSAGE_LEN(3), &msg_len);
  assert(msg_len != 0);
  send_response(task, msg);
}

static void do_ping_write(scamper_task_t *task)
{
  scamper_ping_t *ping = (scamper_ping_t *)task->data;
  scamper_ping_reply_t *reply = NULL;
  char buf[128];

  if(ping->stop_reason == SCAMPER_PING_STOP_NONE
     || ping->stop_reason == SCAMPER_PING_STOP_COMPLETED)
    {
      if((reply = ping->ping_reply) != NULL)
        {
	  while(reply)
	    {
	      do_ping_write_reply(task, ping, reply);
	      reply = reply->next;
	    }
	}
      else
        {
	  do_ping_write_nonresponse(task, ping);
	}
    }
  else if (ping->stop_reason == SCAMPER_PING_STOP_ERROR)
    {
      do_ping_write_error(task, ping, "ping failed");
    }
  else
    {
      snprintf(buf, 128, "internal error: unknown stop_reason %d",
	       ping->stop_reason);
      do_ping_write_error(task, ping, buf);
      assert(0);
    }
}

static void do_ping_free(scamper_task_t *task)
{
  scamper_ping_t *ping;
  ping_state_t *state;

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

      free(state);
    }

  return;
}

#if 0
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
#endif

/*
 * scamper_do_ping_alloc
 *
 * given a string representing a ping task, parse the parameters and assemble
 * a ping.  return the ping structure so that it is all ready to go.
 *
 */
scamper_ping_t *scamper_do_ping_alloc(const control_word_t *words,
				      size_t word_count,
				      const char **error_msg)
{
  uint8_t   probe_wait    = SCAMPER_DO_PING_PROBEWAIT_DEF;
  uint8_t   probe_ttl     = SCAMPER_DO_PING_PROBETTL_DEF;
  uint8_t   probe_tos     = SCAMPER_DO_PING_PROBETOS_DEF;
  uint8_t   probe_method  = SCAMPER_DO_PING_PROBEMETHOD_DEF;
  uint16_t  probe_cksum   = 0;
  uint16_t  probe_sport   = (pid & 0xffff) | 0x8000;
  uint16_t  probe_dport   = 33435;
  uint16_t  reply_count   = SCAMPER_DO_PING_REPLYCOUNT_DEF;
  uint16_t  probe_size    = 0; /* unset */
  uint16_t  pattern_len   = 0;
  uint8_t   pattern_bytes[SCAMPER_DO_PING_PATTERN_MAX/2];
  uint32_t  user_data     = 0;
  uint8_t   opt_set_cksum = 0;  /* user provided checksum */
  const char *src         = NULL;
  const char *dest        = NULL;
  const char *meth        = NULL;
  int       af;

  scamper_ping_t *ping = NULL;
  size_t i;

  for(i = 2; i < word_count; i++)
    {
      switch(words[i].cw_code)
	{
	case KC_DEST_OPT:
	  dest = words[i].cw_address;
	  break;

	/* the ttl to probe with */
	case KC_TTL_OPT:
	  probe_ttl = words[i].cw_uint;
	  break;

	case KC_METH_OPT:
	  meth = words[i].cw_symbol;
	  if(strcasecmp(meth, "icmp-echo") == 0)
	    probe_method = SCAMPER_PING_METHOD_ICMP_ECHO;
	  else if(strcasecmp(meth, "tcp-ack") == 0)
	    probe_method = SCAMPER_PING_METHOD_TCP_ACK;
	  else if(strcasecmp(meth, "udp") == 0)
	    probe_method = SCAMPER_PING_METHOD_UDP;
	  else
	    {
	      *error_msg = "invalid 'meth' option value";
	      return NULL;
	    }
	  break;

	case KC_CKSUM_OPT:
	  probe_cksum = words[i].cw_uint;
	  opt_set_cksum = 1;
	  break;

	case KC_SPORT_OPT:
	  probe_sport = words[i].cw_uint;
	  break;

	case KC_DPORT_OPT:
	  probe_dport = words[i].cw_uint;
	  break;

	case KC_UDATA_OPT:
	  user_data = words[i].cw_uint;
	  break;

	default: /* XXX need better reporting */
	  *error_msg = "invalid option to 'ping' command";
	  return NULL;

#if 0
        /* how long to wait between sending probes */
        case PING_OPT_PROBEWAIT:
          probe_wait = (uint8_t)tmp;
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

        case PING_OPT_SRCADDR:
          if(src != NULL)
            goto err;
          src = opt->str;
          break;

        /* the tos bits to include in each probe */
        case PING_OPT_PROBETOS:
          probe_tos = (uint8_t)tmp;
          break;
#endif
	}
    }

  /* XXX need validation of option values & checking of required options */

  /* allocate the ping object and determine the address to probe */
  if((ping = scamper_ping_alloc()) == NULL)
    {
      goto err;
    }
  if((ping->dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,dest)) == NULL)
    {
      goto err;
    }
  ping->probe_method = probe_method;

  /*
  ** Note: If the user provided a checksum to set for ICMP/UDP, then we must
  ** make room for 2 bytes in the payload.  (The user can't set the TCP
  ** checksum.)
  */
  /* ensure the probe size specified is suitable */
  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  if(probe_size == 0)
	    probe_size = SCAMPER_DO_PING_PROBESIZE_V4_DEF;
	  else if(probe_size < SCAMPER_DO_PING_PROBESIZE_V4_MIN)
	    goto err;

	  if(opt_set_cksum && probe_size < SCAMPER_DO_PING_PROBESIZE_V4_MIN + 2)
	    {
	      probe_size = SCAMPER_DO_PING_PROBESIZE_V4_MIN + 2;
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  if(probe_size != 0 && probe_size != 40)
	    goto err;
	  probe_size = 40;

	  if(opt_set_cksum) opt_set_cksum = 0;  /* not supported */
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  /* this is the same probe size used for UDP traceroute; 20+8+12 */
	  if(probe_size != 0 && probe_size != 40)
	    goto err;
	  probe_size = 40;

	  if(opt_set_cksum) opt_set_cksum = 0;  /* not supported */
	}
    }
  else if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(opt_set_cksum) opt_set_cksum = 0;  /* XXX not supported with IPv6 */

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

  ping->reqnum       = words[0].cw_uint;
  ping->user_data    = user_data;
  ping->probe_size   = probe_size;
  ping->probe_wait   = probe_wait;
  ping->probe_cksum  = probe_cksum;
  ping->probe_ttl    = probe_ttl;
  ping->probe_tos    = probe_tos;
  ping->probe_sport  = probe_sport;
  ping->probe_dport  = probe_dport;
  ping->reply_count  = reply_count;
  ping->opt_set_cksum = opt_set_cksum;
  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

scamper_task_t *scamper_do_ping_alloctask(scamper_ping_t *ping,
					  scamper_writebuf_t *wb)
{
  scamper_task_t *task;
  ping_state_t   *state;
  void           *addr;

#ifdef _WIN32
  scamper_rt_rec_t rr;
#endif

  /* firstly, allocate the task structure */
  if((task = scamper_task_alloc(ping, &ping_funcs)) == NULL)
    {
      goto err;
    }

  task->wb = wb;

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

  /* allocate the necessary state to keep track of probes */
  if((task->state = malloc_zero(sizeof(ping_state_t))) == NULL)
    {
      goto err;
    }
  state = task->state;

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
      if(g_gateway_sa)
        {
	  if((state->pr = scamper_fd_dl(g_interface)) == NULL)
	    {
	      scamper_debug(__func__, "could not get dl for %d", g_interface);
	      goto err;
	    }
	  state->dl_hdr = scamper_dl_hdr_alloc(state->pr, ping->src, ping->dst,
					       g_gateway_sa);
	  if(state->dl_hdr == NULL)
	    {
	      goto err;
	    }
	  if(random_u32(&state->tcp_seq) != 0
	     || random_u32(&state->tcp_ack) != 0)
	    goto err;
	}
      else
        {
	  if((state->rt = scamper_fd_rtsock()) == NULL)
	    goto err;
	}
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
