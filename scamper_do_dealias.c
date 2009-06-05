/*
 * scamper_do_dealias.c
 *
 * $Id: scamper_do_dealias.c,v 1.51 2009/05/29 02:43:56 mjl Exp $
 *
 * Copyright (C) 2008-2009 The University of Waikato
 * Author: Matthew Luckie
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
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
#define strcasecmp _stricmp
#endif

#include <sys/types.h>

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
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "scamper_task.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_rtsock.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "scamper_do_dealias.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

static scamper_task_funcs_t funcs;

/* the default source port to use when tracerouting */
static uint16_t             default_sport;

/* packet buffer for generating the payload of each packet */
static uint8_t             *pktbuf     = NULL;
static size_t               pktbuf_len = 0;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define DEALIAS_OPT_NOBS         1
#define DEALIAS_OPT_DPORT        2
#define DEALIAS_OPT_FUDGE        3
#define DEALIAS_OPT_METHOD       4
#define DEALIAS_OPT_REPLYC       5
#define DEALIAS_OPT_PROBEDEF     6
#define DEALIAS_OPT_ATTEMPTS     7
#define DEALIAS_OPT_WAIT_ROUND   8
#define DEALIAS_OPT_SPORT        9
#define DEALIAS_OPT_TTL          10
#define DEALIAS_OPT_USERID       11
#define DEALIAS_OPT_WAIT_TIMEOUT 12
#define DEALIAS_OPT_WAIT_PROBE   13
#define DEALIAS_OPT_EXCLUDE      14

static const scamper_option_in_t opts[] = {
  {'b', NULL, DEALIAS_OPT_NOBS,         SCAMPER_OPTION_TYPE_NULL},
  {'d', NULL, DEALIAS_OPT_DPORT,        SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, DEALIAS_OPT_FUDGE,        SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, DEALIAS_OPT_METHOD,       SCAMPER_OPTION_TYPE_STR},
  {'o', NULL, DEALIAS_OPT_REPLYC,       SCAMPER_OPTION_TYPE_NUM},
  {'p', NULL, DEALIAS_OPT_PROBEDEF,     SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, DEALIAS_OPT_ATTEMPTS,     SCAMPER_OPTION_TYPE_NUM},
  {'r', NULL, DEALIAS_OPT_WAIT_ROUND,   SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, DEALIAS_OPT_SPORT,        SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, DEALIAS_OPT_TTL,          SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, DEALIAS_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, DEALIAS_OPT_WAIT_TIMEOUT, SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, DEALIAS_OPT_WAIT_PROBE,   SCAMPER_OPTION_TYPE_NUM},
  {'x', NULL, DEALIAS_OPT_EXCLUDE,      SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

#define DEALIAS_PROBEDEF_OPT_CSUM  1
#define DEALIAS_PROBEDEF_OPT_DPORT 2
#define DEALIAS_PROBEDEF_OPT_IP    3
#define DEALIAS_PROBEDEF_OPT_PROTO 4
#define DEALIAS_PROBEDEF_OPT_SPORT 5
#define DEALIAS_PROBEDEF_OPT_TTL   6

static const scamper_option_in_t probedef_opts[] = {
  {'c', NULL, DEALIAS_PROBEDEF_OPT_CSUM,  SCAMPER_OPTION_TYPE_STR},
  {'d', NULL, DEALIAS_PROBEDEF_OPT_DPORT, SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, DEALIAS_PROBEDEF_OPT_IP,    SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, DEALIAS_PROBEDEF_OPT_PROTO, SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, DEALIAS_PROBEDEF_OPT_SPORT, SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, DEALIAS_PROBEDEF_OPT_TTL,   SCAMPER_OPTION_TYPE_NUM},
};
static const int probedef_opts_cnt = SCAMPER_OPTION_COUNT(probedef_opts);

const char *scamper_do_dealias_usage(void)
{
  return
    "dealias [-b] [-d dport] [-f fudge] [-m method] [-o replyc]\n"
    "        [-p '[-c sum] [-d dp] [-i ip] [-P meth] [-s sp] [-t ttl]']\n"
    "        [-q attempts] [-r wait-round] [-s sport] [-t ttl]\n"
    "        [-U userid] [-w wait-timeout] [-W wait-probe] [-x exclude]\n";
}

typedef struct dealias_probe
{
  scamper_dealias_probe_t     *probe;
  struct dealias_probe        *next;
  uint16_t                     icmpseq;
} dealias_probe_t;

typedef struct dealias_prefixscan_state
{
  scamper_addr_t             **addrs;
  int                          addrc;
  scamper_addr_t             **aaliases;
  int                          aaliasc;
  int                          attempt; 
  int                          seq;
  int                          round0;
  int                          round;
  int                          replyc;
#ifndef _WIN32
  scamper_fd_t                *rt;
#endif
} dealias_prefixscan_state_t;

typedef struct dealias_state
{
  scamper_fd_t                *icmp;
  scamper_fd_t               **probefds;
  scamper_dl_hdr_t           **dlhdrs;
  scamper_dealias_probedef_t  *probedefs;
  uint32_t                     probedefc;
  uint32_t                     probedefi;
  uint32_t                     probe;
  uint32_t                     round;
  struct timeval               next_round;
  splaytree_t                 *probes;
  int                          needtcp;
  dealias_prefixscan_state_t  *prefixscan;
#ifndef _WIN32
  scamper_fd_t                *rt;
#endif
} dealias_state_t;

static void dealias_handleerror(scamper_task_t *task, int error)
{
  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
  return;
}

static void dealias_result(scamper_task_t *task, uint8_t result)
{
  if(result == SCAMPER_DEALIAS_RESULT_NONE)
    scamper_debug(__func__, "none");
  else if(result == SCAMPER_DEALIAS_RESULT_ALIASES)
    scamper_debug(__func__, "aliases");
  else if(result == SCAMPER_DEALIAS_RESULT_NOTALIASES)
    scamper_debug(__func__, "not aliases");
  else
    scamper_debug(__func__, "%d", result);

  ((scamper_dealias_t *)task->data)->result = result;
  scamper_queue_done(task->queue, 0);
  return;
}

static int dealias_prefixscan_aalias_cmp(const void *va, const void *vb)
{
  const scamper_addr_t *a = *((const scamper_addr_t **)va);
  const scamper_addr_t *b = *((const scamper_addr_t **)vb);
  return scamper_addr_cmp(a, b);
}

static void dealias_prefixscan_array_free(scamper_addr_t **addrs, int addrc)
{
  int i;

  if(addrs == NULL)
    return;

  for(i=0; i<addrc; i++)
    if(addrs[i] != NULL)
      scamper_addr_free(addrs[i]);

  free(addrs);
  return;
}

static int dealias_prefixscan_array_add(scamper_dealias_t *dealias,
					scamper_addr_t ***out, int *outc,
					struct in_addr *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_addr_t **array = *out;
  scamper_addr_t *sa;

  /* convert the in_addr into something that scamper deals with */
  sa = scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV4, addr);
  if(sa == NULL)
    {
      printerror(errno, strerror, __func__, "could not get addr");
      return -1;
    }

  /*
   * don't consider this address if it is the same as the address
   * we are trying to find an alias for, or it is in the exclude list.
   */
  if(scamper_addr_cmp(prefixscan->a, sa) == 0 ||
     scamper_dealias_prefixscan_xs_in(dealias, sa) != 0)
    {
      scamper_addr_free(sa);
      return 0;
    }

  /* add the scamper address to the array */
  if(array_insert((void ***)&array, outc, sa, NULL) != 0)
    {
      printerror(errno, strerror, __func__, "could not add addr");
      scamper_addr_free(sa);
      return -1;
    }

  *out = array;
  return 0;
}

/*
 * dealias_prefixscan_array:
 *
 * figure out what the next address to scan will be, based on what the
 * previously probed address was.  below are examples of the order in which
 * addresses should be probed given a starting address.  addresses in
 * prefixes less than /30 could be probed in random order.
 *
 * 00100111 39        00100010 34        00101001 41       00100000 32
 * 00100110 38 /31    00100001 33        00101010 42       00100001 33 /31
 * 00100101 37        00100000 32        00101000 40       00100010 34
 * 00100100 36 /30    00100011 35 /30    00101011 43 /30   00100011 35 /30
 * 00100011 35        00100100 36        00101100 44
 * 00100010 34        00100101 37        00101101 45
 * 00100001 33        00100110 38        00101110 46
 * 00100000 32 /29    00100111 39 /29    00101111 47 /29
 * 00101000 40        00101000 40        00100000 32
 * 00101001 41        00101001 41        00100001 33
 * 00101010 42        00101010 42
 * 00101011 43
 * 00101100 44
 * 00101101 45
 * 00101110 46
 * 00101111 47 /28
 *
 */
static int dealias_prefixscan_array(scamper_dealias_t *dealias,
				    scamper_addr_t ***out, int *outc)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_addr_t **array = NULL;
  uint32_t hostid, netid, mask;
  uint32_t slash30[4][3] = {{1, 2, 3}, {2, 0, 3}, {1, 0, 3}, {2, 1, 0}};
  uint32_t cnt[] = {4, 8, 16, 32, 64, 128};
  uint32_t bit;
  struct in_addr a;
  int pre, i;

  memcpy(&a, prefixscan->b->addr, sizeof(a));
  *outc = 0;

  /* if we've been instructed only to try /31 pair */
  if(prefixscan->prefix == 31)
    {
      netid  = ntohl(a.s_addr) & ~0x1;
      hostid = ntohl(a.s_addr) &  0x1;

      if(hostid == 1)
	a.s_addr = htonl(netid | 0);
      else
	a.s_addr = htonl(netid | 1);

      if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	goto err;

      *out = array;
      return 0;
    }

  /* when probing a /30 the first three probes have a particular order */
  mask   = 0x3;
  netid  = ntohl(a.s_addr) & ~mask;
  hostid = ntohl(a.s_addr) &  mask;
  for(i=0; i<3; i++)
    {
      a.s_addr = htonl(netid | slash30[hostid][i]);
      if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	goto err;
    }

  for(pre = 29; pre >= prefixscan->prefix; pre--)
    {
      bit   = (0x1 << (31-pre));
      mask |= bit;

      memcpy(&a, prefixscan->b->addr, sizeof(a));
      netid = ntohl(a.s_addr) & ~mask;

      if((ntohl(a.s_addr) & bit) != 0)
	bit = 0;

      for(hostid=0; hostid<cnt[29-pre]; hostid++)
	{
	  a.s_addr = htonl(netid | bit | hostid);
	  if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	    goto err;
	}
    }

  *out = array;
  return 0;

 err:
  dealias_prefixscan_array_free(array, *outc);
  return -1;
}

static int dealias_probe_cmp(const void *va, const void *vb)
{
  dealias_probe_t *a = (dealias_probe_t *)va;
  dealias_probe_t *b = (dealias_probe_t *)vb;
  if(a->probe->ipid < b->probe->ipid) return -1;
  if(a->probe->ipid > b->probe->ipid) return  1;
  return 0;
}

static scamper_dealias_probe_t *
dealias_probe_udp_find(dealias_state_t *state, scamper_icmp_resp_t *ir)
{
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t findme_probe;
  dealias_probe_t *dp, findme;
  scamper_addr_t addr;

  if(scamper_icmp_resp_inner_dst(ir, &addr) != 0)
    return NULL;

  findme_probe.ipid = ir->ir_inner_ip_id;
  findme.probe = &findme_probe;

  for(dp = splaytree_find(state->probes, &findme); dp != NULL; dp = dp->next)
    {
      def = dp->probe->probedef;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def) == 0 ||
	 def->un.udp.sport != ir->ir_inner_udp_sport ||
	 scamper_addr_cmp(def->dst, &addr) != 0)
	{
	  continue;
	}

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	{
	  if(def->un.udp.dport == ir->ir_inner_udp_dport)
	    return dp->probe;
	}
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	{
	  if(def->un.udp.dport + dp->probe->seq == ir->ir_inner_udp_dport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_tcp_find(dealias_state_t *state, scamper_icmp_resp_t *ir)
{
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t findme_probe;
  dealias_probe_t *dp, findme;
  scamper_addr_t addr;

  if(scamper_icmp_resp_inner_dst(ir, &addr) != 0)
    return NULL;

  findme_probe.ipid = ir->ir_inner_ip_id;
  findme.probe = &findme_probe;

  for(dp = splaytree_find(state->probes, &findme); dp != NULL; dp = dp->next)
    {
      def = dp->probe->probedef;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) == 0 ||
	 def->un.tcp.dport != ir->ir_inner_tcp_dport ||
	 scamper_addr_cmp(def->dst, &addr) != 0)
	{
	  continue;
	}

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  if(def->un.tcp.sport == ir->ir_inner_tcp_sport)
	    return dp->probe;
	}
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT)
	{
	  if(def->un.tcp.sport + dp->probe->seq == ir->ir_inner_tcp_sport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_icmp_find(dealias_state_t *state, scamper_icmp_resp_t *ir)
{
  scamper_dealias_probedef_t *probedef;
  scamper_dealias_probe_t findme_probe;
  dealias_probe_t *dp, findme;
  scamper_addr_t addr;

  if(scamper_icmp_resp_inner_dst(ir, &addr) != 0)
    return NULL;

  findme_probe.ipid = ir->ir_inner_ip_id;
  findme.probe = &findme_probe;

  for(dp = splaytree_find(state->probes, &findme); dp != NULL; dp = dp->next)
    {
      /*
       * check that the icmp probe matches what we would have sent.
       * don't check the checksum as it can be modified.
       */
      probedef = dp->probe->probedef;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(probedef) &&
	 probedef->un.icmp.type == ir->ir_inner_icmp_type &&
	 probedef->un.icmp.code == ir->ir_inner_icmp_code &&
	 probedef->un.icmp.id   == ir->ir_inner_icmp_id   &&
	 dp->icmpseq            == ir->ir_inner_icmp_seq  &&
	 scamper_addr_cmp(probedef->dst, &addr) == 0)
	{
	  return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_echoreq_find(scamper_dealias_t *dealias, scamper_icmp_resp_t *ir)
{
  scamper_dealias_probedef_t *probedef;
  scamper_dealias_probe_t *probe;
  scamper_addr_t addr;
  uint32_t p, i;

  if(ir->ir_icmp_seq >= dealias->probec)
    return NULL;

  p = dealias->probec / 65536;

  if((dealias->probec % 65536) > ir->ir_icmp_seq)
    i = (p * 65536) + ir->ir_icmp_seq;
  else
    i = ((p-1) * 65536) + ir->ir_icmp_seq;

  if(scamper_icmp_resp_src(ir, &addr) != 0)
    return NULL;

  for(;;)
    {
      probe    = dealias->probes[i];
      probedef = probe->probedef;

      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(probedef) &&
	 probedef->un.icmp.type == ICMP_ECHO &&
	 probedef->un.icmp.code == 0 &&
	 probedef->un.icmp.id   == ir->ir_icmp_id &&
	 scamper_addr_cmp(&addr, probedef->dst) == 0)
	{
	  return probe;
	}

      if(i >= 65536)
	i -= 65536;
      else
	break;
    }

  return NULL;
}

static int dealias_state_probefd(dealias_state_t *state, uint32_t i,
				 scamper_dealias_probedef_t *def)
{
  /* TCP probing handle is dealt with later */
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      /* get the first probedef which needs a datalink socket */
      if(state->needtcp == 0)
	{
	  state->needtcp   = 1;
	  state->probedefi = i;
	}
      return 0;
    }

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    state->probefds[i] = scamper_fd_udp4(NULL, def->un.udp.sport);
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    state->probefds[i] = scamper_fd_icmp4(NULL);
  else
    return -1;

  /* check that the fd that was just requested was obtained */
  if(state->probefds[i] != NULL)
    return 0;

  return -1;
}

static void dealias_mercator_handlereply(scamper_task_t *task,
					 scamper_dealias_probe_t *probe,
					 scamper_dealias_reply_t *reply)
{
  if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) &&
     scamper_addr_cmp(probe->probedef->dst, reply->src) != 0)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
    }
  else
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
    }
  return;
}

static void dealias_mercator_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = task->data;
  scamper_dealias_mercator_t *mercator = dealias->data;

  if(dealias->probec < mercator->attempts)
    {
      scamper_queue_probe(task->queue);
    }
  else
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
    }

  return;
}

static int dealias_ally_allzero(scamper_dealias_t *dealias,
				scamper_dealias_ally_t *ally)
{
  uint32_t i;
  uint16_t j;

  for(i=0; i<dealias->probec; i++)
    {
      assert(dealias->probes[i] != NULL);
      for(j=0; j<dealias->probes[i]->replyc; j++)
	{
	  assert(dealias->probes[i]->replies[j] != NULL);
	  if(dealias->probes[i]->replies[j]->ipid != 0)
	    return 0;
	}
    }

  return 1;
}

static void dealias_ally_handlereply(scamper_task_t *task,
				     scamper_dealias_probe_t *probe,
				     scamper_dealias_reply_t *reply)
{
  static int (*const inseq[])(scamper_dealias_t *, uint16_t) = {
    scamper_dealias_ally_inseq,
    scamper_dealias_ally_inseqbs,
  };
  scamper_dealias_t       *dealias = task->data;
  scamper_dealias_ally_t  *ally    = dealias->data;
  scamper_dealias_probe_t *p;
  scamper_dealias_reply_t *r;
  uint32_t i;
  int bs;

  /* check to see if we have replies for all sent probes yet */
  if(dealias->probec != ally->attempts)
    return;

  for(i=0; i<dealias->probec; i++)
    {
      p = dealias->probes[i];
      if(p->replyc != 1)
	return;
      r = p->replies[0];

      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(p->probedef))
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(r) == 0)
	    return;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(p->probedef))
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP_ECHO_REPLY(r) == 0)
	    return;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(p->probedef))
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_TCP(r) == 0)
	    return;
	}
      else return;
    }

  if(SCAMPER_DEALIAS_ALLY_IS_NOBS(dealias) == 0)
    bs = 0;
  else
    bs = 1;

  if(inseq[bs](dealias, ally->fudge) != 0)
    dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
  else if(dealias_ally_allzero(dealias, ally) != 0)
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);

  return;
}

static void dealias_ally_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t      *dealias = task->data;
  scamper_dealias_ally_t *ally    = dealias->data;

  if(dealias->probec == ally->attempts)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
    }

  return;
}

static void dealias_radargun_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = task->data;
  dealias_state_t            *state    = task->state;
  scamper_dealias_radargun_t *radargun = dealias->data;

  /* check to see if we are now finished */
  if(state->round == radargun->attempts)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  /* not finished, keep going ... */
  scamper_queue_probe(task->queue);
  return;
}

static int dealias_prefixscan_next(scamper_task_t *task)
{
  scamper_dealias_t *dealias = task->data;
  dealias_state_t *state = task->state;
  scamper_addr_t *addr = state->prefixscan->addrs[state->probedefc-1];
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probedef_t *def;
  uint32_t *defids = NULL, p;
  size_t size;

  /*
   * if the address we'd otherwise probe has been observed as an alias of
   * prefixscan->a, then we don't need to bother probing it.
   */
  if(array_find((void **)state->prefixscan->aaliases,
		state->prefixscan->aaliasc, addr,
		dealias_prefixscan_aalias_cmp) != NULL)
    {
      prefixscan->ab = scamper_addr_use(addr);
      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
      return 0;
    }

  if((defids = malloc(sizeof(uint32_t) * dealias->probec)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc defids");
      goto err;
    }

  for(p=0; p<dealias->probec; p++)
    defids[p] = dealias->probes[p]->probedef->id;

  if(scamper_dealias_prefixscan_probedef_add(dealias, addr) != 0)
    {
      printerror(errno, strerror, __func__, "could not add probedef");
      goto err;
    }

  for(p=0; p<dealias->probec; p++)
    dealias->probes[p]->probedef = &prefixscan->probedefs[defids[p]];
  free(defids); defids = NULL;

  state->probedefs = prefixscan->probedefs;
  state->probedefc = prefixscan->probedefc;
  def = &state->probedefs[state->probedefc-1];

  /* get the source address for the new probedef */
  if((def->src = scamper_getsrc(def->dst)) == NULL)
    goto err;

  /* reallocate the probefd array to make way for the new probefd */
  size = sizeof(scamper_fd_t *) * state->probedefc;
  if(realloc_wrap((void **)&state->probefds, size) != 0)
    {
      printerror(errno, strerror, __func__, "could not realloc probefds");
      return -1;
    }
  state->probefds[state->probedefc-1] = NULL;

  /* get the fd to probe with */
  state->needtcp = 0;
  if(dealias_state_probefd(state, state->probedefc-1, def) != 0)
    goto err;

  if(state->needtcp != 0)
    {
      /* if we will be probing with tcp, we'll need to use the route socket */
      state->rt = state->prefixscan->rt;

      /* and we'll also need a layer-2 header for the tcp probe */
      size = sizeof(scamper_dl_hdr_t *) * state->probedefc;
      if(realloc_wrap((void **)&state->dlhdrs, size) != 0)
	{
	  printerror(errno, strerror, __func__, "could not realloc dlhdrs");
	  goto err;
	}
      state->dlhdrs[state->probedefc-1] = NULL;
    }

  return 0;

 err:
  if(defids != NULL) free(defids);
  return -1;
}

static void dealias_prefixscan_handlereply(scamper_task_t *task,
					   scamper_dealias_probe_t *probe,
					   scamper_dealias_reply_t *reply)
{
  static int (*const inseq[])(scamper_dealias_probe_t **, int, uint16_t) = {
    scamper_dealias_ipid_inseq,
    scamper_dealias_ipid_inseqbs,
  };
  scamper_dealias_t *dealias = task->data;
  dealias_state_t *state = task->state;
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probe_t **probes = NULL;
  uint32_t defid;
  int p, s, bs, seq;

  /* if the reply is not for the most recently sent probe */
  if(probe != dealias->probes[dealias->probec-1])
    {
      return;
    }

  /* if the reply is not the first reply for this probe */
  if(probe->replyc != 1)
    {
      return;
    }

  /*
   * if we are currently waiting for our turn to probe, then for now
   * ignore the late response.
   */
  if(scamper_queue_isprobe(task->queue) != 0)
    {
      return;
    }

  /* check if we should count this reply as a valid response */
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(probe->probedef))
    {
      if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply))
	state->prefixscan->replyc++;
      else
	return;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(probe->probedef))
    {
      if(SCAMPER_DEALIAS_REPLY_IS_ICMP_ECHO_REPLY(reply))
	state->prefixscan->replyc++;
      else
	return;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(probe->probedef))
    {
      if(SCAMPER_DEALIAS_REPLY_IS_TCP(reply))
	state->prefixscan->replyc++;
      else
	return;
    }
  else return;

  /*
   * if we sent a UDP probe, and got a port unreachable message back from a
   * different interface, then we might be able to use that for alias
   * resolution.
   */
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(probe->probedef) &&
     SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) &&
     scamper_addr_cmp(probe->probedef->dst, reply->src) != 0)
    {
      if(probe->probedef->id == 0)
	{
	  /*
	   * if the reply is for prefixscan->a, then keep a record of the
	   * address of the interface used in the response.
	   */
	  if(array_find((void **)state->prefixscan->aaliases,
			state->prefixscan->aaliasc, reply->src,
			dealias_prefixscan_aalias_cmp) == NULL)
	    {
	      if(array_insert((void ***)&state->prefixscan->aaliases,
			      &state->prefixscan->aaliasc, reply->src,
			      dealias_prefixscan_aalias_cmp) != 0)
		{
		  printerror(errno, strerror, __func__,
			     "could not add to aaliases");
		  goto err;
		}
	      scamper_addr_use(reply->src);
	    }
	}
      else
	{
	  /*
	   * if the address used to reply is probedef->a, or is one of the
	   * aliases previously observed for a, then we infer aliases.
	   */
	  if(scamper_addr_cmp(reply->src, prefixscan->a) == 0 ||
	     array_find((void **)state->prefixscan->aaliases,
			state->prefixscan->aaliasc, reply->src,
			dealias_prefixscan_aalias_cmp) != NULL)
	    {
	      prefixscan->ab = scamper_addr_use(probe->probedef->dst);
	      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	      return;
	    }
	}
    }

  /*
   * another probe received in sequence.
   * we will probably send another probe, so reset attempts
   */
  seq = ++state->prefixscan->seq;
  state->prefixscan->attempt = 0;

  assert(seq >= 1 && seq <= prefixscan->replyc);

  /*
   * if we don't have a reply from each IP address yet, then keep probing.
   * ideally, this could be optimised to use the previous observed IP-ID
   * for probedef zero if we have probed other probedefs in the interim and
   * have just obtained a reply.
   */
  if(seq < 2)
    {
      if(state->probe != 0)
	{
	  state->probe = 0;
	  return;
	}

      if(state->probedefc == 1)
	{
	  /* figure out what we're going to probe next */
	  if(dealias_prefixscan_next(task) != 0)
	    goto err;

	  /* if it turns out we don't need to probe, handle that */
	  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	    return;
	}

      state->probe = state->probedefc-1;
      return;
    }

  if((probes = malloc_zero(sizeof(scamper_dealias_probe_t *) * seq)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc probes");
      goto err;
    }
  probes[seq-1] = probe;

  /* if the reply was not for the first probe, then skip over earlier probes */
  p = dealias->probec-2; defid = probes[seq-1]->probedef->id;
  while(p >= 0 && dealias->probes[p]->probedef->id == defid)
    p--;
  if(p<0)
    goto err;

  for(s=seq-1; s>0; s--)
    {
      if(probes[s]->probedef->id == 0)
	defid = state->probedefc - 1;
      else
	defid = 0;

      if(p < 0)
	goto err;

      while(p >= 0)
	{
	  assert(defid == dealias->probes[p]->probedef->id);

	  /* skip over any unresponded to probes */
	  if(dealias->probes[p]->replyc == 0)
	    {
	      p--;
	      continue;
	    }

	  /* record the probe for this defid */
	  probes[s-1] = dealias->probes[p];

	  /* skip over any probes that proceeded this one with same defid */
	  while(p >= 0 && dealias->probes[p]->probedef->id == defid)
	    p--;

	  break;
	}
    }

  if(SCAMPER_DEALIAS_PREFIXSCAN_IS_NOBS(dealias) == 0)
    bs = 0;
  else
    bs = 1;

  /*
   * check to see if the sequence of replies indicates an alias.  free
   * the probes array before we check the result, as it is easiest here.
   */
  p = inseq[bs](probes, seq, prefixscan->fudge);
  free(probes); probes = NULL;

  if(p != 0)
    {
      if(seq == prefixscan->replyc)
	{
	  p = state->probedefc-1;
	  prefixscan->ab = scamper_addr_use(prefixscan->probedefs[p].dst);
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	  return;
	}

      if(state->probe == 0)
	state->probe = state->probedefc - 1;
      else
	state->probe = 0;
	
      return;
    }

  /* if there are no other addresses to try, then finish */
  if(state->probedefc-1 == state->prefixscan->addrc)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  if(dealias_prefixscan_next(task) != 0)
    goto err;
  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
    return;

  state->prefixscan->round   = 0;
  state->prefixscan->attempt = 0;
  state->probe               = state->probedefc-1;

  if(dealias->probes[dealias->probec-1]->probedef->id == 0)
    state->prefixscan->seq   = 1;
  else
    state->prefixscan->seq   = 0;

  return;

 err:
  if(probes != NULL) free(probes);
  dealias_handleerror(task, errno);
  return;
}

static void dealias_prefixscan_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t *dealias = task->data;
  dealias_state_t *state = task->state;
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probe_t *probe = dealias->probes[dealias->probec-1];
  scamper_dealias_probedef_t *def = probe->probedef;

  if(state->prefixscan->replyc == 0)
    {
      /* if we're allowed to send another attempt, then do so */
      if(state->prefixscan->attempt < prefixscan->attempts)
	{
	  goto done;
	}

      /* if the probed address is unresponsive, and it is not prefixscan->a */
      if(def->id != 0)
	{
	  /* if there are other addresses to try, then probe one now */
	  if(state->probedefc-1 < state->prefixscan->addrc)
	    {
	      if(dealias_prefixscan_next(task) != 0)
		goto err;

	      /* if it turns out we don't need to probe, handle that */
	      if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
		return;

	      state->prefixscan->round   = 0;
	      state->prefixscan->seq     = 0;
	      state->prefixscan->attempt = 0;
	      state->probe               = state->probedefc-1;

	      goto done;
	    }
	}

      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  /* keep going! */
 done:
  if(state->probe == 0)
    state->round = state->prefixscan->round0;
  else
    state->round = state->prefixscan->round;
  scamper_queue_probe(task->queue);
  return;

 err:
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (*const func[])(scamper_task_t *, scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *) = {
    dealias_mercator_handlereply,
    dealias_ally_handlereply,
    NULL, /* radargun */
    dealias_prefixscan_handlereply,
  };
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply = NULL;
  scamper_dealias_t *dealias  = task->data;
  scamper_addr_t addr;
  uint32_t i;
  int type;

  /* if we haven't sent a probe yet, then we have nothing to match */
  if(dealias->probec == 0)
    return;

  if(dl->dl_af != AF_INET || dl->dl_ip_proto != IPPROTO_TCP)
    return;

  addr.type = SCAMPER_ADDR_TYPE_IPV4;
  addr.addr = dl->dl_ip_src;

  i = dealias->probec - 1;
  for(;;)
    {
      probe = dealias->probes[i];
      def   = probe->probedef;

      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) &&
	 def->un.tcp.dport == dl->dl_tcp_sport &&
	 scamper_addr_cmp(def->dst, &addr) == 0)
	{
	  if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	    {
	      if(def->un.tcp.sport == dl->dl_tcp_dport)
		break;
	    }
	  else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT)
	    {
	      if(def->un.tcp.sport + probe->seq == dl->dl_tcp_dport)
		break;
	    }
	}

      if(i == 0)
	return;

      i--;
    }

  scamper_dl_rec_tcp_print(dl);

  if((reply = scamper_dealias_reply_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc reply");
      goto err;
    }
  type = SCAMPER_ADDR_TYPE_IPV4;
  if((reply->src = scamper_addrcache_get(addrcache, type, addr.addr)) == NULL)
    {
      scamper_debug(__func__, "could not get address from cache");
      goto err;
    }
  timeval_cpy(&reply->rx, &dl->dl_tv);
  reply->ttl       = dl->dl_ip_ttl;
  reply->ipid      = dl->dl_ip_id;
  reply->proto     = IPPROTO_TCP;
  reply->tcp_flags = dl->dl_tcp_flags;
  if(scamper_dealias_reply_add(probe, reply) != 0)
    {
      scamper_debug(__func__, "could not add reply to probe");
      goto err;
    }

  if(func[dealias->method-1] != NULL)
    func[dealias->method-1](task, probe, reply);
  return;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_icmp(scamper_task_t *task,scamper_icmp_resp_t *ir)
{
  static void (*const func[])(scamper_task_t *, scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *) = {
    dealias_mercator_handlereply,
    dealias_ally_handlereply,
    NULL, /* radargun */
    dealias_prefixscan_handlereply,
  };
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply = NULL;
  scamper_dealias_t *dealias = task->data;
  dealias_state_t *state = task->state;
  void *addr;
  int type;

  /* if we haven't sent a probe yet, then we have nothing to match */
  if(dealias->probec == 0)
    return;

  if(ir->ir_af != AF_INET)
    return;

  /*
   * ignore the message if it is received on an fd that we didn't use to send
   * it.  this is to avoid recording duplicate replies if an unbound socket
   * is in use.
   */
  if(ir->ir_fd != scamper_fd_fd_get(state->icmp))
    {
      return;
    }

  scamper_icmp_resp_print(ir);

  /* if the ICMP type is not something that we care for, then drop it */
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) != 0 ||
     SCAMPER_ICMP_RESP_IS_UNREACH(ir) != 0 ||
     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) != 0)
    {
      if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir) == 0)
	{
	  return;
	}

      if(ir->ir_inner_ip_proto == IPPROTO_UDP)
	probe = dealias_probe_udp_find(state, ir);
      else if(ir->ir_inner_ip_proto == IPPROTO_ICMP)
	probe = dealias_probe_icmp_find(state, ir);
      else if(ir->ir_inner_ip_proto == IPPROTO_TCP)
	probe = dealias_probe_tcp_find(state, ir);
      else return;
    }
  else if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) != 0)
    {
      probe = dealias_probe_echoreq_find(dealias, ir);
    }
  else
    {
      return;
    }

  if(probe == NULL)
    return;

  type = SCAMPER_ADDR_TYPE_IPV4;
  addr = &ir->ir_ip_src.v4;

  if((reply = scamper_dealias_reply_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc reply");
      goto err;
    }
  if((reply->src = scamper_addrcache_get(addrcache, type, addr)) == NULL)
    {
      scamper_debug(__func__, "could not get address from cache");
      goto err;
    }
  timeval_cpy(&reply->rx, &ir->ir_rx);
  reply->ttl           = (uint8_t)ir->ir_ip_ttl;
  reply->ipid          = ir->ir_ip_id;
  reply->proto         = IPPROTO_ICMP;
  reply->icmp_type     = ir->ir_icmp_type;
  reply->icmp_code     = ir->ir_icmp_code;
  reply->icmp_q_ip_ttl = ir->ir_inner_ip_ttl;
  if(scamper_dealias_reply_add(probe, reply) != 0)
    {
      scamper_debug(__func__, "could not add reply to probe");
      goto err;
    }

  if(func[dealias->method-1] != NULL)
    func[dealias->method-1](task, probe, reply);
  return;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_timeout(scamper_task_t *task)
{
  static void (*const func[])(scamper_task_t *) = {
    dealias_mercator_handletimeout,
    dealias_ally_handletimeout,
    dealias_radargun_handletimeout,
    dealias_prefixscan_handletimeout,
  };
  scamper_dealias_t *dealias = task->data;
  func[dealias->method-1](task);
  return;
}

/*
 * dealias_state_probe
 *
 * record the fact that a probe was sent with a particular IP-ID value.
 */
static int dealias_state_probe(dealias_state_t *state,
			       scamper_dealias_probe_t *probe, uint16_t seq)
{
  scamper_dealias_probe_t findme_probe;
  dealias_probe_t findme;
  dealias_probe_t *dp = NULL;

  findme_probe.ipid = probe->ipid;
  findme.probe = &findme_probe;

  /* allocate a structure to record this probe's details */
  if((dp = malloc(sizeof(dealias_probe_t))) == NULL)
    {
      printerror(errno,strerror,__func__, "could not malloc dealias_probe_t");
      goto err;
    }
  dp->icmpseq = seq;

  /*
   * probes with the same IP-ID are chained together in a linked list,
   * from most recently sent to least recently sent.  any existing probe
   * that uses this IP-ID is linked to the freshly sent probe and the
   * new probe structure takes its place at the head of the list.
   */
  dp->probe = probe;
  if((dp->next = splaytree_find(state->probes, &findme)) != NULL)
    {
      if(splaytree_remove_item(state->probes, &findme) != 0)
	{
	  scamper_debug(__func__, "could not remove IPID %d", probe->ipid);
	  goto err;
	}
    }

  if(splaytree_insert(state->probes, dp) == NULL)
    {
      scamper_debug(__func__, "could not add probe to tree");
      goto err;
    }

  return 0;

 err:
  if(dp != NULL) free(dp);
  return -1;
}

static void dealias_probe_free(void *item)
{
  dealias_probe_t *probe = item, *next;
  while(probe != NULL)
    {
      next = probe->next;
      free(probe);
      probe = next;
    }
  return;
}

static int dealias_handle_rt(scamper_task_t *task, scamper_rt_rec_t *rt)
{
  dealias_state_t *state = task->state;
  uint32_t i = state->probedefi;
  scamper_dealias_probedef_t *def = &state->probedefs[i];
  scamper_dl_hdr_t *dlhdr;

  if((state->probefds[i] = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      return -1;
    }

  if((dlhdr = scamper_dl_hdr_alloc(state->probefds[i], def->src,
				   def->dst, rt->gwaddr)) == NULL)
    {
      return -1;
    }
  state->dlhdrs[i] = dlhdr;

  return 0;
}

#ifndef _WIN32
static void do_dealias_handle_rt(scamper_task_t *task, scamper_rt_rec_t *rt)
{
  scamper_dealias_t *dealias = task->data;
  dealias_state_t *state = task->state;
  scamper_dealias_probedef_t *def;

  assert(state->rt != NULL);

  /* if there was a problem getting the ifindex, handle that */
  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(errno, strerror, __func__, "could not get ifindex");
      dealias_handleerror(task, errno);
      return;
    }

  /* get details about the route to use */
  if(dealias_handle_rt(task, rt) != 0)
    {
      dealias_handleerror(task, errno);
      return;
    }

  /* if there are no further probedefs to consider, then start probing */
  if(++state->probedefi == state->probedefc)
    {
      /* if we might need the route socket later, keep it */
      if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
	state->prefixscan->rt = state->rt;
      else
	scamper_fd_free(state->rt);

      /* this signals that probing should commence */
      state->rt = NULL;
      scamper_queue_probe(task->queue);
      return;
    }

  while(state->probedefi < state->probedefc)
    {
      def = &state->probedefs[state->probedefi];
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
	break;
      state->probedefi++;      
    }

  if(state->probedefi == state->probedefc)
    {
      scamper_fd_free(state->rt);
      state->rt = NULL;
    }

  scamper_queue_probe(task->queue);
  return;
}
#endif

static void dealias_state_free(dealias_state_t *state)
{
  uint32_t i;
  int j;

  if(state == NULL)
    return;

  if(state->rt != NULL)
    scamper_fd_free(state->rt);

  if(state->icmp != NULL)
    scamper_fd_free(state->icmp);

  if(state->prefixscan != NULL)
    {
      if(state->prefixscan->rt != NULL && state->rt == NULL)
	scamper_fd_free(state->prefixscan->rt);

      if(state->prefixscan->addrs != NULL)
	{
	  for(j=0; j<state->prefixscan->addrc; j++)
	    if(state->prefixscan->addrs[j] != NULL)
	      scamper_addr_free(state->prefixscan->addrs[j]);
	  free(state->prefixscan->addrs);
	}

      if(state->prefixscan->aaliases != NULL)
	{
	  for(j=0; j<state->prefixscan->aaliasc; j++)
	    if(state->prefixscan->aaliases[j] != NULL)
	      scamper_addr_free(state->prefixscan->aaliases[j]);
	  free(state->prefixscan->aaliases);
	}

      free(state->prefixscan);
    }

  if(state->probefds != NULL)
    {
      for(i=0; i<state->probedefc; i++)
	if(state->probefds[i] != NULL)
	  scamper_fd_free(state->probefds[i]);
      free(state->probefds);
    }

  if(state->dlhdrs != NULL)
    {
      for(i=0; i<state->probedefc; i++)
	if(state->dlhdrs[i] != NULL)
	  scamper_dl_hdr_free(state->dlhdrs[i]);
      free(state->dlhdrs);
    }

  if(state->probes != NULL)
    splaytree_free(state->probes, dealias_probe_free);

  free(state);

  return;
}

static int dealias_state_alloc(scamper_task_t *task)
{
  scamper_dealias_t            *dealias    = task->data;
  dealias_state_t              *state      = NULL;
  scamper_dealias_mercator_t   *mercator   = dealias->data;
  scamper_dealias_ally_t       *ally       = dealias->data;
  scamper_dealias_radargun_t   *radargun   = dealias->data;
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probedef_t *def;
  uint32_t i;
  size_t size;

#ifdef _WIN32
  scamper_rt_rec_t rr;
#endif

  if((state = malloc_zero(sizeof(dealias_state_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc state");
      goto err;
    }

  if((state->probes = splaytree_alloc(dealias_probe_cmp)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc probes");
      goto err;
    }

  /* get the icmp fd we will listen on */
  state->icmp = scamper_fd_icmp4(NULL);

  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      state->probedefs = &mercator->probedef;
      state->probedefc = 1;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      state->probedefs = ally->probedefs;
      state->probedefc = 2;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      state->probedefs = radargun->probedefs;
      state->probedefc = radargun->probedefc;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      state->probedefs  = prefixscan->probedefs;
      state->probedefc  = prefixscan->probedefc;

      state->prefixscan = malloc_zero(sizeof(dealias_prefixscan_state_t));
      if(state->prefixscan == NULL)
	{
	  printerror(errno, strerror, __func__, "could not malloc prefixscan");
	  goto err;
	}

      if(dealias_prefixscan_array(dealias, &state->prefixscan->addrs,
				  &state->prefixscan->addrc) != 0)
	goto err;
    }
  else
    {
      scamper_debug(__func__, "unhandled method %d", dealias->method);
      goto err;
    }

  state->probefds = malloc_zero(sizeof(scamper_fd_t *) * state->probedefc);
  if(state->probefds == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc probefds");
      goto err;
    }

  for(i=0; i<state->probedefc; i++)
    {
      def = &state->probedefs[i];
      if((def->src = scamper_getsrc(def->dst)) == NULL)
	{
	  scamper_debug(__func__, "could not get src for probedef %d", i);
	  goto err;
	}
      if(dealias_state_probefd(state, i, def) != 0)
	{
	  scamper_debug(__func__, "could not get probefd %d", i);
	  goto err;
	}
    }

  task->state = state;

  /*
   * if at least one of the probedefs requires a datalink socket, then
   * start by opening a route socket to find the appropriate interface
   * details.
   */
  if(state->needtcp != 0)
    {
      size = sizeof(scamper_dl_hdr_t *) * state->probedefc;
      if((state->dlhdrs = malloc_zero(size)) == NULL)
	{
	  scamper_debug(__func__, "could not malloc dlhdrs");
	  goto err;
	}

#ifdef _WIN32
      for(i=0; i<state->probedefi; i++)
	{
	  def = state->probedefs[i];
	  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
	    continue;

	  if(scamper_rtsock_getroute(def->dst, &rr) != 0 ||
	     dealias_handle_rt(task, &rr) != 0)
	    {
	      goto err;
	    }
	}
#else
      if((state->rt = scamper_fd_rtsock()) == NULL)
	{
	  scamper_debug(__func__, "could not get route socket");
	  goto err;
	}
#endif
    }

  return 0;

 err:
  dealias_state_free(state);
  return -1;
}

static void do_dealias_probe(scamper_task_t *task)
{
  scamper_dealias_probedef_t *def;
  scamper_dealias_mercator_t *mercator;
  scamper_dealias_radargun_t *radargun;
  scamper_dealias_prefixscan_t *prefixscan;
  scamper_dealias_ally_t *ally;
  scamper_dealias_t *dealias = task->data;
  dealias_state_t *state = task->state;
  scamper_dealias_probe_t *dp = NULL;
  scamper_probe_t probe;
  uint16_t u16;
  int wait;

  assert(dealias != NULL);

  mercator   = dealias->data;
  radargun   = dealias->data;
  ally       = dealias->data;
  prefixscan = dealias->data;

  if(state == NULL)
    {
      gettimeofday_wrap(&dealias->start);

      /* allocate state and store it with the task */
      if(dealias_state_alloc(task) != 0)
	{
	  scamper_debug(__func__, "could not alloc state");
	  goto err;
	}
      state = task->state;
    }

#ifndef _WIN32
  if(state->rt != NULL)
    {
      def = &state->probedefs[state->probedefi];
      if(def == NULL || scamper_rtsock_getroute(state->rt, def->dst) != 0)
	{
	  dealias_handleerror(task, errno);
	  goto err;
	}
      scamper_queue_wait(task->queue, 5000);
      return;
    }
#endif

  if(pktbuf_len < 2)
    {
      if(realloc_wrap((void **)&pktbuf, 2) != 0)
	{
	  printerror(errno, strerror, __func__, "could not realloc pktbuf");
	  goto err;
	}
      pktbuf_len = 2;
    }

  def = &state->probedefs[state->probe];

  memset(&probe, 0, sizeof(probe));
  probe.pr_ip_src    = def->src;
  probe.pr_ip_dst    = def->dst;
  probe.pr_ip_ttl    = def->ttl;
  probe.pr_ip_tos    = def->tos;

#ifndef _WIN32
  probe.pr_ip_id     = random() % 65536;
#else
  probe.pr_ip_id     = (rand() << 16) | rand();
#endif

  probe.pr_data      = pktbuf;
  probe.pr_len       = 2;

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      probe.pr_fd = scamper_fd_fd_get(state->probefds[state->probe]);
      probe.pr_ip_proto  = IPPROTO_UDP;
      probe.pr_udp_sport = def->un.udp.sport;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	probe.pr_udp_dport = def->un.udp.dport;
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	probe.pr_udp_dport = def->un.udp.dport + state->round;
      else
	goto err;

      /* hack to get the udp csum to be a particular value, and be valid */
      u16 = htons(dealias->probec + 1);
      memcpy(probe.pr_data, &u16, 2);
      u16 = scamper_udp4_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      probe.pr_fd = scamper_fd_fd_get(state->probefds[state->probe]);
      probe.pr_ip_proto  = IPPROTO_ICMP;
      probe.pr_icmp_type = ICMP_ECHO;
      probe.pr_icmp_code = 0;
      probe.pr_icmp_id   = def->un.icmp.id;
      probe.pr_icmp_seq  = dealias->probec & 0xffff;

      /* hack to get the icmp csum to be a particular value, and be valid */
      u16 = htons(def->un.icmp.csum);
      memcpy(probe.pr_data, &u16, 2);
      u16 = scamper_icmp4_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      probe.pr_dl = scamper_fd_write_state(state->probefds[state->probe]);
      probe.pr_dl_hdr    = state->dlhdrs[state->probe]->dl_hdr;
      probe.pr_dl_size   = state->dlhdrs[state->probe]->dl_size;
      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_dport = def->un.tcp.dport;
      probe.pr_tcp_flags = def->un.tcp.flags;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	probe.pr_tcp_sport = def->un.tcp.sport;
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT)
	probe.pr_tcp_sport = def->un.tcp.sport + state->round;
      else
	goto err;
    }

  /*
   * allocate a probe record before we try and send the probe as there is no
   * point sending something into the wild that we can't record
   */
  if((dp = scamper_dealias_probe_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc probe");
      goto err;
    }
  dp->probedef = def;
  dp->ipid = probe.pr_ip_id;
  dp->seq = state->round;

  if(dealias_state_probe(state, dp, dealias->probec & 0xffff) != 0)
    {
      goto err;
    }

  /* send the probe */
  if(scamper_probe(&probe) != 0)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* record details of the probe in the scamper_dealias_t data structures */
  timeval_cpy(&dp->tx, &probe.pr_tx);
  if(scamper_dealias_probe_add(dealias, dp) != 0)
    {
      scamper_debug(__func__, "could not add probe to dealias data");
      goto err;
    }

  /* figure out how long to wait until sending the next probe */
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      /* we just wait the specified number of seconds with mercator probes */
      wait = mercator->wait_timeout * 1000;
      state->round++;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      /*
       * we wait a fixed amount of time before we send the next probe with
       * ally.  except when the last probe has been sent, where we wait for
       * some other length of time for any final replies to come in
       */
      if(dealias->probec != ally->attempts)
	wait = ally->wait_probe;
      else
	wait = ally->wait_timeout * 1000;

      if(++state->probe == 2)
	{
	  state->probe = 0;
	  state->round++;
	}
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      if(state->probe == 0)
	{
	  timeval_add_ms(&state->next_round, &probe.pr_tx,
			 radargun->wait_round);
	}
      state->probe++;

      if(state->probe < radargun->probedefc)
	{
	  wait = radargun->wait_probe;
	}
      else
	{
	  state->probe = 0;
	  state->round++;
	  if(state->round < radargun->attempts)
	    {
	      if(timeval_cmp(&probe.pr_tx, &state->next_round) < 0)
		wait = timeval_diff_ms(&state->next_round, &probe.pr_tx);
	      else
		wait = 0;

	      if(wait < radargun->wait_probe)
		wait = radargun->wait_probe;
	    }
	  else
	    {
	      /* we're all finished */
	      wait = radargun->wait_timeout * 1000;
	    }
	}
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      state->prefixscan->replyc = 0;

      if(def->id == 0)
	state->prefixscan->round0++;
      else
	state->prefixscan->round++;

      state->prefixscan->attempt++;
      wait = prefixscan->wait_probe;
    }
  else
    {
      scamper_debug(__func__, "unhandled method %d", dealias->method);
      goto err;
    }

  scamper_queue_wait(task->queue, wait);
  return;

 err:
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_write(scamper_task_t *task)
{
  const char *outfile_name;
  scamper_outfile_t *outfile;
  scamper_file_t *sf;

  outfile_name = scamper_source_getoutfile(task->source);
  assert(outfile_name != NULL);

  if((outfile = scamper_outfiles_get(outfile_name)) != NULL)
    {
      sf = scamper_outfile_getfile(outfile);
      scamper_file_write_dealias(sf, (scamper_dealias_t *)task->data);
    }

  return;
}

static void do_dealias_free(scamper_task_t *task)
{
  scamper_dealias_t *dealias;
  dealias_state_t *state;

  /* free any dealias data collected */
  if((dealias = task->data) != NULL)
    {
      scamper_dealias_free(dealias);
    }

  if((state = task->state) != NULL)
    {
      dealias_state_free(state);
    }

  return;
}

static int dealias_arg_param_validate(int optid, char *param, long *out)
{
  long tmp;

  switch(optid)
    {
    case DEALIAS_OPT_NOBS:
      break;

    case DEALIAS_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_FUDGE:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_METHOD:
      if(strcasecmp(param, "mercator") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_MERCATOR;
      else if(strcasecmp(param, "ally") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_ALLY;
      else if(strcasecmp(param, "radargun") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_RADARGUN;
      else if(strcasecmp(param, "prefixscan") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_PREFIXSCAN;
      else
	return -1;
      break;

    case DEALIAS_OPT_PROBEDEF:
      tmp = 0;
      break;

    case DEALIAS_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 500)
	return -1;
      break;

    case DEALIAS_OPT_SPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_TTL:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	return -1;
      break;

    case DEALIAS_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_TIMEOUT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_PROBE:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_ROUND:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 180000)
	return -1;
      break;

    case DEALIAS_OPT_EXCLUDE:
      tmp = 0;
      break;

    case DEALIAS_OPT_REPLYC:
      if(string_tolong(param, &tmp) != 0 || tmp < 3 || tmp > 255)
	return -1;
      break;

    default:
      scamper_debug(__func__, "unhandled optid %d", optid);
      return -1;
    }

  if(out != NULL)
    *out = tmp;
  return 0;
}

static int dealias_probedef_args(scamper_dealias_probedef_t *def, char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  uint16_t dport = 33435;
  uint16_t sport = default_sport;
  uint16_t csum  = 0;
  uint16_t opts  = 0;
  uint8_t  ttl   = 255;
  char *end;
  long tmp;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, probedef_opts, probedef_opts_cnt,
			   &opts_out, &end) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      /* check for an option being used multiple times */
      if(opts & (1<<(opt->id-1)))
	{
	  scamper_debug(__func__,"option %d specified multiple times",opt->id);
	  goto err;
	}

      opts |= (1 << (opt->id-1));

      switch(opt->id)
	{
	case DEALIAS_PROBEDEF_OPT_CSUM:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 0 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid csum %s", opt->str);
	      goto err;
	    }
	  csum = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_DPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid dport %s", opt->str);
	      goto err;
	    }
	  dport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_IP:
	  def->dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, opt->str);
	  if(def->dst == NULL)
	    {
	      scamper_debug(__func__, "invalid dst ip %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_PROTO:
	  if(strcasecmp(opt->str, "udp") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
	  else if(strcasecmp(opt->str, "tcp-ack") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK;
	  else if(strcasecmp(opt->str, "icmp-echo") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO;
	  else if(strcasecmp(opt->str, "tcp-ack-sport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT;
	  else if(strcasecmp(opt->str, "udp-dport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT;
	  else
	    {
	      scamper_debug(__func__, "invalid probe type %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_SPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid sport %s", opt->str);
	      goto err;
	    }
	  sport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_TTL:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 255)
	    {
	      scamper_debug(__func__, "invalid ttl %s", opt->str);
	      goto err;
	    }
	  ttl = (uint8_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled optid %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  /*
   * if there is something at the end of the option string, then this
   * probedef is not valid
   */
  if(end != NULL)
    {
      scamper_debug(__func__, "invalid option string");
      goto err;
    }

  /* record the ttl */
  def->ttl = ttl;

  /* if no protocol type is defined, choose UDP */
  if((opts & (1<<(DEALIAS_PROBEDEF_OPT_PROTO-1))) == 0)
    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      /* don't provide the choice of the checksum value in a UDP probe */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_CSUM-1)))
	{
	  scamper_debug(__func__, "csum option not permitted for udp");
	  goto err;
	}

      def->un.udp.dport = dport;
      def->un.udp.sport = sport;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      /* ICMP probes don't have source or destination ports */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_SPORT-1)))
	{
	  scamper_debug(__func__, "sport option not permitted for icmp");
	  goto err;
	}
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_DPORT-1)))
	{
	  scamper_debug(__func__, "dport option not permitted for icmp");
	  goto err;
	}

      def->un.icmp.type = ICMP_ECHO;
      def->un.icmp.code = 0;
      def->un.icmp.csum = csum;
      def->un.icmp.id   = default_sport;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      /* don't provide the choice of the checksum value in a TCP probe */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_CSUM-1)))
	{
	  scamper_debug(__func__, "csum option not permitted for tcp");
	  goto err;
	}

      def->un.tcp.dport = dport;
      def->un.tcp.sport = sport;
      def->un.tcp.flags = TH_ACK;
    }
  else
    {
      scamper_debug(__func__, "unhandled method %d", def->method);
      goto err;
    }

  return 0;

 err:
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(def->dst != NULL) scamper_addr_free(def->dst);
  return -1;
}

/*
 * scamper_do_dealias_alloc
 *
 * given a string representing a dealias task, parse the parameters and
 * assemble a dealias.  return the dealias structure so that it is all ready
 * to go.
 */
void *scamper_do_dealias_alloc(char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_dealias_t *dealias = NULL;
  scamper_dealias_probedef_t *pd = NULL, pd0;
  scamper_dealias_prefixscan_t *prefixscan;
  scamper_dealias_mercator_t *mercator;
  scamper_dealias_radargun_t *radargun;
  scamper_dealias_ally_t *ally;
  scamper_addr_t *dst   = NULL;
  uint8_t  method       = SCAMPER_DEALIAS_METHOD_MERCATOR;
  uint8_t  attempts     = 0;
  uint8_t  replyc       = 0;
  uint8_t  wait_timeout = 0;
  uint16_t wait_probe   = 0;
  uint32_t wait_round   = 0;
  uint16_t sport        = 0;
  uint16_t dport        = 0;
  uint8_t  ttl          = 0;
  uint16_t fudge        = 0;
  uint8_t  prefix       = 0;
  uint32_t userid       = 0;
  char   **probedefs    = NULL;
  uint32_t probedefc    = 0;
  char   **xs           = NULL;
  int      xc           = 0;
  int      nobs         = 0;
  uint8_t  flags        = 0;
  int      xi;
  int      af;
  uint32_t i;
  size_t   len;
  char    *addr, *addr2 = NULL, *ptr;
  long     tmp;

  memset(&pd0, 0, sizeof(pd0));

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      scamper_debug(__func__, "could not parse command");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 dealias_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case DEALIAS_OPT_NOBS:
	  nobs = 1;
	  break;

	case DEALIAS_OPT_ATTEMPTS:
	  attempts = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_SPORT:
	  sport = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_FUDGE:
	  fudge = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_METHOD:
	  method = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_TTL:
	  ttl = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case DEALIAS_OPT_PROBEDEF:
	  len = sizeof(char *) * (probedefc+1);
	  if(realloc_wrap((void **)&probedefs, len) != 0)
	    {
	      scamper_debug(__func__, "could not realloc probedefs");
	      goto err;
	    }
	  probedefs[probedefc++] = opt->str;
	  break;

	case DEALIAS_OPT_WAIT_TIMEOUT:
	  wait_timeout = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_WAIT_PROBE:
	  wait_probe = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_WAIT_ROUND:
	  wait_round = (uint32_t)tmp;
	  break;

	case DEALIAS_OPT_EXCLUDE:
	  len = sizeof(char *) * (xc+1);
	  if(realloc_wrap((void **)&xs, len) != 0)
	    {
	      scamper_debug(__func__, "could not realloc excludes");
	      goto err;
	    }
	  xs[xc++] = opt->str;
	  break;

	case DEALIAS_OPT_REPLYC:
	  replyc = (uint8_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled option %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  if(wait_timeout == 0)
    wait_timeout = 5;

  if(method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      /* if there is no IP address after the options string, then stop now */
      if(addr == NULL)
	{
	  scamper_debug(__func__, "missing target address for mercator");
	  goto err;
	}
      if((dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr)) == NULL)
	{
	  scamper_debug(__func__, "unable to resolve address for mercator");
	  goto err;
	}
      if(probedefc != 0 || xc != 0 || wait_probe != 0 || fudge != 0 ||
	 attempts > 3 || nobs != 0 || replyc != 0)
	{
	  scamper_debug(__func__, "invalid parameters for mercator");
	  goto err;
	}
      if(attempts == 0) attempts = 3;
      if(dport == 0)    dport    = 33435;
      if(sport == 0)    sport    = default_sport;
      if(ttl == 0)      ttl      = 255;
    }
  else if(method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      if(probedefc != 2 || xc != 0 || dport != 0 || sport != 0 ||
	 ttl != 0 || replyc != 0)
	{
	  scamper_debug(__func__, "invalid parameters for ally");
	  goto err;
	}
      if(wait_probe == 0) wait_probe = 150;
      if(attempts == 0)   attempts   = 5;
      if(fudge == 0)      fudge      = 200;
      if(nobs != 0)       flags     |= SCAMPER_DEALIAS_ALLY_FLAG_NOBS;

      if((pd = malloc_zero(2 * sizeof(scamper_dealias_probedef_t))) == NULL)
	{
	  scamper_debug(__func__, "could not malloc pd for ally");
	  goto err;
	}

      for(i=0; i<2; i++)
	{
	  if(dealias_probedef_args(&pd[i], probedefs[i]) != 0)
	    {
	      scamper_debug(__func__, "could not read ally probedef %d", i);
	      goto err;
	    }
	  pd[i].id = i;
	}

      /* sanity check the probedef destination addresses */
      if((pd[0].dst == NULL && pd[1].dst != NULL) ||
	 (pd[0].dst != NULL && pd[1].dst == NULL))
	{
	  scamper_debug(__func__, "dst IP specified for ally inconsistently");
	  goto err;
	}

      if(pd[0].dst == NULL)
	{
	  if(addr == NULL)
	    {
	      scamper_debug(__func__, "missing destination IP address");
	      goto err;
	    }

	  /*
	   * the same address is going to be used for both probes. resolve
	   * it now
	   */
	  if((dst=scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr))==NULL)
	    {
	      scamper_debug(__func__, "could not resolve %s", addr);
	      goto err;
	    }
	  pd[0].dst = scamper_addr_use(dst);
	  pd[1].dst = scamper_addr_use(dst);
	  scamper_addr_free(dst); dst = NULL;
	}
      else if(addr != NULL)
	{
	  scamper_debug(__func__, "destination IP address specified twice");
	  goto err;
	}

      if(pd[0].dst->type != SCAMPER_ADDR_TYPE_IPV4 ||
	 pd[1].dst->type != SCAMPER_ADDR_TYPE_IPV4)
	{
	  scamper_debug(__func__, "destination IP address not IPv4");
	  goto err;
	}
    }
  else if(method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      if(probedefc == 0 || xc != 0 || dport != 0 || sport != 0 ||
	 ttl != 0 || nobs != 0 || replyc != 0)
	{
	  scamper_debug(__func__, "invalid parameters for radargun");
	  goto err;
	}

      if(wait_probe == 0) wait_probe   = 150;
      if(attempts == 0)   attempts     = 30;
      if(wait_round == 0) wait_round   = probedefc * wait_probe;

      pd = malloc_zero(probedefc * sizeof(scamper_dealias_probedef_t));
      if(pd == NULL)
	{
	  scamper_debug(__func__, "could not malloc radargun pd");
	  goto err;
	}

      for(i=0; i<probedefc; i++)
	{
	  if(dealias_probedef_args(&pd[i], probedefs[i]) != 0)
	    {
	      scamper_debug(__func__,"could not parse radargun probedef %d",i);
	      goto err;
	    }

	  if((pd[0].dst == NULL && pd[i].dst != NULL) ||
	     (pd[0].dst != NULL && pd[i].dst == NULL))
	    {
	      scamper_debug(__func__, "inconsistent dst IP addresses");
	      goto err;
	    }

	  pd[i].id = i;
	}

      if(pd[0].dst == NULL)
	{
	  if(addr == NULL)
	    {
	      scamper_debug(__func__, "required dst IP address missing");
	      goto err;
	    }

	  if((dst=scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr))==NULL)
	    {
	      scamper_debug(__func__, "could not resolve %s", addr);
	      goto err;
	    }

	  for(i=0; i<probedefc; i++)
	    pd[i].dst = scamper_addr_use(dst);

	  scamper_addr_free(dst); dst = NULL;
	}
      else if(addr != NULL)
	{
	  scamper_debug(__func__, "destination IP address specified twice");
	  goto err;
	}
    }
  else if(method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      /* check the sanity of various parameters */
      if(probedefc != 1 || addr == NULL || dport != 0 || sport != 0 || ttl != 0)
	{
	  scamper_debug(__func__, "invalid parameters for prefixscan");
	  goto err;
	}

      if(ttl == 0)        ttl        = 255;
      if(wait_probe == 0) wait_probe = 1000;
      if(attempts == 0)   attempts   = 2;
      if(fudge == 0)      fudge      = 200;
      if(replyc == 0)     replyc     = 5;
      if(nobs != 0)       flags     |= SCAMPER_DEALIAS_PREFIXSCAN_FLAG_NOBS;

      /*
       * we need `a' and `b' to traceroute.  parse the `addr' string.
       * start by getting the second address.
       *
       * skip over the first address until we get to whitespace.
       */
      ptr = addr;
      while(*ptr != ' ' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	{
	  scamper_debug(__func__, "missing second address");
	  goto err;
	}
      *ptr = '\0'; ptr++;
      while(*ptr == ' ' && *ptr != '\0')
	ptr++;
      if(*ptr == '\0')
	{
	  scamper_debug(__func__, "missing second address");
	  goto err;
	}
      /*
       * store a pointer to the second address in addr2.  now, find
       * the prefix specified.
       */
      addr2 = ptr;
      while(*ptr != '/' && *ptr != '\0')
	ptr++;
      if(*ptr != '/')
	{
	  scamper_debug(__func__, "missing prefix");
	  goto err;
	}
      *ptr = '\0'; ptr++;

      if(string_tolong(ptr, &tmp) != 0 || tmp < 24 || tmp >= 32)
	{
	  scamper_debug(__func__, "invalid prefix %s", ptr);
	  goto err;
	}
      prefix = (uint8_t)tmp;

      /* check the sanity of the probedef */
      if(dealias_probedef_args(&pd0, probedefs[0]) != 0)
	{
	  scamper_debug(__func__, "could not parse prefixscan probedef");
	  goto err;
	}
      if(pd0.dst != NULL)
	{
	  scamper_debug(__func__, "prefixscan ip address spec. in probedef");
	  goto err;
	}
    }
  else
    {
      scamper_debug(__func__, "unhandled method");
      goto err;
    }

  if(probedefs != NULL)
    {
      free(probedefs);
      probedefs = NULL;
    }

  if((dealias = scamper_dealias_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc dealias structure");
      goto err;
    }
  dealias->method = method;
  dealias->userid = userid;

  if(method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      if(scamper_dealias_mercator_alloc(dealias) != 0)
	{
	  scamper_debug(__func__, "could not alloc mercator structure");
	  goto err;
	}
      mercator = dealias->data;

      mercator->attempts        = attempts;
      mercator->wait_timeout    = wait_timeout;
      mercator->probedef.id     = 0;
      mercator->probedef.dst    = scamper_addr_use(dst);
      mercator->probedef.ttl    = ttl;
      mercator->probedef.method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
      mercator->probedef.un.udp.sport = sport;
      mercator->probedef.un.udp.dport = dport;
    }
  else if(method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      if(scamper_dealias_ally_alloc(dealias) != 0)
	{
	  scamper_debug(__func__, "could not alloc ally structure");
	  goto err;
	}
      ally = dealias->data;

      ally->attempts     = attempts;
      ally->wait_probe   = wait_probe;
      ally->wait_timeout = wait_timeout;
      ally->fudge        = fudge;
      ally->flags        = flags;
      memcpy(ally->probedefs, pd, sizeof(ally->probedefs));
      memset(pd, 0, sizeof(pd));
    }
  else if(method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      if(scamper_dealias_radargun_alloc(dealias) != 0)
	{
	  scamper_debug(__func__, "could not alloc radargun structure");
	  goto err;
	}

      radargun = dealias->data;
      if(scamper_dealias_radargun_probedefs_alloc(radargun, probedefc) != 0)
	{
	  scamper_debug(__func__, "could not alloc radargun probedefs");
	  goto err;
	}

      radargun->attempts     = attempts;
      radargun->wait_probe   = wait_probe;
      radargun->wait_timeout = wait_timeout;
      radargun->wait_round   = wait_round;
      radargun->probedefc    = probedefc;

      len = sizeof(scamper_dealias_probedef_t);
      for(i=0; i<probedefc; i++)
	{
	  memcpy(&radargun->probedefs[i], &pd[i], len);
	}
    }
  else if(method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      if(scamper_dealias_prefixscan_alloc(dealias) != 0)
	{
	  scamper_debug(__func__, "could not alloc prefixscan structure");
	  goto err;
	}
      prefixscan = dealias->data;

      prefixscan->prefix       = prefix;
      prefixscan->attempts     = attempts;
      prefixscan->fudge        = fudge;
      prefixscan->wait_probe   = wait_probe;
      prefixscan->wait_timeout = wait_timeout;
      prefixscan->flags        = flags;
      prefixscan->replyc       = replyc;

      /* resolve the two addresses now */
      prefixscan->a = scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr);
      if(prefixscan->a == NULL)
	{
	  scamper_debug(__func__, "could not resolve %s", addr);
	  goto err;
	}
      af = scamper_addr_af(prefixscan->a);
      prefixscan->b = scamper_addrcache_resolve(addrcache, af, addr2);
      if(prefixscan->b == NULL)
	{
	  scamper_debug(__func__, "could not resolve %s", addr2);
	  goto err;
	}

      /* add the first probedef */
      if(scamper_dealias_prefixscan_probedefs_alloc(prefixscan, 1) != 0)
	{
	  scamper_debug(__func__, "could not alloc prefixscan probedefs");
	  goto err;
	}
      memcpy(prefixscan->probedefs, &pd0, sizeof(pd0));
      prefixscan->probedefs[0].dst = scamper_addr_use(prefixscan->a);
      prefixscan->probedefc        = 1;

      /* resolve any addresses to exclude in the scan */
      for(xi=0; xi<xc; xi++)
	{
	  if((dst = scamper_addrcache_resolve(addrcache, af, xs[xi])) == NULL)
	    {
	      scamper_debug(__func__, "could not resolve %s", xs[xi]);
	      goto err;
	    }
	  if(scamper_dealias_prefixscan_xs_add(dealias, dst) != 0)
	    {
	      scamper_debug(__func__, "could not add %s to xs", xs[xi]);
	      goto err;
	    }
	  scamper_addr_free(dst); dst = NULL;
	}
    }
  else
    {
      scamper_debug(__func__, "unhandled method");
      goto err;
    }

  if(pd != NULL) free(pd);
  if(pd0.dst != NULL) scamper_addr_free(pd0.dst);
  if(dst != NULL) scamper_addr_free(dst);
  return dealias;

 err:
  if(pd != NULL)
    {
      for(i=0; i<probedefc; i++)
	if(pd[i].dst != NULL)
	  scamper_addr_free(pd[i].dst);
      free(pd);
    }
  if(pd0.dst != NULL) scamper_addr_free(pd0.dst);
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(probedefs != NULL) free(probedefs);
  if(dealias != NULL) scamper_dealias_free(dealias);
  if(dst != NULL) scamper_addr_free(dst);
  return NULL;
}

/*
 * scamper_do_dealias_arg_validate
 *
 *
 */
int scamper_do_dealias_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  dealias_arg_param_validate);
}

int scamper_do_dealias_dstaddrs(void *data, void *param,
				int (*foreach)(struct scamper_addr *, void *))
{
  scamper_dealias_t             *dealias = (scamper_dealias_t *)data;
  scamper_dealias_prefixscan_t  *prefixscan;
  scamper_dealias_mercator_t    *mercator;
  scamper_dealias_radargun_t    *radargun;
  scamper_dealias_ally_t        *ally;
  scamper_addr_t               **addrs = NULL;
  uint32_t p;
  int i, j, k, rc = -1;

  assert(dealias->data != NULL);

  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      mercator = dealias->data;
      assert(mercator->probedef.dst != NULL);
      return foreach(mercator->probedef.dst, param);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      ally = dealias->data;
      assert(ally->probedefs[0].dst != NULL);
      assert(ally->probedefs[1].dst != NULL);
      if((i = foreach(ally->probedefs[0].dst, param)) != 0)
	return i;
      return foreach(ally->probedefs[1].dst, param);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      radargun = dealias->data;
      for(p=0; p<radargun->probedefc; p++)
	{
	  if((j = foreach(radargun->probedefs[p].dst, param)) != 0)
	    return j;
	}
      return 0;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      prefixscan = dealias->data;
      assert(prefixscan->a != NULL);
      if((i = foreach(prefixscan->a, param)) != 0)
	return i;
      if(dealias_prefixscan_array(dealias, &addrs, &j) != 0)
	return -1;
      assert(j > 0);
      for(i=0; i<j; i++)
	{
	  if((k = foreach(addrs[i], param)) != 0)
	    break;
	}
      if(i == j)
	rc = 0;

      dealias_prefixscan_array_free(addrs, j);      
    }

  return rc;
}

void scamper_do_dealias_free(void *data)
{
  scamper_dealias_free((scamper_dealias_t *)data);
  return;
}

scamper_task_t *scamper_do_dealias_alloctask(void *data,
					     scamper_list_t *list,
					     scamper_cycle_t *cycle)
{
  scamper_dealias_t *dealias = (scamper_dealias_t *)data;

  /* associate the list and cycle with the trace */
  dealias->list  = scamper_list_use(list);
  dealias->cycle = scamper_cycle_use(cycle);

  /* allocate a task structure and store the trace with it */
  return scamper_task_alloc(data, &funcs);
}

void scamper_do_dealias_cleanup(void)
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

int scamper_do_dealias_init(void)
{
#ifndef _WIN32
  pid_t pid = getpid();
#else
  DWORD pid = GetCurrentProcessId();
#endif

  default_sport = (pid & 0x7fff) + 0x8000;

  funcs.probe                  = do_dealias_probe;
  funcs.handle_icmp            = do_dealias_handle_icmp;
  funcs.handle_timeout         = do_dealias_handle_timeout;
  funcs.handle_dl              = do_dealias_handle_dl;
  funcs.write                  = do_dealias_write;
  funcs.task_free              = do_dealias_free;
  funcs.task_addrs             = scamper_do_dealias_dstaddrs;

#ifndef _WIN32
  funcs.handle_rt              = do_dealias_handle_rt;
#endif

  return 0;
}
