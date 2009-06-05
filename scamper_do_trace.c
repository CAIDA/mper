/*
 * scamper_do_trace.c
 *
 * $Id: scamper_do_trace.c,v 1.221 2009/05/19 04:40:39 mjl Exp $
 *
 * Copyright (C) 2005-2009 The University of Waikato
 * Author: Matthew Luckie
 * Doubletree implementation (C) 2008 Alistair King
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

#ifndef _WIN32
#include <sys/param.h>
#endif

#if !defined(__sun__) && !defined(_WIN32)
#include <sys/sysctl.h>
#endif

#include <sys/types.h>

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

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#endif

#if defined(__linux__)
#define __FAVOR_BSD
#endif

#if defined(__sun__)
#define BSD_COMP
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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tlv.h"
#include "scamper_icmpext.h"
#include "scamper_trace.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_rtsock.h"
#include "scamper_getsrc.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_debug.h"
#include "scamper_do_trace.h"
#include "scamper_addr2mac.h"
#include "scamper_options.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_tcp4.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_if.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

#define SCAMPER_DO_TRACE_ATTEMPTS_MIN  1
#define SCAMPER_DO_TRACE_ATTEMPTS_DEF  2
#define SCAMPER_DO_TRACE_ATTEMPTS_MAX  20 

#define SCAMPER_DO_TRACE_DPORT_MIN     1
#define SCAMPER_DO_TRACE_DPORT_DEF     (32768+666+1) /* probe_id starts at 0 */
#define SCAMPER_DO_TRACE_DPORT_MAX     65535

#define SCAMPER_DO_TRACE_FIRSTHOP_MIN  1
#define SCAMPER_DO_TRACE_FIRSTHOP_DEF  1
#define SCAMPER_DO_TRACE_FIRSTHOP_MAX  255

#define SCAMPER_DO_TRACE_GAPLIMIT_MIN  1
#define SCAMPER_DO_TRACE_GAPLIMIT_DEF  5
#define SCAMPER_DO_TRACE_GAPLIMIT_MAX  255

#define SCAMPER_DO_TRACE_GAPACTION_MIN 1
#define SCAMPER_DO_TRACE_GAPACTION_DEF SCAMPER_TRACE_GAPACTION_STOP
#define SCAMPER_DO_TRACE_GAPACTION_MAX 2

#define SCAMPER_DO_TRACE_HOLDTIME_MIN  0
#define SCAMPER_DO_TRACE_HOLDTIME_DEF  0
#define SCAMPER_DO_TRACE_HOLDTIME_MAX  255

#define SCAMPER_DO_TRACE_HOPLIMIT_MIN  0
#define SCAMPER_DO_TRACE_HOPLIMIT_DEF  0
#define SCAMPER_DO_TRACE_HOPLIMIT_MAX  255

#define SCAMPER_DO_TRACE_LOOPS_MIN     0
#define SCAMPER_DO_TRACE_LOOPS_DEF     1 /* stop on the first loop found */
#define SCAMPER_DO_TRACE_LOOPS_MAX     255

#define SCAMPER_DO_TRACE_LOOPACTION_MIN 0
#define SCAMPER_DO_TRACE_LOOPACTION_DEF 0
#define SCAMPER_DO_TRACE_LOOPACTION_MAX 1

#define SCAMPER_DO_TRACE_PPS_MIN       1
#define SCAMPER_DO_TRACE_PPS_MAX       1000
#define SCAMPER_DO_TRACE_PPS_DEF       20

#define SCAMPER_DO_TRACE_SPORT_MIN     1
#define SCAMPER_DO_TRACE_SPORT_MAX     65535

#define SCAMPER_DO_TRACE_TOS_MIN 0
#define SCAMPER_DO_TRACE_TOS_DEF 0
#define SCAMPER_DO_TRACE_TOS_MAX 255

#define SCAMPER_DO_TRACE_WAIT_MIN   1
#define SCAMPER_DO_TRACE_WAIT_DEF   5
#define SCAMPER_DO_TRACE_WAIT_MAX   10

#define SCAMPER_DO_TRACE_WAITPROBE_MIN 0
#define SCAMPER_DO_TRACE_WAITPROBE_DEF 0
#define SCAMPER_DO_TRACE_WAITPROBE_MAX 200 /* 2 seconds */

/*
 * pmtud_L2_state
 *
 * this struct records state when inferring the MTU of the underlying media.
 *
 * when scamper has to discover the MTU of the link itself, it uses the L2
 * table above to choose a suitable initial guess.  it records the index
 * into the L2 table into L2_idx.
 */
typedef struct pmtud_L2_state
{
  int                  idx;   /* index into the L2 table */
  int                  lower; /* lower bounds of the L2 search space */
  int                  upper; /* upper bounds of the L2 search space */
  int                  in;    /* probe size not to get a suitable response */
  int                  out;   /* size of probe to infer the underlying MTU */
  scamper_trace_hop_t *hop;   /* the last probe to obtain a response */
} pmtud_L2_state_t;

/*
 * pmtud_TTL_state
 *
 * this struct records state when inferring the TTL range of hops that
 * are responsible for not sending a fragmentation required message where
 * one is required.
 */
typedef struct pmtud_TTL_state
{
  int                  lower; /* lower bounds of the TTL search space */
  int                  upper; /* upper bounds of the TTL search space */
  scamper_trace_hop_t *hop;   /* the last TTL probe to obtain a response */
} pmtud_TTL_state_t;

/*
 * pmtud_L2
 *
 * this struct associates a known MTU with an index into an array.
 */
typedef struct pmtud_L2
{
  int   idx;            /* index into the L2 array where this node resides */
  int   mtu;            /* the MTU of the link */
  char *descr;          /* some description of the L2 media */
} pmtud_L2_t;

/*
 * trace_probe
 *
 * this struct keeps state of each probe sent with the trace
 */
typedef struct trace_probe
{
  struct timeval  tx_tv;  /* the time we transmitted the probe */
  struct timeval  rx_tv;  /* the time we received the first answer */
  uint16_t        rx;     /* how many responses scamper got to the probe */
  uint16_t        size;   /* the size of the probe sent */
  uint8_t         ttl;    /* the TTL that was set for the probe */
  uint8_t         id;     /* the attempt number made with ttl/size params */
  uint8_t         mode;   /* the mode scamper was in when probe was sent */
  uint8_t         flags;  /* the probe's flags */
} trace_probe_t;

#define TRACE_PROBE_FLAG_DL_TX   0x01
#define TRACE_PROBE_FLAG_DL_RX   0x02
#define TRACE_PROBE_FLAG_TIMEOUT 0x04
#define TRACE_ALLOC_HOPS         16

/*
 * trace_state
 *
 * this is a fairly large struct that keeps state for the traceroute
 * process.  it also deals with state in the PMTUD phase, if used.
 */
typedef struct trace_state
{
  uint8_t              mode;          /* current trace mode scamper is in */
  uint8_t              ttl;           /* ttl to set in the probe packet */
  uint8_t              attempt;       /* attempt number at the current probe */
  uint8_t              loopc;         /* count of loops so far */
  uint8_t              iloopc;        /* count of ignored loops */
  uint16_t             alloc_hops;    /* number of trace->hops allocated */
  uint16_t             payload_size;  /* how much payload to include */
  uint16_t             header_size;   /* size of headers */
  struct timeval       next_tx;       /* when the next probe should be tx */

#ifndef _WIN32
  scamper_fd_t        *route;         /* fd to query route socket with */
#endif

  scamper_fd_t        *icmp;          /* fd to listen to icmp packets with */
  scamper_fd_t        *probe;         /* fd to probe with */
  scamper_fd_t        *dl;            /* struct to use with datalink access */

  scamper_dl_hdr_t    *dl_hdr;        /* header to use with datalink */

  trace_probe_t      **probes;        /* probes sent so far */
  uint16_t             id_next;       /* next id to use in probes */
  uint16_t             id_max;        /* maximum id available */

  /* these fields are used when probing to enumerate all interfaces at a hop */
  uint8_t              confidence;    /* index into k[] */
  uint8_t              n;             /* index into k[] */
  scamper_addr_t     **interfaces;    /* ifaces found so far at this ttl */
  uint16_t             interfacec;    /* count of interfaces */

  /*
   * these fields are used for doubletree.
   * the lss contains the list of addresses visited when probing backwards.
   * this is a subset of the global lss.
   * it is used to probe backwards through a loop, where otherwise probing
   * would be halted by the first address in the loop being added to the lss
   * the first time it is seen.
   */
  scamper_addr_t     **lss;
  int                  lssc;

  /* these fields are used in Path MTU discovery */
  pmtud_L2_state_t    *L2;           /* state kept when doing L2 MTU search */
  pmtud_TTL_state_t   *TTL;          /* state kept when doing a TTL search */
  scamper_trace_hop_t *last_fragmsg; /* last fragmentation msg stored */
} trace_state_t;

static const uint8_t MODE_TRACE            = 0;
static const uint8_t MODE_LASTDITCH        = 1;
static const uint8_t MODE_PMTUD_DEFAULT    = 2;
static const uint8_t MODE_PMTUD_SILENT_L2  = 3;
static const uint8_t MODE_PMTUD_SILENT_TTL = 4;
static const uint8_t MODE_PMTUD_BADSUGG    = 5;
#ifndef _WIN32
static const uint8_t MODE_RTSOCK           = 6;
#endif
static const uint8_t MODE_DTREE_FIRST      = 7;
static const uint8_t MODE_DTREE_FWD        = 8;
static const uint8_t MODE_DTREE_BACK       = 9;

#define MODE_MIN             MODE_TRACE
#define MODE_MAX             MODE_DTREE_BACK

/* the callback functions registered with the trace task */
static scamper_task_funcs_t trace_funcs;

/* the default source port to use when tracerouting */
static uint16_t default_sport;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

/* temporary buffer shared amongst traceroutes */
static uint8_t *pktbuf     = NULL;
static size_t   pktbuf_len = 0;

/* local stop set */
static splaytree_t *lss = NULL;

/*
 * these MTUs were largely taken from the NetBSD version of traceroute, and
 * are used to choose a packet size to probe with in the absense of a
 * Fragmentation Needed message.
 *
 * they have been annoted with their corresponding Layer 2 type, largely
 * taken from RFC 1191
 */
static const pmtud_L2_t L2[] =
{
  { 0,    68, "RFC791 MTU"},    /* Official RFC 791 minimum MTU */
  { 1,   296, "P2P low delay"}, /* Point-to-Point links, (low delay) */
  { 2,   508, ""},
  { 3,   512, "NetBIOS"},       /* NetBIOS */
  { 4,   544, "DEC Portal"},    /* DEC IP Portal */
  { 5,   552, ""},
  { 6,   576, "v4 min MTU"},    /* X25 MTU, IPv4 Minimum MTU */
  { 7,  1006, "SLIP"},          /* SLIP */
  { 8,  1280, "v6 min MTU"},    /* IPv6 Minimum MTU */
  { 9,  1454, "PPPoE ADSL"},    /* an optimally sized PPPoE frame in DSL */
  {10,  1480, "v4tun Ether"},   /* Ethernet MTU with tunnel over IPv4 */
  {11,  1492, "IEEE 802.3"},    /* IEEE 802.3 */
  {12,  1500, "Ethernet"},      /* Ethernet MTU */
  {13,  1514, "Ethernet Max"},  /* Ethernet Max MTU */
  {14,  1536, "Exp. Ether"},    /* Exp. Ethernet Nets */
  {15,  2002, "IEEE 802.5"},    /* IEEE 802.5, Recommended MTU */
  {16,  2048, "Wideband"},      /* Wideband Network */
  {17,  4352, "FDDI"},          /* FDDI */
  {18,  4464, "IEEE 802.5"},    /* IEEE 802.5, Maximum MTU */
  {19,  4470, "IP over ATM"},   /* ATM / T3 / SONET SDH */
  {20,  8166, "IEEE 802.4"},    /* IEEE 802.4 */
  {21,  9000, "Broadcom GigE"}, /* Broadcom GigE MTU */
  {22,  9192, "OC-192"},        /* OC-192 and other really fast media */
  {23, 16110, "Intel GigE"},    /* Intel Pro 1000 MTU */
  {24, 17914, "Token Ring"},    /* 16Mb IBM Token Ring */
  {25, 65535, "IPv[46] MTU"}    /* The IPv[46] Maximum MTU */
};

static const pmtud_L2_t *L2_1454 = &L2[9];
static const pmtud_L2_t *L2_1500 = &L2[12];
static const int         L2_cnt  = sizeof(L2) / sizeof(pmtud_L2_t);

#define TRACE_OPT_DPORT       1
#define TRACE_OPT_FIRSTHOP    2
#define TRACE_OPT_GAPLIMIT    3
#define TRACE_OPT_GAPACTION   4
#define TRACE_OPT_LOOPS       5
#define TRACE_OPT_LOOPACTION  6
#define TRACE_OPT_MAXTTL      7
#define TRACE_OPT_PMTUD       8
#define TRACE_OPT_PAYLOAD     9
#define TRACE_OPT_PROTOCOL    10
#define TRACE_OPT_ATTEMPTS    11
#define TRACE_OPT_ALLATTEMPTS 12
#define TRACE_OPT_SPORT       13
#define TRACE_OPT_TOS         14
#define TRACE_OPT_TTLDST      15
#define TRACE_OPT_WAIT        16
#define TRACE_OPT_SRCADDR     17
#define TRACE_OPT_CONFIDENCE  18
#define TRACE_OPT_WAITPROBE   19
#define TRACE_OPT_STOPSET     20
#define TRACE_OPT_DTREE       21

static const scamper_option_in_t opts[] = {
  {'c', NULL, TRACE_OPT_CONFIDENCE,  SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, TRACE_OPT_DPORT,       SCAMPER_OPTION_TYPE_STR},
  {'f', NULL, TRACE_OPT_FIRSTHOP,    SCAMPER_OPTION_TYPE_NUM},
  {'g', NULL, TRACE_OPT_GAPLIMIT,    SCAMPER_OPTION_TYPE_NUM},
  {'G', NULL, TRACE_OPT_GAPACTION,   SCAMPER_OPTION_TYPE_NUM},
  {'l', NULL, TRACE_OPT_LOOPS,       SCAMPER_OPTION_TYPE_NUM},
  {'L', NULL, TRACE_OPT_LOOPACTION,  SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, TRACE_OPT_MAXTTL,      SCAMPER_OPTION_TYPE_NUM},
  {'M', NULL, TRACE_OPT_PMTUD,       SCAMPER_OPTION_TYPE_NULL},
  {'p', NULL, TRACE_OPT_PAYLOAD,     SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, TRACE_OPT_PROTOCOL,    SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, TRACE_OPT_ATTEMPTS,    SCAMPER_OPTION_TYPE_NUM},
  {'Q', NULL, TRACE_OPT_ALLATTEMPTS, SCAMPER_OPTION_TYPE_NULL},
  {'s', NULL, TRACE_OPT_SPORT,       SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, TRACE_OPT_SRCADDR,     SCAMPER_OPTION_TYPE_STR},
  {'t', NULL, TRACE_OPT_TOS,         SCAMPER_OPTION_TYPE_NUM},
  {'T', NULL, TRACE_OPT_TTLDST,      SCAMPER_OPTION_TYPE_NULL},
  {'w', NULL, TRACE_OPT_WAIT,        SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, TRACE_OPT_WAITPROBE,   SCAMPER_OPTION_TYPE_NUM},
  {'z', NULL, TRACE_OPT_STOPSET,     SCAMPER_OPTION_TYPE_STR},
  {'Z', NULL, TRACE_OPT_DTREE,       SCAMPER_OPTION_TYPE_NULL},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_trace_usage(void)
{
  return "trace [-MQTZ] [-c confidence] [-d dport] [-f firsthop]\n"
         "      [-g gaplimit] [-G gapaction] [-l loops] [-L loopaction]\n"
         "      [-m maxttl] [-p payload] [-P method] [-q attempts] \n"
         "      [-s sport] [-S srcaddr] [-t tos] [-w wait-timeout] \n"
         "      [-W wait-probe] [-z stopset]";
}

static int k(trace_state_t *state)
{
  /*
   * number of probes (k) to send to rule out a load-balancer having n hops;
   * 95% confidence level first from 823-augustin-e2emon.pdf, then extended
   * with gmp-based code.
   * 99% confidence derived with gmp-based code.
   */
  static const int k[][2] = {
    {   0,   0 },
    {   0,   0 }, 
    {   6,   8 }, /* n=2  : +6, +8 */
    {  11,  15 }, /* n=3  : +5, +7 */
    {  16,  21 }, /* n=4  : +5, +6 */
    {  21,  28 }, /* n=5  : +5, +7 */
    {  27,  36 }, /* n=6  : +6, +8 */
    {  33,  43 }, /* n=7  : +6, +7 */
    {  38,  51 }, /* n=8  : +5, +8 */
    {  44,  58 }, /* n=9  : +6, +7 */
    {  51,  66 }, /* n=10 : +7, +8 */
    {  57,  74 }, /* n=11 : +6, +8 */
    {  63,  82 }, /* n=12 : +6, +8 */
    {  70,  90 }, /* n=13 : +7, +8 */
    {  76,  98 }, /* n=14 : +6, +8 */
    {  83, 106 }, /* n=15 : +7, +8 */
    {  90, 115 }, /* n=16 : +7, +9 */
    {  96, 123 }, /* n=17 : +6, +8 */
    { 103, 132 }, /* n=18 : +7, +9 */
    { 110, 140 }, /* n=19 : +7, +8 */
    { 117, 149 }, /* n=20 : +7, +9 */
    { 124, 157 }, /* n=21 */
    { 131, 166 }, /* n=22 */
    { 138, 175 }, /* n=23 */
    { 145, 183 }, /* n=24 */
    { 152, 192 }, /* n=25 */
  };

#define TRACE_CONFIDENCE_MAX_N 25

  assert(state->confidence < 2);
  assert(state->n >= 2);
  assert(state->n <= TRACE_CONFIDENCE_MAX_N);
  return k[state->n][state->confidence];
}

/*
 * trace_queue
 *
 * the task is ready to be probed again.  put it in a queue to wait a little
 * longer, or put it into the queue to be probed asap.
 */
static int trace_queue(scamper_task_t *task)
{
  scamper_trace_t *trace = task->data;
  trace_state_t   *state = task->state;
  struct timeval   tv;

  if(trace->wait_probe == 0)
    {
      return scamper_queue_probe(task->queue);
    }

  gettimeofday_wrap(&tv);
  if(timeval_cmp(&state->next_tx, &tv) <= 0)
    {
      return scamper_queue_probe(task->queue);
    }

  return scamper_queue_wait_tv(task->queue, &state->next_tx);
}

static int trace_interface_cmp(const void *va, const void *vb)
{
  scamper_addr_t *a = *((scamper_addr_t **)va);
  scamper_addr_t *b = *((scamper_addr_t **)vb);
  return scamper_addr_cmp(a, b);
}

/*
 * pmtud_L2_hop
 *
 * utility to replace the currently cached hop record recorded when scamper
 * does the L2 MTU search.
 */
static void pmtud_L2_hop(trace_state_t *state, scamper_trace_hop_t *hop)
{
  assert(state->L2 != NULL);

  if(state->L2->hop != NULL) scamper_trace_hop_free(state->L2->hop);
  state->L2->hop = hop;
  return;
}

/*
 * pmtud_L2_set_probesize
 *
 * given the lower and upper values of the PMTU search, suggest a packet
 * size to probe next.  apply a few heuristics to the search to try and
 * find the PMTU to the next node faster.
 */
static void pmtud_L2_set_probesize(trace_state_t *state,
				   const int lower, const int upper)
{
  int idx = state->L2->idx;
  int size;

  /* callers should detect end of L2 search before calling this function */
  assert(lower + 1 != upper);

  /* make sure the L2->idx parameter has been set (to something reasonable) */
  assert(idx >= 0);
  assert(idx < L2_cnt);

  /* make sure the suggested window size is within the current window */
  assert(state->L2->lower == -1 || lower >= state->L2->lower);
  assert(state->L2->upper == -1 || upper <= state->L2->upper);

  /*
   * if we've narrowed it down to between two entries in the L2 table,
   * then try one byte higher than the lower, as there's a fair chance
   * the underlying mtu will be L2[idx].mtu.
   *
   * we make an exception if the lower bounds is Ethernet: there exists
   * a strong possibility the underlying MTU is Ethernet, and the cost
   * of guessing wrong [i.e. getting an unexpected response] is small.
   */
  if(lower == 1500 || (lower == L2[idx].mtu && upper <= L2[idx+1].mtu))
    {
      size = lower + 1;
    }
  /*
   * if there is a media MTU higher than the current lower bounds that
   * is smaller than the upper bounds, then try it
   */
  else if(lower >= L2[idx].mtu && L2[idx+1].mtu < upper)
    {
      size = L2[++idx].mtu;
    }
  /*
   * if we did not get a response to the last media MTU probe, and there
   * is a smaller known media MTU to try, then try it now
   */
  else if(upper == L2[idx].mtu && lower < L2[idx-1].mtu)
    {
      size = L2[--idx].mtu;
    }
  /*
   * scamper is operating between two known MTU types, do a binary chop
   */
  else
    {
      size = (lower + upper) / 2;
    }

  state->attempt = 0;
  state->payload_size = size - state->header_size;
  state->L2->idx = idx;
  state->L2->lower = lower;
  state->L2->upper = upper;

  return;
}

/*
 * pmtud_L2_init
 *
 * utility to search the L2 table for a suitable initial probe size, based
 * on known [to scamper] L2 media MTUs in relation to the last probe sent that
 * went unacknowledged.
 */
static int pmtud_L2_init(trace_state_t *state)
{
  pmtud_L2_state_t *L2s;
  int size = state->header_size + state->payload_size;
  int idx;

  /*
   * if the probe that was not answered is > 1500 bytes and scamper has
   * not got a response to a packet 1500 bytes or larger yet, then
   * forcibly try the ethernet MTU next, as the chances are good that the
   * media will be plain old ethernet.
   */
  if(size > 1500)
    {
      idx = L2_1500->idx;
    }
  /*
   * if the probe that was not answered is > 1454 bytes, then forcibly try
   * the lower bounds of X-over-ethernet types.
   */
  else if(size > 1454)
    {
      idx = L2_1454->idx;
    }
  else
    {
      for(idx=0; idx<L2_cnt-1; idx++)
	{
	  if(size > L2[idx].mtu && size <= L2[idx+1].mtu)
	    {
	      break;
	    }
	}
    }

  if((L2s = malloc(sizeof(pmtud_L2_state_t))) == NULL)
    {
      return -1;
    }

  L2s->idx   = idx;
  L2s->hop   = NULL;
  L2s->lower = -1;
  L2s->upper = size;
  L2s->in    = size;
  L2s->out   = -1;

  state->L2           = L2s;
  state->payload_size = L2[idx].mtu - state->header_size;
  state->attempt      = 0;

  return 0;
}

/*
 * pmtud_TTL_hop
 *
 * utility to replace the currently cached hop record recorded when scamper
 * does the TTL search.
 */
static void pmtud_TTL_hop(trace_state_t *state, scamper_trace_hop_t *hop)
{
  if(state->TTL->hop != NULL)
    {
      scamper_trace_hop_free(state->TTL->hop);
    }
  state->TTL->hop = hop;
  return;
}

/*
 * pmtud_TTL_set_probettl
 *
 * return: 0 if there are no more TTLs to probe, 1 if probing should continue
 */
static int pmtud_TTL_set_probettl(scamper_task_t *task,
				  const int lower, int upper)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  int cur;

  /* check to see if we have to do any more TTL searching */
  while(lower + 1 < upper)
    {
      /* halve the TTL space */
      cur = (lower + upper) / 2;

      /*
       * check to see if experience at soliciting a TTL expired message has
       * been good.  skip TTLs that have been non-responsive
       */
      while(cur < upper && trace->hops[cur-1] == NULL)
	{
	  cur++;
	}

      /* scamper got a suitable TTL probe value, so we are done */
      if(cur != upper)
	{
	  state->TTL->lower = lower;
	  state->TTL->upper = upper;
	  state->ttl = cur;
	  state->attempt = 0;
	  return 1;
	}

      /*
       * there are no TTLs above the half-way point to probe for, so try for
       * ones lower
       */
      upper = (lower + upper) / 2;
    }

  return 0;
}

/*
 * hop_find
 *
 * check to see if there is any other hop in the trace with the
 * same address
 */
static scamper_trace_hop_t *hop_find(const scamper_trace_t *trace,
				     const scamper_addr_t *addr)
{
  scamper_trace_hop_t *hop;
  uint16_t i;

  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    {
      for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	{
	  if(scamper_addr_cmp(hop->hop_addr, addr) == 0)
	    {
	      return hop;
	    }
	}
    }

  return NULL;
}

/*
 * pmtud_TTL_init
 *
 * initialise the bounds of a TTL search
 */
static int pmtud_TTL_init(scamper_task_t *task)
{
  scamper_trace_hop_t *hop;
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  int lower, upper;
  uint8_t turn_ttl;

  if((state->TTL = malloc_zero(sizeof(pmtud_TTL_state_t))) == NULL)
    {
      return -1;
    }

  /*
   * the packet size that is dropped silently is the size we are
   * doing a TTL limited search with
   */
  state->payload_size = state->L2->in - state->header_size;

  /*
   * use the last ICMP fragmentation required message recorded in the
   * path MTU discovery phase to infer a suitable lower-bound for inferring
   * the range of TTLs that could be responsible for not sending an ICMP
   * fragmentation required message
   */
  if(state->last_fragmsg == NULL)
    {
      lower = 0;
    }
  else
    {
      SCAMPER_TRACE_HOP_GET_TURN_TTL(state->last_fragmsg, turn_ttl);
      if((lower = state->last_fragmsg->hop_probe_ttl - turn_ttl) < 1)
	{
	  lower = 0;
	}
    }

  /*
   * the upper bound of TTLs to search is set by closest response past
   * the hop that sends nothing
   */
  if((hop = hop_find(trace, state->L2->hop->hop_addr)) != NULL)
    {
      upper = hop->hop_probe_ttl;
    }
  else
    {
      SCAMPER_TRACE_HOP_GET_TURN_TTL(state->L2->hop, turn_ttl);
      upper = state->L2->hop->hop_probe_ttl - turn_ttl + 1;
    }

  /* if the TTL limited search is a null operation, then say so */
  if(pmtud_TTL_set_probettl(task, lower, upper) == 0)
    {
      return 0;
    }

  return 1;
}

/*
 * pmtud_hopins
 *
 * take the hop structure and put it into the list of hops based on the
 * TTL distance into the path.
 * XXX: this isn't what this function actually does.
 */
static void pmtud_hopins(scamper_trace_t *trace, scamper_trace_hop_t *hop)
{
  scamper_trace_hop_t *cur, *pre;

  assert(hop != NULL);

  if((pre = trace->pmtud->hops) == NULL)
    {
      trace->pmtud->hops = hop;
      return;
    }
  
  for(cur = pre->hop_next; cur != NULL; cur = cur->hop_next)
    {
      pre = cur;
    }

  pre->hop_next = hop;
  hop->hop_next = cur;

  return;
}

/*
 * pmtu_L2_search_end
 *
 * scamper has had to infer the underlying next-hop MTU due to a pmtud
 * fault.  given the hop used to infer the nhmtu, insert that into the
 * trace and tidy up.
 */
static int pmtud_L2_search_end(scamper_task_t *task)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  scamper_trace_hop_t *hop;
  uint16_t out;

  assert(state->L2->out >= 0);
  assert(state->L2->out <= 65535);

  out = state->L2->out;

  /*
   * copy details of the TTL-expired message furthest into the path
   * into the trace if there is one to copy
   */
  if(state->TTL != NULL)
    {
      /*
       * if there was no TTL response with the large packet from anywhere
       * in the path
       */
      if(state->TTL->hop == NULL)
	{
	  /*
	   * if the lowest TTL tried was zero, then we infer that the host
	   * itself has an MTU mismatch with the particular router it is
	   * using for the destination
	   */
	  if(state->TTL->lower == 0)
	    {
	      scamper_tlv_set(&trace->pmtud->tlvs,
			      SCAMPER_TRACE_PMTUD_TLV_OUTMTU, 2, &out);
	    }
	}
      else
	{
	  pmtud_hopins(trace, state->TTL->hop);
	}
      free(state->TTL);
      state->TTL = NULL;
    }

  /*
   * copy details of the hop to terminate the largest probe into
   * the pmtu struct.  hops between the TTL expired message (if we
   * have one) and the ICMP unreach message have their PMTU inferred
   */
  if((hop = state->L2->hop) != NULL)
    {
      pmtud_hopins(trace, hop);
      state->last_fragmsg = hop;
      free(state->L2);
      state->L2 = NULL;

      /*
       * if the hop that we last recorded is a hop message that would
       * ordinarily have caused scamper to stop PMTU discovery, then
       * stop it now
       */
      if(!SCAMPER_TRACE_HOP_IS_ICMP_PACKET_TOO_BIG(hop))
	{
	  trace->pmtud->pmtu = hop->hop_probe_size;
	  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
	  return 1;
	}
    }

  if(state->L2 != NULL)
    {
      free(state->L2);
      state->L2 = NULL;
    }

  state->payload_size = out - state->header_size;
  state->mode = MODE_PMTUD_DEFAULT;
  state->attempt = 0;
  state->ttl = 255;

  return 0;
}

static int dtree_lss_add(scamper_addr_t *iface)
{
  if(splaytree_insert(lss, iface) != NULL)
    {
      scamper_addr_use(iface);
      return 0;
    }
  return -1;
}

static int dtree_lss_in(scamper_addr_t *iface)
{
  if(splaytree_find(lss, iface) != NULL)
    return 1;
  return 0;
}

static int state_lss_in(trace_state_t *state, scamper_addr_t *iface)
{
  if(array_find((void **)state->lss, state->lssc, iface,
		trace_interface_cmp) != NULL)
    {
      return 1;
    }
  return 0;
}

static int state_lss_add(trace_state_t *state, scamper_addr_t *iface)
{
  if(array_insert((void ***)&state->lss, &state->lssc, iface,
		  trace_interface_cmp) == 0)
    {
      return 0;
    }
  return -1;
}

/*
 * trace_ipid_fudge
 *
 * play games with the embedded IP ID, which may come back with a different
 * IP ID than what was sent; return the ID of the corresponding probe in *id.
 * this code was inspired by information from David Malone.
 *
 * the IPID transmitted is assigned from a counter (state->id_next) which
 * starts from one -- *not* zero.  this is so systems that zero the IPID
 * will not confuse this algorithm.
 *
 * the IPID is transmitted by scamper in network byte order.
 *
 */
static int trace_ipid_fudge(const trace_state_t *state,
			    const uint16_t ipid, uint16_t *id)
{
  /* ensure the IP ID is not zero */
  if(ipid == 0)
    {
      return -1;
    }

  /* check if the IP ID is in range */
  if(ipid <= state->id_next)
    {
      *id = ipid - 1;
      return 0;
    }
  
  /* check if the IP ID was incremented */
  if(ipid == state->id_next + 1)
    {
      scamper_debug(__func__, "ip id one greater than sent");
      *id = ipid - 2;
      return 0;
    }

  /* check if the IP ID was byte swapped. XXX: is this correct? */
  if(byteswap16(ipid) <= state->id_next)
    {
      scamper_debug(__func__, "ip id byte swapped");
      *id = byteswap16(ipid) - 1;
      return 0;
    }

  return -1;
}

/*
 * trace_stop
 *
 * set the trace's stop parameters to whatever it is passed
 */
static void trace_stop(scamper_trace_t *trace,
		       const uint8_t reason, const uint8_t data)
{
  /* if we've already set a stop reason, then don't clobber it */
  if(trace->stop_reason != SCAMPER_TRACE_STOP_NONE)
    {
      scamper_debug(__func__, "reason %d/%d preceeds %d/%d",
		    trace->stop_reason, trace->stop_data, reason, data);
      return;
    }

  trace->stop_reason = reason;
  trace->stop_data   = data;

  return;
}

static void trace_stop_completed(scamper_trace_t *trace)
{
  trace_stop(trace, SCAMPER_TRACE_STOP_COMPLETED, 0);
  return;
}

static void trace_stop_gaplimit(scamper_trace_t *trace)
{
  trace_stop(trace, SCAMPER_TRACE_STOP_GAPLIMIT, 0);
  return;
}

static void trace_stop_error(scamper_trace_t *trace, int error)
{
  trace_stop(trace, SCAMPER_TRACE_STOP_ERROR, error);
  return;
}

static void trace_stop_hoplimit(scamper_trace_t *trace)
{
  trace_stop(trace, SCAMPER_TRACE_STOP_HOPLIMIT, 0);
  return;
}

/*
 * trace_isloop
 *
 * given a trace and a hop record, determine if there is a loop.
 */
static int trace_isloop(const scamper_trace_t *trace,
			const scamper_trace_hop_t *hop,
			trace_state_t *state)
{
  scamper_trace_hop_t *tmp;
  uint8_t ttl_h, ttl_t;
  int i;

  /* need at least a couple of probes first */
  if(hop->hop_probe_ttl <= trace->firsthop)
    {
      return 0;
    }

  /*
   * check to see if the address has already been seen this hop; if it is,
   * then we've already checked this address for loops so we don't need to
   * check it again.
   */
  for(tmp = trace->hops[hop->hop_probe_ttl-1]; tmp != hop; tmp = tmp->hop_next)
    {
      if(scamper_addr_cmp(hop->hop_addr, tmp->hop_addr) == 0)
	{
	  return 0;
	}
    }

  /* compare all hop records until the hop prior to this one */
  for(i=hop->hop_probe_ttl-2; i>=trace->firsthop-1; i--)
    {
      for(tmp = trace->hops[i]; tmp != NULL; tmp = tmp->hop_next)
	{
	  assert(i+1 == tmp->hop_probe_ttl);

	  /* if the addresses match, then there is a loop */
	  if(scamper_addr_cmp(hop->hop_addr, tmp->hop_addr) == 0)
	    {
	      /*
	       * if the loop is between adjacent hops
	       */
	      if(tmp->hop_probe_ttl + 1 == hop->hop_probe_ttl)
		{
		  /*
		   * check for zero-ttl forwarding.  continue probing if
		   * the condition is met.
		   */
		  SCAMPER_TRACE_HOP_GET_TURN_TTL(tmp, ttl_t);
		  SCAMPER_TRACE_HOP_GET_TURN_TTL(hop, ttl_h);
		  if(ttl_t == 0 && ttl_h == 1)
		    {
		      return 0;
		    }

		  /*
		   * check the loopaction parameter for what we should do
		   *
		   * the loopaction parameter has values 0 .. 255; currently
		   * the loopaction parameter counts the number of loops
		   * between adjacent hops to ignore.
		   */
		  if(++state->iloopc <= trace->loopaction)
		    return 0;		  
		}

	      /* check if the loop condition is met */
	      state->loopc++;
	      if(state->loopc >= trace->loops)
		{
		  return 1;
		}

	      /* count the loop just once for this hop */
	      break;
	    }
	}
    }

  return 0;
}

/*
 * trace_hopins
 *
 * insert the hop record into the hop list at the appropriate place
 */
static void trace_hopins(scamper_trace_hop_t **hops, scamper_trace_hop_t *hop)
{
  scamper_trace_hop_t *pre, *cur;

  assert(hops != NULL);
  assert(hop != NULL);

  /* insert at head if no other hop recorded */
  if((cur = *hops) == NULL)
    {
      *hops = hop;
      hop->hop_next = NULL;
      return;
    }

  /* search for the place to insert this hop record */
  pre = NULL;
  while(cur != NULL && cur->hop_probe_id <= hop->hop_probe_id)
    {
      pre = cur;
      cur = cur->hop_next;
    }

  /* the place to insert is at the head of the list */
  if(pre == NULL)
    {
      assert(hop->hop_probe_id < cur->hop_probe_id);
      *hops = hop;
    }
  else
    {
      pre->hop_next = hop;
    }
  hop->hop_next = cur;

  return;
}

/*
 * trace_handlerror
 *
 * the code encountered some error when doing the traceroute, so stop the
 * trace now.
 */
static int trace_handleerror(scamper_task_t *task, const int error)
{
  trace_stop_error((scamper_trace_t *)task->data, error);
  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
  return 0;
}

/*
 * trace_hop
 *
 * this function creates a generic hop record with the basic details from
 * the probe structure copied in, as well as an address based on the details
 * passed in
 */
static scamper_trace_hop_t *trace_hop(const trace_probe_t *probe,
				      const int af, const void *addr)
{
  scamper_trace_hop_t *hop;
  int type;

  /* determine the scamper address type to use from the address family */
  if(af == AF_INET) type = SCAMPER_ADDR_TYPE_IPV4;
  else if(af == AF_INET6) type = SCAMPER_ADDR_TYPE_IPV6;
  else return NULL;

  if((hop = scamper_trace_hop_alloc()) == NULL)
    {
      return NULL;
    }

  if((hop->hop_addr = scamper_addrcache_get(addrcache, type, addr)) == NULL)
    {
      scamper_trace_hop_free(hop);
      return NULL;
    }

  hop->hop_probe_ttl  = probe->ttl;
  hop->hop_probe_id   = probe->id + 1;
  hop->hop_probe_size = probe->size;  

  /*
   * if the probe's datalink tx timestamp flag is set, scamper has a tx
   * timestamp recorded
   */
  if(probe->flags & TRACE_PROBE_FLAG_DL_TX)
    {
      hop->hop_flags |= SCAMPER_TRACE_HOP_FLAG_TS_DL_TX;
    }

  return hop;
}

/*
 * trace_icmp_hop
 *
 * given a trace probe and an ICMP response, allocate and initialise a
 * scamper_trace_hop record.
 */
static scamper_trace_hop_t *trace_icmp_hop(scamper_trace_t *trace,
					   trace_probe_t *probe,
					   scamper_icmp_resp_t *ir)
{
  scamper_trace_hop_t *hop;
  scamper_addr_t addr;

  /* get a pointer to the source address of the ICMP response */
  if(scamper_icmp_resp_src(ir, &addr) != 0)
    {
      return NULL;
    }

  /* create a generic hop record without any special bits filled out */
  if((hop = trace_hop(probe, ir->ir_af, addr.addr)) == NULL)
    {
      return NULL;
    }

  /* fill out the basic bits of the hop structure */
  hop->hop_reply_size = ir->ir_ip_size;
  hop->hop_icmp_type  = ir->ir_icmp_type;
  hop->hop_icmp_code  = ir->ir_icmp_code;

  /*
   * we cannot depend on the TTL field of the IP packet being made available,
   * so we signal explicitly when the reply ttl is valid
   */
  if(ir->ir_ip_ttl != -1)
    {
      hop->hop_reply_ttl = (uint8_t)ir->ir_ip_ttl;
      hop->hop_flags |= SCAMPER_TRACE_HOP_FLAG_REPLY_TTL;
    }

  /*
   * if the probe's datalink rx timestamp flag is set, scamper has a rx
   * timestamp recorded
   */
  if(probe->flags & TRACE_PROBE_FLAG_DL_RX)
    {
      hop->hop_flags |= SCAMPER_TRACE_HOP_FLAG_TS_DL_RX;
      timeval_diff_tv(&hop->hop_rtt, &probe->tx_tv, &probe->rx_tv);
    }
  else
    {
      timeval_diff_tv(&hop->hop_rtt, &probe->tx_tv, &ir->ir_rx);
      if(ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_KERNRX)
	{
	  hop->hop_flags |= SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX;
	}
    }

  if(SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir))
    {
      if(scamper_tlv_set(&hop->hop_tlvs, SCAMPER_TRACE_HOP_TLV_NHMTU,
			 2, &ir->ir_icmp_nhmtu) == NULL)
	{
	  goto err;
	}
    }

  if(ir->ir_af == AF_INET)
    {
      if(scamper_tlv_set(&hop->hop_tlvs, SCAMPER_TRACE_HOP_TLV_REPLY_IPID,
			 2, &ir->ir_ip_id) == NULL ||
	 scamper_tlv_set(&hop->hop_tlvs, SCAMPER_TRACE_HOP_TLV_REPLY_IPTOS,
			 1, &ir->ir_ip_tos) == NULL)
	{
	  goto err;
	}
    }

  if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir))
    {
      /*
       * IPv4: record ToS byte
       * IPv6: might pay to record traffic class byte here.
       */
      if(ir->ir_af == AF_INET &&
	 scamper_tlv_set(&hop->hop_tlvs, SCAMPER_TRACE_HOP_TLV_INNER_IPTOS,
			 1, &ir->ir_inner_ip_tos) == NULL)
	{
	  goto err;
	}

      if(ir->ir_inner_ip_ttl != 1)
	{
	  if(scamper_tlv_set(&hop->hop_tlvs, SCAMPER_TRACE_HOP_TLV_INNER_IPTTL,
			     1, &ir->ir_inner_ip_ttl) == NULL)
	    {
	      goto err;
	    }
	}

      if(ir->ir_inner_ip_size != probe->size)
	{
	  if(scamper_tlv_set(&hop->hop_tlvs, SCAMPER_TRACE_HOP_TLV_INNER_IPLEN,
			     2, &ir->ir_inner_ip_size) == NULL)
	    {
	      goto err;
	    }
	}
    }

  /* if ICMP extensions are included, then parse and include them. */
  if(ir->ir_ext != NULL &&
     scamper_icmpext_parse(&hop->hop_icmpext,ir->ir_ext,ir->ir_extlen) != 0)
    {
      goto err;
    }

  /* record the fact that we have a hop record thanks to this probe */
  if(probe->rx != 65535) probe->rx++;

  return hop;

 err:
  scamper_trace_hop_free(hop);
  return NULL;
}

static scamper_trace_hop_t *trace_tcp_hop(trace_probe_t *probe,
					  scamper_dl_rec_t *dl)
{
  scamper_trace_hop_t *hop;

  /* create a generic hop record without any special bits filled out */
  if((hop = trace_hop(probe, dl->dl_af, dl->dl_ip_src)) == NULL)
    {
      return NULL;
    }

  /* fill out the basic bits of the hop structure */
  hop->hop_reply_size = dl->dl_ip_size;
  hop->hop_reply_ttl = dl->dl_ip_ttl;
  hop->hop_tcp_flags = dl->dl_tcp_flags;
  timeval_diff_tv(&hop->hop_rtt, &probe->tx_tv, &dl->dl_tv);

  /* set the flags that are known to apply to this hop record */
  hop->hop_flags |= (SCAMPER_TRACE_HOP_FLAG_REPLY_TTL |
		     SCAMPER_TRACE_HOP_FLAG_TCP |
		     SCAMPER_TRACE_HOP_FLAG_TS_DL_RX);

  if(dl->dl_af == AF_INET)
    {
      if(scamper_tlv_set(&hop->hop_tlvs, SCAMPER_TRACE_HOP_TLV_REPLY_IPID,
			 2, &dl->dl_ip_id) == NULL ||
	 scamper_tlv_set(&hop->hop_tlvs, SCAMPER_TRACE_HOP_TLV_REPLY_IPTOS,
			 1, &dl->dl_ip_tos) == NULL)
	{
	  goto err;
	}
    }

  return hop;

 err:
  scamper_trace_hop_free(hop);
  return NULL;
}

/*
 * trace_next_mode
 *
 * if the trace is going into another mode, this function figures out
 * which mode to put it into
 */
static void trace_next_mode(scamper_task_t *task)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  uint16_t ifmtu;
  int ifindex;

  if((trace->flags & SCAMPER_TRACE_FLAG_DTREE) != 0)
    {
      if(state->mode == MODE_DTREE_FWD)
	{
	  if(trace->firsthop > 1)
	    {
	      state->mode    = MODE_DTREE_BACK;
	      state->ttl     = trace->firsthop - 1;
	      state->attempt = 0;
	      trace_queue(task);
	    }
	  else
	    {
	      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
	    }
	}
      else if(state->mode == MODE_DTREE_BACK)
	{
	  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
	}
      return;
    }

  /* XXX clean up the rest of this function */

  if((trace->flags & SCAMPER_TRACE_FLAG_PMTUD) == 0 ||
     trace->stop_reason == SCAMPER_TRACE_STOP_HOPLIMIT ||
     trace->stop_reason == SCAMPER_TRACE_STOP_GAPLIMIT ||
     trace->stop_reason == SCAMPER_TRACE_STOP_LOOP ||
     trace->stop_reason == SCAMPER_TRACE_STOP_NONE)
    {
      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
      return;
    }

  /* if the interface's MTU is useless, then we can't do PMTUD */
  scamper_fd_ifindex(state->dl, &ifindex);
  if(scamper_if_getmtu(ifindex, &ifmtu) == -1 || ifmtu <= state->header_size)
    {
      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
      return;
    }

  if((trace->pmtud = malloc_zero(sizeof(struct scamper_trace_pmtud))) == NULL)
    {
      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
      return;
    }
  trace->pmtud->ifmtu = ifmtu;

  state->attempt      = 0;
  state->mode         = MODE_PMTUD_DEFAULT;
  state->payload_size = ifmtu - state->header_size;
  state->ttl          = 255;

  trace_queue(task);
  return;
}

/*
 * trace_stop_reason
 *
 * check to see if we have a stop condition based on the hop record
 */
static void trace_stop_reason(scamper_trace_t *trace, scamper_trace_hop_t *hop,
			      trace_state_t *state,
			      uint8_t *stop_reason, uint8_t *stop_data)
{
  int rc;

  /*
   * the message received is an ICMP port unreachable -- something that
   * the destination should have sent.  make sure the port unreachable
   * message makes sense based on the traceroute type.
   */
  if(SCAMPER_TRACE_HOP_IS_ICMP_UNREACH_PORT(hop) &&
     (SCAMPER_TRACE_TYPE_IS_UDP(trace) || SCAMPER_TRACE_TYPE_IS_TCP(trace)))
    {
      *stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
      *stop_data = 0;
    }
  else if(SCAMPER_TRACE_HOP_IS_ICMP_UNREACH(hop))
    {
      *stop_reason = SCAMPER_TRACE_STOP_UNREACH;
      *stop_data = hop->hop_icmp_code;
    }
  else if(SCAMPER_TRACE_HOP_IS_ICMP_ECHO_REPLY(hop))
    {
      /*
       * the message received is an ICMP echo reply -- something that only
       * makes sense to include as part of the traceroute if the traceroute
       * is using echo requests.
       */
      if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO ||
	 trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
	{
	  *stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
	  *stop_data = 0;
	}
      else
	{
	  *stop_reason = SCAMPER_TRACE_STOP_NONE;
	  *stop_data = 0;
	}
    }
  else if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV6 &&
	  hop->hop_icmp_type == ICMP6_PACKET_TOO_BIG)
    {
      /*
       * IPv6 uses a different ICMP type for packet too big messages, so
       * check this.
       */
      *stop_reason = SCAMPER_TRACE_STOP_ICMP;
      *stop_data   = hop->hop_icmp_type;
    }
  else if(trace->loops != 0 && (rc = trace_isloop(trace, hop, state)) != 0)
    {
      /* check for a loop condition */
      *stop_reason = SCAMPER_TRACE_STOP_LOOP;
      *stop_data   = 0;
    }
  else if(SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop) &&
	  (trace->flags & SCAMPER_TRACE_FLAG_IGNORETTLDST) == 0 &&
	  scamper_addr_cmp(trace->dst, hop->hop_addr) == 0)
    {
      /*
       * if an ICMP TTL expired message is received from an IP address
       * matching the destination being probed, and the traceroute is
       * to stop when this occurs, then stop.
       */
      *stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
      *stop_data   = 0;
    }
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace) && SCAMPER_TRACE_HOP_IS_TCP(hop))
    {
      *stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
      *stop_data   = 0;
    }
  else if((trace->flags & SCAMPER_TRACE_FLAG_DTREE) != 0 &&
	  scamper_trace_dtree_gss_find(trace, hop->hop_addr) != NULL)
    {
      *stop_reason = SCAMPER_TRACE_STOP_GSS;
      *stop_data   = 0;
      trace->dtree->gss_stop = scamper_addr_use(hop->hop_addr);
    }
  else
    {
      *stop_reason = SCAMPER_TRACE_STOP_NONE;
      *stop_data   = 0;
    }

  return;
}

/*
 * handleicmp_trace
 *
 * we received an ICMP response in the traceroute state.  check to see
 * if the probe is in sequence, and adjust the trace accordingly.
 */
static int handleicmp_trace(scamper_task_t *task,
			    scamper_icmp_resp_t *ir,
			    trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  scamper_trace_hop_t *hop;
  uint8_t stop_reason;
  uint8_t stop_data;
  size_t len;

  assert(state->mode == MODE_TRACE ||
	 state->mode == MODE_DTREE_FWD || state->mode == MODE_DTREE_BACK);

  /* we should only have to deal with probes sent while in the trace state */
  if(probe->mode != MODE_TRACE &&
     probe->mode != MODE_DTREE_FWD && probe->mode != MODE_DTREE_BACK)
    {
      return 0;
    }

  /* create a hop record and insert it into the trace */
  if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
    {
      return -1;
    }
  trace_hopins(&trace->hops[hop->hop_probe_ttl-1], hop);

  /*
   * if the response is not for the current working hop (i.e. a late reply)
   * check if probing should now halt.  otherwise keep waiting.
   */
  if(hop->hop_probe_ttl != state->ttl)
    {
      /* XXX: handle doubletree */
      trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
      if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	{
	  trace_stop(trace, stop_reason, stop_data);
	  trace_next_mode(task);
	}
      return 0;
    }

  /*
   * the rest of the code in this function deals with the fact this is a
   * reply for the current working hop.
   *
   * check if we are to send all allotted probes to the target
   */
  if((trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS) != 0)
    {
      assert(trace->confidence == 0);

      /*
       * if we get an out of order reply, then we go back to waiting for
       * the one we just probed for
       */
      if(probe->id+1 != state->attempt)
	{
	  return 0;
	}

      /*
       * this response is for the last probe sent.  if there are still
       * probes to send for this hop, then send the next one
       */
      if(state->attempt < trace->attempts)
	{
	  trace_queue(task);
	  return 0;
	}
    }
  else if(trace->confidence != 0)
    {
      /*
       * record details of the interface, if its details are not
       * currently held
       */
      if(array_find((void **)state->interfaces, state->interfacec,
		    hop->hop_addr, trace_interface_cmp) == NULL)
	{
	  len = (state->interfacec + 1) * sizeof(scamper_addr_t *);
	  if(realloc_wrap((void **)&state->interfaces, len) != 0)
	    {
	      printerror(errno, strerror, __func__,
			 "could not realloc interfaces");
	      trace_handleerror(task, errno);
	      return -1;
	    }

	  state->interfaces[state->interfacec++] = hop->hop_addr;

	  if(state->interfacec > 1)
	    {
	      qsort(state->interfaces, state->interfacec,
		    sizeof(scamper_addr_t *), trace_interface_cmp);
	      state->n++;
	    }
	}

      /*
       * make sure we know the required number of probes to send to reach
       * a particular confidence level
       */
      if(state->n <= TRACE_CONFIDENCE_MAX_N)
	{
	  /*
	   * if we get an out of order reply, then we go back to waiting for
	   * the one we just probed for
	   */
	  if(probe->id+1 != state->attempt)
	    {
	      return 0;
	    }

	  /*
	   * this response is for the last probe sent.  if there are still
	   * probes to send for this hop, then send the next one
	   */
	  if(state->attempt < k(state))
	    {
	      trace_queue(task);
	      return 0;
	    }
	}

      free(state->interfaces);
      state->interfaces = NULL;
      state->interfacec = 0;
      state->n = 2;
    }

  state->attempt = 0;

  if(state->mode == MODE_DTREE_BACK)
    {
      if(state->ttl == 1)
	{
	  trace_next_mode(task);
	  return 0;
	}

      /*
       * consult the local stop set to see if we should stop backwards
       * probing yet.
       */
      if(dtree_lss_in(hop->hop_addr) == 0)
	{
	  dtree_lss_add(hop->hop_addr);
	  state_lss_add(state, hop->hop_addr);
	  state->ttl--;
	  trace->firsthop--;
	  trace_queue(task);
	  return 0;
	}

      /*
       * if it is in the local stop set because there is forwarding loop
       * in this trace, handle that.
       */
      if(state_lss_in(state, hop->hop_addr) != 0)
	{
	  state->ttl--;
	  trace->firsthop--;
	  trace_queue(task);
	  return 0;
	}

      trace->dtree->lss_stop = scamper_addr_use(hop->hop_addr);
      trace_next_mode(task);
      return 0;
    }

  trace->hop_count++;
  state->ttl++;

  /*
   * if we're in a mode where we only care about the first response to
   * a probe, then check it now.  the else block below handles the case
   * where we want a larger number of responses from a hop.
   */
  if(trace->confidence == 0 &&
     (trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS) == 0)
    {
      /* check to see if we have a stop reason from the ICMP response */
      trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
      if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	{
	  /* did we get a stop condition out of all that? */
	  trace_stop(trace, stop_reason, stop_data);
	  trace_next_mode(task);
	  return 0;
	}
    }
  else
    {
      /* check all hop records for a reason to halt the trace */
      hop = trace->hops[trace->hop_count-1]; assert(hop != NULL);
      while(hop != NULL)
	{
	  trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
	  if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	    {
	      /* did we get a stop condition out of all that? */
	      trace_stop(trace, stop_reason, stop_data);
	      trace_next_mode(task);
	      return 0;
	    }
	  hop = hop->hop_next;
	}
    }

  /* check if we've reached the hoplimit */
  if(trace->hop_count == 255 || trace->hop_count == trace->hoplimit)
    {
      /* if not, has the hop limit now reached? */
      trace_stop_hoplimit(trace);
      trace_next_mode(task);
      return 0;
    }

  /* keep probing */
  trace_queue(task);
  return 0;
}

/*
 * handleicmp_dtree_first
 *
 * handle receiving an ICMP response to the first series of doubletree
 * probes which aims to find the place at which to commence probing
 */
static int handleicmp_dtree_first(scamper_task_t *task,scamper_icmp_resp_t *ir,
				  trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  scamper_trace_hop_t *hop;
  scamper_addr_t src;
  uint8_t stop_reason, stop_data;
  int done = 0;

  /* make sure the corresponding probe is one that was sent in this mode */
  if(probe->mode != MODE_DTREE_FIRST)
    return 0;

  /* ignore late replies if the firsthop has been shifted back */
  if(probe->ttl > trace->firsthop)
    return 0;
  assert(probe->ttl == trace->firsthop);

  /* get the source address of the reply */
  if(scamper_icmp_resp_src(ir, &src) != 0)
    return -1;

  /* the next probe we sent will be the first attempt at it */
  state->attempt = 0;

  /* check to see if the distance should be reduced */
  if(SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) ||
     SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) ||
     scamper_addr_cmp(trace->dst, &src) == 0)
    {
      /* halve the probe ttl if that can be done */
      if(probe->ttl > 1)
	{
	  trace->firsthop /= 2;
	  state->ttl = trace->firsthop;
	  trace_queue(task);
	  return 0;
	}
      assert(probe->ttl == 1);

      /* got response which can't be probed past at first hop. we're done */
      done = 1;
    }

  /* create a hop record and insert it into the trace */
  if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
    {
      return -1;
    }
  trace_hopins(&trace->hops[hop->hop_probe_ttl-1], hop);

  /* this many hops */
  trace->hop_count = hop->hop_probe_ttl;

  /* if we are done (can't probe beyond first hop) then finish */
  if(done != 0)
    {
      trace->firsthop = 1;
      trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
      assert(stop_reason != SCAMPER_TRACE_STOP_NONE);
      trace_stop(trace, stop_reason, stop_data);
      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
      return 0;
    }

  /*
   * if the response comes from an address not in the global stop set,
   * then probe forward
   */
  if(scamper_trace_dtree_gss_find(trace, hop->hop_addr) == NULL)
    {
      state->ttl  = hop->hop_probe_ttl + 1;
      state->mode = MODE_DTREE_FWD;
      trace_queue(task);
      return 0;
    }

  /* hit something in the global stop set. probe backwards */ 
  trace->stop_reason = SCAMPER_TRACE_STOP_GSS;
  trace->stop_data   = 0;
  trace->dtree->gss_stop = scamper_addr_use(hop->hop_addr);

  /* can't probe backwards, so we're done */
  if(trace->firsthop == 1)
    {
      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
      return 0;
    }

  /* backwards probing */
  state->ttl  = trace->firsthop - 1;
  state->mode = MODE_DTREE_BACK;
  trace_queue(task);

  return 0;
}

/*
 * handleicmp_lastditch
 *
 * we received an ICMP response while checking if the end-host is
 * responsive.
 */
static int handleicmp_lastditch(scamper_task_t *task,
				scamper_icmp_resp_t *ir,
				trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  scamper_trace_hop_t *hop;

  if(probe->mode == MODE_TRACE)
    {
      /* record the response in the trace */
      if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
	{
	  return -1;
	}
      trace_hopins(&trace->hops[hop->hop_probe_ttl-1], hop);
    }
  else if(probe->mode == MODE_LASTDITCH)
    {
      if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
	{
	  return -1;
	}
      trace_hopins(&trace->lastditch, hop);
      trace_stop_gaplimit((scamper_trace_t *)task->data);
      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
    }

  return 0;
}

static int handleicmp_pmtud_default(scamper_task_t *task,
				    scamper_icmp_resp_t *ir,
				    trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  trace_state_t   *state = task->state;
  scamper_trace_hop_t *hop;

  /*
   * if the response is for a probe that fits with the current
   * probing details, then record it
   */
  if(probe->mode == MODE_PMTUD_DEFAULT &&
     probe->size == state->header_size + state->payload_size)
    {
      if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
	{
	  return -1;
	}
      pmtud_hopins(trace, hop);
      state->last_fragmsg = hop;

      if(SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir))
	{
	  /*
	   * if the fragmentation required message did not include the
	   * suggested packet size for the next hop, or if the suggested
	   * MTU is larger than (or the same size) as the probe packet, then
	   * abandon the pmtud operation at this point
	   */
	  if(ir->ir_icmp_nhmtu == 0 || ir->ir_icmp_nhmtu >= probe->size)
	    {
	      state->mode = MODE_PMTUD_BADSUGG;
	      pmtud_L2_init(state);
	      trace_queue(task);
	      return 0;
	    }

	  /*
	   * if the message supplied an MTU to use, but it is too small
	   * to be probed, then stop probing here.
	   */
	  if(ir->ir_icmp_nhmtu < state->header_size)
	    {
	      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
	      return 0;
	    }

	  state->attempt = 0;
	  state->payload_size = ir->ir_icmp_nhmtu - state->header_size;
	  trace_queue(task);
	}
      else if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) ||
	      SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
	      SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir))
	{
	  trace->pmtud->pmtu = probe->size;
	  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
	}
    }

  return 0;
}

static int handleicmp_pmtud_silent_L2(scamper_task_t *task,
				      scamper_icmp_resp_t *ir,
				      trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  scamper_trace_hop_t *hop;

  assert(state->L2 != NULL);

  /*
   * if we get a response that is out of the bounds we are searching, it
   * could be a delayed message.  at the moment, we just ignore the response.
   */
  if(probe->size < state->L2->lower || state->L2->upper <= probe->size)
    {
      scamper_debug(__func__, "L2 search %d < %d || %d <= %d",
		    probe->size, state->L2->lower,
		    state->L2->upper, probe->size);
      return 0;
    }

  /* record the hop details */
  if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
    {
      return -1;
    }
  pmtud_L2_hop(state, hop);

  /*
   * if there is still space to search, reduce the search space and send
   * another probe
   */
  if(probe->size + 1 != state->L2->upper)
    {
      /*
       * raise the lower bounds of our search based on successfully
       * receiving a response for a given packet size.
       */
      pmtud_L2_set_probesize(state, probe->size, state->L2->upper);
    }
  else
    {
      state->L2->lower = state->L2->out = probe->size;
      if(pmtud_TTL_init(task) == 1)
	{
	  state->mode = MODE_PMTUD_SILENT_TTL;
	}
      else
	{
	  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
	  return 0;
	}
    }

  trace_queue(task);
  return 0;
}

static int handleicmp_pmtud_silent_TTL(scamper_task_t *task,
				       scamper_icmp_resp_t *ir,
				       trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  scamper_trace_hop_t *hop;

  /* we got a TTL expired message */
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir))
    {
      /* record the hop details */
      if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
	{
	  return -1;
	}
      pmtud_TTL_hop(state, hop);

      /* if there is no more TTL space to search, then we are done */
      if(pmtud_TTL_set_probettl(task, probe->ttl, state->TTL->upper) == 0)
	{
	  /*
	   * if we are not finished with PMTU yet, put the trace back in
	   * the queue
	   */
	  if(pmtud_L2_search_end(task) == 1)
	    {
	      return 0;
	    }
	}
    }
  /*
   * if we get a fragmentation required message during a TTL limited
   * search for the MTU inferred, then record the message and stop
   * the TTL limited search
   */
  else if(SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) &&
	  ir->ir_icmp_nhmtu == state->L2->out)
    {
      /* record the hop details */
      if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
	{
	  return -1;
	}
      pmtud_hopins((scamper_trace_t *)task->data, hop);

      state->attempt      = 0;
      state->payload_size = ir->ir_icmp_nhmtu - state->header_size;
      state->ttl          = 255;
      state->mode         = MODE_PMTUD_DEFAULT;

      free(state->L2); state->L2 = NULL;
      free(state->TTL); state->TTL = NULL;
    }

  /* put the trace back into the probe queue */
  trace_queue(task);
  return 0;
}

/*
 * handleicmp_pmtud_badsugg
 *
 * we are in the badsugg state, which is used to infer a 'correct' next-hop
 * mtu size when the suggested packet size is no help.
 */
static int handleicmp_pmtud_badsugg(scamper_task_t *task,
				    scamper_icmp_resp_t *ir,
				    trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  scamper_trace_hop_t *hop;
  scamper_addr_t addr;
  int upper, lower;

  if(scamper_icmp_resp_src(ir, &addr) != 0)
    {
      return -1;
    }

  /*
   * adjust the window we are searching based on where the response came
   * from and the size of the probe that caused the response
   */
  if(scamper_addr_cmp(state->last_fragmsg->hop_addr, &addr) == 0)
    {
      lower = state->L2->lower;
      upper = probe->size;
    }
  else
    {
      lower = probe->size;
      upper = state->L2->upper;

      /* replace the layer-2 hop we get a response for with this hop */
      if((hop = trace_icmp_hop(trace, probe, ir)) == NULL)
	{
	  return -1;
	}
      pmtud_L2_hop(state, hop);
    }

  if(lower + 1 != upper)
    {
      pmtud_L2_set_probesize(state, lower, upper);
    }
  else
    {
      /* terminate the search now */
      state->L2->lower = state->L2->out = lower;
      state->L2->upper = upper;

      /* if the pmtud is completed, then move on */
      if(pmtud_L2_search_end(task) == 1)
	{
	  return 0;
	}
    }

  /* put the trace back into the probe queue */
  trace_queue(task);

  return 0;
}

static void do_trace_handle_icmp(scamper_task_t *task, scamper_icmp_resp_t *ir)
{
  static int (*const func[])(scamper_task_t *, scamper_icmp_resp_t *,
			     trace_probe_t *) = {
    handleicmp_trace,            /* MODE_TRACE            == 0x00 */
    handleicmp_lastditch,        /* MODE_LASTDITCH        == 0x01 */
    handleicmp_pmtud_default,    /* MODE_PMTUD_DEFAULT    == 0x02 */
    handleicmp_pmtud_silent_L2,  /* MODE_PMTUD_SILENT_L2  == 0x03 */
    handleicmp_pmtud_silent_TTL, /* MODE_PMTUD_SILENT_TTL == 0x04 */
    handleicmp_pmtud_badsugg,    /* MODE_PMTUD_BADSUGG    == 0x05 */
    NULL,                        /* MODE_RTSOCK           == 0x06 */
    handleicmp_dtree_first,      /* MODE_DTREE_FIRST      == 0x07 */
    handleicmp_trace,            /* MODE_DTREE_FWD        == 0x08 */
    handleicmp_trace,            /* MODE_DTREE_BACK       == 0x09 */
  };

  scamper_trace_t   *trace = task->data;
  trace_state_t     *state = task->state;
  uint16_t           id;
  uint8_t            proto;

  assert(state->mode <= MODE_MAX);

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

  /*
   * if the trace is in a mode that does not handle ICMP responses, then
   * stop now
   */
  if(func[state->mode] == NULL)
    {
      return;
    }

  if(trace->type == SCAMPER_TRACE_TYPE_UDP ||
     trace->type == SCAMPER_TRACE_TYPE_UDP_PARIS)
    {
      /* if the ICMP type is not something that we care for, then drop it */
      if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_UNREACH(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) == 0)
	{
	  return;
	}

      /*
       * if the ICMP response does not reference a UDP probe sent from our
       * source port to a destination probe we're likely to have probed, then
       * ignore the packet
       */
      if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir) == 0 ||
	 ir->ir_inner_ip_proto  != IPPROTO_UDP ||
	 ir->ir_inner_udp_sport != trace->sport)
	{
	  return;
	}

      if(trace->type == SCAMPER_TRACE_TYPE_UDP)
	{
	  if(ir->ir_inner_udp_dport <  trace->dport ||
	     ir->ir_inner_udp_dport >= trace->dport+state->id_next)
	    {
	      return;
	    }

	  /* XXX: handle wrap-around */
	  id = ir->ir_inner_udp_dport - trace->dport;
	}
      else if(trace->type == SCAMPER_TRACE_TYPE_UDP_PARIS)
	{
	  if(ir->ir_inner_udp_dport != trace->dport)
	    {
	      return;
	    }

	  if(ir->ir_af == AF_INET)
	    {
	      if(ntohs(ir->ir_inner_udp_sum) == ir->ir_inner_ip_id &&
		 ir->ir_inner_udp_sum != 0)
		{
		  id = ntohs(ir->ir_inner_udp_sum) - 1;
		}
	      else if(trace_ipid_fudge(state, ir->ir_inner_ip_id, &id) != 0)
		{
		  return;
		}
	    }
	  else
	    {
	      if(ir->ir_inner_udp_sum == 0)
		{
		  return;
		}
	      id = ntohs(ir->ir_inner_udp_sum) - 1;
	    }
	}
      else return;
    }
  else if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO ||
	  trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
    {
     /* if the ICMP type is not something that we care for, then drop it */
      if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) == 0)
	{
	  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) == 0 &&
	     SCAMPER_ICMP_RESP_IS_UNREACH(ir) == 0 &&
	     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) == 0)
	    {
	      return;
	    }

	  if(ir->ir_af == AF_INET) proto = IPPROTO_ICMP;
	  else if(ir->ir_af == AF_INET6) proto = IPPROTO_ICMPV6;
	  else return;

	  if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir) == 0 ||
	     ir->ir_inner_ip_proto != proto          ||
	     ir->ir_inner_icmp_id  != trace->sport   ||
	     ir->ir_inner_icmp_seq >= state->id_next)
	    {
	      return;
	    }

	  id = ir->ir_inner_icmp_seq;
	}
      else
	{
	  if(ir->ir_icmp_id  != trace->sport ||
	     ir->ir_icmp_seq >= state->id_next)
	    {
	      return;
	    }

	  id = ir->ir_icmp_seq;
	}
    }
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
    {
      /* if the ICMP type is not something that we care for, then drop it */
      if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_UNREACH(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) == 0)
	{
	  return;
	}

      /*
       * if the ICMP response does not reference a TCP probe sent from our
       * source port to the destination port specified then ignore the
       * ICMP packet
       */
      if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir) == 0 ||
	 ir->ir_inner_ip_proto  != IPPROTO_TCP ||
	 ir->ir_inner_tcp_sport != trace->sport ||
	 ir->ir_inner_tcp_dport != trace->dport)
	{
	  return;
	}

      if(ir->ir_af == AF_INET)
	{
	  /* determine which probe id the ip id corresponds to */
	  if(trace_ipid_fudge(state, ir->ir_inner_ip_id, &id) != 0)
	    {
	      return;
	    }
	}
      else
	{
	  if(ir->ir_inner_ip_flow == 0)
	    {
	      return;
	    }
	  id = ir->ir_inner_ip_flow - 1;
	}
    }
  else
    {
      return;
    }

  if(id < state->id_next)
    {
      func[state->mode](task, ir, state->probes[id]);
    }

  return;
}

/*
 * timeout_trace
 *
 * this function is called if the trace timed out on the wait queue, and
 * all allotted attempts have been sent.
 */
static void timeout_trace(scamper_task_t *task)
{
  scamper_trace_t     *trace = task->data;
  trace_state_t       *state = task->state;
  scamper_trace_hop_t *hop;
  int                  i, deadpath;
  uint8_t              stop_reason, stop_data;

  /* we tried this hop, so move onto the next */
  trace->hop_count++;
  state->ttl++;

  /* tidy up after any confidence probing */
  if(state->interfaces != NULL)
    {
      free(state->interfaces);
      state->interfaces = NULL;
      state->interfacec = 0;
    }
  assert(state->interfaces == NULL);
  assert(state->interfacec == 0);
  state->n = 2;

  /*
   * if we probed for all attempts on the hop, then check to see if we
   * got any responses on this hop, and if we did, check to see if we
   * should stop probing this target yet
   */
  if((trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS) || trace->confidence != 0)
    {
      for(hop = trace->hops[trace->hop_count-1];hop != NULL; hop=hop->hop_next)
	{
	  /*
	   * first, check to see if there is a reason to stop probing with
	   * this particular hop record
	   */
	  trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
	  if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	    {
	      trace_stop(trace, stop_reason, stop_data);
	      trace_next_mode(task);
	      return;
	    }
	}
    }

  if(trace->hop_count == 255 || trace->hop_count == trace->hoplimit)
    {
      trace_stop_hoplimit(trace);
      trace_next_mode(task);
      return;
    }

  /*
   * if we haven't checked to see if the path is dead yet, check to see
   * if we should do so at this time.  a dead path is defined as a path
   * that has an unresponsive target host, which we stop tracing after
   * the gaplimit is reached.
   */
  if(trace->hop_count - (trace->firsthop - 1) >= trace->gaplimit)
    {
      deadpath = 1;
      for(i=0; i<trace->gaplimit; i++)
	{
	  if(trace->hops[trace->hop_count-1-i] != NULL)
	    {
	      deadpath = 0;
	      break;
	    }
	}

      if(deadpath != 0)
	{
	  if(trace->gapaction == SCAMPER_TRACE_GAPACTION_LASTDITCH)
	    {
	      state->mode = MODE_LASTDITCH;
	      state->ttl = 255;
	    }
	  else
	    {
	      trace_stop_gaplimit(trace);
	      trace_next_mode(task);
	    }
	}
    }

  return;
}

static void timeout_dtree_back(scamper_task_t *task)
{
  scamper_trace_t     *trace = task->data;
  trace_state_t       *state = task->state;
  scamper_trace_hop_t *hop;

  /* tidy up after any confidence probing */
  if(state->interfaces != NULL)
    {
      free(state->interfaces);
      state->interfaces = NULL;
      state->interfacec = 0;
    }

  if(state->ttl == 1)
    {
      trace_next_mode(task);
      return;
    }

  if((trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS) || trace->confidence != 0)
    {
      for(hop = trace->hops[state->ttl-1]; hop != NULL; hop = hop->hop_next)
	{
	  if(dtree_lss_in(hop->hop_addr) != 0)
	    {
	      trace_next_mode(task);
	      return;
	    }
	}
    }

  state->attempt = 0;
  state->ttl--;
  trace->firsthop--;
  trace_queue(task);

  return;
}

static void timeout_dtree_first(scamper_task_t *task)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;

  /*
   * go into forwards probing mode if we've made it all the way back to
   * ttl one
   */
  if(state->ttl == 1)
    {
      state->mode = MODE_DTREE_FWD;
      state->ttl++;
      trace->hop_count++;
      return;
    }

  /* halve ttl and try again */
  state->ttl /= 2;
  trace->firsthop /= 2;
  return;
}

static void timeout_lastditch(scamper_task_t *task)
{
  /* we received no responses to any of the last-ditch probes */
  trace_stop_gaplimit((scamper_trace_t *)task->data);
  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
  return;
}

static void timeout_pmtud_default(scamper_task_t *task)
{
  trace_state_t *state = task->state;

  pmtud_L2_init(state);
  state->mode = MODE_PMTUD_SILENT_L2;

  return;
}

static void timeout_pmtud_silent_L2(scamper_task_t *task)
{
  trace_state_t *state = task->state;
  int size = state->header_size + state->payload_size;

  /*
   * have we scanned the L2 table to the official minimum MTU?
   * if we have, then PMTU fails and we abort.
   */
  if(state->L2->idx == 0)
    {
      scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
      return;
    }

  /*
   * we did not get a response for this probe size
   * if we can halve the search space again, then do that
   */
  if(state->L2->lower + 1 != size)
    {
      pmtud_L2_set_probesize(state, state->L2->lower, size);
    }
  else
    {
      state->L2->out = state->L2->lower;

      /* set the bounds of the TTL search */
      if(pmtud_TTL_init(task) == 1)
	{
	  state->mode = MODE_PMTUD_SILENT_TTL;
	}
      else
	{
	  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
	}
    }

  return;
}

static void timeout_pmtud_silent_TTL(scamper_task_t *task)
{
  trace_state_t *state = task->state;

  /*
   * select another TTL to probe with, if possible. if not, then
   * the search halts and we move on
   */
  if(pmtud_TTL_set_probettl(task, state->TTL->lower, state->ttl) == 0)
    {
      /* finish this portion of the TTL limited search */
      pmtud_L2_search_end(task);
    }

  return;
}

/*
 * timeout_pmtud_badsugg
 *
 * if we timeout while trying to determine the underlying MTU on a path
 * where a router gives a bad suggestion, chances are that an ICMP blackhole
 * exists later in the path.  try sending a larger packet, if we can.
 */
static void timeout_pmtud_badsugg(scamper_task_t *task)
{
  trace_state_t *state = task->state;
  int lower, upper;

  lower = state->header_size + state->payload_size;
  upper = state->L2->upper;

  pmtud_L2_hop(state, NULL);

  if(lower + 1 != upper)
    {
      pmtud_L2_set_probesize(state, lower, upper);
    }
  else
    {
      /* terminate the search now */
      state->L2->lower = state->L2->out = lower;
      state->L2->upper = upper;
      pmtud_L2_search_end(task);
    }

  return;
}

#ifndef _WIN32
static void timeout_rtsock(scamper_task_t *task)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;

  /*
   * if we can't get sense out of the route socket, then do the trace
   * anyway, but without pmtud or datalink support
   */
  trace->flags &= ~(SCAMPER_TRACE_FLAG_PMTUD | SCAMPER_TRACE_FLAG_DL);
  state->mode = MODE_TRACE;

  return;
}
#endif

/*
 * do_trace_handle_timeout
 *
 * the trace has expired while sitting on the wait queue.
 * handle this event appropriately.
 */
static void do_trace_handle_timeout(scamper_task_t *task)
{
  static void (* const func[])(scamper_task_t *) = {
    timeout_trace,             /* MODE_TRACE            == 0x00 */
    timeout_lastditch,         /* MODE_LASTDITCH        == 0x01 */
    timeout_pmtud_default,     /* MODE_PMTUD_DEFAULT    == 0x02 */
    timeout_pmtud_silent_L2,   /* MODE_PMTUD_SILENT_L2  == 0x03 */
    timeout_pmtud_silent_TTL,  /* MODE_PMTUD_SILENT_TTL == 0x04 */
    timeout_pmtud_badsugg,     /* MODE_PMTUD_BADSUGG    == 0x05 */
#ifndef _WIN32
    timeout_rtsock,            /* MODE_RTSOCK           == 0x06 */
#else
    NULL,                      /* MODE_RTSOCK           == 0x06 */
#endif
    timeout_dtree_first,       /* MODE_DTREE_FIRST      == 0x07 */
    timeout_trace,             /* MODE_DTREE_FWD        == 0x08 */
    timeout_dtree_back,        /* MODE_DTREE_BACK       == 0x09 */
  };

  scamper_trace_t *trace = task->data;
  trace_state_t   *state = task->state;
  trace_probe_t   *probe;

  assert(state->mode <= MODE_MAX);

#ifndef _WIN32
  if(state->mode == MODE_RTSOCK)
    {
      trace_handleerror(task, 0);
      return;
    }
#endif

  probe = state->probes[state->id_next-1];

  if(probe->rx == 0)
    {
      probe->flags |= TRACE_PROBE_FLAG_TIMEOUT;
    }
  else
    {
      assert(trace->wait_probe != 0);
      return;
    }

  /*
   * if we have sent all alloted attempts for this probe type, then
   * handle this particular probe failing
   */
  if((trace->confidence == 0 && state->attempt == trace->attempts) ||
     (trace->confidence != 0 && state->attempt == k(state)))
    {
      /* we're probably going to send another probe, so reset the attempt # */
      state->attempt = 0;

      /* call the function that handles a timeout in this particular mode */
      func[state->mode](task);
    }

  return;
}

static int handletcp_trace(scamper_task_t *task, scamper_dl_rec_t *dl,
			   trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;
  scamper_trace_hop_t *hop;
  size_t len;

  /* we should only have to deal with probes sent while in the trace state */
  if(probe->mode != MODE_TRACE)
    {
      return 0;
    }

  /* create a hop record based off the TCP data */
  if((hop = trace_tcp_hop(probe, dl)) == NULL)
    {
      return -1;
    }
  trace_hopins(&trace->hops[hop->hop_probe_ttl-1], hop);

  /* make sure we don't wrap */
  if(probe->rx != 65535)
    {
      probe->rx++;
    }

  /* if we are sending all allotted probes to the target */
  if((trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS) != 0)
    {
      if(probe->id + 1 != trace->attempts)
	{
	  trace_queue(task);
	  return 0;
	}
      trace->hop_count++;
    }
  else if(trace->confidence != 0)
    {
      /* record details of the interface */
      if(array_find((void **)state->interfaces, state->interfacec,
		    hop->hop_addr, trace_interface_cmp) == NULL)
	{
	  len = (state->interfacec + 1) * sizeof(scamper_addr_t *);
	  if(realloc_wrap((void **)&state->interfaces, len) != 0)
	    {
	      printerror(errno, strerror, __func__,
			 "could not realloc interfaces");
	      trace_handleerror(task, errno);
	      return -1;
	    }

	  state->interfaces[state->interfacec++] = hop->hop_addr;

	  if(state->interfacec > 1)
	    {
	      qsort(state->interfaces, state->interfacec,
		    sizeof(scamper_addr_t *), trace_interface_cmp);
	      state->n++;
	    }
	}

      /* if there are still probes to send for this hop, send the next one */
      if(state->n <= TRACE_CONFIDENCE_MAX_N && state->attempt < k(state))
	{
	  trace_queue(task);
	  return 0;
	}
      trace->hop_count++;
    }
  else
    {
      if(probe->rx == 1 && (probe->flags & TRACE_PROBE_FLAG_TIMEOUT) == 0)
	{
	  trace->hop_count++;
	}
    }

  trace_stop_completed(trace);
  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);

  return 0;
}

static int handletcp_lastditch(scamper_task_t *task, scamper_dl_rec_t *dl,
			       trace_probe_t *probe)
{
  scamper_trace_t *trace = task->data;
  scamper_trace_hop_t *hop;

  /* only handle TCP responses in these two states */
  if(probe->mode != MODE_TRACE && probe->mode != MODE_LASTDITCH)
    {
      return 0;
    }

  if(probe->rx != 65535) probe->rx++;

  /* create a hop record based off the TCP data */
  if((hop = trace_tcp_hop(probe, dl)) == NULL)
    {
      return -1;
    }

  if(probe->mode == MODE_LASTDITCH)
    {
      trace_hopins(&trace->lastditch, hop);
      trace_stop_gaplimit(trace);
    }
  else
    {
      trace_hopins(&trace->hops[hop->hop_probe_ttl-1], hop);
      trace_stop_completed(trace);
    }

  scamper_queue_done(task->queue, scamper_holdtime_get()*1000);
  return 0;
}

/*
 * dlin_trace
 *
 * handle a datalink record for an inbound packet which was sent
 * for a probe in the trace state.
 *
 * in this case, we use the timestamp and the ethernet mac address
 * [if available] to update the hop record.
 */
static void dlin_trace(scamper_trace_t *trace,
		       scamper_dl_rec_t *dl, trace_probe_t *probe)
{
  scamper_trace_hop_t *hop;
  struct timeval tv;

  /* adjust the rtt based on the timestamp included in the datalink record */
  timeval_diff_tv(&tv, &probe->tx_tv, &probe->rx_tv);

  for(hop=trace->hops[probe->ttl-1]; hop != NULL; hop = hop->hop_next)
    {
      if(probe->id + 1 < hop->hop_probe_id) continue;
      if(probe->id + 1 > hop->hop_probe_id) break;

      scamper_debug(__func__,
		    "hop %d.%06d dl_rec %d.%06d diff %d",
		    hop->hop_rtt.tv_sec, hop->hop_rtt.tv_usec,
		    tv.tv_sec, tv.tv_usec, 
		    timeval_diff_us(&hop->hop_rtt, &tv));

      hop->hop_flags &= ~(SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX);
      hop->hop_flags |= SCAMPER_TRACE_HOP_FLAG_TS_DL_RX;
      timeval_cpy(&hop->hop_rtt, &tv);
    }

  return;
}

static void dlout_apply(scamper_trace_hop_t *hop,
			trace_probe_t *probe, struct timeval *diff)
{
  while(hop != NULL)
    {
      if(probe->id + 1 > hop->hop_probe_id)
	{
	  break;
	}

      if(probe->id + 1 == hop->hop_probe_id)
	{
	  hop->hop_flags |= SCAMPER_TRACE_HOP_FLAG_TS_DL_TX;
	  timeval_add_tv(&hop->hop_rtt, diff);
	}

      hop = hop->hop_next;
    }

  return;
}

/*
 * dlout_trace
 *
 * adjust the RTT recorded for a probe/reply sequence based on an updated
 * transmit timestamp corresponding to when the packet was queued at the
 * network interface.
 */
static void dlout_trace(scamper_trace_t *trace,
			trace_probe_t *probe, struct timeval *diff)
{
  dlout_apply(trace->hops[probe->ttl-1], probe, diff);
  return;
}

/*
 * dlout_lastditch
 *
 */
static void dlout_lastditch(scamper_trace_t *trace,
			    trace_probe_t *probe, struct timeval *diff)
{
  dlout_apply(trace->lastditch, probe, diff);
  return;
}

/*
 * do_trace_handle_dl
 *
 * handle a datalink record that may have something useful for the
 * traceroute, such as a more accurate timestamp or a mac address of
 * the host that delivered the response to us.
 */
static void do_trace_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (* const dlout_func[])(scamper_trace_t *, trace_probe_t *,
				     struct timeval *) =
  {
    dlout_trace,     /* MODE_TRACE            == 0x00 */
    dlout_lastditch, /* MODE_LASTDITCH        == 0x01 */
    NULL,            /* MODE_PMTUD_DEFAULT    == 0x02 */
    NULL,            /* MODE_PMTUD_SILENT_L2  == 0x03 */
    NULL,            /* MODE_PMTUD_SILENT_TTL == 0x04 */
    NULL,            /* MODE_PMTUD_BADSUGG    == 0x05 */
    NULL,            /* MODE_RTSOCK           == 0x06 */
  };

  static void (* const dlin_func[])(scamper_trace_t *, scamper_dl_rec_t *,
				    trace_probe_t *) =
  {
    dlin_trace,      /* MODE_TRACE            == 0x00 */
    NULL,            /* MODE_LASTDITCH        == 0x01 */
    NULL,            /* MODE_PMTUD_DEFAULT    == 0x02 */
    NULL,            /* MODE_PMTUD_SILENT_L2  == 0x03 */
    NULL,            /* MODE_PMTUD_SILENT_TTL == 0x04 */
    NULL,            /* MODE_PMTUD_BADSUGG    == 0x05 */
    NULL,            /* MODE_RTSOCK           == 0x06 */
  };

  static int (* const handletcp_func[])(scamper_task_t *, scamper_dl_rec_t *,
					trace_probe_t *) =
  {
    handletcp_trace,     /* MODE_TRACE            == 0x00 */
    handletcp_lastditch, /* MODE_LASTDITCH        == 0x01 */
    NULL,                /* MODE_PMTUD_DEFAULT    == 0x02 */
    NULL,                /* MODE_PMTUD_SILENT_L2  == 0x03 */
    NULL,                /* MODE_PMTUD_SILENT_TTL == 0x04 */
    NULL,                /* MODE_PMTUD_BADSUGG    == 0x05 */
    NULL,                /* MODE_RTSOCK           == 0x06 */
  };

  scamper_trace_t *trace = task->data;
  trace_state_t   *state = task->state;
  trace_probe_t   *probe;
  uint16_t         probe_id;
  int              direction;
  struct timeval   diff;

  /* if this record has no timestamp, go no further */
  if((dl->dl_flags & SCAMPER_DL_FLAG_TIMESTAMP) == 0)
    {
      return;
    }

  /*
   * try and determine the direction of the packet and the associated probe
   * for this datalink record
   */
  if(trace->type == SCAMPER_TRACE_TYPE_UDP ||
     trace->type == SCAMPER_TRACE_TYPE_UDP_PARIS)
    {
      if(dl->dl_ip_proto == IPPROTO_UDP)
	{
	  if(dl->dl_udp_sport != trace->sport)
	    return;

	  direction = 1;

	  if(trace->type == SCAMPER_TRACE_TYPE_UDP)
	    {
	      probe_id = dl->dl_udp_dport - trace->dport;
	    }
	  else
	    {
	      probe_id = ntohs(dl->dl_udp_sum) - 1;
	    }
	}
      else if(SCAMPER_DL_IS_ICMP(dl))
	{
	  if(SCAMPER_DL_IS_ICMP_TTL_EXP(dl) == 0 &&
	     SCAMPER_DL_IS_ICMP_UNREACH(dl) == 0 &&
	     SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl) == 0)
	    {
	      return;
	    }
	  if(dl->dl_icmp_ip_proto != IPPROTO_UDP)
	    return;
	  if(dl->dl_icmp_udp_sport != trace->sport)
	    return;

	  direction = 0;

	  if(trace->type == SCAMPER_TRACE_TYPE_UDP)
	    {
	      probe_id = dl->dl_icmp_udp_dport - trace->dport;
	    }
	  else
	    {
	      if(dl->dl_icmp_udp_dport != trace->dport)
		return;

	      if(dl->dl_af == AF_INET)
		{
		  if(ntohs(dl->dl_icmp_udp_sum) == dl->dl_icmp_ip_id &&
		     dl->dl_icmp_udp_sum != 0)
		    {
		      probe_id = ntohs(dl->dl_icmp_udp_sum) - 1;
		    }
		  else if(trace_ipid_fudge(state,dl->dl_icmp_ip_id,
					   &probe_id) != 0)
		    {
		      return;
		    }
		}
	      else
		{
		  assert(dl->dl_af == AF_INET6);
		  if(dl->dl_icmp_udp_sum == 0)
		    return;

		  probe_id = ntohs(dl->dl_icmp_udp_sum) - 1;
		}
	    }
	}
      else return;
    }
  else if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO ||
	  trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
    {
      if(SCAMPER_DL_IS_ICMP(dl) == 0)
	return;

      if(SCAMPER_DL_IS_ICMP_ECHO_REQUEST(dl))
	{
	  if(dl->dl_icmp_id != trace->sport)
	    return;

	  probe_id = dl->dl_icmp_seq;
	  direction = 1;
	}
      else if(SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl))
	{
	  if(dl->dl_icmp_id != trace->sport)
	    return;

	  probe_id = dl->dl_icmp_seq;
	  direction = 0;
	}
      else if((SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ||
	       SCAMPER_DL_IS_ICMP_UNREACH(dl) ||
	       SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl)) &&
	      SCAMPER_DL_IS_ICMP_PROTO_ICMP_ECHO_REQ(dl))
	{
	  if(dl->dl_icmp_icmp_id != trace->sport)
	    return;

	  probe_id = dl->dl_icmp_icmp_seq;
	  direction = 0;
	}
      else return;
    }
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
    {
      if(dl->dl_ip_proto == IPPROTO_TCP)
	{
	  /*
	   * if the syn flag (and only the syn flag is set) and the sport
	   * and dport match what we probe with, then the probe is probably
	   * an outgoing one.
	   */
	  if((dl->dl_tcp_flags & TH_SYN)  == TH_SYN &&
	     (dl->dl_tcp_flags & ~TH_SYN) == 0 &&
	     dl->dl_tcp_sport == trace->sport)
	    {
	      if(dl->dl_af == AF_INET)
		probe_id = dl->dl_ip_id - 1;
	      else
		probe_id = dl->dl_ip_flow - 1;

	      direction = 1;
	    }
	  else if(dl->dl_tcp_sport == trace->dport &&
		  dl->dl_tcp_dport == trace->sport)
	    {
	      /*
	       * there is no easy way to determine which probe the reply is
	       * for, so assume it was for the last one
	       */
	      probe_id = state->id_next - 1;
	      direction = 0;	      
	    }
	  else return;
	}
      else if(SCAMPER_DL_IS_ICMP(dl))
	{
	  if(SCAMPER_DL_IS_ICMP_TTL_EXP(dl) == 0 &&
	     SCAMPER_DL_IS_ICMP_UNREACH(dl) == 0 &&
	     SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl) == 0)
	    {
	      return;
	    }
	  if(dl->dl_icmp_ip_proto  != IPPROTO_TCP  ||
	     dl->dl_icmp_tcp_sport != trace->sport ||
	     dl->dl_icmp_tcp_dport != trace->dport)
	    {
	      return;
	    }

	  /* determine which probe the ICMP response corresponds to */
	  if(dl->dl_af == AF_INET)
	    {
	      if(trace_ipid_fudge(state, dl->dl_icmp_ip_id, &probe_id) != 0)
		{
		  return;
		}
	    }
	  else
	    {
	      if(dl->dl_icmp_ip_flow == 0)
		return;

	      probe_id = dl->dl_icmp_ip_flow - 1;
	    }

	  direction = 0;
	}
      else return;
    }
  else return;

  /* find the probe that corresponds to this datalink record */
  if(probe_id >= state->id_next)
    {
      return;
    }
  probe = state->probes[probe_id];

  /* make sure the probe structure makes sense */
  assert(probe->mode <= MODE_MAX);

  /* if this is an inbound packet with a timestamp attached */
  if(direction == 0)
    {
      /* inbound TCP packets result in a hop record being created */
      if(dl->dl_ip_proto == IPPROTO_TCP)
	{
	  /*
	   * record the receive timestamp with the probe structure if it hasn't
	   * been previously recorded
	   */
	  if((probe->flags & TRACE_PROBE_FLAG_DL_RX) != 0)
	    {
	      timeval_cpy(&probe->rx_tv, &dl->dl_tv);
	      probe->flags |= TRACE_PROBE_FLAG_DL_RX;
	    }

	  if(handletcp_func[probe->mode] != NULL)
	    {
	      handletcp_func[probe->mode](task, dl, probe);
	    }
	}
      /* other datalink records result in timestamps being adjusted */
      else if((probe->flags & TRACE_PROBE_FLAG_DL_RX) == 0)
	{
	  /* update the receive timestamp stored with the probe */
	  probe->flags |= TRACE_PROBE_FLAG_DL_RX;
	  timeval_cpy(&probe->rx_tv, &dl->dl_tv);

	  /* if at least one hop record is present then adjust */
	  if(probe->rx > 0 && dlin_func[probe->mode] != NULL)
	    {
	      dlin_func[probe->mode](trace, dl, probe);
	    }
	}
    }
  else
    {
      scamper_debug(__func__, "probe %d.%06d dl_rec %d.%06d diff %d",
		    probe->tx_tv.tv_sec, probe->tx_tv.tv_usec,
		    dl->dl_tv.tv_sec, dl->dl_tv.tv_usec, 
		    timeval_diff_us(&probe->tx_tv, &dl->dl_tv));

      /* if at least one hop record is present then adjust */
      if(probe->rx > 0 && dlout_func[probe->mode] != NULL)
	{
	  timeval_diff_tv(&diff, &probe->tx_tv, &dl->dl_tv);
	  dlout_func[probe->mode](trace, probe, &diff);
	}

      /* update the TX timestamp of the probe */
      probe->flags |= TRACE_PROBE_FLAG_DL_TX;
      timeval_cpy(&probe->tx_tv, &dl->dl_tv);
    }

  return;
}

static int trace_handle_rt(scamper_task_t *task, scamper_rt_rec_t *rt)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state = task->state;

  /*
   * if scamper is supposed to get tx timestamps from the datalink, or
   * scamper needs the datalink to transmit packets, then try and get a
   * datalink on the ifindex specified.
   */
  if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      return -1;
    }

  /*
   * if we're doing path MTU discovery debugging, or doing tcp traceroute,
   * or doing udp paris traceroute, determine the underlying framing to use
   * with each probe packet that will be sent on the datalink.
   */
  if((trace->flags & SCAMPER_TRACE_FLAG_PMTUD) != 0 ||
     SCAMPER_TRACE_TYPE_IS_TCP(trace) ||
     trace->type == SCAMPER_TRACE_TYPE_UDP_PARIS)
    {
      if((state->dl_hdr = scamper_dl_hdr_alloc(state->dl,trace->src,
					       trace->dst,rt->gwaddr)) == NULL)
	{
	  return -1;
	}
    }

  if((trace->flags & SCAMPER_TRACE_FLAG_DTREE) == 0)
    state->mode = MODE_TRACE;
  else
    state->mode = MODE_DTREE_FIRST;

  state->attempt = 0;
  return 0;
}

#ifndef _WIN32
static void do_trace_handle_rt(scamper_task_t *task, scamper_rt_rec_t *rt)
{
  trace_state_t *state = task->state;

  if(state->mode != MODE_RTSOCK)
    return;

  assert(state->route != NULL);
  scamper_fd_free(state->route);
  state->route = NULL;

  /* if there was a problem getting the ifindex, handle that */
  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(errno, strerror, __func__, "could not get ifindex");
      trace_handleerror(task, errno);
      return;
    }

  if(trace_handle_rt(task, rt) != 0)
    {
      trace_handleerror(task, errno);
    }
  else
    {
      scamper_queue_probe(task->queue);
    }
  return;
}
#endif

static void do_trace_write(scamper_task_t *task)
{
  const char *outfile_name;
  scamper_outfile_t *outfile;
  scamper_file_t *sf;

  outfile_name = scamper_source_getoutfile(task->source);
  assert(outfile_name != NULL);

  if((outfile = scamper_outfiles_get(outfile_name)) != NULL)
    {
      sf = scamper_outfile_getfile(outfile);
      scamper_file_write_trace(sf, (scamper_trace_t *)task->data);
    }

  return;
}

static void trace_state_free(trace_state_t *state)
{
  trace_probe_t *probe;
  int i;

  /* free the probe records scamper kept */
  if(state->probes != NULL)
    {
      for(i=0; i<state->id_next; i++)
	{
	  probe = state->probes[i];
	  free(probe);
	}
      free(state->probes);
    }

  if(state->dl != NULL)     scamper_fd_free(state->dl);
  if(state->icmp != NULL)   scamper_fd_free(state->icmp);
  if(state->probe != NULL)  scamper_fd_free(state->probe);

#ifndef _WIN32
  if(state->route != NULL)  scamper_fd_free(state->route);
#endif

  if(state->dl_hdr != NULL) scamper_dl_hdr_free(state->dl_hdr);

  if(state->interfaces != NULL)
    free(state->interfaces);

  if(state->lss != NULL)
    free(state->lss);

  free(state);
  return;
}

static int trace_state_alloc(scamper_task_t *task)
{
  scamper_trace_t *trace = task->data;
  trace_state_t *state;
  void *addr;
  int id_max;

#ifdef _WIN32
  scamper_rt_rec_t rr;
#endif

  assert(trace != NULL);

  /* allocate struct to keep state while processing the trace */
  if((state = malloc_zero(sizeof(trace_state_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc state");
      goto err;
    }

  /* determine the source address used for sending probes */
  if(trace->src == NULL)
    {
      if((trace->src = scamper_getsrc(trace->dst)) == NULL)
	goto err;
      addr = NULL;
    }
  else
    {
      addr = trace->src->addr;
    }

  state->n = 2;
  if(trace->confidence == 99)
    state->confidence = 1;

  /* allocate memory to record hops */
  state->alloc_hops = TRACE_ALLOC_HOPS;
  if(trace->firsthop >= state->alloc_hops)
    {
      if(state->alloc_hops + (uint16_t)trace->firsthop > 256)
	{
	  state->alloc_hops = 256;
	}
      else
	{
	  state->alloc_hops += trace->firsthop;
	}
    }

  if(scamper_trace_hops_alloc(trace, state->alloc_hops) == -1)
    {
      printerror(errno, strerror, __func__, "could not malloc hops");
      goto err;
    }

  /* allocate enough ids to probe each hop with max number of attempts */
  id_max = (state->alloc_hops - trace->firsthop + 2) * trace->attempts;

  /* allocate enough space to store state for each probe */
  if((state->probes = malloc(sizeof(trace_probe_t *) * id_max)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc probes");
      goto err;
    }

  /* if scamper has to get the ifindex, then start in the rtsock mode */
  if((trace->flags & (SCAMPER_TRACE_FLAG_PMTUD|SCAMPER_TRACE_FLAG_DL)) != 0 ||
     SCAMPER_TRACE_TYPE_IS_TCP(trace) ||
     trace->type == SCAMPER_TRACE_TYPE_UDP_PARIS)
    {
#ifndef _WIN32
      state->mode = MODE_RTSOCK;
      if((state->route = scamper_fd_rtsock()) == NULL)
	{
	  goto err;
	}
#else
      if(scamper_rtsock_getroute(trace->dst, &rr) != 0 ||
	 trace_handle_rt(task, &rr) != 0)
	{
	  goto err;
	}
#endif
    }
  else
    {
      if((trace->flags & SCAMPER_TRACE_FLAG_DTREE) == 0)
	state->mode = MODE_TRACE;
      else
	state->mode = MODE_DTREE_FIRST;
    }

  state->dl           = NULL;
  state->dl_hdr       = NULL;
  state->ttl          = trace->firsthop;
  state->attempt      = 0;
  state->header_size  = scamper_trace_probe_headerlen(trace);
  state->payload_size = trace->probe_size - state->header_size;
  state->id_next      = 0;
  state->id_max       = id_max;

  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      state->icmp = scamper_fd_icmp4(NULL);
    }
  else if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      state->icmp = scamper_fd_icmp6(NULL);
    }
  else goto err;
  if(state->icmp == NULL)
    {
      goto err;
    }

  if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
    {
      if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	state->probe = scamper_fd_tcp4(NULL, trace->sport);
      else
	state->probe = scamper_fd_tcp6(NULL, trace->sport);
    }
  else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
    {
      if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	state->probe = scamper_fd_icmp4(addr);
      else
	state->probe = scamper_fd_icmp6(addr);
    }
  else if(SCAMPER_TRACE_TYPE_IS_UDP(trace))
    {
      if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	state->probe = scamper_fd_udp4(NULL, trace->sport);
      else
	state->probe = scamper_fd_udp6(NULL, trace->sport);
    }
  if(state->probe == NULL)
    {
      goto err;
    }

  task->state = state;
  return 0;

 err:
  if(state != NULL) trace_state_free(state);
  return -1;
}

static void do_trace_free(scamper_task_t *task)
{
  scamper_trace_t *trace;
  trace_state_t *state;

  /* free any state kept */
  if((state = task->state) != NULL)
    {
      trace_state_free(state);
    }

  /* free any trace data collected */
  if((trace = task->data) != NULL)
    {
      scamper_trace_free(trace);
    }

  return;
}

/*
 * do_trace_probe
 *
 * time to probe, so send the packet.
 */
static void do_trace_probe(scamper_task_t *task)
{
  scamper_trace_t *trace = task->data;
  trace_state_t   *state = task->state;
  trace_probe_t   *tp = NULL;
  scamper_probe_t  probe;
  uint16_t         u16, i;
  trace_probe_t  **probes;
  uint8_t         *buf;

  assert(trace != NULL);

  if(state != NULL)
    {
      assert(state->attempt < trace->attempts || trace->confidence != 0);
      assert(state->id_next <= state->id_max);
      assert(state->alloc_hops > 0);
      assert(state->alloc_hops <= 256);
      assert(state->ttl != 0);
    }
  else
    {
      /* timestamp when the trace began */
      gettimeofday_wrap(&trace->start);

      /* allocate state and store it with the task */
      if(trace_state_alloc(task) != 0)
	{
	  goto err;
	}
      state = task->state;
    }

#ifndef _WIN32
  if(state->mode == MODE_RTSOCK)
    {
      if(scamper_rtsock_getroute(state->route, trace->dst) != 0)
	{
	  trace->flags &= ~(SCAMPER_TRACE_FLAG_PMTUD | SCAMPER_TRACE_FLAG_DL);
	  if((trace->flags & SCAMPER_TRACE_FLAG_DTREE) == 0)
	    state->mode = MODE_TRACE;
	  else
	    state->mode = MODE_DTREE_FIRST;
	  state->attempt = 0;
	}
      else
	{
	  state->attempt++;
	  scamper_queue_wait(task->queue, trace->wait * 1000);
	  return;
	}
    }
#endif

  /* allocate some more space in the trace to store replies, if necessary */
  if(trace->hop_count == state->alloc_hops)
    {
      /*
       * figure out exactly how many hops should be allocated in the
       * trace structure
       */
      if(256 - state->alloc_hops <= TRACE_ALLOC_HOPS)
	{
	  u16 = state->alloc_hops + TRACE_ALLOC_HOPS;
	}
      else
	{
	  u16 = 256;
	}

      /* allocate the new hops */
      if(scamper_trace_hops_alloc(trace, u16) != 0)
	{
	  printerror(errno, strerror, __func__, "could not realloc hops");
	  goto err;
	}

      /* initialise the new hops to have null pointers */
      for(i=state->alloc_hops; i<u16; i++)
	{
	  trace->hops[i] = NULL;	  
	}
      state->alloc_hops = u16;
    }

  /* allocate some more space to store probes, if necessary */
  if(state->id_next == state->id_max)
    {
      u16 = state->id_max + TRACE_ALLOC_HOPS;
      probes = realloc(state->probes, sizeof(trace_probe_t *) * u16);
      if(probes == NULL)
	{
	  printerror(errno, strerror, __func__, "could not realloc");
	  goto err;
	}

      state->id_max = u16;
      state->probes = probes;
    }

  /* allocate a larger global pktbuf if needed */
  if(pktbuf_len < state->payload_size)
    {
      if((buf = realloc(pktbuf, state->payload_size)) == NULL)
	{
	  printerror(errno, strerror, __func__, "could not realloc");
	  goto err;
	}
      pktbuf     = buf;
      pktbuf_len = state->payload_size;
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_ip_src    = trace->src;
  probe.pr_ip_dst    = trace->dst;
  probe.pr_ip_tos    = trace->tos;
  probe.pr_ip_ttl    = state->ttl;
  probe.pr_data      = pktbuf;
  probe.pr_len       = state->payload_size;
  probe.pr_fd        = scamper_fd_fd_get(state->probe);

  if((state->mode == MODE_PMTUD_DEFAULT ||
      state->mode == MODE_PMTUD_SILENT_L2 ||
      state->mode == MODE_PMTUD_SILENT_TTL ||
      state->mode == MODE_PMTUD_BADSUGG ||
      SCAMPER_TRACE_TYPE_IS_TCP(trace) ||
      trace->type == SCAMPER_TRACE_TYPE_UDP_PARIS) &&
     state->dl != NULL)
    {
      probe.pr_dl      = scamper_fd_write_state(state->dl);
      probe.pr_dl_hdr  = state->dl_hdr->dl_hdr;
      probe.pr_dl_size = state->dl_hdr->dl_size;
    }

  if(trace->payload_len == 0 ||
     (state->mode != MODE_TRACE && state->mode != MODE_LASTDITCH))
    {
      if(probe.pr_len > 0)
	{
	  memset(probe.pr_data, 0, probe.pr_len);
	}
    }
  else
    {
      memcpy(probe.pr_data, trace->payload, trace->payload_len);
    }

  if(SCAMPER_TRACE_TYPE_IS_UDP(trace))
    {
      probe.pr_ip_proto  = IPPROTO_UDP;
      probe.pr_udp_sport = trace->sport;
      probe.pr_udp_dport = trace->dport;

      /*
       * traditional traceroute identifies probes by varying the UDP
       * destination port number.  UDP-based paris traceroute identifies
       * probes by varying the UDP checksum -- accomplished by manipulating
       * the payload of the packet to get sequential values for the checksum
       */
      if(trace->type == SCAMPER_TRACE_TYPE_UDP)
	{
	  probe.pr_udp_dport += state->id_next;
	}
      else
	{
	  /*
	   * hack the checksum to be our id field by setting the checksum
	   * id we want into the packet's body, then calculate the checksum
	   * across the packet, and then set the packet's body to be the
	   * value returned for the checksum.  this effectively swaps two
	   * 16 bit quantities in the packet
	   */
	  u16 = htons(state->id_next + 1);
	  memcpy(probe.pr_data, &u16, 2);

	  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	    {
	      /*
	       * while the paris traceroute paper says that the payload of the
	       * packet is set so that the checksum field can be used to
	       * identify a returned probe, the paris traceroute code uses the
	       * IP ID field.
	       * this is presumably because FreeBSD systems seem to reset the
	       * UDP checksum quoted in ICMP destination unreachable messages.
	       * scamper's paris traceroute implementation used both IP ID and
	       * UDP checksum.
	       */
	      probe.pr_ip_id = state->id_next + 1;
	      u16 = scamper_udp4_cksum(&probe);
	    }
	  else
	    {
	      u16 = scamper_udp6_cksum(&probe);
	    }

	  memcpy(probe.pr_data, &u16, 2);
	}
    }
  else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
    {
      switch(trace->dst->type)
	{
	case SCAMPER_ADDR_TYPE_IPV4:
	  probe.pr_ip_proto = IPPROTO_ICMP;
	  probe.pr_icmp_type = ICMP_ECHO;
	  break;

	case SCAMPER_ADDR_TYPE_IPV6:
	  probe.pr_ip_proto = IPPROTO_ICMPV6;
	  probe.pr_icmp_type = ICMP6_ECHO_REQUEST;
	  break;
	}

      probe.pr_icmp_code = 0;
      probe.pr_icmp_id   = trace->sport;
      probe.pr_icmp_seq  = state->id_next;

      /*
       * ICMP-based paris traceroute tries to ensure the same path is taken
       * through a load balancer by sending all probes with a constant value
       * for the checksum.  manipulate the payload so this happens.
       */
      if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
	{
	  probe.pr_icmp_sum = htons(trace->dport);
	  u16 = htons(trace->dport);
	  memcpy(probe.pr_data, &u16, 2);
	  switch(trace->dst->type)
	    {
	    case SCAMPER_ADDR_TYPE_IPV4:
	      u16 = scamper_icmp4_cksum(&probe);
	      break;

	    case SCAMPER_ADDR_TYPE_IPV6:
	      u16 = scamper_icmp6_cksum(&probe);
	      break;
	    }
	  memcpy(probe.pr_data, &u16, 2);
	}
    }
  else
    {
      assert(SCAMPER_TRACE_TYPE_IS_TCP(trace));

      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_sport = trace->sport;
      probe.pr_tcp_dport = trace->dport;
      probe.pr_tcp_seq   = 0;
      probe.pr_tcp_ack   = 0;
      probe.pr_tcp_win   = 0;

      if(trace->type == SCAMPER_TRACE_TYPE_TCP)
	probe.pr_tcp_flags = TH_SYN;
      else
	probe.pr_tcp_flags = TH_ACK;

      if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	probe.pr_ip_id   = state->id_next + 1;
      else
	probe.pr_ip_flow = state->id_next + 1;
    }

  /*
   * allocate a trace probe state record before we try and send the probe
   * as there is no point sending something into the wild that we can't
   * record
   */
  if((tp = malloc_zero(sizeof(trace_probe_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc trace_probe_t");
      goto err;
    }

  /* send the probe */
  if(scamper_probe(&probe) == -1)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* another probe sent */
  trace->probec++;

  timeval_cpy(&tp->tx_tv, &probe.pr_tx);
  tp->ttl   = probe.pr_ip_ttl;
  tp->size  = probe.pr_len + state->header_size;
  tp->mode  = state->mode;
  tp->id    = state->attempt;

  state->probes[state->id_next] = tp;
  state->id_next++;
  state->attempt++;

  /* define the lower bounds on when the next probe will be transmitted */
  if(trace->wait_probe > 0)
    {
      timeval_add_cs(&state->next_tx, &probe.pr_tx, trace->wait_probe);
    }

  /* queue the traceroute to wait for any response */
  probe.pr_tx.tv_sec += trace->wait;
  scamper_queue_wait_tv(task->queue, &probe.pr_tx);

  return;

 err:
  if(tp != NULL) free(tp);
  trace_handleerror(task, errno);
  return;
}

static int trace_arg_param_validate(int optid, char *param, long *out)
{
  long tmp;

  switch(optid)
    {
    case TRACE_OPT_DPORT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_DPORT_MIN ||
	 tmp > SCAMPER_DO_TRACE_DPORT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_FIRSTHOP:
      if(string_tolong(param, &tmp) == -1    ||
	 tmp < SCAMPER_DO_TRACE_FIRSTHOP_MIN ||
	 tmp > SCAMPER_DO_TRACE_FIRSTHOP_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_GAPLIMIT:
      if(string_tolong(param, &tmp) == -1    ||
	 tmp < SCAMPER_DO_TRACE_GAPLIMIT_MIN ||
	 tmp > SCAMPER_DO_TRACE_GAPLIMIT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_GAPACTION:
      if(string_tolong(param, &tmp) == -1     ||
	 tmp < SCAMPER_DO_TRACE_GAPACTION_MIN ||
	 tmp > SCAMPER_DO_TRACE_GAPACTION_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_LOOPS:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_LOOPS_MIN ||
	 tmp > SCAMPER_DO_TRACE_LOOPS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_LOOPACTION:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_LOOPACTION_MIN ||
	 tmp > SCAMPER_DO_TRACE_LOOPACTION_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_MAXTTL:
      if(string_tolong(param, &tmp) == -1    ||
	 tmp < SCAMPER_DO_TRACE_HOPLIMIT_MIN ||
	 tmp > SCAMPER_DO_TRACE_HOPLIMIT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_PAYLOAD:
      if((strlen(param) % 2) != 0)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_PROTOCOL:
      if(strcasecmp(param, "UDP") == 0)
	tmp = SCAMPER_TRACE_TYPE_UDP;
      else if(strcasecmp(param, "TCP") == 0)
	tmp = SCAMPER_TRACE_TYPE_TCP;
      else if(strcasecmp(param, "ICMP") == 0)
	tmp = SCAMPER_TRACE_TYPE_ICMP_ECHO;
      else if(strcasecmp(param, "ICMP-paris") == 0)
	tmp = SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS;
      else if(strcasecmp(param, "UDP-paris") == 0)
	tmp = SCAMPER_TRACE_TYPE_UDP_PARIS;
      else if(strcasecmp(param, "TCP-ack") == 0)
	tmp = SCAMPER_TRACE_TYPE_TCP_ACK;
      else goto err;
      break;

    case TRACE_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) == -1    ||
	 tmp < SCAMPER_DO_TRACE_ATTEMPTS_MIN ||
	 tmp > SCAMPER_DO_TRACE_ATTEMPTS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_SPORT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_SPORT_MIN ||
	 tmp > SCAMPER_DO_TRACE_SPORT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_TOS:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_TOS_MIN ||
	 tmp > SCAMPER_DO_TRACE_TOS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_WAIT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_WAIT_MIN ||
	 tmp > SCAMPER_DO_TRACE_WAIT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_CONFIDENCE:
      if(string_tolong(param, &tmp) != 0 || (tmp != 95 && tmp != 99))
	{
	  goto err;
	}
      break;

    case TRACE_OPT_WAITPROBE:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_WAITPROBE_MIN ||
	 tmp > SCAMPER_DO_TRACE_WAITPROBE_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_SRCADDR:
    case TRACE_OPT_STOPSET:
      /* these parameters are validated at execution time */
      break;

    case TRACE_OPT_PMTUD:
    case TRACE_OPT_ALLATTEMPTS:
    case TRACE_OPT_TTLDST:
    case TRACE_OPT_DTREE:
      /* these options don't have parameters */
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
 * scamper_do_trace_alloc
 *
 * given a string representing a traceroute task, parse the parameters and
 * assemble a trace.  return the trace structure so that it is all ready to
 * go.
 */
void *scamper_do_trace_alloc(char *str)
{
  /* default values of various trace parameters */
  uint8_t  type        = SCAMPER_TRACE_TYPE_UDP;
  uint8_t  flags       = 0;
  uint8_t  attempts    = SCAMPER_DO_TRACE_ATTEMPTS_DEF;
  uint8_t  firsthop    = SCAMPER_DO_TRACE_FIRSTHOP_DEF;
  uint8_t  gaplimit    = SCAMPER_DO_TRACE_GAPLIMIT_DEF;
  uint8_t  gapaction   = SCAMPER_DO_TRACE_GAPACTION_DEF;
  uint8_t  hoplimit    = SCAMPER_DO_TRACE_HOPLIMIT_DEF;
  uint8_t  tos         = SCAMPER_DO_TRACE_TOS_DEF;
  uint8_t  wait        = SCAMPER_DO_TRACE_WAIT_DEF;
  uint8_t  wait_probe  = SCAMPER_DO_TRACE_WAITPROBE_DEF;
  uint8_t  loops       = SCAMPER_DO_TRACE_LOOPS_DEF;
  uint8_t  loopaction  = SCAMPER_DO_TRACE_LOOPACTION_DEF;
  uint8_t  confidence  = 0;
  uint16_t sport       = default_sport;
  uint16_t dport       = SCAMPER_DO_TRACE_DPORT_DEF;
  uint8_t *payload     = NULL;
  uint16_t payload_len = 0;
  slist_t *gss         = NULL;
  size_t   i, len;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_trace_t *trace = NULL;
  scamper_addr_t *sa;
  char *addr;
  long tmp;
  char *src = NULL;
  int af;
  uint32_t optids = 0;

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
	 trace_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      optids |= (0x1 << opt->id);

      switch(opt->id)
	{
	case TRACE_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case TRACE_OPT_FIRSTHOP:
	  firsthop = (uint8_t)tmp;
	  break;

	case TRACE_OPT_GAPLIMIT:
	  gaplimit = (uint8_t)tmp;
	  break;

	case TRACE_OPT_GAPACTION:
	  gapaction = (uint8_t)tmp;
	  break;

	case TRACE_OPT_LOOPS:
	  loops = (uint8_t)tmp;
	  break;

	case TRACE_OPT_LOOPACTION:
	  loopaction = (uint8_t)tmp;
	  break;

	case TRACE_OPT_MAXTTL:
	  hoplimit = (uint8_t)tmp;
	  break;

	case TRACE_OPT_PAYLOAD:
	  len = strlen(opt->str);
	  payload_len = len/2;
	  if((payload = malloc(payload_len)) == NULL)
	    {
	      printerror(errno,strerror,__func__, "could not malloc payload");
	      goto err;
	    }
	  for(i=0; i<len; i+=2)
	    {
	      payload[i/2] = hex2byte(opt->str[i], opt->str[i+1]);
	    }
	  break;

	case TRACE_OPT_PMTUD:
	  flags |= SCAMPER_TRACE_FLAG_PMTUD;
	  break;

	case TRACE_OPT_PROTOCOL:
	  type = (uint8_t)tmp;
	  break;

	case TRACE_OPT_ATTEMPTS:
	  attempts = (uint8_t)tmp;
	  break;

	case TRACE_OPT_ALLATTEMPTS:
	  flags |= SCAMPER_TRACE_FLAG_ALLATTEMPTS;
	  break;

	case TRACE_OPT_SPORT:
	  sport = (uint16_t)tmp;
	  break;

	case TRACE_OPT_TOS:
	  tos = (uint8_t)tmp;
	  break;

	case TRACE_OPT_TTLDST:
	  flags |= SCAMPER_TRACE_FLAG_IGNORETTLDST;
	  break;

	case TRACE_OPT_WAIT:
	  wait = (uint8_t)tmp;
	  break;

	case TRACE_OPT_SRCADDR:
	  if(src != NULL)
	    goto err;
	  src = opt->str;
	  break;

	case TRACE_OPT_CONFIDENCE:
	  confidence = (uint8_t)tmp;
	  break;

	case TRACE_OPT_WAITPROBE:
	  wait_probe = (uint8_t)tmp;
	  break;

	case TRACE_OPT_DTREE:
	  if(gss == NULL && (gss = slist_alloc()) == NULL)
	    goto err;
	  break;

	case TRACE_OPT_STOPSET:
	  if((gss == NULL && (gss = slist_alloc()) == NULL) ||
	     slist_tail_push(gss, opt->str) == NULL)
	    {
	      goto err;
	    }
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  /* sanity check that we don't begin beyond our probe hoplimit */
  if(firsthop > hoplimit && hoplimit != 0)
    {
      goto err;
    }

  /* can't really do pmtud properly without all of the path */
  if((firsthop > 1 || gss != NULL) && (flags & SCAMPER_TRACE_FLAG_PMTUD))
    {
      goto err;
    }

  /* cannot specify both a confidence value and tell it to send all attempts */
  if(confidence != 0 && (flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS))
    {
      goto err;
    }

  /* can't really do pmtud properly without a UDP traceroute method */
  if((flags & SCAMPER_TRACE_FLAG_PMTUD) == 1 &&
     type != SCAMPER_TRACE_TYPE_UDP && type != SCAMPER_TRACE_TYPE_UDP_PARIS)
    {
      goto err;
    }

  if((trace = scamper_trace_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc trace");
      goto err;
    }
  if((trace->dst= scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      goto err;
    }

  trace->type        = type;
  trace->flags       = flags;
  trace->attempts    = attempts;
  trace->hoplimit    = hoplimit;
  trace->gaplimit    = gaplimit;
  trace->gapaction   = gapaction;
  trace->firsthop    = firsthop;
  trace->tos         = tos;
  trace->wait        = wait;
  trace->loops       = loops;
  trace->loopaction  = loopaction;
  trace->sport       = sport;
  trace->dport       = dport;
  trace->payload     = payload;
  trace->payload_len = payload_len;
  trace->confidence  = confidence;
  trace->wait_probe  = wait_probe;

  /* to start with, we are this far into the path */
  trace->hop_count = firsthop - 1;

  /* don't allow tcptraceroute to have a payload */
  if(SCAMPER_TRACE_TYPE_IS_TCP(trace) && trace->payload_len > 0)
    {
      goto err;
    }

  switch(trace->dst->type)
    {
    case SCAMPER_ADDR_TYPE_IPV4:
      if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
	{
	  trace->probe_size = 40;
	}
      else
	{
	  if(trace->payload_len == 0)
	    trace->probe_size = 44;
	  else
	    trace->probe_size = 20 + 8 + trace->payload_len;
	}
      break;

    case SCAMPER_ADDR_TYPE_IPV6:
      if(trace->payload_len == 0 || SCAMPER_TRACE_TYPE_IS_TCP(trace))
	{
	  trace->probe_size = 60;
	}
      else
	{
	  trace->probe_size = 40 + 8 + trace->payload_len;
	}
      break;

    default:
      goto err;
    }

  if(src != NULL)
    {
      af = scamper_addr_af(trace->dst);
      if(af != AF_INET && af != AF_INET6)
	goto err;

      if((trace->src = scamper_addrcache_resolve(addrcache, af, src)) == NULL)
	goto err;
    }

  /*
   * if icmp paris traceroute is being used, say that the csum used can be
   * found in the trace->dport value.
   */
  if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
    {
      trace->flags |= SCAMPER_TRACE_FLAG_ICMPCSUMDP;
      if((optids & (0x1 << TRACE_OPT_DPORT)) == 0)
	trace->dport = default_sport;
    }

  if(scamper_option_dl() != 0)
    {
      trace->flags |= SCAMPER_TRACE_FLAG_DL;
    }

  /* add the nodes to the global stop set for this trace */
  if(gss != NULL)
    {
      if(scamper_trace_dtree_alloc(trace) != 0)
	goto err;

      trace->flags |= SCAMPER_TRACE_FLAG_DTREE;
      trace->dtree->firsthop = trace->firsthop;

      af = scamper_addr_af(trace->dst);
      while((addr = slist_head_pop(gss)) != NULL)
	{
	  sa = scamper_addrcache_resolve(addrcache, af, addr);

	  if(sa == NULL ||
	     (scamper_trace_dtree_gss_find(trace, sa) == NULL &&
	      scamper_trace_dtree_gss_add(trace, sa) != 0))
	    goto err;
	}

      slist_free(gss);
      gss = NULL;
    }

  return trace;

 err:
  if(gss != NULL) slist_free(gss);
  if(trace != NULL) scamper_trace_free(trace);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

/*
 * scamper_do_trace_arg_validate
 *
 *
 */
int scamper_do_trace_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  trace_arg_param_validate);
}

int scamper_do_trace_dstaddr(void *data, void *param,
			     int (*foreach)(struct scamper_addr *, void *))
{
  scamper_trace_t *trace = (scamper_trace_t *)data;
  return foreach(trace->dst, param);
}

void scamper_do_trace_free(void *data)
{
  scamper_trace_free((scamper_trace_t *)data);
  return;
}

/*
 * scamper_do_trace_alloctask
 *
 */
scamper_task_t *scamper_do_trace_alloctask(void *data,
					   scamper_list_t *list,
					   scamper_cycle_t *cycle)
{
  scamper_trace_t *trace = (scamper_trace_t *)data;

  /* associate the list and cycle with the trace */
  trace->list = scamper_list_use(list);
  trace->cycle = scamper_cycle_use(cycle);

  /* allocate a task structure and store the trace with it */
  return scamper_task_alloc(data, &trace_funcs);
}

void scamper_do_trace_cleanup(void)
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  if(lss != NULL)
    {
      splaytree_free(lss, (splaytree_free_t)scamper_addr_free);
      lss = NULL;
    }

  return;
}

int scamper_do_trace_init(void)
{
#ifndef _WIN32
  pid_t pid = getpid();
#else
  DWORD pid = GetCurrentProcessId();
#endif
  default_sport = (pid & 0x7fff) + 0x8000;

  /* allocate a local stop set for use with doubletree */
  if((lss = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not allocate lss");
      return -1;
    }

  trace_funcs.probe          = do_trace_probe;
  trace_funcs.handle_icmp    = do_trace_handle_icmp;
  trace_funcs.handle_dl      = do_trace_handle_dl;
  trace_funcs.handle_timeout = do_trace_handle_timeout;
  trace_funcs.write          = do_trace_write;
  trace_funcs.task_free      = do_trace_free;
  trace_funcs.task_addrs     = scamper_do_trace_dstaddr;

#ifndef _WIN32
  trace_funcs.handle_rt      = do_trace_handle_rt;
#endif

  return 0;
}
