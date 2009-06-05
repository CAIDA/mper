/*
 * scamper_file_warts.c
 *
 * the Waikato ARTS file format replacement
 *
 * $Id: scamper_file_warts.c,v 1.186 2009/05/17 01:07:55 mjl Exp $
 *
 * Copyright (C) 2004-2009 The University of Waikato
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
typedef int ssize_t;
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#define ftruncate _chsize
#define lseek _lseek
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#include <stdlib.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tlv.h"
#include "scamper_icmpext.h"
#include "scamper_trace.h"
#include "scamper_ping.h"
#include "scamper_tracelb.h"
#include "scamper_dealias.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"

#include "mjl_splaytree.h"
#include "utils.h"

#define WARTS_MAGIC 0x1205
#define WARTS_HDRLEN 8

/*
 * trace attributes: 2 bytes each.
 * the first 4 bits are the type, the second 12 bits are the length
 */
#define WARTS_TRACE_ATTR_HDR(type, len) ((type << 12) | len)
#define WARTS_TRACE_ATTR_HDR_TYPE(hdr)  ((hdr >> 12) & 0xf)
#define WARTS_TRACE_ATTR_HDR_LEN(hdr)    (hdr & 0x0fff)
#define WARTS_TRACE_ATTR_EOF       0x0000
#define WARTS_TRACE_ATTR_PMTUD     0x1
#define WARTS_TRACE_ATTR_LASTDITCH 0x2
#define WARTS_TRACE_ATTR_DTREE     0x3

/* how many entries to grow the table by each time */
#define WARTS_ADDR_TABLEGROW  1000
#define WARTS_LIST_TABLEGROW  1
#define WARTS_CYCLE_TABLEGROW 1

/*
 * warts_list / warts_cycle
 *
 * these structures associate a scamper structure with an id number used
 * to represent the structure on disk.
 */
typedef struct warts_list
{
  scamper_list_t *list;
  uint32_t id;
} warts_list_t;
typedef struct warts_cycle
{
  scamper_cycle_t *cycle;
  uint32_t id;
} warts_cycle_t;

/*
 * warts_hdr
 *
 * this object is written at the start of every object.
 * the magic field is a special integer value that signifies a new warts
 * record.
 * the type field says what type of record follows.
 * the length field reports the length of the following record.
 */
typedef struct warts_hdr
{
  uint16_t magic;
  uint16_t type;
  uint32_t len;
} warts_hdr_t;

/*
 * warts_state
 *
 * warts keeps state of lists, cycles, and addresses declared in a warts
 * file.  each resource is stored either in a tree (for fast searching) or
 * a table (for fast indexing).  when a file is open for writing, the tree
 * is used.  when a file is open for reading, the table is used.  each null
 * entry is used for the first ([0]) entry in the corresponding table.
 */
typedef struct warts_state
{
  int               ispipe;
  off_t             off;

  /* temporary buffer for leftover partial reads */
  uint8_t          *readbuf;
  size_t            readlen;
  size_t            readbuf_len;

  /*
   * if a partial read was done on the last loop through but whatever
   * warts object was there was not completely read, then keep track of it
   */
  uint16_t          hdr_type;
  uint32_t          hdr_len;

  /* list state */
  uint32_t          list_count;
  splaytree_t      *list_tree;
  warts_list_t    **list_table;
  warts_list_t      list_null;

  /* cycle state */
  uint32_t          cycle_count;
  splaytree_t      *cycle_tree;
  warts_cycle_t   **cycle_table;
  warts_cycle_t     cycle_null;

  /* address state */
  uint32_t          addr_count;
  scamper_addr_t  **addr_table;

} warts_state_t;

/*
 * warts_var
 *
 * warts often stores optional items of data with each object.  it does
 * this by declaring an array of bits that declare which optional bits of
 * data will be stored.  the warts_var structure is a convenient way of
 * encouraging the code for each object to be consistent.
 *
 * the id field corresponds to a bit
 * the size field records how large the field is stored on disk; -1 is variable
 * the tlv_id field records the id for a scamper_tlv_t if the data item is
 * stored optionally in the data structure itself.
 */
typedef struct warts_var
{
  int     id;
  ssize_t size;
  int     tlv_id;
} warts_var_t;
#define WARTS_VAR_COUNT(array) (sizeof(array)/sizeof(warts_var_t))
#define WARTS_VAR_MFB(array) ((WARTS_VAR_COUNT(array) / 7) + \
			      (WARTS_VAR_COUNT(array) % 7 == 0 ? 0 : 1))

typedef int (*wpr_t)(const uint8_t *,uint32_t *,const uint32_t,void *, void *);
typedef void (*wpw_t)(uint8_t *,uint32_t *,const uint32_t,const void *,void *);

typedef struct warts_param_reader
{
  void       *data;
  wpr_t       read;
  void       *param;
} warts_param_reader_t;

typedef struct warts_param_writer
{
  const void *data;
  wpw_t       write;
  void       *param;
} warts_param_writer_t;

/*
 * the optional bits of a list structure
 */
#define WARTS_LIST_DESCR      1              /* description of list */
#define WARTS_LIST_MONITOR    2              /* canonical name of monitor */
static const warts_var_t list_vars[] =
{
  {WARTS_LIST_DESCR,   -1, -1},
  {WARTS_LIST_MONITOR, -1, -1},
};
#define list_vars_mfb WARTS_VAR_MFB(list_vars)

/*
 * the optional bits of a cycle start structure
 */
#define WARTS_CYCLE_STOP_TIME 1              /* time at which cycle ended */
#define WARTS_CYCLE_HOSTNAME  2              /* hostname at cycle point */
static const warts_var_t cycle_vars[] =
{
  {WARTS_CYCLE_STOP_TIME,  4, -1},
  {WARTS_CYCLE_HOSTNAME,  -1, -1},
};
#define cycle_vars_mfb WARTS_VAR_MFB(cycle_vars)

/*
 * the optional bits of a trace structure
 */
#define WARTS_TRACE_LIST_ID        1   /* list id assigned by warts */
#define WARTS_TRACE_CYCLE_ID       2   /* cycle id assigned by warts */
#define WARTS_TRACE_ADDR_SRC_GID   3   /* src address key, deprecated */
#define WARTS_TRACE_ADDR_DST_GID   4   /* dst address key, deprecated */
#define WARTS_TRACE_START          5   /* start timestamp */
#define WARTS_TRACE_STOP_R         6   /* stop reason */
#define WARTS_TRACE_STOP_D         7   /* stop data */
#define WARTS_TRACE_FLAGS          8   /* flags */
#define WARTS_TRACE_ATTEMPTS       9   /* attempts */
#define WARTS_TRACE_HOPLIMIT       10  /* hoplimit */
#define WARTS_TRACE_TYPE           11  /* type */
#define WARTS_TRACE_PROBE_S        12  /* probe size */
#define WARTS_TRACE_PORT_SRC       13  /* source port */
#define WARTS_TRACE_PORT_DST       14  /* destination port */
#define WARTS_TRACE_FIRSTHOP       15  /* first hop */
#define WARTS_TRACE_TOS            16  /* type of service bits */
#define WARTS_TRACE_WAIT           17  /* how long to wait per probe */
#define WARTS_TRACE_LOOPS          18  /* max loops before stopping */
#define WARTS_TRACE_HOPCOUNT       19  /* hop count */
#define WARTS_TRACE_GAPLIMIT       20  /* gap limit */
#define WARTS_TRACE_GAPACTION      21  /* gap action */
#define WARTS_TRACE_LOOPACTION     22  /* loop action */
#define WARTS_TRACE_PROBEC         23  /* probe count */
#define WARTS_TRACE_WAITPROBE      24  /* min wait between probes */
#define WARTS_TRACE_CONFIDENCE     25  /* confidence level to attain */
#define WARTS_TRACE_ADDR_SRC       26  /* source address key */
#define WARTS_TRACE_ADDR_DST       27  /* destination address key */

static const warts_var_t trace_vars[] =
{
  {WARTS_TRACE_LIST_ID,      4, -1},
  {WARTS_TRACE_CYCLE_ID,     4, -1},
  {WARTS_TRACE_ADDR_SRC_GID, 4, -1},
  {WARTS_TRACE_ADDR_DST_GID, 4, -1},
  {WARTS_TRACE_START,        8, -1},
  {WARTS_TRACE_STOP_R,       1, -1},
  {WARTS_TRACE_STOP_D,       1, -1},
  {WARTS_TRACE_FLAGS,        1, -1},
  {WARTS_TRACE_ATTEMPTS,     1, -1},
  {WARTS_TRACE_HOPLIMIT,     1, -1},
  {WARTS_TRACE_TYPE,         1, -1},
  {WARTS_TRACE_PROBE_S,      2, -1},
  {WARTS_TRACE_PORT_SRC,     2, -1},
  {WARTS_TRACE_PORT_DST,     2, -1},
  {WARTS_TRACE_FIRSTHOP,     1, -1},
  {WARTS_TRACE_TOS,          1, -1},
  {WARTS_TRACE_WAIT,         1, -1},
  {WARTS_TRACE_LOOPS,        1, -1},
  {WARTS_TRACE_HOPCOUNT,     2, -1},
  {WARTS_TRACE_GAPLIMIT,     1, -1},
  {WARTS_TRACE_GAPACTION,    1, -1},
  {WARTS_TRACE_LOOPACTION,   1, -1},
  {WARTS_TRACE_PROBEC,       2, -1},
  {WARTS_TRACE_WAITPROBE,    1, -1},
  {WARTS_TRACE_CONFIDENCE,   1, -1},
  {WARTS_TRACE_ADDR_SRC,    -1, -1},
  {WARTS_TRACE_ADDR_DST,    -1, -1},
};
#define trace_vars_mfb WARTS_VAR_MFB(trace_vars)

/*
 * the optional bits of a trace pmtud structure
 */
#define WARTS_TRACE_PMTUD_IFMTU  1           /* interface mtu */
#define WARTS_TRACE_PMTUD_PMTU   2           /* path mtu */
#define WARTS_TRACE_PMTUD_OUTMTU 3           /* mtu to gateway */
static const warts_var_t pmtud_vars[] =
{
  {WARTS_TRACE_PMTUD_IFMTU,  2, -1},
  {WARTS_TRACE_PMTUD_PMTU,   2, -1},
  {WARTS_TRACE_PMTUD_OUTMTU, 2, SCAMPER_TRACE_PMTUD_TLV_OUTMTU},
};
#define pmtud_vars_mfb WARTS_VAR_MFB(pmtud_vars)

/*
 * the optional bits of a trace dtree structure
 */
#define WARTS_TRACE_DTREE_LSS_STOP_GID 1 /* deprecated */
#define WARTS_TRACE_DTREE_GSS_STOP_GID 2 /* deprecated */
#define WARTS_TRACE_DTREE_FIRSTHOP     3 /* firsthop */
#define WARTS_TRACE_DTREE_LSS_STOP     4 /* lss stop address */
#define WARTS_TRACE_DTREE_GSS_STOP     5 /* gss stop address */
static const warts_var_t trace_dtree_vars[] = 
{
  {WARTS_TRACE_DTREE_LSS_STOP_GID,  4, -1},
  {WARTS_TRACE_DTREE_GSS_STOP_GID,  4, -1},
  {WARTS_TRACE_DTREE_FIRSTHOP,      1, -1},
  {WARTS_TRACE_DTREE_LSS_STOP,     -1, -1},
  {WARTS_TRACE_DTREE_GSS_STOP,     -1, -1},
};
#define trace_dtree_vars_mfb WARTS_VAR_MFB(trace_dtree_vars)

/*
 * the optional bits of a trace hop structure
 */
#define WARTS_TRACE_HOP_ADDR_GID     1       /* address id, deprecated */
#define WARTS_TRACE_HOP_PROBE_TTL    2       /* probe ttl */
#define WARTS_TRACE_HOP_REPLY_TTL    3       /* reply ttl */
#define WARTS_TRACE_HOP_FLAGS        4       /* flags */
#define WARTS_TRACE_HOP_PROBE_ID     5       /* probe id */
#define WARTS_TRACE_HOP_RTT          6       /* round trip time */
#define WARTS_TRACE_HOP_ICMP_TC      7       /* icmp type / code */
#define WARTS_TRACE_HOP_PROBE_SIZE   8       /* probe size */
#define WARTS_TRACE_HOP_REPLY_SIZE   9       /* reply size */
#define WARTS_TRACE_HOP_REPLY_IPID   10      /* ipid of reply packet */
#define WARTS_TRACE_HOP_REPLY_IPTOS  11      /* tos bits of reply packet */
#define WARTS_TRACE_HOP_NHMTU        12      /* next hop mtu in ptb message */
#define WARTS_TRACE_HOP_INNER_IPLEN  13      /* ip->len from inside icmp */
#define WARTS_TRACE_HOP_INNER_IPTTL  14      /* ip->ttl from inside icmp */
#define WARTS_TRACE_HOP_TCP_FLAGS    15      /* tcp->flags of reply packet */
#define WARTS_TRACE_HOP_INNER_IPTOS  16      /* ip->tos byte inside icmp */
#define WARTS_TRACE_HOP_ICMPEXT      17      /* RFC 4884 icmp extension data */
#define WARTS_TRACE_HOP_ADDR         18      /* address */
static const warts_var_t hop_vars[] =
{
  {WARTS_TRACE_HOP_ADDR_GID,     4, -1},
  {WARTS_TRACE_HOP_PROBE_TTL,    1, -1},
  {WARTS_TRACE_HOP_REPLY_TTL,    1, -1},
  {WARTS_TRACE_HOP_FLAGS,        1, -1},
  {WARTS_TRACE_HOP_PROBE_ID,     1, -1},
  {WARTS_TRACE_HOP_RTT,          4, -1},
  {WARTS_TRACE_HOP_ICMP_TC,      2, -1},
  {WARTS_TRACE_HOP_PROBE_SIZE,   2, -1},
  {WARTS_TRACE_HOP_REPLY_SIZE,   2, -1},
  {WARTS_TRACE_HOP_REPLY_IPID,   2, SCAMPER_TRACE_HOP_TLV_REPLY_IPID},
  {WARTS_TRACE_HOP_REPLY_IPTOS,  1, SCAMPER_TRACE_HOP_TLV_REPLY_IPTOS},
  {WARTS_TRACE_HOP_NHMTU,        2, SCAMPER_TRACE_HOP_TLV_NHMTU},
  {WARTS_TRACE_HOP_INNER_IPLEN,  2, SCAMPER_TRACE_HOP_TLV_INNER_IPLEN},
  {WARTS_TRACE_HOP_INNER_IPTTL,  1, SCAMPER_TRACE_HOP_TLV_INNER_IPTTL},
  {WARTS_TRACE_HOP_TCP_FLAGS,    1, -1},
  {WARTS_TRACE_HOP_INNER_IPTOS,  1, SCAMPER_TRACE_HOP_TLV_INNER_IPTOS},
  {WARTS_TRACE_HOP_ICMPEXT      -1, -1},
  {WARTS_TRACE_HOP_ADDR,        -1, -1},
};
#define hop_vars_mfb WARTS_VAR_MFB(hop_vars)

/*
 * the optional bits of a ping structure
 */
#define WARTS_PING_LIST_ID         1
#define WARTS_PING_CYCLE_ID        2
#define WARTS_PING_ADDR_SRC_GID    3 /* deprecated */
#define WARTS_PING_ADDR_DST_GID    4 /* deprecated */
#define WARTS_PING_START           5
#define WARTS_PING_STOP_R          6
#define WARTS_PING_STOP_D          7
#define WARTS_PING_PATTERN_LEN     8
#define WARTS_PING_PATTERN_BYTES   9
#define WARTS_PING_PROBE_COUNT    10
#define WARTS_PING_PROBE_SIZE     11
#define WARTS_PING_PROBE_WAIT     12
#define WARTS_PING_PROBE_TTL      13
#define WARTS_PING_REPLY_COUNT    14
#define WARTS_PING_PING_SENT      15
#define WARTS_PING_PROBE_METHOD   16
#define WARTS_PING_PROBE_SPORT    17
#define WARTS_PING_PROBE_DPORT    18
#define WARTS_PING_USERID         19
#define WARTS_PING_ADDR_SRC       20
#define WARTS_PING_ADDR_DST       21
static const warts_var_t ping_vars[] =
{
  {WARTS_PING_LIST_ID,        4, -1},
  {WARTS_PING_CYCLE_ID,       4, -1},
  {WARTS_PING_ADDR_SRC_GID,   4, -1},
  {WARTS_PING_ADDR_DST_GID,   4, -1},
  {WARTS_PING_START,          8, -1},
  {WARTS_PING_STOP_R,         1, -1},
  {WARTS_PING_STOP_D,         1, -1},
  {WARTS_PING_PATTERN_LEN,    2, -1},
  {WARTS_PING_PATTERN_BYTES, -1, -1},
  {WARTS_PING_PROBE_COUNT,    2, -1},
  {WARTS_PING_PROBE_SIZE,     2, -1},
  {WARTS_PING_PROBE_WAIT,     1, -1},
  {WARTS_PING_PROBE_TTL,      1, -1},
  {WARTS_PING_REPLY_COUNT,    2, -1},
  {WARTS_PING_PING_SENT,      2, -1},
  {WARTS_PING_PROBE_METHOD,   1, -1},
  {WARTS_PING_PROBE_SPORT,    2, -1},
  {WARTS_PING_PROBE_DPORT,    2, -1},
  {WARTS_PING_USERID,         4, -1},
  {WARTS_PING_ADDR_SRC,      -1, -1},
  {WARTS_PING_ADDR_DST,      -1, -1},
};
#define ping_vars_mfb WARTS_VAR_MFB(ping_vars)

#define WARTS_PING_REPLY_ADDR_GID        1 /* deprecated */
#define WARTS_PING_REPLY_FLAGS           2
#define WARTS_PING_REPLY_REPLY_TTL       3
#define WARTS_PING_REPLY_REPLY_SIZE      4
#define WARTS_PING_REPLY_ICMP_TC         5
#define WARTS_PING_REPLY_RTT             6
#define WARTS_PING_REPLY_PROBE_ID        7
#define WARTS_PING_REPLY_REPLY_IPID      8
#define WARTS_PING_REPLY_PROBE_IPID      9
#define WARTS_PING_REPLY_REPLY_PROTO     10
#define WARTS_PING_REPLY_TCP_FLAGS       11
#define WARTS_PING_REPLY_ADDR            12
static const warts_var_t ping_reply_vars[] =
{
  {WARTS_PING_REPLY_ADDR_GID,        4, -1},
  {WARTS_PING_REPLY_FLAGS,           1, -1},
  {WARTS_PING_REPLY_REPLY_TTL,       1, -1},
  {WARTS_PING_REPLY_REPLY_SIZE,      2, -1},
  {WARTS_PING_REPLY_ICMP_TC,         2, -1},
  {WARTS_PING_REPLY_RTT,             4, -1},
  {WARTS_PING_REPLY_PROBE_ID,        2, -1},
  {WARTS_PING_REPLY_REPLY_IPID,      2, -1},
  {WARTS_PING_REPLY_PROBE_IPID,      2, -1},
  {WARTS_PING_REPLY_REPLY_PROTO,     1, -1},
  {WARTS_PING_REPLY_TCP_FLAGS,       1, -1},
  {WARTS_PING_REPLY_ADDR,           -1, -1},
};
#define ping_reply_vars_mfb WARTS_VAR_MFB(ping_reply_vars)

/*
 * the optional bits of a tracelb structure
 */
#define WARTS_TRACELB_LIST_ID      1        /* list id assigned by warts */
#define WARTS_TRACELB_CYCLE_ID     2        /* cycle id assigned by warts */
#define WARTS_TRACELB_ADDR_SRC_GID 3        /* src address key, deprecated */
#define WARTS_TRACELB_ADDR_DST_GID 4        /* dst address key, deprecated */
#define WARTS_TRACELB_START        5        /* start timestamp */
#define WARTS_TRACELB_SPORT        6        /* source port */
#define WARTS_TRACELB_DPORT        7        /* destination port */
#define WARTS_TRACELB_PROBE_SIZE   8        /* probe size */
#define WARTS_TRACELB_TYPE         9        /* type */
#define WARTS_TRACELB_FIRSTHOP     10       /* first hop */
#define WARTS_TRACELB_WAIT_TIMEOUT 11       /* wait before probe timeout */
#define WARTS_TRACELB_WAIT_PROBE   12       /* minimum wait between probes */
#define WARTS_TRACELB_ATTEMPTS     13       /* attempts */
#define WARTS_TRACELB_CONFIDENCE   14       /* confidence level to attain */
#define WARTS_TRACELB_TOS          15       /* type of service bits */
#define WARTS_TRACELB_NODEC        16       /* the number of nodes found */
#define WARTS_TRACELB_LINKC        17       /* the number of links found */
#define WARTS_TRACELB_PROBEC       18       /* number of probes sent */
#define WARTS_TRACELB_PROBECMAX    19       /* max number of probes to send */
#define WARTS_TRACELB_GAPLIMIT     20       /* gaplimit */
#define WARTS_TRACELB_ADDR_SRC     21       /* src address */
#define WARTS_TRACELB_ADDR_DST     22       /* dst address */

static const warts_var_t tracelb_vars[] =
{
  {WARTS_TRACELB_LIST_ID,      4, -1},
  {WARTS_TRACELB_CYCLE_ID,     4, -1},
  {WARTS_TRACELB_ADDR_SRC_GID, 4, -1},
  {WARTS_TRACELB_ADDR_DST_GID, 4, -1},
  {WARTS_TRACELB_START,        8, -1},
  {WARTS_TRACELB_SPORT,        2, -1},
  {WARTS_TRACELB_DPORT,        2, -1},
  {WARTS_TRACELB_PROBE_SIZE,   2, -1},
  {WARTS_TRACELB_TYPE,         1, -1},
  {WARTS_TRACELB_FIRSTHOP,     1, -1},
  {WARTS_TRACELB_WAIT_TIMEOUT, 1, -1},
  {WARTS_TRACELB_WAIT_PROBE,   1, -1},
  {WARTS_TRACELB_ATTEMPTS,     1, -1},
  {WARTS_TRACELB_CONFIDENCE,   1, -1},
  {WARTS_TRACELB_TOS,          1, -1},
  {WARTS_TRACELB_NODEC,        2, -1},
  {WARTS_TRACELB_LINKC,        2, -1},
  {WARTS_TRACELB_PROBEC,       4, -1},
  {WARTS_TRACELB_PROBECMAX,    4, -1},
  {WARTS_TRACELB_GAPLIMIT,     1, -1},
  {WARTS_TRACELB_ADDR_SRC,    -1, -1},
  {WARTS_TRACELB_ADDR_DST,    -1, -1},
};
#define tracelb_vars_mfb WARTS_VAR_MFB(tracelb_vars)

#define WARTS_TRACELB_NODE_ADDR_GID  1
#define WARTS_TRACELB_NODE_FLAGS     2
#define WARTS_TRACELB_NODE_LINKC     3
#define WARTS_TRACELB_NODE_QTTL      4
#define WARTS_TRACELB_NODE_ADDR      5

static const warts_var_t tracelb_node_vars[] =
{
  {WARTS_TRACELB_NODE_ADDR_GID, 4, -1}, /* deprecated */
  {WARTS_TRACELB_NODE_FLAGS,    1, -1},
  {WARTS_TRACELB_NODE_LINKC,    2, -1},
  {WARTS_TRACELB_NODE_QTTL,     1, -1},
  {WARTS_TRACELB_NODE_ADDR,    -1, -1},
};
#define tracelb_node_vars_mfb WARTS_VAR_MFB(tracelb_node_vars)

#define WARTS_TRACELB_LINK_FROM    1
#define WARTS_TRACELB_LINK_TO      2
#define WARTS_TRACELB_LINK_HOPC    3

static const warts_var_t tracelb_link_vars[] =
{
  {WARTS_TRACELB_LINK_FROM,   2, -1},
  {WARTS_TRACELB_LINK_TO,     2, -1},
  {WARTS_TRACELB_LINK_HOPC,   1, -1},
};
#define tracelb_link_vars_mfb WARTS_VAR_MFB(tracelb_link_vars)

#define WARTS_TRACELB_PROBE_TX         1
#define WARTS_TRACELB_PROBE_FLOWID     2
#define WARTS_TRACELB_PROBE_TTL        3
#define WARTS_TRACELB_PROBE_ATTEMPT    4
#define WARTS_TRACELB_PROBE_RXC        5

static const warts_var_t tracelb_probe_vars[] =
{
  {WARTS_TRACELB_PROBE_TX,      8, -1},
  {WARTS_TRACELB_PROBE_FLOWID,  2, -1},
  {WARTS_TRACELB_PROBE_TTL,     1, -1},
  {WARTS_TRACELB_PROBE_ATTEMPT, 1, -1},
  {WARTS_TRACELB_PROBE_RXC,     2, -1},
};
#define tracelb_probe_vars_mfb WARTS_VAR_MFB(tracelb_probe_vars)

#define WARTS_TRACELB_REPLY_RX         1
#define WARTS_TRACELB_REPLY_IPID       2
#define WARTS_TRACELB_REPLY_TTL        3
#define WARTS_TRACELB_REPLY_FLAGS      4
#define WARTS_TRACELB_REPLY_ICMP_TC    5
#define WARTS_TRACELB_REPLY_TCP_FLAGS  6
#define WARTS_TRACELB_REPLY_ICMP_EXT   7
#define WARTS_TRACELB_REPLY_ICMP_Q_TTL 8
#define WARTS_TRACELB_REPLY_ICMP_Q_TOS 9
#define WARTS_TRACELB_REPLY_FROM_GID   10 /* deprecated */
#define WARTS_TRACELB_REPLY_FROM       11

static const warts_var_t tracelb_reply_vars[] =
{
  {WARTS_TRACELB_REPLY_RX,         8, -1},
  {WARTS_TRACELB_REPLY_IPID,       2, -1},
  {WARTS_TRACELB_REPLY_TTL,        1, -1},
  {WARTS_TRACELB_REPLY_FLAGS,      1, -1},
  {WARTS_TRACELB_REPLY_ICMP_TC,    2, -1},
  {WARTS_TRACELB_REPLY_TCP_FLAGS,  1, -1},
  {WARTS_TRACELB_REPLY_ICMP_EXT,  -1, -1},
  {WARTS_TRACELB_REPLY_ICMP_Q_TTL, 1, -1},
  {WARTS_TRACELB_REPLY_ICMP_Q_TOS, 1, -1},
  {WARTS_TRACELB_REPLY_FROM_GID,   4, -1},
  {WARTS_TRACELB_REPLY_FROM,      -1, -1},
};
#define tracelb_reply_vars_mfb WARTS_VAR_MFB(tracelb_reply_vars)

#define WARTS_TRACELB_PROBESET_PROBEC 1

static const warts_var_t tracelb_probeset_vars[] =
{
  {WARTS_TRACELB_PROBESET_PROBEC, 2, -1},
};
#define tracelb_probeset_vars_mfb WARTS_VAR_MFB(tracelb_probeset_vars)

#define WARTS_DEALIAS_LIST_ID  1
#define WARTS_DEALIAS_CYCLE_ID 2
#define WARTS_DEALIAS_START    3
#define WARTS_DEALIAS_METHOD   4
#define WARTS_DEALIAS_RESULT   5
#define WARTS_DEALIAS_PROBEC   6
#define WARTS_DEALIAS_USERID   7

static const warts_var_t dealias_vars[] =
{
  {WARTS_DEALIAS_LIST_ID,  4, -1},
  {WARTS_DEALIAS_CYCLE_ID, 4, -1},
  {WARTS_DEALIAS_START,    8, -1},
  {WARTS_DEALIAS_METHOD,   1, -1},
  {WARTS_DEALIAS_RESULT,   1, -1},
  {WARTS_DEALIAS_PROBEC,   4, -1},
  {WARTS_DEALIAS_USERID,   4, -1},
};
#define dealias_vars_mfb WARTS_VAR_MFB(dealias_vars)

#define WARTS_DEALIAS_ALLY_WAIT_PROBE   1
#define WARTS_DEALIAS_ALLY_WAIT_TIMEOUT 2
#define WARTS_DEALIAS_ALLY_ATTEMPTS     3
#define WARTS_DEALIAS_ALLY_FUDGE        4
#define WARTS_DEALIAS_ALLY_FLAGS        5

static const warts_var_t dealias_ally_vars[] =
{
  {WARTS_DEALIAS_ALLY_WAIT_PROBE,    2, -1},
  {WARTS_DEALIAS_ALLY_WAIT_TIMEOUT,  1, -1},
  {WARTS_DEALIAS_ALLY_ATTEMPTS,      1, -1},
  {WARTS_DEALIAS_ALLY_FUDGE,         2, -1},
  {WARTS_DEALIAS_ALLY_FLAGS,         1, -1},
};
#define dealias_ally_vars_mfb WARTS_VAR_MFB(dealias_ally_vars)

#define WARTS_DEALIAS_MERCATOR_ATTEMPTS     1
#define WARTS_DEALIAS_MERCATOR_WAIT_TIMEOUT 2

static const warts_var_t dealias_mercator_vars[] = 
{
  {WARTS_DEALIAS_MERCATOR_ATTEMPTS,     1, -1},
  {WARTS_DEALIAS_MERCATOR_WAIT_TIMEOUT, 1, -1},
};
#define dealias_mercator_vars_mfb WARTS_VAR_MFB(dealias_mercator_vars)

#define WARTS_DEALIAS_RADARGUN_PROBEDEFC    1
#define WARTS_DEALIAS_RADARGUN_ATTEMPTS     2
#define WARTS_DEALIAS_RADARGUN_WAIT_PROBE   3
#define WARTS_DEALIAS_RADARGUN_WAIT_ROUND   4
#define WARTS_DEALIAS_RADARGUN_WAIT_TIMEOUT 5

static const warts_var_t dealias_radargun_vars[] =
{
  {WARTS_DEALIAS_RADARGUN_PROBEDEFC,    4, -1},
  {WARTS_DEALIAS_RADARGUN_ATTEMPTS,     2, -1},
  {WARTS_DEALIAS_RADARGUN_WAIT_PROBE,   2, -1},
  {WARTS_DEALIAS_RADARGUN_WAIT_ROUND,   4, -1},
  {WARTS_DEALIAS_RADARGUN_WAIT_TIMEOUT, 1, -1},
};
#define dealias_radargun_vars_mfb WARTS_VAR_MFB(dealias_radargun_vars)

#define WARTS_DEALIAS_PREFIXSCAN_A            1
#define WARTS_DEALIAS_PREFIXSCAN_B            2
#define WARTS_DEALIAS_PREFIXSCAN_AB           3
#define WARTS_DEALIAS_PREFIXSCAN_XS           4
#define WARTS_DEALIAS_PREFIXSCAN_PREFIX       5
#define WARTS_DEALIAS_PREFIXSCAN_ATTEMPTS     6
#define WARTS_DEALIAS_PREFIXSCAN_FUDGE        7
#define WARTS_DEALIAS_PREFIXSCAN_WAIT_PROBE   8
#define WARTS_DEALIAS_PREFIXSCAN_WAIT_TIMEOUT 9
#define WARTS_DEALIAS_PREFIXSCAN_PROBEDEFC    10
#define WARTS_DEALIAS_PREFIXSCAN_FLAGS        11
#define WARTS_DEALIAS_PREFIXSCAN_REPLYC       12

static const warts_var_t dealias_prefixscan_vars[] =
{
  {WARTS_DEALIAS_PREFIXSCAN_A,            -1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_B,            -1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_AB,           -1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_XS,           -1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_PREFIX,        1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_ATTEMPTS,      1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_FUDGE,         2, -1},
  {WARTS_DEALIAS_PREFIXSCAN_WAIT_PROBE,    2, -1},
  {WARTS_DEALIAS_PREFIXSCAN_WAIT_TIMEOUT,  1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_PROBEDEFC,     2, -1},
  {WARTS_DEALIAS_PREFIXSCAN_FLAGS,         1, -1},
  {WARTS_DEALIAS_PREFIXSCAN_REPLYC,        1, -1},
};
#define dealias_prefixscan_vars_mfb WARTS_VAR_MFB(dealias_prefixscan_vars)

#define WARTS_DEALIAS_PROBEDEF_DST_GID    1
#define WARTS_DEALIAS_PROBEDEF_SRC_GID    2
#define WARTS_DEALIAS_PROBEDEF_ID         3
#define WARTS_DEALIAS_PROBEDEF_METHOD     4
#define WARTS_DEALIAS_PROBEDEF_TTL        5
#define WARTS_DEALIAS_PROBEDEF_TOS        6
#define WARTS_DEALIAS_PROBEDEF_4BYTES     7
#define WARTS_DEALIAS_PROBEDEF_TCP_FLAGS  8
#define WARTS_DEALIAS_PROBEDEF_ICMP_ID    9
#define WARTS_DEALIAS_PROBEDEF_DST        10
#define WARTS_DEALIAS_PROBEDEF_SRC        11

static const warts_var_t dealias_probedef_vars[] =
{
  {WARTS_DEALIAS_PROBEDEF_DST_GID,    4, -1},
  {WARTS_DEALIAS_PROBEDEF_SRC_GID,    4, -1},
  {WARTS_DEALIAS_PROBEDEF_ID,         4, -1},
  {WARTS_DEALIAS_PROBEDEF_METHOD,     1, -1},
  {WARTS_DEALIAS_PROBEDEF_TTL,        1, -1},
  {WARTS_DEALIAS_PROBEDEF_TOS,        1, -1},
  {WARTS_DEALIAS_PROBEDEF_4BYTES,     4, -1},
  {WARTS_DEALIAS_PROBEDEF_TCP_FLAGS,  1, -1},
  {WARTS_DEALIAS_PROBEDEF_ICMP_ID,    2, -1},
  {WARTS_DEALIAS_PROBEDEF_DST,       -1, -1},
  {WARTS_DEALIAS_PROBEDEF_SRC,       -1, -1},
};
#define dealias_probedef_vars_mfb WARTS_VAR_MFB(dealias_probedef_vars)

#define WARTS_DEALIAS_PROBE_DEF    1
#define WARTS_DEALIAS_PROBE_TX     2
#define WARTS_DEALIAS_PROBE_REPLYC 3
#define WARTS_DEALIAS_PROBE_IPID   4
#define WARTS_DEALIAS_PROBE_SEQ    5

static const warts_var_t dealias_probe_vars[] =
{
  {WARTS_DEALIAS_PROBE_DEF,    4, -1},
  {WARTS_DEALIAS_PROBE_TX,     8, -1},
  {WARTS_DEALIAS_PROBE_REPLYC, 2, -1},
  {WARTS_DEALIAS_PROBE_IPID,   2, -1},
  {WARTS_DEALIAS_PROBE_SEQ,    4, -1},
};
#define dealias_probe_vars_mfb WARTS_VAR_MFB(dealias_probe_vars)

#define WARTS_DEALIAS_REPLY_SRC_GID    1
#define WARTS_DEALIAS_REPLY_RX         2
#define WARTS_DEALIAS_REPLY_IPID       3
#define WARTS_DEALIAS_REPLY_TTL        4
#define WARTS_DEALIAS_REPLY_ICMP_TC    5
#define WARTS_DEALIAS_REPLY_ICMP_Q_TTL 6
#define WARTS_DEALIAS_REPLY_ICMP_EXT   7
#define WARTS_DEALIAS_REPLY_PROTO      8
#define WARTS_DEALIAS_REPLY_TCP_FLAGS  9
#define WARTS_DEALIAS_REPLY_SRC        10

static const warts_var_t dealias_reply_vars[] =
{
  {WARTS_DEALIAS_REPLY_SRC_GID,     4, -1},
  {WARTS_DEALIAS_REPLY_RX,          8, -1},
  {WARTS_DEALIAS_REPLY_IPID,        2, -1},
  {WARTS_DEALIAS_REPLY_TTL,         1, -1},
  {WARTS_DEALIAS_REPLY_ICMP_TC,     2, -1},
  {WARTS_DEALIAS_REPLY_ICMP_Q_TTL,  1, -1},
  {WARTS_DEALIAS_REPLY_ICMP_EXT,   -1, -1},
  {WARTS_DEALIAS_REPLY_PROTO,       1, -1},
  {WARTS_DEALIAS_REPLY_TCP_FLAGS,   1, -1},
  {WARTS_DEALIAS_REPLY_SRC,        -1, -1},
};
#define dealias_reply_vars_mfb WARTS_VAR_MFB(dealias_reply_vars)

/*
 * warts_addr, warts_addrtable
 *
 * keep track of addresses being written to disk.
 */
typedef struct warts_addr
{
  scamper_addr_t *addr;
  uint32_t        id;
  uint8_t         ondisk;
} warts_addr_t;
typedef struct warts_addrtable
{
  warts_addr_t **addrs;
  int            addrc;
} warts_addrtable_t;

typedef struct warts_trace_hop
{
  scamper_trace_hop_t *hop;
  uint8_t              flags[WARTS_VAR_MFB(hop_vars)];
  uint16_t             flags_len;
  uint16_t             params_len;
} warts_trace_hop_t;

typedef struct warts_trace_dtree
{
  uint8_t               flags[WARTS_VAR_MFB(trace_dtree_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
  uint32_t              len;
} warts_trace_dtree_t;

typedef struct warts_ping_reply
{
  scamper_ping_reply_t *reply;
  uint8_t               flags[WARTS_VAR_MFB(ping_reply_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
} warts_ping_reply_t;

typedef struct warts_tracelb_node
{
  uint8_t               flags[WARTS_VAR_MFB(tracelb_node_vars)];
  uint16_t              flags_len;
  uint16_t              params_len;
} warts_tracelb_node_t;

typedef struct warts_tracelb_reply
{
  uint8_t                 flags[WARTS_VAR_MFB(tracelb_reply_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
} warts_tracelb_reply_t;

typedef struct warts_tracelb_probe
{
  uint8_t                 flags[WARTS_VAR_MFB(tracelb_probe_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
  warts_tracelb_reply_t  *replies;
} warts_tracelb_probe_t;

typedef struct warts_tracelb_probeset
{
  uint8_t                 flags[WARTS_VAR_MFB(tracelb_probeset_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
  warts_tracelb_probe_t  *probes;
  uint16_t                probec;
} warts_tracelb_probeset_t;

typedef struct warts_tracelb_link
{
  uint16_t                  from;
  uint16_t                  to;
  uint8_t                   flags[WARTS_VAR_MFB(tracelb_link_vars)];
  uint16_t                  flags_len;
  uint16_t                  params_len;
  warts_tracelb_probeset_t *sets;
  uint8_t                   hopc;
} warts_tracelb_link_t;

typedef struct warts_dealias_probedef
{
  uint8_t                 flags[WARTS_VAR_MFB(dealias_probedef_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
} warts_dealias_probedef_t;

typedef struct warts_dealias_data
{
  warts_dealias_probedef_t *probedefs;
  uint32_t                  probedefc;
  uint8_t                   flags[1];
  uint16_t                  flags_len;
  uint16_t                  params_len;
} warts_dealias_data_t;

typedef struct warts_dealias_reply
{
  uint8_t                 flags[WARTS_VAR_MFB(dealias_reply_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
} warts_dealias_reply_t;

typedef struct warts_dealias_probe
{
  uint8_t                 flags[WARTS_VAR_MFB(dealias_probe_vars)];
  uint16_t                flags_len;
  uint16_t                params_len;
  warts_dealias_reply_t  *replies;
} warts_dealias_probe_t;

static void flag_ij(const int id, int *i, int *j)
{
  if(id % 7 == 0)
    {
      *i = (id / 7) - 1;
      *j = 7;
    }
  else
    {
      *i = id / 7;
      *j = id % 7;
    }
  return;
}

/*
 * flag_set
 *
 * small routine to set a flag bit.  this exists because the 8th bit of
 * each byte used for flags is used to indicate when another set of flags
 * follows the byte.
 */
static void flag_set(uint8_t *flags, const int id, int *max_id)
{
  int i, j;

  assert(id > 0);
  flag_ij(id, &i, &j);
  flags[i] |= (0x1 << (j-1));

  if(max_id != NULL && *max_id < id)
    *max_id = id;

  return;
}

static int flag_isset(const uint8_t *flags, const int id)
{
  int i, j;

  assert(id > 0);
  flag_ij(id, &i, &j);

  if((flags[i] & (0x1 << (j-1))) == 0)
    return 0;

  return 1;
}

/*
 * fold_flags
 *
 * go through and set each link bit in the flag set, as appropriate.
 * conveniently return the count of the number of bytes required to store
 * the flags.
 */
static uint16_t fold_flags(uint8_t *flags, const int max_id)
{
  uint16_t i, j;

  /* if no flags are set, it is still a requirement to include a zero byte */
  if(max_id == 0)
    {
      return 1;
    }

  /* figure out how many bytes have been used */
  j = max_id / 7;
  if((max_id % 7) != 0) j++;

  /*
   * j has to be greater than zero by the above logic.  however, the for
   * loop below will go bananas if it is not
   */
  assert(j > 0);

  /* skip through and set the 'more flags' bit for all flag bytes necessary */
  for(i=0; i<j-1; i++)
    {
      flags[i] |= 0x80;
    }

  return j;
}

static int warts_addr_cmp(const void *va, const void *vb)
{
  const warts_addr_t *a = *((const warts_addr_t **)va);
  const warts_addr_t *b = *((const warts_addr_t **)vb);
  return scamper_addr_cmp(a->addr, b->addr);
}

static uint32_t warts_addr_size(warts_addrtable_t *t, scamper_addr_t *addr)
{
  warts_addr_t f, *wa;

  f.addr = addr;
  if(array_find((void **)t->addrs, t->addrc, &f, warts_addr_cmp) != NULL)
    {
      return 1 + 4;
    }

  if((wa = malloc_zero(sizeof(warts_addr_t))) != NULL)
    {
      wa->addr = scamper_addr_use(addr);
      wa->id   = t->addrc;

      if(array_insert((void ***)&t->addrs, &t->addrc, wa, warts_addr_cmp) != 0)
	{
	  free(wa);
	}
    }

  return 1 + 1 + scamper_addr_size(addr);
}

static void warts_addrtable_clean(warts_addrtable_t *table)
{
  int i;
  if(table->addrs != NULL)
    {
      for(i=0; i<table->addrc; i++)
	{
	  scamper_addr_free(table->addrs[i]->addr);
	  free(table->addrs[i]);
	}
      free(table->addrs);
    }
  return;
}

static void insert_addr(uint8_t *buf, uint32_t *off, const uint32_t len,
			const scamper_addr_t *addr, void *param)
{
  warts_addrtable_t *table = param;
  warts_addr_t *wa, f;
  uint32_t id;
  size_t size;

  assert(table != NULL);
  assert(len - *off >= 1 + 1);

  f.addr = (scamper_addr_t *)addr;
  wa = array_find((void **)table->addrs, table->addrc, &f, warts_addr_cmp);
  assert(wa != NULL);

  if(wa->ondisk == 0)
    {
      size = scamper_addr_size(addr);
      buf[(*off)++] = (uint8_t)size;
      buf[(*off)++] = addr->type;
      memcpy(&buf[*off], addr->addr, size);

      /* make a record to say this address is now recorded */
      if(wa != NULL)
	wa->ondisk = 1;
    }
  else
    {
      size = 4;
      id = htonl(wa->id);
      buf[(*off)++] = 0;
      memcpy(&buf[*off], &id, size);
    }

  *off += size;
  return;
}

static void insert_uint16(uint8_t *buf, uint32_t *off, const uint32_t len,
			  const uint16_t *in, void *param)
{
  uint16_t tmp = htons(*in);
  assert(len - *off >= 2);
  memcpy(&buf[*off], &tmp, 2);
  *off += 2;
  return;
}

static void insert_uint16_tlv(uint8_t *buf, uint32_t *off, const uint32_t len,
			      const scamper_tlv_t *in, uint8_t *type)
{
  const scamper_tlv_t *tlv = scamper_tlv_get(in, *type);
  assert(tlv != NULL);
  assert(tlv->tlv_len == 2);
  insert_uint16(buf, off, len, &tlv->tlv_val_16, NULL);
  return;
}

static void insert_uint32(uint8_t *buf, uint32_t *off, const uint32_t len,
			  const uint32_t *in, void *param)
{
  uint32_t tmp = htonl(*in);

  assert(len - *off >= 4);

  memcpy(&buf[*off], &tmp, 4);
  *off += 4;
  return;
}

static void insert_byte(uint8_t *buf, uint32_t *off, const uint32_t len,
			const uint8_t *in, void *param)
{
  assert(len - *off >= 1);
  buf[(*off)++] = *in;
  return;
}

static void insert_byte_tlv(uint8_t *buf, uint32_t *off, const uint32_t len,
			    const scamper_tlv_t *in, uint8_t *type)
{
  const scamper_tlv_t *tlv = scamper_tlv_get(in, *type);
  assert(tlv != NULL);
  assert(tlv->tlv_len == 1);
  insert_byte(buf, off, len, &tlv->tlv_val_8, NULL);
  return;
}

static void insert_bytes_uint16(uint8_t *buf,uint32_t *off,const uint32_t len,
				const void *vin, uint16_t *count)
{
  assert(len - *off >= *count);
  memcpy(buf + *off, vin, *count);
  *off += *count;
  return;
}

static void insert_string(uint8_t *buf, uint32_t *off, const uint32_t len,
			  const char *in, void *param)
{
  uint8_t c;
  int i = 0;

  do
    {
      assert(len - *off > 0);
      buf[(*off)++] = c = in[i++];
    }
  while(c != '\0');

  return;
}

/*
 * insert_timeval
 *
 * this function may cause trouble in the future with timeval struct members
 * changing types and so on.
 */
static void insert_timeval(uint8_t *buf, uint32_t *off, const uint32_t len,
			   const struct timeval *in, void *param)
{
  uint32_t t32;

  assert(len - *off >= 8);

  t32 = htonl(in->tv_sec);
  memcpy(buf + *off, &t32, 4); *off += 4;
  
  t32 = htonl(in->tv_usec);
  memcpy(buf + *off, &t32, 4); *off += 4;

  return;
}

static void insert_rtt(uint8_t *buf, uint32_t *off, const uint32_t len,
		       const struct timeval *tv, void *param)
{
  uint32_t t32 = (tv->tv_sec * 1000000) + tv->tv_usec;
  insert_uint32(buf, off, len, &t32, NULL);
  return;
}

static int extract_addr(const uint8_t *buf, uint32_t *off,
			const uint32_t len, scamper_addr_t **out, void *param)
{
  warts_addrtable_t *table = param;
  warts_addr_t *wa;
  uint32_t u32;
  uint8_t size;
  uint8_t type;

  assert(table != NULL);

  /* make sure there is enough data left for the address header */
  if(len - *off < 1)
    return -1;

  /* get the byte saying how large the record is */
  size = buf[(*off)++];

  /*
   * if the address length field is zero, then we have a 4 byte index value
   * following.
   */
  if(size == 0)
    {
      if(len - *off < 4)
	return -1;

      memcpy(&u32, &buf[*off], 4); u32 = ntohl(u32);
      *out = scamper_addr_use(table->addrs[u32]->addr);
      *off += 4;
      return 0;
    }

  /*
   * we have an address defined inline.  extract the address out and store
   * it in a table, incase it is referenced shortly
   */
  type = buf[(*off)++];
  if((wa = malloc_zero(sizeof(warts_addr_t))) == NULL ||
     (wa->addr = scamper_addr_alloc(type, &buf[*off])) == NULL ||
     array_insert((void ***)&table->addrs, &table->addrc, wa, NULL) != 0)
    {
      goto err;
    }

  *out = scamper_addr_use(wa->addr);
  *off += size;
  return 0;

 err:
  if(wa != NULL)
    {
      if(wa->addr != NULL) scamper_addr_free(wa->addr);
      free(wa);
    }
  return -1;
}

static int extract_string(const uint8_t *buf, uint32_t *off,
			  const uint32_t len, char **out, void *param)
{
  uint32_t i;

  for(i=*off; i<len; i++)
    {
      /* scan for the null terminator */
      if(buf[i] == '\0')
	{
	  if((*out = memdup(buf+*off, (size_t)(i-*off+1))) == NULL)
	    {
	      return -1;
	    }

	  *off = i+1;
	  return 0;
	}
    }

  return -1;
}

static int extract_uint32(const uint8_t *buf, uint32_t *off,
			  const uint32_t len, uint32_t *out, void *param)
{
  if(len - *off < 4)
    {
      return -1;
    }

  memcpy(out, buf + *off, 4); *off += 4;
  *out = ntohl(*out);
  return 0;
}

static int extract_uint16(const uint8_t *buf, uint32_t *off,
			  const uint32_t len, uint16_t *out, void *param)
{
  if(len - *off < 2)
    {
      return -1;
    }

  memcpy(out, buf + *off, 2); *off += 2;
  *out = ntohs(*out);
  return 0;
}

static int extract_uint16_tlv(const uint8_t *buf, uint32_t *off,
			      const uint32_t len, scamper_tlv_t **tlvs,
			      uint8_t *type)
{
  uint16_t t16;

  if(extract_uint16(buf, off, len, &t16, NULL) != 0)
    {
      return -1;
    }

  if(scamper_tlv_set(tlvs, *type, 2, &t16) == NULL)
    {
      return -1;
    }

  return 0;
}

static int extract_byte(const uint8_t *buf, uint32_t *off,
			const uint32_t len, uint8_t *out, void *param)
{
  if(len - *off < 1)
    {
      return -1;
    }

  *out = buf[(*off)++];
  return 0;  
}

static int extract_bytes_alloc(const uint8_t *buf, uint32_t *off,
			       const uint32_t len, uint8_t **out,
			       uint16_t *req)
{
  if(len - *off < *req)
    {
      return -1;
    }

  if(*req == 0)
    {
      *out = NULL;
    }
  else
    {
      if((*out = malloc(*req)) == NULL)
	{
	  return -1;
	}

      memcpy(*out, buf + *off, *req);
      *off += *req;
    }

  return 0;
}

/*
 * extract_bytes
 *
 * copy the number of requested bytes into the specified array
 */
static int extract_bytes(const uint8_t *buf, uint32_t *off, const uint32_t len,
			 uint8_t *out, uint16_t *req)
{
  if(len - *off < *req)
    return -1;

  if(req == 0)
    return 0;

  memcpy(out, buf + *off, *req);
  *off += *req;

  return 0;
}

static int extract_byte_tlv(const uint8_t *buf, uint32_t *off,
			    const uint32_t len,
			    scamper_tlv_t **tlvs, uint8_t *type)
{
  uint8_t  t8;

  if(extract_byte(buf, off, len, &t8, NULL) != 0)
    {
      return -1;
    }

  if(scamper_tlv_set(tlvs, *type, 1, &t8) == NULL)
    {
      return -1;
    }

  return 0;
}

static int extract_addr_gid(const uint8_t *buf, uint32_t *off,
			    const uint32_t len,
			    scamper_addr_t **addr, warts_state_t *state)
{
  uint32_t id;

  if(extract_uint32(buf, off, len, &id, NULL) != 0)
    {
      return -1;
    }

  if(id >= state->addr_count)
    {
      return -1;
    }

  *addr = scamper_addr_use(state->addr_table[id]);
  return 0;
}

static int extract_list(const uint8_t *buf, uint32_t *off,
			const uint32_t len,
			scamper_list_t **list, warts_state_t *state)
{
  uint32_t id;

  if(extract_uint32(buf, off, len, &id, NULL) != 0)
    {
      return -1;
    }

  if(id >= state->list_count)
    {
      return -1;
    }

  *list = scamper_list_use(state->list_table[id]->list);
  return 0;
}

static int extract_cycle(const uint8_t *buf, uint32_t *off,
			 const uint32_t len,
			 scamper_cycle_t **cycle, warts_state_t *state)
{
  uint32_t id;

  if(extract_uint32(buf, off, len, &id, NULL) != 0)
    {
      return -1;
    }

  if(id >= state->cycle_count)
    {
      return -1;
    }

  *cycle = scamper_cycle_use(state->cycle_table[id]->cycle);
  return 0;
}

static int extract_timeval(const uint8_t *buf, uint32_t *off,
			   const uint32_t len, struct timeval *tv, void *param)
{
  uint32_t t32;

  if(extract_uint32(buf, off, len, &t32, NULL) != 0)
    {
      return -1;
    }
  tv->tv_sec = t32;

  if(extract_uint32(buf, off, len, &t32, NULL) != 0)
    {
      return -1;
    }
  tv->tv_usec = t32;

  return 0;
}

static int extract_rtt(const uint8_t *buf, uint32_t *off, const uint32_t len,
		       struct timeval *tv, void *param)
{
  uint32_t t32;

  if(extract_uint32(buf, off, len, &t32, NULL) != 0)
    {
      return -1;
    }

  tv->tv_sec  = t32 / 1000000;
  tv->tv_usec = t32 % 1000000;
  return 0;
}

static int warts_params_read(const uint8_t *buf, uint32_t *off, uint32_t len,
			     warts_param_reader_t *handlers, int handler_cnt)
{
  warts_param_reader_t *handler;
  const uint8_t *flags = &buf[*off];
  uint16_t flags_len, params_len;
  uint32_t final_off;
  int      i, j, id;

  /* if there are no flags set at all, then there's nothing left to do */
  if(flags[0] == 0)
    {
      (*off)++;
      return 0;
    }

  /* figure out how long the flags block is */
  flags_len = 0;
  while((buf[*off] & 0x80) != 0 && *off < len)
    {
      (*off)++; flags_len++;
    }
  flags_len++; (*off)++;
  if(*off > len)
    {
      goto err;
    }

  /* the length field */
  if(extract_uint16(buf, off, len, &params_len, NULL) != 0)
    {
      goto err;
    }

  /*
   * this calculation is required so we handle the case where we have
   * new parameters that we don't know how to handle (i.e. so we can skip
   * over them)
   */
  final_off = *off + params_len;

  /* read all flag bytes */
  for(i=0; i<flags_len; i++)
    {
      /* if no flags are set in this byte, then skip over it */
      if((flags[i] & 0x7f) == 0)
	{
	  continue;
	}

      /* try each bit in this byte */
      for(j=0; j<7; j++)
	{
	  /* if this flag is unset, then skip the rest of the loop */
	  if((flags[i] & (0x1 << j)) == 0)
	    {
	      continue;
	    }

	  /*
	   * if the id is greater than we have handlers for, then we've
	   * got to the end of what we can parse.
	   */
	  if((id = (i*7)+j) >= handler_cnt)
	    {
	      goto done;
	    }

	  handler = &handlers[id]; assert(handler->read != NULL);
	  if(handler->read(buf, off, len, handler->data, handler->param) == -1)
	    {
	      goto err;
	    }
	}
    }

 done:
  *off = final_off;
  return 0;

 err:
  return -1;  
}

static void warts_params_write(uint8_t *buf, uint32_t *off,
			       const uint32_t len,
			       const uint8_t *flags,
			       const uint16_t flags_len,
			       const uint16_t params_len,
			       const warts_param_writer_t *handlers,
			       const int handler_cnt)
{
  int i, j, id;
  uint16_t tmp;

  /* write the flag bytes out */
  tmp = flags_len;
  insert_bytes_uint16(buf, off, len, flags, &tmp);

  /*
   * if there are flags specified, then write the parameter length out.
   * otherwise, there are no parameters to write, so we are done.
   */
  if(flags[0] != 0)
    {
      insert_uint16(buf, off, len, &params_len, NULL);
    }
  else
    {
      assert(params_len == 0);
      return;
    }

  /* handle writing the parameter for each flight out */
  for(i=0; i<flags_len; i++)
    {
      /* skip flag bytes where no flags are set */
      if((flags[i] & 0x7f) == 0)
	{
	  continue;
	}

      /* try each flag bit in the byte */
      for(j=0; j<7; j++)
	{
	  /* skip over unset flags */
	  if((flags[i] & (0x1 << j)) == 0)
	    {
	      continue;
	    }

	  /* this is the parameter id for the flag */
	  id = (i*7)+j;

	  /*
	   * if the id is greater than we have handlers for, then either there
	   * is some code missing, or there is a bug.
	   */
	  assert(id < handler_cnt);
	  assert(handlers[id].write != NULL);

	  /* actually write the data out */
	  handlers[id].write(buf,off,len,handlers[id].data,handlers[id].param);
	}
    }

  return;
}

/*
 * warts_read
 *
 * this function reads the requested number of bytes into a new piece of
 * memory returned in *buf.  as the underlying file descriptor may be
 * set O_NONBLOCK, most of this code is spent dealing with partial reads.
 */
static int warts_read(scamper_file_t *sf, uint8_t **buf, size_t len)
{
  warts_state_t *state = scamper_file_getstate(sf);
  int            fd    = scamper_file_getfd(sf);
  uint8_t       *tmp   = NULL;
  int            ret;
  size_t         rc;

  /* if there is data left over from a prior read, then append to it. */
  if(state->readbuf != NULL)
    {
      assert(state->readbuf_len == len);

      /* read */
      if((ret = read_wrap(fd, state->readbuf + state->readlen, &rc,
			  len - state->readlen)) != 0)
	{
	  /* rc will be zero if nothing was read, so safe to use */
	  state->readlen += rc;

	  /*
	   * we got an error (or EOF) without successfully reading whatever
	   * was left over.
	   */
	  if((ret == -1 && errno != EAGAIN) || ret == -2)
	    {
	      if(ret == -2)
		scamper_file_seteof(sf);
	      return -1;
	    }

	  /*
	   * read has not completed yet, but we haven't got a failure
	   * condition either.
	   */
	  *buf = NULL;
	  return 0;
	}

      *buf = state->readbuf;
      state->readlen = 0;
      state->readbuf = NULL;
      state->readbuf_len = 0;
      state->off += len;

      return 0;
    }

  /* no data left over, reading from scratch */
  if((tmp = malloc(len)) == NULL)
    {
      return -1;
    }

  /* try and read.  if we read the whole amount, everything is good */
  if((ret = read_wrap(fd, tmp, &rc, len)) == 0)
    {
      *buf = tmp;
      state->off += len;
      return 0;
    }

  /* if a partial read occured, then record the partial read in state */
  if(rc != 0)
    {
      state->readlen = rc;
      state->readbuf = tmp;
      state->readbuf_len = len;
    }
  else
    {
      free(tmp);
    }

  /* if we got eof and we had a partial read, then we've got a problem */
  if(ret == -2)
    {
      /* got eof */
      scamper_file_seteof(sf);

      /* partial read, so error condition */
      if(rc != 0)
	{
	  return -1;
	}

      return 0;
    }

  /* if the read would block, then there's no problem */
  if(ret == -1 && errno == EAGAIN)
    {
      return 0;
    }

  return -1;
}

/*
 * warts_hdr_write
 *
 */
static int warts_hdr_write(const scamper_file_t *sf,
			   const uint16_t type, const uint32_t len)
{
  const uint16_t hdr_magic = WARTS_MAGIC;
  const uint16_t hdr_len = WARTS_HDRLEN;
  scamper_file_writefunc_t wf = scamper_file_getwritefunc(sf);
  warts_state_t *state = scamper_file_getstate(sf);
  int      fd = scamper_file_getfd(sf);
  void    *param;
  uint32_t off = 0;
  off_t    pos = 0;
  uint8_t  buf[WARTS_HDRLEN];
  size_t   wc;

  insert_uint16(buf, &off, hdr_len, &hdr_magic, NULL);
  insert_uint16(buf, &off, hdr_len, &type, NULL);
  insert_uint32(buf, &off, hdr_len, &len, NULL);

  assert(off == hdr_len);

  if(state->ispipe == 0 && (pos = lseek(fd, 0, SEEK_CUR)) == (off_t)-1)
    {
      if(errno != ESPIPE)
	{
	  return -1;
	}
      state->ispipe = 1;
    }

  if(wf == NULL)
    {
      if(write_wrap(fd, buf, &wc, hdr_len) != 0)
	{
	  /* truncate if a partial header was written */
	  if(wc != 0 && state->ispipe == 0)
	    {
	      ftruncate(fd, pos);
	    }
	  return -1;
	}
    }
  else
    {
      param = scamper_file_getwriteparam(sf);
      return wf(param, buf, hdr_len);
    }

  return 0;
}

/*
 * warts_write
 *
 * this function will write a record to disk, appending a warts_header
 * on the way out to the disk.  if the write fails for whatever reason
 * (as in the disk is full and only a partial recrd can be written), then
 * the write will be retracted in its entirety.
 */
static int warts_write(const scamper_file_t *sf, const uint8_t type,
		       const void *buf, const size_t len)
{
  scamper_file_writefunc_t wf = scamper_file_getwritefunc(sf);
  warts_state_t *state = scamper_file_getstate(sf);
  void *param;
  off_t off = 0;
  int fd = scamper_file_getfd(sf);

  if(state->ispipe == 0 && (off = lseek(fd, 0, SEEK_CUR)) == (off_t)-1)
    {
      if(errno != ESPIPE)
	{
	  return -1;
	}
      state->ispipe = 1;
    }

  if(warts_hdr_write(sf, type, len) == -1)
    {
      return -1;
    }

  if(wf == NULL)
    {
      if(write_wrap(fd, buf, NULL, len) != 0)
	{
	  /*
	   * if we could not write the buf out, then truncate the warts file
	   * at the hdr we just wrote out above.
	   */
	  if(state->ispipe == 0)
	    {
	      ftruncate(fd, off);
	    }
	  return -1;
	}
    }
  else
    {
      param = scamper_file_getwriteparam(sf);
      return wf(param, buf, len);
    }

  return 0;
}

/*
 * warts_hdr_read
 *
 */
static int warts_hdr_read(scamper_file_t *sf, warts_hdr_t *hdr)
{
  const uint32_t len = 8;
  uint8_t  *buf = NULL;
  uint32_t  off = 0;

  if(warts_read(sf, &buf, len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      return 0;
    }

  /* these three statements are guaranteed not to fail... */
  extract_uint16(buf, &off, len, &hdr->magic, NULL);
  extract_uint16(buf, &off, len, &hdr->type, NULL);
  extract_uint32(buf, &off, len, &hdr->len, NULL);
  free(buf);

  assert(off == len);
  return 1;

 err:
  return -1;
}

/*
 * warts_addr_read
 *
 * read an address structure out of the file and record it in the splay
 * tree of addresses.
 *
 * each address record consists of
 *   - an id assigned to the address, modulo 255
 *   - the address family the address belongs to
 *   - the address [length determined by record length]
 */
static int warts_addr_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			   scamper_addr_t **addr_out)
{
  warts_state_t  *state = scamper_file_getstate(sf);
  scamper_addr_t *addr = NULL, **table;
  uint8_t        *buf = NULL;
  size_t          size;

  /* the data has to be at least 3 bytes long to be valid */
  assert(hdr->len > 2);

  if((state->addr_count % WARTS_ADDR_TABLEGROW) == 0)
    {
      size = sizeof(scamper_addr_t *)*(state->addr_count+WARTS_ADDR_TABLEGROW);
      if((table = realloc(state->addr_table, size)) == NULL)
	{
	  goto err;
	}
      state->addr_table = table;
    }

  /* read the address record from the file */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      if(addr_out != NULL)
	{
	  *addr_out = NULL;
	}
      return 0;
    }

  /*
   * sanity check that the warts id recorded in the file matches what we
   * think it should be.
   */
  if(state->addr_count % 255 != buf[0])
    {
      goto err;
    }

  /* allocate a scamper address using the record read from disk */
  if((addr = scamper_addr_alloc(buf[1], buf+2)) == NULL)
    {
      goto err;
    }

  state->addr_table[state->addr_count++] = addr;
  free(buf);

  if(addr_out != NULL)
    {
      *addr_out = addr;
    }

  return 0;

 err:
  if(addr != NULL) scamper_addr_free(addr);
  if(buf != NULL) free(buf);
  return -1;
}

static int warts_list_cmp(const void *va, const void *vb)
{
  const warts_list_t *wa = (const warts_list_t *)va;
  const warts_list_t *wb = (const warts_list_t *)vb;
  return scamper_list_cmp(wa->list, wb->list);
}

static warts_list_t *warts_list_alloc(scamper_list_t *list, uint32_t id)
{
  warts_list_t *wl;
  if((wl = malloc_zero(sizeof(warts_list_t))) != NULL)
    {
      wl->list = scamper_list_use(list);
      wl->id = id;
    }
  return wl;
}

static void warts_list_free(warts_list_t *wl)
{
  if(wl->list != NULL) scamper_list_free(wl->list);
  free(wl);
  return;
}

/*
 * warts_list_params
 *
 * put together an outline of the optional bits for a list structure,
 * including the flags structure that sits at the front, and the size (in
 * bytes) of the various parameters that will be optionally included in the
 * file.
 */
static void warts_list_params(const scamper_list_t *list, uint8_t *flags,
			      uint16_t *flags_len, uint16_t *params_len)
{
  int max_id = 0;

  /* unset all the flags */
  memset(flags, 0, list_vars_mfb);
  *params_len = 0;

  if(list->descr != NULL)
    {
      flag_set(flags, WARTS_LIST_DESCR,   &max_id);
      *params_len += strlen(list->descr) + 1;
    }

  if(list->monitor != NULL)
    {
      flag_set(flags, WARTS_LIST_MONITOR, &max_id);
      *params_len += strlen(list->monitor) + 1;
    }

  *flags_len = fold_flags(flags, max_id);

  return;
}

/*
 * warts_list_params_read
 *
 */
static int warts_list_params_read(scamper_list_t *list,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&list->descr,   (wpr_t)extract_string, NULL}, /* WARTS_LIST_DESCR   */
    {&list->monitor, (wpr_t)extract_string, NULL}, /* WARTS_LIST_MONITOR */
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_list_params_write(const scamper_list_t *list,
				    uint8_t *buf, uint32_t *off,
				    const uint32_t len,
				    const uint8_t *flags,
				    const uint16_t flags_len,
				    const uint16_t params_len)
{
  warts_param_writer_t handlers[] = {
    {list->descr,   (wpw_t)insert_string, NULL}, /* WARTS_LIST_DESCR */
    {list->monitor, (wpw_t)insert_string, NULL}, /* WARTS_LIST_MONITOR */
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return;
}

/*
 * warts_list_read
 *
 * each list record consists of
 *   - a 4 byte id assigned to the list by warts
 *   - a 4 byte list id assigned by a human
 *   - the name of the list
 *   - optional parameters (e.g. list description, monitor)
 */
static int warts_list_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			   scamper_list_t **list_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_list_t *list = NULL;
  warts_list_t *wl = NULL, **table;
  uint8_t  *buf = NULL;
  size_t    size;
  uint32_t  i = 0;
  uint32_t  id;

  /*
   * must at least include the warts list id, the human-assigned list-id,
   * a name, and some amount of flags + parameters
   */
  if(hdr->len < 4 + 4 + 2 + 1)
    {
      goto err;
    }

  if((state->list_count % WARTS_LIST_TABLEGROW) == 0)
    {
      size = sizeof(warts_list_t *)*(state->list_count + WARTS_LIST_TABLEGROW);
      if((table = realloc(state->list_table, size)) == NULL)
	{
	  goto err;
	}
      state->list_table = table;
    }

  /* read the list record from the file */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      if(list_out != NULL)
	{
	  *list_out = NULL;
	}
      return 0;
    }

  /* preallocate an empty list structure */
  if((list = malloc_zero(sizeof(scamper_list_t))) == NULL)
    {
      goto err;
    }
  list->refcnt = 1;

  /*
   * sanity check that the warts id recorded in the file matches what we
   * think it should be.
   */
  if(extract_uint32(buf, &i, hdr->len, &id, NULL) != 0 ||
     id != state->list_count)
    {
      goto err;
    }

  /* get the list id (assigned by a human) and name */
  if(extract_uint32(buf, &i, hdr->len, &list->id, NULL) != 0 ||
     extract_string(buf, &i, hdr->len, &list->name, NULL) != 0)
    {
      goto err;
    }

  if(warts_list_params_read(list, buf, &i, hdr->len) != 0)
    {
      goto err;
    }

  if((wl = warts_list_alloc(list, state->list_count)) == NULL)
    {
      goto err;
    }

  state->list_table[state->list_count++] = wl;
  scamper_list_free(list);
  free(buf);

  if(list_out != NULL)
    {
      *list_out = list;
    }
  return 0;

 err:
  if(list != NULL) scamper_list_free(list);
  if(wl != NULL)   warts_list_free(wl);
  if(buf != NULL)  free(buf);
  return -1;
}

/*
 * warts_list_write
 *
 * take a list structure and write it to disk.  update the state held, too
 */
static int warts_list_write(const scamper_file_t *sf, scamper_list_t *list,
			    uint32_t *id)
{
  warts_state_t *state = scamper_file_getstate(sf);
  warts_list_t *wl = NULL;
  uint8_t  *buf = NULL;
  uint8_t   flags[list_vars_mfb];
  uint32_t  off = 0, len;
  uint16_t  name_len, flags_len, params_len;

  /* we require a list name */
  if(list->name == NULL)
    {
      goto err;
    }

  /* allocate a warts wrapping structure for the list */
  if((wl = warts_list_alloc(list, state->list_count)) == NULL)
    {
      goto err;
    }

  /* figure out how large the record will be */
  name_len = strlen(list->name) + 1;
  warts_list_params(list, flags, &flags_len, &params_len);
  len = 4 + 4 + name_len + flags_len + params_len;
  if(params_len != 0) len += 2;

  /* allocate the record */
  if((buf = malloc(len)) == NULL)
    {
      goto err;
    }

  /* list id assigned by warts */
  insert_uint32(buf, &off, len, &wl->id, NULL);

  /* list id assigned by a person */
  insert_uint32(buf, &off, len, &list->id, NULL);

  /* list name */
  insert_bytes_uint16(buf, &off, len, list->name, &name_len);

  /* copy in the flags for any parameters */
  warts_list_params_write(list, buf, &off, len, flags, flags_len, params_len);

  assert(off == len);

  if(splaytree_insert(state->list_tree, wl) == NULL)
    {
      goto err;
    }

  /* write the list record to disk */
  if(warts_write(sf, SCAMPER_FILE_OBJ_LIST, buf, len) == -1)
    {
      goto err;
    }

  state->list_count++;
  *id = wl->id;
  free(buf);
  return 0;

 err:
  if(wl != NULL)
    {
      splaytree_remove_item(state->list_tree, wl);
      warts_list_free(wl);
    }
  if(buf != NULL) free(buf);
  return -1;
}

/*
 * warts_list_getid
 *
 * given a scamper_list structure, return the id to use internally to
 * uniquely identify it.  allocate the id if necessary.
 */
static int warts_list_getid(const scamper_file_t *sf, scamper_list_t *list,
			    uint32_t *id)
{
  warts_state_t *state = scamper_file_getstate(sf);
  warts_list_t findme, *wl;

  if(list == NULL)
    {
      *id = 0;
      return 0;
    }

  /* see if there is a tree entry for this list */
  findme.list = list;
  if((wl = splaytree_find(state->list_tree, &findme)) != NULL)
    {
      *id = wl->id;
      return 0;
    }

  /* no tree entry, so write it to a file and return the assigned id */
  if(warts_list_write(sf, list, id) == 0)
    {
      return 0;
    }

  return -1;
}

static int warts_cycle_cmp(const void *va, const void *vb)
{
  const warts_cycle_t *a = (const warts_cycle_t *)va;
  const warts_cycle_t *b = (const warts_cycle_t *)vb;
  return scamper_cycle_cmp(a->cycle, b->cycle);
}

static warts_cycle_t *warts_cycle_alloc(scamper_cycle_t *cycle, uint32_t id)
{
  warts_cycle_t *wc;
  if((wc = malloc_zero(sizeof(warts_cycle_t))) != NULL)
    {
      wc->cycle = scamper_cycle_use(cycle);
      wc->id = id;
    }
  return wc;
}

static void warts_cycle_free(warts_cycle_t *cycle)
{
  if(cycle->cycle != NULL) scamper_cycle_free(cycle->cycle);
  free(cycle);
  return;
}

static void warts_cycle_params(const scamper_cycle_t *cycle, uint8_t *flags,
			       uint16_t *flags_len, uint16_t *params_len)
{
  int max_id;

  /* unset all the flags, reset max_id */
  memset(flags, 0, cycle_vars_mfb);
  max_id = 0;

  *params_len = 0;

  if(cycle->hostname != NULL)
    {
      flag_set(flags, WARTS_CYCLE_HOSTNAME, &max_id);
      *params_len += strlen(cycle->hostname) + 1;
    }

  if(cycle->stop_time != 0)
    {
      flag_set(flags, WARTS_CYCLE_STOP_TIME, &max_id);
      *params_len += 4;
    }

  /* figure out how many bytes the flags will require */
  *flags_len = fold_flags(flags, max_id);

  return;
}

static void warts_cycle_params_write(const scamper_cycle_t *cycle,
				     uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     const uint8_t *flags,
				     const uint16_t flags_len,
				     const uint16_t params_len)
{
  warts_param_writer_t handlers[] = {
    {&cycle->stop_time, (wpw_t)insert_uint32, NULL},
    {cycle->hostname,   (wpw_t)insert_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return;
}

static int warts_cycle_params_read(scamper_cycle_t *cycle,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&cycle->stop_time, (wpr_t)extract_uint32, NULL},
    {&cycle->hostname,  (wpr_t)extract_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

/*
 * warts_cycle_read
 *
 * 4 byte cycle id (assigned by warts from counter)
 * 4 byte list id (assigned by warts)
 * 4 byte cycle id (assigned by human)
 * 4 byte time since the epoch, representing start time of the cycle
 * 1 byte flags (followed by optional data items)
 */
static int warts_cycle_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			    scamper_cycle_t **cycle_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_cycle_t *cycle = NULL;
  warts_cycle_t *wc = NULL, **table;
  size_t   size;
  uint8_t *buf = NULL;
  uint32_t id;
  uint32_t off = 0;

  /* ensure the cycle_start object is large enough to be valid */
  if(hdr->len < 4 + 4 + 4 + 4 + 1)
    {
      goto err;
    }

  if((state->cycle_count % WARTS_CYCLE_TABLEGROW) == 0)
    {
      size = sizeof(warts_list_t *)*(state->cycle_count+WARTS_CYCLE_TABLEGROW);
      if((table = realloc(state->cycle_table, size)) == NULL)
	{
	  goto err;
	}
      state->cycle_table = table;
    }

  /* read the cycle_start structure out of the file */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      if(cycle_out != NULL)
	{
	  *cycle_out = NULL;
	}
      return 0;
    }

  /*
   * sanity check that the warts id recorded in the file matches what we
   * think it should be.
   */
  if(extract_uint32(buf, &off, hdr->len, &id, NULL) != 0 ||
     id != state->cycle_count)
    {
      goto err;
    }

  /* the _warts_ list id for the cycle */
  if(extract_uint32(buf, &off, hdr->len, &id, NULL) != 0 ||
     id >= state->list_count)
    {
      goto err;
    }

  if((cycle = scamper_cycle_alloc(state->list_table[id]->list)) == NULL)
    {
      goto err;
    }

  /*
   * the second 4 bytes is the actual cycle id assigned by a human.
   * the third 4 bytes is seconds since the epoch.
   */
  if(extract_uint32(buf, &off, hdr->len, &cycle->id, NULL) != 0 ||
     extract_uint32(buf, &off, hdr->len, &cycle->start_time, NULL) != 0)
    {
      goto err;
    }

  if(warts_cycle_params_read(cycle, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  if((wc = warts_cycle_alloc(cycle, state->cycle_count)) == NULL)
    {
      goto err;
    }

  state->cycle_table[state->cycle_count++] = wc;
  scamper_cycle_free(cycle);
  free(buf);

  if(cycle_out != NULL)
    {
      *cycle_out = cycle;
    }

  return 0;

 err:
  if(cycle != NULL)
    {
      if(cycle->list != NULL) scamper_list_free(cycle->list);
      free(cycle);
    }
  if(buf != NULL) free(buf);
  return -1;
}

/*
 * warts_cycle_write
 *
 * write out a cycle record.  depending on whether the type is a start point,
 * or a cycle definition, some
 *
 * 4 byte cycle id (assigned by warts from counter)
 * 4 byte list id (assigned by warts)
 * 4 byte cycle id (assigned by human)
 * 4 byte time since the epoch, representing start time of the cycle
 * 1 byte flags (followed by optional data items)
 */
static int warts_cycle_write(const scamper_file_t *sf, scamper_cycle_t *cycle,
			     const int type, uint32_t *id)
{
  warts_state_t *state = scamper_file_getstate(sf);
  warts_cycle_t *wc = NULL;
  uint32_t warts_list_id;
  uint8_t *buf = NULL;
  uint8_t  flags[cycle_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t off = 0, len;

  /* find the list associated w/ the cycle, as we require the warts list id */
  if(warts_list_getid(sf, cycle->list, &warts_list_id) == -1)
    {
      goto err;
    }

  /* allocate warts_cycle wrapping struct to associate a warts-assigned id */
  if((wc = warts_cycle_alloc(cycle, state->cycle_count)) == NULL)
    {
      goto err;
    }

  /* figure out the shape the optional parameters will take */
  warts_cycle_params(cycle, flags, &flags_len, &params_len);

  /* allocate a temporary buf for recording the cycle */
  len = 4 + 4 + 4 + 4 + flags_len + params_len;
  if(params_len != 0) len += 2;
  if((buf = malloc(len)) == NULL)
    {
      goto err;
    }

  /* cycle and list ids, assigned by warts from counters */
  insert_uint32(buf, &off, len, &wc->id, NULL);
  insert_uint32(buf, &off, len, &warts_list_id, NULL);

  /* human cycle id, timestamp */
  insert_uint32(buf, &off, len, &cycle->id, NULL);
  insert_uint32(buf, &off, len, &cycle->start_time, NULL);

  /* copy in the optionally-included parameters */
  warts_cycle_params_write(cycle, buf,&off,len, flags, flags_len, params_len);

  assert(off == len);

  if(splaytree_insert(state->cycle_tree, wc) == NULL)
    {
      goto err;
    }

  if(warts_write(sf, type, buf, len) == -1)
    {
      goto err;
    }

  if(id != NULL) *id = wc->id;
  state->cycle_count++;
  free(buf);

  return 0;

 err:
  if(wc != NULL)
    {
      splaytree_remove_item(state->cycle_tree, wc);
      warts_cycle_free(wc);
    }
  if(buf != NULL) free(buf);
  return -1;
}

/*
 * warts_cycle_stop_read
 *
 * a cycle_stop record consists of the cycle id (assigned by warts from a
 * counter), a timestamp, and some optional parameters.
 */
static int warts_cycle_stop_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_cycle_t **cycle_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_cycle_t *cycle;
  uint32_t  off = 0;
  uint32_t  id;
  uint8_t  *buf = NULL;

  if(hdr->len < 4 + 4 + 1)
    {
      goto err;
    }

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      if(cycle_out != NULL)
	{
	  *cycle_out = NULL;
	}
      return 0;
    }

  /*
   * get an index into the stored cycles.
   *
   * if the id does not make sense (is larger than any cycle currently
   * defined, or is the null cycle entry, or there is no current cycle
   * for this id) then we have a problem...
   */
  if(extract_uint32(buf, &off, hdr->len, &id, NULL) != 0 || 
     id >= state->cycle_count || id == 0 || state->cycle_table[id] == NULL)
    {
      goto err;
    }

  /* embed the stop timestamp with the cycle object */
  cycle = state->cycle_table[id]->cycle;
  if(extract_uint32(buf, &off, hdr->len, &cycle->stop_time, NULL) != 0)
    {
      goto err;
    }

  /*
   * if the caller wants the cycle record, then get a reference to it.
   * don't need the cycle in the array any longer, though.
   */
  if(cycle_out != NULL)
    {
      *cycle_out = scamper_cycle_use(cycle);
    }
  warts_cycle_free(state->cycle_table[id]);
  state->cycle_table[id] = NULL;

  free(buf);

  return 0;

 err:
  if(buf != NULL) free(buf);
  return -1;
}

static int warts_cycle_getid(const scamper_file_t *sf, scamper_cycle_t *cycle,
			     uint32_t *id)
{
  warts_state_t *state = scamper_file_getstate(sf);
  warts_cycle_t findme, *wc;

  /* if no cycle is specified, we use the special value zero */
  if(cycle == NULL)
    {
      *id = 0;
      return 0;
    }

  /* see if there is an entry for this cycle */
  findme.cycle = cycle;
  if((wc = splaytree_find(state->cycle_tree, &findme)) != NULL)
    {
      *id = wc->id;
      return 0;
    }

  if(warts_cycle_write(sf, cycle, SCAMPER_FILE_OBJ_CYCLE_DEF, id) == 0)
    {
      return 0;
    }

  return -1;
}

/*
 * warts_cycle_stop_write
 *
 * this function writes a record denoting the end of the cycle pointed to
 * by the cycle parameter.
 * it writes
 *  the 4 byte cycle id assigned by warts
 *  the 4 byte stop time
 *  where applicable, additional parameters
 */
static int warts_cycle_stop_write(const scamper_file_t *sf,
				  scamper_cycle_t *cycle)
{
  uint32_t wc_id;
  uint8_t *buf = NULL;
  uint32_t off = 0, len;
  uint8_t  flag = 0;

  assert(cycle != NULL);

  if(warts_cycle_getid(sf, cycle, &wc_id) != 0)
    {
      goto err;
    }

  len = 4 + 4 + 1;
  if((buf = malloc(len)) == NULL)
    {
      goto err;
    }

  insert_uint32(buf, &off, len, &wc_id, NULL);
  insert_uint32(buf, &off, len, &cycle->stop_time, NULL);
  insert_byte(buf, &off, len, &flag, NULL);

  assert(off == len);

  if(warts_write(sf, SCAMPER_FILE_OBJ_CYCLE_STOP, buf, len) == -1)
    {
      goto err;
    }

  free(buf);
  return 0;

 err:
  if(buf != NULL) free(buf);
  return -1;
}

static int warts_icmpext_read(const uint8_t *buf, uint32_t *off, uint32_t len,
			      scamper_icmpext_t **exts)
{
  scamper_icmpext_t *ie, *next = NULL;
  uint16_t tmp;
  uint16_t u16;
  uint8_t cn, ct;

  /* make sure there's enough left for the length field */
  if(len - *off < 2)
    {
      return -1;
    }

  /* extract the length field that says how much data is left past it */
  memcpy(&tmp, &buf[*off], 2);
  tmp = ntohs(tmp);

  *off += 2;

  assert(tmp > 0);

  /* make sure there's enough left for the extension data */
  if(len - *off < tmp)
    {
      return -1;
    }

  while(tmp >= 4)
    {
      memcpy(&u16, &buf[*off], 2); u16 = ntohs(u16);
      if(len - *off < (uint32_t)(u16 + 2 + 1 + 1))
	{
	  return -1;
	}
      cn = buf[*off+2];
      ct = buf[*off+3];
      
      if((ie = scamper_icmpext_alloc(cn, ct, u16, &buf[*off+4])) == NULL)
	{
	  return -1;
	}

      if(next == NULL)
	{
	  *exts = ie;
	}
      else
	{
	  next->ie_next = ie;
	}
      next = ie;

      *off += (2 + 1 + 1 + u16);
      tmp  -= (2 + 1 + 1 + u16);
    }

  assert(tmp == 0);
  return 0;
}

static void warts_icmpext_write(uint8_t *buf,uint32_t *off,const uint32_t len,
				const scamper_icmpext_t *exts)
{
  const scamper_icmpext_t *ie;
  uint16_t tmp = 0;
  uint16_t u16;

  for(ie=exts; ie != NULL; ie = ie->ie_next)
    {
      assert(*off + tmp + 1 + 1 + 2 + ie->ie_dl <= len);

      /* convert the data length field to network byte order and write */
      u16 = htons(ie->ie_dl);
      memcpy(&buf[*off + 2 + tmp], &u16, 2); tmp += 2;

      /* write the class num/type fields */
      buf[*off + 2 + tmp] = ie->ie_cn; tmp++;
      buf[*off + 2 + tmp] = ie->ie_ct; tmp++;

      /* write any data */
      if(ie->ie_dl != 0)
	{
	  memcpy(&buf[*off + 2 + tmp], ie->ie_data, ie->ie_dl);
	  tmp += ie->ie_dl;
	}
    }

  /* write, at the start of the data, the length of the icmp extension data */
  u16 = htons(tmp);
  memcpy(&buf[*off], &u16, 2);
  *off = *off + 2 + tmp;

  return;
}

static void warts_trace_params(const scamper_trace_t *trace,
			       warts_addrtable_t *table, uint8_t *flags,
			       uint16_t *flags_len, uint16_t *params_len)
{
  int i, max_id = 0;
  const warts_var_t *var;

  /* unset all the flags possible */
  memset(flags, 0, trace_vars_mfb);
  *params_len = 0;

  /* for now, we include the base data items */
  for(i=0; i<sizeof(trace_vars)/sizeof(warts_var_t); i++)
    {
      var = &trace_vars[i];

      if(var->id == WARTS_TRACE_ADDR_SRC_GID ||
	 var->id == WARTS_TRACE_ADDR_DST_GID)
	{
	  continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_TRACE_ADDR_SRC)
	{
	  *params_len += warts_addr_size(table, trace->src);
	  continue;
	}
      else if(var->id == WARTS_TRACE_ADDR_DST)
	{
	  *params_len += warts_addr_size(table, trace->dst);
	  continue;
	}

      assert(var->size >= 0);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_trace_params_read(scamper_trace_t *trace,warts_state_t *state,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&trace->list,        (wpr_t)extract_list,     state},
    {&trace->cycle,       (wpr_t)extract_cycle,    state},
    {&trace->src,         (wpr_t)extract_addr_gid, state},
    {&trace->dst,         (wpr_t)extract_addr_gid, state},
    {&trace->start,       (wpr_t)extract_timeval,  NULL},
    {&trace->stop_reason, (wpr_t)extract_byte,     NULL},
    {&trace->stop_data,   (wpr_t)extract_byte,     NULL},
    {&trace->flags,       (wpr_t)extract_byte,     NULL},
    {&trace->attempts,    (wpr_t)extract_byte,     NULL},
    {&trace->hoplimit,    (wpr_t)extract_byte,     NULL},
    {&trace->type,        (wpr_t)extract_byte,     NULL},
    {&trace->probe_size,  (wpr_t)extract_uint16,   NULL},
    {&trace->sport,       (wpr_t)extract_uint16,   NULL},
    {&trace->dport,       (wpr_t)extract_uint16,   NULL},
    {&trace->firsthop,    (wpr_t)extract_byte,     NULL},
    {&trace->tos,         (wpr_t)extract_byte,     NULL},
    {&trace->wait,        (wpr_t)extract_byte,     NULL},
    {&trace->loops,       (wpr_t)extract_byte,     NULL},
    {&trace->hop_count,   (wpr_t)extract_uint16,   NULL},
    {&trace->gaplimit,    (wpr_t)extract_byte,     NULL},
    {&trace->gapaction,   (wpr_t)extract_byte,     NULL},
    {&trace->loopaction,  (wpr_t)extract_byte,     NULL},
    {&trace->probec,      (wpr_t)extract_uint16,   NULL},
    {&trace->wait_probe,  (wpr_t)extract_byte,     NULL},
    {&trace->confidence,  (wpr_t)extract_byte,     NULL},
    {&trace->src,         (wpr_t)extract_addr,     table},
    {&trace->dst,         (wpr_t)extract_addr,     table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static int warts_trace_params_write(const scamper_trace_t *trace,
				    const scamper_file_t *sf,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off,
				    const uint32_t len,
				    const uint8_t *flags,
				    const uint16_t flags_len,
				    const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  warts_param_writer_t handlers[] = {
    {&list_id,            (wpw_t)insert_uint32,  NULL},
    {&cycle_id,           (wpw_t)insert_uint32,  NULL},
    {NULL,                NULL,                  NULL},
    {NULL,                NULL,                  NULL},
    {&trace->start,       (wpw_t)insert_timeval, NULL},
    {&trace->stop_reason, (wpw_t)insert_byte,    NULL},
    {&trace->stop_data,   (wpw_t)insert_byte,    NULL},
    {&trace->flags,       (wpw_t)insert_byte,    NULL},
    {&trace->attempts,    (wpw_t)insert_byte,    NULL},
    {&trace->hoplimit,    (wpw_t)insert_byte,    NULL},
    {&trace->type,        (wpw_t)insert_byte,    NULL},
    {&trace->probe_size,  (wpw_t)insert_uint16,  NULL},
    {&trace->sport,       (wpw_t)insert_uint16,  NULL},
    {&trace->dport,       (wpw_t)insert_uint16,  NULL},
    {&trace->firsthop,    (wpw_t)insert_byte,    NULL},
    {&trace->tos,         (wpw_t)insert_byte,    NULL},
    {&trace->wait,        (wpw_t)insert_byte,    NULL},
    {&trace->loops,       (wpw_t)insert_byte,    NULL},
    {&trace->hop_count,   (wpw_t)insert_uint16,  NULL},
    {&trace->gaplimit,    (wpw_t)insert_byte,    NULL},
    {&trace->gapaction,   (wpw_t)insert_byte,    NULL},
    {&trace->loopaction,  (wpw_t)insert_byte,    NULL},
    {&trace->probec,      (wpw_t)insert_uint16,  NULL},
    {&trace->wait_probe,  (wpw_t)insert_byte,    NULL},
    {&trace->confidence,  (wpw_t)insert_byte,    NULL},
    {trace->src,          (wpw_t)insert_addr,    table},
    {trace->dst,          (wpw_t)insert_addr,    table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  trace->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, trace->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

static int warts_trace_hop_read_icmp_tc(const uint8_t *buf, uint32_t *off,
					uint32_t len, scamper_trace_hop_t *hop,
					void *param)
{
  if(len - *off < 2)
    {
      return -1;
    }
  hop->hop_icmp_type = buf[(*off)++];
  hop->hop_icmp_code = buf[(*off)++];
  return 0;
}

static void warts_trace_hop_write_icmp_tc(uint8_t *buf, uint32_t *off,
					  const uint32_t len,
					  const scamper_trace_hop_t *hop,
					  void *param)
{
  assert(len - *off >= 2);
  buf[(*off)++] = hop->hop_icmp_type;
  buf[(*off)++] = hop->hop_icmp_code;
  return;
}

static int warts_trace_hop_read_probe_id(const uint8_t *buf, uint32_t *off,
					 uint32_t len, uint8_t *out,
					 void *param)
{
  if(len - *off < 1)
    {
      return -1;
    }
  *out = buf[(*off)++] + 1;
  return 0;
}

static void warts_trace_hop_write_probe_id(uint8_t *buf, uint32_t *off,
					   const uint32_t len,
					   const uint8_t *in, void *param)
{
  assert(len - *off >= 1);
  buf[(*off)++] = *in - 1;
  return;
}

static int warts_trace_hop_read_icmpext(const uint8_t *buf, uint32_t *off,
					uint32_t len, scamper_trace_hop_t *hop,
					void *param)
{
  return warts_icmpext_read(buf, off, len, &hop->hop_icmpext);
}

static void warts_trace_hop_write_icmpext(uint8_t *buf, uint32_t *off,
					  const uint32_t len,
					  const scamper_trace_hop_t *hop,
					  void *param)
{
  warts_icmpext_write(buf, off, len, hop->hop_icmpext);
  return;
}

static void warts_trace_hop_params(const scamper_trace_hop_t *hop,
				   warts_addrtable_t *table, uint8_t *flags,
				   uint16_t *flags_len, uint16_t *params_len)
{
  static const int tlv_idx[] = {
    WARTS_TRACE_HOP_REPLY_IPID,  /* SCAMPER_TRACE_HOP_TLV_REPLY_IPID */
    WARTS_TRACE_HOP_REPLY_IPTOS, /* SCAMPER_TRACE_HOP_TLV_REPLY_IPTOS */
    WARTS_TRACE_HOP_NHMTU,       /* SCAMPER_TRACE_HOP_TLV_NHMTU */
    WARTS_TRACE_HOP_INNER_IPLEN, /* SCAMPER_TRACE_HOP_TLV_INNER_IPLEN */
    WARTS_TRACE_HOP_INNER_IPTTL, /* SCAMPER_TRACE_HOP_TLV_INNER_IPTTL */
    WARTS_TRACE_HOP_INNER_IPTOS, /* SCAMPER_TRACE_HOP_TLV_INNER_IPTOS */
  };
  scamper_icmpext_t *ie;
  scamper_tlv_t *tlv;
  int max_id = 0;

  /* unset all the flags possible */
  memset(flags, 0, hop_vars_mfb);
  *params_len = 0;

  flag_set(flags, WARTS_TRACE_HOP_PROBE_TTL,  &max_id); *params_len += 1;
  flag_set(flags, WARTS_TRACE_HOP_REPLY_TTL,  &max_id); *params_len += 1;
  flag_set(flags, WARTS_TRACE_HOP_FLAGS,      &max_id); *params_len += 1;
  flag_set(flags, WARTS_TRACE_HOP_PROBE_ID,   &max_id); *params_len += 1;
  flag_set(flags, WARTS_TRACE_HOP_RTT,        &max_id); *params_len += 4;
  flag_set(flags, WARTS_TRACE_HOP_PROBE_SIZE, &max_id); *params_len += 2;
  flag_set(flags, WARTS_TRACE_HOP_REPLY_SIZE, &max_id); *params_len += 2;

  flag_set(flags, WARTS_TRACE_HOP_ADDR, &max_id);
  *params_len += warts_addr_size(table, hop->hop_addr);

  if((hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) == 0)
    {
      flag_set(flags, WARTS_TRACE_HOP_ICMP_TC,    &max_id); *params_len += 2;
    }
  else
    {
      flag_set(flags, WARTS_TRACE_HOP_TCP_FLAGS,  &max_id); *params_len += 1;
    }

  /* go through the TLVs and decide which flags to set */
  for(tlv = hop->hop_tlvs; tlv != NULL; tlv = tlv->tlv_next)
    {
      assert(tlv->tlv_type-1 < (int)(sizeof(tlv_idx)/sizeof(int)));
      flag_set(flags, tlv_idx[tlv->tlv_type-1], &max_id);
      *params_len += tlv->tlv_len;
    }

  if(hop->hop_icmpext != NULL)
    {
      flag_set(flags, WARTS_TRACE_HOP_ICMPEXT, &max_id);
      *params_len += 2;
      for(ie = hop->hop_icmpext; ie != NULL; ie = ie->ie_next)
	{
	  *params_len += (2 + 1 + 1 + ie->ie_dl);
	}
    }

  *flags_len = fold_flags(flags, max_id);

  return;
}

static int warts_trace_hop_read(scamper_trace_hop_t *hop, warts_state_t *state,
				warts_addrtable_t *table,
				const uint8_t *buf,uint32_t *off,uint32_t len)
{
  uint8_t types[] = {
    SCAMPER_TRACE_HOP_TLV_REPLY_IPID,
    SCAMPER_TRACE_HOP_TLV_REPLY_IPTOS,
    SCAMPER_TRACE_HOP_TLV_NHMTU,
    SCAMPER_TRACE_HOP_TLV_INNER_IPLEN,
    SCAMPER_TRACE_HOP_TLV_INNER_IPTTL,
    SCAMPER_TRACE_HOP_TLV_INNER_IPTOS,
  };

  warts_param_reader_t handlers[] = {
    {&hop->hop_addr,       (wpr_t)extract_addr_gid,              state},
    {&hop->hop_probe_ttl,  (wpr_t)extract_byte,                  NULL},
    {&hop->hop_reply_ttl,  (wpr_t)extract_byte,                  NULL},
    {&hop->hop_flags,      (wpr_t)extract_byte,                  NULL},
    {&hop->hop_probe_id,   (wpr_t)warts_trace_hop_read_probe_id, NULL},
    {&hop->hop_rtt,        (wpr_t)extract_rtt,                   NULL},
    {hop,                  (wpr_t)warts_trace_hop_read_icmp_tc,  NULL},
    {&hop->hop_probe_size, (wpr_t)extract_uint16,                NULL},
    {&hop->hop_reply_size, (wpr_t)extract_uint16,                NULL},
    {&hop->hop_tlvs,       (wpr_t)extract_uint16_tlv,            &types[0]},
    {&hop->hop_tlvs,       (wpr_t)extract_byte_tlv,              &types[1]},
    {&hop->hop_tlvs,       (wpr_t)extract_uint16_tlv,            &types[2]},
    {&hop->hop_tlvs,       (wpr_t)extract_uint16_tlv,            &types[3]},
    {&hop->hop_tlvs,       (wpr_t)extract_byte_tlv,              &types[4]},
    {&hop->hop_tcp_flags,  (wpr_t)extract_byte,                  NULL},
    {&hop->hop_tlvs,       (wpr_t)extract_byte_tlv,              &types[5]},
    {hop,                  (wpr_t)warts_trace_hop_read_icmpext,  NULL},
    {&hop->hop_addr,       (wpr_t)extract_addr,                  table},
  };

  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_trace_hop_write(const warts_trace_hop_t *state,
				  warts_addrtable_t *table,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  scamper_trace_hop_t *hop = state->hop;

  uint8_t types[] = {
    SCAMPER_TRACE_HOP_TLV_REPLY_IPID,
    SCAMPER_TRACE_HOP_TLV_REPLY_IPTOS,
    SCAMPER_TRACE_HOP_TLV_NHMTU,
    SCAMPER_TRACE_HOP_TLV_INNER_IPLEN,
    SCAMPER_TRACE_HOP_TLV_INNER_IPTTL,
    SCAMPER_TRACE_HOP_TLV_INNER_IPTOS,
  };

  warts_param_writer_t handlers[] = {
    {NULL,                 NULL,                                  NULL},
    {&hop->hop_probe_ttl,  (wpw_t)insert_byte,                    NULL},
    {&hop->hop_reply_ttl,  (wpw_t)insert_byte,                    NULL},
    {&hop->hop_flags,      (wpw_t)insert_byte,                    NULL},
    {&hop->hop_probe_id,   (wpw_t)warts_trace_hop_write_probe_id, NULL},
    {&hop->hop_rtt,        (wpw_t)insert_rtt,                     NULL},
    {hop,                  (wpw_t)warts_trace_hop_write_icmp_tc,  NULL},
    {&hop->hop_probe_size, (wpw_t)insert_uint16,                  NULL},
    {&hop->hop_reply_size, (wpw_t)insert_uint16,                  NULL},
    {hop->hop_tlvs,        (wpw_t)insert_uint16_tlv,              &types[0]},
    {hop->hop_tlvs,        (wpw_t)insert_byte_tlv,                &types[1]},
    {hop->hop_tlvs,        (wpw_t)insert_uint16_tlv,              &types[2]},
    {hop->hop_tlvs,        (wpw_t)insert_uint16_tlv,              &types[3]},
    {hop->hop_tlvs,        (wpw_t)insert_byte_tlv,                &types[4]},
    {&hop->hop_tcp_flags,  (wpw_t)insert_byte,                    NULL},
    {hop->hop_tlvs,        (wpw_t)insert_byte_tlv,                &types[5]},
    {hop,                  (wpw_t)warts_trace_hop_write_icmpext,  NULL},
    {hop->hop_addr,        (wpw_t)insert_addr,                    table},
  };

  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_trace_hops_read(scamper_trace_hop_t **hops,
				 warts_state_t *state,
				 warts_addrtable_t *table, const uint8_t *buf,
				 uint32_t *off, uint32_t len, uint16_t count)
{
  scamper_trace_hop_t *head = NULL, *hop = NULL;
  int i;

  for(i=0; i<count; i++)
    {
      /*
       * the hop list is stored in a linked list; add each new hop to the
       * end of the list
       */
      if(hop != NULL)
	{
	  hop->hop_next = scamper_trace_hop_alloc();
	  hop = hop->hop_next;
	}
      else
	{
	  head = hop = scamper_trace_hop_alloc();
	}

      /* could not allocate an empty hop structure ... */
      if(hop == NULL)
	goto err;

      if(warts_trace_hop_read(hop, state, table, buf, off, len) != 0)
	goto err;
    }

  *hops = head;
  return 0;

 err:
  while(head != NULL)
    {
      hop = head;
      head = head->hop_next;
      scamper_trace_hop_free(hop);
    }
  return -1;
}

static void warts_trace_pmtud_params(const scamper_trace_t *trace,
				     uint8_t *flags, uint16_t *flags_len,
				     uint16_t *params_len)
{
  static const int tlv_idx[] = {
    WARTS_TRACE_PMTUD_OUTMTU, /* SCAMPER_TRACE_PMTUD_TLV_OUTMTU */
  };
  scamper_tlv_t *tlv;
  int max_id = 0;

  /* unset all the flags possible */
  memset(flags, 0, pmtud_vars_mfb);
  *params_len = 0;

  /* for now, we include the base data items */
  flag_set(flags, WARTS_TRACE_PMTUD_IFMTU, &max_id); *params_len += 2;
  flag_set(flags, WARTS_TRACE_PMTUD_PMTU, &max_id);  *params_len += 2;

  /* go through the TLVs and decide which flags to set */
  for(tlv = trace->pmtud->tlvs; tlv != NULL; tlv = tlv->tlv_next)
    {
      flag_set(flags, tlv_idx[tlv->tlv_type-1], &max_id);
      *params_len += tlv->tlv_len;
    }

  *flags_len = fold_flags(flags, max_id);

  return;
}

static int warts_trace_pmtud_read(scamper_trace_t *trace, warts_state_t *state,
				  warts_addrtable_t *table, const uint8_t *buf,
				  uint32_t *off, uint32_t len)
{
  uint8_t outmtu = SCAMPER_TRACE_PMTUD_TLV_OUTMTU;
  scamper_tlv_t *tlvs = NULL;
  uint16_t ifmtu;
  uint16_t pmtu;
  warts_param_reader_t handlers[] = {
    {&ifmtu, (wpr_t)extract_uint16,     NULL},
    {&pmtu,  (wpr_t)extract_uint16,     NULL},
    {&tlvs,  (wpr_t)extract_uint16_tlv, &outmtu},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_trace_hop_t *hops;
  uint16_t count;

  if(scamper_trace_pmtud_alloc(trace) != 0)
    goto err;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  trace->pmtud->ifmtu = ifmtu;
  trace->pmtud->pmtu  = pmtu;
  trace->pmtud->tlvs  = tlvs;

  if(extract_uint16(buf, off, len, &count, NULL) != 0)
    goto err;

  if(count != 0)
    {
      if(warts_trace_hops_read(&hops, state, table, buf, off, len, count) != 0)
	{
	  goto err;
	}

      trace->pmtud->hops = hops;
    }

  return 0;

 err:
  return -1;
}

static void warts_trace_pmtud_write(const scamper_trace_t *trace, uint8_t *buf,
				    uint32_t *off, uint32_t len,
				    uint8_t *flags, uint16_t flags_len,
				    uint16_t params_len)
{
  uint16_t outmtu;
  warts_param_writer_t handlers[] = {
    {&trace->pmtud->ifmtu, (wpw_t)insert_uint16, NULL},
    {&trace->pmtud->pmtu,  (wpw_t)insert_uint16, NULL},
    {&outmtu,              (wpw_t)insert_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  SCAMPER_TRACE_PMTUD_GET_OUTMTU(trace->pmtud, outmtu);

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return;
}

static int warts_trace_lastditch_read(scamper_trace_t *trace,
				      warts_state_t *state,
				      warts_addrtable_t *table,
				      const uint8_t *buf,
				      uint32_t *off, uint32_t len)
{
  scamper_trace_hop_t *hops;
  uint16_t count;

  if(warts_params_read(buf, off, len, NULL, 0) != 0)
    {
      goto err;
    }

  if(extract_uint16(buf, off, len, &count, NULL) != 0)
    {
      goto err;
    }

  if(count != 0)
    {
      if(warts_trace_hops_read(&hops, state, table, buf, off, len, count) != 0)
	{
	  goto err;
	}
      trace->lastditch = hops;
    }

  return 0;

 err:
  return -1;
}

static int warts_trace_dtree_params(const scamper_file_t *sf,
				    const scamper_trace_t *trace,
				    warts_addrtable_t *table,
				    warts_trace_dtree_t *state)
{
  scamper_trace_dtree_t *dtree = trace->dtree;
  int max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, trace_dtree_vars_mfb);
  state->params_len = 0;

  /* include the firsthop specified */
  flag_set(state->flags, WARTS_TRACE_DTREE_FIRSTHOP, &max_id);
  state->params_len += 1;

  /* include the address which caused backwards probing to halt */
  if(dtree->lss_stop != NULL)
    {
      flag_set(state->flags, WARTS_TRACE_DTREE_LSS_STOP, &max_id);
      state->params_len += warts_addr_size(table, dtree->lss_stop);
    }

  /* include the address which caused forwards probing to halt */
  if(dtree->gss_stop != NULL)
    {
      flag_set(state->flags, WARTS_TRACE_DTREE_GSS_STOP, &max_id);
      state->params_len += warts_addr_size(table, dtree->gss_stop);
    }

  state->flags_len = fold_flags(state->flags, max_id);

  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2 ;

  return 0;
}

static void warts_trace_dtree_write(const scamper_trace_t *trace,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off, uint32_t len,
				    warts_trace_dtree_t *state)
{
  warts_param_writer_t handlers[] = {
    {NULL,                    NULL,                 NULL},
    {NULL,                    NULL,                 NULL},
    {&trace->dtree->firsthop, (wpw_t)insert_byte,   NULL},
    {trace->dtree->lss_stop,  (wpw_t)insert_addr,   table},
    {trace->dtree->gss_stop,  (wpw_t)insert_addr,   table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  return;
}

static int warts_trace_dtree_read(scamper_trace_t *trace, warts_state_t *state,
				  warts_addrtable_t *table, const uint8_t *buf,
				  uint32_t *off, uint32_t len)
{
  scamper_addr_t *lss_stop = NULL, *gss_stop = NULL;
  uint8_t firsthop = 0;

  warts_param_reader_t handlers[] = {
    {&lss_stop, (wpr_t)extract_addr_gid, state},
    {&gss_stop, (wpr_t)extract_addr_gid, state},
    {&firsthop, (wpr_t)extract_byte,     NULL},
    {&lss_stop, (wpr_t)extract_addr,     table},
    {&gss_stop, (wpr_t)extract_addr,     table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_trace_dtree_alloc(trace) != 0 ||
     warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    {
      return -1;
    }

  trace->dtree->lss_stop = lss_stop;
  trace->dtree->gss_stop = gss_stop;
  trace->dtree->firsthop = firsthop;
  return 0;
}

/*
 * warts_trace_read
 *
 */
static int warts_trace_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			    scamper_trace_t **trace_out)
{
  warts_state_t       *state = scamper_file_getstate(sf);
  scamper_trace_t     *trace = NULL;
  uint8_t             *buf = NULL;
  uint32_t             i, off = 0;
  scamper_trace_hop_t *hops = NULL;
  scamper_trace_hop_t *hop;
  uint16_t             count;
  int                  max_ttl;
  uint8_t              type;
  uint16_t             len;
  uint16_t             junk16;
  warts_addrtable_t    table;

  memset(&table, 0, sizeof(table));

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *trace_out = NULL;
      return 0;
    }

  if((trace = scamper_trace_alloc()) == NULL)
    {
      goto err;
    }

  /* read the trace's parameters */
  if(warts_trace_params_read(trace, state, &table, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  /*
   * the next two bytes tell us how many scamper_hops to read out of trace
   * if we did not get any responses, we are done.
   */
  if(extract_uint16(buf, &off, hdr->len, &count, NULL) != 0)
    {
      goto err;
    }

  /* read all the hop records */
  if(warts_trace_hops_read(&hops,state,&table, buf, &off, hdr->len, count) != 0)
    {
      goto err;
    }

  /* work out the maximum ttl probed with that got a response */
  max_ttl = 0;
  for(i=0, hop = hops; i < count; i++)
    {
      if(hop->hop_probe_ttl > max_ttl)
	{
	  max_ttl = hop->hop_probe_ttl;
	}
      hop = hop->hop_next;
    }

  /*
   * if the hop_count field was provided in the file, then
   * make sure it makes sense based on the hop data we've just scanned
   */
  if(trace->hop_count != 0)
    {
      if(trace->hop_count < max_ttl)
	{
	  goto err;
	}
    }
  else
    {
      trace->hop_count = max_ttl;
    }

  /* allocate enough hops to string the trace together */
  if(scamper_trace_hops_alloc(trace, trace->hop_count) == -1)
    {
      goto err;
    }

  if(hops == NULL)
    {
      assert(count == 0);
      goto done;
    }

  /*
   * now loop through the hops array stored in this procedure
   * and assemble the responses into trace->hops.
   */
  trace->hops[hops->hop_probe_ttl-1] = hop = hops;
  while(hop->hop_next != NULL) 
    {
      if(hop->hop_probe_ttl != hop->hop_next->hop_probe_ttl)
	{
	  i = hop->hop_next->hop_probe_ttl-1;
	  trace->hops[i] = hop->hop_next;
	  hop->hop_next = NULL;
	  hop = trace->hops[i];
	}
      else hop = hop->hop_next;
    }
  hops = NULL;

  for(;;)
    {
      if(extract_uint16(buf, &off, hdr->len, &junk16, NULL) != 0)
	{
	  goto err;
	}
      if(junk16 == WARTS_TRACE_ATTR_EOF)
	{
	  break;
	}

      type = WARTS_TRACE_ATTR_HDR_TYPE(junk16);
      len  = WARTS_TRACE_ATTR_HDR_LEN(junk16);

      if(type == WARTS_TRACE_ATTR_PMTUD)
	{
	  i = off;
	  if(warts_trace_pmtud_read(trace,state,&table,buf,&i,hdr->len) != 0)
	    {
	      goto err;
	    }
	}
      else if(type == WARTS_TRACE_ATTR_LASTDITCH)
	{
	  i = off;
	  if(warts_trace_lastditch_read(trace, state, &table,
 					buf, &i, hdr->len) != 0)
	    {
	      goto err;
	    }
	}
      else if(type == WARTS_TRACE_ATTR_DTREE)
	{
	  i = off;
	  if(warts_trace_dtree_read(trace,state,&table,buf,&i,hdr->len) != 0)
	    {
	      goto err;
	    }
	}

      off += len;
    }

  assert(off == hdr->len);

 done:
  warts_addrtable_clean(&table);
  free(buf);
  *trace_out = trace;
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(hops != NULL) free(hops);
  if(buf != NULL) free(buf);
  if(trace != NULL) scamper_trace_free(trace);
  return -1;
}

static int warts_trace_hop_state(const scamper_file_t *sf,
				 scamper_trace_hop_t *hop,
				 warts_trace_hop_t *state, 
				 warts_addrtable_t *table, uint32_t *len)
{
  /* for each hop, figure out how much space it will take up */
  warts_trace_hop_params(hop, table, state->flags, &state->flags_len,
			 &state->params_len);

  /* store the actual hop record with the state structure too */
  state->hop = hop;

  /* increase length required for the trace record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_trace_write(const scamper_file_t *sf,
			     const scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  uint8_t             *buf = NULL;
  uint8_t              trace_flags[trace_vars_mfb];
  uint16_t             trace_flags_len, trace_params_len;
  warts_trace_hop_t   *hop_state = NULL;
  uint16_t             hop_recs;
  uint8_t              pmtud_flags[pmtud_vars_mfb];
  uint16_t             pmtud_flags_len = 0, pmtud_params_len = 0;
  warts_trace_hop_t   *pmtud_state = NULL;
  uint16_t             pmtud_recs = 0;
  uint32_t             pmtud_len = 0;
  warts_trace_hop_t   *lastditch_state = NULL;
  uint16_t             lastditch_recs = 0;
  uint32_t             lastditch_len = 0;
  warts_trace_dtree_t  dtree_state;
  uint16_t             junk16;
  uint8_t              junk8;
  uint32_t             off = 0, len, len2;
  size_t               size;
  int                  i, j;
  warts_addrtable_t    table;

  /* make sure the table is nulled out */
  memset(&table, 0, sizeof(table));

  /* figure out which trace data items we'll store in this record */
  warts_trace_params(trace, &table,
		     trace_flags, &trace_flags_len, &trace_params_len);

  /*
   * this represents the length of the trace's flags and parameters, and the
   * 2-byte field that records the number of hop records that follow
   */
  len = trace_flags_len + trace_params_len + 2;
  if(trace_params_len != 0) len += 2;

  /* for each hop, figure out what is going to be stored in this record */
  if((hop_recs = scamper_trace_hop_count(trace)) > 0)
    {
      size = hop_recs * sizeof(warts_trace_hop_t);
      if((hop_state = (warts_trace_hop_t *)malloc(size)) == NULL)
	{
	  goto err;
	}

      for(i=0, j=0; i<trace->hop_count; i++)
	{
	  for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	    {
	      /* record basic hop state */
	      len2 = len;
	      if(warts_trace_hop_state(sf, hop, &hop_state[j++],
				       &table, &len2) == -1)
		{
		  goto err;
		}
	      if(len2 < len)
		{
		  goto err;
		}
	      len = len2;
	    }
	}
    }

  /* figure out how much space we need for PMTUD data, if we have it */
  if(trace->pmtud != NULL)
    {
      /* figure out what the structure of the pmtud header looks like */
      warts_trace_pmtud_params(trace, pmtud_flags, &pmtud_flags_len,
			       &pmtud_params_len);

      /* count the number of hop records */
      pmtud_recs = scamper_trace_pmtud_hop_count(trace);

      /* allocate an array of address indexes for the pmtud hop addresses */
      size = pmtud_recs * sizeof(warts_trace_hop_t);
      if((pmtud_state = (warts_trace_hop_t *)malloc(size)) == NULL)
	{
	  goto err;
	}

      /* flags + params + number of hop records for pmtud structure */
      pmtud_len = pmtud_flags_len + pmtud_params_len + 2;
      if(pmtud_params_len != 0) pmtud_len += 2;

      /* record hop state for each pmtud hop */
      for(hop = trace->pmtud->hops, j=0; hop != NULL; hop = hop->hop_next)
	{
	  if(warts_trace_hop_state(sf, hop, &pmtud_state[j++], &table,
				   &pmtud_len) == -1)
	    {
	      goto err;
	    }
	}

      len += (2 + pmtud_len); /* 2 = size of attribute header */
    }

  if(trace->lastditch != NULL)
    {
      /* count the number of last-ditch hop records */
      lastditch_recs = scamper_trace_lastditch_hop_count(trace);

      /* allocate an array of hop state structs for the lastditch hops */
      size = lastditch_recs * sizeof(warts_trace_hop_t);
      if((lastditch_state = (warts_trace_hop_t *)malloc(size)) == NULL)
	{
	  goto err;
	}

      /* need to record count of lastditch hops and a single zero flags byte */
      lastditch_len = 3;

      /* record hop state for each lastditch reply */
      for(hop = trace->lastditch, j=0; hop != NULL; hop = hop->hop_next)
	{
	  if(warts_trace_hop_state(sf, hop, &lastditch_state[j++], &table,
				   &lastditch_len) == -1)
	    {
	      goto err;
	    }
	}

      len += (2 + lastditch_len); /* 2 = size of attribute header */
    }

  if(trace->dtree != NULL)
    {
      /* figure out what the structure of the dtree header looks like */
      if(warts_trace_dtree_params(sf, trace, &table, &dtree_state) != 0)
	goto err;

      /* 2 = size of attribute header */
      len += (2 + dtree_state.len);
    }

  len += 2; /* EOF */

  if((buf = malloc(len)) == NULL)
    {
      goto err;
    }

  /* write trace parameters */
  if(warts_trace_params_write(trace, sf, &table, buf, &off, len, trace_flags,
			      trace_flags_len, trace_params_len) == -1)
    {
      goto err;
    }

  /* hop record count */
  insert_uint16(buf, &off, len, &hop_recs, NULL);

  /* write each traceroute hop record */
  for(i=0; i<hop_recs; i++)
    {
      warts_trace_hop_write(&hop_state[i], &table, buf, &off, len);
    }
  if(hop_state != NULL)
    {
      free(hop_state);
      hop_state = NULL;
    }

  /* write the PMTUD data */
  if(trace->pmtud != NULL)
    {
      /* write the attribute header */
      junk16 = WARTS_TRACE_ATTR_HDR(WARTS_TRACE_ATTR_PMTUD, pmtud_len);
      insert_uint16(buf, &off, len, &junk16, NULL);
		    
      /* write details of the pmtud measurement */
      warts_trace_pmtud_write(trace, buf, &off, len,
			      pmtud_flags, pmtud_flags_len, pmtud_params_len);

      /* write the number of hop records */
      insert_uint16(buf, &off, len, &pmtud_recs, NULL);

      for(i=0; i<pmtud_recs; i++)
	{
	  warts_trace_hop_write(&pmtud_state[i], &table, buf, &off, len);
	}
      if(pmtud_state != NULL)
	{
	  free(pmtud_state);
	  pmtud_state = NULL;
	}
    }

  /* write the last-ditch data */
  if(trace->lastditch != NULL)
    {
      /* write the attribute header */
      junk16 = WARTS_TRACE_ATTR_HDR(WARTS_TRACE_ATTR_LASTDITCH, lastditch_len);
      insert_uint16(buf, &off, len, &junk16, NULL);

      /* write the last-ditch flags: currently zero */
      junk8 = 0;
      insert_byte(buf, &off, len, &junk8, NULL);

      /* write the number of hop records */
      insert_uint16(buf, &off, len, &lastditch_recs, NULL);

      for(i=0; i<lastditch_recs; i++)
	{
	  warts_trace_hop_write(&lastditch_state[i], &table, buf, &off, len);
	}
      free(lastditch_state);
      lastditch_state = NULL;
    }

  /* write doubletree data */
  if(trace->dtree != NULL)
    {
      junk16 = WARTS_TRACE_ATTR_HDR(WARTS_TRACE_ATTR_DTREE, dtree_state.len);
      insert_uint16(buf, &off, len, &junk16, NULL);

      /* write details of the pmtud measurement */
      warts_trace_dtree_write(trace, &table, buf, &off, len, &dtree_state);
    }

  /* write the end of trace attributes header */
  junk16 = WARTS_TRACE_ATTR_EOF;
  insert_uint16(buf, &off, len, &junk16, NULL);

  assert(off == len);

  if(warts_write(sf, SCAMPER_FILE_OBJ_TRACE, buf, len) == -1)
    {
      goto err;
    }

  warts_addrtable_clean(&table);
  free(buf);
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(buf != NULL) free(buf);
  if(hop_state != NULL) free(hop_state);
  if(pmtud_state != NULL) free(pmtud_state);
  if(lastditch_state != NULL) free(lastditch_state);
  return -1;
}

static void warts_tracelb_params(const scamper_tracelb_t *trace,
				 warts_addrtable_t *table, uint8_t *flags,
				 uint16_t *flags_len, uint16_t *params_len)
{
  int i, max_id = 0;
  const warts_var_t *var;

  /* unset all the flags possible */
  memset(flags, 0, tracelb_vars_mfb);
  *params_len = 0;

  /* for now, we include the base data items */
  for(i=0; i<sizeof(tracelb_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_vars[i];

      if(var->id == WARTS_TRACELB_ADDR_SRC_GID ||
	 var->id == WARTS_TRACELB_ADDR_DST_GID)
	{
	  continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_TRACELB_ADDR_SRC)
	{
	  *params_len += warts_addr_size(table, trace->src);
	  continue;
	}
      else if(var->id == WARTS_TRACELB_ADDR_DST)
	{
	  *params_len += warts_addr_size(table, trace->dst);
	  continue;
	}

      assert(var->size >= 0);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_tracelb_params_read(scamper_tracelb_t *trace,
				     warts_state_t *state,
				     warts_addrtable_t *table, uint8_t *buf,
				     uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&trace->list,         (wpr_t)extract_list,      state},
    {&trace->cycle,        (wpr_t)extract_cycle,     state},
    {&trace->src,          (wpr_t)extract_addr_gid,  state},
    {&trace->dst,          (wpr_t)extract_addr_gid,  state},
    {&trace->start,        (wpr_t)extract_timeval,   NULL},
    {&trace->sport,        (wpr_t)extract_uint16,    NULL},
    {&trace->dport,        (wpr_t)extract_uint16,    NULL},
    {&trace->probe_size,   (wpr_t)extract_uint16,    NULL},
    {&trace->type,         (wpr_t)extract_byte,      NULL},
    {&trace->firsthop,     (wpr_t)extract_byte,      NULL},
    {&trace->wait_timeout, (wpr_t)extract_byte,      NULL},
    {&trace->wait_probe,   (wpr_t)extract_byte,      NULL},
    {&trace->attempts,     (wpr_t)extract_byte,      NULL},
    {&trace->confidence,   (wpr_t)extract_byte,      NULL},
    {&trace->tos,          (wpr_t)extract_byte,      NULL},
    {&trace->nodec,        (wpr_t)extract_uint16,    NULL},
    {&trace->linkc,        (wpr_t)extract_uint16,    NULL},
    {&trace->probec,       (wpr_t)extract_uint32,    NULL},
    {&trace->probec_max,   (wpr_t)extract_uint32,    NULL},
    {&trace->gaplimit,     (wpr_t)extract_byte,      NULL},
    {&trace->src,          (wpr_t)extract_addr,      table},
    {&trace->dst,          (wpr_t)extract_addr,      table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static int warts_tracelb_params_write(const scamper_tracelb_t *trace,
				      const scamper_file_t *sf,
				      warts_addrtable_t *table,
				      uint8_t *buf, uint32_t *off,
				      const uint32_t len,
				      const uint8_t *flags,
				      const uint16_t flags_len,
				      const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  warts_param_writer_t handlers[] = {
    {&list_id,             (wpw_t)insert_uint32,  NULL},
    {&cycle_id,            (wpw_t)insert_uint32,  NULL},
    {NULL,                 NULL,                  NULL},
    {NULL,                 NULL,                  NULL},
    {&trace->start,        (wpw_t)insert_timeval, NULL},
    {&trace->sport,        (wpw_t)insert_uint16,  NULL},
    {&trace->dport,        (wpw_t)insert_uint16,  NULL},
    {&trace->probe_size,   (wpw_t)insert_uint16,  NULL},
    {&trace->type,         (wpw_t)insert_byte,    NULL},
    {&trace->firsthop,     (wpw_t)insert_byte,    NULL},
    {&trace->wait_timeout, (wpw_t)insert_byte,    NULL},
    {&trace->wait_probe,   (wpw_t)insert_byte,    NULL},
    {&trace->attempts,     (wpw_t)insert_byte,    NULL},
    {&trace->confidence,   (wpw_t)insert_byte,    NULL},
    {&trace->tos,          (wpw_t)insert_byte,    NULL},
    {&trace->nodec,        (wpw_t)insert_uint16,  NULL},
    {&trace->linkc,        (wpw_t)insert_uint16,  NULL},
    {&trace->probec,       (wpw_t)insert_uint32,  NULL},
    {&trace->probec_max,   (wpw_t)insert_uint32,  NULL},
    {&trace->gaplimit,     (wpw_t)insert_byte,    NULL},
    {trace->src,           (wpw_t)insert_addr,    table},
    {trace->dst,           (wpw_t)insert_addr,    table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  trace->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, trace->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

static int warts_tracelb_node_state(const scamper_file_t *sf,
				    const scamper_tracelb_node_t *node,
				    warts_addrtable_t *table,
				    warts_tracelb_node_t *state, uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tracelb_node_vars_mfb);
  state->params_len = 0;

  /* for now, we include the base data items */
  for(i=0; i<sizeof(tracelb_node_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_node_vars[i];

      if(var->id == WARTS_TRACELB_NODE_ADDR_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_TRACELB_NODE_QTTL)
	{
	  /* don't include the qttl field if it isn't used */
	  if(SCAMPER_TRACELB_NODE_QTTL(node) == 0)
	    continue;
	}

      flag_set(state->flags, var->id, &max_id);

      if(var->id == WARTS_TRACELB_NODE_ADDR)
	{
	  state->params_len += warts_addr_size(table, node->addr);
	  continue;
	}

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_tracelb_node_read(scamper_tracelb_node_t *node,
				   warts_state_t *state,
				   warts_addrtable_t *table,const uint8_t *buf,
				   uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&node->addr,  (wpr_t)extract_addr_gid,  state},
    {&node->flags, (wpr_t)extract_byte,      NULL},
    {&node->linkc, (wpr_t)extract_uint16,    NULL},
    {&node->q_ttl, (wpr_t)extract_byte,      NULL},
    {&node->addr,  (wpr_t)extract_addr,      table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    {
      return -1;
    }

  return 0;
}

static void warts_tracelb_node_write(const scamper_tracelb_node_t *node,
				     const warts_tracelb_node_t *state,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {NULL,         NULL,                 NULL},
    {&node->flags, (wpw_t)insert_byte,   NULL},
    {&node->linkc, (wpw_t)insert_uint16, NULL},
    {&node->q_ttl, (wpw_t)insert_byte,   NULL},
    {node->addr,   (wpw_t)insert_addr,   table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
                     state->params_len, handlers, handler_cnt);
  return;
}

static int extract_tracelb_reply_icmp_tc(const uint8_t *buf, uint32_t *off,
					 uint32_t len,
					 scamper_tracelb_reply_t *reply,
					 void *param)
{
  if(len - *off < 2)
    {
      return -1;
    }
  reply->reply_icmp_type = buf[(*off)++];
  reply->reply_icmp_code = buf[(*off)++];
  return 0;
}

static void insert_tracelb_reply_icmp_tc(uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 const scamper_tracelb_reply_t *reply,
					 void *param)
{
  assert(len - *off >= 2);
  buf[(*off)++] = reply->reply_icmp_type;
  buf[(*off)++] = reply->reply_icmp_code;
  return;
}

static int extract_tracelb_reply_icmp_ext(const uint8_t *buf, uint32_t *off,
					  uint32_t len,
					  scamper_tracelb_reply_t *reply,
					  void *param)
{
  return warts_icmpext_read(buf, off, len, &reply->reply_icmp_ext);
}

static void insert_tracelb_reply_icmp_ext(uint8_t *buf, uint32_t *off,
					  const uint32_t len,
					  const scamper_tracelb_reply_t *reply,
					  void *param)
{
  warts_icmpext_write(buf, off, len, reply->reply_icmp_ext);
  return;
}

static int warts_tracelb_reply_state(const scamper_file_t *sf,
				     const scamper_tracelb_reply_t *reply,
				     warts_tracelb_reply_t *state,
				     warts_addrtable_t *table, uint32_t *len)
{
  const warts_var_t *var;
  scamper_icmpext_t *ie;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(state->flags, 0, tracelb_reply_vars_mfb);
  state->params_len = 0;

  /* figure out what to include */
  for(i=0; i<sizeof(tracelb_reply_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_reply_vars[i];

      if(var->id == WARTS_TRACELB_REPLY_FROM_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_TRACELB_REPLY_TTL)
	{
	  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_REPLY_TTL) == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACELB_REPLY_ICMP_TC ||
	      var->id == WARTS_TRACELB_REPLY_ICMP_Q_TTL ||
	      var->id == WARTS_TRACELB_REPLY_ICMP_Q_TOS)
	{
	  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) != 0)
	    continue;
	}
      else if(var->id == WARTS_TRACELB_REPLY_TCP_FLAGS)
	{
	  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0)
	    continue;
	}
      else if(var->id == WARTS_TRACELB_REPLY_ICMP_EXT)
	{
	  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) != 0 ||
	     reply->reply_icmp_ext == NULL)
	    continue;

	  state->params_len += 2;
	  for(ie = reply->reply_icmp_ext; ie != NULL; ie = ie->ie_next)
	    {
	      state->params_len += (2 + 1 + 1 + ie->ie_dl);
	    }
	}
      else if(var->id == WARTS_TRACELB_REPLY_FROM)
	{
	  state->params_len += warts_addr_size(table, reply->reply_from);
	}

      flag_set(state->flags, var->id, &max_id);

      if(var->size > 0)
	{
	  state->params_len += var->size;
	}
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_tracelb_reply_read(scamper_tracelb_reply_t *reply,
				    warts_state_t *state,
				    warts_addrtable_t *table,
				    const uint8_t *buf,
				    uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&reply->reply_rx,         (wpr_t)extract_timeval,                NULL},
    {&reply->reply_ipid,       (wpr_t)extract_uint16,                 NULL},
    {&reply->reply_ttl,        (wpr_t)extract_byte,                   NULL},
    {&reply->reply_flags,      (wpr_t)extract_byte,                   NULL},
    {reply,                    (wpr_t)extract_tracelb_reply_icmp_tc,  NULL},
    {&reply->reply_tcp_flags,  (wpr_t)extract_byte,                   NULL},
    {reply,                    (wpr_t)extract_tracelb_reply_icmp_ext, NULL},
    {&reply->reply_icmp_q_ttl, (wpr_t)extract_byte,                   NULL},
    {&reply->reply_icmp_q_tos, (wpr_t)extract_byte,                   NULL},
    {&reply->reply_from,       (wpr_t)extract_addr_gid,               state},
    {&reply->reply_from,       (wpr_t)extract_addr,                   table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_tracelb_reply_write(const scamper_tracelb_reply_t *reply,
				      const warts_tracelb_reply_t *state,
				      warts_addrtable_t *table,
				      uint8_t *buf,uint32_t *off,uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {&reply->reply_rx,         (wpw_t)insert_timeval,                NULL},
    {&reply->reply_ipid,       (wpw_t)insert_uint16,                 NULL},
    {&reply->reply_ttl,        (wpw_t)insert_byte,                   NULL},
    {&reply->reply_flags,      (wpw_t)insert_byte,                   NULL},
    {reply,                    (wpw_t)insert_tracelb_reply_icmp_tc,  NULL},
    {&reply->reply_tcp_flags,  (wpw_t)insert_byte,                   NULL},
    {reply,                    (wpw_t)insert_tracelb_reply_icmp_ext, NULL},
    {&reply->reply_icmp_q_ttl, (wpw_t)insert_byte,                   NULL},
    {&reply->reply_icmp_q_tos, (wpw_t)insert_byte,                   NULL},
    {NULL,                     NULL,                                 NULL},
    {reply->reply_from,        (wpw_t)insert_addr,                   table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
                     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_tracelb_probe_free(warts_tracelb_probe_t *state)
{
  if(state->replies != NULL)
    {
      free(state->replies);
      state->replies = NULL;
    }
  return;
}

static int warts_tracelb_probe_state(const scamper_file_t *sf,
				     const scamper_tracelb_probe_t *probe,
				     warts_tracelb_probe_t *state,
				     warts_addrtable_t *table,
				     uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size;

  memset(state->flags, 0, tracelb_probe_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tracelb_probe_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_probe_vars[i];
      flag_set(state->flags, var->id, &max_id);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  if(probe->rxc > 0)
    {
      size = sizeof(warts_tracelb_reply_t) * probe->rxc;
      if((state->replies = malloc_zero(size)) == NULL)
	{
	  return -1;
	}

      for(i=0; i<probe->rxc; i++)
	{
	  if(warts_tracelb_reply_state(sf, probe->rxs[i], &state->replies[i],
				       table, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static int warts_tracelb_probe_read(scamper_tracelb_probe_t *probe,
				    warts_state_t *state,
				    warts_addrtable_t *table,
				    const uint8_t *buf,
				    uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&probe->tx,         (wpr_t)extract_timeval,                NULL},
    {&probe->flowid,     (wpr_t)extract_uint16,                 NULL},
    {&probe->ttl,        (wpr_t)extract_byte,                   NULL},
    {&probe->attempt,    (wpr_t)extract_byte,                   NULL},
    {&probe->rxc,        (wpr_t)extract_uint16,                 NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_tracelb_reply_t *reply;
  uint16_t i;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(probe->rxc > 0)
    {
      if(scamper_tracelb_probe_replies_alloc(probe, probe->rxc) != 0)
	return -1;

      for(i=0; i<probe->rxc; i++)
	{
	  if((reply = scamper_tracelb_reply_alloc(NULL)) == NULL)
	    return -1;
	  probe->rxs[i] = reply;

	  if(warts_tracelb_reply_read(reply, state, table, buf, off, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static void warts_tracelb_probe_write(const scamper_tracelb_probe_t *probe,
				      const warts_tracelb_probe_t *state,
				      warts_addrtable_t *table,
				      uint8_t *buf,uint32_t *off,uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {&probe->tx,         (wpw_t)insert_timeval,                NULL},
    {&probe->flowid,     (wpw_t)insert_uint16,                 NULL},
    {&probe->ttl,        (wpw_t)insert_byte,                   NULL},
    {&probe->attempt,    (wpw_t)insert_byte,                   NULL},
    {&probe->rxc,        (wpw_t)insert_uint16,                 NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint16_t i;

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);

  for(i=0; i<probe->rxc; i++)
    {
      warts_tracelb_reply_write(probe->rxs[i], &state->replies[i], table,
				buf, off, len);
    }

  return;
}

static void warts_tracelb_probeset_free(warts_tracelb_probeset_t *state)
{
  uint16_t i;

  if(state->probes != NULL)
    {
      for(i=0; i<state->probec; i++)
	warts_tracelb_probe_free(&state->probes[i]);
      free(state->probes);
      state->probes = NULL;
    }

  return;
}

static int warts_tracelb_probeset_state(const scamper_file_t *sf,
					const scamper_tracelb_probeset_t *set,
					warts_tracelb_probeset_t *state,
					warts_addrtable_t *table,
					uint32_t *len)
{
  const warts_var_t *var;
  int i, max_id = 0;
  size_t size;

  state->probec = set->probec;

  memset(state->flags, 0, tracelb_probeset_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tracelb_probeset_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_probeset_vars[i];
      flag_set(state->flags, var->id, &max_id);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  if(set->probec > 0)
    {
      size = sizeof(warts_tracelb_probe_t) * set->probec;
      if((state->probes = malloc_zero(size)) == NULL)
	{
	  return -1;
	}

      for(i=0; i<set->probec; i++)
	{
	  if(warts_tracelb_probe_state(sf, set->probes[i], &state->probes[i],
				       table, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static int warts_tracelb_probeset_read(scamper_tracelb_probeset_t *set,
				       warts_state_t *state,
				       warts_addrtable_t *table,
				       const uint8_t *buf, uint32_t *off,
				       uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&set->probec, (wpr_t)extract_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint16_t i;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(set->probec > 0)
    {
      if(scamper_tracelb_probeset_probes_alloc(set, set->probec) != 0)
	return -1;

      for(i=0; i<set->probec; i++)
	{
	  if((set->probes[i] = scamper_tracelb_probe_alloc()) == NULL ||
	     warts_tracelb_probe_read(set->probes[i], state, table,
				      buf, off, len) != 0)
	    {
	      return -1;
	    }
	}
    }

  return 0;
}

static void warts_tracelb_probeset_write(const scamper_tracelb_probeset_t *set,
					 const warts_tracelb_probeset_t *state,
					 warts_addrtable_t *table,
					 uint8_t *buf, uint32_t *off,
					 uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {&set->probec, (wpw_t)insert_uint16, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint16_t i;

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);

  for(i=0; i<set->probec; i++)
    {
      warts_tracelb_probe_write(set->probes[i], &state->probes[i], table,
				buf, off, len);
    }

  return;
}

static void warts_tracelb_link_free(warts_tracelb_link_t *state)
{
  uint8_t i;
  if(state->sets != NULL)
    {
      for(i=0; i<state->hopc; i++)
	warts_tracelb_probeset_free(&state->sets[i]);
      free(state->sets);
      state->sets = NULL;
    }
  return;
}

static int warts_tracelb_link_state(const scamper_file_t *sf,
				    const scamper_tracelb_t *trace,
				    const scamper_tracelb_link_t *link,
				    warts_tracelb_link_t *state,
				    warts_addrtable_t *table, uint32_t *len)
{
  const warts_var_t *var;
  size_t size;
  int i, j, max_id = 0;
  uint8_t s;

  state->hopc = link->hopc;

  /*
   * get the index into the nodes array for each of the nodes represented
   * in the link.  the loop finishes when j reaches 2, i.e. both nodes have
   * been identified.
   */
  for(i=0, j=0; i<trace->nodec; i++)
    {
      if(link->from == trace->nodes[i])
	{
	  state->from = i;
	  j++;
	}
      if(link->to == trace->nodes[i])
	{
	  state->to = i;
	  j++;
	}

      if(j == 2 || (link->to == NULL && j == 1))
	break;
    }

  /* unset all the flags possible */
  memset(state->flags, 0, tracelb_link_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tracelb_link_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracelb_link_vars[i];

      /* if the link does not include a `to' node, skip it */
      if(var->id == WARTS_TRACELB_LINK_TO && link->to == NULL)
	continue;

      flag_set(state->flags, var->id, &max_id);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  if(link->hopc > 0)
    {
      size = sizeof(warts_tracelb_probeset_t) * link->hopc;
      if((state->sets = malloc_zero(size)) == NULL)
	{
	  return -1;
	}

      for(s=0; s<link->hopc; s++)
	{
	  if(warts_tracelb_probeset_state(sf, link->sets[s], &state->sets[s],
					  table, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static int warts_tracelb_link_read(scamper_tracelb_t *trace,
				   scamper_tracelb_link_t *link,
				   warts_state_t *state,
				   warts_addrtable_t *table,
				   const uint8_t *buf,
				   uint32_t *off, uint32_t len)
{
  uint16_t from, to;
  warts_param_reader_t handlers[] = {
    {&from,         (wpr_t)extract_uint16, NULL},
    {&to,           (wpr_t)extract_uint16, NULL},
    {&link->hopc,   (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_tracelb_probeset_t *set;
  uint8_t i;
  uint32_t o = *off;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    {
      return -1;
    }
  link->from = trace->nodes[from];

  if(flag_isset(&buf[o], WARTS_TRACELB_LINK_TO) != 0)
    link->to = trace->nodes[to];
  else
    link->to = NULL;

  if(link->hopc > 0)
    {
      if(scamper_tracelb_link_probesets_alloc(link, link->hopc) != 0)
	return -1;

      for(i=0; i<link->hopc; i++)
	{
	  if((set = scamper_tracelb_probeset_alloc()) == NULL)
	    return -1;
	  link->sets[i] = set;

	  if(warts_tracelb_probeset_read(set, state, table, buf, off, len) != 0)
	    return -1;
	}
    }

  return 0;
}

static void warts_tracelb_link_write(const scamper_tracelb_link_t *link,
				     const warts_tracelb_link_t *state,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_writer_t handlers[] = {
    {&state->from,          (wpw_t)insert_uint16,   NULL},
    {&state->to,            (wpw_t)insert_uint16,   NULL},
    {&link->hopc,           (wpw_t)insert_byte,     NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint32_t i;

  warts_params_write(buf, off, len, state->flags, state->flags_len,
                     state->params_len, handlers, handler_cnt);

  for(i=0; i<link->hopc; i++)
    {
      warts_tracelb_probeset_write(link->sets[i], &state->sets[i], table,
				   buf, off, len);
    }

  return;
}

/*
 * warts_tracelb_read
 *
 */
static int warts_tracelb_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			      scamper_tracelb_t **trace_out)
{
  warts_state_t          *state = scamper_file_getstate(sf);
  scamper_tracelb_t      *trace = NULL;
  uint8_t                *buf = NULL;
  uint32_t                i, off = 0;
  uint16_t               *nlc = NULL, j;
  scamper_tracelb_node_t *node;
  warts_addrtable_t       table;

  memset(&table, 0, sizeof(table));

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *trace_out = NULL;
      return 0;
    }

  if((trace = scamper_tracelb_alloc()) == NULL)
    {
      goto err;
    }

  /* read the trace's parameters */
  if(warts_tracelb_params_read(trace, state, &table, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  /* read the nodes */
  if(trace->nodec > 0)
    {
      if(scamper_tracelb_nodes_alloc(trace, trace->nodec) != 0)
	{
	  goto err;
	}
      for(i=0; i<trace->nodec; i++)
	{
	  if((trace->nodes[i] = scamper_tracelb_node_alloc(NULL)) == NULL)
	    goto err;

	  if(warts_tracelb_node_read(trace->nodes[i], state, &table,
				     buf, &off, hdr->len) != 0)
	    goto err;
	}
    }

  /* read the links */
  if(trace->linkc > 0)
    {
      if(scamper_tracelb_links_alloc(trace, trace->linkc) != 0)
	{
	  goto err;
	}
      for(i=0; i<trace->linkc; i++)
	{
	  if((trace->links[i] = scamper_tracelb_link_alloc()) == NULL)
	    goto err;

	  if(warts_tracelb_link_read(trace, trace->links[i], state, &table,
				     buf, &off, hdr->len) != 0)
	    goto err;
	}
    }

  /* don't need the buf any more */
  free(buf); buf = NULL;

  /*
   * add the links to their respective nodes.
   */
  if(trace->nodec > 0)
    {
      if((nlc = malloc_zero(sizeof(uint16_t) * trace->nodec)) == NULL)
	{
	  goto err;
	}
      for(i=0; i<trace->linkc; i++)
	{
	  for(j=0; j<trace->nodec; j++)
	    {
	      if(trace->links[i]->from == trace->nodes[j])
		break;
	    }

	  if(j == trace->nodec)
	    goto err;

	  node = trace->nodes[j];

	  if(node->links == NULL &&
	     scamper_tracelb_node_links_alloc(node, node->linkc) != 0)
	    goto err;

	  if(nlc[j] == node->linkc)
	    goto err;

	  node->links[nlc[j]++] = trace->links[i];
	}

      for(i=0; i<trace->nodec; i++)
	{
	  if(nlc[i] != trace->nodes[i]->linkc)
	    goto err;
	}

      free(nlc); nlc = NULL;
    }

  warts_addrtable_clean(&table);
  *trace_out = trace;
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(buf != NULL) free(buf);
  if(nlc != NULL) free(nlc);
  if(trace != NULL) scamper_tracelb_free(trace);
  return -1;
}

static int warts_tracelb_write(const scamper_file_t *sf,
			       const scamper_tracelb_t *trace)
{
  const scamper_tracelb_node_t *node;
  const scamper_tracelb_link_t *link;
  uint8_t                      *buf = NULL;
  uint32_t                      off = 0, len, len2;
  uint8_t                       trace_flags[tracelb_vars_mfb];
  uint16_t                      trace_flags_len, trace_params_len;
  warts_tracelb_node_t         *node_state = NULL;
  warts_tracelb_link_t         *link_state = NULL;
  size_t                        size;
  int                           i;
  warts_addrtable_t             table;

  /* make sure the table is nulled out */
  memset(&table, 0, sizeof(table));

  /* figure out which tracelb data items we'll store in this record */
  warts_tracelb_params(trace, &table, trace_flags, &trace_flags_len,
		       &trace_params_len);

  /* this represents the length of the trace's flags and parameters */
  len = trace_flags_len + trace_params_len;
  if(trace_params_len != 0) len += 2;

  /* record the node records */
  if(trace->nodec > 0)
    {
      size = trace->nodec * sizeof(warts_tracelb_node_t);
      if((node_state = (warts_tracelb_node_t *)malloc_zero(size)) == NULL)
	{
	  goto err;
	}

      for(i=0; i<trace->nodec; i++)
	{
	  len2 = len;
	  node = trace->nodes[i];
	  if(warts_tracelb_node_state(sf, node, &table, &node_state[i],
				      &len2) != 0)
	    {
	      goto err;
	    }

	  /* check for wrapping */
	  if(len2 < len)
	    goto err;
	  len = len2;
	}
    }

  /* record the link records */
  if(trace->linkc > 0)
    {
      size = trace->linkc * sizeof(warts_tracelb_link_t);
      if((link_state = (warts_tracelb_link_t *)malloc_zero(size)) == NULL)
	{
	  goto err;
	}

      for(i=0; i<trace->linkc; i++)
	{
	  len2 = len;
	  link = trace->links[i];
	  if(warts_tracelb_link_state(sf, trace, link, &link_state[i],
				      &table, &len2) != 0)
	    {
	      goto err;
	    }

	  /* check for wrapping */
	  if(len2 < len)
	    goto err;
	  len = len2;
	}
    }

  if((buf = malloc(len)) == NULL)
    {
      goto err;
    }

  /* write trace params */
  if(warts_tracelb_params_write(trace, sf, &table, buf, &off, len, trace_flags,
				trace_flags_len, trace_params_len) != 0)
    {
      goto err;
    }

  /* write trace nodes */
  for(i=0; i<trace->nodec; i++)
    {
 warts_tracelb_node_write(trace->nodes[i], &node_state[i], &table,
			       buf, &off, len);
    }
  if(node_state != NULL)
    {
      free(node_state);
      node_state = NULL;
    }

  /* write trace links */
  for(i=0; i<trace->linkc; i++)
    {
      link = trace->links[i];
      warts_tracelb_link_write(link, &link_state[i], &table, buf, &off, len);
      warts_tracelb_link_free(&link_state[i]);
    }
  if(link_state != NULL)
    {
      free(link_state);
      link_state = NULL;
    }

  assert(off == len);

  if(warts_write(sf, SCAMPER_FILE_OBJ_TRACELB, buf, off) == -1)
    {
      goto err;
    }

  warts_addrtable_clean(&table);
  free(buf);
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(node_state != NULL) free(node_state);
  if(link_state != NULL) free(link_state);
  if(buf != NULL) free(buf);
  return -1;
}

static void warts_ping_reply_params(const scamper_ping_t *ping,
				    const scamper_ping_reply_t *reply,
				    warts_addrtable_t *table,
				    uint8_t *flags, uint16_t *flags_len,
				    uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(flags, 0, ping_reply_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(ping_reply_vars)/sizeof(warts_var_t); i++)
    {
      var = &ping_reply_vars[i];

      if(var->id == WARTS_PING_REPLY_ADDR_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_PING_REPLY_REPLY_TTL)
	{
	  if((reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_TTL) == 0)
	    continue;
	}
      else if(var->id == WARTS_PING_REPLY_REPLY_IPID)
	{
	  if((reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID) == 0)
	    continue;
	}
      else if(var->id == WARTS_PING_REPLY_PROBE_IPID)
	{
	  if((reply->flags & SCAMPER_PING_REPLY_FLAG_PROBE_IPID) == 0)
	    continue;
	}
      else if(var->id == WARTS_PING_REPLY_REPLY_PROTO)
	{
	  /* in this case, the reply protocol will always be ICMP */
	  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	    continue;
	}
      else if(var->id == WARTS_PING_REPLY_ICMP_TC)
	{
	  /* only store this if its an ICMP message */
	  if(SCAMPER_PING_REPLY_IS_ICMP(reply) == 0)
	    continue;
	}
      else if(var->id == WARTS_PING_REPLY_TCP_FLAGS)
	{
	  /* only store this if its a TCP packet */
	  if(SCAMPER_PING_REPLY_IS_TCP(reply) == 0)
	    continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_PING_REPLY_ADDR)
	{
	  *params_len += warts_addr_size(table, reply->addr);
	  continue;
	}

      assert(var->size >= 0);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);

  return;
}

static int warts_ping_reply_state(const scamper_file_t *sf,
				  const scamper_ping_t *ping,
				  scamper_ping_reply_t *reply,
				  warts_ping_reply_t *state,
				  warts_addrtable_t *table,
				  uint32_t *len)
{
  warts_ping_reply_params(ping, reply, table, state->flags,
			  &state->flags_len,&state->params_len);

  state->reply = reply;

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_ping_reply_read_icmptc(const uint8_t *buf, uint32_t *off,
					uint32_t len,
					scamper_ping_reply_t *reply,
					void *param)
{
  if(len - *off < 2)
    {
      return -1;
    }
  reply->icmp_type = buf[(*off)++];
  reply->icmp_code = buf[(*off)++];
  return 0;
}

static void warts_ping_reply_write_icmptc(uint8_t *buf, uint32_t *off,
					  const uint32_t len,
					  const scamper_ping_reply_t *reply,
					  void *param)
{
  assert(len - *off >= 2);

  buf[(*off)++] = reply->icmp_type;
  buf[(*off)++] = reply->icmp_code;

  return;
}

static int warts_ping_reply_read(const scamper_ping_t *ping,
				 scamper_ping_reply_t *reply,
				 warts_state_t *state,
				 warts_addrtable_t *table, const uint8_t *buf,
				 uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&reply->addr,            (wpr_t)extract_addr_gid,             state},
    {&reply->flags,           (wpr_t)extract_byte,                 NULL},
    {&reply->reply_ttl,       (wpr_t)extract_byte,                 NULL},
    {&reply->reply_size,      (wpr_t)extract_uint16,               NULL},
    {reply,                   (wpr_t)warts_ping_reply_read_icmptc, NULL},
    {&reply->rtt,             (wpr_t)extract_rtt,                  NULL},
    {&reply->probe_id,        (wpr_t)extract_uint16,               NULL},
    {&reply->reply_ipid,      (wpr_t)extract_uint16,               NULL},
    {&reply->probe_ipid,      (wpr_t)extract_uint16,               NULL},
    {&reply->reply_proto,     (wpr_t)extract_byte,                 NULL},
    {&reply->tcp_flags,       (wpr_t)extract_byte,                 NULL},
    {&reply->addr,            (wpr_t)extract_addr,                 table},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
  uint32_t o = *off;
  int i;

  if((i = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return i;

  /*
   * some earlier versions of the ping reply structure did not include
   * the reply protocol field.  fill it with something valid.
   */
  if(flag_isset(&buf[o], WARTS_PING_REPLY_REPLY_PROTO) == 0)
    {
      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	reply->reply_proto = IPPROTO_ICMP;
      else
	reply->reply_proto = IPPROTO_ICMPV6;
    }

  return 0;
}

static void warts_ping_reply_write(const warts_ping_reply_t *state,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  scamper_ping_reply_t *reply = state->reply;

  warts_param_writer_t handlers[] = {
    {NULL,                    NULL,                                 NULL},
    {&reply->flags,           (wpw_t)insert_byte,                   NULL},
    {&reply->reply_ttl,       (wpw_t)insert_byte,                   NULL},
    {&reply->reply_size,      (wpw_t)insert_uint16,                 NULL},
    {reply,                   (wpw_t)warts_ping_reply_write_icmptc, NULL},
    {&reply->rtt,             (wpw_t)insert_rtt,                    NULL},
    {&reply->probe_id,        (wpw_t)insert_uint16,                 NULL},
    {&reply->reply_ipid,      (wpw_t)insert_uint16,                 NULL},
    {&reply->probe_ipid,      (wpw_t)insert_uint16,                 NULL},
    {&reply->reply_proto,     (wpw_t)insert_byte,                   NULL},
    {&reply->tcp_flags,       (wpw_t)insert_byte,                   NULL},
    {reply->addr,             (wpw_t)insert_addr,                   table},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_writer_t);

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static void warts_ping_params(const scamper_ping_t *ping,
			      warts_addrtable_t *table, uint8_t *flags,
			      uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  uint16_t pad_len = ping->pattern_len;
  int i, max_id = 0;

  /* unset all the flags possible */
  memset(flags, 0, ping_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(ping_vars)/sizeof(warts_var_t); i++)
    {
      var = &ping_vars[i];

      if(var->id == WARTS_PING_ADDR_SRC_GID ||
	 var->id == WARTS_PING_ADDR_DST_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_PING_PATTERN_BYTES)
	{
	  flag_set(flags, WARTS_PING_PATTERN_BYTES, &max_id);
	  *params_len += pad_len;
	  continue;
	}
      else if(var->id == WARTS_PING_PROBE_SPORT ||
	      var->id == WARTS_PING_PROBE_DPORT)
	{
	  if(SCAMPER_PING_METHOD_IS_UDP(ping) == 0 &&
	     SCAMPER_PING_METHOD_IS_TCP(ping) == 0)
	    continue;
	}
      else if(var->id == WARTS_PING_USERID)
	{
	  if(ping->userid == 0)
	    continue;
	}

      flag_set(flags, var->id, &max_id);

      if(var->id == WARTS_PING_ADDR_SRC)
	{
	  *params_len += warts_addr_size(table, ping->src);
	  continue;
	}
      else if(var->id == WARTS_PING_ADDR_DST)
	{
	  *params_len += warts_addr_size(table, ping->dst);
	  continue;
	}

      assert(var->size >= 0);
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);

  return;
}

static int warts_ping_params_read(scamper_ping_t *ping, warts_state_t *state,
				  warts_addrtable_t *table,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&ping->list,          (wpr_t)extract_list,         state},
    {&ping->cycle,         (wpr_t)extract_cycle,        state},
    {&ping->src,           (wpr_t)extract_addr_gid,     state},
    {&ping->dst,           (wpr_t)extract_addr_gid,     state},
    {&ping->start,         (wpr_t)extract_timeval,      NULL},
    {&ping->stop_reason,   (wpr_t)extract_byte,         NULL},
    {&ping->stop_data,     (wpr_t)extract_byte,         NULL},
    {&ping->pattern_len,   (wpr_t)extract_uint16,       NULL},
    {&ping->pattern_bytes, (wpr_t)extract_bytes_alloc,  &ping->pattern_len},
    {&ping->probe_count,   (wpr_t)extract_uint16,       NULL},
    {&ping->probe_size,    (wpr_t)extract_uint16,       NULL},
    {&ping->probe_wait,    (wpr_t)extract_byte,         NULL},
    {&ping->probe_ttl,     (wpr_t)extract_byte,         NULL},
    {&ping->reply_count,   (wpr_t)extract_uint16,       NULL},
    {&ping->ping_sent,     (wpr_t)extract_uint16,       NULL},
    {&ping->probe_method,  (wpr_t)extract_byte,         NULL},
    {&ping->probe_sport,   (wpr_t)extract_uint16,       NULL},
    {&ping->probe_dport,   (wpr_t)extract_uint16,       NULL},
    {&ping->userid,        (wpr_t)extract_uint32,       NULL},
    {&ping->src,           (wpr_t)extract_addr,         table},
    {&ping->dst,           (wpr_t)extract_addr,         table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static int warts_ping_params_write(const scamper_ping_t *ping,
				   const scamper_file_t *sf,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   const uint8_t *flags,
				   const uint16_t flags_len,
				   const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  uint16_t pad_len = ping->pattern_len;
  warts_param_writer_t handlers[] = {
    {&list_id,             (wpw_t)insert_uint32,       NULL},
    {&cycle_id,            (wpw_t)insert_uint32,       NULL},
    {NULL,                 NULL,                       NULL},
    {NULL,                 NULL,                       NULL},
    {&ping->start,         (wpw_t)insert_timeval,      NULL},
    {&ping->stop_reason,   (wpw_t)insert_byte,         NULL},
    {&ping->stop_data,     (wpw_t)insert_byte,         NULL},
    {&ping->pattern_len,   (wpw_t)insert_uint16,       NULL},
    {&ping->pattern_bytes, (wpw_t)insert_bytes_uint16, &pad_len},
    {&ping->probe_count,   (wpw_t)insert_uint16,       NULL},
    {&ping->probe_size,    (wpw_t)insert_uint16,       NULL},
    {&ping->probe_wait,    (wpw_t)insert_byte,         NULL},
    {&ping->probe_ttl,     (wpw_t)insert_byte,         NULL},
    {&ping->reply_count,   (wpw_t)insert_uint16,       NULL},
    {&ping->ping_sent,     (wpw_t)insert_uint16,       NULL},
    {&ping->probe_method,  (wpw_t)insert_byte,         NULL},
    {&ping->probe_sport,   (wpw_t)insert_uint16,       NULL},
    {&ping->probe_dport,   (wpw_t)insert_uint16,       NULL},
    {&ping->userid,        (wpw_t)insert_uint32,       NULL},
    {ping->src,            (wpw_t)insert_addr,         table},
    {ping->dst,            (wpw_t)insert_addr,         table},
  };

  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  ping->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, ping->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

static int warts_ping_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			   scamper_ping_t **ping_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_ping_t *ping = NULL;
  uint8_t *buf = NULL;
  uint32_t off = 0;
  uint16_t i;
  scamper_ping_reply_t *reply;
  uint16_t reply_count;
  warts_addrtable_t table;

  memset(&table, 0, sizeof(table));

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *ping_out = NULL;
      return 0;
    }

  if((ping = scamper_ping_alloc()) == NULL)
    {
      goto err;
    }

  if(warts_ping_params_read(ping, state, &table, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  /* determine how many replies to read */
  if(extract_uint16(buf, &off, hdr->len, &reply_count, NULL) != 0)
    {
      goto err;
    }

  /* allocate the ping_replies array */
  if(scamper_ping_replies_alloc(ping, ping->ping_sent) != 0)
    {
      goto err;
    }

  /* if there are no replies, then we are done */
  if(reply_count == 0)
    {
      goto done;
    }

  /* for each reply, read it and insert it into the ping structure */
  for(i=0; i<reply_count; i++)
    {
      if((reply = scamper_ping_reply_alloc()) == NULL)
	{
	  goto err;
	}

      if(warts_ping_reply_read(ping,reply,state,&table,buf,&off,hdr->len) != 0)
	{
	  goto err;
	}

      if(scamper_ping_reply_append(ping, reply) != 0)
	{
	  goto err;
	}
    }

  assert(off == hdr->len);

 done:
  warts_addrtable_clean(&table);
  *ping_out = ping;
  free(buf);
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(buf != NULL) free(buf);
  if(ping != NULL) scamper_ping_free(ping);
  return -1;
}

static int warts_ping_write(const scamper_file_t *sf,
			    const scamper_ping_t *ping)
{
  warts_addrtable_t table;
  warts_ping_reply_t *reply_state = NULL;
  scamper_ping_reply_t *reply;
  uint8_t *buf = NULL;
  uint8_t  flags[ping_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t len, off = 0;
  uint16_t reply_count;
  size_t   size;
  int      i, j;

  memset(&table, 0, sizeof(table));

  /* figure out which ping data items we'll store in this record */
  warts_ping_params(ping, &table, flags, &flags_len, &params_len);

  /* length of the ping's flags, parameters, and number of reply records */
  len = flags_len + 2 + params_len + 2;

  if((reply_count = scamper_ping_reply_count(ping)) > 0)
    {
      size = reply_count * sizeof(warts_ping_reply_t);
      if((reply_state = (warts_ping_reply_t *)malloc(size)) == NULL)
	{
	  goto err;
	}

      for(i=0, j=0; i<ping->ping_sent; i++)
	{
	  for(reply=ping->ping_replies[i]; reply != NULL; reply = reply->next)
	    {
	      if(warts_ping_reply_state(sf, ping, reply, &reply_state[j++],
					&table, &len) == -1)
		{
		  goto err;
		}
	    }
	}
    }

  if((buf = malloc(len)) == NULL)
    {
      goto err;
    }

  if(warts_ping_params_write(ping, sf, &table, buf, &off, len,
			     flags, flags_len, params_len) == -1)
    {
      goto err;
    }

  /* reply record count */
  insert_uint16(buf, &off, len, &reply_count, NULL);

  /* write each ping reply record */
  for(i=0; i<reply_count; i++)
    {
      warts_ping_reply_write(&reply_state[i], &table, buf, &off, len);
    }
  if(reply_state != NULL)
    {
      free(reply_state);
      reply_state = NULL;
    }

  assert(off == len);

  if(warts_write(sf, SCAMPER_FILE_OBJ_PING, buf, len) == -1)
    {
      goto err;
    }

  warts_addrtable_clean(&table);
  free(buf);
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(buf != NULL) free(buf);
  return -1;
}

static void warts_dealias_params(const scamper_dealias_t *dealias,
				 uint8_t *flags, uint16_t *flags_len,
				 uint16_t *params_len)
{
  int max_id = 0;

  memset(flags, 0, dealias_vars_mfb);
  *params_len = 0;

  flag_set(flags, WARTS_DEALIAS_LIST_ID,  &max_id); *params_len += 4;
  flag_set(flags, WARTS_DEALIAS_CYCLE_ID, &max_id); *params_len += 4;
  flag_set(flags, WARTS_DEALIAS_START,    &max_id); *params_len += 8;
  flag_set(flags, WARTS_DEALIAS_METHOD,   &max_id); *params_len += 1;
  flag_set(flags, WARTS_DEALIAS_RESULT,   &max_id); *params_len += 1;
  flag_set(flags, WARTS_DEALIAS_PROBEC,   &max_id); *params_len += 4;

  if(dealias->userid != 0)
    {
      flag_set(flags, WARTS_DEALIAS_USERID, &max_id);
      *params_len += 4;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_dealias_params_read(scamper_dealias_t *dealias,
				     warts_state_t *state,
				     uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&dealias->list,    (wpr_t)extract_list,    state},
    {&dealias->cycle,   (wpr_t)extract_cycle,   state},
    {&dealias->start,   (wpr_t)extract_timeval, NULL},
    {&dealias->method,  (wpr_t)extract_byte,    NULL},
    {&dealias->result,  (wpr_t)extract_byte,    NULL},
    {&dealias->probec,  (wpr_t)extract_uint32,  NULL},
    {&dealias->userid,  (wpr_t)extract_uint32,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static int warts_dealias_params_write(const scamper_dealias_t *dealias,
				      const scamper_file_t *sf,
				      uint8_t *buf, uint32_t *off,
				      const uint32_t len,
				      const uint8_t *flags,
				      const uint16_t flags_len,
				      const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  warts_param_writer_t handlers[] = {
    {&list_id,          (wpw_t)insert_uint32,       NULL},
    {&cycle_id,         (wpw_t)insert_uint32,       NULL},
    {&dealias->start,   (wpw_t)insert_timeval,      NULL},
    {&dealias->method,  (wpw_t)insert_byte,         NULL},
    {&dealias->result,  (wpw_t)insert_byte,         NULL},
    {&dealias->probec,  (wpw_t)insert_uint32,       NULL},
    {&dealias->userid,  (wpw_t)insert_uint32,       NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  dealias->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, dealias->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

static int warts_dealias_probedef_params(const scamper_file_t *sf,
					 const scamper_dealias_probedef_t *p,
					 warts_dealias_probedef_t *state,
					 warts_addrtable_t *table,
					 uint32_t *len)
{
  int max_id = 0;

  memset(state->flags, 0, dealias_probedef_vars_mfb);
  state->params_len = 0;

  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_DST, &max_id);
  state->params_len += warts_addr_size(table, p->dst);
  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_SRC, &max_id);
  state->params_len += warts_addr_size(table, p->src);
  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_ID, &max_id);
  state->params_len += 4;
  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_METHOD, &max_id);
  state->params_len += 1;
  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_TTL, &max_id);
  state->params_len += 1;
  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_TOS, &max_id);
  state->params_len += 1;

  /* always include the first 4 bytes of the IP payload */
  flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_4BYTES, &max_id);
  state->params_len += 4;

  /* sometimes include icmp id/sequence number */
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(p))
    {
      flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_ICMP_ID, &max_id);
      state->params_len += 2;
    }

  /* sometimes include tcp flags */
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(p))
    {
      flag_set(state->flags, WARTS_DEALIAS_PROBEDEF_TCP_FLAGS, &max_id);
      state->params_len += 1;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  /* increase length for the probedef record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_probedef_read(scamper_dealias_probedef_t *p,
				       warts_state_t *state,
				       warts_addrtable_t *table,
				       uint8_t *buf,uint32_t *off,uint32_t len)
{
  uint8_t bytes[4]; uint16_t bytes_len = 4;
  uint16_t u16;
  uint8_t tcp_flags = 0;
  uint16_t icmpid   = 0;
  warts_param_reader_t handlers[] = {
    {&p->dst,    (wpr_t)extract_addr_gid,  state},
    {&p->src,    (wpr_t)extract_addr_gid,  state},
    {&p->id,     (wpr_t)extract_uint32,    NULL},
    {&p->method, (wpr_t)extract_byte,      NULL},
    {&p->ttl,    (wpr_t)extract_byte,      NULL},
    {&p->tos,    (wpr_t)extract_byte,      NULL},
    {bytes,      (wpr_t)extract_bytes,     &bytes_len},
    {&tcp_flags, (wpr_t)extract_byte,      NULL},
    {&icmpid,    (wpr_t)extract_uint16,    NULL},
    {&p->dst,    (wpr_t)extract_addr,      table},
    {&p->src,    (wpr_t)extract_addr,      table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(p))
    {
      p->un.icmp.type = bytes[0];
      p->un.icmp.code = bytes[1];
      memcpy(&u16, bytes+2, 2);
      p->un.icmp.csum = ntohs(u16);
      p->un.icmp.id   = icmpid;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(p))
    {
      memcpy(&u16, bytes+0, 2);
      p->un.tcp.sport = ntohs(u16);
      memcpy(&u16, bytes+2, 2);
      p->un.tcp.dport = ntohs(u16);
      p->un.tcp.flags = tcp_flags;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(p))
    {
      memcpy(&u16, bytes+0, 2);
      p->un.udp.sport = ntohs(u16);
      memcpy(&u16, bytes+2, 2);
      p->un.udp.dport = ntohs(u16);
    }
  else
    {
      return -1;
    }

  return 0;
}

static void warts_dealias_probedef_write(const scamper_dealias_probedef_t *p,
					 warts_dealias_probedef_t *state,
					 const scamper_file_t *sf,
					 warts_addrtable_t *table,
					 uint8_t *buf, uint32_t *off,
					 const uint32_t len)
{
  uint8_t bytes[4]; uint16_t bytes_len = 4;
  uint8_t tcp_flags;
  uint16_t icmpid;
  uint16_t u16;

  warts_param_writer_t handlers[] = {
    {NULL,         NULL,                        NULL},
    {NULL,         NULL,                        NULL},
    {&p->id,       (wpw_t)insert_uint32,        NULL},
    {&p->method,   (wpw_t)insert_byte,          NULL},
    {&p->ttl,      (wpw_t)insert_byte,          NULL},
    {&p->tos,      (wpw_t)insert_byte,          NULL},
    {bytes,        (wpw_t)insert_bytes_uint16, &bytes_len},
    {&tcp_flags,   (wpw_t)insert_byte,          NULL},
    {&icmpid,      (wpw_t)insert_uint16,        NULL},
    {p->dst,       (wpw_t)insert_addr,          table},
    {p->src,       (wpw_t)insert_addr,          table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(p))
    {
      bytes[0] = p->un.icmp.type;
      bytes[1] = p->un.icmp.code;
      u16 = htons(p->un.icmp.csum);
      memcpy(bytes+2, &u16, 2);
      icmpid = p->un.icmp.id;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(p))
    {
      u16 = htons(p->un.udp.sport);
      memcpy(bytes+0, &u16, 2);
      u16 = htons(p->un.udp.dport);
      memcpy(bytes+2, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(p))
    {
      u16 = htons(p->un.tcp.sport);
      memcpy(bytes+0, &u16, 2);
      u16 = htons(p->un.tcp.dport);
      memcpy(bytes+2, &u16, 2);
      tcp_flags = p->un.tcp.flags;
    }

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  return;
}

static int extract_dealias_prefixscan_xs(const uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 scamper_dealias_prefixscan_t *pfs,
					 void *param)
{
  scamper_addr_t **xs;
  uint16_t xc, i;

  if(extract_uint16(buf, off, len, &xc, NULL) != 0)
    return -1;

  if(scamper_dealias_prefixscan_xs_alloc(pfs, xc) != 0)
    return -1;

  xs = pfs->xs;
  for(i=0; i<xc; i++)
    {
      if(extract_addr(buf, off, len, &xs[i], param) != 0)
	return -1;
    }

  pfs->xs = xs;
  pfs->xc = xc;

  return 0;
}

static void insert_dealias_prefixscan_xs(uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 const scamper_dealias_prefixscan_t *p,
					 void *param)
{
  uint16_t i;

  i = htons(p->xc);
  insert_uint16(buf, off, len, &i, NULL);

  for(i=0; i<p->xc; i++)
    insert_addr(buf, off, len, p->xs[i], param);

  return;
}

static int warts_dealias_prefixscan_state(const scamper_file_t *sf,
					  const void *data,
					  warts_dealias_data_t *state,
					  warts_addrtable_t *table,
					  uint32_t *len)
{
  const scamper_dealias_prefixscan_t *p = data;
  const warts_var_t *var;
  int max_id = 0;
  uint16_t i, j;
  size_t size;

  if(p->probedefc > 0)
    {
      size = p->probedefc * sizeof(warts_dealias_probedef_t);
      if((state->probedefs = malloc_zero(size)) == NULL)
	return -1;
    }

  memset(state->flags, 0, dealias_prefixscan_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(dealias_prefixscan_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_prefixscan_vars[i];

      if(var->id == WARTS_DEALIAS_PREFIXSCAN_A)
	{
	  if(p->a != NULL)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += warts_addr_size(table, p->a);
	    }
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_B)
	{
	  if(p->b != NULL)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += warts_addr_size(table, p->b);
	    }
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_AB)
	{
	  if(p->ab != NULL)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += warts_addr_size(table, p->ab);
	    }
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_XS)
	{
	  if(p->xc > 0)
	    {
	      flag_set(state->flags, var->id, &max_id);
	      state->params_len += 2;
	      for(j=0; j<p->xc; j++)
		state->params_len += warts_addr_size(table, p->xs[j]);
	    }
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_PROBEDEFC)
	{
	  if(p->probedefc == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_FLAGS)
	{
	  if(p->flags == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_PREFIXSCAN_REPLYC)
	{
	  if(p->replyc == 5)
	    continue;
	}

      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  for(i=0; i<p->probedefc; i++)
    {
      if(warts_dealias_probedef_params(sf, &p->probedefs[i],
				       &state->probedefs[i], table, len) != 0)
	{
	  return -1;
	}
    }

  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_prefixscan_read(scamper_dealias_t *dealias,
					 warts_state_t *state,
					 warts_addrtable_t *table,
					 scamper_dealias_probedef_t **defs,
					 uint8_t *buf, uint32_t *off,
					 uint32_t len)
{
  scamper_dealias_prefixscan_t pfs, *p;
  warts_param_reader_t handlers[] = {
    {&pfs.a,            (wpr_t)extract_addr,                  table},
    {&pfs.b,            (wpr_t)extract_addr,                  table},
    {&pfs.ab,           (wpr_t)extract_addr,                  table},
    {&pfs,              (wpr_t)extract_dealias_prefixscan_xs, table},
    {&pfs.prefix,       (wpr_t)extract_byte,                  NULL},
    {&pfs.attempts,     (wpr_t)extract_byte,                  NULL},
    {&pfs.fudge,        (wpr_t)extract_uint16,                NULL},
    {&pfs.wait_probe,   (wpr_t)extract_uint16,                NULL},
    {&pfs.wait_timeout, (wpr_t)extract_byte,                  NULL},
    {&pfs.probedefc,    (wpr_t)extract_uint16,                NULL},
    {&pfs.flags,        (wpr_t)extract_byte,                  NULL},
    {&pfs.replyc,       (wpr_t)extract_byte,                  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint32_t o = *off;
  uint16_t i;

  memset(&pfs, 0, sizeof(pfs));
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(scamper_dealias_prefixscan_alloc(dealias) != 0)
    return -1;

  p = dealias->data;
  memcpy(p, &pfs, sizeof(pfs));

  /* by default we require five replies before inferring an alias */
  if(flag_isset(&buf[o], WARTS_DEALIAS_PREFIXSCAN_REPLYC) == 0)
    p->replyc = 5;

  if(p->probedefc > 0)
    {
      if(scamper_dealias_prefixscan_probedefs_alloc(p, p->probedefc) != 0)
	return -1;

      for(i=0; i<p->probedefc; i++)
	{
	  if(warts_dealias_probedef_read(&p->probedefs[i], state, table,
					 buf, off, len) != 0)
	    return -1;
	}
    }

  *defs = p->probedefs;
  return 0;
}

static void warts_dealias_prefixscan_write(const void *data,
					   const scamper_file_t *sf,
					   warts_addrtable_t *table,
					   uint8_t *buf, uint32_t *off,
					   const uint32_t len,
					   warts_dealias_data_t *state)
{
  const scamper_dealias_prefixscan_t *prefixscan = data;
  warts_param_writer_t handlers[] = {
    {prefixscan->a,             (wpw_t)insert_addr,                  table},
    {prefixscan->b,             (wpw_t)insert_addr,                  table},
    {prefixscan->ab,            (wpw_t)insert_addr,                  table},
    {prefixscan,                (wpw_t)insert_dealias_prefixscan_xs, table},
    {&prefixscan->prefix,       (wpw_t)insert_byte,                  NULL},
    {&prefixscan->attempts,     (wpw_t)insert_byte,                  NULL},
    {&prefixscan->fudge,        (wpw_t)insert_uint16,                NULL},
    {&prefixscan->wait_probe,   (wpw_t)insert_uint16,                NULL},
    {&prefixscan->wait_timeout, (wpw_t)insert_byte,                  NULL},
    {&prefixscan->probedefc,    (wpw_t)insert_uint16,                NULL},
    {&prefixscan->flags,        (wpw_t)insert_byte,                  NULL},
    {&prefixscan->replyc,       (wpw_t)insert_byte,                  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint32_t i;

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  for(i=0; i<prefixscan->probedefc; i++)
    {
      warts_dealias_probedef_write(&prefixscan->probedefs[i],
				   &state->probedefs[i],
				   sf, table, buf, off, len);
    }

  return;
}

static int warts_dealias_radargun_state(const scamper_file_t *sf,
					const void *data,
					warts_dealias_data_t *state,
					warts_addrtable_t *table, uint32_t *len)
{
  const scamper_dealias_radargun_t *rg = data;
  int max_id = 0;
  size_t size;
  uint32_t i;

  if(rg->probedefc == 0)
    return -1;

  size = rg->probedefc * sizeof(warts_dealias_probedef_t);
  if((state->probedefs = malloc_zero(size)) == NULL)
    return -1;

  memset(state->flags, 0, dealias_radargun_vars_mfb);
  state->params_len = 0;

  flag_set(state->flags, WARTS_DEALIAS_RADARGUN_PROBEDEFC, &max_id);
  state->params_len += 4;
  flag_set(state->flags, WARTS_DEALIAS_RADARGUN_ATTEMPTS, &max_id);
  state->params_len += 2;
  flag_set(state->flags, WARTS_DEALIAS_RADARGUN_WAIT_PROBE, &max_id);
  state->params_len += 2;
  flag_set(state->flags, WARTS_DEALIAS_RADARGUN_WAIT_ROUND, &max_id);
  state->params_len += 4;
  flag_set(state->flags, WARTS_DEALIAS_RADARGUN_WAIT_TIMEOUT, &max_id);
  state->params_len += 1;

  state->flags_len = fold_flags(state->flags, max_id);

  for(i=0; i<rg->probedefc; i++)
    {
      if(warts_dealias_probedef_params(sf, &rg->probedefs[i],
				       &state->probedefs[i], table, len) != 0)
	{
	  return -1;
	}
    }

  /* increase length required for the radargun record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_radargun_read(scamper_dealias_t *dealias,
				       warts_state_t *state,
				       warts_addrtable_t *table,
				       scamper_dealias_probedef_t **defs,
				       uint8_t *buf,uint32_t *off,uint32_t len)
{
  scamper_dealias_radargun_t *rg;
  uint32_t probedefc = 0;
  uint16_t attempts = 0;
  uint16_t wait_probe = 0;
  uint32_t wait_round = 0;
  uint8_t  wait_timeout = 0;
  uint32_t i;
  warts_param_reader_t handlers[] = {
    {&probedefc,    (wpr_t)extract_uint32, NULL},
    {&attempts,     (wpr_t)extract_uint16, NULL},
    {&wait_probe,   (wpr_t)extract_uint16, NULL},
    {&wait_round,   (wpr_t)extract_uint32, NULL},
    {&wait_timeout, (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_dealias_radargun_alloc(dealias) != 0)
    return -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  rg = dealias->data;
  if(scamper_dealias_radargun_probedefs_alloc(rg, probedefc) != 0)
    return -1;

  rg->probedefc    = probedefc;
  rg->attempts     = attempts;  
  rg->wait_probe   = wait_probe;
  rg->wait_round   = wait_round;
  rg->wait_timeout = wait_timeout;

  for(i=0; i<probedefc; i++)
    {
      if(warts_dealias_probedef_read(&rg->probedefs[i], state, table,
				     buf, off, len) != 0)
	return -1;
    }

  *defs = rg->probedefs;
  return 0;
}

static void warts_dealias_radargun_write(const void *data,
					 const scamper_file_t *sf,
					 warts_addrtable_t *table,
					 uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 warts_dealias_data_t *state)
{
  const scamper_dealias_radargun_t *rg = data;
  warts_param_writer_t handlers[] = {
    {&rg->probedefc,    (wpw_t)insert_uint32, NULL},
    {&rg->attempts,     (wpw_t)insert_uint16, NULL},
    {&rg->wait_probe,   (wpw_t)insert_uint16, NULL},
    {&rg->wait_round,   (wpw_t)insert_uint32, NULL},
    {&rg->wait_timeout, (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint32_t i;

  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  for(i=0; i<rg->probedefc; i++)
    {
      warts_dealias_probedef_write(&rg->probedefs[i], &state->probedefs[i],
				   sf, table, buf, off, len);
    }

  return;
}

static int warts_dealias_ally_state(const scamper_file_t *sf, const void *data,
				    warts_dealias_data_t *state,
				    warts_addrtable_t *table, uint32_t *len)
{
  const scamper_dealias_ally_t *ally = data;
  int max_id = 0;
  size_t size = sizeof(warts_dealias_probedef_t) * 2;

  if((state->probedefs = malloc_zero(size)) == NULL)
    return -1;

  memset(state->flags, 0, dealias_ally_vars_mfb);
  state->params_len = 0;

  flag_set(state->flags, WARTS_DEALIAS_ALLY_WAIT_PROBE, &max_id);
  state->params_len += 2;
  flag_set(state->flags, WARTS_DEALIAS_ALLY_WAIT_TIMEOUT, &max_id);
  state->params_len += 1;
  flag_set(state->flags, WARTS_DEALIAS_ALLY_ATTEMPTS, &max_id);
  state->params_len += 1;
  flag_set(state->flags, WARTS_DEALIAS_ALLY_FUDGE, &max_id);
  state->params_len += 2;

  if(ally->flags != 0)
    {
      flag_set(state->flags, WARTS_DEALIAS_ALLY_FLAGS, &max_id);
      state->params_len += 1;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  if(warts_dealias_probedef_params(sf, &ally->probedefs[0],
				   &state->probedefs[0], table, len) != 0 ||
     warts_dealias_probedef_params(sf, &ally->probedefs[1],
				   &state->probedefs[1], table, len) != 0)
    {
      return -1;
    }

  /* increase length required for the ally record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_ally_read(scamper_dealias_t *dealias,
				   warts_state_t *state,
				   warts_addrtable_t *table,
				   scamper_dealias_probedef_t **defs,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  scamper_dealias_ally_t *ally;
  uint16_t wait_probe = 0;
  uint8_t  wait_timeout = 0;
  uint8_t  attempts = 0;
  uint16_t fudge = 0;
  uint8_t  flags = 0;
  warts_param_reader_t handlers[] = {
    {&wait_probe,   (wpr_t)extract_uint16, NULL},
    {&wait_timeout, (wpr_t)extract_byte,   NULL},
    {&attempts,     (wpr_t)extract_byte,   NULL},
    {&fudge,        (wpr_t)extract_uint16, NULL},
    {&flags,        (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_dealias_ally_alloc(dealias) != 0)
    return -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  ally = dealias->data;
  ally->wait_probe   = wait_probe;
  ally->wait_timeout = wait_timeout;
  ally->attempts     = attempts;
  ally->fudge        = fudge;
  ally->flags        = flags;

  if(warts_dealias_probedef_read(&ally->probedefs[0], state, table,
				 buf, off, len) != 0 ||
     warts_dealias_probedef_read(&ally->probedefs[1], state, table,
				 buf, off, len) != 0)
    {
      return -1;
    }

  *defs = ally->probedefs;
  return 0;
}

static void warts_dealias_ally_write(const void *data,
				     const scamper_file_t *sf,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     warts_dealias_data_t *state)
{
  const scamper_dealias_ally_t *ally = data;
  warts_param_writer_t handlers[] = {
    {&ally->wait_probe,   (wpw_t)insert_uint16, NULL},
    {&ally->wait_timeout, (wpw_t)insert_byte,   NULL},
    {&ally->attempts,     (wpw_t)insert_byte,   NULL},
    {&ally->fudge,        (wpw_t)insert_uint16, NULL},
    {&ally->flags,        (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  warts_dealias_probedef_write(&ally->probedefs[0], &state->probedefs[0],
			       sf, table, buf, off, len);
  warts_dealias_probedef_write(&ally->probedefs[1], &state->probedefs[1],
			       sf, table, buf, off, len);
  return;
}

static int warts_dealias_mercator_state(const scamper_file_t *sf,
					const void *data,
					warts_dealias_data_t *state,
					warts_addrtable_t *table,uint32_t *len)
{
  const scamper_dealias_mercator_t *m = data;
  int max_id = 0;
  size_t size = sizeof(warts_dealias_probedef_t);

  if((state->probedefs = malloc_zero(size)) == NULL)
    return -1;

  assert(sizeof(state->flags) >= dealias_mercator_vars_mfb);

  memset(state->flags, 0, dealias_mercator_vars_mfb);
  state->params_len = 0;

  flag_set(state->flags, WARTS_DEALIAS_MERCATOR_ATTEMPTS, &max_id);
  state->params_len += 1;
  flag_set(state->flags, WARTS_DEALIAS_MERCATOR_WAIT_TIMEOUT, &max_id);
  state->params_len += 1;

  state->flags_len = fold_flags(state->flags, max_id);

  if(warts_dealias_probedef_params(sf, &m->probedef, &state->probedefs[0],
				   table, len) != 0)
    {
      return -1;
    }

  /* increase length required for the mercator record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_mercator_read(scamper_dealias_t *dealias,
				       warts_state_t *state,
				       warts_addrtable_t *table,
				       scamper_dealias_probedef_t **def,
				       uint8_t *buf, uint32_t *off,
				       uint32_t len)
{
  scamper_dealias_mercator_t *mercator;
  uint8_t attempts = 0;
  uint8_t wait_timeout = 0;
  warts_param_reader_t handlers[] = {
    {&attempts,     (wpr_t)extract_byte,   NULL},
    {&wait_timeout, (wpr_t)extract_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(scamper_dealias_mercator_alloc(dealias) != 0)
    return -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  mercator = dealias->data;
  mercator->attempts     = attempts;
  mercator->wait_timeout = wait_timeout;

  if(warts_dealias_probedef_read(&mercator->probedef, state, table,
				 buf, off, len) != 0)
    {
      return -1;
    }

  *def = &mercator->probedef;
  return 0;
}

static void warts_dealias_mercator_write(const void *data,
					 const scamper_file_t *sf,
					 warts_addrtable_t *table,
					 uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 warts_dealias_data_t *state)
{
  const scamper_dealias_mercator_t *m = data;
  warts_param_writer_t handlers[] = {
    {&m->attempts,     (wpw_t)insert_byte,   NULL},
    {&m->wait_timeout, (wpw_t)insert_byte,   NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  warts_dealias_probedef_write(&m->probedef, &state->probedefs[0], sf, table,
			       buf, off, len);
  return;
}

static int extract_dealias_reply_icmptc(const uint8_t *buf, uint32_t *off,
					uint32_t len,
					scamper_dealias_reply_t *reply,
					void *param)
{
  if(len - *off < 2)
    {
      return -1;
    }
  reply->icmp_type = buf[(*off)++];
  reply->icmp_code = buf[(*off)++];
  return 0;
}

static void insert_dealias_reply_icmptc(uint8_t *buf, uint32_t *off,
					const uint32_t len,
					const scamper_dealias_reply_t *reply,
					void *param)
{
  assert(len - *off >= 2);
  buf[(*off)++] = reply->icmp_type;
  buf[(*off)++] = reply->icmp_code;
  return;
}

static int extract_dealias_reply_icmpext(const uint8_t *buf, uint32_t *off,
					 uint32_t len,
					 scamper_dealias_reply_t *reply,
					 void *param)
{
  return warts_icmpext_read(buf, off, len, &reply->icmp_ext);
}

static void insert_dealias_reply_icmpext(uint8_t *buf, uint32_t *off,
					 const uint32_t len,
					 const scamper_dealias_reply_t *reply,
					 void *param)
{
  warts_icmpext_write(buf, off, len, reply->icmp_ext);
  return;
}

static int warts_dealias_reply_state(const scamper_dealias_reply_t *reply,
				     warts_dealias_reply_t *state,
				     const scamper_file_t *sf,
				     warts_addrtable_t *table, uint32_t *len)
{
  const warts_var_t *var;
  scamper_icmpext_t *ie;
  int i, max_id = 0;

  memset(state->flags, 0, dealias_reply_vars_mfb);
  state->params_len = 0;

  /* encode any icmp extensions included */
  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply) && reply->icmp_ext != NULL)
    {
      flag_set(state->flags, WARTS_DEALIAS_REPLY_ICMP_EXT, &max_id);
      state->params_len += 2;

      for(ie = reply->icmp_ext; ie != NULL; ie = ie->ie_next)
	{
	  state->params_len += (2 + 1 + 1 + ie->ie_dl);
	}
    }

  for(i=0; i<sizeof(dealias_reply_vars)/sizeof(warts_var_t); i++)
    {
      var = &dealias_reply_vars[i];

      if(var->id == WARTS_DEALIAS_REPLY_SRC_GID)
	{
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_ICMP_TC)
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply) == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_ICMP_Q_TTL)
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply) == 0)
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_ICMP_EXT)
	{
	  continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_PROTO)
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply))
	    continue;
	}
      else if(var->id == WARTS_DEALIAS_REPLY_TCP_FLAGS)
	{
	  if(SCAMPER_DEALIAS_REPLY_IS_TCP(reply) == 0)
	    continue;
	}

      flag_set(state->flags, var->id, &max_id);

      if(var->id == WARTS_DEALIAS_REPLY_SRC)
	{
	  state->params_len += warts_addr_size(table, reply->src);
	  continue;
	}

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);

  /* increase length required for the dealias reply record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_reply_read(scamper_dealias_reply_t *reply,
				    warts_state_t *state,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&reply->src,           (wpr_t)extract_addr_gid,              state},
    {&reply->rx,            (wpr_t)extract_timeval,               NULL},
    {&reply->ipid,          (wpr_t)extract_uint16,                NULL},
    {&reply->ttl,           (wpr_t)extract_byte,                  NULL},
    {reply,                 (wpr_t)extract_dealias_reply_icmptc,  NULL},
    {&reply->icmp_q_ip_ttl, (wpr_t)extract_byte,                  NULL},
    {reply,                 (wpr_t)extract_dealias_reply_icmpext, NULL},
    {&reply->proto,         (wpr_t)extract_byte,                  NULL},
    {&reply->tcp_flags,     (wpr_t)extract_byte,                  NULL},
    {&reply->src,           (wpr_t)extract_addr,                  table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  uint32_t o = *off;
  int i;

  if((i = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return i;

  if(flag_isset(&buf[o], WARTS_DEALIAS_REPLY_PROTO) == 0)
    {
      if(reply->src->type == SCAMPER_ADDR_TYPE_IPV4)
	reply->proto = IPPROTO_ICMP;
      else
	reply->proto = IPPROTO_ICMPV6;
    }

  return i;
}

static int warts_dealias_reply_write(const scamper_dealias_reply_t *r,
				     const scamper_file_t *sf,
				     warts_addrtable_t *table,
				     uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     warts_dealias_reply_t *state)
{
  warts_param_writer_t handlers[] = {
    {NULL,              NULL,                                NULL},
    {&r->rx,            (wpw_t)insert_timeval,               NULL},
    {&r->ipid,          (wpw_t)insert_uint16,                NULL},
    {&r->ttl,           (wpw_t)insert_byte,                  NULL},
    {r,                 (wpw_t)insert_dealias_reply_icmptc,  NULL},
    {&r->icmp_q_ip_ttl, (wpw_t)insert_byte,                  NULL},
    {r,                 (wpw_t)insert_dealias_reply_icmpext, NULL},
    {&r->proto,         (wpw_t)insert_byte,                  NULL},
    {&r->tcp_flags,     (wpw_t)insert_byte,                  NULL},
    {r->src,            (wpw_t)insert_addr,                  table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);
  return 0;
}

static int warts_dealias_probe_state(const scamper_file_t *sf,
				     const scamper_dealias_probe_t *probe,
				     warts_dealias_probe_t *state,
				     warts_addrtable_t *table, uint32_t *len)
{
  int i = 0;
  size_t size;

  memset(state->flags, 0, dealias_probe_vars_mfb);
  state->params_len = 0;

  flag_set(state->flags, WARTS_DEALIAS_PROBE_DEF, &i);
  state->params_len += 4;
  flag_set(state->flags, WARTS_DEALIAS_PROBE_TX, &i);
  state->params_len += 8;
  flag_set(state->flags, WARTS_DEALIAS_PROBE_REPLYC, &i);
  state->params_len += 2;
  flag_set(state->flags, WARTS_DEALIAS_PROBE_IPID, &i);
  state->params_len += 2;
  flag_set(state->flags, WARTS_DEALIAS_PROBE_SEQ, &i);
  state->params_len += 4;

  state->flags_len = fold_flags(state->flags, i);
  state->replies = NULL;

  if(probe->replyc > 0)
    {
      size = sizeof(warts_dealias_reply_t) * probe->replyc;
      if((state->replies = malloc_zero(size)) == NULL)
	return -1;

      for(i=0; i<probe->replyc; i++)
	{
	  if(warts_dealias_reply_state(probe->replies[i], &state->replies[i],
				       sf, table, len) != 0)
	    {
	      free(state->replies);
	      state->replies = NULL;
	      return -1;
	    }
	}
    }

  /* increase length required for the probe record */
  *len += state->flags_len + state->params_len;
  if(state->params_len != 0) *len += 2;

  return 0;
}

static int warts_dealias_probe_read(scamper_dealias_probe_t *probe,
				    warts_state_t *state,
				    scamper_dealias_probedef_t *defs,
				    warts_addrtable_t *table,
				    uint8_t *buf, uint32_t *off, uint32_t len)
{
  int i;
  uint32_t probedef_id;
  warts_param_reader_t handlers[] = {
    {&probedef_id,   (wpr_t)extract_uint32,  NULL},
    {&probe->tx,     (wpr_t)extract_timeval, NULL},
    {&probe->replyc, (wpr_t)extract_uint16,  NULL},
    {&probe->ipid,   (wpr_t)extract_uint16,  NULL},
    {&probe->seq,    (wpr_t)extract_uint32,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_dealias_reply_t *reply;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    {
      return -1;
    }

  probe->probedef = defs + probedef_id;

  if(probe->replyc == 0)
    return 0;

  if(scamper_dealias_replies_alloc(probe, probe->replyc) != 0)
    {
      return -1;
    }

  for(i=0; i<probe->replyc; i++)
    {
      if((reply = scamper_dealias_reply_alloc()) == NULL)
	{
	  return -1;
	}
      probe->replies[i] = reply;

      if(warts_dealias_reply_read(reply, state, table, buf, off, len) != 0)
	{
	  return -1;
	}
    }

  return 0;
}

static void warts_dealias_probe_write(const scamper_dealias_probe_t *probe,
				      const scamper_file_t *sf,
				      warts_addrtable_t *table,
				      uint8_t *buf, uint32_t *off,
				      const uint32_t len,
				      warts_dealias_probe_t *state)
{
  int i;
  warts_param_writer_t handlers[] = {
    {&probe->probedef->id, (wpw_t)insert_uint32,  NULL},
    {&probe->tx,           (wpw_t)insert_timeval, NULL},
    {&probe->replyc,       (wpw_t)insert_uint16,  NULL},
    {&probe->ipid,         (wpw_t)insert_uint16,  NULL},
    {&probe->seq,          (wpw_t)insert_uint32,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len,
		     state->flags, state->flags_len, state->params_len,
		     handlers, handler_cnt);

  for(i=0; i<probe->replyc; i++)
    {
      warts_dealias_reply_write(probe->replies[i], sf, table, buf, off, len,
				&state->replies[i]);
    }

  return;
}

static int warts_dealias_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			      scamper_dealias_t **dealias_out)
{
  static int (*const read[])(scamper_dealias_t *,warts_state_t *,
			     warts_addrtable_t *,scamper_dealias_probedef_t **,
			     uint8_t *, uint32_t *, uint32_t) = {
    warts_dealias_mercator_read,
    warts_dealias_ally_read,
    warts_dealias_radargun_read,
    warts_dealias_prefixscan_read,
  };
  scamper_dealias_t *dealias = NULL;
  scamper_dealias_probedef_t *defs;
  scamper_dealias_probe_t *probe;
  warts_addrtable_t table;
  warts_state_t *state = scamper_file_getstate(sf);
  uint8_t *buf = NULL;
  uint32_t off = 0;
  uint16_t i;

  memset(&table, 0, sizeof(table));

  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }
  if(buf == NULL)
    {
      *dealias_out = NULL;
      return 0;
    }

  if((dealias = scamper_dealias_alloc()) == NULL)
    {
      goto err;
    }

  if(warts_dealias_params_read(dealias, state, buf, &off, hdr->len) != 0)
    {
      goto err;
    }

  if(read[dealias->method-1](dealias,state,&table,&defs,buf,&off,hdr->len)!=0)
    goto err;

  if(dealias->probec == 0)
    goto done;

  if(scamper_dealias_probes_alloc(dealias, dealias->probec) != 0)
    {
      goto err;
    }

  for(i=0; i<dealias->probec; i++)
    {
      if((probe = scamper_dealias_probe_alloc()) == NULL)
	{
	  goto err;
	}
      dealias->probes[i] = probe;

      if(warts_dealias_probe_read(probe, state, defs, &table,
				  buf, &off, hdr->len) != 0)
	{
	  goto err;
	}
    }

 done:
  assert(off == hdr->len);
  warts_addrtable_clean(&table);
  *dealias_out = dealias;
  free(buf);
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(buf != NULL) free(buf);
  if(dealias != NULL) scamper_dealias_free(dealias);
  return -1;
}

static void warts_dealias_probes_free(warts_dealias_probe_t *probes,
				      uint32_t cnt)
{
  uint32_t i;

  if(probes != NULL)
    {
      for(i=0; i<cnt; i++)
	{
	  free(probes[i].replies);
	}
      free(probes);
    }

  return;
}

static int warts_dealias_write(const scamper_file_t *sf,
			       const scamper_dealias_t *dealias)
{
  static int (*const state[])(const scamper_file_t *, const void *,
			      warts_dealias_data_t *, warts_addrtable_t *,
			      uint32_t *) = {
    warts_dealias_mercator_state,
    warts_dealias_ally_state,    
    warts_dealias_radargun_state,
    warts_dealias_prefixscan_state,
  };
  static void (*const write[])(const void *, const scamper_file_t *,
			       warts_addrtable_t *, uint8_t *, uint32_t *,
			       const uint32_t, warts_dealias_data_t *) = {
    warts_dealias_mercator_write,
    warts_dealias_ally_write,
    warts_dealias_radargun_write,
    warts_dealias_prefixscan_write,
  };
  uint8_t                 *buf = NULL;
  uint8_t                  flags[dealias_vars_mfb];
  uint16_t                 flags_len, params_len;
  scamper_dealias_probe_t *probe;
  warts_dealias_data_t     data;
  warts_dealias_probe_t   *probes = NULL;
  uint32_t                 len, len2, off;
  size_t                   size;
  uint32_t                 i;
  warts_addrtable_t        table;

  memset(&data, 0, sizeof(data));
  memset(&table, 0, sizeof(table));

  /* figure out which dealias data items we'll store in this record */
  warts_dealias_params(dealias, flags, &flags_len, &params_len);
  len = flags_len + params_len + 2;

  /* figure out the state that we have to allocate */
  if(state[dealias->method-1](sf, dealias->data, &data, &table, &len) != 0)
     {
       goto err;
     }

  /*
   * figure out the state that we have to allocate to store the
   * probes sent (and their responses)
   */
  if(dealias->probec > 0)
    {
      size = dealias->probec * sizeof(warts_dealias_probe_t);
      if((probes = (warts_dealias_probe_t *)malloc_zero(size)) == NULL)
	{
	  goto err;
	}

      for(i=0; i<dealias->probec; i++)
	{
	  probe = dealias->probes[i];
	  len2 = len;
	  if(warts_dealias_probe_state(sf,probe,&probes[i],&table,&len2) != 0)
	    goto err;
	  if(len2 < len)
	    goto err;
	  len = len2;
	}
    }

  if((buf = malloc(len)) == NULL)
    goto err;
  off = 0;

  if(warts_dealias_params_write(dealias, sf, buf, &off, len,
				flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  write[dealias->method-1](dealias->data, sf, &table, buf, &off, len, &data);

  if(data.probedefs != NULL)
    free(data.probedefs);
  data.probedefs = NULL;

  if(dealias->probec > 0)
    {
      for(i=0; i<dealias->probec; i++)
	{
	  probe = dealias->probes[i];
	  warts_dealias_probe_write(probe,sf,&table,buf,&off, len, &probes[i]);
	}
    }

  warts_dealias_probes_free(probes, dealias->probec);
  probes = NULL;

  assert(off == len);

  if(warts_write(sf, SCAMPER_FILE_OBJ_DEALIAS, buf, len) == -1)
    {
      goto err;
    }

  warts_addrtable_clean(&table);
  free(buf);
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(probes != NULL) warts_dealias_probes_free(probes, dealias->probec);
  if(data.probedefs != NULL) free(data.probedefs);
  if(buf != NULL) free(buf);
  return -1;
}

/*
 * scamper_file_warts_read
 *
 */
int scamper_file_warts_read(scamper_file_t *sf, scamper_file_filter_t *filter,
			    uint16_t *type, void **data)
{
  warts_state_t   *state = scamper_file_getstate(sf);
  scamper_list_t  *list;
  scamper_cycle_t *cycle;
  scamper_addr_t  *addr;
  warts_hdr_t      hdr;
  int              fd;
  int              isfilter;
  int              tmp;
  uint8_t         *buf;
  char             offs[16];

  fd = scamper_file_getfd(sf);

  for(;;)
    {
      /*
       * check to see if the previous read got a warts header but not
       * the payload
       */
      if(state->hdr_type == 0)
	{
	  /* read the header for the next record from the file */
	  if((tmp = warts_hdr_read(sf, &hdr)) == 0)
	    {
	      *data = NULL;
	      break;
	    }
	  else if(tmp == -1)
	    {
	      /* partial record */
	      return -1;
	    }

	  /* if the header does not pass a basic sanity check, then give up */
	  if(hdr.magic != WARTS_MAGIC || hdr.type == 0)
	    {
	      goto err;
	    }
	}
      else
	{
	  hdr.type = state->hdr_type;
	  hdr.len  = state->hdr_len;
	}

      /* does the caller wants to know about this type? */
      if((isfilter = scamper_file_filter_isset(filter, hdr.type)) == 1)
	{
	  *type = hdr.type;
	}

      *data = NULL;

      if(hdr.type == SCAMPER_FILE_OBJ_ADDR)
	{
	  if(warts_addr_read(sf, &hdr, &addr) != 0)
	    goto err;

	  if(addr != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	      if(isfilter == 1)
		{
		  *data = scamper_addr_use(addr);
		  break;
		}
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	      break;
	    }
	}
      else if(hdr.type == SCAMPER_FILE_OBJ_LIST)
	{
	  if(warts_list_read(sf, &hdr, &list) != 0)
	    goto err;

	  if(list != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	      if(isfilter == 1)
		{
		  *data = scamper_list_use(list);
		  break;
		}
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	      break;
	    }
	}
      else if(hdr.type == SCAMPER_FILE_OBJ_CYCLE_DEF ||
	      hdr.type == SCAMPER_FILE_OBJ_CYCLE_START)
	{
	  if(warts_cycle_read(sf, &hdr, &cycle) != 0)
	    goto err;

	  if(cycle != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	      if(isfilter == 1)
		{
		  *data = scamper_cycle_use(cycle);
		  break;
		}
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	      break;
	    }
	}
      else if(hdr.type == SCAMPER_FILE_OBJ_CYCLE_STOP)
	{
	  if(warts_cycle_stop_read(sf, &hdr, &cycle) != 0)
	    goto err;

	  if(cycle != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	      if(isfilter == 1)
		{
		  *data = cycle;
		  break;
		}
	      else
		{
		  scamper_cycle_free(cycle);
		}
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	      break;
	    }
	}
      else if(isfilter == 0)
	{
	  /* reader doesn't care what the data is, and neither do we */
	  if(warts_read(sf, &buf, hdr.len) != 0)
	    goto err;

	  if(buf != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	      free(buf);
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	      break;
	    }
	}
      else if(hdr.type == SCAMPER_FILE_OBJ_TRACE)
	{
	  if(warts_trace_read(sf, &hdr, (scamper_trace_t **)data) != 0)
	    {
	      goto err;
	    }

	  if(*data != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	    }

	  break;
	}
      else if(hdr.type == SCAMPER_FILE_OBJ_PING)
	{
	  if(warts_ping_read(sf, &hdr, (scamper_ping_t **)data) != 0)
	    {
	      goto err;
	    }

	  if(*data != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	    }

	  break;
	}
      else if(hdr.type == SCAMPER_FILE_OBJ_TRACELB)
	{
	  if(warts_tracelb_read(sf, &hdr, (scamper_tracelb_t **)data) != 0)
	    {
	      goto err;
	    }

	  if(*data != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	    }

	  break;
	}
      else if(hdr.type == SCAMPER_FILE_OBJ_DEALIAS)
	{
	  if(warts_dealias_read(sf, &hdr, (scamper_dealias_t **)data) != 0)
	    goto err;

	  if(*data != NULL)
	    {
	      state->hdr_type = 0; state->hdr_len = 0;
	    }
	  else
	    {
	      state->hdr_type = hdr.type;
	      state->hdr_len  = hdr.len;
	    }

	  break;
	}
      else
	{
	  /* we don't know about this object */
	  return -1;
	}
    }

  return 0;

 err:
  fprintf(stderr,
	  "off 0x%s magic 0x%04x type 0x%04x len 0x%08x\n",
	  offt_tostr(offs, sizeof(offs), state->off, 8, 'x'),
	  hdr.magic, hdr.type, hdr.len);
  return -1;
}

int scamper_file_warts_write_ping(const scamper_file_t *sf,
				  const scamper_ping_t *ping)
{
  return warts_ping_write(sf, ping);
}

int scamper_file_warts_write_trace(const scamper_file_t *sf,
				   const scamper_trace_t *trace)
{
  return warts_trace_write(sf, trace);
}

int scamper_file_warts_write_tracelb(const scamper_file_t *sf,
				     const scamper_tracelb_t *tracelb)
{
  return warts_tracelb_write(sf, tracelb);
}

int scamper_file_warts_write_dealias(const scamper_file_t *sf,
				     const scamper_dealias_t *dealias)
{
  return warts_dealias_write(sf, dealias);
}

int scamper_file_warts_write_cycle_start(const scamper_file_t *sf,
					 scamper_cycle_t *c)
{
  return warts_cycle_write(sf, c, SCAMPER_FILE_OBJ_CYCLE_START, NULL);
}

int scamper_file_warts_write_cycle_stop(const scamper_file_t *sf,
					scamper_cycle_t *c)
{
  return warts_cycle_stop_write(sf, c);
}

/*
 * scamper_file_warts_init_read
 *
 * initialise the scamper_file_t's state structure so that it is all set
 * for reading.  the first entry of the list and cycle tables is pre-set
 * to be null for data objects that don't have associated list/cycle
 * objects.
 */
int scamper_file_warts_init_read(scamper_file_t *sf)
{
  warts_state_t *state;
  size_t size;

  if((state = (warts_state_t *)malloc_zero(sizeof(warts_state_t))) == NULL)
    {
      goto err;
    }

  size = sizeof(scamper_addr_t *) * WARTS_ADDR_TABLEGROW;
  if((state->addr_table = malloc(size)) == NULL)
    {
      goto err;
    }
  state->addr_table[0] = NULL;
  state->addr_count = 1;

  size = sizeof(warts_list_t *) * WARTS_LIST_TABLEGROW;
  if((state->list_table = malloc(size)) == NULL)
    {
      goto err;
    }
  state->list_table[0] = &state->list_null;
  state->list_count = 1;

  size = sizeof(warts_cycle_t *) * WARTS_CYCLE_TABLEGROW;
  if((state->cycle_table = malloc(size)) == NULL)
    {
      goto err;
    }
  state->cycle_table[0] = &state->cycle_null;
  state->cycle_count = 1;

  scamper_file_setstate(sf, state);
  return 0;

 err:
  if(state != NULL)
    {
      if(state->addr_table != NULL) free(state->addr_table);
      if(state->list_table != NULL) free(state->list_table);
      if(state->cycle_table != NULL) free(state->cycle_table);
      free(state);
    }
  return -1;
}

/*
 * scamper_file_warts_init_write
 *
 * get the scamper_file_t object ready to write warts objects and keep state
 */
int scamper_file_warts_init_write(scamper_file_t *sf)
{
  warts_state_t *state = NULL;

  if((state = (warts_state_t *)malloc_zero(sizeof(warts_state_t))) == NULL)
    {
      goto err;
    }

  if((state->list_tree = splaytree_alloc(warts_list_cmp)) == NULL)
    {
      goto err;
    }
  state->list_count = 1;

  if((state->cycle_tree = splaytree_alloc(warts_cycle_cmp)) == NULL)
    {
      goto err;
    }
  state->cycle_count = 1;

  scamper_file_setstate(sf, state);

  return 0;

 err:
  if(state != NULL)
    {
      if(state->list_tree != NULL)  splaytree_free(state->list_tree, NULL);
      if(state->cycle_tree != NULL) splaytree_free(state->cycle_tree, NULL);
      free(state);
    }
  return -1;
}

/*
 * scamper_file_warts_init_append
 *
 * go through the file and form the address, list, and cycle dictionaries
 */
int scamper_file_warts_init_append(scamper_file_t *sf)
{
  warts_state_t   *state;
  warts_hdr_t      hdr;
  int              i, fd;
  uint32_t         j;
  scamper_addr_t  *addr;
  scamper_list_t  *list;
  scamper_cycle_t *cycle;

  /* init the warts structures as if we were reading the file */
  if(scamper_file_warts_init_read(sf) == -1)
    {
      return -1;
    }

  fd = scamper_file_getfd(sf);

  for(;;)
    {
      /* read the header for the next record from the file */
      if((i = warts_hdr_read(sf, &hdr)) == 0)
	{
	  /* EOF */
	  break;
	}
      else if(i == -1)
	{
	  /* partial record */
	  return -1;
	}

      if(hdr.magic != WARTS_MAGIC || hdr.type == 0)
	{
	  return -1;
	}

      switch(hdr.type)
	{
	case SCAMPER_FILE_OBJ_ADDR:
	  if(warts_addr_read(sf, &hdr, &addr) != 0 || addr == NULL)
	    return -1;
	  break;

	case SCAMPER_FILE_OBJ_LIST:
	  if(warts_list_read(sf, &hdr, &list) != 0 || list == NULL)
	    return -1;
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_START:
	case SCAMPER_FILE_OBJ_CYCLE_DEF:
	  if(warts_cycle_read(sf, &hdr, &cycle) != 0 || cycle == NULL)
	    return -1;
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_STOP:
	  if(warts_cycle_stop_read(sf, &hdr, &cycle) != 0 || cycle == NULL)
	    return -1;
	  scamper_cycle_free(cycle);
	  break;

	default:
	  if(lseek(fd, hdr.len, SEEK_CUR) == -1)
	    {
	      return -1;
	    }
	  break;
	}      
    }

  /* get the state structure created in init_read */
  state = scamper_file_getstate(sf);

  /*
   * all the lists are in a table.  put them into a splay tree so we can
   * find them quickly, and then trash the list table
   */
  if((state->list_tree = splaytree_alloc(warts_list_cmp)) == NULL)
    {
      return -1;
    }
  for(j=1; j<state->list_count; j++)
    {
      if(splaytree_insert(state->list_tree, state->list_table[j]) == NULL)
	{
	  return -1;
	}
    }
  free(state->list_table); state->list_table = NULL;

  if((state->cycle_tree = splaytree_alloc(warts_cycle_cmp)) == NULL)
    {
      return -1;
    }
  for(j=1; j<state->cycle_count; j++)
    {
      /* don't install finished cycles into the splaytree */
      if(state->cycle_table[j] == NULL)
	{
	  continue;
	}

      if(splaytree_insert(state->cycle_tree, state->cycle_table[j]) == NULL)
	{
	  return -1;
	}
    }
  free(state->cycle_table); state->cycle_table = NULL;

  return 0;
}

int scamper_file_warts_is(const scamper_file_t *sf)
{
  uint16_t magic16;
  int fd = scamper_file_getfd(sf);

  if(lseek(fd, 0, SEEK_SET) == -1)
    {
      return 0;
    }

  if(read_wrap(fd, &magic16, NULL, sizeof(magic16)) != 0)
    {
      return 0;
    }

  if(ntohs(magic16) == WARTS_MAGIC)
    {
      if(lseek(fd, 0, SEEK_SET) == -1)
	{
	  return 0;
	}
      return 1;
    }

  return 0;
}

static void warts_free_state(splaytree_t *tree, void **table,
			     unsigned int count, splaytree_free_t free_cb)
{
  unsigned int i;

  if(table != NULL)
    {
      for(i=1; i<count; i++)
	{
	  if(table[i] != NULL)
	    {
	      free_cb(table[i]);
	    }
	}
      free(table);
    }
  if(tree != NULL)
    {
      splaytree_free(tree, free_cb);
    }

  return;
}

void scamper_file_warts_free_state(scamper_file_t *sf)
{
  warts_state_t *state;
  uint32_t i;

  /* there may not actually be state allocated with the file ... */
  if((state = scamper_file_getstate(sf)) == NULL)
    {
      return;
    }

  if(state->readbuf != NULL)
    {
      free(state->readbuf);
    }

  warts_free_state(state->list_tree,
		   (void **)state->list_table, state->list_count,
		   (splaytree_free_t)warts_list_free);

  warts_free_state(state->cycle_tree,
		   (void **)state->cycle_table, state->cycle_count,
		   (splaytree_free_t)warts_cycle_free);

  if(state->addr_table != NULL)
    {
      for(i=1; i<state->addr_count; i++)
	if(state->addr_table[i] != NULL)
	  scamper_addr_free(state->addr_table[i]);
      free(state->addr_table);
    }

  free(state);

  return;
}
