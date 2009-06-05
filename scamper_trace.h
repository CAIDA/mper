/*
 * scamper_trace.h
 *
 * $Id: scamper_trace.h,v 1.115 2009/04/22 02:24:26 mjl Exp $
 *
 * Copyright (C) 2003-2009 The University of Waikato
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

#ifndef __SCAMPER_TRACE_H
#define __SCAMPER_TRACE_H

/* forward declare some important structures */
struct scamper_tlv;
struct scamper_icmpext;
struct scamper_list;
struct scamper_cycle;
struct scamper_addr;

#define SCAMPER_TRACE_STOP_NONE      0x00 /* null reason */
#define SCAMPER_TRACE_STOP_COMPLETED 0x01 /* got an ICMP port unreach */
#define SCAMPER_TRACE_STOP_UNREACH   0x02 /* got an other ICMP unreach code */
#define SCAMPER_TRACE_STOP_ICMP      0x03 /* got an ICMP msg, not unreach */
#define SCAMPER_TRACE_STOP_LOOP      0x04 /* loop detected */
#define SCAMPER_TRACE_STOP_GAPLIMIT  0x05 /* gaplimit reached */
#define SCAMPER_TRACE_STOP_ERROR     0x06 /* sendto error */
#define SCAMPER_TRACE_STOP_HOPLIMIT  0x07 /* hoplimit reached */
#define SCAMPER_TRACE_STOP_GSS       0x08 /* found hop in global stop set */

#define SCAMPER_TRACE_FLAG_ALLATTEMPTS  0x01 /* send all allotted attempts */
#define SCAMPER_TRACE_FLAG_PMTUD        0x02 /* conduct PMTU discovery */
#define SCAMPER_TRACE_FLAG_DL           0x04 /* datalink for TX timestamps */
#define SCAMPER_TRACE_FLAG_IGNORETTLDST 0x08 /* ignore ttl exp. rx f/ dst */
#define SCAMPER_TRACE_FLAG_DTREE        0x10 /* doubletree */
#define SCAMPER_TRACE_FLAG_ICMPCSUMDP   0x20 /* icmp csum found in dport */

#define SCAMPER_TRACE_TYPE_ICMP_ECHO       0x01 /* ICMP echo requests */
#define SCAMPER_TRACE_TYPE_UDP             0x02 /* UDP to unused ports */
#define SCAMPER_TRACE_TYPE_TCP             0x03 /* TCP SYN packets */
#define SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS 0x04 /* paris traceroute */
#define SCAMPER_TRACE_TYPE_UDP_PARIS       0x05 /* paris traceroute */
#define SCAMPER_TRACE_TYPE_TCP_ACK         0x06 /* TCP ACK packets */

#define SCAMPER_TRACE_GAPACTION_STOP      0x01 /* stop when gaplimit reached */
#define SCAMPER_TRACE_GAPACTION_LASTDITCH 0x02 /* send TTL-255 probes */

#define SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop) (		\
 ((hop)->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) == 0 &&	\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 11) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 3)))

#define SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP_TRANS(hop) (		\
 ((hop)->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) == 0 &&	\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 11 && (hop)->hop_icmp_code == 0) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 0)))

#define SCAMPER_TRACE_HOP_IS_ICMP_PACKET_TOO_BIG(hop) (		\
 ((hop)->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) == 0 &&	\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 4) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 2)))

#define SCAMPER_TRACE_HOP_IS_ICMP_UNREACH(hop) (		\
 ((hop)->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) == 0 &&	\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 1)))

#define SCAMPER_TRACE_HOP_IS_ICMP_UNREACH_PORT(hop) (		\
 ((hop)->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) == 0 &&	\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 3) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 1 && (hop)->hop_icmp_code == 4)))

#define SCAMPER_TRACE_HOP_IS_ICMP_ECHO_REPLY(hop) (		\
 ((hop)->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) == 0 &&	\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 0) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 129)))

#define SCAMPER_TRACE_HOP_IS_TCP(hop) (				\
 (hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) != 0)

#define SCAMPER_TRACE_TYPE_IS_ICMP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_ICMP_ECHO ||		\
 (trace)->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)

#define SCAMPER_TRACE_TYPE_IS_UDP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP ||			\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP_PARIS)

#define SCAMPER_TRACE_TYPE_IS_TCP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_TCP ||			\
 (trace)->type == SCAMPER_TRACE_TYPE_TCP_ACK)

#define SCAMPER_TRACE_TYPE_IS_UDP_PARIS(trace) (		\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP_PARIS)

#define SCAMPER_TRACE_IS_ICMPCSUMDP(trace) (			\
 (trace)->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)

/*
 * hop TLV types:
 * these items are stored conditionally in the hop data structure as needed.
 */
#define SCAMPER_TRACE_HOP_TLV_REPLY_IPID  0x01 /* 2 bytes */
#define SCAMPER_TRACE_HOP_TLV_REPLY_IPTOS 0x02 /* 1 byte  */
#define SCAMPER_TRACE_HOP_TLV_NHMTU       0x03 /* 2 bytes */
#define SCAMPER_TRACE_HOP_TLV_INNER_IPLEN 0x04 /* 2 bytes */
#define SCAMPER_TRACE_HOP_TLV_INNER_IPTTL 0x05 /* 1 byte  */
#define SCAMPER_TRACE_HOP_TLV_INNER_IPTOS 0x06 /* 1 byte  */

/*
 * scamper hop flags:
 * these flags give extra meaning to fields found in the hop structure
 * by default.
 */
#define SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX 0x01 /* socket rx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_DL_TX   0x02 /* datalink tx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_DL_RX   0x04 /* datalink rx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_TSC     0x08 /* rtt computed w/ tsc clock */
#define SCAMPER_TRACE_HOP_FLAG_REPLY_TTL  0x10 /* reply ttl included */
#define SCAMPER_TRACE_HOP_FLAG_TCP        0x20 /* reply is TCP */

/*
 * this macro is a more convenient way to check that the hop record
 * has both the tx and rx timestamps from the datalink for computing the
 * RTT
 */
#define SCAMPER_TRACE_HOP_FLAG_DL_RTT(hop)			\
 ((hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_TX) &&		\
  (hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_RX))

/*
 * pmtud TLV types:
 * these items are stored conditionally in the PMTUD data structure as
 * needed.
 */
#define SCAMPER_TRACE_PMTUD_TLV_OUTMTU    0x01  /* 2 bytes */

/*
 * scamper_trace_hop:
 *
 * hold data on each response received as part of a traceroute.
 */
typedef struct scamper_trace_hop
{
  /* the address of the hop that responded */
  scamper_addr_t              *hop_addr;

  /* flags defined by SCAMPER_TRACE_HOP_FLAG_* */
  uint8_t                      hop_flags;

  /*
   * probe_id:   the attempt # this probe is in response to [count from 0]
   * probe_ttl:  the ttl that we sent to the trace->dst
   * probe_size: the size of the probe we sent
   * reply_size: the size of the icmp response we received
   * reply_ttl:  the ttl of the reply packet
   */
  uint8_t                      hop_probe_id;
  uint8_t                      hop_probe_ttl;
  uint8_t                      hop_reply_ttl;
  uint16_t                     hop_probe_size;
  uint16_t                     hop_reply_size;

  /* icmp type / code returned by this hop */
  union
  {
    struct hop_icmp
    {
      uint8_t                  hop_icmp_type;
      uint8_t                  hop_icmp_code;
    } icmp;
    struct hop_tcp
    {
      uint8_t                  hop_tcp_flags;
    } tcp;
  } hop_un;

  /* time elapsed between sending the probe and receiving this resp */
  struct timeval               hop_rtt;

  /* any data items to store conditionally */
  struct scamper_tlv          *hop_tlvs;

  /* ICMP extensions */
  struct scamper_icmpext      *hop_icmpext;

  struct scamper_trace_hop    *hop_next;
} scamper_trace_hop_t;

#define hop_icmp_type hop_un.icmp.hop_icmp_type
#define hop_icmp_code hop_un.icmp.hop_icmp_code
#define hop_tcp_flags hop_un.tcp.hop_tcp_flags

typedef struct scamper_trace_pmtud
{
  uint16_t             ifmtu; /* the outgoing interface's MTU */
  uint16_t             pmtu;  /* the packet size we reached the target with */
  scamper_trace_hop_t *hops;  /* list of hops that returned icmp messages */
  struct scamper_tlv  *tlvs;  /* any data items to store conditionally */
} scamper_trace_pmtud_t;

typedef struct scamper_trace_dtree
{
  uint8_t          firsthop;
  uint16_t         gssc;
  scamper_addr_t **gss;
  scamper_addr_t  *gss_stop;
  scamper_addr_t  *lss_stop;
} scamper_trace_dtree_t;

/*
 * scamper_trace:
 * a trace structure contains enough state for scamper to probe a series
 * of traces concurrently.
 */
typedef struct scamper_trace
{
  /* the current list, cycle, and defaults */
  struct scamper_list   *list;
  struct scamper_cycle  *cycle;

  /* source and destination addresses of the trace */
  struct scamper_addr   *src;
  struct scamper_addr   *dst;

  /* when the trace commenced */
  struct timeval         start;

  /* hops array, number of valid hops specified by hop_count */
  scamper_trace_hop_t  **hops;
  uint16_t               hop_count;

  /* number of probes sent for this traceroute */
  uint16_t               probec;

  /* why the trace finished */
  uint8_t                stop_reason;
  uint8_t                stop_data;

  /* trace parameters */
  uint8_t                type;
  uint8_t                flags;
  uint8_t                attempts;
  uint8_t                hoplimit;
  uint8_t                gaplimit;
  uint8_t                gapaction;
  uint8_t                firsthop;
  uint8_t                tos;
  uint8_t                wait;
  uint8_t                wait_probe;
  uint8_t                loops;
  uint8_t                loopaction;
  uint8_t                confidence;
  uint16_t               probe_size;
  uint16_t               sport;
  uint16_t               dport;

  /* payload */
  uint8_t               *payload;
  uint16_t               payload_len;

  /* anything optional to store with the trace */
  struct scamper_tlv    *tlvs;

  /* if we perform PMTU discovery on the trace, then record the data here */
  scamper_trace_pmtud_t *pmtud;

  /* if we perform last ditch probing, then record any responses here */
  scamper_trace_hop_t   *lastditch;

  /* if we perform doubletree, record doubletree parameters and data here */
  scamper_trace_dtree_t *dtree;

} scamper_trace_t;

/*
 * scamper_trace_alloc:
 *  allocate a brand new scamper trace object, empty of any data
 *
 * scamper_trace_hops_alloc:
 *  allocate an array of hop records to the trace object
 *
 * scamper_trace_free:
 *  free the memory used by this trace object.
 *  this function assumes that any memory that would be dynamically
 *  allocated can be freed with free()
 *
 * scamper_trace_probe_headerlen:
 *  return the size of headers sent with each probe for the trace
 *
 * scamper_trace_addr:
 *  return the address of the trace -- caller doesn't know that it is a trace.
 */
scamper_trace_t *scamper_trace_alloc(void);
int scamper_trace_hops_alloc(scamper_trace_t *trace, const int hops);
void scamper_trace_free(scamper_trace_t *trace);
uint16_t scamper_trace_pathlength(const scamper_trace_t *trace);
int scamper_trace_probe_headerlen(const scamper_trace_t *trace);
scamper_addr_t *scamper_trace_addr(const void *va);
const char *scamper_trace_type_tostr(const scamper_trace_t *trace);
int scamper_trace_iscomplete(const scamper_trace_t *trace);

/*
 * scamper_trace_loop:
 *
 * find the nth instance of a loop in the trace.  if 'a' or 'b' are non-null,
 * on exit they hold the start and end of the loop.  if '*b' is non-null on
 * entry, it specifies the hop at which to commence looking for the next
 * instance of a loop.
 */
int scamper_trace_loop(const scamper_trace_t *trace, const int n,
		       const scamper_trace_hop_t **a,
		       const scamper_trace_hop_t **b);

/*
 * scamper_trace_hop_alloc:
 *  allocate a blank hop record
 *
 * scamper_trace_hop_free:
 *  free the memory used by a hop structure
 *
 * scamper_trace_hop_count:
 *  return the total number of hops attached to the trace structure
 */
scamper_trace_hop_t *scamper_trace_hop_alloc(void);
void scamper_trace_hop_free(scamper_trace_hop_t *hop);
int scamper_trace_hop_count(const scamper_trace_t *trace);

int scamper_trace_hop_addr_cmp(const scamper_trace_hop_t *a,
			       const scamper_trace_hop_t *b);

/*
 * scamper_trace_pmtud_alloc:
 *  allocate a blank pmtud record for the trace structure
 *
 * scamper_trace_pmtud_free:
 *  free the attached pmtud record from the trace structure
 *
 * scamper_trace_pmtud_hop_count:
 *  return the total number of hops attached to the pmtud structure
 */
int scamper_trace_pmtud_alloc(scamper_trace_t *trace);
void scamper_trace_pmtud_free(scamper_trace_t *trace);
int scamper_trace_pmtud_hop_count(const scamper_trace_t *trace);

int scamper_trace_lastditch_hop_count(const scamper_trace_t *trace);

/*
 * functions for helping with doubletree
 */
int scamper_trace_dtree_alloc(scamper_trace_t *trace);
void scamper_trace_dtree_free(scamper_trace_t *trace);
int scamper_trace_dtree_gss_add(scamper_trace_t *trace, scamper_addr_t *iface);
scamper_addr_t *scamper_trace_dtree_gss_find(const scamper_trace_t *trace,
                                             const scamper_addr_t *iface);

/*
 * Utility macros
 *
 *
 */
#define SCAMPER_TRACE_PMTUD_GET_OUTMTU(pmtud, outmtu)                       \
 do                                                                         \
   {                                                                        \
     const scamper_tlv_t *tlv;                                              \
     if((tlv=scamper_tlv_get(pmtud->tlvs,                                   \
			     SCAMPER_TRACE_PMTUD_TLV_OUTMTU)) == NULL)      \
       {                                                                    \
	 outmtu = pmtud->ifmtu;                                             \
       }                                                                    \
     else                                                                   \
       {                                                                    \
         outmtu = tlv->tlv_val_16;                                          \
       }                                                                    \
   }                                                                        \
 while(0)

#define SCAMPER_TRACE_HOP_GET_REPLY_IPID(hop, ipid)			    \
 do									    \
   {									    \
     const scamper_tlv_t *tlv;						    \
     if((tlv=scamper_tlv_get(hop->hop_tlvs,				    \
			     SCAMPER_TRACE_HOP_TLV_REPLY_IPID)) != NULL)    \
       {								    \
	 ipid = tlv->tlv_val_16;					    \
       }								    \
     else								    \
       {								    \
	 ipid = 0;							    \
       }								    \
   }									    \
 while(0)

#define SCAMPER_TRACE_HOP_GET_TURN_TTL(hop, turn_ttl)                       \
 do                                                                         \
   {                                                                        \
     const scamper_tlv_t *tlv;                                              \
     if((tlv=scamper_tlv_get(hop->hop_tlvs,                                 \
			     SCAMPER_TRACE_HOP_TLV_INNER_IPTTL)) == NULL)   \
       {                                                                    \
         turn_ttl = 1;                                                      \
       }                                                                    \
     else                                                                   \
       {                                                                    \
         turn_ttl = tlv->tlv_val_8;                                         \
       }                                                                    \
   }                                                                        \
 while(0)

#define SCAMPER_TRACE_HOP_GET_NHMTU(hop, nhmtu)                             \
 do                                                                         \
   {                                                                        \
     const scamper_tlv_t *tlv;                                              \
     if((tlv=scamper_tlv_get(hop->hop_tlvs,                                 \
			     SCAMPER_TRACE_HOP_TLV_NHMTU)) != NULL)         \
       {                                                                    \
         nhmtu = tlv->tlv_val_16;                                           \
       }                                                                    \
     else                                                                   \
       {                                                                    \
         nhmtu = 0;                                                         \
       }                                                                    \
   }                                                                        \
 while(0)

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

#ifndef TH_URG
#define TH_URG 0x20
#endif

#ifndef TH_ECE
#define TH_ECE 0x40
#endif

#ifndef TH_CWR
#define TH_CWR 0x80
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef ICMP_UNREACH
#define ICMP_UNREACH 3
#endif

#ifndef ICMP_UNREACH_NET
#define ICMP_UNREACH_NET 0
#endif

#ifndef ICMP_UNREACH_HOST
#define ICMP_UNREACH_HOST 1
#endif

#ifndef ICMP_UNREACH_PROTOCOL
#define ICMP_UNREACH_PROTOCOL 2
#endif

#ifndef ICMP_UNREACH_PORT
#define ICMP_UNREACH_PORT 3
#endif

#ifndef ICMP_UNREACH_NEEDFRAG
#define ICMP_UNREACH_NEEDFRAG 4
#endif

#ifndef ICMP_UNREACH_SRCFAIL
#define ICMP_UNREACH_SRCFAIL 5
#endif

#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB 13
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#ifndef ICMP_TIMXCEED
#define ICMP_TIMXCEED 11
#endif

#ifndef ICMP_TIMXCEED_INTRANS
#define ICMP_TIMXCEED_INTRANS 0
#endif

#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH 1
#endif

#ifndef ICMP6_PACKET_TOO_BIG
#define ICMP6_PACKET_TOO_BIG 2
#endif

#ifndef ICMP6_DST_UNREACH_NOROUTE
#define ICMP6_DST_UNREACH_NOROUTE 0
#endif

#ifndef ICMP6_DST_UNREACH_ADMIN
#define ICMP6_DST_UNREACH_ADMIN 1
#endif

#ifndef ICMP6_DST_UNREACH_BEYONDSCOPE
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2
#endif

#ifndef ICMP6_DST_UNREACH_ADDR
#define ICMP6_DST_UNREACH_ADDR 3
#endif

#ifndef ICMP6_DST_UNREACH_NOPORT
#define ICMP6_DST_UNREACH_NOPORT 4
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#endif

#endif /* __SCAMPER_TRACE_H */
