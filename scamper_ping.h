/*
 * scamper_ping.h
 *
 * $Id: scamper_ping.h,v 1.23 2009/04/21 20:15:16 mjl Exp $
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

#ifndef __SCAMPER_PING_H
#define __SCAMPER_PING_H

#define SCAMPER_PING_REPLY_IS_ICMP(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 && \
  (reply)->reply_proto == 1) ||                    \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 && \
  (reply)->reply_proto == 58))

#define SCAMPER_PING_REPLY_IS_TCP(reply) ( \
 ((reply)->reply_proto == 6))

#define SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) (     \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 0) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 129))

#define SCAMPER_PING_REPLY_IS_ICMP_UNREACH(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 3) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 1))

#define SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(reply) (   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 &&                             \
  (reply)->icmp_type == 3 && (reply)->icmp_code == 3) ||   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 &&                            \
  (reply)->icmp_type == 1 && (reply)->icmp_code == 4))

#define SCAMPER_PING_REPLY_IS_ICMP_TTL_EXP(reply) (         \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&          \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 11) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&          \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 3))

#define SCAMPER_PING_METHOD_IS_ICMP(ping) (\
 ((ping)->probe_method == SCAMPER_PING_METHOD_ICMP_ECHO))

#define SCAMPER_PING_METHOD_IS_TCP(ping) (                    \
 ((ping)->probe_method == SCAMPER_PING_METHOD_TCP_ACK ||      \
  (ping)->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT))

#define SCAMPER_PING_METHOD_IS_UDP(ping) (                \
 ((ping)->probe_method == SCAMPER_PING_METHOD_UDP ||      \
  (ping)->probe_method == SCAMPER_PING_METHOD_UDP_DPORT))

#define SCAMPER_PING_STOP_NONE      0x00 /* null reason */
#define SCAMPER_PING_STOP_COMPLETED 0x01 /* sent all probes */
#define SCAMPER_PING_STOP_ERROR     0x02 /* error occured during ping */

#define SCAMPER_PING_REPLY_FLAG_REPLY_TTL  0x01 /* reply ttl included */
#define SCAMPER_PING_REPLY_FLAG_REPLY_IPID 0x02 /* reply ipid included */
#define SCAMPER_PING_REPLY_FLAG_PROBE_IPID 0x04 /* probe ipid included */

#define SCAMPER_PING_METHOD_ICMP_ECHO     0x00
#define SCAMPER_PING_METHOD_TCP_ACK       0x01
#define SCAMPER_PING_METHOD_TCP_ACK_SPORT 0x02
#define SCAMPER_PING_METHOD_UDP           0x03
#define SCAMPER_PING_METHOD_UDP_DPORT     0x04

/*
 * scamper_ping_reply
 *
 * a ping reply structure keeps track of how a ping packet was responded to.
 * the default structure has enough fields for interesting pieces out of an
 * echo reply packet.
 *
 * if the icmp type/code is not an ICMP echo reply packet, then the TLVs
 * defined above may be present in the response.
 */
typedef struct scamper_ping_reply
{
  /* where the response came from */
  scamper_addr_t            *addr;

  /* timestamps for sending the probe and getting this response */
  struct timeval             tx;
  struct timeval             rx;

  /* flags defined by SCAMPER_PING_REPLY_FLAG_* */
  uint8_t                    flags;

  /* the TTL / size of the packet that is returned */
  uint8_t                    reply_proto;
  uint8_t                    reply_ttl;
  uint16_t                   reply_size;
  uint16_t                   reply_ipid;
  uint16_t                   probe_ipid;

  /* the icmp type / code returned */
  uint8_t                    icmp_type;
  uint8_t                    icmp_code;
  uint8_t                    icmp_q_ip_ttl;

  /* the tcp flags returned */
  uint8_t                    tcp_flags;

  /* if a single probe gets more than one response, they get chained */
  struct scamper_ping_reply *next;

} scamper_ping_reply_t;

/*
 * scamper_ping
 *
 * this structure contains details of a ping between a source and a
 * destination.  is specifies the parameters to the ping and the
 * replies themselves.
 */
typedef struct scamper_ping
{
  uint32_t               reqnum;
  uint32_t               user_data;

  /* source and destination addresses of the ping */
  scamper_addr_t        *src;          /* -S option */
  scamper_addr_t        *dst;

  /* when the ping started */
  struct timeval         start;

  /* why the ping finished */
  uint8_t                stop_reason;
  uint8_t                stop_data;

  /* the pattern to use inside of a probe.  if null then all zeros */
  uint16_t               pattern_len;  /* -p option to ping */
  uint8_t               *pattern_bytes;

  /* ping options */
  uint16_t               probe_size;   /* -s option to ping */
  uint8_t                probe_method; /* -P option to ping */
  uint8_t                probe_wait;   /* -i option to ping */
  uint16_t               probe_cksum;
  uint8_t                probe_ttl;    /* -m option to ping */
  uint8_t                probe_tos;    /* -z option to ping */
  uint16_t               probe_sport;
  uint16_t               probe_dport;  /* -d option to ping */
  uint16_t               reply_count;  /* -o option to ping */
  uint32_t               spacing;      /* in ms */

  uint8_t                opt_set_cksum;  /* user provided checksum */

  /* actual data collected with the ping */
  scamper_ping_reply_t *ping_reply;
} scamper_ping_t;

/* basic routines to allocate and free scamper_ping structures */
scamper_ping_t *scamper_ping_alloc(void);
void scamper_ping_free(scamper_ping_t *ping);
scamper_addr_t *scamper_ping_addr(const void *va);
int scamper_ping_setpattern(scamper_ping_t *ping,uint8_t *bytes,uint16_t len);

/* basic routines to allocate and free scamper_ping_reply structures */
scamper_ping_reply_t *scamper_ping_reply_alloc(void);
void scamper_ping_reply_free(scamper_ping_reply_t *reply);
int scamper_ping_reply_append(scamper_ping_t *p, scamper_ping_reply_t *reply);
uint32_t scamper_ping_reply_count(const scamper_ping_t *ping);

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#endif

#endif /* __SCAMPER_PING_H */
