/*
 * scamper_icmp_resp.h
 *
 * $Id: scamper_icmp_resp.h,v 1.21 2009/04/03 04:02:40 mjl Exp $
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

#ifndef __SCAMPER_ICMP_RESP_H
#define __SCAMPER_ICMP_RESP_H

#define SCAMPER_ICMP_RESP_FLAG_KERNRX   (0x01)
#define SCAMPER_ICMP_RESP_FLAG_INNER_IP (0x02)

#define SCAMPER_ICMP_RESP_IPOPT_FLAG_NOOP            0x01
#define SCAMPER_ICMP_RESP_IPOPT_FLAG_V4RR            0x02 /* -R: IPv4 RR */
#define SCAMPER_ICMP_RESP_IPOPT_FLAG_TSONLY          0x04 /* -T tsonly */
#define SCAMPER_ICMP_RESP_IPOPT_FLAG_TSANDADDR       0x08 /* -T tsandaddr */
#define SCAMPER_ICMP_RESP_IPOPT_FLAG_TSPS            0x10 /* -T tsprespec */

#define SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) ( \
 (ir->ir_af == AF_INET  && ir->ir_icmp_type == 0) || \
 (ir->ir_af == AF_INET6 && ir->ir_icmp_type == 129))

#define SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) ( \
 (ir->ir_af == AF_INET  && ir->ir_icmp_type == 11) || \
 (ir->ir_af == AF_INET6 && ir->ir_icmp_type == 3))

#define SCAMPER_ICMP_RESP_IS_UNREACH(ir) ( \
 (ir->ir_af == AF_INET  && ir->ir_icmp_type == 3) || \
 (ir->ir_af == AF_INET6 && ir->ir_icmp_type == 1))

#define SCAMPER_ICMP_RESP_IS_UNREACH_PORT(ir) ( \
 (ir->ir_af == AF_INET && ir->ir_icmp_type == 3 && ir->ir_icmp_code == 3) || \
 (ir->ir_af == AF_INET6 && ir->ir_icmp_type == 1 && ir->ir_icmp_code == 4))

#define SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) ( \
 (ir->ir_af == AF_INET && ir->ir_icmp_type == 3 && ir->ir_icmp_code == 4) || \
 (ir->ir_af == AF_INET6 && ir->ir_icmp_type == 2))

/* this macro checks to see if the inner structs are valid */
#define SCAMPER_ICMP_RESP_INNER_IS_SET(ir) ( \
 ((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_INNER_IP) != 0))

#define SCAMPER_ICMP_RESP_INNER_IS_ICMP(ir) ( \
 (ir->ir_af == AF_INET  && ir->ir_inner_ip_proto == 1) || \
 (ir->ir_af == AF_INET6 && ir->ir_inner_ip_proto == 58))

#define SCAMPER_ICMP_RESP_INNER_IS_TCP(ir) ( \
 (ir->ir_inner_ip_proto == 6))

#define SCAMPER_ICMP_RESP_INNER_IS_UDP(ir) ( \
 (ir->ir_inner_ip_proto == 17))

#define SCAMPER_ICMP_RESP_INNER_IS_ICMP_ECHO_REQ(ir) ( \
 (ir->ir_af == AF_INET  && \
  ir->ir_inner_ip_proto == 1  && ir->ir_inner_icmp_type == 8) || \
 (ir->ir_af == AF_INET6 && \
  ir->ir_inner_ip_proto == 58 && ir->ir_inner_icmp_type == 128))

/*
 * an ICMP response may consist of up to four pieces.  when an ICMP
 * packet is received, scamper parses the packet and records values of
 * interest in this structure.
 *
 * the four pieces of interesting information can be broken up into the
 * following categories:
 *
 * 1. the IP header
 * 2. the ICMP header
 * 3. [optional] IP header of probe that caused this message
 * 4. [optional] transport header of probe that caused this message
 *
 * the optional pieces - the 'inner' IP and transport headers are found
 * depending on the type / code of the ICMP message.  they are always
 * found in 'destination unreachable' type messages, but obviously
 * are not found in echo replies or the like.
 */
typedef struct scamper_icmp_resp
{
  /* the address family (AF_INET / AF_INET6) of the response */
  int               ir_af;

  /* the icmp file descriptor the message was received on */
  int               ir_fd;

  /* when the ICMP response was received */
  struct timeval    ir_rx;

  /* flags, whose meanings are defined above */
  uint8_t           ir_flags;

  /*
   * category 1: the IP header;
   *
   * scamper records the source of the ICMP message but not the destination,
   * as that is the host scamper is running on, and that is not interesting.
   *
   * scamper also records the size, ttl, ipid, and tos fields of the
   * response
   */
  union
  {
    struct in_addr  v4;
    struct in6_addr v6;
  } ir_ip_src;

  uint16_t          ir_ip_size;
  uint16_t          ir_ip_id;
  uint8_t           ir_ip_tos;
  int16_t           ir_ip_ttl;  /* ir_ip_hlim; -1 if unavailable */

  uint8_t           ir_ipopt; /* the IP Options type(s) */

  /*
   * if the response includes the IPv4 record route option, IP addresses
   * are found here.
   */
  struct in_addr   *ir_ipopt_rrs;
  uint8_t           ir_ipopt_rrc;

  /*
   * if the response includes the IPv4 timestamp option, the results of it
   * are found in here.
   */
  uint8_t           ir_ipopt_tsc;
  struct in_addr   *ir_ipopt_tsips;
  uint32_t         *ir_ipopt_tstss;

  /*
   * category 2: the ICMP header;
   *
   * scamper records the type and code of the ICMP message.  depending on
   * the type of the message, optional ICMP id and sequence fields are
   * also recorded.  if the message 
   */
  uint8_t           ir_icmp_type;
  uint8_t           ir_icmp_code;

  union
  {
    struct ir_idseq
    {
      uint16_t      id;
      uint16_t      seq;
    } idseq;

    uint16_t        nhmtu;
  } ir_icmp_un;

  /*
   * category 3: the inner IP header;
   *
   * if the ICMP type/code hints that a portion of the probe is included
   * in the ICMP response, then scamper records interesting portions of the
   * IP header.  we don't record the source address, as that is the host
   * that scamper is running on, and that does not seem to be interesting.
   */
  union
  {
    struct in_addr  v4;
    struct in6_addr v6;
  } ir_inner_ip_dst;

  uint16_t          ir_inner_ip_size;
  uint16_t          ir_inner_ip_id;    /* IPv4 ID */
  uint32_t          ir_inner_ip_flow;  /* IPv6 flow */
  uint8_t           ir_inner_ip_tos;
  uint8_t           ir_inner_ip_ttl;   /* ir_inner_ip_hlim */
  uint8_t           ir_inner_ip_proto;
  struct in_addr   *ir_inner_ipopt_rrs;
  uint8_t           ir_inner_ipopt_rrc;
  uint8_t           ir_inner_ipopt_tsc;
  struct in_addr   *ir_inner_ipopt_tsips;
  uint32_t         *ir_inner_ipopt_tstss;

  /*
   * category 4: details of the transport header
   *
   * the IPv4 ICMP RFC says that if an ICMP error message
   */
  union
  {
    struct irt_udp
    {
      uint16_t sport;
      uint16_t dport;
      uint16_t sum;
    } irit_udp;

    struct irt_tcp
    {
      uint16_t sport;
      uint16_t dport;
      uint32_t seq;
    } irit_tcp;

    struct irt_icmp
    {
      uint8_t  type;
      uint8_t  code;
      uint16_t sum;
      uint16_t id;
      uint16_t seq;
    } irit_icmp;
  } ir_inner_trans_un;

  uint8_t          *ir_ext;
  uint16_t          ir_extlen;

} scamper_icmp_resp_t;

#define ir_ip_hlim         ir_ip_ttl

#define ir_icmp_id         ir_icmp_un.idseq.id
#define ir_icmp_seq        ir_icmp_un.idseq.seq
#define ir_icmp_nhmtu      ir_icmp_un.nhmtu

#define ir_inner_ip_hlim   ir_inner_ip_ttl
#define ir_inner_udp_sport ir_inner_trans_un.irit_udp.sport
#define ir_inner_udp_dport ir_inner_trans_un.irit_udp.dport
#define ir_inner_udp_sum   ir_inner_trans_un.irit_udp.sum
#define ir_inner_tcp_sport ir_inner_trans_un.irit_tcp.sport
#define ir_inner_tcp_dport ir_inner_trans_un.irit_tcp.dport
#define ir_inner_tcp_seq   ir_inner_trans_un.irit_tcp.seq
#define ir_inner_icmp_type ir_inner_trans_un.irit_icmp.type
#define ir_inner_icmp_code ir_inner_trans_un.irit_icmp.code
#define ir_inner_icmp_sum  ir_inner_trans_un.irit_icmp.sum
#define ir_inner_icmp_id   ir_inner_trans_un.irit_icmp.id
#define ir_inner_icmp_seq  ir_inner_trans_un.irit_icmp.seq

int scamper_icmp_resp_src(scamper_icmp_resp_t *resp, scamper_addr_t *addr);
int scamper_icmp_resp_inner_dst(scamper_icmp_resp_t *resp, scamper_addr_t *a);

void scamper_icmp_resp_handle(scamper_icmp_resp_t *resp);

void scamper_icmp_resp_clean(scamper_icmp_resp_t *ir);

/* scamper only uses this function if it is built in debug mode */
#if !defined(NDEBUG) && !defined(WITHOUT_DEBUGFILE)
void    scamper_icmp_resp_print(const scamper_icmp_resp_t *resp);
#else
#define scamper_icmp_resp_print(resp) ((void)0)
#endif

#endif /* __SCAMPER_ICMP_RESP_H */
