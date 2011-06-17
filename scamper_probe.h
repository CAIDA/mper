/*
 * scamper_probe.h
 *
 * $Id: scamper_probe.h,v 1.20 2008/05/06 04:16:50 mjl Exp $
 *
 * Copyright (C) 2005-2007 The University of Waikato
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

#ifndef __SCAMPER_PROBE_H
#define __SCAMPER_PROBE_H

/*
 * scamper_probe_ipopt
 *
 * this structure is used to hold IPv4 options and IPv6 extension headers.
 */
typedef struct scamper_probe_ipopt
{
  uint8_t  type;
  uint8_t  len;
  uint8_t *val;
} scamper_probe_ipopt_t;

#define SCAMPER_PROBE_IPOPTS_V6ROUTE0 0
#define SCAMPER_PROBE_IPOPTS_V6FRAG   1
#define SCAMPER_PROBE_IPOPTS_V4RR     2
#define SCAMPER_PROBE_IPOPTS_V4TSPS   3 /* TS: prespecified interfaces */
#define SCAMPER_PROBE_IPOPTS_V4TSO    4 /* TS: record only timestamps */
#define SCAMPER_PROBE_IPOPTS_V4TSAA   5 /* TS: record IP and timestamps */

/*
 * scamper_probe
 *
 * this structure details how a probe should be formed and sent.
 * it records any error code
 */
typedef struct scamper_probe
{
  /* if using the datalink, pr_dl != NULL and the datalink header to use */
  scamper_dl_t          *pr_dl;
  uint16_t               pr_dl_size;
  uint8_t               *pr_dl_hdr;

  /* file descriptor to use */
  int                    pr_fd;

  /* IP header parameters */
  scamper_addr_t        *pr_ip_src;
  scamper_addr_t        *pr_ip_dst;
  uint8_t                pr_ip_tos;
  uint8_t                pr_ip_ttl;
  uint8_t                pr_ip_proto;
  uint16_t               pr_ip_id;        /* IPv4 ID */
  uint16_t               pr_ip_off;
  uint32_t               pr_ip_flow;      /* IPv6 flow id */

  /* IPv4 options / IPv6 extension headers */
  scamper_probe_ipopt_t *pr_ipopts;
  int                    pr_ipoptc;

  /* UDP header parameters */
  uint16_t               pr_udp_sport;
  uint16_t               pr_udp_dport;

  /* ICMP header parameters */
  uint8_t                pr_icmp_type;
  uint8_t                pr_icmp_code;
  uint16_t               pr_icmp_id;
  uint16_t               pr_icmp_seq;
  uint16_t               pr_icmp_sum;
  uint16_t               pr_icmp_mtu;

  /* TCP header parameters */
  uint16_t               pr_tcp_sport;
  uint16_t               pr_tcp_dport;
  uint32_t               pr_tcp_seq;
  uint32_t               pr_tcp_ack;
  uint8_t                pr_tcp_flags;
  uint16_t               pr_tcp_win;
  uint16_t               pr_tcp_mss;

  /* the contents of the packet's body */
  void                  *pr_data;
  uint16_t               pr_len;

  /* the time immediately before the call to sendto was made */
  struct timeval         pr_tx;

  /* if an error occurs in the probe function, the errno is recorded */
  int                    pr_errno;
} scamper_probe_t;

int scamper_probe(scamper_probe_t *probe);

/*
 * scamper_probe_cleanup:
 * cleanup any state kept inside the scamper_probe module
 */
void scamper_probe_cleanup(void);

#endif /* __SCAMPER_PROBE_H */
