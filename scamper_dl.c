/*
 * scamper_dl: manage BPF/PF_PACKET datalink instances for scamper
 *
 * $Id: scamper_dl.c,v 1.123 2009/04/21 04:15:19 mjl Exp $
 *
 *          Matthew Luckie
 * 
 *          Supported by:
 *           The University of Waikato
 *           NLANR Measurement and Network Analysis
 *           CAIDA
 *           The WIDE Project
 *
 * The purpose of this code is to obtain the timestamp of when the
 * outgoing probe hits the wire.  This is so scamper sees when the probe
 * is actually sent and allows it to compute the RTT more accurately in
 * theory.
 *
 * David Moore (CAIDA) originally suggested that scamper use BPF for this
 * task.  I decided to use file handles to the underlying packet capture
 * interface instead of pcap(3) for two reasons.  The first is that I
 * needed file descriptors to pass to select(2).  pcap(3) got in the way.
 * The second is that I like writing filters with BPF instructions.
 *
 * The pcap library was very useful to document how to access the various
 * datalink types, particularly the dlpi interface.  The libnet interface
 * was also helpful to determine how to write raw packets.
 *
 * Copyright (C) 2004-2008 The University of Waikato
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

#if defined(__APPLE__)
#define _BSD_SOCKLEN_T_
#define HAVE_BPF
#include <stdint.h>
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#define HAVE_BPF
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
#define snprintf _snprintf
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#endif

#if defined(HAVE_BPF)
#include <net/bpf.h>
#endif

#if defined(__sun__)
#define HAVE_DLPI
#define MAXDLBUF 8192
#include <sys/bufmod.h>
#include <sys/dlpi.h>
#include <stropts.h>
#endif

#ifndef _WIN32
#include <net/if.h>
#endif

#if defined(__linux__)
#define __FAVOR_BSD
#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif
#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#if defined(__linux__)
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/types.h>
#include <linux/filter.h>
#endif /* __linux__ */

#if defined(HAVE_BPF) || defined(__linux__)
#define HAVE_BPF_FILTER
#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_privsep.h"
#include "scamper_task.h"
#include "scamper_target.h"
#include "scamper_addr2mac.h"
#include "scamper_if.h"
#include "utils.h"

#if !defined(HAVE_BPF) && !defined(__linux__) && !defined(HAVE_DLPI) && !defined(_WIN32)
#error "datalink support not available on this system"
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

#ifndef ICMP_MINLEN
#define	ICMP_MINLEN 8
#endif

#ifndef ICMP_UNREACH
#define ICMP_UNREACH 3
#endif

#ifndef ICMP_TIMXCEED
#define ICMP_TIMXCEED 11
#endif

#ifndef ICMP_UNREACH_NEEDFRAG
#define ICMP_UNREACH_NEEDFRAG 4
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH 1
#endif

#ifndef ICMP6_PACKET_TOO_BIG
#define ICMP6_PACKET_TOO_BIG 2
#endif

#ifndef ICMP6_TIME_EXCEEDED
#define ICMP6_TIME_EXCEEDED 3
#endif

#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH 1
#endif

#ifndef ICMP6_PACKET_TOO_BIG
#define ICMP6_PACKET_TOO_BIG 2
#endif

#ifndef ICMP6_TIME_EXCEEDED
#define ICMP6_TIME_EXCEEDED 3
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#endif

#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY 129
#endif

#ifndef ND_ROUTER_ADVERT
#define ND_ROUTER_ADVERT 134
#endif

#ifndef TH_SYN
#define TH_SYN 0x02
#endif

#ifndef TH_ACK
#define TH_ACK 0x10
#endif

#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_ARP  0x0806

#ifdef _WIN32
struct ip
{
  uint8_t        ip_vhl;
  uint8_t        ip_tos;
  uint16_t       ip_len;
  uint16_t       ip_id;
  uint16_t       ip_off;
  uint8_t        ip_ttl;
  uint8_t        ip_p;
  uint16_t       ip_sum;
  struct in_addr ip_src;
  struct in_addr ip_dst;
};
struct icmp
{
  uint8_t   icmp_type;
  uint8_t   icmp_code;
  uint16_t  icmp_cksum;
  uint16_t  icmp_id;
  uint16_t  icmp_seq;
  struct ip icmp_ip;
};
#define icmp_nextmtu icmp_seq
struct ip6_hdr
{
  uint32_t        ip6_vfc_flow;
  uint16_t        ip6_plen;
  uint8_t         ip6_nxt;
  uint8_t         ip6_hlim;
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
};
struct icmp6_hdr
{
  uint8_t  icmp6_type;
  uint8_t  icmp6_code;
  uint16_t icmp6_cksum;
  uint16_t icmp6_id;
  uint16_t icmp6_seq;
};
struct udphdr
{
  uint16_t uh_sport;
  uint16_t uh_dport;
  uint16_t uh_ulen;
  uint16_t uh_sum;
};
struct tcphdr {
  uint16_t th_sport;
  uint16_t th_dport;
  uint32_t th_seq;
  uint32_t th_ack;
  uint8_t  th_offx2;
  uint8_t  th_flags;
  uint16_t th_win;
  uint16_t th_sum;
  uint16_t th_urp;
};
#endif

struct scamper_dl
{
  /* the file descriptor that scamper has on the datalink */
  scamper_fd_t  *fdn;

  /* the callback used to read packets off the datalink */
  int          (*dlt_cb)(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len);

  /* the underlying type of the datalink (DLT_* or ARPHDR_* values) */
  int            type;

  /* how the user should frame packet to transmit on the datalink */
  int            tx_type;

  /* if we're using BPF, then we need to use an appropriately sized buffer */
#if defined(HAVE_BPF)
  u_int          readbuf_len;
#endif

};

static uint8_t          *readbuf = NULL;
static size_t            readbuf_len = 0;

#if defined(HAVE_BPF)
static scamper_osinfo_t *osinfo = NULL;
#endif

/*
 * dl_parse_ip
 *
 * pkt points to the beginning of an IP header.  given the length of the
 * packet, parse the contents into a datalink record structure.
 */
static int dl_parse_ip(scamper_dl_rec_t *dl, uint8_t *pktbuf, size_t pktlen)
{
  struct ip        *ip4;
  struct ip6_hdr   *ip6;
  struct icmp      *icmp4;
  struct icmp6_hdr *icmp6;
  struct tcphdr    *tcp;
  struct udphdr    *udp;
  size_t            iphdrlen;
  uint8_t          *pkt = pktbuf;
  size_t            len = pktlen;

  if((pkt[0] >> 4) == 4) /* IPv4 */
    {
      ip4 = (struct ip *)pkt;

#ifndef _WIN32
      iphdrlen = (ip4->ip_hl << 2);
#else
      iphdrlen = ((ip4->ip_vhl) & 0xf) << 2;
#endif

      /*
       * make sure that the captured packet has enough to cover the whole
       * of the IP header
       */
      if(iphdrlen > len)
	{
	  return 0;
	}

      /* if this IPv4 packet does not have an offset of zero, then discard */
      if((ntohs(ip4->ip_off) & IP_OFFMASK) != 0)
	{
	  return 0;
	}

      dl->dl_af       = AF_INET;
      dl->dl_ip_proto = ip4->ip_p;
      dl->dl_ip_size  = ntohs(ip4->ip_len);
      dl->dl_ip_id    = ntohs(ip4->ip_id);
      dl->dl_ip_tos   = ip4->ip_tos;
      dl->dl_ip_ttl   = ip4->ip_ttl;

      dl->dl_ip_src = (uint8_t *)&ip4->ip_src;
      dl->dl_ip_dst = (uint8_t *)&ip4->ip_dst;
    }
  else if((pkt[0] >> 4) == 6) /* IPv6 */
    {
      ip6 = (struct ip6_hdr *)pkt;

      if((iphdrlen = sizeof(struct ip6_hdr)) > len)
	{
	  return 0;
	}

      dl->dl_af       = AF_INET6;
      dl->dl_ip_proto = ip6->ip6_nxt;
      dl->dl_ip_size  = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
      dl->dl_ip_hlim  = ip6->ip6_hlim;

#ifndef _WIN32
      dl->dl_ip_flow  = ntohl(ip6->ip6_flow) & 0xfffff;
#else
      dl->dl_ip_flow  = ntohl(ip6->ip6_vfc_flow) & 0xfffff;
#endif

      dl->dl_ip_src = (uint8_t *)&ip6->ip6_src;
      dl->dl_ip_dst = (uint8_t *)&ip6->ip6_dst;
    }
  else
    {
      return 0;
    }

  /* we're done with the IP header now, so move the pkt pointer past it */
  pkt += iphdrlen;
  len -= iphdrlen;

  if(dl->dl_ip_proto == IPPROTO_UDP)
    {
      if((int)sizeof(struct udphdr) > len)
	{
	  return 0;
	}

      udp = (struct udphdr *)pkt;
      dl->dl_udp_dport = ntohs(udp->uh_dport);
      dl->dl_udp_sport = ntohs(udp->uh_sport);
      dl->dl_udp_sum   = udp->uh_sum;
    }
  else if(dl->dl_ip_proto == IPPROTO_TCP)
    {
      if((int)sizeof(struct tcphdr) > len)
	{
	  return 0;
	}

      tcp = (struct tcphdr *)pkt;
      dl->dl_tcp_dport  = ntohs(tcp->th_dport);
      dl->dl_tcp_sport  = ntohs(tcp->th_sport);
      dl->dl_tcp_seq    = ntohl(tcp->th_seq);
      dl->dl_tcp_ack    = ntohl(tcp->th_ack);
#ifndef _WIN32
      dl->dl_tcp_off    = (tcp->th_off << 4) | tcp->th_x2;
#else
      dl->dl_tcp_off    = tcp->th_offx2;
#endif
      dl->dl_tcp_flags  = tcp->th_flags;
      dl->dl_tcp_window = ntohs(tcp->th_win);
    }
  else if(dl->dl_ip_proto == IPPROTO_ICMP)
    {
      /* the absolute minimum ICMP header size is 8 bytes */
      if(ICMP_MINLEN > len)
	{
	  return 0;
	}

      icmp4 = (struct icmp *)pkt;
      dl->dl_icmp_type = icmp4->icmp_type;
      dl->dl_icmp_code = icmp4->icmp_code;

      switch(dl->dl_icmp_type)
	{
	case ICMP_UNREACH:
	case ICMP_TIMXCEED:
	  if(ICMP_MINLEN + (int)sizeof(struct ip) > len)
	    {
	      return 0;
	    }

	  if(dl->dl_icmp_type == ICMP_UNREACH &&
	     dl->dl_icmp_code == ICMP_UNREACH_NEEDFRAG)
	    {
	      dl->dl_icmp_nhmtu = ntohs(icmp4->icmp_nextmtu);
	    }

	  ip4 = &icmp4->icmp_ip;

	  dl->dl_icmp_ip_proto = ip4->ip_p;
	  dl->dl_icmp_ip_size  = ntohs(ip4->ip_len);
	  dl->dl_icmp_ip_id    = ntohs(ip4->ip_id);
	  dl->dl_icmp_ip_tos   = ip4->ip_tos;
	  dl->dl_icmp_ip_ttl   = ip4->ip_ttl;

	  dl->dl_icmp_ip_src = (uint8_t *)&ip4->ip_src;
	  dl->dl_icmp_ip_dst = (uint8_t *)&ip4->ip_dst;

	  /*
	   * the ICMP response should include the IP header and the first
	   * 8 bytes of the transport header.
	   */
#ifndef _WIN32
	  if((size_t)(ICMP_MINLEN + (ip4->ip_hl << 2) + 8) > len)
#else
	  if((size_t)(ICMP_MINLEN + ((ip4->ip_vhl & 0xf) << 2) + 8) > len)
#endif
	    {
	      return 0;
	    }

	  pkt = (uint8_t *)ip4;

#ifndef _WIN32
	  iphdrlen = (ip4->ip_hl << 2);
#else
	  iphdrlen = ((ip4->ip_vhl & 0xf) << 2);
#endif

	  pkt += iphdrlen;

	  if(dl->dl_icmp_ip_proto == IPPROTO_UDP)
	    {
	      udp = (struct udphdr *)pkt;
	      dl->dl_icmp_udp_sport = ntohs(udp->uh_sport);
	      dl->dl_icmp_udp_dport = ntohs(udp->uh_dport);
	      dl->dl_icmp_udp_sum   = udp->uh_sum;
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_ICMP)
	    {
	      icmp4 = (struct icmp *)pkt;
	      dl->dl_icmp_icmp_type = icmp4->icmp_type;
	      dl->dl_icmp_icmp_code = icmp4->icmp_code;
	      dl->dl_icmp_icmp_id   = ntohs(icmp4->icmp_id);
	      dl->dl_icmp_icmp_seq  = ntohs(icmp4->icmp_seq);
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_TCP)
	    {
	      tcp = (struct tcphdr *)pkt;
	      dl->dl_icmp_tcp_sport = ntohs(tcp->th_sport);
	      dl->dl_icmp_tcp_dport = ntohs(tcp->th_dport);
	      dl->dl_icmp_tcp_seq   = ntohl(tcp->th_seq);
	    }
	  break;

	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
	  dl->dl_icmp_id  = ntohs(icmp4->icmp_id);
	  dl->dl_icmp_seq = ntohs(icmp4->icmp_seq);
	  break;

	default:
	  return 0;
	}
    }
  else if(dl->dl_ip_proto == IPPROTO_ICMPV6)
    {
      /* the absolute minimum ICMP header size is 8 bytes */
      if((int)sizeof(struct icmp6_hdr) > len)
	{
	  return 0;
	}

      icmp6 = (struct icmp6_hdr *)pkt;
      dl->dl_icmp_type = icmp6->icmp6_type;
      dl->dl_icmp_code = icmp6->icmp6_code;

      switch(dl->dl_icmp_type)
	{
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_DST_UNREACH:
	case ICMP6_PACKET_TOO_BIG:
	  pkt += sizeof(struct icmp6_hdr);
	  len -= sizeof(struct icmp6_hdr);

	  if((int)sizeof(struct ip6_hdr) + 8 > len)
	    {
	      return 0;
	    }

	  if(dl->dl_icmp_type == ICMP6_PACKET_TOO_BIG)
	    {
#ifndef _WIN32
	      dl->dl_icmp_nhmtu = (ntohl(icmp6->icmp6_mtu) % 0xffff);
#else
	      dl->dl_icmp_nhmtu = ntohs(icmp6->icmp6_seq);
#endif
	    }

	  ip6 = (struct ip6_hdr *)pkt;
	  pkt += sizeof(struct ip6_hdr);

	  dl->dl_icmp_ip_proto = ip6->ip6_nxt;
	  dl->dl_icmp_ip_size  = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
	  dl->dl_icmp_ip_hlim  = ip6->ip6_hlim;

#ifndef _WIN32
	  dl->dl_icmp_ip_flow  = ntohl(ip6->ip6_flow) & 0xfffff;
#else
	  dl->dl_icmp_ip_flow  = ntohl(ip6->ip6_vfc_flow) & 0xfffff;
#endif

	  dl->dl_icmp_ip_src = (uint8_t *)&ip6->ip6_src;
	  dl->dl_icmp_ip_dst = (uint8_t *)&ip6->ip6_dst;

	  if(dl->dl_icmp_ip_proto == IPPROTO_UDP)
	    {
	      udp = (struct udphdr *)pkt;
	      dl->dl_icmp_udp_sport = ntohs(udp->uh_sport);
	      dl->dl_icmp_udp_dport = ntohs(udp->uh_dport);
	      dl->dl_icmp_udp_sum   = udp->uh_sum;
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_ICMPV6)
	    {
	      icmp6 = (struct icmp6_hdr *)pkt;
	      dl->dl_icmp_icmp_type = icmp6->icmp6_type;
	      dl->dl_icmp_icmp_code = icmp6->icmp6_code;
	      dl->dl_icmp_icmp_id   = ntohs(icmp6->icmp6_id);
	      dl->dl_icmp_icmp_seq  = ntohs(icmp6->icmp6_seq);
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_TCP)
	    {
	      tcp = (struct tcphdr *)pkt;
	      dl->dl_icmp_tcp_sport = ntohs(tcp->th_sport);
	      dl->dl_icmp_tcp_dport = ntohs(tcp->th_dport);
	      dl->dl_icmp_tcp_seq   = ntohl(tcp->th_seq);
	    }
	  break;

	case ICMP6_ECHO_REPLY:
	case ICMP6_ECHO_REQUEST:
	  dl->dl_icmp_id  = ntohs(icmp6->icmp6_id);
	  dl->dl_icmp_seq = ntohs(icmp6->icmp6_seq);
	  break;

	case ND_ROUTER_ADVERT:
	  scamper_addr2mac_isat_v6(dl->dl_ifindex, pktbuf, pktlen);
	  return 0;

	default:
	  return 0;
	}
    }

  return 1;
}

/*
 * dlt_raw_cb
 *
 * handle raw IP frames.
 * i'm not sure how many of these interface types there are, but the linux
 * sit interface is an example of one that is...
 *
 */
static int dlt_raw_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  int ret;

  if((ret = dl_parse_ip(dl, pkt, len)) != 0)
    {
      dl->dl_type = SCAMPER_DL_TYPE_RAW;
    }

  return ret;
}

/*
 * dlt_null_cb
 *
 * handle the BSD loopback encapsulation.  the first 4 bytes say what protocol
 * family is used.  filter out anything that is not IPv4 / IPv6
 *
 */
static int dlt_null_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  uint32_t pf;
  int ret;

  /* ensure the packet holds at least 4 bytes for the psuedo header */
  if(len <= 4)
    {
      return 0;
    }

  memcpy(&pf, pkt, 4);
  if(pf == PF_INET || pf == PF_INET6)
    {
      if((ret = dl_parse_ip(dl, pkt+4, len-4)) != 0)
	{
	  dl->dl_type = SCAMPER_DL_TYPE_NULL;
	}

      return ret;
    }

  return 0;
}

/*
 * dlt_en10mb_cb
 *
 * handle ethernet frames.
 *
 * an ethernet frame consists of
 *   - 6 bytes dst mac
 *   - 6 bytes src mac
 *   - 2 bytes type
 *
 */
static int dlt_en10mb_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  int ret;
  uint16_t type;
  uint16_t junk16;

  /* ensure the packet holds at least the length of the ethernet header */
  if(len <= 14)
    {
      return 0;
    }

  /*
   * firstly, we check the ethernet frame type to see if it is IPv4 or
   * IPv6.  if it is, then we parse the packet.  if the packet is not
   * mangled, then we complete the datalink record by recording the
   * source and destination mac addresses in the datalink record
   */
  memcpy(&type, pkt+12, 2); type = ntohs(type);
  if(type == ETHERTYPE_IP || type == ETHERTYPE_IPV6)
    {
      if((ret = dl_parse_ip(dl, pkt+14, len-14)) != 0)
	{
	  dl->dl_type = SCAMPER_DL_TYPE_ETHERNET;
	  dl->dl_lladdr_dst = pkt;
	  dl->dl_lladdr_src = pkt + 6;
	}

      return ret;
    }
  /*
   * if this is an arp record, then we pass the arp record to our addr2mac
   * code to maintain the arp record.  we then fall through and return 0
   * which signals to the caller not to process this packet any further
   */
  else if(type == ETHERTYPE_ARP)
    {
      memcpy(&junk16, pkt+14+6, 2); junk16 = ntohs(junk16);
      if(junk16 == 0x0002)
	{
	  scamper_addr2mac_isat_v4(dl->dl_ifindex, pkt, len);
	}
    }

  return 0;
}

/*
 * dlt_firewire_cb
 *
 * handle IP frames on firewire devices.  a firewire layer-2 frame consists
 * of two 8 byte EUI64 addresses which represent the dst and the src
 * addresses, and a 2 byte ethertype
 */
static int dlt_firewire_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  int ret;
  uint16_t type;

  /* ensure the packet holds at least the length of the firewire header */
  if(len <= 18)
    {
      return 0;
    }

  memcpy(&type, pkt+16, 2); type = ntohs(type);
  if(type == ETHERTYPE_IP || type == ETHERTYPE_IPV6)
    {
      if((ret = dl_parse_ip(dl, pkt+18, len-18)) != 0)
	{
	  dl->dl_type = SCAMPER_DL_TYPE_FIREWIRE;
	  dl->dl_lladdr_dst = pkt;
	  dl->dl_lladdr_src = pkt + 8;
	}

      return ret;
    }

  return 0;
}

/*
 * dl_handlerec
 *
 * figure out where the datalink record should be sent and then pass it
 * to whatever task would like it.
 *
 * if the record is an ICMP error message, the record should be passed
 * to a suit
 */
static void dl_handlerec(scamper_dl_rec_t *dl)
{
  scamper_task_t *task;
  scamper_addr_t  addr;

  if(dl->dl_af == AF_INET)
    {
      addr.type = SCAMPER_ADDR_TYPE_IPV4;

      if(dl->dl_ip_proto == IPPROTO_ICMP)
	{
	  if(dl->dl_icmp_type == ICMP_ECHO)
	    {
	      addr.addr = dl->dl_ip_dst;
	    }
	  else if(dl->dl_icmp_type == ICMP_ECHOREPLY)
	    {
	      addr.addr = dl->dl_ip_src;
	    }
	  else
	    {
	      addr.addr = dl->dl_icmp_ip_dst;
	    }
	}
      else if(dl->dl_ip_proto == IPPROTO_TCP)
	{
	  if((dl->dl_tcp_flags & TH_SYN) && (dl->dl_tcp_flags & ~TH_SYN) == 0)
	    {
	      addr.addr = dl->dl_ip_dst;
	    }
	  else
	    {
	      addr.addr = dl->dl_ip_src;
	    }
	}
      else
	{
	  addr.addr = dl->dl_ip_dst;
	}
    }
  else if(dl->dl_af == AF_INET6)
    {
      addr.type = SCAMPER_ADDR_TYPE_IPV6;

      if(dl->dl_ip_proto == IPPROTO_ICMPV6)
	{
	  if(dl->dl_icmp_type == ICMP6_ECHO_REQUEST)
	    {
	      addr.addr = dl->dl_ip_dst;
	    }
	  else if(dl->dl_icmp_type == ICMP6_ECHO_REPLY)
	    {
	      addr.addr = dl->dl_ip_src;
	    }
	  else
	    {
	      addr.addr = dl->dl_icmp_ip_dst;
	    }
	}
      else if(dl->dl_ip_proto == IPPROTO_TCP)
	{
	  if((dl->dl_tcp_flags & TH_SYN) && (dl->dl_tcp_flags & ~TH_SYN) == 0)
	    {
	      addr.addr = dl->dl_ip_dst;
	    }
	  else
	    {
	      addr.addr = dl->dl_ip_src;
	    }
	}
      else
	{
	  addr.addr = dl->dl_ip_dst;
	}
    }
  else return;

  if((task = scamper_target_find(&addr)) == NULL)
    {
      return;
    }
  if(task->funcs->handle_dl != NULL)
    {
      task->funcs->handle_dl(task, dl);
    }

  return;
}

#if defined(HAVE_BPF)
static int dl_bpf_open_dev(char *dev, const size_t len)
{
  int i=0, fd;

  do
    {
      snprintf(dev, len, "/dev/bpf%d", i);
      if((fd = open(dev, O_RDWR)) == -1)
	{
	  if(errno == EBUSY)
	    {
	      continue;
	    }
	  else
	    {
	      printerror(errno, strerror, __func__, "could not open %s", dev);
	      return -1;
	    }
	}
      else break;
    }
  while(++i < 32768);

  return fd;
}

static int dl_bpf_open(const int ifindex)
{
  struct ifreq ifreq;
  char dev[16];
  int  fd;

  /* work out the name corresponding to the ifindex */
  memset(&ifreq, 0, sizeof(ifreq));
  if(if_indextoname((unsigned int)ifindex, ifreq.ifr_name) == NULL)
    {
      printerror(errno, strerror, __func__, "if_indextoname failed");
      return -1;
    }

  if((fd = dl_bpf_open_dev(dev, sizeof(dev))) == -1)
    {
      return -1;
    }

  /* set the interface that will be sniffed */
  if(ioctl(fd, BIOCSETIF, &ifreq) == -1)
    {
      printerror(errno, strerror, __func__, "%s BIOCSETIF %s failed",
		 dev, ifreq.ifr_name);
      close(fd);
      return -1;
    }

  return fd;
}

static int dl_bpf_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  char ifname[IFNAMSIZ];
  u_int tmp;
  int ifindex, fd;
  uint8_t *buf;

  /* get the file descriptor associated with the fd node */
  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      goto err;
    }

  /* get the interface index */
  if(scamper_fd_ifindex(fdn, &ifindex) != 0)
    {
      goto err;
    }

  /* convert the interface index to a name */
  if(if_indextoname((unsigned int)ifindex, ifname) == NULL)
    {
      printerror(errno, strerror, __func__,"if_indextoname %d failed",ifindex);
      goto err;
    }

  /* get the suggested read buffer size */
  if(ioctl(fd, BIOCGBLEN, &node->readbuf_len) == -1)
    {
      printerror(errno, strerror, __func__, "bpf BIOCGBLEN %s failed", ifname);
      goto err;
    }

  /* get the DLT type for the interface */
  if(ioctl(fd, BIOCGDLT, &tmp) == -1)
    {
      printerror(errno, strerror, __func__, "bpf BIOCGDLT %s failed", ifname);
      goto err;
    }
  node->type = tmp;

  switch(node->type)
    {
    case DLT_NULL:
      node->dlt_cb = dlt_null_cb;
      if(osinfo->os_id == SCAMPER_OSINFO_OS_FREEBSD &&
	 osinfo->os_rel[0] >= 6)
	{
	  node->tx_type = SCAMPER_DL_TX_NULL;
	}
      else
	{
	  node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
	}
      break;

    case DLT_EN10MB:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHERNET;
      break;

    case DLT_RAW:
      node->dlt_cb = dlt_raw_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;

#if defined(DLT_APPLE_IP_OVER_IEEE1394)
    case DLT_APPLE_IP_OVER_IEEE1394:
      node->dlt_cb = dlt_firewire_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;
#endif

    default:
      scamper_debug(__func__, "%s unhandled datalink %d", ifname, node->type);
      goto err;
    }

  scamper_debug(__func__, "bpf if %s index %d buflen %d datalink %d",
		ifname, ifindex, node->readbuf_len, node->type);

  tmp = 1;
  if(ioctl(fd, BIOCIMMEDIATE, &tmp) == -1)
    {
      printerror(errno, strerror, __func__, "bpf BIOCIMMEDIATE failed");
      goto err;
    }

  if(readbuf_len < node->readbuf_len)
    {
      if((buf = realloc(readbuf, node->readbuf_len)) == NULL)
	{
	  printerror(errno, strerror, __func__, "could not realloc");
	  return -1;
	}
      readbuf     = buf;
      readbuf_len = node->readbuf_len;
    }

  return 0;

 err:
  return -1;
}

static int dl_bpf_init(void)
{
  struct bpf_version bv;
  int  fd;
  char buf[16];
  int  err;

  if((fd = dl_bpf_open_dev(buf, sizeof(buf))) == -1)
    {
      if(errno == ENXIO)
	{
	  return 0;
	}
      return -1;
    }

  err = ioctl(fd, BIOCVERSION, &bv);
  close(fd);
  if(err == -1)
    {
      printerror(errno, strerror, __func__, "BIOCVERSION failed");
      return -1;
    }

  scamper_debug(__func__, "bpf version %d.%d", bv.bv_major, bv.bv_minor);
  if(bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION)
    {
      fprintf(stderr,
	      "scamper_dl_init: bpf ver %d.%d is incompatible with %d.%d",
	      bv.bv_major, bv.bv_minor, BPF_MAJOR_VERSION, BPF_MINOR_VERSION);
      return -1;
    }

  /*
   * use a global osinfo structure for the datalink code since other
   * bits of the code want to use it too.
   */
  if((osinfo = uname_wrap()) == NULL)
    {
      printerror(errno, strerror, __func__, "uname failed");
      return -1;
    }

  if(osinfo->os_rel[0] == 4 &&
     (osinfo->os_rel[1] == 3 || osinfo->os_rel[1] == 4))
    {
      printerror(0, NULL, __func__,
		 "BPF file descriptors do not work with "
		 "select in FreeBSD 4.3 or 4.4");
      return -1;
    }

  return 0;
}

static int dl_bpf_read(const int fd, scamper_dl_t *node)
{
  struct bpf_hdr    *bpf_hdr;
  scamper_dl_rec_t   dl;
  int                len;
  uint8_t           *buf = readbuf;

  while((len = read(fd, buf, node->readbuf_len)) == -1)
    {
      if(errno == EINTR) continue;
      if(errno == EWOULDBLOCK) return 0;
      printerror(errno, strerror, __func__, "read %d bytes from fd %d failed",
		 node->readbuf_len, fd);
      return -1;
    }

  /* record the ifindex now, as the cb may need it */
  if(scamper_fd_ifindex(node->fdn, &dl.dl_ifindex) != 0)
    {
      return -1;
    }

  while(buf < readbuf + len)
    {
      bpf_hdr = (struct bpf_hdr *)buf;

      /* reset the datalink record */
      memset(&dl, 0, sizeof(dl));

      if(node->dlt_cb(&dl, buf + bpf_hdr->bh_hdrlen, bpf_hdr->bh_caplen))
	{
	  /* bpf always supplies a timestamp */
	  dl.dl_flags |= SCAMPER_DL_FLAG_TIMESTAMP;

	  dl.dl_tv.tv_sec  = bpf_hdr->bh_tstamp.tv_sec;
	  dl.dl_tv.tv_usec = bpf_hdr->bh_tstamp.tv_usec;

	  dl_handlerec(&dl);
	}

      buf += BPF_WORDALIGN(bpf_hdr->bh_caplen + bpf_hdr->bh_hdrlen);
    }

  return 0;
}

static int dl_bpf_tx(const scamper_dl_t *node,
		     const uint8_t *pkt, const size_t len)
{
  ssize_t wb;

  if((wb = write(scamper_fd_fd_get(node->fdn), pkt, len)) < (ssize_t)len)
    {
      if(wb == -1)
	{
	  printerror(errno, strerror, __func__, "%d bytes failed", len);
	}
      else
	{
	  scamper_debug(__func__, "%d bytes sent of %d total", wb, len);
	}

      return -1;
    }

  return 0;
}

static int dl_bpf_filter(scamper_dl_t *node, struct bpf_insn *insns, int len)
{
  struct bpf_program prog;

  prog.bf_len   = len;
  prog.bf_insns = insns;

  if(ioctl(scamper_fd_fd_get(node->fdn), BIOCSETF, (caddr_t)&prog) == -1)
    {
      printerror(errno, strerror, __func__, "BIOCSETF failed");
      return -1;
    }

  return 0;
}

#elif defined(__linux__)

static int dl_linux_open(const int ifindex)
{
  struct sockaddr_ll sll;
  int fd;

  /* open the socket in non cooked mode for now */
  if((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
      printerror(errno, strerror, __func__, "could not open PF_PACKET");
      return -1;
    }

  /* scamper only wants packets on this interface */
  memset(&sll, 0, sizeof(sll));
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);
  if(bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
    {
      printerror(errno, strerror, __func__, "could not bind to %d", ifindex);
      close(fd);
      return -1;
    }

  return fd;
}

static int dl_linux_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  struct ifreq ifreq;
  char ifname[IFNAMSIZ];
  int fd, ifindex;

  if(scamper_fd_ifindex(fdn, &ifindex) != 0)
    {
      goto err;
    }

  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      goto err;
    }

  if(if_indextoname(ifindex, ifname) == NULL)
    {
      printerror(errno, strerror, __func__,"if_indextoname %d failed",ifindex);
      goto err;
    }

  /* find out what type of datalink the interface has */
  memcpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));
  if(ioctl(fd, SIOCGIFHWADDR, &ifreq) == -1)
    {
      printerror(errno, strerror, __func__, "%s SIOCGIFHWADDR failed", ifname);
      goto err;
    }

  node->type = ifreq.ifr_hwaddr.sa_family;

  /* scamper can only deal with ethernet datalinks at this time */
  switch(node->type)
    {
    case ARPHRD_ETHER:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHERNET;
      break;

    case ARPHRD_LOOPBACK:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHLOOP;
      break;

#if defined(ARPHRD_SIT)
    case ARPHRD_SIT:
      node->dlt_cb = dlt_raw_cb;
      node->tx_type = SCAMPER_DL_TX_RAW;
      break;
#endif

#if defined(ARPHRD_IEEE1394)
    case ARPHRD_IEEE1394:
      node->dlt_cb = dlt_firewire_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;
#endif

    default:
      scamper_debug(__func__, "%s unhandled datalink %d", ifname, node->type);
      goto err;
    }

  return 0;

 err:
  return -1;
}

static int dl_linux_read(const int fd, scamper_dl_t *node)
{
  scamper_dl_rec_t   dl;
  ssize_t            len;
  struct sockaddr_ll from;
  socklen_t          fromlen;

  fromlen = sizeof(from);
  while((len = recvfrom(fd, readbuf, readbuf_len, MSG_TRUNC,
			(struct sockaddr *)&from, &fromlen)) == -1)
    {
      if(errno == EINTR)
	{
	  fromlen = sizeof(from);
	  continue;
	}
      if(errno == EAGAIN)
	{
	  return 0;
	}

      printerror(errno, strerror, __func__, "read %d bytes from fd %d failed",
		 readbuf_len, fd);

      return -1;
    }

  /* sanity check the packet length */
  if(len > readbuf_len) len = readbuf_len;

  /* reset the flags */
  dl.dl_flags = 0;

  /* record the ifindex now, as the cb routine may need it */
  if(scamper_fd_ifindex(node->fdn, &dl.dl_ifindex) != 0)
    {
      return -1;
    }

  /* if the packet passes the filter, we need to get the time it was rx'd */
  if(node->dlt_cb(&dl, readbuf, len))
    {
      /* scamper treats the failure of this ioctl as non-fatal */
      if(ioctl(fd, SIOCGSTAMP, &dl.dl_tv) == 0)
	{
	  dl.dl_flags |= SCAMPER_DL_FLAG_TIMESTAMP;
	}
      else
	{
	  printerror(errno, strerror, __func__,
		     "could not SIOCGSTAMP on fd %d", fd);
	}

      dl_handlerec(&dl);
    }

  return 0;
}

static int dl_linux_tx(const scamper_dl_t *node,
		       const uint8_t *pkt, const size_t len)
{
  struct sockaddr_ll sll;
  struct sockaddr *sa = (struct sockaddr *)&sll;
  ssize_t wb;
  int fd, ifindex;

  if(scamper_fd_ifindex(node->fdn, &ifindex) != 0)
    {
      return -1;
    }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;

  if(node->type == ARPHRD_SIT)
    {
      sll.sll_protocol = htons(ETH_P_IPV6);
    }
  else
    {
      sll.sll_protocol = htons(ETH_P_ALL);
    }

  fd = scamper_fd_fd_get(node->fdn);

  if((wb = sendto(fd, pkt, len, 0, sa, sizeof(sll))) < (ssize_t)len)
    {
      if(wb == -1)
	{
	  printerror(errno, strerror, __func__, "%d bytes failed", len);
	}
      else
	{
	  scamper_debug(__func__, "%d bytes sent of %d total", wb, len);
	}

      return -1;
    }

  return 0;
}

static int dl_linux_filter(scamper_dl_t *node,
			   struct sock_filter *insns, int len)
{
  struct sock_fprog prog;
  int i;

  for(i=0; i<len; i++)
    {
      if(insns[i].code == (BPF_RET+BPF_K) && insns[i].k > 0)
	{
	  insns[i].k = 65535;
	}
    }

  prog.len    = len;
  prog.filter = insns;

  if(setsockopt(scamper_fd_fd_get(node->fdn), SOL_SOCKET, SO_ATTACH_FILTER,
		(caddr_t)&prog, sizeof(prog)) == -1)
    {
      printerror(errno, strerror, __func__, "SO_ATTACH_FILTER failed");
      return -1;
    }

  return 0;
}

#elif defined(HAVE_DLPI)

static int dl_dlpi_open(const int ifindex)
{
  char ifname[5+IFNAMSIZ];
  int fd;

  strncpy(ifname, "/dev/", sizeof(ifname));
  if(if_indextoname(ifindex, ifname+5) == NULL)
    {
      printerror(errno, strerror, __func__,"if_indextoname %d failed",ifindex);
      return -1;
    }

  if((fd = open(ifname, O_RDWR)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open %s", ifname);
      return -1;
    }

  return fd;
}

static int dl_dlpi_req(const int fd, void *req, size_t len)
{
  union	DL_primitives *dlp;
  struct strbuf ctl;

  ctl.maxlen = 0;
  ctl.len = len;
  ctl.buf = (char *)req;

  if(putmsg(fd, &ctl, NULL, 0) == -1)
    {
      dlp = req;
      printerror(errno, strerror, __func__,
		 "could not putmsg %d", dlp->dl_primitive);
      return -1;
    }

  return 0;
}

static int dl_dlpi_ack(const int fd, void *ack, int primitive)
{
  union	DL_primitives *dlp;
  struct strbuf ctl;
  int flags;

  flags = 0;
  ctl.maxlen = MAXDLBUF;
  ctl.len = 0;
  ctl.buf = (char *)ack;
  if(getmsg(fd, &ctl, NULL, &flags) == -1)
    {
      printerror(errno, strerror, __func__, "could not getmsg %d", primitive);
      return -1;
    }

  dlp = ack;
  if(dlp->dl_primitive != primitive)
    {
      scamper_debug(__func__,
		    "expected %d, got %d", primitive, dlp->dl_primitive);
      return -1;
    }

  return 0;
}

static int dl_dlpi_promisc(const int fd, const int level)
{
  dl_promiscon_req_t promiscon_req;
  uint32_t buf[MAXDLBUF];

  promiscon_req.dl_primitive = DL_PROMISCON_REQ;
  promiscon_req.dl_level = level;
  if(dl_dlpi_req(fd, &promiscon_req, sizeof(promiscon_req)) == -1)
    {
      return -1;
    }

  /* check for an ack to the promisc req */
  if(dl_dlpi_ack(fd, buf, DL_OK_ACK) == -1)
    {
      return -1;
    }

  return 0;
}

static int strioctl(int fd, int cmd, void *dp, int len)
{
  struct strioctl str;

  str.ic_cmd = cmd;
  str.ic_timout = -1;
  str.ic_len = len;
  str.ic_dp = (char *)dp;
  if(ioctl(fd, I_STR, &str) == -1)
    {
      return -1;
    }

  return str.ic_len;
}

static int dl_dlpi_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  uint32_t         buf[MAXDLBUF];
  struct timeval   tv;
  dl_info_req_t    info_req;
  dl_info_ack_t   *info_ack;
  dl_attach_req_t  attach_req;
  dl_bind_req_t    bind_req;
  int              i, fd;

#ifndef NDEBUG
  char             ifname[IFNAMSIZ];
#endif

  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      return -1;
    }

  /*
   * send an information request to the datalink to determine what type
   * of packets they supply
   */
  info_req.dl_primitive = DL_INFO_REQ;
  if(dl_dlpi_req(fd, &info_req, sizeof(info_req)) == -1)
    {
      return -1;
    }

  /*
   * read the information acknowledgement, which contains details on the
   * type of the interface, etc.
   */
  if(dl_dlpi_ack(fd, buf, DL_INFO_ACK) == -1)
    {
      return -1;
    }
  info_ack = (dl_info_ack_t *)buf;

  /* record the mac type with the node */
  node->type = info_ack->dl_mac_type;
  node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;

  /* determine how to handle the datalink */
  switch(node->type)
    {
    case DL_CSMACD:
    case DL_ETHER:
      node->dlt_cb = dlt_en10mb_cb;
      break;

    default:
      scamper_debug(__func__, "unhandled datalink %d", node->type);
      return -1;
    }

  /* attach to the interface */
  if(info_ack->dl_provider_style == DL_STYLE2)
    {
      attach_req.dl_primitive = DL_ATTACH_REQ;
      attach_req.dl_ppa = 0;
      if(dl_dlpi_req(fd, &attach_req, sizeof(attach_req)) == -1)
	{
	  return -1;
	}

      /* check for a generic ack */
      if(dl_dlpi_ack(fd, buf, DL_OK_ACK) == -1)
	{
	  return -1;
	}
    }

  /* bind the interface */
  memset(&bind_req, 0, sizeof(bind_req));
  bind_req.dl_primitive = DL_BIND_REQ;
  bind_req.dl_service_mode = DL_CLDLS;
  if(dl_dlpi_req(fd, &bind_req, sizeof(bind_req)) == -1)
    {
      return -1;
    }

  /* check for an ack to the bind */
  if(dl_dlpi_ack(fd, buf, DL_BIND_ACK) == -1)
    {
      return -1;
    }

  /*
   * turn on phys and sap promisc modes.  dlpi will not supply outbound
   * probe packets unless in phys promisc mode.
   */
  if(dl_dlpi_promisc(fd, DL_PROMISC_PHYS) == -1 ||
     dl_dlpi_promisc(fd, DL_PROMISC_SAP) == -1)
    {
      return -1;
    }

  /* get full link layer */
  if(strioctl(fd, DLIOCRAW, NULL, 0) == -1)
    {
      printerror(errno, strerror, __func__, "could not DLIOCRAW");
      return -1;
    }

  /* push bufmod */
  if(ioctl(fd, I_PUSH, "bufmod") == -1)
    {
      printerror(errno, strerror, __func__, "could not push bufmod");
      return -1;
    }

  /* we only need the first 128 bytes of the packet */
  i = 128;
  if(strioctl(fd, SBIOCSSNAP, &i, sizeof(i)) == -1)
    {
      printerror(errno, strerror, __func__, "could not SBIOCSSNAP %d", i);
      return -1;
    }

  /* send the data every 50ms */
  tv.tv_sec = 0;
  tv.tv_usec = 50000;
  if(strioctl(fd, SBIOCSTIME, &tv, sizeof(tv)) == -1)
    {
      printerror(errno, strerror, __func__,
		 "could not SBIOCSTIME %d.%06d", tv.tv_sec, tv.tv_usec);
      return -1;
    }

  /* set the chunk length */
  i = 65535;
  if(strioctl(fd, SBIOCSCHUNK, &i, sizeof(i)) == -1)
    {
      printerror(errno, strerror, __func__, "could not SBIOCSCHUNK %d", i);
      return -1;
    }

  if(ioctl(fd, I_FLUSH, FLUSHR) == -1)
    {
      printerror(errno, strerror, __func__, "could not flushr");
      return -1;
    }

#ifndef NDEBUG
  if(scamper_fd_ifindex(fdn, &ifindex) != 0 ||
     if_indextoname(ifindex, ifname) == NULL)
    {
      strncpy(ifname, "<null>");
    }
  scamper_debug(__func__, "dlpi if %s index %d datalink %d",
		ifname, ifindex, node->type);
#endif

  return 0;
}

static int dl_dlpi_read(const int fd, scamper_dl_t *node)
{
  scamper_dl_rec_t  dl;
  struct strbuf     data;
  struct sb_hdr    *sbh;
  uint8_t          *buf = readbuf;
  int               flags;

  flags = 0;
  data.buf = readbuf;
  data.maxlen = readbuf_len;
  data.len = 0;

  if(getmsg(fd, NULL, &data, &flags) == -1)
    {
      printerror(errno, strerror, __func__, "could not getmsg");
      return -1;
    }

  while(buf < readbuf + data.len)
    {
      sbh = (struct sb_hdr *)buf;

      dl.dl_flags = SCAMPER_DL_FLAG_TIMESTAMP;

      if(node->dlt_cb(&dl, buf + sizeof(struct sb_hdr), sbh->sbh_msglen))
	{
	  dl.dl_tv.tv_sec  = sbh->sbh_timestamp.tv_sec;
	  dl.dl_tv.tv_usec = sbh->sbh_timestamp.tv_usec;

	  dl_handlerec(&dl);
	}

      buf += sbh->sbh_totlen;
    }

  return -1;
}

static int dl_dlpi_tx(const scamper_dl_t *node,
		      const uint8_t *pkt, const size_t len)
{
  return -1;
}

#endif

#if defined(HAVE_BPF_FILTER)

#if defined(HAVE_BPF)
static void bpf_stmt(struct bpf_insn *insn, uint16_t code, uint32_t k)
#else
static void bpf_stmt(struct sock_filter *insn, uint16_t code, uint32_t k)
#endif
{
  insn->code = code;
  insn->jt   = 0;
  insn->jf   = 0;
  insn->k    = k;
  return;
}

static int dl_filter(scamper_dl_t *node)
{
#if defined(HAVE_BPF)
  struct bpf_insn insns[1];
#else
  struct sock_filter insns[1];
#endif

  bpf_stmt(&insns[0], BPF_RET+BPF_K, 200);

#if defined(HAVE_BPF)
  if(dl_bpf_filter(node, insns, 1) == -1)
#elif defined(__linux__)
  if(dl_linux_filter(node, insns, 1) == -1)
#endif
    {
      return -1;
    }

   return 0;
}
#endif

int scamper_dl_rec_src(scamper_dl_rec_t *dl, scamper_addr_t *addr)
{
  if(dl->dl_af == AF_INET)
    addr->type = SCAMPER_ADDR_TYPE_IPV4;
  else if(dl->dl_af == AF_INET6)
    addr->type = SCAMPER_ADDR_TYPE_IPV6;
  else
    return -1;

  addr->addr = dl->dl_ip_src;
  return 0;
}

#if !defined(NDEBUG) && !defined(WITHOUT_DEBUGFILE)
void scamper_dl_rec_tcp_print(scamper_dl_rec_t *dl)
{
  static const char *tcpflags[] = {
    "fin",
    "syn",
    "rst",
    "psh",
    "ack",
    "urg",
    "ece",
    "cwr"
  };
  char addr[64];
  char fbuf[32], *flags;
  char ack[18];
  char ipid[16];
  uint8_t u8;
  int i;

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);
  assert(dl->dl_ip_proto == IPPROTO_TCP);

  if((u8 = dl->dl_tcp_flags) != 0)
    {
      flags = fbuf;
      for(i=0; i<8; i++)
	{
	  if((dl->dl_tcp_flags & (1<<i)) != 0)
	    {
	      memcpy(flags, tcpflags[i], 3); flags += 3;
	      u8 &= ~(1<<i);
	      if(u8 != 0)
		{
		  *flags = '-';
		  flags++;
		}
	      else break;
	    }
	}
      *flags = '\0';
      flags = fbuf;
    }
  else
    {
      flags = "nil";
    }

  if(dl->dl_tcp_flags & TH_ACK || dl->dl_tcp_ack != 0)
    {
      snprintf(ack, sizeof(ack), " ack 0x%08x", dl->dl_tcp_ack);
    }
  else ack[0] = '\0';

  if(dl->dl_af == AF_INET)
    snprintf(ipid, sizeof(ipid), "ipid 0x%04x ", dl->dl_ip_id);
  else
    ipid[0] = '\0';

  scamper_debug(NULL, "from %s %stcp %d:%d %s seq 0x%08x%s",
		addr_tostr(dl->dl_af, dl->dl_ip_src, addr, sizeof(addr)),
		ipid, dl->dl_tcp_sport, dl->dl_tcp_dport, flags,
		dl->dl_tcp_seq, ack);

  return;
}
#endif

/*
 * dl_read_cb
 *
 * this function is called by scamper_fds when a BPF fd fires as being
 * available to read from.
 */
void scamper_dl_read_cb(const int fd, void *param)
{
  assert(param != NULL);

#if defined(HAVE_BPF)
  dl_bpf_read(fd, (scamper_dl_t *)param);
#elif defined(__linux__)
  dl_linux_read(fd, (scamper_dl_t *)param);
#elif defined(HAVE_DLPI)
  dl_dlpi_read(fd, (scamper_dl_t *)param);
#endif

  return;
}

void scamper_dl_state_free(scamper_dl_t *dl)
{
  assert(dl != NULL);
  free(dl);
  return;
}

/*
 * scamper_dl_state_alloc
 *
 * given the scamper_fd_t supplied, initialise the file descriptor and do
 * initial setup tasks, then compile and set a filter to pick up the packets
 * scamper is responsible for transmitting.
 */
scamper_dl_t *scamper_dl_state_alloc(scamper_fd_t *fdn)
{
  scamper_dl_t *dl = NULL;

  if((dl = malloc_zero(sizeof(scamper_dl_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "malloc node failed");
      goto err;
    }
  dl->fdn = fdn;

#if defined(HAVE_BPF)
  if(dl_bpf_node_init(fdn, dl) == -1)
#elif defined(__linux__)
  if(dl_linux_node_init(fdn, dl) == -1)
#elif defined(HAVE_DLPI)
  if(dl_dlpi_node_init(fdn, dl) == -1)
#endif
    {
      goto err;
    }

#if defined(HAVE_BPF_FILTER)
  dl_filter(dl);
#endif

  return dl;

 err:
  scamper_dl_state_free(dl);
  return NULL;
}

int scamper_dl_tx(const scamper_dl_t *node,
		  const uint8_t *pkt, const size_t len)
{
#if defined(HAVE_BPF)
  if(dl_bpf_tx(node, pkt, len) == -1)
#elif defined(__linux__)
  if(dl_linux_tx(node, pkt, len) == -1)
#elif defined(HAVE_DLPI)
  if(dl_dlpi_tx(node, pkt, len) == -1)
#endif
    {
      return -1;
    }

  return 0;
}

scamper_dl_hdr_t *scamper_dl_hdr_alloc(scamper_fd_t *fd, scamper_addr_t *src,
				       scamper_addr_t *dst, scamper_addr_t *gw)
{
  scamper_dl_t *dl;
  scamper_dl_hdr_t *dl_hdr = NULL;
  uint16_t dl_size;
  int af, ifindex;

#ifndef NDEBUG
  char addr[64];
#endif

  dl = scamper_fd_read_state(fd);

  switch(dl->tx_type)
    {
    case SCAMPER_DL_TX_UNSUPPORTED:
      return NULL;

    case SCAMPER_DL_TX_ETHERNET:
    case SCAMPER_DL_TX_ETHLOOP:
      dl_size = 14;
      break;

    case SCAMPER_DL_TX_NULL:
      dl_size = sizeof(int);
      break;

    case SCAMPER_DL_TX_RAW:
      dl_size = 0;
      break;

    default:
      scamper_debug(__func__, "unhandled tx_type %d", dl->tx_type);
      return NULL;
    }

  /* get the interface index */
  if(scamper_fd_ifindex(dl->fdn, &ifindex) != 0)
    {
      goto err;
    }

  if((dl_hdr = malloc(sizeof(scamper_dl_hdr_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc dl_hdr");
      goto err;
    }
  dl_hdr->dl_hdr = NULL;

  if((dl_hdr->dl_size = dl_size) == 0)
    {
      return dl_hdr;
    }

  if((dl_hdr->dl_hdr = malloc(dl_size)) == NULL)
    {
      goto err;
    }

  if(dl->tx_type == SCAMPER_DL_TX_ETHERNET)
    {
      /*
       * allocate a datalink header to use, and determine the source mac
       * address to use
       */
      if(scamper_if_getmac(ifindex, dl_hdr->dl_hdr+6) == -1)
	{
	  scamper_debug(__func__, "could not get source mac");
	  goto err;
	}

      /*
       * determine the destination mac address (the target).
       */
      if(gw == NULL)
	{
	  /* no gateway address means destination is on local network */
	  memcpy(dl_hdr->dl_hdr, dl_hdr->dl_hdr+6, 6);
	  if(scamper_addr2mac_whohas(ifindex, src, dst, dl_hdr->dl_hdr) != 1)
	    {
	      scamper_debug(__func__,
			    "could not get destination mac for %s: ifindex %d",
			    scamper_addr_tostr(dst, addr, sizeof(addr)),
			    ifindex);
	      goto err;
	    }
	}
      else if(gw->type == SCAMPER_ADDR_TYPE_ETHERNET)
	{
	  /* the gateway mac address was provided by the route socket */
	  memcpy(dl_hdr->dl_hdr, gw->addr, 6);
	}
      else
	{
	  /* the gateway address was returned as an IP */
	  memcpy(dl_hdr->dl_hdr, dl_hdr->dl_hdr+6, 6);
	  if(scamper_addr2mac_whohas(ifindex, src, gw, dl_hdr->dl_hdr) != 1)
	    {
	      scamper_debug(__func__, "could not get gateway mac");
	      goto err;
	    }
	}

      if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
	{
	  dl_hdr->dl_hdr[12] = 0x08;
	  dl_hdr->dl_hdr[13] = 0x00;
	}
      else if(dst->type == SCAMPER_ADDR_TYPE_IPV6)
	{
	  dl_hdr->dl_hdr[12] = 0x86;
	  dl_hdr->dl_hdr[13] = 0xDD;
	}
      else goto err;
    }
  else if(dl->tx_type == SCAMPER_DL_TX_NULL)
    {
      if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
	{
	  af = AF_INET;
	}
      else if(dst->type == SCAMPER_ADDR_TYPE_IPV6)
	{
	  af = AF_INET6;
	}
      else goto err;

      memcpy(dl_hdr->dl_hdr, &af, sizeof(int));
    }
  else if(dl->tx_type == SCAMPER_DL_TX_ETHLOOP)
    {
      memset(dl_hdr->dl_hdr, 0, 12);
      if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
	{
	  dl_hdr->dl_hdr[12] = 0x08;
	  dl_hdr->dl_hdr[13] = 0x00;
	}
      else if(dst->type == SCAMPER_ADDR_TYPE_IPV6)
	{
	  dl_hdr->dl_hdr[12] = 0x86;
	  dl_hdr->dl_hdr[13] = 0xDD;
	}
      else goto err;
    }
  else goto err;

  return dl_hdr;

 err:
  if(dl_hdr != NULL) scamper_dl_hdr_free(dl_hdr);
  return NULL;
}

void scamper_dl_hdr_free(scamper_dl_hdr_t *hdr)
{
  if(hdr->dl_hdr != NULL) free(hdr->dl_hdr);
  free(hdr);
  return;
}

void scamper_dl_close(int fd)
{
#ifndef _WIN32
  close(fd);
#endif
  return;
}

/*
 * scamper_dl_open_fd
 *
 * routine to actually open a datalink.  called by scamper_dl_open below,
 * as well as by the privsep code.
 */
int scamper_dl_open_fd(const int ifindex)
{
#if defined(HAVE_BPF)
  return dl_bpf_open(ifindex);
#elif defined(__linux__)
  return dl_linux_open(ifindex);
#elif defined(HAVE_DLPI)
  return dl_dlpi_open(ifindex);
#elif defined(_WIN32)
  return -1;
#endif
}

/*
 * scamper_dl_open
 *
 * return a file descriptor for the datalink for the interface specified.
 * use privilege separation if required, otherwise open fd directly.
 */
int scamper_dl_open(const int ifindex)
{
  int fd;

#if defined(WITHOUT_PRIVSEP)
  if((fd = scamper_dl_open_fd(ifindex)) == -1)
#else
  if((fd = scamper_privsep_open_datalink(ifindex)) == -1)
#endif
    {
      scamper_debug(__func__, "could not open ifindex %d", ifindex);
      return -1;
    }

  return fd;
}

void scamper_dl_cleanup()
{
  if(readbuf != NULL)
    {
      free(readbuf);
      readbuf = NULL;
    }

#if defined(HAVE_BPF)
  if(osinfo != NULL)
    {
      scamper_osinfo_free(osinfo);
      osinfo = NULL;
    }
#endif

  return;
}

int scamper_dl_init()
{
#if defined(HAVE_BPF)
  if(dl_bpf_init() == -1)
    {
      return -1;
    }
#elif defined(__linux__)
  readbuf_len = 128;
  if((readbuf = malloc(readbuf_len)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc readbuf");
      readbuf_len = 0;
      return -1;
    }
#elif defined(HAVE_DLPI)
  readbuf_len = 65536; /* magic obtained from pcap-dlpi.c */
  if((readbuf = malloc(readbuf_len)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc readbuf");
      readbuf_len = 0;
      return -1;
    }
#endif

  return 0;
}
