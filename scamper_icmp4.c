/*
 * scamper_icmp4.c
 *
 * $Id: scamper_icmp4.c,v 1.85 2009/05/19 04:40:40 mjl Exp $
 *
 * Copyright (C) 2003-2008 The University of Waikato
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
typedef int ssize_t;
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define IP_HDR_HTONS
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

#if defined(__FreeBSD__)
#include <sys/param.h>
#endif

#if defined(__sun__)
#define _XPG4_2
#define __EXTENSIONS__
#define IP_HDR_HTONS
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif

#if defined(__linux__)
#define __FAVOR_BSD
#include <sys/ioctl.h>
#define IP_HDR_HTONS
#endif

#if defined(__OpenBSD__) && OpenBSD >= 199706

#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include <assert.h>

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_icmp_resp.h"
#include "scamper_icmp4.h"
#include "scamper_privsep.h"
#include "scamper_debug.h"
#include "utils.h"

#ifndef IP_DF
#define IP_DF 0x4000
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef ICMP_UNREACH
#define ICMP_UNREACH 3
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

#ifndef ICMP_MINLEN
#define	ICMP_MINLEN 8
#endif

#ifndef ICMP_UNREACH_NEEDFRAG
#define ICMP_UNREACH_NEEDFRAG 4
#endif

/*
 * if the [linux] system has SO_TIMESTAMP, then do not use SIOCGSTAMP, as
 * that requires an extra system call
 */
#if defined(SO_TIMESTAMP)
#undef SIOCGSTAMP
#endif

static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;

uint16_t scamper_icmp4_cksum(scamper_probe_t *probe)
{
  uint16_t tmp, *w;
  int i, sum = 0;

  sum += htons(((probe->pr_icmp_type << 8) | probe->pr_icmp_code));
  sum += htons(probe->pr_icmp_id);
  sum += htons(probe->pr_icmp_seq);

  w = (uint16_t *)probe->pr_data;
  for(i = probe->pr_len; i > 1; i -= 2)
    {
      sum += *w++;
    }
  if(i != 0)
    {
      sum += ((uint8_t *)w)[0];
    }

  /* fold the checksum */
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  if((tmp = ~sum) == 0)
    {
      tmp = 0xffff;
    }

  return tmp;
}

static void ip4_build(scamper_probe_t *probe, uint8_t *buf)
{
  struct ip *ip = (struct ip *)buf;

#ifndef _WIN32
  ip->ip_v   = 4;
  ip->ip_hl  = 5;
#else
  ip->ip_vhl = 0x45;
#endif

  ip->ip_tos = probe->pr_ip_tos;
  ip->ip_len = htons(20 + 8 + probe->pr_len);
  ip->ip_id  = htons(probe->pr_ip_id);
  ip->ip_off = htons(IP_DF);
  ip->ip_ttl = probe->pr_ip_ttl;
  ip->ip_p   = IPPROTO_ICMP;
  ip->ip_sum = 0;
  memcpy(&ip->ip_src, probe->pr_ip_src->addr, sizeof(ip->ip_src));
  memcpy(&ip->ip_dst, probe->pr_ip_dst->addr, sizeof(ip->ip_dst));
  ip->ip_sum = in_cksum(ip, sizeof(struct ip));

  return;
}

static void icmp4_build(scamper_probe_t *probe, uint8_t *buf)
{
  struct icmp *icmp = (struct icmp *)buf;

  icmp->icmp_type  = probe->pr_icmp_type;
  icmp->icmp_code  = probe->pr_icmp_code;
  icmp->icmp_cksum = 0;
  icmp->icmp_id    = htons(probe->pr_icmp_id);
  icmp->icmp_seq   = htons(probe->pr_icmp_seq);

  /* if there is data to include in the payload, copy it in now */
  if(probe->pr_len > 0)
    {
      memcpy(buf + 8, probe->pr_data, probe->pr_len);
    }

  icmp->icmp_cksum = in_cksum(icmp, (size_t)(probe->pr_len + 8));

  return;
}

int scamper_icmp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  size_t req = 20 + 8 + probe->pr_len;

  if(req <= *len)
    {
      ip4_build(probe, buf);
      icmp4_build(probe, buf + 20);

      *len = req;
      return 0;
    }

  *len = req;
  return -1;
}

/*
 * scamper_icmp4_probe
 *
 * send an ICMP probe to a destination
 */
int scamper_icmp4_probe(scamper_probe_t *probe)
{
  struct sockaddr_in  sin4;
  char                addr[128];
  size_t              len;
  int                 i, icmphdrlen;
  uint8_t            *buf;

#if !defined(IP_HDR_HTONS)
  struct ip          *ip;
#endif

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_ICMP);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len > 0 || probe->pr_data == NULL);

  switch(probe->pr_icmp_type)
    {
    case ICMP_ECHO:
      icmphdrlen = (1 + 1 + 2 + 2 + 2);
      break;

    default:
      probe->pr_errno = EINVAL;
      return -1;
    }

  len = sizeof(struct ip) + icmphdrlen + probe->pr_len;

  i = len;
  if(setsockopt(probe->pr_fd,
		SOL_SOCKET, SO_SNDBUF, (char *)&i, sizeof(i)) == -1)
    {
      printerror(errno, strerror, __func__,
		 "could not set buffer to %d bytes", i);
      return -1;
    }

  if(pktbuf_len < len)
    {
      if((buf = realloc(pktbuf, len)) == NULL)
	{
	  printerror(errno, strerror, __func__, "could not realloc");
	  return -1;
	}
      pktbuf     = buf;
      pktbuf_len = len;
    }

  /* build the IPv4 header from the probe structure */
  ip4_build(probe, pktbuf);

  /* byte swap the length and offset fields back to host-byte order if reqd */
#if !defined(IP_HDR_HTONS)
  ip = (struct ip *)pktbuf;
  ip->ip_len = ntohs(ip->ip_len);
  ip->ip_off = ntohs(ip->ip_off);
#endif

  icmp4_build(probe, pktbuf + 20);

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET,
		   probe->pr_ip_dst->addr, 0);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  i = sendto(probe->pr_fd, pktbuf, len, 0, (struct sockaddr *)&sin4,
	     sizeof(struct sockaddr_in));

  if(i < 0)
    {
      /* error condition, could not send the packet at all */
      probe->pr_errno = errno;
      printerror(probe->pr_errno, strerror, __func__,
		 "could not send to %s (%d ttl, %d seq, %d len)",
		 scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)),
		 probe->pr_ip_ttl, probe->pr_icmp_seq, len);
      return -1;
    }
  else if((size_t)i != len)
    {
      /* error condition, sent a portion of the probe */
      fprintf(stderr,
	      "scamper_icmp4_probe: sent %d bytes of %d byte packet to %s",
	      i, (int)len,
	      scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
      return -1;
    }

  return 0;
}

/*
 * scamper_icmp4_icmp_ip_len
 *
 * this function returns the ip header's length field inside an icmp message
 * in a consistent fashion based on the system it is running on and the
 * type of the message.
 *
 * thanks to the use of an ICMP_FILTER or scamper's own type filtering, the
 * two ICMP types scamper has to deal with are ICMP_TIMXCEED and ICMP_UNREACH
 *
 * note that the filtering will filter any ICMP_TIMXCEED message with a code
 * other than ICMP_TIMXCEED_INTRANS, but we might as well deal with the whole
 * type.
 *
 * the pragmatic way is just to use pcap, which passes packets up in network
 * byte order consistently.
 */
static uint16_t scamper_icmp4_icmp_ip_len(const struct icmp *icmp)
{
  uint16_t len;

#if defined(__linux__) || defined(__OpenBSD__) || defined(__sun__) || defined(_WIN32)
  len = ntohs(icmp->icmp_ip.ip_len);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__) || defined(__DragonFly__)
  if(icmp->icmp_type == ICMP_TIMXCEED)
    {
      if(icmp->icmp_code <= 1)
	{
	  len = icmp->icmp_ip.ip_len;
	}
      else
	{
	  len = ntohs(icmp->icmp_ip.ip_len);
	}
    }
  else
    {
      switch(icmp->icmp_code)
	{
	case ICMP_UNREACH_NET:
	case ICMP_UNREACH_HOST:
	case ICMP_UNREACH_PROTOCOL:
	case ICMP_UNREACH_PORT:
	case ICMP_UNREACH_SRCFAIL:
	case ICMP_UNREACH_NEEDFRAG:
	case ICMP_UNREACH_NET_UNKNOWN:
	case ICMP_UNREACH_NET_PROHIB:
	case ICMP_UNREACH_TOSNET:
	case ICMP_UNREACH_HOST_UNKNOWN:
	case ICMP_UNREACH_ISOLATED:
	case ICMP_UNREACH_HOST_PROHIB:
	case ICMP_UNREACH_TOSHOST:

# if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
	case ICMP_UNREACH_HOST_PRECEDENCE:
	case ICMP_UNREACH_PRECEDENCE_CUTOFF:
	case ICMP_UNREACH_FILTER_PROHIB:
# endif
	  len = icmp->icmp_ip.ip_len;
	  break;

	default:
	  len = ntohs(icmp->icmp_ip.ip_len);
	}
    }
#else
  len = icmp->icmp_ip.ip_len;
#endif

  return len;
}

/*
 * scamper_icmp4_ip_len
 *
 * given the ip header encapsulating the icmp response, return the length
 * of the ip packet
 */
static uint16_t scamper_icmp4_ip_len(const struct ip *ip)
{
  uint16_t len;

#if defined(__linux__) || defined(__OpenBSD__) || defined(__sun__) || defined(_WIN32)
  len = ntohs(ip->ip_len);
#else
  len = ip->ip_len + (ip->ip_hl << 2);
#endif

  return len;
}

/*
 * icmp4_recv_ip_outer
 *
 * copy the outer-details of the ICMP message into the response structure.
 * get details of the time the packet was received.
 */
#ifndef _WIN32
static void icmp4_recv_ip_outer(int fd, scamper_icmp_resp_t *resp,
				struct ip *ip, struct icmp *icmp,
				struct msghdr *msg)
#else
static void icmp4_recv_ip_outer(int fd, scamper_icmp_resp_t *resp,
				struct ip *ip, struct icmp *icmp)
#endif
{
  /*
   * to start with, get a timestamp from the kernel if we can, otherwise
   * just get one from user-space.
   */
#if defined(SO_TIMESTAMP)
  struct cmsghdr *cmsg;

  /*
   * RFC 2292:
   * this should be taken care of by CMSG_FIRSTHDR, but not always is.
   */
  if(msg->msg_controllen >= sizeof(struct cmsghdr))
    {
      cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(msg);
      while(cmsg != NULL)
	{
	  if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP)
	    {
	      timeval_cpy(&resp->ir_rx, (struct timeval *)CMSG_DATA(cmsg));
	      resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;
	      break;
	    }
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(msg, cmsg);
	}
    }  
#elif defined(SIOCGSTAMP)
  if(ioctl(fd, SIOCGSTAMP, &resp->ir_rx) != -1)
    {
      resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;
    }
#else
  gettimeofday_wrap(&resp->ir_rx);
#endif

  /* the response came from ... */
  memcpy(&resp->ir_ip_src.v4, &ip->ip_src, sizeof(struct in_addr));

  resp->ir_af        = AF_INET;
  resp->ir_ip_ttl    = ip->ip_ttl;
  resp->ir_ip_id     = ntohs(ip->ip_id);
  resp->ir_ip_tos    = ip->ip_tos;
  resp->ir_ip_size   = scamper_icmp4_ip_len(ip);
  resp->ir_icmp_type = icmp->icmp_type;
  resp->ir_icmp_code = icmp->icmp_code;

  return;
}

int scamper_icmp4_recv(int fd, scamper_icmp_resp_t *resp)
{
  uint8_t              pbuf[512];
  ssize_t              poffset;
  ssize_t              pbuflen;
  struct icmp         *icmp;
  struct ip           *ip_outer = (struct ip *)pbuf;
  struct ip           *ip_inner;
  struct udphdr       *udp;
  struct tcphdr       *tcp;
  uint8_t              type, code;
  uint8_t              nh;
  int                  iphdrlen;
  uint8_t             *ext;
  ssize_t              extlen;

#ifndef _WIN32
  struct sockaddr_in   from;
  uint8_t              ctrlbuf[256];
  struct msghdr        msg;
  struct iovec         iov;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)pbuf;
  iov.iov_len  = sizeof(pbuf);

  msg.msg_name       = (caddr_t)&from;
  msg.msg_namelen    = sizeof(from);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((pbuflen = recvmsg(fd, &msg, 0)) == -1)
    {
      printerror(errno, strerror, __func__, "could not recvmsg");
      return -1;
    }

  iphdrlen = ip_outer->ip_hl << 2;

#else

  if((pbuflen = recv(fd, pbuf, sizeof(pbuf), 0)) == SOCKET_ERROR)
    {
      printerror(errno, strerror, __func__, "could not recv");
      return -1;
    }

  iphdrlen = (ip_outer->ip_vhl & 0xf) << 2;

#endif

  /*
   * an ICMP header has to be at least 8 bytes:
   * 1 byte type, 1 byte code, 2 bytes checksum, 4 bytes 'data'
   */
  if(pbuflen < iphdrlen + 8)
    {
      scamper_debug(__func__, "pbuflen [%d] < iphdrlen [%d] + 8",
		    pbuflen, iphdrlen); 
      return -1;
    }

  icmp = (struct icmp *)(pbuf + iphdrlen);
  type = icmp->icmp_type;
  code = icmp->icmp_code;

  /* check to see if the ICMP type / code is what we want */ 
  if((type != ICMP_TIMXCEED || code != ICMP_TIMXCEED_INTRANS) && 
      type != ICMP_UNREACH && type != ICMP_ECHOREPLY)
    {
      scamper_debug(__func__, "type %d, code %d not wanted", type, code);
      return -1;
    }

  memset(resp, 0, sizeof(scamper_icmp_resp_t));

  resp->ir_fd = fd;

  /*
   * if we get an ICMP echo reply, there is no 'inner' IP packet as there
   * was no error condition.
   * so get the outer packet's details and be done
   */
  if(type == ICMP_ECHOREPLY)
    {
      resp->ir_icmp_id  = ntohs(icmp->icmp_id);
      resp->ir_icmp_seq = ntohs(icmp->icmp_seq);
      memcpy(&resp->ir_inner_ip_dst.v4, &ip_outer->ip_src,
	     sizeof(struct in_addr));

#ifndef _WIN32
      icmp4_recv_ip_outer(fd, resp, ip_outer, icmp, &msg);
#else
      icmp4_recv_ip_outer(fd, resp, ip_outer, icmp);
#endif

      return 0;
    }

  ip_inner = &icmp->icmp_ip;
  nh = ip_inner->ip_p;

#ifndef _WIN32
  poffset = iphdrlen + ICMP_MINLEN + (ip_inner->ip_hl << 2);
#else
  poffset = iphdrlen + ICMP_MINLEN + ((ip_inner->ip_vhl & 0xf) << 2);
#endif

  /* search for an ICMP / UDP / TCP header in this packet */
  while(poffset + 8 <= pbuflen)
    {
      /* if we can't deal with the inner header, then stop now */
      if(nh != IPPROTO_UDP && nh != IPPROTO_ICMP && nh != IPPROTO_TCP)
        {
          scamper_debug(__func__, "unhandled next header %d", nh);
	  return -1;
	}

      resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_INNER_IP;

      /* record details of the IP header and the ICMP headers */
#ifndef _WIN32
      icmp4_recv_ip_outer(fd, resp, ip_outer, icmp, &msg);
#else
      icmp4_recv_ip_outer(fd, resp, ip_outer, icmp);
#endif

      /* record details of the IP header found in the ICMP error message */
      memcpy(&resp->ir_inner_ip_dst.v4, &ip_inner->ip_dst,
	     sizeof(struct in_addr));

      resp->ir_inner_ip_proto = nh;
      resp->ir_inner_ip_ttl   = ip_inner->ip_ttl;
      resp->ir_inner_ip_id    = ntohs(ip_inner->ip_id);
      resp->ir_inner_ip_tos   = ip_inner->ip_tos;
      resp->ir_inner_ip_size  = scamper_icmp4_icmp_ip_len(icmp);

      if(type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG)
	{
	  resp->ir_icmp_nhmtu = ntohs(icmp->icmp_nextmtu);
	}

      if(nh == IPPROTO_UDP)
	{
          udp = (struct udphdr *)(pbuf+poffset);
	  resp->ir_inner_udp_sport = ntohs(udp->uh_sport);
	  resp->ir_inner_udp_dport = ntohs(udp->uh_dport);
	  resp->ir_inner_udp_sum   = udp->uh_sum;
	}
      else if(nh == IPPROTO_ICMP)
	{
	  icmp = (struct icmp *)(pbuf+poffset);
	  resp->ir_inner_icmp_type = icmp->icmp_type;
	  resp->ir_inner_icmp_code = icmp->icmp_code;
	  resp->ir_inner_icmp_sum  = icmp->icmp_cksum;
	  resp->ir_inner_icmp_id   = ntohs(icmp->icmp_id);
	  resp->ir_inner_icmp_seq  = ntohs(icmp->icmp_seq);
	}
      else if(nh == IPPROTO_TCP)
	{
	  tcp = (struct tcphdr *)(pbuf+poffset);
	  resp->ir_inner_tcp_sport = ntohs(tcp->th_sport);
	  resp->ir_inner_tcp_dport = ntohs(tcp->th_dport);
	  resp->ir_inner_tcp_seq   = ntohl(tcp->th_seq);
	}

      /*
       * check for ICMP extensions
       *
       * the length of the message must be at least padded out to 128 bytes,
       * and must have 4 bytes of header beyond that for there to be
       * extensions included
       */
      if(pbuflen - (iphdrlen+8) > 128 + 4)
	{
	  ext    = pbuf    + (iphdrlen + 8 + 128);
	  extlen = pbuflen - (iphdrlen + 8 + 128);

	  if((ext[0] & 0xf0) == 0x20 &&
	     ((ext[2] == 0 && ext[3] == 0) || in_cksum(ext, extlen) == 0))
	    {
	      resp->ir_ext    = memdup(ext, extlen);
	      resp->ir_extlen = extlen;
	    }
	}

      return 0;
    }

  scamper_debug(__func__, "packet not ours");

  return -1;
}

void scamper_icmp4_read_cb(const int fd, void *param)
{
  scamper_icmp_resp_t resp;

  resp.ir_ext = NULL;

  if(scamper_icmp4_recv(fd, &resp) == 0)
    {
      scamper_icmp_resp_handle(&resp);
    }

  if(resp.ir_ext != NULL)
    {
      free(resp.ir_ext);
    }

  return;
}

void scamper_icmp4_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

void scamper_icmp4_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_icmp4_open(const void *addr)
{
  struct sockaddr_in sin;
  int fd = -1;
  int opt;

#ifndef _WIN32
  int   hdr;
#else
  DWORD hdr;
#endif

#if defined(ICMP_FILTER)
  struct icmp_filter filter;
#endif

#if defined(WITHOUT_PRIVSEP)
  if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
#else
  if((fd = scamper_privsep_open_icmp(AF_INET)) == -1)
#endif
    {
      printerror(errno, strerror, __func__, "could not open ICMP socket");
      goto err;
    }

#ifndef _WIN32
  hdr = 1;
  if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hdr, sizeof(hdr)) == -1)
#else
  hdr = TRUE;
  if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (char *)&hdr, sizeof(hdr)) == -1)
#endif
    {
      printerror(errno, strerror, __func__, "could not set IP_HDRINCL");
      goto err;
    }

  opt = 65535 + 128;
#ifndef _WIN32
  if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
#else
  if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&opt, sizeof(opt)) == -1)
#endif
    {
      printerror(errno, strerror, __func__, "could not set SO_RCVBUF");
      goto err;
    }

#if defined(SO_TIMESTAMP)
  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) == -1)
    {
      printerror(errno, strerror, __func__, "could not set SO_TIMESTAMP");
      goto err;
    }
#endif

  /*
   * on linux systems with ICMP_FILTER defined, filter all messages except
   * destination unreachable and time exceeded messages
   */
#if defined(ICMP_FILTER)
  filter.data = ~((1 << ICMP_DEST_UNREACH)  |
		  (1 << ICMP_TIME_EXCEEDED) |
		  (1 << ICMP_ECHOREPLY)
		  );
  if(setsockopt(fd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter)) == -1)
    {
      printerror(errno, strerror, __func__, "could not set ICMP_FILTER");
      goto err;
    }
#endif

  if(addr != NULL)
    {
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, addr, 0);
      if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
	  printerror(errno, strerror, __func__, "could not bind");
	  goto err;
	}
    }

  return fd;

 err:
  if(fd != -1) scamper_icmp4_close(fd);
  return -1;
}
