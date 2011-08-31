/*
 * scamper_icmp6.c
 *
 * $Id: scamper_icmp6.c,v 1.79 2009/05/19 04:40:40 mjl Exp $
 *
 * Copyright (C) 2003-2009 The University of Waikato
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_icmp_resp.h"
#include "scamper_ip6.h"
#include "scamper_icmp6.h"
#include "scamper_privsep.h"
#include "scamper_debug.h"
#include "utils.h"

/*
 * if the [linux] system has SO_TIMESTAMP, then do not use SIOCGSTAMP, as
 * that requires an extra system call
 */
#if defined(SO_TIMESTAMP)
#undef SIOCGSTAMP
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

#ifndef ICMP6_TIME_EXCEED_TRANSIT
#define ICMP6_TIME_EXCEED_TRANSIT 0
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#endif

#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY 129
#endif

static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;

uint16_t scamper_icmp6_cksum(scamper_probe_t *probe)
{
  uint16_t tmp, *w;
  int i, sum = 0;

  /*
   * the ICMP6 checksum includes a checksum calculated over a psuedo header
   * that includes the src and dst IP addresses, the protocol tyoe, and
   * the ICMP6 length.  this is a departure from the ICMPv4 checksum, which
   * was only over the payload of the packet
   */
  w = (uint16_t *)probe->pr_ip_src->addr;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  w = (uint16_t *)probe->pr_ip_dst->addr;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += htons(probe->pr_len + 8);
  sum += htons(IPPROTO_ICMPV6);

  /* ICMP header */
  sum += htons((probe->pr_icmp_type << 8) | probe->pr_icmp_code);
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

int scamper_icmp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  struct ip6_hdr   *ip6;
  struct icmp6_hdr *icmp;
  size_t            ip6hlen, req, icmp6hlen;

  /*
   * build the IPv6 header; pass in the total buffer space available in
   * the ip6hlen parameter.  when this function returns, that value is
   * replaced by the length of the IPv6 header including any options
   */
  ip6hlen = *len;
  scamper_ip6_build(probe, buf, &ip6hlen);

  /* currently, we only understand how to build ICMP6 echo packets */
  icmp6hlen = 8;

  /* calculate the total number of bytes required for this packet */
  req = ip6hlen + icmp6hlen + probe->pr_len;

  if(req <= *len)
    {
      /*
       * calculate and record the ip6_plen value.
       * any IPv6 extension headers present are considered part of the payload
       */
      ip6 = (struct ip6_hdr *)buf;
      ip6->ip6_plen = htons(ip6hlen - 40 + icmp6hlen + probe->pr_len);

      /* build the icmp6 header */
      icmp = (struct icmp6_hdr *)buf;
      icmp->icmp6_type  = probe->pr_icmp_type;
      icmp->icmp6_code  = probe->pr_icmp_code;
      icmp->icmp6_id    = htons(probe->pr_icmp_id);
      icmp->icmp6_seq   = htons(probe->pr_icmp_seq);

      /* if there is data to include in the payload, copy it in now */
      if(probe->pr_len > 0)
	{
	  memcpy(buf + ip6hlen + icmp6hlen, probe->pr_data, probe->pr_len);
	}

      /* compute the ICMP6 checksum */
      icmp->icmp6_cksum = scamper_icmp6_cksum(probe);

      *len = req;
      return 0;
    }

  *len = req;
  return -1;
}

int scamper_icmp6_probe(scamper_probe_t *probe)
{
  struct sockaddr_in6  sin6;
  struct icmp6_hdr    *icmp;
  char                 addr[128];
  size_t               len, icmphdrlen;
  int                  i;
  uint8_t             *buf;

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_ICMPV6);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len > 0 || probe->pr_data == NULL);

  switch(probe->pr_icmp_type)
    {
    case ICMP6_ECHO_REQUEST:
      icmphdrlen = (1 + 1 + 2 + 2 + 2);
      break;

    default:
      probe->pr_errno = EINVAL;
      return -1;
    }

  icmphdrlen = (1 + 1 + 2 + 2 + 2);
  len = probe->pr_len + icmphdrlen;

  i = probe->pr_ip_ttl;
  if(setsockopt(probe->pr_fd,
		IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&i, sizeof(i)) == -1)
    {
      printerror(errno, strerror, __func__, "could not set hlim to %d", i);
      return -1;
    }

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

  icmp = (struct icmp6_hdr *)pktbuf;
  icmp->icmp6_type  = probe->pr_icmp_type;
  icmp->icmp6_code  = probe->pr_icmp_code;
  icmp->icmp6_cksum = 0;
  icmp->icmp6_id    = htons(probe->pr_icmp_id);
  icmp->icmp6_seq   = htons(probe->pr_icmp_seq);

  /* if there is data to include in the payload, copy it in now */
  if(probe->pr_len > 0)
    {
      memcpy(pktbuf + icmphdrlen, probe->pr_data, probe->pr_len);
    }

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6,
		   probe->pr_ip_dst->addr, 0);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  i = sendto(probe->pr_fd, pktbuf, len, 0, (struct sockaddr *)&sin6,
	     sizeof(struct sockaddr_in6));

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
	      "scamper_icmp6_probe: sent %d bytes of %d byte packet to %s",
	      i, (int)len,
	      scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
      return -1;
    }

  return 0;
}

/*
 * icmp6_recv_ip_outer
 *
 * copy the outer-details of the ICMP6 message into the response structure.
 * get details of when the packet was received.
 */
static void icmp6_recv_ip_outer(int fd, scamper_icmp_resp_t *resp,
#ifndef _WIN32
				struct msghdr *msg,
#endif
				struct icmp6_hdr *icmp,
				struct sockaddr_in6 *from, size_t size)
{
  int16_t hlim = -1;

#if (defined(IPV6_HOPLIMIT) || defined(SO_TIMESTAMP)) && !defined(_WIN32)
  /* get the HLIM field of the ICMP6 packet returned */
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
#if defined(IPV6_HOPLIMIT)
	  if(cmsg->cmsg_level == IPPROTO_IPV6 &&
	     cmsg->cmsg_type == IPV6_HOPLIMIT)
	    {
	      hlim = *((uint8_t *)CMSG_DATA(cmsg));
	    }
#endif

#if defined(SO_TIMESTAMP)
	  if(cmsg->cmsg_level == SOL_SOCKET &&
	     cmsg->cmsg_type == SCM_TIMESTAMP)
	    {
	      timeval_cpy(&resp->ir_rx, (struct timeval *)CMSG_DATA(cmsg));
	      resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;
	    }
#endif
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(msg, cmsg);
	}
    }
#endif

#if defined(__linux__) && !defined(SO_TIMESTAMP) && defined(SIOCGSTAMP)
  if(ioctl(fd, SIOCGSTAMP, &resp->ir_rx) != -1)
    {
      resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;
    }
#else
  gettimeofday_wrap(&resp->ir_rx);
#endif

  memcpy(&resp->ir_ip_src.v6, &from->sin6_addr, sizeof(struct in6_addr));

  resp->ir_af        = AF_INET6;
  resp->ir_icmp_type = icmp->icmp6_type;
  resp->ir_icmp_code = icmp->icmp6_code;
  resp->ir_ip_hlim   = hlim;
  resp->ir_ip_size   = size;

  return;
}

/*
 * scamper_icmp6_recv
 *
 * handle receiving an ICMPv6 packet.
 *
 * if the packet is an ICMP response that we should concern ourselves with
 * (i.e. it is in response to one of our UDP probes) then we fill out
 * the attached icmp_response structure and return zero.
 *
 * if we should ignore this packet, or an error condition occurs, then
 * we return -1.
 */
int scamper_icmp6_recv(int fd, scamper_icmp_resp_t *resp)
{
  struct sockaddr_in6  from;
  uint8_t              pbuf[65536];
  ssize_t              poffset;
  ssize_t              pbuflen;
  struct icmp6_hdr    *icmp;
  struct ip6_hdr      *ip;
  struct udphdr       *udp;
  struct tcphdr       *tcp;
  uint8_t              type, code;
  uint8_t              nh;
  uint8_t             *ext;
  ssize_t              extlen;

#ifndef _WIN32
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
#endif

#ifdef _WIN32
  if((pbuflen = recv(fd, pbuf, sizeof(pbuf), 0)) < 0)
    {
      printerror(errno, strerror, __func__, "could not recv");
      return -1;
    }
#endif

  icmp = (struct icmp6_hdr *)pbuf;
  if(pbuflen < (ssize_t)sizeof(struct icmp6_hdr))
    {
      return -1; 
    }

  type = icmp->icmp6_type;
  code = icmp->icmp6_code;

  /* check to see if the ICMP type / code is what we want */ 
  if((type != ICMP6_TIME_EXCEEDED || code != ICMP6_TIME_EXCEED_TRANSIT) && 
      type != ICMP6_DST_UNREACH && type != ICMP6_PACKET_TOO_BIG &&
      type != ICMP6_ECHO_REPLY)
    {
      scamper_debug(__func__,"ICMP6 type %d / code %d not wanted", type, code);
      return -1;
    }

  poffset  = sizeof(struct icmp6_hdr);
  ip       = (struct ip6_hdr *)(pbuf + poffset);

  memset(resp, 0, sizeof(scamper_icmp_resp_t));

  resp->ir_fd = fd;

  if(type == ICMP6_ECHO_REPLY)
    {
      resp->ir_icmp_id  = ntohs(icmp->icmp6_id);
      resp->ir_icmp_seq = ntohs(icmp->icmp6_seq);
      memcpy(&resp->ir_inner_ip_dst.v6, &from.sin6_addr,
	     sizeof(struct in6_addr));

#ifndef _WIN32
      icmp6_recv_ip_outer(fd,resp,&msg,icmp,&from,
			  pbuflen + sizeof(struct ip6_hdr));
#else
      icmp6_recv_ip_outer(fd,resp,icmp,&from,pbuflen+sizeof(struct ip6_hdr));
#endif

      return 0;
    }

  nh       = ip->ip6_nxt;
  poffset += sizeof(struct ip6_hdr);

  /* search for a ICMP / UDP / TCP header in this packet */
  while(poffset + (ssize_t)sizeof(struct udphdr) <= pbuflen)
    {
      if(nh != IPPROTO_UDP && nh != IPPROTO_ICMPV6 && nh != IPPROTO_TCP)
        {
	  scamper_debug(__func__, "unhandled next header %d", nh);
	  return -1;
	}

      resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_INNER_IP;

      /* record details of the IP header and the ICMP headers */
#ifndef _WIN32
      icmp6_recv_ip_outer(fd,resp,&msg,icmp,&from,
			  pbuflen + sizeof(struct ip6_hdr));
#else
      icmp6_recv_ip_outer(fd,resp,icmp,&from,pbuflen+sizeof(struct ip6_hdr));
#endif

      memcpy(&resp->ir_inner_ip_dst.v6, &ip->ip6_dst, sizeof(struct in6_addr));
      resp->ir_inner_ip_proto = nh;
      resp->ir_inner_ip_hlim  = ip->ip6_hlim;
      resp->ir_inner_ip_size  = ntohs(ip->ip6_plen) + sizeof(struct ip6_hdr);

#ifndef _WIN32
      resp->ir_inner_ip_flow = ntohl(ip->ip6_flow) & 0xfffff;
#else
      resp->ir_inner_ip_flow = ntohl(ip->ip6_vfc_flow) & 0xfffff;
#endif

      if(type == ICMP6_PACKET_TOO_BIG)
	{
#ifndef _WIN32
	  resp->ir_icmp_nhmtu = (ntohl(icmp->icmp6_mtu) % 0xffff);
#else
	  resp->ir_icmp_nhmtu = ntohs(icmp->icmp6_seq);
#endif
	}

      if(nh == IPPROTO_UDP)
	{
          udp = (struct udphdr *)(pbuf+poffset);
	  resp->ir_inner_udp_sport = ntohs(udp->uh_sport);
	  resp->ir_inner_udp_dport = ntohs(udp->uh_dport);
	  resp->ir_inner_udp_sum   = udp->uh_sum;
	}
      else if(nh == IPPROTO_ICMPV6)
	{
	  icmp = (struct icmp6_hdr *)(pbuf+poffset);
	  resp->ir_inner_icmp_type = icmp->icmp6_type;
	  resp->ir_inner_icmp_code = icmp->icmp6_code;
	  resp->ir_inner_icmp_sum  = icmp->icmp6_cksum;
	  resp->ir_inner_icmp_id   = ntohs(icmp->icmp6_id);
	  resp->ir_inner_icmp_seq  = ntohs(icmp->icmp6_seq);
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
      if(pbuflen - 8 > 128 + 4)
	{
	  ext    = pbuf    + (8 + 128);
	  extlen = pbuflen - (8 + 128);

	  if((ext[0] & 0xf0) == 0x20 &&
	     ((ext[2] == 0 && ext[3] == 0) || in_cksum(ext, extlen) == 0))
	    {
	      resp->ir_ext    = memdup(ext, extlen);
	      resp->ir_extlen = extlen;
	    }
	}

      return 0;
    }

  return -1;
}

void scamper_icmp6_read_cb(const int fd, void *param)
{
  scamper_icmp_resp_t resp;

  resp.ir_ext = NULL;

  if(scamper_icmp6_recv(fd, &resp) == 0)
    {
      scamper_icmp_resp_handle(&resp);
    }

  if(resp.ir_ext != NULL)
    {
      free(resp.ir_ext);
    }

  return;
}

void scamper_icmp6_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

void scamper_icmp6_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_icmp6_open(const void *addr)
{
  struct sockaddr_in6 sin6;
  int fd = -1;
  int opt;

#if defined(ICMP6_FILTER)
  struct icmp6_filter filter;
#endif

#if defined(WITHOUT_PRIVSEP)
  if((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1)
#else
  if((fd = scamper_privsep_open_icmp(AF_INET6)) == -1)
#endif
    {
      printerror(errno, strerror, __func__, "could not open ICMP socket");
      goto err;
    }

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&opt, sizeof(opt)) == -1)
    {
      printerror(errno, strerror, __func__, "could not SO_RCVBUF");
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

#if defined(ICMP6_FILTER)
  /*
   * if the operating system has filtering capabilities for the ICMP6
   * raw socket, then install a filter that passes the three ICMP message
   * types that scamper cares about / processes.
   */
  ICMP6_FILTER_SETBLOCKALL(&filter);
  ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
  ICMP6_FILTER_SETPASS(ICMP6_PACKET_TOO_BIG, &filter);
  ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filter);
  ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
  if(setsockopt(fd,IPPROTO_ICMPV6,ICMP6_FILTER,&filter,sizeof(filter)) == -1)
    {
      printerror(errno, strerror, __func__, "could not IPV6_FILTER");
      goto err;
    }
#endif

#if defined(IPV6_DONTFRAG)
  opt = 1;
  if(setsockopt(fd,IPPROTO_IPV6,IPV6_DONTFRAG,(char *)&opt, sizeof(opt)) == -1)
    {
      printerror(errno, strerror, __func__, "could not set IPV6_DONTFRAG");
      goto err;
    }
#endif

  /*
   * ask the icmp6 socket to supply the TTL of any packet it receives
   * so that scamper might be able to infer the length of the reverse path
   */
#if defined(IPV6_RECVHOPLIMIT)
  opt = 1;
  if(setsockopt(fd, IPPROTO_IPV6,IPV6_RECVHOPLIMIT, &opt,sizeof(opt)) == -1)
    {
      printerror(errno, strerror, __func__, "could not set IPV6_RECVHOPLIMIT");
    }
#elif defined(IPV6_HOPLIMIT)
  opt = 1;
  if(setsockopt(fd,IPPROTO_IPV6,IPV6_HOPLIMIT,(char *)&opt,sizeof(opt)) == -1)
    {
      printerror(errno, strerror, __func__, "could not set IPV6_HOPLIMIT");
    }
#endif

  if(addr != NULL)
    {
      sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, addr, 0);
      if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) != 0)
	{
	  printerror(errno, strerror, __func__, "could not bind");
	  goto err;
	}
    }

  return fd;

 err:
  if(fd != -1) scamper_icmp6_close(fd);
  return -1;
}
