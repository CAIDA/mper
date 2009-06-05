/*
 * scamper_tcp6.c
 *
 * $Id: scamper_tcp6.c,v 1.14 2009/03/21 09:27:16 mjl Exp $
 *
 * Copyright (C) 2006-2009 The University of Waikato
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

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <sys/types.h>

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
struct ip6_hdr
{
  uint32_t        ip6_vfc_flow;
  uint16_t        ip6_plen;
  uint8_t         ip6_nxt;
  uint8_t         ip6_hlim;
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
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

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#endif

#if defined(__linux__)
#define __FAVOR_BSD
#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip6.h"
#include "scamper_tcp6.h"

#include "scamper_debug.h"
#include "utils.h"

static void tcp_cksum(struct ip6_hdr *ip6, struct tcphdr *tcp, size_t len)
{
  uint16_t *w;
  int sum = 0;

  /*
   * the TCP checksum includes a checksum calculated over a psuedo header
   * that includes the src and dst IP addresses, the protocol type, and
   * the TCP length.
   */
  w = (uint16_t *)&ip6->ip6_src;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  w = (uint16_t *)&ip6->ip6_dst;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += htons(len);
  sum += htons(IPPROTO_TCP);

  /* compute the checksum over the body of the TCP message */
  w = (uint16_t *)tcp;
  while(len > 1)
    {
      sum += *w++;
      len -= 2;
    }

  if(len != 0)
    {
      sum += ((uint8_t *)w)[0];
    }

  /* fold the checksum */
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  if((tcp->th_sum = ~sum) == 0)
    {
      tcp->th_sum = 0xffff;
    }

  return;
}

int scamper_tcp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  struct ip6_hdr *ip6;
  struct tcphdr  *tcp;
  size_t          ip6hlen, tcphlen, req;

  /* build the IPv6 header */
  ip6hlen = *len;
  scamper_ip6_build(probe, buf, &ip6hlen);

  /* for now, we don't handle any TCP options */
  tcphlen = 20;

  /* calculate the total number of bytes required for this packet */
  req = ip6hlen + tcphlen + probe->pr_len;

  if(req <= *len)
    {
      ip6 = (struct ip6_hdr *)buf;
      ip6->ip6_plen = htons(ip6hlen - 40 + 20 + probe->pr_len);

      /* build the tcp header */
      tcp = (struct tcphdr *)(buf + ip6hlen);
      tcp->th_sport = htons(probe->pr_tcp_sport);
      tcp->th_dport = htons(probe->pr_tcp_dport);
      tcp->th_seq   = htonl(probe->pr_tcp_seq);
      tcp->th_ack   = htonl(probe->pr_tcp_ack);

#ifndef _WIN32
      tcp->th_off   = tcphlen >> 2;
      tcp->th_x2    = 0;
#else
      tcp->th_offx2 = ((tcphlen >> 2) << 4);
#endif
      tcp->th_flags = probe->pr_tcp_flags;
      tcp->th_win   = htons(probe->pr_tcp_win);
      tcp->th_sum   = 0;
      tcp->th_urp   = 0;

      /* if there is data to include in the payload, copy it in now */
      if(probe->pr_len > 0)
	{
	  memcpy(buf + ip6hlen + tcphlen, probe->pr_data, probe->pr_len);
	}

      /* compute the checksum over the tcp portion of the probe */
      tcp_cksum(ip6, tcp, tcphlen + probe->pr_len);

      *len = req;
      return 0;
    }

  *len = req;
  return -1;
}

void scamper_tcp6_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_tcp6_open(const void *addr, int sport)
{
  struct sockaddr_in6 sin6;
  char tmp[128];
  int fd = -1;

  if((fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open socket");
      goto err;
    }

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1)
    {
      if(addr == NULL || addr_tostr(AF_INET6, addr, tmp, sizeof(tmp)) == NULL)
	printerror(errno,strerror,__func__, "could not bind port %d", sport);
      else
	printerror(errno,strerror,__func__, "could not bind %s:%d", tmp, sport);
      goto err;
    }

  return fd;

 err:
  if(fd != -1) scamper_tcp6_close(fd);
  return -1;
}
