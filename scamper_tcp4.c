/*
 * scamper_tcp4.c
 *
 * $Id: scamper_tcp4.c,v 1.35 2009/03/21 09:27:16 mjl Exp $
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

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(__sun__)
#define IP_HDR_HTONS
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
#include <sys/socket.h>
#include <sys/time.h>
#endif

#if defined(__linux__)
#define __FAVOR_BSD
#define IP_HDR_HTONS
#endif

#if defined(__OpenBSD__) && OpenBSD >= 199706
#define IP_HDR_HTONS
#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <assert.h>

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_tcp4.h"
#include "scamper_debug.h"
#include "utils.h"

#ifndef IP_DF
#define IP_DF 0x4000
#endif

static void tcp_cksum(scamper_probe_t *probe, struct tcphdr *tcp, size_t len)
{
  uint16_t *w;
  int sum = 0;

  /*
   * the TCP checksum includes a checksum calculated over a psuedo header
   * that includes the src and dst IP addresses, the protocol type, and
   * the TCP length.
   */
  w = probe->pr_ip_src->addr;
  sum += *w++; sum += *w++;
  w = probe->pr_ip_dst->addr;
  sum += *w++; sum += *w++;
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
  ip->ip_len = htons(20 + 20 + probe->pr_len);
  ip->ip_id  = htons(probe->pr_ip_id);
  ip->ip_off = htons(IP_DF);
  ip->ip_ttl = probe->pr_ip_ttl;
  ip->ip_p   = IPPROTO_TCP;
  ip->ip_sum = 0;
  memcpy(&ip->ip_src, probe->pr_ip_src->addr, sizeof(ip->ip_src));
  memcpy(&ip->ip_dst, probe->pr_ip_dst->addr, sizeof(ip->ip_dst));
  ip->ip_sum = in_cksum(ip, sizeof(struct ip));

  return;
}

static void tcp4_build(scamper_probe_t *probe, uint8_t *buf)
{
  struct tcphdr *tcp = (struct tcphdr *)buf;
  size_t tcphlen = 20;

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
      memcpy(buf + tcphlen, probe->pr_data, probe->pr_len);
    }

  /* compute the checksum over the tcp portion of the probe */
  tcp_cksum(probe, tcp, tcphlen + probe->pr_len);

  return;
}

int scamper_tcp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  /* for now, we don't handle any TCP options */
  size_t req = 20 + 20 + probe->pr_len;

  if(req <= *len)
    {
      ip4_build(probe, buf);
      tcp4_build(probe, buf+20);

      *len = req;
      return 0;
    }

  *len = req;
  return -1;
}

void scamper_tcp4_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_tcp4_open(const void *addr, int sport)
{
  struct sockaddr_in sin4;
  char tmp[32];
  int fd = -1;

  if((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open socket");
      goto err;
    }

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      if(addr == NULL || addr_tostr(AF_INET, addr, tmp, sizeof(tmp)) == NULL)
	printerror(errno,strerror,__func__, "could not bind port %d", sport);
      else
	printerror(errno,strerror,__func__, "could not bind %s:%d", tmp, sport);
      goto err;
    }

  return fd;

 err:
  if(fd != -1) scamper_tcp4_close(fd);
  return -1;
}
