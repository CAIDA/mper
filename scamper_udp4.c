/*
 * scamper_udp4.c
 *
 * $Id: scamper_udp4.c,v 1.58 2009/03/21 20:06:33 mjl Exp $
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
struct udphdr
{
  uint16_t uh_sport;
  uint16_t uh_dport;
  uint16_t uh_ulen;
  uint16_t uh_sum;
};
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(__sun__)
#define IP_HDR_HTONS
#endif

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
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
#include <netinet/udp.h>
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
#include "scamper_udp4.h"
#include "scamper_privsep.h"
#include "scamper_debug.h"
#include "utils.h"

#ifndef IP_DF
#define IP_DF 0x4000
#endif

/*
 * these variables are used to store a packet buffer that is allocated
 * in the scamper_udp4_probe function large enough for the largest probe
 * the routine sends
 */
static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;

uint16_t scamper_udp4_cksum(scamper_probe_t *probe)
{
  uint16_t tmp, *w;
  int i, sum = 0;

  /* compute the checksum over the psuedo header */
  w = (uint16_t *)probe->pr_ip_src->addr;
  sum += *w++; sum += *w++;
  w = (uint16_t *)probe->pr_ip_dst->addr;
  sum += *w++; sum += *w++;
  sum += htons(IPPROTO_UDP);
  sum += htons(probe->pr_len + 8);

  /* main UDP header */
  sum += htons(probe->pr_udp_sport);
  sum += htons(probe->pr_udp_dport);
  sum += htons(probe->pr_len + 8);

  /* compute the checksum over the payload of the UDP message */
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
  ip->ip_p   = IPPROTO_UDP;
  ip->ip_sum = 0;
  memcpy(&ip->ip_src, probe->pr_ip_src->addr, sizeof(ip->ip_src));
  memcpy(&ip->ip_dst, probe->pr_ip_dst->addr, sizeof(ip->ip_dst));
  ip->ip_sum = in_cksum(ip, sizeof(struct ip));

  return;
}

static void udp4_build(scamper_probe_t *probe, uint8_t *buf)
{
  struct udphdr *udp = (struct udphdr *)buf;

  udp->uh_sport = htons(probe->pr_udp_sport);
  udp->uh_dport = htons(probe->pr_udp_dport);
  udp->uh_ulen  = htons(8 + probe->pr_len);
  udp->uh_sum = scamper_udp4_cksum(probe);

  /* if there is data to include in the payload, copy it in now */
  if(probe->pr_len > 0)
    {
      memcpy(buf + 8, probe->pr_data, probe->pr_len);
    }

  return;
}

int scamper_udp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  size_t req = 20 + 8 + probe->pr_len;

  if(req <= *len)
    {
      ip4_build(probe, buf);
      udp4_build(probe, buf + 20);

      *len = req;
      return 0;
    }

  *len = req;
  return -1;
}

int scamper_udp4_probe(scamper_probe_t *probe)
{
  struct sockaddr_in  sin4;
  int                 i;
  char                addr[128];
  size_t              len;
  uint8_t            *buf;

#if !defined(IP_HDR_HTONS)
  struct ip          *ip;
#endif

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_UDP);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len > 0 || probe->pr_data == NULL);

  /* compute length, for sake of readability */
  len = sizeof(struct ip) + sizeof(struct udphdr) + probe->pr_len;

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

  ip4_build(probe, pktbuf);

#if !defined(IP_HDR_HTONS)
  ip = (struct ip *)pktbuf;
  ip->ip_len = ntohs(ip->ip_len);
  ip->ip_off = ntohs(ip->ip_off);
#endif

  udp4_build(probe, pktbuf + 20);

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET,
		   probe->pr_ip_dst->addr, probe->pr_udp_dport);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  i = sendto(probe->pr_fd, pktbuf, len, 0, (struct sockaddr *)&sin4,
	     sizeof(struct sockaddr_in));

  if(i < 0)
    {
      /* error condition, could not send the packet at all */
      probe->pr_errno = errno;
      printerror(probe->pr_errno, strerror, __func__,
		 "could not send to %s (%d ttl, %d dport, %d len)",
		 scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)),
		 probe->pr_ip_ttl, probe->pr_udp_dport, len);
      return -1;
    }
  else if((size_t)i != len)
    {
      /* error condition, sent a portion of the probe */
      fprintf(stderr,
	      "scamper_udp4_probe: sent %d bytes of %d byte packet to %s",
	      i, (int)len,
	      scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
      return -1;
    }

  return 0;
}

void scamper_udp4_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

void scamper_udp4_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_udp4_open(const void *addr, int sport)
{
  int fd = -1;

#ifndef _WIN32
  int   hdr;
#else
  DWORD hdr;
#endif

#if defined(WITHOUT_PRIVSEP)
  struct sockaddr_in sin4;
  char tmp[32];

  if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
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
#else
  if((fd = scamper_privsep_open_rawudp(addr, sport)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open socket");
      goto err;
    }
#endif

#ifndef _WIN32
  hdr = 1;
  if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hdr, sizeof(hdr)) == -1)
#else
  hdr = TRUE;
  if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (char *)&hdr, sizeof(hdr)) == -1)
#endif
    {
      printerror(errno, strerror, __func__, "could not IP_HDRINCL");
      goto err;
    }

  return fd;

 err:
  if(fd != -1) scamper_udp4_close(fd);
  return -1;
}
