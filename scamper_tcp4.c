/*
 * scamper_tcp4.c
 *
 * $Id: scamper_tcp4.c,v 1.45 2010/09/11 22:10:42 mjl Exp $
 *
 * Copyright (C) 2005-2010 The University of Waikato
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tcp4.c,v 1.45 2010/09/11 22:10:42 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip4.h"
#include "scamper_tcp4.h"
#include "scamper_debug.h"
#include "utils.h"

static void tcp_mss(uint8_t *buf, uint16_t mss)
{
  buf[0] = 2;
  buf[1] = 4;
  bytes_htons(buf+2, mss);
  return;
}

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

static void tcp4_build(scamper_probe_t *probe, uint8_t *buf)
{
  struct tcphdr *tcp = (struct tcphdr *)buf;
  size_t tcphlen = 20;

  tcp->th_sport = htons(probe->pr_tcp_sport);
  tcp->th_dport = htons(probe->pr_tcp_dport);
  tcp->th_seq   = htonl(probe->pr_tcp_seq);
  tcp->th_ack   = htonl(probe->pr_tcp_ack);
  tcp->th_flags = probe->pr_tcp_flags;
  tcp->th_win   = htons(probe->pr_tcp_win);
  tcp->th_sum   = 0;
  tcp->th_urp   = 0;

  if(probe->pr_tcp_flags & TH_SYN)
    {
      if(probe->pr_tcp_mss != 0)
	{
	  tcp_mss(buf+tcphlen, probe->pr_tcp_mss);
	  tcphlen += 4;
	}
    }

#ifndef _WIN32
  tcp->th_off   = tcphlen >> 2;
  tcp->th_x2    = 0;
#else
  tcp->th_offx2 = ((tcphlen >> 2) << 4);
#endif

  /* if there is data to include in the payload, copy it in now */
  if(probe->pr_len > 0)
    {
      memcpy(buf + tcphlen, probe->pr_data, probe->pr_len);
    }

  /* compute the checksum over the tcp portion of the probe */
  tcp_cksum(probe, tcp, tcphlen + probe->pr_len);

  return;
}

size_t scamper_tcp4_hlen(scamper_probe_t *probe)
{
  size_t len = 20;
  if(probe->pr_tcp_mss != 0)
    len += 4;
  return len;
}

int scamper_tcp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  size_t ip4hlen, req;
  int rc = 0;

  ip4hlen = *len;
  scamper_ip4_build(probe, buf, &ip4hlen);
  req = ip4hlen + scamper_tcp4_hlen(probe) + probe->pr_len;

  if(req <= *len)
    tcp4_build(probe, buf + ip4hlen);
  else
    rc = -1;

  *len = req;
  return rc;
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
