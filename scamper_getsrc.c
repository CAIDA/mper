/*
 * scamper_getsrc.c
 *
 * $Id: scamper_getsrc.c,v 1.13 2009/03/21 09:27:16 mjl Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_debug.h"
#include "scamper_getsrc.h"
#include "utils.h"

static int udp4 = -1;
static int udp6 = -1;

extern scamper_addrcache_t *addrcache;

/*
 * scamper_getsrc
 *
 * given a destination address, determine the src address used in the IP
 * header to transmit probes to it.
 */
scamper_addr_t *scamper_getsrc(const scamper_addr_t *dst)
{
  struct sockaddr_storage sas;
  scamper_addr_t *src;
  socklen_t socklen, sockleno;
  int sock;
  int af;
  void *addr;
  char buf[64];

  if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(udp4 == -1 && (udp4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	{
	  printerror(errno, strerror, __func__, "could not open udp4 sock");
	  return NULL;
	}

      af = AF_INET;
      sock = udp4;
      addr = &((struct sockaddr_in *)&sas)->sin_addr;
      socklen = sizeof(struct sockaddr_in);
    }
  else if(dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(udp6 == -1 && (udp6 = socket(AF_INET6, SOCK_DGRAM,IPPROTO_UDP)) == -1)
	{
	  printerror(errno, strerror, __func__, "could not open udp6 sock");
	  return NULL;
	}

      af = AF_INET6;
      sock = udp6;
      addr = &((struct sockaddr_in6 *)&sas)->sin6_addr;
      socklen = sizeof(struct sockaddr_in6);
    }
  else return NULL;

  sockaddr_compose((struct sockaddr *)&sas, af, dst->addr, 80);

  if(connect(sock, (struct sockaddr *)&sas, socklen) != 0)
    {
      printerror(errno, strerror, __func__, "connect to dst failed for %s",
		 scamper_addr_tostr(dst, buf, sizeof(buf)));
      return NULL;
    }

  sockleno = socklen;
  if(getsockname(sock, (struct sockaddr *)&sas, &sockleno) != 0)
    {
      printerror(errno, strerror, __func__, "could not getsockname for %s",
		 scamper_addr_tostr(dst, buf, sizeof(buf)));
      return NULL;
    }

  src = scamper_addrcache_get(addrcache, dst->type, addr);

  memset(&sas, 0, sizeof(sas));
  connect(sock, (struct sockaddr *)&sas, socklen);
  return src;
}

int scamper_getsrc_init()
{
  return 0;
}

void scamper_getsrc_cleanup()
{
  if(udp4 != -1)
    {
#ifndef _WIN32
      close(udp4);
#else
      closesocket(udp4);
#endif
      udp4 = -1;
    }

  if(udp6 != -1)
    {
#ifndef _WIN32
      close(udp6);
#else
      closesocket(udp6);
#endif
      udp6 = -1;
    }

  return;
}
