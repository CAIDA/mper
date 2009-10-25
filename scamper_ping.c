/*
 * scamper_ping.c
 *
 * $Id: scamper_ping.c,v 1.14 2009/02/19 22:10:26 mjl Exp $
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

#ifdef _WIN32
#include <winsock2.h>
#endif

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <stdlib.h>
#include <string.h>

#if defined(DMALLOC)
#include <string.h>
#include <dmalloc.h>
#endif

#include "scamper_addr.h"
#include "scamper_ping.h"

#include "utils.h"

int scamper_ping_setpattern(scamper_ping_t *ping, uint8_t *bytes, uint16_t len)
{
  uint8_t *dup;

  /* make a duplicate of the pattern bytes before freeing the old pattern */
  if(bytes != NULL && len > 0)
    {
      if((dup = memdup(bytes, len)) == NULL)
	{
	  return -1;
	}
    }
  else
    {
      dup = NULL;
      len = 0;
    }

  /* clear out anything there */
  if(ping->pattern_bytes != NULL)
    {
      free(ping->pattern_bytes);
    }

  /* copy in the new pattern */
  ping->pattern_bytes = dup;
  ping->pattern_len   = len;

  return 0;
}

scamper_addr_t *scamper_ping_addr(const void *va)
{
  return ((const scamper_ping_t *)va)->dst;
}

scamper_ping_t *scamper_ping_alloc()
{
  return (scamper_ping_t *)malloc_zero(sizeof(scamper_ping_t));
}

void scamper_ping_free(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply, *reply_next;

  if(ping == NULL) return;

  reply = ping->ping_reply;
  while(reply != NULL)
    {
      reply_next = reply->next;
      scamper_ping_reply_free(reply);
      reply = reply_next;
    }

  if(ping->dst != NULL) scamper_addr_free(ping->dst);
  if(ping->src != NULL) scamper_addr_free(ping->src);

  free(ping);
  return;
}

uint32_t scamper_ping_reply_count(const scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  uint32_t count = 0;

  reply = ping->ping_reply;
  while(reply != NULL)
    {
      count++;
      reply = reply->next;
    }

  return count;
}

int scamper_ping_reply_append(scamper_ping_t *p, scamper_ping_reply_t *reply)
{
  scamper_ping_reply_t *current;

  if(p == NULL || reply == NULL)
    {
      return -1;
    }

  if((current = p->ping_reply) == NULL)
    {
      p->ping_reply = reply;
    }
  else
    {
      while(current->next != NULL)
	{
	  current = current->next;
	}

      current->next = reply;
    }

  return 0;
}

scamper_ping_reply_t *scamper_ping_reply_alloc(void)
{
  return (scamper_ping_reply_t *)malloc_zero(sizeof(scamper_ping_reply_t));
}

void scamper_ping_reply_free(scamper_ping_reply_t *reply)
{
  if(reply == NULL) return;

  if(reply->addr != NULL)
    {
      scamper_addr_free(reply->addr);
    }

  free(reply);

  return;
}
