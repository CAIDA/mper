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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_ping.h"

#include "utils.h"

int scamper_ping_stats(const scamper_ping_t *ping,
		       uint32_t *nreplies, uint32_t *ndups, uint16_t *nloss,
		       struct timeval *min_rtt, struct timeval *max_rtt,
		       struct timeval *avg_rtt, struct timeval *stddev_rtt)
{
  struct timeval min_rtt_, max_rtt_;
  scamper_ping_reply_t *reply;
  uint16_t i;
  uint32_t nreplies_ = 0;
  uint32_t ndups_ = 0;
  uint16_t nloss_ = 0;

  for(i=0; i<ping->ping_sent; i++)
    {
      if((reply = ping->ping_replies[i]) == NULL)
	{
	  nloss_++;
	  continue;
	}

      nreplies_++;
      for(;;)
	{
	  if(nreplies_ != 0)
	    {
	      if(timeval_cmp(&reply->rtt, &min_rtt_) < 0)
		memcpy(&min_rtt_, &reply->rtt, sizeof(&min_rtt_));
	      else if(timeval_cmp(&reply->rtt, &max_rtt_) < 0)
		memcpy(&max_rtt_, &reply->rtt, sizeof(&max_rtt_));
	    }
	  else
	    {
	      memcpy(&min_rtt_, &reply->rtt, sizeof(min_rtt_));
	      memcpy(&max_rtt_, &reply->rtt, sizeof(max_rtt_));
	    }

	  if(reply->next != NULL)
	    {
	      reply = reply->next;
	      ndups_++;
	    }
	  else break;
	}
    }

  if(min_rtt != NULL) memcpy(min_rtt, &min_rtt_, sizeof(min_rtt_));
  if(max_rtt != NULL) memcpy(max_rtt, &max_rtt_, sizeof(max_rtt_));
  if(ndups != NULL) *ndups = ndups_;
  if(nreplies != NULL) *nreplies = nreplies_;
  if(nloss != NULL) *nloss = nloss_;

  return 0;
}

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
  int i;

  if(ping == NULL) return;

  if(ping->ping_replies != NULL)
    {
      for(i=0; i<ping->ping_sent; i++)
	{
	  reply = ping->ping_replies[i];
	  while(reply != NULL)
	    {
	      reply_next = reply->next;
	      scamper_ping_reply_free(reply);
	      reply = reply_next;
	    }
	}
      free(ping->ping_replies);
    }

  if(ping->dst != NULL) scamper_addr_free(ping->dst);
  if(ping->src != NULL) scamper_addr_free(ping->src);

  if(ping->cycle != NULL) scamper_cycle_free(ping->cycle);
  if(ping->list != NULL) scamper_list_free(ping->list);

  free(ping);
  return;
}

uint32_t scamper_ping_reply_count(const scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  uint16_t i;
  uint32_t count;

  for(i=0, count=0; i<ping->ping_sent; i++)
    {
      reply = ping->ping_replies[i];

      while(reply != NULL)
	{
	  count++;
	  reply = reply->next;
	}
    }

  return count;
}

int scamper_ping_reply_append(scamper_ping_t *p, scamper_ping_reply_t *reply)
{
  scamper_ping_reply_t *replies;

  if(p == NULL || reply == NULL || reply->probe_id >= p->ping_sent)
    {
      return -1;
    }

  if((replies = p->ping_replies[reply->probe_id]) == NULL)
    {
      p->ping_replies[reply->probe_id] = reply;
    }
  else
    {
      while(replies->next != NULL)
	{
	  replies = replies->next;
	}

      replies->next = reply;
    }

  return 0;
}

int scamper_ping_replies_alloc(scamper_ping_t *ping, int count)
{
  size_t size;

  size = sizeof(scamper_ping_reply_t *) * count;
  if((ping->ping_replies = (scamper_ping_reply_t **)malloc_zero(size)) != NULL)
    {
      return 0;
    }

  return -1;
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
