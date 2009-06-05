/*
 * scamper_linepoll
 *
 * $Id: scamper_linepoll.c,v 1.13 2009/02/28 06:41:54 mjl Exp $
 *
 * this code takes a string chunk and splits it up into lines, calling
 * the callback for each line.  It buffers any partial lines in the
 * process.
 *
 * Copyright (C) 2004-2009 The University of Waikato
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

#ifndef _WIN32
#include <netinet/in.h>
#endif

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
#endif

#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_linepoll.h"

struct scamper_linepoll
{
  scamper_linepoll_handler_t handler;
  void    *param;
  uint8_t *buf;
  size_t   len;
};

/*
 * scamper_linepoll_flush
 *
 *
 */
int scamper_linepoll_flush(scamper_linepoll_t *lp)
{
  void *tmp;

  if(lp->len > 0)
    {
      if((tmp = realloc(lp->buf, lp->len+1)) != NULL)
	{
	  lp->buf = tmp;
	  lp->buf[lp->len] = '\0';
	  lp->handler(lp->param, lp->buf, lp->len);

	  free(lp->buf);
	  lp->buf = NULL;
	  lp->len = 0;
	}
      else return -1;
    }

  return 0;
}

/*
 * scamper_linepoll_handle
 *
 * take the input buf and call lp->handler for each complete line it reads.
 * if the last read had an incomplete line, then merge the line together.
 */
int scamper_linepoll_handle(scamper_linepoll_t *lp, uint8_t *buf, size_t len)
{
  uint8_t *bbuf;
  size_t i = 0, s = 0, blen;

  assert(lp != NULL);
  assert(buf != NULL);

  /* make sure there is something in the buf */
  if(len < 1)
    {
      return 0;
    }

  /*
   * there is a partial line from the previous read, deal with it now.
   * it is dealt with by scanning for the actual end of the line in this
   * buffer, and then putting the two pieces together.
   */
  if(lp->len > 0)
    {
      /* scan for the end-of-line */
      while(i < len)
	{
	  /* until a \n is found, keep looking */
	  if(buf[i] != '\n')
	    {
	      i++;
	      continue;
	    }

	  /* allocate a buffer big enough to take both segments of the line */
	  if((bbuf = malloc(lp->len + i + 1)) == NULL)
	    {
	      return -1;
	    }
	  buf[i] = '\0';
	  memcpy(bbuf, lp->buf, lp->len);
	  memcpy(bbuf+lp->len, buf, i+1);
	  blen = lp->len+i;

	  /* we don't need the old buf anymore */
	  free(lp->buf); lp->buf = NULL; lp->len = 0;

	  /* drop the \r of a \r\n if necessary */
	  if(bbuf[blen-1] == '\r')
	    {
	      /*
	       * make sure that if the \r is dropped, we're not left with an
	       * empty line
	       */
	      if(blen-1 > 0)
		{
		  bbuf[--blen] = '\0';
		  lp->handler(lp->param, bbuf, blen);
		}
	    }
	  else
	    {
	      /* blen should be > 0, as lp->len > 0 above */
	      assert(blen > 0);
	      lp->handler(lp->param, bbuf, blen);
	    }

	  free(bbuf);
	  break;
	}

      /*
       * if a newline was not found then merge the two buffers together
       * and hold them for next time.
       */
      if(i == len)
	{
	  /* allocate a bigger buffer */
	  if((bbuf = realloc(lp->buf, lp->len + len)) == NULL)
	    {
	      return -1;
	    }
	  lp->buf = bbuf;

	  /*
	   * copy in additional data and then increase the record held of
	   * the total length of the line so far
	   */
	  memcpy(lp->buf+lp->len, buf, len);
	  lp->len += len;

	  return 0;
	}

      s = ++i;
    }

  while(i < len)
    {
      /* skip until a new-line character is found */
      if(buf[i] != '\n')
	{
	  i++;
	  continue;
	}

      /*
       * if this is a blank line we don't need to pass it
       * note that if the end-of-line sequence is \r\n, then the \r is
       * stripped in addition to the \n
       */
      if(s != i)
	{
	  buf[i] = '\0';
	  if(buf[i-1] != '\r')
	    {
	      lp->handler(lp->param, buf+s, i-s);
	    }
	  else if(i - 1 != 0)
	    {
	      buf[i-1] = '\0';
	      lp->handler(lp->param, buf+s, i-s-1);
	    }
	}

      /* update the starting point for the next line */
      s = ++i;
    }

  if(s < len)
    {
      if((lp->buf = malloc(len - s)) == NULL)
	{
	  return -1;
	}

      lp->len = len - s;
      memcpy(lp->buf, buf+s, lp->len);
    }

  return 0;
}

scamper_linepoll_t *scamper_linepoll_alloc(scamper_linepoll_handler_t handler,
					   void *param)
{
  scamper_linepoll_t *lp;

  if((lp = malloc(sizeof(scamper_linepoll_t))) == NULL)
    {
      return NULL;
    }

  lp->handler = handler;
  lp->param = param;
  lp->buf = NULL;
  lp->len = 0;

  return lp;
}

void scamper_linepoll_free(scamper_linepoll_t *lp, int feedlastline)
{
  assert(lp != NULL);

  if(feedlastline == 1)
    {
      scamper_linepoll_flush(lp);
    }

  if(lp->buf != NULL) free(lp->buf);
  free(lp);

  return;
}
