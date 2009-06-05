/*
 * scamper_writebuf.c: use in combination with select to send without blocking
 *
 * $Id: scamper_writebuf.c,v 1.21 2009/03/13 23:05:15 mjl Exp $
 *
 * Copyright (C) 2004-2008 The University of Waikato
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
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
struct iovec
{
  void   *iov_base;
  size_t  iov_len;
};
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_fds.h"
#include "scamper_writebuf.h"
#include "mjl_list.h"
#include "utils.h"

/*
 * scamper_writebuf
 *
 * this is a simple struct to maintain a list of iovec structures that are
 * to be sent when the underlying fd allows.
 *
 * the caller may register a scamper_fd struct with the writebuf that can be
 * managed by the writebuf code; that is, the iovecs are automatically sent
 * as the fd allows.  the caller must supply an error function with the fdn
 * so that if something goes wrong, the owner of the fdn can be told.
 *
 */
struct scamper_writebuf
{
  slist_t      *iovs;
  scamper_fd_t *fdn;
  int           error;
  void         *param;
  void        (*efunc)(void *, int, scamper_writebuf_t *);
  void        (*dfunc)(void *, scamper_writebuf_t *);
};

#ifndef _WIN32
static int writebuf_tx(scamper_writebuf_t *wb, int fd)
{
  struct msghdr msg;
  struct iovec *iov;
  uint8_t *bytes;
  ssize_t size;
  slist_node_t *node;
  int i, iovs;

  if((iovs = slist_count(wb->iovs)) == 0)
    {
      return 0;
    }

  /*
   * if there is only one iovec, or we can't allocate an array large enough
   * for the backlog, then just send the first without allocating the
   * array.  otherwise, fill the array with the iovecs to send.
   */
  if(iovs == 1 || (iov = malloc(iovs * sizeof(struct iovec))) == NULL)
    {
      iov = slist_head_get(wb->iovs);
      iovs = 1;
    }
  else
    {
      node = slist_head_node(wb->iovs);
      for(i=0; i<iovs; i++)
	{
	  assert(node != NULL);
	  memcpy(&iov[i], slist_node_item(node), sizeof(struct iovec));
	  node = slist_node_next(node);
	}
    }

  /* fill out the msghdr and set the send buf to be the iovecs */
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = iovs;
  size = sendmsg(fd, &msg, 0);

  /* if we allocated an array of iovecs, then free it now */
  if(iovs > 1)
    {
      free(iov);
    }

  if(size == -1)
    {
      if(errno == EAGAIN)
	{
	  return 0;
	}
      return -1;
    }

  /* free up the iovecs that have been sent */
  while(size > 0)
    {
      node = slist_head_node(wb->iovs);
      iov = slist_node_item(node);

      /* if the whole iovec was used then it can be free'd */
      if(iov->iov_len <= (size_t)size)
	{
	  size -= iov->iov_len;
	  free(iov->iov_base);
	  free(iov);
	  slist_head_pop(wb->iovs);
	  continue;
	}

      /* if this iovec was only partially sent, then shift the vec */
      bytes = iov->iov_base;
      memmove(iov->iov_base, bytes + size, iov->iov_len - size);
      iov->iov_len -= size;
      break;
    }

  return 0;
}
#endif

#ifdef _WIN32
static int writebuf_tx(scamper_writebuf_t *wb, int fd)
{
  struct iovec *iov;
  int size;

  if(slist_count(wb->iovs) == 0)
    return 0;

  iov = slist_head_get(wb->iovs);
  if((size = send(fd, iov->iov_base, iov->iov_len, 0)) == -1)
    return -1;

  if((size_t)size == iov->iov_len)
    {
      slist_head_pop(wb->iovs);
      free(iov->iov_base);
      free(iov);
    }
  else
    {
      iov->iov_len -= size;
      memmove(iov->iov_base, (uint8_t *)iov->iov_base + size, iov->iov_len);
    }

  return 0;
}
#endif

/*
 * writebuf_callback
 *
 * this function is called by the scamper_fd code whenever the fd is ready to
 * write to.
 */
static void writebuf_callback(int fd, void *param)
{
  scamper_writebuf_t *wb = (scamper_writebuf_t *)param;

  assert(wb->fdn != NULL);
  assert(scamper_fd_fd_get(wb->fdn) == fd);

  /*
   * if this callback was called, but there is no outstanding data to
   * send, then withdraw the entry from the fd monitoring module
   */
  if(slist_count(wb->iovs) == 0)
    {
      if(wb->fdn != NULL)
	scamper_fd_write_pause(wb->fdn);
      return;
    }

  if(writebuf_tx(wb, fd) != 0)
    {
      wb->error = errno;
      if(wb->efunc != NULL)
	wb->efunc(wb->param, errno, wb);
      return;
    }

  /* if all the iovecs are sent, withdraw the fd monitor */
  if(slist_count(wb->iovs) == 0)
    {
      scamper_fd_write_pause(wb->fdn);
      if(wb->dfunc != NULL)
	wb->dfunc(wb->param, wb);
      return;
    }

  return;
}

int scamper_writebuf_tx(scamper_writebuf_t *wb, int fd)
{
  assert(wb->fdn == NULL);
  assert(slist_count(wb->iovs) > 0);
  return writebuf_tx(wb, fd);
}

size_t scamper_writebuf_len(const scamper_writebuf_t *wb)
{
  slist_node_t *node = slist_head_node(wb->iovs);
  struct iovec *iov;
  size_t len = 0;

  while(node != NULL)
    {
      iov = slist_node_item(node);
      len += iov->iov_len;
      node = slist_node_next(node);
    }

  return len;
}

/*
 * scamper_writebuf_flush
 *
 * the caller wants anything buffered to be flushed now.  probably because
 * the caller wants to close the fd afterwards.
 */
int scamper_writebuf_flush(scamper_writebuf_t *wb)
{
  assert(wb->fdn != NULL);
  writebuf_callback(scamper_fd_fd_get(wb->fdn), wb);
  return 0;
}

void scamper_writebuf_detach(scamper_writebuf_t *wb)
{
  assert(wb->fdn != NULL);
  scamper_fd_write_pause(wb->fdn);
  wb->fdn   = NULL;
  wb->efunc = NULL;
  wb->param = NULL;
  return;
}

/*
 * scamper_writebuf_send
 *
 * register an iovec to send when it can be sent without blocking the
 * rest of scamper.
 */
int scamper_writebuf_send(scamper_writebuf_t *wb, const void *data, size_t len)
{
  struct iovec *iov;

  /* make sure there is data to send */
  if(len < 1)
    {
      return 0;
    }

  /*
   * an error occured last time sendmsg(2) was called which makes this
   * writebuf invalid
   */
  if(wb->error != 0)
    {
      return -1;
    }

  /* allocate the iovec and fill it out */
  if((iov = malloc(sizeof(struct iovec))) == NULL)
    {
      return -1;
    }
  if((iov->iov_base = malloc(len)) == NULL)
    {
      free(iov);
      return -1;
    }
  memcpy(iov->iov_base, data, len);
  iov->iov_len = len;

  /* put the iovec at the tail of iovecs to send */
  if(slist_tail_push(wb->iovs, iov) == NULL)
    {
      free(iov->iov_base);
      free(iov);
      return -1;
    }

  if(wb->fdn != NULL)
    {
      scamper_fd_write_unpause(wb->fdn);
    }

  return 0;
}

/*
 * scamper_writebuf_free
 *
 */
void scamper_writebuf_free(scamper_writebuf_t *wb)
{
  struct iovec *iov;

  if(wb == NULL)
    {
      return;
    }

  if(wb->fdn != NULL)
    {
      scamper_fd_write_pause(wb->fdn);
    }

  if(wb->iovs != NULL)
    {
      while((iov = slist_head_pop(wb->iovs)) != NULL)
	{
	  free(iov->iov_base);
	  free(iov);
	}
      slist_free(wb->iovs);
    }

  free(wb);
  return;
}

void scamper_writebuf_attach(scamper_writebuf_t *wb,
			     scamper_fd_t *fdn, void *param,
			     void (*efunc)(void *, int, scamper_writebuf_t *),
			     void (*dfunc)(void *, scamper_writebuf_t *))
{
  wb->fdn   = fdn;
  wb->param = param;
  wb->efunc = efunc;
  wb->dfunc = dfunc;
  scamper_fd_write_set(fdn, writebuf_callback, wb);
  return;
}

/*
 * scamper_writebuf_alloc
 *
 */
scamper_writebuf_t *scamper_writebuf_alloc(void)
{
  scamper_writebuf_t *wb = NULL;

  if((wb = malloc_zero(sizeof(scamper_writebuf_t))) == NULL)
    {
      goto err;
    }

  if((wb->iovs = slist_alloc()) == NULL)
    {
      goto err;
    }

  return wb;

 err:
  scamper_writebuf_free(wb);
  return NULL;
}
