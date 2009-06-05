/*
 * scamper_fds: manage events and file descriptors
 *
 * $Id: scamper_fds.c,v 1.51 2009/04/06 00:55:10 mjl Exp $
 *
 *          Matthew Luckie
 * 
 *          Supported by:
 *           The University of Waikato
 *           NLANR Measurement and Network Analysis
 *           CAIDA
 *           The WIDE Project
 *
 * Copyright (C) 2004-2009 The University of Waikato
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

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>  
#define snprintf _snprintf
#endif

#ifndef _WIN32
#include <sys/param.h>
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_fds.h"
#include "scamper_debug.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_tcp4.h"
#include "scamper_tcp6.h"
#include "scamper_dl.h"
#ifndef _WIN32
#include "scamper_rtsock.h"
#endif
#include "utils.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"

/*
 * scamper_fd_poll
 *
 * node to hold callback details for the fd.
 */
typedef struct scamper_fd_poll
{
  scamper_fd_t    *fdn;    /* back pointer to the fd struct */
  scamper_fd_cb_t  cb;     /* callback to use when event arises */
  void            *param;  /* user-defined parameter to pass to callback */
  dlist_t         *list;   /* which list the node is in */
  dlist_node_t    *node;   /* node in the poll list */
  uint8_t          flags;  /* flags associated with structure */
} scamper_fd_poll_t;

/*
 * scamper_fd
 *
 * a file descriptor, details of its type and other identifying information,
 * and what to do when read/write events are found with select.
 */
struct scamper_fd
{
  int               fd;     /* the file descriptor being polled */
  int               type;   /* the type of the file descriptor */
  int               refcnt; /* number of references to this structure */
  scamper_fd_poll_t read;   /* if monitored for read events */
  scamper_fd_poll_t write;  /* if monitored for write events */
  splaytree_node_t *node;   /* node for this fd in the splaytree */
  struct timeval    tv;     /* when this node should be expired */

  union
  {
    struct fd_poll_tcp
    {
      void     *addr;
      uint16_t  sport;
    } fd_poll_tcp;

    struct fd_poll_udp
    {
      void     *addr;
      uint16_t  sport;
    } fd_poll_udp;

    struct fd_poll_icmp
    {
      void     *addr;
    } fd_poll_icmp;

    struct fd_poll_dl
    {
      int       ifindex;
    } fd_poll_dl;

  } fd_un;
};

#define SCAMPER_FD_TYPE_PRIVATE  0x00
#define SCAMPER_FD_TYPE_ICMP4    0x01
#define SCAMPER_FD_TYPE_ICMP6    0x02
#define SCAMPER_FD_TYPE_UDP4     0x03
#define SCAMPER_FD_TYPE_UDP6     0x04
#define SCAMPER_FD_TYPE_TCP4     0x05
#define SCAMPER_FD_TYPE_TCP6     0x06
#define SCAMPER_FD_TYPE_DL       0x07

#ifndef _WIN32
#define SCAMPER_FD_TYPE_RTSOCK   0x08
#define SCAMPER_FD_TYPE_IFSOCK   0x09
#endif

#define SCAMPER_FD_POLL_FLAG_INACTIVE 0x01 /* the fd should not be polled */

#define fd_tcp_sport  fd_un.fd_poll_tcp.sport
#define fd_tcp_addr   fd_un.fd_poll_tcp.addr
#define fd_udp_sport  fd_un.fd_poll_udp.sport
#define fd_udp_addr   fd_un.fd_poll_udp.addr
#define fd_icmp_addr  fd_un.fd_poll_icmp.addr
#define fd_dl_ifindex fd_un.fd_poll_dl.ifindex

static splaytree_t *fd_tree     = NULL;
static dlist_t     *read_fds    = NULL;
static dlist_t     *write_fds   = NULL;
static dlist_t     *read_queue  = NULL;
static dlist_t     *write_queue = NULL;
static dlist_t     *refcnt_0    = NULL;

#ifndef NDEBUG

static char *fd_addr_tostr(char *buf, size_t len, int af, void *addr)
{
  char tmp[128];

  if(addr == NULL || addr_tostr(af, addr, tmp, sizeof(tmp)) == NULL)
    return "";

  snprintf(buf, len, " %s", tmp);
  return buf;
}

static char *fd_tostr(scamper_fd_t *fdn)
{
  static char buf[144];
  char addr[128];

  switch(fdn->type)
    {
    case SCAMPER_FD_TYPE_PRIVATE:
      return "private";

    case SCAMPER_FD_TYPE_ICMP4:
      snprintf(buf, sizeof(buf), "icmp4%s",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET, fdn->fd_icmp_addr));
      return buf;

    case SCAMPER_FD_TYPE_ICMP6:
      snprintf(buf, sizeof(buf), "icmp6%s",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET6, fdn->fd_icmp_addr));
      return buf;

    case SCAMPER_FD_TYPE_UDP4:
      snprintf(buf, sizeof(buf), "udp4%s %d",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET, fdn->fd_icmp_addr),
	       fdn->fd_udp_sport);
      return buf;

    case SCAMPER_FD_TYPE_UDP6:
      snprintf(buf, sizeof(buf), "udp6%s %d",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET6, fdn->fd_icmp_addr),
	       fdn->fd_udp_sport);
      return buf;

    case SCAMPER_FD_TYPE_TCP4:
      snprintf(buf, sizeof(buf), "tcp4%s %d",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET, fdn->fd_icmp_addr),
	       fdn->fd_tcp_sport);
      return buf;

    case SCAMPER_FD_TYPE_TCP6:
      snprintf(buf, sizeof(buf), "tcp6%s %d",
	       fd_addr_tostr(addr, sizeof(addr), AF_INET6, fdn->fd_icmp_addr),
	       fdn->fd_tcp_sport);
      return buf;

    case SCAMPER_FD_TYPE_DL:
      snprintf(buf, sizeof(buf), "dl %d", fdn->fd_dl_ifindex);
      return buf;

#ifdef SCAMPER_FD_TYPE_RTSOCK
    case SCAMPER_FD_TYPE_RTSOCK:
      return "rtsock";
#endif

#ifdef SCAMPER_FD_TYPE_IFSOCK
    case SCAMPER_FD_TYPE_IFSOCK:
      return "ifsock";
#endif
    }

  return "?";
}
#endif

static void fd_close(scamper_fd_t *fdn)
{
  switch(fdn->type)
    {
    case SCAMPER_FD_TYPE_PRIVATE:
      break;

    case SCAMPER_FD_TYPE_ICMP4:
      scamper_icmp4_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_ICMP6:
      scamper_icmp6_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_UDP4:
      scamper_udp4_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_UDP6:
      scamper_udp6_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_TCP4:
      scamper_tcp4_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_TCP6:
      scamper_tcp6_close(fdn->fd);
      break;

    case SCAMPER_FD_TYPE_DL:
      scamper_dl_close(fdn->fd);
      break;

#ifdef SCAMPER_FD_TYPE_RTSOCK
    case SCAMPER_FD_TYPE_RTSOCK:
      scamper_rtsock_close(fdn->fd);
      break;
#endif

#ifdef SCAMPER_FD_TYPE_IFSOCK
    case SCAMPER_FD_TYPE_IFSOCK:
      close(fdn->fd);
      break;
#endif
    }

  return;
}

/*
 * fd_free
 *
 * free up memory allocated to scamper's monitoring of the file descriptor.
 */
static void fd_free(scamper_fd_t *fdn)
{
  scamper_debug(__func__, "fd %d type %s", fdn->fd, fd_tostr(fdn));

  if(fdn->read.node != NULL)
    {
      dlist_node_pop(fdn->read.list, fdn->read.node);
    }

  if(fdn->write.node != NULL)
    {
      dlist_node_pop(fdn->write.list, fdn->write.node);
    }

  if(fdn->node != NULL)
    {
      splaytree_remove_node(fd_tree, fdn->node);
    }

  if(fdn->type == SCAMPER_FD_TYPE_DL)
    {
      scamper_dl_state_free(fdn->read.param);
    }
  if(fdn->type == SCAMPER_FD_TYPE_ICMP4 || fdn->type == SCAMPER_FD_TYPE_ICMP6)
    {
      if(fdn->fd_icmp_addr != NULL)
	free(fdn->fd_icmp_addr);
    }

  free(fdn);

  return;
}

/*
 * fd_refcnt_0
 *
 * this function is called whenever a fdn with a refcnt field of zero is
 * found.
 */
static void fd_refcnt_0(scamper_fd_t *fdn)
{
  /*
   * if the fd is in a list that is currently locked, then it can't be
   * removed just yet
   */
  if((fdn->read.list  != NULL && dlist_islocked(fdn->read.list)  != 0) ||
     (fdn->write.list != NULL && dlist_islocked(fdn->write.list) != 0))
    {
      return;
    }

  /*
   * if this is a private fd and the reference count has reached zero,
   * then the scamper_fd structure can be freed up completely now
   */
  if(fdn->type == SCAMPER_FD_TYPE_PRIVATE)
    {
      fd_free(fdn);
      return;
    }

  /*
   * this fd is a shared fd.  detach it from any poll lists it is in.
   */
  if(fdn->read.list != NULL)
    {
      scamper_fd_read_pause(fdn);
      dlist_node_eject(fdn->read.list, fdn->read.node);
      fdn->read.list = NULL;
    }
  if(fdn->write.list != NULL)
    {
      scamper_fd_write_pause(fdn);
      dlist_node_eject(fdn->write.list, fdn->write.node);
      fdn->write.list = NULL;
    }

  /*
   * set this fd to be closed in one minute unless something else comes
   * along and wants to use it.  use the structure's read-node for this.
   */
  gettimeofday_wrap(&fdn->tv);
  fdn->tv.tv_sec += 60;
  dlist_node_tail_push(refcnt_0, fdn->read.node);
  fdn->read.list = refcnt_0;

  return;
}

/*
 * fd_refcnt_0_reap
 *
 * loop through the list of fds with a refcnt of zero, and reap them if their
 * time has expired.
 */
static void fd_refcnt_0_reap(void)
{
  scamper_fd_poll_t *fdp;
  struct timeval tv;

  /* nothing to do */
  if(dlist_count(refcnt_0) == 0)
    {
      return;
    }

  gettimeofday_wrap(&tv);

  while((fdp = (scamper_fd_poll_t *)dlist_head_get(refcnt_0)) != NULL)
    {
      if(timeval_cmp(&fdp->fdn->tv, &tv) > 0)
	{
	  break;
	}

      fd_close(fdp->fdn);
      fd_free(fdp->fdn);
    }

  return; 
}

/*
 * fd_set_assemble
 *
 * given a list of scamper_fd_poll_t structures held in a list, compose an
 * fd_set for them to pass to select.
 */
static fd_set *fd_set_assemble(dlist_t *fds, fd_set *fdset, int *nfds)
{
  scamper_fd_poll_t *fdp;
  dlist_node_t      *node;
  int                count = 0;

  FD_ZERO(fdset);

  node = dlist_head_node(fds);
  while(node != NULL)
    {
      /* file descriptor associated with the node */
      fdp = (scamper_fd_poll_t *)dlist_node_item(node);

      /* get the next node incase this node is subsequently removed */
      node = dlist_node_next(node);

      /* if there is nothing using this fdn any longer, then stop polling it */
      if(fdp->fdn->refcnt == 0)
	{
	  fd_refcnt_0(fdp->fdn);
	  continue;
	}

      /* if the inactive flag is set, then skip over this file descriptor */
      if((fdp->flags & SCAMPER_FD_POLL_FLAG_INACTIVE) != 0)
	{
	  dlist_node_eject(fds, fdp->node);
	  fdp->list = NULL;
	  continue;
	}

      /* monitor this file descriptor */
      FD_SET(fdp->fdn->fd, fdset);
      count++;

      /* update the maxfd seen if appropriate */
      if(*nfds < fdp->fdn->fd)
	{
	  *nfds = fdp->fdn->fd;
	}
    }

  /*
   * if there are no fds in the set to monitor, then return a null pointer
   * to pass to select
   */
  if(count == 0)
    {
      return NULL;
    }

  return fdset;
}

/*
 * fd_set_check
 *
 * given an fd_set that has been passed to select, as well as a list of
 * fds that are being monitored, figure out which ones have an event and
 * use the callback provided to deal with the event.
 */
static void fd_set_check(fd_set *fdset, dlist_t *fds, int *count)
{
  scamper_fd_poll_t *fdp;
  dlist_node_t *node;

  /* stop now if there is nothing to check */
  if(fdset == NULL || *count == 0)
    {
      return;
    }

  /* nodes in this list should not be removed while this function is called */
  dlist_lock(fds);

  /* loop through */
  node = dlist_head_node(fds);
  while(node != NULL && *count > 0)
    {
      fdp = (scamper_fd_poll_t *)dlist_node_item(node);
      node = dlist_node_next(node);      

      if(FD_ISSET(fdp->fdn->fd, fdset))
	{
	  fdp->cb(fdp->fdn->fd, fdp->param);
	  (*count)--;
	}
    }

  /* can modify the list now */
  dlist_unlock(fds);

  return;
}

static int fd_addr_cmp(int type, void *a, void *b)
{
  assert(type == SCAMPER_FD_TYPE_TCP4  || type == SCAMPER_FD_TYPE_TCP6 ||
	 type == SCAMPER_FD_TYPE_UDP4  || type == SCAMPER_FD_TYPE_UDP6 ||
	 type == SCAMPER_FD_TYPE_ICMP4 || type == SCAMPER_FD_TYPE_ICMP6);

  if(a == NULL && b != NULL) return -1;
  if(a != NULL && b == NULL) return  1;
  if(a == NULL && b == NULL) return  0;

  if(type == SCAMPER_FD_TYPE_TCP4 || type == SCAMPER_FD_TYPE_UDP4 ||
     type == SCAMPER_FD_TYPE_ICMP4)
    return addr4_cmp(a, b);
  else
    return addr6_cmp(a, b);
}

/*
 * fd_cmp
 *
 * given two scamper_fd_t structures, determine if their properties are
 * the same.  used to maintain the splaytree of existing file descriptors
 * held by scamper.
 */
static int fd_cmp(const void *va, const void *vb)
{
  const scamper_fd_t *a = (const scamper_fd_t *)va;
  const scamper_fd_t *b = (const scamper_fd_t *)vb;

  if(a->type < b->type) return -1;
  if(a->type > b->type) return  1;

  switch(a->type)
    {
    case SCAMPER_FD_TYPE_TCP4:
    case SCAMPER_FD_TYPE_TCP6:
      if(a->fd_tcp_sport < b->fd_tcp_sport) return -1;
      if(a->fd_tcp_sport > b->fd_tcp_sport) return  1;
      return fd_addr_cmp(a->type, a->fd_tcp_addr, b->fd_tcp_addr);

    case SCAMPER_FD_TYPE_UDP4:
    case SCAMPER_FD_TYPE_UDP6:
      if(a->fd_udp_sport < b->fd_udp_sport) return -1;
      if(a->fd_udp_sport > b->fd_udp_sport) return  1;
      return fd_addr_cmp(a->type, a->fd_udp_addr, b->fd_udp_addr);

    case SCAMPER_FD_TYPE_DL:
      if(a->fd_dl_ifindex < b->fd_dl_ifindex) return -1;
      if(a->fd_dl_ifindex > b->fd_dl_ifindex) return  1;
      return 0;

    case SCAMPER_FD_TYPE_ICMP4:
    case SCAMPER_FD_TYPE_ICMP6:
      return fd_addr_cmp(a->type, a->fd_icmp_addr, b->fd_icmp_addr);
    }

  return 0;
}

/*
 * fd_alloc
 *
 * allocate a scamper_fd_t structure and do generic setup tasks.
 */
static scamper_fd_t *fd_alloc(int type, int fd)
{
  scamper_fd_t *fdn = NULL;

  if((fdn = malloc_zero(sizeof(scamper_fd_t))) == NULL)
    {
      goto err;
    }
  fdn->type   = type;
  fdn->fd     = fd;
  fdn->refcnt = 1;

  /* set up to poll read ability */
  if((fdn->read.node = dlist_node_alloc(&fdn->read)) == NULL)
    {
      goto err;
    }
  fdn->read.fdn   = fdn;
  fdn->read.flags = SCAMPER_FD_POLL_FLAG_INACTIVE;

  /* set up to poll write ability */
  if((fdn->write.node = dlist_node_alloc(&fdn->write)) == NULL)
    {
      goto err;
    }
  fdn->write.fdn   = fdn;
  fdn->write.flags = SCAMPER_FD_POLL_FLAG_INACTIVE;

  return fdn;

 err:
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

/*
 * fd_find
 *
 * search the tree of file descriptors known to scamper for a matching
 * entry.  if one is found, increment its reference count and return it.
 */
static scamper_fd_t *fd_find(scamper_fd_t *findme)
{
  scamper_fd_t *fdn;

  if((fdn = splaytree_find(fd_tree, findme)) != NULL)
    {
      /*
       * the node may be in the refcnt_0 list, or it might be in the read
       * list itself.  whatever list it is in, remove it from it.
       */
      if(fdn->refcnt == 0)
	{
	  assert(fdn->read.list != NULL);
	  dlist_node_eject(fdn->read.list, fdn->read.node);
	  fdn->read.list = NULL;
	}

      fdn->refcnt++;
    }

  return fdn;
}

/*
 * fd_null
 *
 * allocate a file descriptor of a specified type.
 */
#ifndef _WIN32
static scamper_fd_t *fd_null(int type)
{
  scamper_fd_t *fdn = NULL, findme;
  int fd = -1;

  /* first check if a sharable fd exists for this type */
  findme.type = type;
  if((fdn = fd_find(&findme)) != NULL)
    {
      return fdn;
    }

  if(type == SCAMPER_FD_TYPE_RTSOCK) fd = scamper_rtsock_open();
  else if(type == SCAMPER_FD_TYPE_IFSOCK) fd = socket(AF_INET, SOCK_DGRAM, 0);

  if(fd == -1 || (fdn = fd_alloc(type, fd)) == NULL ||
     (fdn->node = splaytree_insert(fd_tree, fdn)) == NULL)
    {
      goto err;
    }

  return fdn;

 err:
  if(fd != -1)
    {
      if(type == SCAMPER_FD_TYPE_RTSOCK)
	scamper_rtsock_close(fd);
      else if(type == SCAMPER_FD_TYPE_IFSOCK)
	close(fd);
    }
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}
#endif

static scamper_fd_t *fd_icmp(int type, void *addr)
{
  scamper_fd_t *fdn = NULL, findme;
  size_t len = 0;
  int fd = -1;

  findme.type = type;
  findme.fd_icmp_addr = addr;

  if((fdn = fd_find(&findme)) != NULL)
    {
      return fdn;
    }

  if(type == SCAMPER_FD_TYPE_ICMP4)
    {
      fd  = scamper_icmp4_open(addr);
      len = sizeof(struct in_addr);
    }
  else if(type == SCAMPER_FD_TYPE_ICMP6)
    {
      fd  = scamper_icmp6_open(addr);
      len = sizeof(struct in6_addr);
    }

  if(fd == -1 || (fdn = fd_alloc(type, fd)) == NULL ||
     (addr != NULL && (fdn->fd_icmp_addr = memdup(addr, len)) == NULL) ||
     (fdn->node = splaytree_insert(fd_tree, fdn)) == NULL)
    {
      goto err;
    }

  return fdn;

 err:
  if(fd != -1)
    {
      if(type == SCAMPER_FD_TYPE_ICMP4)
	scamper_icmp4_close(fd);
      else if(type == SCAMPER_FD_TYPE_ICMP6)
	scamper_icmp6_close(fd);
    }
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

static scamper_fd_t *fd_tcp(int type, void *addr, uint16_t sport)
{
  scamper_fd_t *fdn, findme;
  size_t len = 0;
  int fd = -1;

  findme.type = type;
  findme.fd_tcp_addr = addr;
  findme.fd_tcp_sport = sport;

  if((fdn = fd_find(&findme)) != NULL)
    {
      return fdn;
    }

  if(type == SCAMPER_FD_TYPE_TCP4)
    {
      fd  = scamper_tcp4_open(addr, sport);
      len = sizeof(struct in_addr);
    }
  else if(type == SCAMPER_FD_TYPE_TCP6)
    {
      fd = scamper_tcp6_open(addr, sport);
      len = sizeof(struct in6_addr);
    }

  if(fd == -1 || (fdn = fd_alloc(type, fd)) == NULL ||
     (addr != NULL && (fdn->fd_tcp_addr = memdup(addr, len)) == NULL))
    {
      goto err;
    }
  fdn->fd_tcp_sport = sport;

  if((fdn->node = splaytree_insert(fd_tree, fdn)) == NULL)
    {
      goto err;
    }

  return fdn;

 err:
  if(fd != -1)
    {
      if(type == SCAMPER_FD_TYPE_TCP4)
	scamper_tcp4_close(fd);
      else if(type == SCAMPER_FD_TYPE_TCP6)
	scamper_tcp6_close(fd);
    }
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

static scamper_fd_t *fd_udp(int type, void *addr, uint16_t sport)
{
  scamper_fd_t *fdn, findme;
  size_t len = 0;
  int fd = -1;

  findme.type = type;
  findme.fd_udp_addr = addr;
  findme.fd_udp_sport = sport;

  if((fdn = fd_find(&findme)) != NULL)
    {
      return fdn;
    }

  if(type == SCAMPER_FD_TYPE_UDP4)
    {
      fd  = scamper_udp4_open(addr, sport);
      len = sizeof(struct in_addr);
    }
  else if(type == SCAMPER_FD_TYPE_UDP6)
    {
      fd  = scamper_udp6_open(addr, sport);
      len = sizeof(struct in6_addr);
    }

  if(fd == -1 || (fdn = fd_alloc(type, fd)) == NULL ||
     (addr != NULL && (fdn->fd_udp_addr = memdup(addr, len)) == NULL))
    {
      printerror(errno, strerror, __func__, "could not open socket");
      goto err;
    }
  fdn->fd_udp_sport = sport;

  if((fdn->node = splaytree_insert(fd_tree, fdn)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not add socket to tree");
      goto err;
    }

  return fdn;

 err:
  if(fd != -1)
    {
      if(type == SCAMPER_FD_TYPE_UDP4)
	scamper_udp4_close(fd);
      else if(type == SCAMPER_FD_TYPE_UDP6)
	scamper_udp6_close(fd);
    }
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

static int fdp_list(void *item, void *param)
{
  ((scamper_fd_poll_t *)item)->list = (dlist_t *)param;
  return 0;
}

/*
 * scamper_fds_poll
 *
 * the money function: this function polls the file descriptors held by
 * scamper.  for each fd with an event, it calls the callback registered
 * with the fd.
 */
int scamper_fds_poll(struct timeval *timeout)
{
  fd_set rfds, *rfdsp;
  fd_set wfds, *wfdsp;
  int count, nfds = -1;

  /* concat any new fds to monitor now */
  dlist_foreach(read_queue, fdp_list, read_fds);
  dlist_concat(read_fds, read_queue);
  dlist_foreach(write_queue, fdp_list, write_fds);
  dlist_concat(write_fds, write_queue);

  /* compose the sets of file descriptors to monitor */
  rfdsp = fd_set_assemble(read_fds, &rfds, &nfds);
  wfdsp = fd_set_assemble(write_fds, &wfds, &nfds);

  /* find out which file descriptors have an event */
#ifdef _WIN32
  if(nfds == -1)
    {
      if(timeout != NULL && timeout->tv_sec >= 0 && timeout->tv_usec >= 0)
	Sleep((timeout->tv_sec * 1000) + (timeout->tv_usec / 1000));
      count = 0;
    }
  else
#endif
  if((count = select(nfds+1, rfdsp, wfdsp, NULL, timeout)) < 0)
    {
      printerror(errno, strerror, __func__, "select failed");
      return -1;
    }

  /* reap any expired fds */
  fd_refcnt_0_reap();

  /* if there are fds to check, then check them */
  if(count > 0)
    {
      fd_set_check(rfdsp, read_fds, &count);
      fd_set_check(wfdsp, write_fds, &count);
    }

  return 0;
}

/*
 * scamper_fd_fd_get
 *
 * return the actual file descriptor associated with the scamper_fd_t
 */
int scamper_fd_fd_get(const scamper_fd_t *fdn)
{
  return fdn->fd;
}

/*
 * scamper_fd_fd_set
 *
 * set the file descriptor being monitored with the scamper_fd_t
 */
int scamper_fd_fd_set(scamper_fd_t *fdn, int fd)
{
  fdn->fd = fd;
  return 0;
}

/*
 * scamper_fd_read_pause
 *
 * ignore any read events on the fd.
 */
void scamper_fd_read_pause(scamper_fd_t *fdn)
{
  fdn->read.flags |= SCAMPER_FD_POLL_FLAG_INACTIVE;
  return;
}

/*
 * scamper_fd_read_unpause
 *
 * monitor read events on the fd.  unset the inactive flag, and push the
 * node back onto the read list
 */
void scamper_fd_read_unpause(scamper_fd_t *fdn)
{
  assert(fdn->read.cb != NULL);

  if((fdn->read.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) != 0)
    {
      fdn->read.flags &= ~(SCAMPER_FD_POLL_FLAG_INACTIVE);

      /*
       * the fd may still be on the read fds list, just with the inactive bit
       * set.  if it isn't, then we have to put it on the queue.
       */
      if(fdn->read.list != read_fds)
	{
	  dlist_node_head_push(read_queue, fdn->read.node);
	  fdn->read.list = read_queue;
	}
    }

  return;
}

/*
 * scmaper_fd_write_pause
 *
 * ignore any write events on the fd
 */
void scamper_fd_write_pause(scamper_fd_t *fdn)
{
  fdn->write.flags |= SCAMPER_FD_POLL_FLAG_INACTIVE;
  return;
}

/*
 * scamper_fd_write_unpause
 *
 * monitor write events on the fd.  unset the inactive flag, and push the
 * node back onto the write list
 */
void scamper_fd_write_unpause(scamper_fd_t *fdn)
{
  assert(fdn->write.cb != NULL);

  if((fdn->write.flags & SCAMPER_FD_POLL_FLAG_INACTIVE) != 0)
    {
      fdn->write.flags &= ~(SCAMPER_FD_POLL_FLAG_INACTIVE);

      /*
       * the fd may still be on the write fds list, just with the inactive bit
       * set.  if it isn't, then we have to put it on the queue.
       */
      if(fdn->write.list != write_fds)
	{
	  dlist_node_head_push(write_queue, fdn->write.node);
	  fdn->write.list = write_queue;
	}
    }

  return;
}

void scamper_fd_read_set(scamper_fd_t *fdn, scamper_fd_cb_t cb, void *param)
{
  assert(fdn->type == SCAMPER_FD_TYPE_PRIVATE);
  fdn->read.cb = cb;
  fdn->read.param = param;
  return;
}

void scamper_fd_write_set(scamper_fd_t *fdn, scamper_fd_cb_t cb, void *param)
{
  assert(fdn->type == SCAMPER_FD_TYPE_PRIVATE);
  fdn->write.cb = cb;
  fdn->write.param = param;
  return;
}

void *scamper_fd_read_state(scamper_fd_t *fdn)
{
  return fdn->read.param;
}

void *scamper_fd_write_state(scamper_fd_t *fdn)
{
  return fdn->write.param;
}

scamper_fd_t *scamper_fd_icmp4(void *addr)
{
  scamper_fd_t *fdn;

  if((fdn = fd_icmp(SCAMPER_FD_TYPE_ICMP4, addr)) != NULL)
    {
      fdn->read.cb = scamper_icmp4_read_cb;
      scamper_fd_read_unpause(fdn);
    }

  return fdn;
}

scamper_fd_t *scamper_fd_icmp6(void *addr)
{
  scamper_fd_t *fdn;

  if((fdn = fd_icmp(SCAMPER_FD_TYPE_ICMP6, addr)) != NULL)
    {
      fdn->read.cb = scamper_icmp6_read_cb;
      scamper_fd_read_unpause(fdn);
    }

  return fdn;
}

#ifndef _WIN32
scamper_fd_t *scamper_fd_rtsock(void)
{
  scamper_fd_t *fdn;

  if((fdn = fd_null(SCAMPER_FD_TYPE_RTSOCK)) != NULL)
    {
      fdn->read.cb = scamper_rtsock_read_cb;
      scamper_fd_read_unpause(fdn);
    }

  return fdn;
}
#endif

scamper_fd_t *scamper_fd_tcp4(void *addr, uint16_t sport)
{
  return fd_tcp(SCAMPER_FD_TYPE_TCP4, addr, sport);
}

scamper_fd_t *scamper_fd_tcp6(void *addr, uint16_t sport)
{
  return fd_tcp(SCAMPER_FD_TYPE_TCP6, addr, sport);
}

scamper_fd_t *scamper_fd_udp4(void *addr, uint16_t sport)
{
  return fd_udp(SCAMPER_FD_TYPE_UDP4, addr, sport);
}

scamper_fd_t *scamper_fd_udp6(void *addr, uint16_t sport)
{
  return fd_udp(SCAMPER_FD_TYPE_UDP6, addr, sport);
}

#ifndef _WIN32
scamper_fd_t *scamper_fd_ifsock(void)
{
  return fd_null(SCAMPER_FD_TYPE_IFSOCK);
}
#endif

scamper_fd_t *scamper_fd_dl(int ifindex)
{
  scamper_fd_t *fdn = NULL, findme;
  scamper_dl_t *dl = NULL;
  int fd = -1;

  findme.type = SCAMPER_FD_TYPE_DL;
  findme.fd_dl_ifindex = ifindex;

  if((fdn = fd_find(&findme)) != NULL)
    {
      scamper_fd_read_unpause(fdn);
      return fdn;
    }

  /*
   * open the file descriptor for the ifindex, and then allocate a scamper_fd
   * for the file descriptor
   */
  if((fd  = scamper_dl_open(ifindex)) == -1 ||
     (fdn = fd_alloc(SCAMPER_FD_TYPE_DL, fd)) == NULL)
    {
      goto err;
    }

  /*
   * record the ifindex for the file descriptor, and then allocate the state
   * that is maintained with it
   */
  fdn->fd_dl_ifindex = ifindex;

  /*
   * 1. add the file descriptor to the splay tree
   * 2. allocate state for the datalink file descriptor
   */
  if((fdn->node = splaytree_insert(fd_tree, fdn)) == NULL ||
     (dl = scamper_dl_state_alloc(fdn)) == NULL)
    {
      goto err;
    }

  /* set the file descriptor up for reading */
  fdn->read.cb     = scamper_dl_read_cb;
  fdn->read.param  = dl;
  fdn->write.cb    = NULL;
  fdn->write.param = dl;
  scamper_fd_read_unpause(fdn);

  return fdn;

 err:
  if(fdn != NULL) free(fdn);
  if(fd != -1) scamper_dl_close(fd);
  return NULL;
}

/*
 * scamper_fd_private
 *
 * allocate a private fd for scamper to manage.  this fd is not shared amongst
 * scamper.
 */
scamper_fd_t *scamper_fd_private(int fd,
				 scamper_fd_cb_t read_cb, void *read_param,
				 scamper_fd_cb_t write_cb, void *write_param)
{
  scamper_fd_t *fdn = NULL;

  if((fdn = fd_alloc(SCAMPER_FD_TYPE_PRIVATE, fd)) == NULL)
    {
      goto err;
    }

  if(read_cb != NULL)
    {
      scamper_fd_read_set(fdn, read_cb, read_param);
      scamper_fd_read_unpause(fdn);
    }

  if(write_cb != NULL)
    {
      scamper_fd_write_set(fdn, write_cb, write_param);
      scamper_fd_write_unpause(fdn);
    }

  return fdn;

 err:
  if(fdn != NULL) fd_free(fdn);
  return NULL;
}

/*
 * scamper_fd_ifindex
 *
 * if the file descriptor is associated with a known ifindex, return details
 * of it.
 */
int scamper_fd_ifindex(const scamper_fd_t *fdn, int *ifindex)
{
  if(fdn->type == SCAMPER_FD_TYPE_DL)
    {
      *ifindex = fdn->fd_dl_ifindex;
      return 0;
    }

  return -1;
}

/*
 * scamper_fd_sport
 *
 * if the file descriptor has a known source port, return details of it.
 */
int scamper_fd_sport(const scamper_fd_t *fdn, uint16_t *sport)
{
  switch(fdn->type)
    {
    case SCAMPER_FD_TYPE_UDP4:
    case SCAMPER_FD_TYPE_UDP6:
      *sport = fdn->fd_udp_sport;
      return 0;

    case SCAMPER_FD_TYPE_TCP4:
    case SCAMPER_FD_TYPE_TCP6:
      *sport = fdn->fd_tcp_sport;
      return 0;
    }

  return -1;
}

/*
 * scamper_fd_free
 *
 * this function reduces the reference count for a given file descriptor.
 *
 * if zero is reached, the fd will be dealt with when scamper_fd_poll is next
 * called.  the fd cannot be summarily removed here without the potential
 * to screw up any current call to scamper_fd_poll as that function assumes
 * the list remains intact for the duration of any events found with select.
 *
 */
void scamper_fd_free(scamper_fd_t *fdn)
{
  assert(fdn != NULL);
  assert(fdn->refcnt > 0);
  if(--fdn->refcnt == 0)
    {
      fd_refcnt_0(fdn);
    }
  return;
}

/*
 * alloc_list
 *
 * helper function to allocate a list for scamper_fds_init
 */
static dlist_t *alloc_list(char *name)
{
  dlist_t *list;
  if((list = dlist_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "alloc %s failed", name);
    }
  return list;
}

/*
 * scamper_fds_init
 *
 * setup the global data structures necessary for scamper to manage a set of
 * file descriptors
 */
int scamper_fds_init()
{
#ifndef _WIN32
  scamper_debug(__func__, "fd table size: %d", getdtablesize());
#endif

  if((read_fds    = alloc_list("read fd list"))   == NULL ||
     (read_queue  = alloc_list("read fd queue"))  == NULL ||
     (write_fds   = alloc_list("write fd list"))  == NULL ||
     (write_queue = alloc_list("write fd queue")) == NULL ||
     (refcnt_0    = alloc_list("refcnt_0 list"))  == NULL)
    {
      return -1;
    }

  if((fd_tree = splaytree_alloc(fd_cmp)) == NULL)
    {
      printerror(errno, strerror, __func__, "alloc fd tree failed");
      return -1;
    }

  return 0;
}

/*
 * cleanup_list
 *
 * helper function to remove scamper_fd_poll structures from any lists.
 */
static void cleanup_list(dlist_t *list)
{
  scamper_fd_poll_t *poll;

  if(list == NULL) return;

  while((poll = dlist_head_pop(list)) != NULL)
    {
      poll->list = NULL;
      poll->node = NULL;
    }

  dlist_free(list);

  return;
}

/*
 * scamper_fds_cleanup
 *
 * tidy up the state allocated to maintain fd records.
 */
void scamper_fds_cleanup()
{
  scamper_fd_poll_t *fdp;

  /* clean up the lists */
  cleanup_list(read_fds);    read_fds = NULL;
  cleanup_list(write_fds);   write_fds = NULL;
  cleanup_list(read_queue);  read_queue = NULL;
  cleanup_list(write_queue); write_queue = NULL;

  /* reap anything on the reap list */
  if(refcnt_0 != NULL)
    {
      while((fdp = (scamper_fd_poll_t *)dlist_head_get(refcnt_0)) != NULL)
	{
	  fd_close(fdp->fdn);
	  fd_free(fdp->fdn);
	}
      dlist_free(refcnt_0);
      refcnt_0 = NULL;
    }

  /* clean up the tree */
  if(fd_tree != NULL)
    {
      splaytree_free(fd_tree, NULL);
      fd_tree = NULL;
    }

  return;
}
