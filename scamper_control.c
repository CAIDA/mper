/*
 * scamper_control.c
 *
 * $Id: scamper_control.c,v 1.116 2009/05/26 22:14:15 mjl Exp $
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
 ***************************************************************************
 *
 * if scamper is started as a daemon that listens for commands, then this
 * file contains the logic that drives the daemon.
 * 
 * by default, scamper listens locally for commands.  there are plans to
 * status notifications out to interested parties for the purpose of scamper
 * process monitoring.
 *
 */

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef int ssize_t;
typedef int pid_t;
typedef int socklen_t;
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#include <process.h>
#define close _close
#define read _read
#define snprintf _snprintf
#define strcasecmp _stricmp
#define SHUT_RDWR SD_BOTH
#define O_NONBLOCK _O_NONBLOCK
#endif

#if defined(__APPLE__)
#define _BSD_SOCKLEN_T_
#include <stdint.h>
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper.h"
#include "scamper_control.h"
#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_linepoll.h"
#include "scamper_writebuf.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_sources.h"
#include "mjl_list.h"
#include "utils.h"

/*
 * client_t
 *
 * this structure records state required to manage a client connected to
 * scamper via a control socket.
 */
typedef struct client
{
  /* node for this client in the list of connected clients */
  dlist_node_t       *node;

  /*
   * fdn: file descriptor managed by scamper for the client fd.
   * lp:  interface to read a line at a time from the client.
   * wb:  interface to handle non-blocking writes to the scamper_fd.
   */
  scamper_fd_t       *fdn;
  scamper_linepoll_t *lp;
  scamper_writebuf_t *wb;

  /* the mode the client is in */
  int                 mode;

  /*
   * the next set of variables are used when the client's connection is used
   * to supply tasks, and is also used to send the results back.
   *
   *  source:     the source allocated to the control socket.
   */
  scamper_source_t   *source;
} client_t;

#define CLIENT_MODE_ATTACHED    1
#define CLIENT_MODE_FLUSH       2

/*
 * client_list: a doubly linked list of connected clients
 * fd: a scamper_fd struct that contains callback details
 */
static dlist_t      *client_list  = NULL;
static scamper_fd_t *fdn          = NULL;

/*
 * client_free
 *
 * free up client state for the socket handle.
 */
static void client_free(client_t *client)
{
  int fd;

  if(client == NULL) return;

  /* if there's an open socket here, close it now */
  if(client->fdn != NULL)
    {
      fd = scamper_fd_fd_get(client->fdn);
      scamper_fd_free(client->fdn);

      shutdown(fd, SHUT_RDWR);
      close(fd);
    }

  /* remove the linepoll structure */
  if(client->lp != NULL) scamper_linepoll_free(client->lp, 0);

  /* remove the writebuf structure */
  if(client->wb != NULL) scamper_writebuf_free(client->wb);

  /* remove the client from the list of clients */
  if(client->node != NULL) dlist_node_pop(client_list, client->node);

  /* make sure the source is empty before freeing */
  if(client->source != NULL)
    {
      scamper_source_abandon(client->source);
      scamper_source_free(client->source);
    }

  free(client);
  return;
}

static int client_send(client_t *client, char *fs, ...)
{
  char    msg[512], *str;
  va_list ap;
  int     ret;
  size_t  len;

  va_start(ap, fs);
  if((ret = vsnprintf(msg, sizeof(msg), fs, ap)) > (int)sizeof(msg))
    {
      len = ret;

      if((str = malloc((size_t)(len + 2))) == NULL)
	{
	  va_end(ap);
	  return -1;
	}
      vsnprintf(str, len+1, fs, ap);
      va_end(ap);

      str[len++] = '\n'; 
      str[len] = '\0';

      ret = scamper_writebuf_send(client->wb, str, len);
      free(str);
    }
  else
    {
      len = ret;

      va_end(ap);

      msg[len++] = '\n'; 
      msg[len] = '\0';

      ret = scamper_writebuf_send(client->wb, msg, len);
    }

  return ret;
}

static void client_signalmore(void *param)
{
  client_t *client = (client_t *)param;
  client_send(client, "MORE");
  scamper_fd_read_unpause(client->fdn);
  return;
}

static int client_isdone(client_t *client)
{
  size_t len;
  assert(client->wb != NULL);

  if((len = scamper_writebuf_len(client->wb)) != 0)
    {
      scamper_debug(__func__, "client writebuf len %d", len);
      return 0;
    }

  if(client->source != NULL && scamper_source_isfinished(client->source) == 0)
    {
      scamper_debug(__func__, "source not finished");
      return 0;
    }

  return 1;
}

/*
 * client_drained
 *
 * this callback is called when the client's writebuf is empty.
 * the point being to check when the client has had all its output sent
 * and it can be cleaned up
 */
static void client_drained(void *ptr, scamper_writebuf_t *wb)
{
  client_t *client = (client_t *)ptr;

  if(client->mode != CLIENT_MODE_FLUSH)
    return;

  if(client_isdone(client) == 0)
    return;

  client_free(client);  
  return;
}

/*
 * client_attached_cb
 *
 * this callback is used when a control socket has been 'attached' such that
 * it sends commands over the control socket and in return it obtains
 * results.
 */
static int client_attached_cb(client_t *client, uint8_t *buf, size_t len)
{
  assert(client->source != NULL);

  /* the control socket will not be supplying any more tasks */
  if(len == 4 && strcasecmp((char *)buf, "done") == 0)
    {
      /* mark the source as not going to supply any further tasks */
      scamper_source_control_finish(client->source);
      return client_send(client, "OK");
    }

  /* try the command to see if it is valid and acceptable */
  if(scamper_source_command(client->source, (char *)buf) == 0)
    {
      return client_send(client, "OK");
    }

  return client_send(client, "ERR command not accepted");
}

/*
 * client_read_line
 *
 * callback passed to the client's linepoll instance, which is used to read
 * incoming commands.  the current mode the client is in determines how the
 * command is actually handled.
 */
static int client_read_line(void *param, uint8_t *buf, size_t len)
{
  static int (*const func[])(client_t *, uint8_t *, size_t) = {
    client_attached_cb,      /* CLIENT_MODE_ATTACHED    == 0x01 */
  };

  client_t *client = (client_t *)param;
  assert(client->mode == 0 || client->mode == 1);
  return func[client->mode](client, buf, len);
}

static void client_read(const int fd, void *param)
{
  client_t *client;
  ssize_t rc;
  uint8_t buf[256];

  client = (client_t *)param;
  assert(scamper_fd_fd_get(client->fdn) == fd);

  /* try and read more from the client */
  if((rc = read(fd, buf, sizeof(buf))) < 0)
    {
      if(errno != EAGAIN && errno != EINTR)
	{
	  printerror(errno, strerror, __func__, "read failed");
	}

      /* destroy the client */
      client_free(client);
      return;
    }

  /* if there is incoming data, deal with it */
  if(rc > 0)
    {
      scamper_linepoll_handle(client->lp, buf, (size_t)rc);
      return;
    }

  /* nothing left to do read with this fd */
  scamper_fd_read_pause(client->fdn);

  if(client->source != NULL)
    {
      scamper_source_control_finish(client->source);
      scamper_source_abandon(client->source);
    }

  if(client_isdone(client) != 0)
    {
      client_free(client);
      return;
    }
  client->mode = CLIENT_MODE_FLUSH;

  return;
}

/*
 * client_alloc
 *
 * given a new inbound client, allocate a new node for it.
 */
static client_t *client_alloc(struct sockaddr *sa, socklen_t slen, int fd)
{
  client_t *client;
  char buf[128];

  /* make the socket non-blocking, so a read or write will not hang scamper */
#ifndef _WIN32
  if(fcntl_set(fd, O_NONBLOCK) == -1)
    {
      return NULL;
    }
#endif

  /* allocate the structure that holds the socket/client together */
  if((client = malloc_zero(sizeof(struct client))) == NULL)
    {
      return NULL;
    }

  /* put the node into the list of sockets that are connected */
  if((client->node = dlist_tail_push(client_list, client)) == NULL)
    {
      goto cleanup;
    }

  /* add the file descriptor to the event manager */
  if((client->fdn=scamper_fd_private(fd,client_read,client,NULL,NULL)) == NULL)
    {
      goto cleanup;
    }

  /* put a wrapper around the socket to read from it one line at a time */
  if((client->lp = scamper_linepoll_alloc(client_read_line, client)) == NULL)
    {
      goto cleanup;
    }

  if((client->wb = scamper_writebuf_alloc()) == NULL)
    {
      goto cleanup;
    }
  scamper_writebuf_attach(client->wb,client->fdn,client,NULL,client_drained);

  if((client->source = scamper_source_alloc(client_signalmore, client)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not allocate source");
      goto cleanup;
    }

  /* put the source into rotation */
  if(scamper_sources_add(client->source) != 0)
    {
      printerror(errno, strerror, __func__, "could not add source to rotation");
      goto cleanup;
    }

  client->mode = CLIENT_MODE_ATTACHED;

  snprintf(buf, sizeof(buf), "mper version=%s protocol=%d.%d", MPER_VERSION,
	   CLIENT_PROTOCOL_MAJOR, CLIENT_PROTOCOL_MINOR);
  client_send(client, buf);
  return client;

 cleanup:
  if(client->source != NULL)
    {
      scamper_source_abandon(client->source);
      scamper_source_free(client->source);
    }
  if(client->wb != NULL) scamper_writebuf_free(client->wb);
  if(client->lp != NULL) scamper_linepoll_free(client->lp, 0);
  if(client->node != NULL) dlist_node_pop(client_list, client->node);
  free(client);

  return NULL;
}

static void control_accept(const int fd, void *param)
{
  struct sockaddr_storage ss;
  socklen_t socklen;
  int s;

  /* accept the new client */
  socklen = sizeof(ss);
  if((s = accept(fd, (struct sockaddr *)&ss, &socklen)) == -1)
    {
      return;
    }

  scamper_debug(__func__, "fd %d", s);

  /* allocate a client struct to keep track of data coming in on socket */
  if(client_alloc((struct sockaddr *)&ss, socklen, s) == NULL)
    {
      shutdown(s, SHUT_RDWR);
      close(s);
    }

  return;
}

int scamper_control_init(int port)
{
  struct sockaddr_in sin;
  struct in_addr     in;
  int                fd = -1, opt;

  /* open the TCP socket we are going to listen on */
  if((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
      printerror(errno, strerror, __func__, "could not create TCP socket");
      return -1;
    }

  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) != 0)
    {
      printerror(errno, strerror, __func__, "could not set SO_REUSEADDR");
      goto cleanup;
    }

  /* bind the socket to loopback on the specified port */
  in.s_addr = htonl(INADDR_LOOPBACK);
  sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);
  if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
    {
      printerror(errno, strerror, __func__,
		 "could not bind to loopback port %d", port);
      goto cleanup;
    }

  /* tell the system we want to listen for new clients on this socket */
  if(listen(fd, -1) == -1)
    {
      printerror(errno, strerror, __func__, "could not listen");
      goto cleanup;
    }

  /* allocate the list of clients connected to this scamper process */
  if((client_list = dlist_alloc()) == NULL)
    {
      goto cleanup;
    }

  if((fdn = scamper_fd_private(fd, control_accept, NULL, NULL, NULL)) == NULL)
    {
      goto cleanup;
    }

  return 0;

 cleanup:
  if(client_list != NULL) dlist_free(client_list);
  if(fdn != NULL) scamper_fd_free(fdn);
  close(fd);
  return -1;
}

/*
 * scamper_control_cleanup
 *
 * go through and free all the clients that are connected.
 * write anything left in the writebuf to the clients (non-blocking) and
 * then close the socket.
 */
void scamper_control_cleanup()
{
  client_t *client;
  int fd;

  if(client_list != NULL)
    {
      while((client = dlist_head_pop(client_list)) != NULL)
	{
	  client->node = NULL;
	  scamper_writebuf_flush(client->wb);
	  client_free(client);
	}

      dlist_free(client_list);
      client_list = NULL;
    }

  /* stop monitoring the control socket for new connections */
  if(fdn != NULL)
    {
      if((fd = scamper_fd_fd_get(fdn)) != -1)
	{
	  close(fd);
	}

      scamper_fd_free(fdn);
      fdn = NULL;
    }

  return;
}
