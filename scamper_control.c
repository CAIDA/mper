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
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  /* for TCP_NODELAY */
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
#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_linepoll.h"
#include "scamper_writebuf.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_control.h"
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

/* ====================================================================== */
/* functions for allocating, referencing, and dereferencing scamper sources */
scamper_source_t *scamper_source_alloc(void (*signalmore)(void *),
				       client_t *param);
scamper_source_t *scamper_source_use(scamper_source_t *source);
void scamper_source_abandon(scamper_source_t *source);

/* functions for getting the number of commands/cycles currently buffered */
int scamper_source_getcommandcount(const scamper_source_t *source);
int scamper_source_gettaskcount(const scamper_source_t *source);

/* determine if the source has finished yet */
int scamper_source_isfinished(scamper_source_t *source);

/* functions for adding stuff to the source's command queue */
int scamper_source_command(scamper_source_t *source, const char *command);

/* functions for managing a collection of sources */
int scamper_sources_add(scamper_source_t *source);
int scamper_sources_del(scamper_source_t *source);
void scamper_sources_empty(void);
void scamper_source_control_finish(scamper_source_t *source);
/* ====================================================================== */

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
  scamper_source_command(client->source, (char *)buf);
  return 0;

#if 0
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
#endif
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
  client_t *client = (client_t *)param;
  assert(client->mode == CLIENT_MODE_ATTACHED);
  return client_attached_cb(client, buf, len);
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

int scamper_control_init(int port, int use_tcp)
{
  struct sockaddr_in sin;
  struct in_addr     in;
  int                fd = -1, opt;
#ifndef _WIN32
  struct sockaddr_un sun;
  int path_len;

  if(use_tcp)
#endif
    {
      /* open the TCP socket we are going to listen on */
      if((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        {
	  printerror(errno, strerror, __func__, "could not create TCP socket");
	  return -1;
	}

      opt = 1;
      if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
		    (char *)&opt, sizeof(opt)) != 0)
        {
	  printerror(errno, strerror, __func__, "could not set TCP_NODELAY");
	  goto cleanup;
	}

      opt = 1;
      if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		    (char *)&opt, sizeof(opt)) != 0)
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

      scamper_debug(__func__, "listening on tcp port %d", port);
    }
#ifndef _WIN32
  else
    {
      if((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
        {
	  printerror(errno, strerror, __func__, "could not create unix socket");
	  return -1;
	}

      memset(&sun, 0, sizeof(sun));
      sun.sun_family = AF_LOCAL;
      path_len = snprintf(sun.sun_path, sizeof(sun.sun_path),
			  "/tmp/mper.%d", port);
      if(path_len >= sizeof(sun.sun_path))
        {
	  printerror(errno, NULL, __func__,
	      "INTERNAL ERROR: unix domain socket path too long for port %d",
		     port);
	  goto cleanup;
	}

      (void)unlink(sun.sun_path);
      if(bind(fd, (struct sockaddr *)&sun, SUN_LEN(&sun)) == -1)
        {
	  printerror(errno, strerror, __func__,
		     "could not bind to unix domain socket %s", sun.sun_path);
	  goto cleanup;
	}

      scamper_debug(__func__, "listening on unix domain socket %s",
		    sun.sun_path);
    }
#endif

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


/*
** ========================================================================
** scamper_sources.c
** ========================================================================
*/

#ifdef _WIN32
#define MAXHOSTNAMELEN 256
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define strdup _strdup
#endif

#ifndef _WIN32
#include <sys/param.h>
#include <netdb.h>
#endif

#include "mper_keywords.h"
#include "mper_msg.h"
#include "mper_msg_reader.h"
#include "mper_msg_writer.h"

#include "scamper_addr.h"
#include "scamper_target.h"
#include "scamper_ping.h"
#include "scamper_do_ping.h"

#include "mjl_splaytree.h"

/*
 * scamper_source
 *
 * this structure maintains state regarding tasks that come from a particular
 * source.
 *
 */
struct scamper_source
{
  /* properties of the source */
  uint32_t                      priority;
  int                           refcnt;

  /* variable that indicates if no more commands are coming */
  int                           isfinished;

  /* a function and a parameter to interact with the control socket */
  void                          (*signalmore)(void *param);
  client_t                      *client;

  /*
   * commands:     a list of commands for the source that are queued, ready to
   *               be passed out as tasks
   * onhold:       a list of commands that are on hold.
   * tasks:        a list of tasks currently active from the source.
   */
  slist_t                      *commands;
  dlist_t                      *onhold;
  dlist_t                      *tasks;

  /*
   * nodes to keep track of whether the source is in the active or blocked
   * lists.
   */
  void                         *list_;
  void                         *list_node;
};

/*
 * command
 *
 *  data:  pointer to data allocated for task
 */
typedef struct command
{
  scamper_ping_t       *data;
} command_t;

/*
 * command_onhold
 *
 * structure to keep details of a command on hold.
 *
 *  command: pointer to the command that is waiting on a task to complete
 *  task:    pointer to the task that has blocked this command from executing
 *  source:  pointer to the source that wants to execute the command
 *  node:    pointer to the dlist_node in the source's onhold dlist
 *  cookie:  pointer returned by scamper_task_onhold.
 */
typedef struct command_onhold
{
  command_t        *command;
  scamper_task_t   *task;
  scamper_source_t *source;
  dlist_node_t     *node;
  void             *cookie;
} command_onhold_t;

/*
 * global variables for managing sources:
 *
 * a source is stored in one of two lists depending on its state.  it is
 * either stored in the active list, a round-robin circular list, or in
 * the blocked list.
 *
 * the source, if any, currently being used (that is, has not used up its
 * priority quantum) is pointed to by source_cur.  the number of tasks that
 * have been read from the current source in this rotation is held in
 * source_cnt.
 */
static clist_t          *active      = NULL;
static dlist_t          *blocked     = NULL;
static dlist_t          *finished    = NULL;
static scamper_source_t *source_cur  = NULL;
static uint32_t          source_cnt  = 0;


/* ---------------------------------------------------------------------- */

static control_word_t resp_words[MPER_MSG_MAX_WORDS];


static const char *create_error_response(size_t reqnum, const char *txt)
{
  const char *msg = NULL;
  size_t msg_len = 0;

  INIT_CMESSAGE(resp_words, reqnum, CMD_ERROR);
  SET_STR_CWORD(resp_words, 1, TXT, txt, strlen(txt));
  msg = create_control_message(resp_words, CMESSAGE_LEN(1), &msg_len);
  assert(msg_len != 0);
  return msg;
}


static void send_response(scamper_source_t *source, const char *message)
{
  /* XXX somewhat inefficient to do a separate send for just the newline */
  scamper_writebuf_send(source->client->wb, message, strlen(message));
  scamper_writebuf_send(source->client->wb, "\n", 1);
}


/* ---------------------------------------------------------------------- */


/* forward declare */
static void source_free(scamper_source_t *source);

static int source_refcnt_dec(scamper_source_t *source)
{
  assert(source->refcnt > 0);
  source->refcnt--;
  return source->refcnt;
}

static void command_free(command_t *command)
{
  if(command->data != NULL)
    {
      scamper_do_ping_free(command->data);
    }

  free(command);
  return;
}

/*
 * source_next
 *
 * advance to the next source to read addresses from, and reset the
 * current count of how many addresses have been returned off the list
 * for this source-cycle
 */
static scamper_source_t *source_next(void)
{
  void *node;

  if((node = clist_node_next(source_cur->list_node)) != source_cur->list_node)
    {
      source_cur = clist_node_item(node);
    }

  source_cnt = 0;

  return source_cur;
}

/*
 * source_active_detach
 *
 * detach the source out of the active list.  move to the next source
 * if it is the current source that is being read from.
 */
static void source_active_detach(scamper_source_t *source)
{
  void *node;

  assert(source->list_ == active);

  if((node = clist_node_next(source->list_node)) != source->list_node)
    {
      source_cur = clist_node_item(node);
    }
  else
    {
      source_cur = NULL;
    }

  source_cnt = 0;

  clist_node_pop(active, source->list_node);
  source->list_     = NULL;
  source->list_node = NULL;

  return;
}

/*
 * source_blocked_detach
 *
 * detach the source out of the blocked list.
 */
static void source_blocked_detach(scamper_source_t *source)
{
  assert(source->list_ == blocked);

  dlist_node_pop(blocked, source->list_node);
  source->list_     = NULL;
  source->list_node = NULL;
  return;
}

/*
 * source_finished_detach
 *
 * detach the source out of the finished list.
 */
static void source_finished_detach(scamper_source_t *source)
{
  assert(source->list_ == finished);

  dlist_node_pop(finished, source->list_node);
  source->list_     = NULL;
  source->list_node = NULL;
  return;
}

/*
 * source_active_attach
 *
 * some condition has changed, which may mean the source can go back onto
 * the active list for use by the probing process.
 *
 * a caller MUST NOT assume that the source will necessarily end up on the
 * active list after calling this function.  for example, source_active_attach
 * may be called when new tasks are added to the command list.  however, the
 * source may have a zero priority, which means probing this source is
 * currently paused.
 */
static int source_active_attach(scamper_source_t *source)
{
  if(source->list_ == active)
    {
      return 0;
    }

  if(source->list_ == finished)
    {
      return -1;
    }

  if(source->list_ == blocked)
    {
      /* if the source has a zero priority, it must remain blocked */
      if(source->priority == 0)
	{
	  return 0;
	}
      source_blocked_detach(source);
    }

  if((source->list_node = clist_tail_push(active, source)) == NULL)
    {
      return -1;
    }
  source->list_ = active;

  if(source_cur == NULL)
    {
      source_cur = source;
      source_cnt = 0;
    }

  return 0;
}

/*
 * source_blocked_attach
 *
 * put the specified source onto the blocked list.
 */
static int source_blocked_attach(scamper_source_t *source)
{
  if(source->list_ == blocked)
    {
      return 0;
    }

  if(source->list_ == finished)
    {
      return -1;
    }

  if(source->list_node != NULL)
    {
      source_active_detach(source);
    }

  if((source->list_node = dlist_tail_push(blocked, source)) == NULL)
    {
      return -1;
    }
  source->list_ = blocked;

  return 0;
}

/*
 * source_finished_attach
 *
 * put the specified source onto the finished list.
 */
static int source_finished_attach(scamper_source_t *source)
{
  if(source->list_ == finished)
    return 0;

  if(source->list_ == active)
    source_active_detach(source);
  else if(source->list_ == blocked)
    source_blocked_detach(source);

  if((source->list_node = dlist_tail_push(finished, source)) == NULL)
    {
      return -1;
    }

  source->list_ = finished;
  return 0;
}

/*
 * source_command_unhold
 *
 * the task this command was blocked on has now completed, and this callback
 * was used.  put the command at the front of the source's list of things
 * to do.
 */
static void source_command_unhold(void *cookie)
{
  command_onhold_t *onhold  = (command_onhold_t *)cookie;
  scamper_source_t *source  = onhold->source;
  command_t        *command = onhold->command;

  /*
   * 1. disconnect the onhold structure from the source
   * 2. free the onhold structure -- don't need it anymore
   * 3. put the command at the front of the source's command list
   * 4. ensure the source is in active rotation
   */
  dlist_node_pop(source->onhold, onhold->node);
  free(onhold);
  slist_head_push(source->commands, command);
  source_active_attach(source);

  return;
}

/*
 * source_command_onhold
 *
 * 
 */
static int source_command_onhold(scamper_source_t *source,
				 scamper_task_t *task, command_t *command)
{
  command_onhold_t *onhold = NULL;

  if((onhold         = malloc_zero(sizeof(command_onhold_t))) == NULL ||
     (onhold->node   = dlist_tail_push(source->onhold, onhold)) == NULL ||
     (onhold->cookie = scamper_task_onhold(task, onhold,
					   source_command_unhold)) == NULL)
    {
      goto err;
    }

  onhold->task    = task;
  onhold->source  = source;
  onhold->command = command;

  return 0;

 err:
  if(onhold != NULL)
    {
      if(onhold->node != NULL) dlist_node_pop(source->onhold, onhold->node);
      free(onhold);
    }
  return -1;
}

static int command_dstaddrs_foreach(scamper_addr_t *addr, void *param)
{
  scamper_task_t **task_out;
  scamper_task_t *task;

  if((task = scamper_target_find(addr)) == NULL)
    {
      return 0;
    }

  task_out = (scamper_task_t **)param;
  *task_out = task;

  return -1;
}

static scamper_task_t *command_dstaddrs(void *data)
{
  scamper_task_t *task = NULL;
  if(scamper_do_ping_dstaddr(data, &task, command_dstaddrs_foreach) == 0)
    {
      assert(task == NULL);
      return NULL;
    }

  assert(task != NULL);
  return task;
}

static int command_probe_handle(scamper_source_t *source, command_t *command,
				scamper_task_t **task_out)
{
  scamper_task_t *task = NULL;

  if((task = command_dstaddrs(command->data)) != NULL)
    {
      source_command_onhold(source, task, command);
      *task_out = NULL;
      return 0;      
    }

  /* allocate the task structure to keep everything together */
  if((task = scamper_do_ping_alloctask(command->data,
				       source->client->wb)) == NULL)
    {
      goto err;
    }

  /* keep a record in the source that this task is now active */
  task->source = scamper_source_use(source);
  if((task->source_task = dlist_tail_push(source->tasks, task)) == NULL)
    {
      goto err;
    }

  /* record a targetset structure with the task */
  if((task->targetset = scamper_targetset_alloc(task)) == NULL)
    {
      goto err;
    }

  /* return to the caller the task we allocated */
  *task_out = task;

  /* the task that was pointed to by command->data has a new owner */
  command->data = NULL;

  /* free the command, it is no longer required */
  command_free(command);

  return 0;

 err:
  if(task != NULL) scamper_task_free(task);
  command_free(command);
  return -1;
}

/*
 * source_flush_commands
 *
 * remove the ability for the source to supply any more commands, and remove
 * any commands it currently has queued.
 */
static void source_flush_commands(scamper_source_t *source)
{
  command_onhold_t *onhold;
  command_t *command;

  if(source->commands != NULL)
    {
      while((command = slist_head_pop(source->commands)) != NULL)
	{
	  command_free(command);
	}
      slist_free(source->commands);
      source->commands = NULL;
    }

  if(source->onhold != NULL)
    {
      while((onhold = dlist_head_pop(source->onhold)) != NULL)
	{
	  scamper_task_dehold(onhold->task, onhold->cookie);
	  free(onhold);
	}
      dlist_free(source->onhold);
      source->onhold = NULL;
    }

  return;
}

/*
 * source_flush_tasks
 *
 * stop all active tasks that originated from the specified source.
 */
static void source_flush_tasks(scamper_source_t *source)
{
  scamper_task_t *task;

  /* flush all active tasks. XXX: what about completed tasks? */
  if(source->tasks != NULL)
    {
      while((task = dlist_head_pop(source->tasks)) != NULL)
	{
	  task->source_task = NULL;
	  scamper_task_free(task);
	}
      dlist_free(source->tasks);
      source->tasks = NULL;
    }

  return;
}

/*
 * source_detach
 *
 * remove the source from sources management.
 */
static void source_detach(scamper_source_t *source)
{
  /* detach the source from whatever list it is in */
  if(source->list_ == active)
    source_active_detach(source);
  else if(source->list_ == blocked)
    source_blocked_detach(source);
  else if(source->list_ == finished)
    source_finished_detach(source);

  assert(source->list_ == NULL);
  assert(source->list_node == NULL);

  return;
}

/*
 * scamper_source_isfinished
 *
 * determine if the source has queued all it has to do.
 * note that the tasks list may still have active items currently processing.
 */
int scamper_source_isfinished(scamper_source_t *source)
{
  /* if there are commands queued, then the source cannot be finished */
  if(source->commands != NULL && slist_count(source->commands) > 0)
    {
      return 0;
    }

  /* if there are commands that are on hold, the source cannot be finished */
  if(source->onhold != NULL && dlist_count(source->onhold) > 0)
    {
      return 0;
    }

  /* if there are still tasks underway, the source is not finished */
  if(source->tasks != NULL && dlist_count(source->tasks) > 0)
    {
      return 0;
    }

  /*
   * if the source still has commands to come, then it is not finished.
   */
  if(source->isfinished == 0)
    {
      return 0;
    }

  return 1;
}

/*
 * source_free
 *
 * clean up the source
 */
static void source_free(scamper_source_t *source)
{
  assert(source->refcnt == 0);

  /* pull the source out of sources management */
  source_detach(source);

  /* empty the source of commands */
  if(source->commands != NULL)
    {
      source_flush_commands(source);
    }

  /* empty the source of tasks */
  if(source->tasks != NULL)
    {
      source_flush_tasks(source);
    }

  free(source);
  return;
}

/*
 * scamper_source_getcommandcount
 *
 * return the number of commands queued for the source
 */
int scamper_source_getcommandcount(const scamper_source_t *source)
{
  if(source->commands != NULL)
    {
      return slist_count(source->commands);
    }
  return -1;
}

int scamper_source_gettaskcount(const scamper_source_t *source)
{
  if(source->tasks != NULL)
    {
      return dlist_count(source->tasks);
    }
  return -1;
}

/*
 * scamper_source_command
 *
 */
int scamper_source_command(scamper_source_t *source, const char *command)
{
  const control_word_t *words = NULL;
  size_t word_count = 0;
  const char *resp_msg = NULL;
  const char *error_msg = NULL;
  scamper_ping_t *data = NULL;
  command_t *cmd = NULL;

  words = parse_control_message(command, &word_count);
  if(word_count == 0)
    {
      resp_msg = create_error_response(words[0].cw_uint, words[1].cw_str);
      send_response(source, resp_msg);
      return -1;
    }

  if(words[1].cw_code == KC_PING_CMD)
    {
      data = scamper_do_ping_alloc(words, word_count, &error_msg);
      if(data == NULL)
        {
	  resp_msg = create_error_response(words[0].cw_uint, error_msg);
	  send_response(source, resp_msg);
	  return -1;
	}
    }
  else
    {
      resp_msg = create_error_response(words[0].cw_uint, "invalid command");
      send_response(source, resp_msg);
      return -1;
    }

  if((cmd = malloc_zero(sizeof(command_t))) == NULL)
    {
      goto err;
    }
  cmd->data  = data;

  if(slist_tail_push(source->commands, cmd) == NULL)
    {
      goto err;
    }

  source_active_attach(source);
  return 0;

 err:
  if(cmd != NULL) free(cmd);
  return -1;
}

/*
 * scamper_source_taskdone
 *
 * when a task completes, this function is called.  it allows the source
 * to keep track of which tasks came from it.
 */
void scamper_source_taskdone(scamper_source_t *source, scamper_task_t *task)
{
  dlist_node_t *node = task->source_task;

  dlist_node_pop(source->tasks, node);
  task->source_task = NULL;
  scamper_source_free(source);
  task->source = NULL;

  if(scamper_source_isfinished(source) != 0)
    {
      source_detach(source);
    }

  return;
}

/*
 * scamper_source_use
 *
 */
scamper_source_t *scamper_source_use(scamper_source_t *source)
{
  source->refcnt++;
  return source;
}

/*
 * scamper_source_abandon
 *
 */
void scamper_source_abandon(scamper_source_t *source)
{
  source_flush_tasks(source);
  source_flush_commands(source);
  source_detach(source);
  return;
}

/*
 * scamper_source_free
 *
 * the caller is giving up their reference to the source.  make a note
 * of that.  when the reference count reaches zero and the source is
 * finished, free it.
 */
void scamper_source_free(scamper_source_t *source)
{
  /*
   * if there are still references held to the source, or the source is not
   * finished yet, then we don't have to go further.
   */
  if(source_refcnt_dec(source) != 0)
    {
      return;
    }

  source_free(source);
  return;
}

/*
 * scamper_source_alloc
 *
 * create a new source based on the parameters supplied.  the source is
 * not put into rotation -- the caller has to call scamper_sources_add
 * for that to occur.
 */
scamper_source_t *scamper_source_alloc(void (*signalmore)(void *),
				       client_t *client)
{
  scamper_source_t *source = NULL;

  /* make sure the caller passes some details of the source to be created */
  if(signalmore == NULL || client == NULL)
    {
      scamper_debug(__func__, "missing necessary parameters");
      goto err;
    }

  if((source = malloc_zero(sizeof(scamper_source_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc source");
      goto err;
    }

  source->priority = 1;
  source->refcnt = 1;
  source->isfinished = 0;

  /* data parameter and associated callbacks */
  source->signalmore  = signalmore;
  source->client       = client;

  if((source->commands = slist_alloc()) == NULL)
    {
      printerror(errno,strerror,__func__, "could not alloc source->commands");
      goto err;
    }

  if((source->onhold = dlist_alloc()) == NULL)
    {
      printerror(errno,strerror,__func__, "could not alloc source->onhold");
      goto err;
    }

  if((source->tasks = dlist_alloc()) == NULL)
    {
      printerror(errno,strerror,__func__, "could not alloc source->tasks");
      goto err;
    }

  return source;

 err:
  if(source != NULL)
    {
      if(source->commands != NULL) slist_free(source->commands);
      if(source->onhold != NULL) dlist_free(source->onhold);
      if(source->tasks != NULL) dlist_free(source->tasks);
      free(source);
    }
  return NULL;
}

/*
 * scamper_sources_del
 *
 * given a source, remove it entirely.  to do so, existing tasks must be
 * halted, the source must be flushed of on-hold tasks and commands,
 * and it must be removed from the data structures that link the source
 * to the main scamper loop.
 */
int scamper_sources_del(scamper_source_t *source)
{
  source_flush_tasks(source);
  source_flush_commands(source);
  source_detach(source);

  /* if there are external references to the source, then don't free it */
  if(source->refcnt > 1)
    {
      return -1;
    }

  source_free(source);
  return 0;
}

/*
 * scamper_sources_isempty
 *
 * return to the caller if it is likely that the sources have more tasks
 * to return
 */
int scamper_sources_isempty()
{
  /*
   * if there are either active or blocked address list sources, the list
   * can't be empty
   */
  if((active   != NULL && clist_count(active)   > 0) ||
     (blocked  != NULL && dlist_count(blocked)  > 0) ||
     (finished != NULL && dlist_count(finished) > 0))
    {
      return 0;
    }

  return 1;
}

/*
 * scamper_sources_isready
 *
 * return to the caller if a source is ready to return a new task.
 */
int scamper_sources_isready(void)
{
  if(source_cur != NULL || dlist_count(finished) > 0)
    {
      return 1;
    }

  return 0;
}

/*
 * scamper_sources_empty
 *
 * flush all sources of commands; disconnect all sources.
 */
void scamper_sources_empty()
{
  scamper_source_t *source;

  /*
   * for each source, go through and empty the lists, close the files, and
   * leave the list of sources available to read from empty.
   */
  while((source = dlist_tail_get(blocked)) != NULL)
    {
      source_flush_commands(source);
      source_detach(source);
    }

  while((source = clist_tail_get(active)) != NULL)
    {
      source_flush_commands(source);
      source_detach(source);
    }

  while((source = dlist_head_get(finished)) != NULL)
    {
      source_detach(source);
    }

  return;
}

/*
 * scamper_sources_gettask
 *
 * pick off the next task ready to be probed.
 */
int scamper_sources_gettask(scamper_task_t **task)
{
  scamper_source_t *source;
  command_t *command;

  while((source = dlist_head_get(finished)) != NULL)
    {
      source_detach(source);
    }

  /*
   * if the priority of the source was changed in between calls to this
   * function, then make sure the source's priority hasn't been lowered to
   * below how many tasks it has had allocated in this cycle
   */
  if(source_cur != NULL && source_cnt >= source_cur->priority)
    {
      source_next();
    }

  while((source = source_cur) != NULL)
    {
      assert(source->priority > 0);

      while((command = slist_head_pop(source->commands)) != NULL)
	{
	  if(scamper_source_getcommandcount(source) == 0
	     && source->isfinished == 0)
	    {
	      source->signalmore(source->client);
	    }

	  if(command_probe_handle(source, command, task) != 0)
	    {
	      return -1;
	    }
	  if(*task == NULL)
	    {
	      continue;
	    }
	  return 0;
	}

      /* the previous source could not supply a command */
      assert(slist_count(source->commands) == 0);

      /*
       * if the source is not yet finished, put it on the blocked list;
       * otherwise, the source is detached.
       */
      if(scamper_source_isfinished(source) == 0)
	{
	  source_blocked_attach(source);
	}
      else
	{
	  source_detach(source);
	}
    }

  *task = NULL;
  return 0;
}

/*
 * scamper_sources_add
 *
 * add a new source into rotation; put it into the active list for now.
 */
int scamper_sources_add(scamper_source_t *source)
{
  /* put the source in the active queue */
  if(source_active_attach(source) != 0)
    {
      return -1;
    }

  return 0;
}

/*
 * scamper_sources_init
 *
 *
 */
int scamper_sources_init(void)
{
  if((active = clist_alloc()) == NULL)
    {
      return -1;
    }

  if((blocked = dlist_alloc()) == NULL)
    {
      return -1;
    }

  if((finished = dlist_alloc()) == NULL)
    {
      return -1;
    }

  return 0;
}

/*
 * scamper_sources_cleanup
 *
 *
 */
void scamper_sources_cleanup(void)
{
  int f, b, a;

  f = finished != NULL ? dlist_count(finished) : 0;
  b = blocked  != NULL ? dlist_count(blocked)  : 0;
  a = active   != NULL ? clist_count(active)   : 0;

  if(f != 0 || b != 0 || a != 0)
    scamper_debug(__func__, "finished %d, blocked %d, active %d", f, b, a);

  if(blocked != NULL)
    {
      dlist_free(blocked);
      blocked = NULL;
    }

  if(active != NULL)
    {
      clist_free(active);
      active = NULL;
    }

  if(finished != NULL)
    {
      dlist_free(finished);
      finished = NULL;
    }

  return;
}


/* ======================================================================== */

/*
 * scamper_source_control_finish
 *
 * the control socket has finished supplying commands, so make a note of
 * that for the next time the sources code cares to look.
 */
void scamper_source_control_finish(scamper_source_t *source)
{
  if(source->isfinished != 0)
    return;

  source->isfinished = 1;
  if(scamper_source_isfinished(source) != 0)
    {
      source_finished_attach(source);
    }

  return;
}
