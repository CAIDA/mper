/*
 * scamper_source
 *
 * $Id: scamper_sources.c,v 1.28 2009/03/16 03:00:26 mjl Exp $
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

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef __int16 int16_t;
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32
#include <winsock2.h>
#define MAXHOSTNAMELEN 256
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define strdup _strdup
#endif

#ifndef _WIN32
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_task.h"
#include "scamper_target.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_cyclemon.h"

#include "scamper_do_trace.h"
#include "scamper_do_ping.h"
#include "scamper_do_tracelb.h"
#include "scamper_do_dealias.h"
#include "scamper_do_sting.h"

#include "scamper_debug.h"

#include "utils.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"

/*
 * scamper_source
 *
 * this structure maintains state regarding tasks that come from a particular
 * source.  some of the state is stored in scamper_list_t and scamper_cycle_t
 * structures with the resulting data object.
 *
 */
struct scamper_source
{
  /* basic data collection properties to store with the source */
  scamper_list_t               *list;
  scamper_cycle_t              *cycle;

  /* properties of the source */
  uint32_t                      priority;
  int                           type;
  int                           refcnt;
  scamper_outfile_t            *sof;
  scamper_cyclemon_t           *cyclemon;

  /*
   * commands:     a list of commands for the source that are queued, ready to
   *               be passed out as tasks
   * cycle_points: the number of cycle points in the commands list
   * onhold:       a list of commands that are on hold.
   * tasks:        a list of tasks currently active from the source.
   */
  slist_t                      *commands;
  int                           cycle_points;
  dlist_t                      *onhold;
  dlist_t                      *tasks;

  /*
   * nodes to keep track of whether the source is in the active or blocked
   * lists, and a node to keep track of the source in a splaytree
   */
  void                         *list_;
  void                         *list_node;
  splaytree_node_t             *tree_node;

  /* data and callback functions specific to the type of source this is */
  void                         *data;
  int                         (*take)(void *data);
  void                        (*freedata)(void *data);
  int                         (*isfinished)(void *data);
};

/*
 * scamper_source_observer
 *
 * this structure records details of an observer interested in monitoring
 * source events.
 *
 *  func:  the callback function to use when an event occurs
 *  param: the parameter to pass to the function
 *  node:  the appropriate dlist_node in the observers dlist.
 */
struct scamper_source_observer
{
  scamper_source_eventf_t  func;
  void                    *param;
  dlist_node_t            *node;
};

/*
 * command_funcs
 *
 * a utility struct to save passing loads of functions around individually
 * that are necessary to start a probe command.
 */
typedef struct command_func
{
  char             *command;
  size_t            len;
  void           *(*allocdata)(char *);
  scamper_task_t *(*alloctask)(void *, scamper_list_t *, scamper_cycle_t *);
  void            (*freedata)(void *data);
  int             (*dstaddrs)(void *data, void *param,
			      int (*foreach)(struct scamper_addr *, void *));
} command_func_t;

static const command_func_t command_funcs[] = {
  {
    "trace", 5,
    scamper_do_trace_alloc,
    scamper_do_trace_alloctask,
    scamper_do_trace_free,
    scamper_do_trace_dstaddr,
  },
  {
    "ping", 4,
    scamper_do_ping_alloc,
    scamper_do_ping_alloctask,
    scamper_do_ping_free,
    scamper_do_ping_dstaddr,
  },
  {
    "tracelb", 7,
    scamper_do_tracelb_alloc,
    scamper_do_tracelb_alloctask,
    scamper_do_tracelb_free,
    scamper_do_tracelb_dstaddr,
  },
  {
    "dealias", 7,
    scamper_do_dealias_alloc,
    scamper_do_dealias_alloctask,
    scamper_do_dealias_free,
    scamper_do_dealias_dstaddrs,
  },
  {
    "sting", 5,
    scamper_do_sting_alloc,
    scamper_do_sting_alloctask,
    scamper_do_sting_free,
    scamper_do_sting_dstaddr,
  },
};

static size_t command_funcc = sizeof(command_funcs) / sizeof(command_func_t);

/*
 * command
 *
 *  type:  COMMAND_PROBE or COMMAND_CYCLE
 *  funcs: pointer to appropriate command_func_t
 *  data:  pointer to data allocated for task
 *  param: additional parameters specific to the command's type.
 */
typedef struct command
{
  const command_func_t *funcs;
  uint8_t               type;
  void                 *data;
  void                 *param;
} command_t;

#define COMMAND_PROBE 0x00
#define COMMAND_CYCLE 0x01

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
 *
 * the sources are stored in a tree that is searchable by name.
 */
static clist_t          *active      = NULL;
static dlist_t          *blocked     = NULL;
static dlist_t          *finished    = NULL;
static scamper_source_t *source_cur  = NULL;
static uint32_t          source_cnt  = 0;
static splaytree_t      *source_tree = NULL;
static dlist_t          *observers   = NULL;

/* forward declare */
static void source_free(scamper_source_t *source);

static int source_refcnt_dec(scamper_source_t *source)
{
  assert(source->refcnt > 0);
  source->refcnt--;
  return source->refcnt;
}

/*
 * source_event_post_cb
 *
 * callback used by source_event_post to send an event to all the observers
 * in the observers list
 */
static int source_event_post_cb(void *item, void *param)
{
  scamper_source_observer_t *observer = (scamper_source_observer_t *)item;
  scamper_source_event_t *event = (scamper_source_event_t *)param;
  observer->func(event, observer->param);
  return 0;
}

/*
 * scamper_source_event_post
 *
 * send all observers notification that a particular event occured.
 */
void scamper_source_event_post(scamper_source_t *source, int type,
			       scamper_source_event_t *ev)
{
  scamper_source_event_t sse;
  struct timeval tv;

  /* check if there is actually anyone observing */
  if(observers == NULL)
    {
      return;
    }

  /* if null event, then create one from scratch */
  if(ev == NULL)
    {
      memset(&sse, 0, sizeof(sse));
      ev = &sse;
    }

  gettimeofday_wrap(&tv);
  ev->source = source;
  ev->event = type;
  ev->sec = tv.tv_sec;
  dlist_foreach(observers, source_event_post_cb, ev);

  return;
}

static void command_free(command_t *command)
{
  if(command->type == COMMAND_PROBE)
    {
      /*
       * the data parameter is either a scamper_trace_t or scamper_ping_t.
       * free it.
       */
      if(command->data != NULL && command->funcs->freedata != NULL)
	{
	  command->funcs->freedata(command->data);
	}

      scamper_cyclemon_unuse((scamper_cyclemon_t *)command->param);
    }

  free(command);
  return;
}

/*
 * command_cycle
 *
 * given the commands list, append a cycle command to it.
 */
static int command_cycle(scamper_source_t *source, scamper_cycle_t *cycle)
{
  command_t *command = NULL;

  if((command = malloc_zero(sizeof(command_t))) == NULL)
    {
      goto err;
    }

  command->type = COMMAND_CYCLE;
  command->data = cycle;

  if(slist_tail_push(source->commands, command) == NULL)
    {
      goto err;
    }

  source->cycle_points++;

  return 0;

 err:
  if(command != NULL) command_free(command);
  return -1;
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

static scamper_task_t *command_dstaddrs(const command_func_t *funcs,void *data)
{
  scamper_task_t *task = NULL;
  if(funcs->dstaddrs(data, &task, command_dstaddrs_foreach) == 0)
    {
      assert(task == NULL);
      return NULL;
    }

  assert(task != NULL);
  return task;
}

/*
 * command_probe_handle
 *
 *
 */
static int command_probe_handle(scamper_source_t *source, command_t *command,
				scamper_task_t **task_out)
{
  const command_func_t *funcs = command->funcs;
  scamper_cycle_t *cycle;
  scamper_task_t *task = NULL;

  if((task = command_dstaddrs(funcs, command->data)) != NULL)
    {
      source_command_onhold(source, task, command);
      *task_out = NULL;
      return 0;      
    }

  /* get a pointer to the cycle for *this* task */
  cycle = scamper_cyclemon_cycle((scamper_cyclemon_t *)command->param);

  /* allocate the task structure to keep everything together */
  if((task = funcs->alloctask(command->data, source->list, cycle)) == NULL)
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

  /* pass the cyclemon structure to the task */
  task->cyclemon = scamper_cyclemon_use((scamper_cyclemon_t *)command->param);

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
 * command_cycle_handle
 *
 *
 */
static int command_cycle_handle(scamper_source_t *source, command_t *command)
{
  scamper_source_event_t sse;
  scamper_cycle_t *cycle = (scamper_cycle_t *)command->data;
  scamper_file_t *file;
  struct timeval tv;
  char hostname[MAXHOSTNAMELEN];

  /* get the hostname of the system for the cycle point */
  if(gethostname(hostname, sizeof(hostname)) == 0)
    {
      cycle->hostname = strdup(hostname);
    }

  /* get a timestamp for the cycle start point */
  gettimeofday_wrap(&tv);
  cycle->start_time = (uint32_t)tv.tv_sec;

  /* write a cycle start point to disk if there is a file to do so */
  if(source->sof != NULL &&
     (file = scamper_outfile_getfile(source->sof)) != NULL)
    {
      scamper_file_write_cycle_start(file, cycle);
    }

  /* post an event saying the cycle point just rolled around */
  memset(&sse, 0, sizeof(sse));
  sse.sse_cycle_cycle_id = cycle->id;
  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_CYCLE, &sse);

  command_free(command);
  return 0;
}

/*
 * source_cycle_finish
 *
 * when the last cycle is written to disk, we can start on the next cycle.
 */
static void source_cycle_finish(scamper_cycle_t *cycle,
				scamper_source_t *source,
				scamper_outfile_t *outfile)
{
  scamper_file_t *sf;
  struct timeval tv;

  /* timestamp when the cycle ends */
  gettimeofday_wrap(&tv);
  cycle->stop_time = (uint32_t)tv.tv_sec;

  /* write the cycle stop record out */
  if(outfile != NULL)
    {
      sf = scamper_outfile_getfile(outfile);
      scamper_file_write_cycle_stop(sf, cycle);
    }

  if(source != NULL)
    {
      source->cycle_points--;
    }

  return;
}

/*
 * source_cycle
 *
 * allocate and initialise a cycle start object for the source.
 * write the cycle start to disk.
 */
static int source_cycle(scamper_source_t *source, uint32_t cycle_id)
{
  scamper_cyclemon_t *cyclemon = NULL;
  scamper_cycle_t *cycle = NULL;

  /* allocate the new cycle object */
  if((cycle = scamper_cycle_alloc(source->list)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc new cycle");
      goto err;
    }

  /* assign the cycle id */
  cycle->id = cycle_id;

  /* allocate structure to monitor references to the new cycle */
  if((cyclemon = scamper_cyclemon_alloc(cycle, source_cycle_finish, source,
					source->sof)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc new cyclemon");
      goto err;
    }

  /* append the cycle record to the source's commands list */
  if(command_cycle(source, cycle) != 0)
    {
      printerror(errno, strerror, __func__, "could not insert cycle marker");
      goto err;
    }

  /*
   * if there is a previous cycle object associated with the source, then
   * free that.  also free the cyclemon.
   */
  if(source->cycle != NULL)
    {
      scamper_cycle_free(source->cycle);
    }
  if(source->cyclemon != NULL)
    {
      scamper_cyclemon_unuse(source->cyclemon);
    }

  /* store the cycle and we're done */
  source->cycle = cycle;
  source->cyclemon = cyclemon;
  return 0;

 err:
  if(cyclemon != NULL) scamper_cyclemon_free(cyclemon);
  if(cycle != NULL) scamper_cycle_free(cycle);
  return -1;
}

static int source_cmp(const void *a, const void *b)
{
  return strcasecmp(((const scamper_source_t *)b)->list->name,
		    ((const scamper_source_t *)a)->list->name);
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

  if(source->data != NULL)
    {
      source->freedata(source->data);
    }

  source->data        = NULL;
  source->take        = NULL;
  source->freedata    = NULL;
  source->isfinished  = NULL;

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

  /* remove the source from the tree */
  if(source->tree_node != NULL)
    {
      splaytree_remove_node(source_tree, source->tree_node);
      source->tree_node = NULL;

      /* decrement the reference count held for the source */
      if(source_refcnt_dec(source) == 0)
	{
	  source_free(source);
	}
    }

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
   * the callback checks with the source-type specific code to see if there
   * are commands to come.
   */
  if(source->isfinished != NULL && source->isfinished(source->data) == 0)
    {
      return 0;
    }

  return 1;
}

/*
 * scamper_source_finished
 *
 * when a source is known to be finished (say a control socket that will no
 * longer be supplying tasks)
 */
void scamper_source_finished(scamper_source_t *source)
{
  assert(scamper_source_isfinished(source) != 0);
  if(source->cyclemon != NULL)
    {
      assert(scamper_cyclemon_refcnt(source->cyclemon) == 1);
      scamper_cyclemon_unuse(source->cyclemon);
      source->cyclemon = NULL;
    }
  source_finished_attach(source);
  return;
}

/*
 * source_free
 *
 * clean up the source
 */
static void source_free(scamper_source_t *source)
{
  assert(source->refcnt == 0);

  /* the source is now finished.  post a message saying so */
  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_FINISH, NULL);

  if(source->cyclemon != NULL)
    {
      scamper_cyclemon_source_detach(source->cyclemon);
      scamper_cyclemon_unuse(source->cyclemon);
      source->cyclemon = NULL;
    }

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

  /* release this structure's hold on the scamper_outfile */
  if(source->sof != NULL) scamper_outfile_free(source->sof);

  if(source->list != NULL) scamper_list_free(source->list);
  if(source->cycle != NULL) scamper_cycle_free(source->cycle);

  free(source);
  return;
}

/*
 * scamper_source_getname
 *
 * return the name of the source
 */
const char *scamper_source_getname(const scamper_source_t *source)
{
  if(source->list == NULL) return NULL;
  return source->list->name;
}

/*
 * scamper_source_getdescr
 *
 * return the description for the source
 */
const char *scamper_source_getdescr(const scamper_source_t *source)
{
  if(source->list == NULL) return NULL;
  return source->list->descr;
}

/*
 * scamper_source_getoutfile
 *
 * return the name of the outfile associated with the source
 */
const char *scamper_source_getoutfile(const scamper_source_t *source)
{
  return scamper_outfile_getname(source->sof);
}

/*
 * scamper_source_getlistid
 *
 * return the list id for the source
 */
uint32_t scamper_source_getlistid(const scamper_source_t *source)
{
  return source->list->id;
}

/*
 * scamper_source_getcycleid
 *
 * return the cycle id for the source
 */
uint32_t scamper_source_getcycleid(const scamper_source_t *source)
{
  return source->cycle->id;
}

/*
 * scamper_source_getpriority
 *
 * return the priority value for the source
 */
uint32_t scamper_source_getpriority(const scamper_source_t *source)
{
  return source->priority;
}

void scamper_source_setpriority(scamper_source_t *source, uint32_t priority)
{
  scamper_source_event_t sse;
  uint32_t old_priority;

  old_priority = source->priority;
  source->priority = priority;

  if(priority == 0 && old_priority > 0)
    {
      source_blocked_attach(source);
    }
  else if(priority > 0 && old_priority == 0)
    {
      source_active_attach(source);
    }

  memset(&sse, 0, sizeof(sse));
  sse.sse_update_flags |= 0x04;
  sse.sse_update_priority = priority;
  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_UPDATE, &sse);

  return;
}

const char *scamper_source_type_tostr(const scamper_source_t *source)
{
  switch(source->type)
    {
    case SCAMPER_SOURCE_TYPE_FILE:    return "file";
    case SCAMPER_SOURCE_TYPE_CMDLINE: return "cmdline";
    case SCAMPER_SOURCE_TYPE_CONTROL: return "control";
    }

  return NULL;
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

int scamper_source_getcyclecount(const scamper_source_t *source)
{
  return source->cycle_points;
}

int scamper_source_gettaskcount(const scamper_source_t *source)
{
  if(source->tasks != NULL)
    {
      return dlist_count(source->tasks);
    }
  return -1;
}

int scamper_source_gettype(const scamper_source_t *source)
{
  return source->type;
}

void *scamper_source_getdata(const scamper_source_t *source)
{
  return source->data;
}

/*
 * scamper_source_command
 *
 */
int scamper_source_command(scamper_source_t *source, const char *command)
{
  const command_func_t *func = NULL;
  command_t *cmd = NULL;
  char *opts = NULL;
  void *data = NULL;
  size_t i;

  for(i=0; i<command_funcc; i++)
    {
      func = &command_funcs[i];
      if(strncasecmp(command, func->command, func->len) == 0 &&
	 isspace((int)command[func->len]) && command[func->len] != '\0')
	{
	  break;
	}
    }

  if(i == command_funcc)
    {
      return -1;
    }

  /*
   * make a copy of the options, since the next function may modify the
   * contents of it
   */
  if((opts = strdup(command+func->len)) == NULL)
    {
      goto err;
    }

  if((data = func->allocdata(opts)) == NULL)
    {
      goto err;
    }
  free(opts); opts = NULL;

  if((cmd = malloc_zero(sizeof(command_t))) == NULL)
    {
      goto err;
    }
  cmd->type  = COMMAND_PROBE;
  cmd->funcs = func;
  cmd->data  = data;
  cmd->param = scamper_cyclemon_use(source->cyclemon);

  if(slist_tail_push(source->commands, cmd) == NULL)
    {
      goto err;
    }

  source_active_attach(source);
  return 0;

 err:
  if(opts != NULL) free(opts);
  if(data != NULL) func->freedata(data);
  if(cmd != NULL) free(cmd);
  return -1;
}

/*
 * scamper_source_cycle
 *
 * externally visible function to mark a new cycle point; the new cycle
 * id is one greater than the currently active cycle.
 */
int scamper_source_cycle(scamper_source_t *source)
{
  return source_cycle(source, source->cycle->id + 1);
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
      if(source->cyclemon != NULL)
	{
	  assert(scamper_cyclemon_refcnt(source->cyclemon) == 1);
	  scamper_cyclemon_unuse(source->cyclemon);
	  source->cyclemon = NULL;
	}
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
scamper_source_t *scamper_source_alloc(const scamper_source_params_t *ssp)
{
  scamper_source_t *source = NULL;

  /* make sure the caller passes some details of the source to be created */
  if(ssp == NULL || ssp->name == NULL)
    {
      scamper_debug(__func__, "missing necessary parameters");
      goto err;
    }

  if((source = malloc_zero(sizeof(scamper_source_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc source");
      goto err;
    }
  source->refcnt = 1;

  /* data parameter and associated callbacks */
  source->data        = ssp->data;
  source->take        = ssp->take;
  source->freedata    = ssp->freedata;
  source->isfinished  = ssp->isfinished;

  if((source->list = scamper_list_alloc(ssp->list_id, ssp->name, ssp->descr,
					scamper_monitorname_get())) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc source->list");
      goto err;
    }

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

  source->sof = scamper_outfile_use(ssp->sof);
  if(source_cycle(source, ssp->cycle_id) != 0)
    {
      goto err;
    }

  source->type     = ssp->type;
  source->priority = ssp->priority;

  return source;

 err:
  if(source != NULL)
    {
      if(source->list != NULL) scamper_list_free(source->list);
      if(source->cycle != NULL) scamper_cycle_free(source->cycle);
      if(source->commands != NULL) slist_free(source->commands);
      if(source->onhold != NULL) dlist_free(source->onhold);
      if(source->tasks != NULL) dlist_free(source->tasks);
      free(source);
    }
  return NULL;
}

/*
 * scamper_sources_observe
 *
 * something wants to monitor the status of the sources managed by scamper.
 * make a note of that.
 */
scamper_source_observer_t *scamper_sources_observe(scamper_source_eventf_t cb,
						   void *param)
{
  scamper_source_observer_t *observer = NULL;

  if((observers == NULL && (observers = dlist_alloc()) == NULL) ||
     (observer = malloc_zero(sizeof(scamper_source_observer_t))) == NULL ||
     (observer->node = dlist_tail_push(observers, observer)) == NULL)
    {
      goto err;
    }

  observer->func  = cb;
  observer->param = param;

  return observer;

 err:
  if(observer != NULL) scamper_sources_unobserve(observer);
  return NULL;
}

/*
 * scamper_sources_unobserve
 *
 */
void scamper_sources_unobserve(scamper_source_observer_t *observer)
{
  dlist_node_pop(observers, observer->node);
  free(observer);

  if(dlist_count(observers) == 0)
    {
      dlist_free(observers);
      observers = NULL;
    }

  return;
}

/*
 * scamper_sources_get
 *
 * given a name, return the matching source -- if one exists.
 */
scamper_source_t *scamper_sources_get(char *name)
{
  scamper_source_t findme;
  scamper_list_t   list;

  list.name   = name;
  findme.list = &list;

  return (scamper_source_t *)splaytree_find(source_tree, &findme);
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

  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_DELETE, NULL);
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
 * scamper_sources_foreach
 *
 * externally accessible function for iterating over the collection of sources
 * held by scamper.
 */
void scamper_sources_foreach(void *p, int (*func)(void *, scamper_source_t *))
{
  splaytree_inorder(source_tree, (splaytree_inorder_t)func, p);
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
	  if(source->take != NULL)
	    {
	      source->take(source->data);
	    }

	  switch(command->type)
	    {
	    case COMMAND_PROBE:
	      if(command_probe_handle(source, command, task) != 0)
		{
		  return -1;
		}
	      if(*task == NULL)
		{
		  continue;
		}
	      return 0;

	    case COMMAND_CYCLE:
	      command_cycle_handle(source, command);
	      break;

	    default:
	      return -1;
	    }
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
  /* a reference count is used when the source is in the tree */
  if((source->tree_node = splaytree_insert(source_tree, source)) == NULL)
    {
      return -1;
    }
  scamper_source_use(source);

  /* put the source in the active queue */
  if(source_active_attach(source) != 0)
    {
      return -1;
    }

  scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_ADD, NULL);
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

  if((source_tree = splaytree_alloc(source_cmp)) == NULL)
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

  if(source_tree != NULL)
    {
      splaytree_free(source_tree, NULL);
      source_tree = NULL;
    }

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
