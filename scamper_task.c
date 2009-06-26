/*
 * scamper_task.c
 *
 * $Id: scamper_task.c,v 1.27 2009/02/28 09:06:14 mjl Exp $
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
#include <ws2tcpip.h>
#endif

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_icmp_resp.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_target.h"
#include "scamper_sources.h"
#include "scamper_debug.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct task_onhold
{
  void          (*unhold)(void *param);
  void           *param;
} task_onhold_t;

void *scamper_task_onhold(scamper_task_t *task, void *param,
			  void (*unhold)(void *param))
{
  task_onhold_t *toh;
  dlist_node_t *cookie;

  if(task->internal == NULL && (task->internal = dlist_alloc()) == NULL)
    {
      return NULL;
    }

  if((toh = malloc(sizeof(task_onhold_t))) == NULL)
    {
      return NULL;
    }

  if((cookie = dlist_tail_push(task->internal, toh)) == NULL)
    {
      free(toh);
      return NULL;
    }

  toh->param = param;
  toh->unhold = unhold;

  return cookie;
}

int scamper_task_dehold(scamper_task_t *task, void *cookie)
{
  task_onhold_t *toh;

  assert(task->internal != NULL);

  if((toh = dlist_node_pop(task->internal, cookie)) == NULL)
    {
      return -1;
    }

  free(toh);
  return 0;
}

/*
 * scamper_task_alloc
 *
 * allocate and initialise a task object.
 */
scamper_task_t *scamper_task_alloc(void *data, scamper_task_funcs_t *funcs)
{
  scamper_task_t *task;

  assert(data  != NULL);
  assert(funcs != NULL);

  if((task = malloc_zero(sizeof(scamper_task_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc task");
      goto err;
    }
  task->funcs = funcs;
  task->data  = data;

  if(scamper_queue_alloc(task) == -1)
    {
      goto err;
    }

  return task;

 err:
  if(task->queue != NULL) scamper_queue_free(task->queue);
  free(task);
  return NULL;
}

/*
 * scamper_task_free
 *
 * free a task structure.
 * this involves freeing the task using the free pointer provided,
 * freeing the queue data structure, unholding any tasks blocked, and
 * finally freeing the task structure itself.
 */
void scamper_task_free(scamper_task_t *task)
{
  task_onhold_t *toh;

  task->funcs->task_free(task);
  scamper_queue_free(task->queue);

  if(task->internal != NULL)
    {
      while((toh = dlist_head_pop(task->internal)) != NULL)
	{
	  toh->unhold(toh->param);
	  free(toh);
	}
      dlist_free(task->internal);
    }

  if(task->targetset != NULL)
    {
      scamper_targetset_free(task->targetset);
    }

  if(task->source_task != NULL)
    {
      scamper_source_taskdone(task->source, task);
    }
  else if(task->source != NULL)
    {
      scamper_source_free(task->source);
    }

  free(task);
  return;
}
