/*
 * scamper_source_control.c
 *
 * $Id: scamper_source_control.c,v 1.9 2009/05/26 22:13:09 mjl Exp $
 *
 * Copyright (C) 2007-2009 The University of Waikato
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
#define __func__ __FUNCTION__
#endif

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include <assert.h>

#include "scamper_task.h"
#include "scamper_sources.h"
#include "scamper_debug.h"
#include "scamper_source_control.h"
#include "utils.h"

typedef struct scamper_source_control
{
  /* back-pointer to the parent source */
  scamper_source_t  *source;

  /* variable that indicates if no more commands are coming */
  int                isfinished;

  /* a function and a parameter to interact with the control socket */
  void             (*signalmore)(void *param);
  void              *param;
 
} scamper_source_control_t;

/*
 * ssc_take
 *
 * a task has been taken from this source (a control socket).  if there
 * are no tasks left then signal to the 
 */
static int ssc_take(void *data)
{
  scamper_source_control_t *ssc = (scamper_source_control_t *)data;
  if(scamper_source_getcommandcount(ssc->source) == 0 && ssc->isfinished == 0)
    {
      ssc->signalmore(ssc->param);
    }
  return 0;
}

static void ssc_freedata(void *data)
{
  free(data);
  return;
}

static int ssc_isfinished(void *data)
{
  return ((scamper_source_control_t *)data)->isfinished;
}

/*
 * scamper_source_control_finish
 *
 * the control socket has finished supplying commands, so make a note of
 * that for the next time the sources code cares to look.
 */
void scamper_source_control_finish(scamper_source_t *source)
{
  scamper_source_control_t *ssc;

  assert(scamper_source_gettype(source) == SCAMPER_SOURCE_TYPE_CONTROL);
  ssc = (scamper_source_control_t *)scamper_source_getdata(source);
  assert(ssc != NULL);

  if(ssc->isfinished != 0)
    return;

  ssc->isfinished = 1;
  if(scamper_source_isfinished(source) != 0)
    {
      scamper_source_finished(source);
    }

  return;
}

/*
 * scamper_source_control_alloc
 *
 * allocate a new source that is setup to interact with a control socket
 * connection that supplies commands.  the control socket is regulated
 * (on / off) by using the acceptready callback provided.
 */
scamper_source_t *scamper_source_control_alloc(scamper_source_params_t *ssp,
					       void (*signalmore)(void *),
					       void *param)
{
  scamper_source_control_t *ssc = NULL;
  scamper_source_t *source = NULL;

  if(ssp == NULL || signalmore == NULL || param == NULL)
    {
      goto err;
    }

  /* allocate state to keep with the particular control socket */
  if((ssc = malloc_zero(sizeof(scamper_source_control_t))) == NULL)
    {
      goto err;
    }
  ssc->signalmore  = signalmore;
  ssc->param       = param;

  /* append parameters to the source parameters struct */
  ssp->data        = ssc;
  ssp->take        = ssc_take;
  ssp->freedata    = ssc_freedata;
  ssp->isfinished  = ssc_isfinished;
  ssp->type        = SCAMPER_SOURCE_TYPE_CONTROL;

  if((source = scamper_source_alloc(ssp)) == NULL)
    {
      goto err;
    }
  ssc->source = source;

  return source;

 err:
  if(ssc != NULL) free(ssc);
  if(source != NULL) scamper_source_free(source);
  return NULL;
}
