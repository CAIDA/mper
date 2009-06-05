/*
 * scamper_cyclemon: monitor active use of cycle structures so we know when
 *                   to write a cycle-stop record.
 *
 * $Id: scamper_cyclemon.c,v 1.16 2009/02/27 07:04:41 mjl Exp $
 *
 * Copyright (C) 2006-2009 The University of Waikato
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

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
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

#include "scamper_list.h"
#include "scamper_outfiles.h"
#include "scamper_task.h"
#include "scamper_sources.h"
#include "scamper_cyclemon.h"
#include "utils.h"

struct scamper_cyclemon
{
  struct scamper_cycle      *cycle;
  scamper_cyclemon_finish_t  finish;
  scamper_source_t          *source;
  scamper_outfile_t         *outfile;
  int                        refcnt;
};

scamper_cycle_t *scamper_cyclemon_cycle(const scamper_cyclemon_t *cyclemon)
{
  if(cyclemon != NULL)
    {
      return cyclemon->cycle;
    }
  return NULL;
}

void scamper_cyclemon_source_detach(scamper_cyclemon_t *cyclemon)
{
  cyclemon->source = NULL;
  return;
}

/*
 * scamper_cyclemon_free
 *
 */
void scamper_cyclemon_free(scamper_cyclemon_t *cyclemon)
{
  if(cyclemon == NULL)
    {
      return;
    }

  if(cyclemon->cycle != NULL)
    {
      scamper_cycle_free(cyclemon->cycle);
    }

  if(cyclemon->outfile != NULL)
    {
      scamper_outfile_free(cyclemon->outfile);
    }

  free(cyclemon);
  return;
}

void scamper_cyclemon_unuse(scamper_cyclemon_t *cyclemon)
{
  if(cyclemon == NULL)
    {
      return;
    }

  cyclemon->refcnt--;

  /*
   * if there are still others with a pointer to the cycle monitor, then
   * don't finish the cycle off
   */
  if(cyclemon->refcnt > 0)
    {
      return;
    }

  cyclemon->finish(cyclemon->cycle, cyclemon->source, cyclemon->outfile);

  scamper_cyclemon_free(cyclemon);
  return;
}

scamper_cyclemon_t *scamper_cyclemon_use(scamper_cyclemon_t *cyclemon)
{
  if(cyclemon != NULL) cyclemon->refcnt++;
  return cyclemon;
}

int scamper_cyclemon_refcnt(scamper_cyclemon_t *cyclemon)
{
  return cyclemon->refcnt;
}

scamper_cyclemon_t *scamper_cyclemon_alloc(scamper_cycle_t *cycle,
					   scamper_cyclemon_finish_t finish,
					   scamper_source_t *source,
					   scamper_outfile_t *outfile)
{
  scamper_cyclemon_t *cyclemon;

  if((cyclemon = malloc_zero(sizeof(scamper_cyclemon_t))) != NULL)
    {
      cyclemon->cycle   = scamper_cycle_use(cycle);
      cyclemon->outfile = scamper_outfile_use(outfile);
      cyclemon->finish  = finish;
      cyclemon->source  = source;
      cyclemon->refcnt  = 1;
    }

  return cyclemon;
}
