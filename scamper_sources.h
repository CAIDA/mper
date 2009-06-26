/*
 * scamper_source
 *
 * $Id: scamper_sources.h,v 1.7 2008/09/11 23:06:09 mjl Exp $
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

#ifndef __SCAMPER_SOURCE_H
#define __SCAMPER_SOURCE_H

typedef struct scamper_source scamper_source_t;

#define SCAMPER_SOURCE_TYPE_CONTROL 3

typedef struct scamper_source_params
{
  /*
   *  type:     type of the source (control socket)
   *  priority: the mix priority of this source compared to other sources.
   *  sof:      the output file to direct results to.
   */
  int                type;
  uint32_t           priority;
  /* scamper_outfile_t *sof; */

  /*
   * these parameters are set by the scamper_source_*_alloc function
   */
  void              *data;
  int              (*take)(void *data);
  void             (*freedata)(void *data);
  int              (*isfinished)(void *data);

} scamper_source_params_t;

/* functions for allocating, referencing, and dereferencing scamper sources */
scamper_source_t *scamper_source_alloc(const scamper_source_params_t *ssp);
scamper_source_t *scamper_source_use(scamper_source_t *source);
void scamper_source_free(scamper_source_t *source);
void scamper_source_abandon(scamper_source_t *source);

/* take a finished source and put it in a special place */
void scamper_source_finished(scamper_source_t *source);

/* functions for getting various source properties */
int scamper_source_gettype(const scamper_source_t *source);
uint32_t scamper_source_getpriority(const scamper_source_t *source);
void scamper_source_setpriority(scamper_source_t *source, uint32_t priority);

/* functions for getting string representations */
const char *scamper_source_type_tostr(const scamper_source_t *source);

/* functions for dealing with source-type specific data */
void *scamper_source_getdata(const scamper_source_t *source);
void scamper_source_setdata(scamper_source_t *source, void *data);

/* functions for getting the number of commands/cycles currently buffered */
int scamper_source_getcommandcount(const scamper_source_t *source);
int scamper_source_gettaskcount(const scamper_source_t *source);

/* determine if the source has finished yet */
int scamper_source_isfinished(scamper_source_t *source);

/* functions for adding stuff to the source's command queue */
int scamper_source_command(scamper_source_t *source, const char *command);

/* function for advising source that an active task has completed */
void scamper_source_taskdone(scamper_source_t *source,scamper_task_t *task);

/* functions for managing a collection of sources */
int scamper_sources_add(scamper_source_t *source);
int scamper_sources_gettask(scamper_task_t **task);
int scamper_sources_del(scamper_source_t *source);
scamper_source_t *scamper_sources_get(char *name);
int scamper_sources_isready(void);
int scamper_sources_isempty(void);
/* void scamper_sources_foreach(void *p, int (*func)(void *, scamper_source_t *)); */
void scamper_sources_empty(void);
int scamper_sources_init(void);
void scamper_sources_cleanup(void);

#endif /* __SCAMPER_SOURCE_H */
