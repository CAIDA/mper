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

/* functions for allocating, referencing, and dereferencing scamper sources */
scamper_source_t *scamper_source_alloc(void (*signalmore)(void *), void *param);
scamper_source_t *scamper_source_use(scamper_source_t *source);
void scamper_source_free(scamper_source_t *source);
void scamper_source_abandon(scamper_source_t *source);

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
int scamper_sources_isready(void);
int scamper_sources_isempty(void);
void scamper_sources_empty(void);
int scamper_sources_init(void);
void scamper_sources_cleanup(void);
void scamper_source_control_finish(scamper_source_t *source);

#endif /* __SCAMPER_SOURCE_H */
