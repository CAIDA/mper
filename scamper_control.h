/*
 * scamper_control.h
 *
 * $Id: scamper_control.h,v 1.6 2008/03/11 00:31:57 mjl Exp $
 *
 * Copyright (C) 2004-2007 The University of Waikato
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

#ifndef __SCAMPER_CONTROL_H
#define __SCAMPER_CONTROL_H

int scamper_control_init(int port, int use_tcp);
void scamper_control_cleanup(void);

typedef struct scamper_source scamper_source_t;

void scamper_source_free(scamper_source_t *source);

/* function for advising source that an active task has completed */
void scamper_source_taskdone(scamper_source_t *source,scamper_task_t *task);

/* functions for managing a collection of sources */
int scamper_sources_gettask(scamper_task_t **task);
int scamper_sources_init(void);
void scamper_sources_cleanup(void);
int scamper_sources_isready(void);
int scamper_sources_isempty(void);

#endif
