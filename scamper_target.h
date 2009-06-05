/*
 * scamper_target.h
 *
 * $Id: scamper_target.h,v 1.6 2008/05/25 06:59:18 mjl Exp $
 *
 * Copyright (C) 2005-2008 The University of Waikato
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

#ifndef __SCAMPER_TARGET_H
#define __SCAMPER_TARGET_H

typedef struct scamper_targetset scamper_targetset_t;

scamper_targetset_t *scamper_targetset_alloc(scamper_task_t *task);

void scamper_targetset_free(scamper_targetset_t *targetset);

scamper_task_t *scamper_target_find(struct scamper_addr *addr);

int scamper_targets_init(void);
void scamper_targets_cleanup(void);

#endif /* __SCAMPER_TARGET_H */
