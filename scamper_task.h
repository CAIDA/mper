/*
 * scamper_task.h
 *
 * $Id: scamper_task.h,v 1.24 2008/12/03 21:45:34 mjl Exp $
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

#ifndef __SCAMPER_TASK_H
#define __SCAMPER_TASK_H

struct scamper_addr;
struct scamper_queue;
struct scamper_task;
struct scamper_dl_rec;
struct scamper_rt_rec;
struct scamper_icmp_resp;
struct scamper_targetset;

typedef struct scamper_task_funcs
{
  /* probe the destination */
  void (*probe)(struct scamper_task *task);

  /* handle some ICMP packet */
  void (*handle_icmp)(struct scamper_task *task,
		      struct scamper_icmp_resp *icmp);

  /* handle some information from the datalink */
  void (*handle_dl)(struct scamper_task *task, struct scamper_dl_rec *dl_rec);

  /* handle some message from the route socket */
  void (*handle_rt)(struct scamper_task *task, struct scamper_rt_rec *rt_rec);

  /* handle the task timing out on the wait queue */
  void (*handle_timeout)(struct scamper_task *task);

  /* write the task's data object out */
  void (*write)(struct scamper_task *task);

  /* free the task's data and state */
  void (*task_free)(struct scamper_task *task);

  /* call the supplied callback for each destination address */
  int  (*task_addrs)(void *data, void *param,
		     int (*foreach)(struct scamper_addr *, void *));

} scamper_task_funcs_t;

typedef struct scamper_task
{
  /* the data pointer points to the collected data */
  void                     *data;

  /* any state kept during the data collection is kept here */
  void                     *state;

  /* state / details kept internally to the task */
  void                     *internal;

  /* various callbacks that scamper uses to handle this task */
  scamper_task_funcs_t     *funcs;

  /* pointer to a queue structure that manages this task in the queues */
  struct scamper_queue     *queue;

  /* pointer to where the task came from */
  struct scamper_source    *source;
  void                     *source_task;

  /* pointer to a targetset structure, if used */
  struct scamper_targetset *targetset;

} scamper_task_t;

scamper_task_t *scamper_task_alloc(void *data, scamper_task_funcs_t *funcs);

void scamper_task_free(scamper_task_t *task);

/*
 * scamper_task_onhold
 *
 * given a task that another is blocked on, register the fact.
 * when the task is free'd, the unhold function will be called.
 *
 * returns a cookie, so the dehold function can cancel the task
 * from  being on hold at a later point.
 */
void *scamper_task_onhold(scamper_task_t *task, void *param,
			  void (*unhold)(void *param));

/*
 * scamper_task_dehold
 *
 * given a task and a cookie returned from putting another task on hold,
 * de-hold the task with this cookie.
 */
int scamper_task_dehold(scamper_task_t *task, void *cookie);

#endif /* __SCAMPER_TASK_H */
