/*
 * scamper_target.c
 *
 * $Id: scamper_target.c,v 1.16 2009/02/28 05:39:33 mjl Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_task.h"
#include "scamper_target.h"
#include "scamper_debug.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct target
{
  scamper_addr_t   *addr;
  scamper_task_t   *task;
  splaytree_node_t *node;
} target_t;

struct scamper_targetset
{
  scamper_task_t   *task;
  slist_t          *list;
};

static splaytree_t *tree[SCAMPER_ADDR_TYPE_MAX];

static int target_addr4_cmp(const void *va, const void *vb)
{
  assert(((const target_t *)va)->addr->type == SCAMPER_ADDR_TYPE_IPV4);
  assert(((const target_t *)vb)->addr->type == SCAMPER_ADDR_TYPE_IPV4);
  return addr4_cmp(((const target_t *)va)->addr->addr,
		   ((const target_t *)vb)->addr->addr);
}

static int target_addr6_cmp(const void *va, const void *vb)
{
  assert(((const target_t *)va)->addr->type == SCAMPER_ADDR_TYPE_IPV6);
  assert(((const target_t *)vb)->addr->type == SCAMPER_ADDR_TYPE_IPV6);
  return addr6_cmp(((const target_t *)va)->addr->addr,
		   ((const target_t *)vb)->addr->addr);
}

static target_t *target_alloc(scamper_addr_t *addr, scamper_task_t *task)
{
  target_t *target;

  if((target = malloc_zero(sizeof(target_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc target");
      goto err;
    }

  target->addr = scamper_addr_use(addr);
  target->task = task;
  if((target->node = splaytree_insert(tree[addr->type-1], target)) == NULL)
    {
      scamper_debug(__func__, "could not insert into splaytree");
      goto err;
    }

  return target;

 err:
  if(target != NULL)
    {
      if(target->addr != NULL) scamper_addr_free(target->addr);
      free(target);
    }
  return NULL;
}

static void target_free(target_t *target)
{
  assert(target != NULL);
  assert(target->node != NULL);
  assert(target->addr != NULL);

  if(target->node != NULL)
    splaytree_remove_node(tree[target->addr->type-1], target->node);
  if(target->addr != NULL)
    scamper_addr_free(target->addr);
  free(target);

  return;
}

static target_t *target_find(scamper_addr_t *addr)
{
  target_t key;
  assert(tree[addr->type-1] != NULL);
  key.addr = addr;
  return splaytree_find(tree[addr->type-1], &key);
}

scamper_task_t *scamper_target_find(struct scamper_addr *addr)
{
  target_t *target;

  if((target = target_find(addr)) == NULL)
    return NULL;

  return target->task;
}

static int targetset_addrs(scamper_addr_t *addr, void *param)
{
  scamper_targetset_t *targetset = (scamper_targetset_t *)param;
  target_t *target;

  target = target_find(addr);
  assert(target == NULL || target->task == targetset->task);

  if(target == NULL)
    {
      if((target = target_alloc(addr, targetset->task)) == NULL)
	return -1;

      if(slist_tail_push(targetset->list, target) == NULL)
	{
	  free(target);
	  return -1;
	}
    }

  return 0;
}

void scamper_targetset_free(scamper_targetset_t *targetset)
{
  target_t *target;

  if(targetset->list != NULL)
    {
      while((target = slist_head_pop(targetset->list)) != NULL)
	{
	  target_free(target);
	}
      slist_free(targetset->list);
    }

  free(targetset);
  return;
}

scamper_targetset_t *scamper_targetset_alloc(scamper_task_t *task)
{
  scamper_targetset_t *targetset;

  if((targetset = malloc_zero(sizeof(scamper_targetset_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc targetset");
      goto err;
    }
  if((targetset->list = slist_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc list");
      goto err;
    }
  targetset->task = task;

  if(task->funcs->task_addrs(task->data, targetset, targetset_addrs) != 0)
    {
      goto err;
    }

  if(slist_count(targetset->list) < 1)
    {
      goto err;
    }

  return targetset;

 err:
  return NULL;
}

int scamper_targets_init()
{
  if((tree[SCAMPER_ADDR_TYPE_IPV4-1]=splaytree_alloc(target_addr4_cmp))==NULL)
    {
      return -1;
    }

  if((tree[SCAMPER_ADDR_TYPE_IPV6-1]=splaytree_alloc(target_addr6_cmp))==NULL)
    {
      return -1;
    }

  return 0;
}

void scamper_targets_cleanup()
{
  int i;
  for(i=0; i<SCAMPER_ADDR_TYPE_MAX; i++)
    {
      if(tree[i] != NULL)
	splaytree_free(tree[i], NULL);
      tree[i] = NULL;
    }

  return;
}
