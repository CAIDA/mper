/*
 * linked list routines
 * by Matthew Luckie
 *
 * Copyright (C) 2004-2009 Matthew Luckie. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Matthew Luckie ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Matthew Luckie BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: mjl_list.c,v 1.52 2009/01/31 03:13:54 mjl Exp $
 *
 */

#include <stdlib.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "mjl_list.h"

struct slist_node
{
  void              *item;
  struct slist_node *next;
};

struct dlist_node
{
  void              *item;
  struct dlist_node *prev;
  struct dlist_node *next;
  struct dlist      *list;
};

struct clist_node
{
  void              *item;
  struct clist_node *prev;
  struct clist_node *next;
};

struct slist
{
  slist_node_t     *head;
  slist_node_t     *tail;
  int               length;
  unsigned int      lock;
  slist_onremove_t  onremove;
};

struct dlist
{
  dlist_node_t     *head;
  dlist_node_t     *tail;
  int               length;
  unsigned int      lock;
  dlist_onremove_t  onremove;
};

struct clist
{
  clist_node_t     *head;
  int               length;
  unsigned int      lock;
  clist_onremove_t  onremove;
};

#if !defined(NDEBUG) && defined(MJLLIST_DEBUG)
static void slist_assert(const slist_t *list)
{
  slist_node_t *node;
  int i;

  if(list == NULL)
    return;

  assert(list->length >= 0);

  if(list->length == 0)
    {
      assert(list->head == NULL);
      assert(list->tail == NULL);
    }
  else if(list->length == 1)
    {
      assert(list->head != NULL);
      assert(list->tail != NULL);
      assert(list->head == list->tail);
      assert(list->head->next == NULL);
    }
  else
    {
      i = 1; node = list->head;
      while(i<list->length)
	{
	  assert(node != NULL);
	  node = node->next;
	  i++;
	}
      assert(node == list->tail);
    }
  return;  
}
#else
#define slist_assert(list)((void)0)
#endif

void slist_lock(slist_t *list)
{
  assert(list != NULL);
  list->lock++;
  return;
}

void slist_unlock(slist_t *list)
{
  assert(list != NULL);
  assert(list->lock > 0);
  list->lock--;
  return;
}

int slist_islocked(slist_t *list)
{
  assert(list != NULL);
  return list->lock == 0 ? 0 : 1;
}

#ifndef DMALLOC
slist_t *slist_alloc(void)
#else
slist_t *slist_alloc_dm(const char *file, const int line)
#endif
{
  slist_t *list;
  size_t len = sizeof(slist_t);

#ifndef DMALLOC
  list = (slist_t *)malloc(len);
#else
  list = (slist_t *)dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(list != NULL)
    {
      slist_init(list);
    }

  return list;
}

void slist_init(slist_t *list)
{
  assert(list != NULL);
  list->head     = NULL;
  list->tail     = NULL;
  list->length   = 0;
  list->lock     = 0;
  list->onremove = NULL;
  return;
}

void slist_onremove(slist_t *list, slist_onremove_t onremove)
{
  assert(list != NULL);
  list->onremove = onremove;
  return;
}

#ifndef DMALLOC
static slist_node_t *slist_node(void *item, slist_node_t *next)
#else
static slist_node_t *slist_node(void *item, slist_node_t *next,
				const char *file, const int line)
#endif
{
  slist_node_t *node;
  size_t len = sizeof(slist_node_t);

#ifndef DMALLOC
  node = malloc(len);
#else
  node = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(node != NULL)
    {
      node->item = item;
      node->next = next;
    }

  return node;
}

/*
 * slist_dup
 *
 * make a copy of the list that points to the same items.
 * if the foreach function is not null, call that on each item too.
 */
#ifndef DMALLOC
slist_t *slist_dup(slist_t *oldlist, const slist_foreach_t func, void *param)
#else
slist_t *slist_dup_dm(slist_t *oldlist,const slist_foreach_t func,void *param,
		      const char *file, const int line)
#endif
{
  slist_t      *list;
  slist_node_t *oldnode, *node;
  size_t        len = sizeof(slist_t);

  /* first, allocate a replacement slist_t structure */
#ifndef DMALLOC
  list = malloc(len);
#else
  list = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(list != NULL)
    {
      list->head = NULL;
      list->tail = NULL;
      list->length = 0;
    }
  else return NULL;

  if(oldlist->head != NULL)
    {
#ifndef DMALLOC
      if((node = slist_node(oldlist->head->item, NULL)) == NULL)
#else
      if((node = slist_node(oldlist->head->item, NULL, file, line)) == NULL)
#endif
	{
	  goto err;
	}

      if(func != NULL) func(oldlist->head->item, param);

      list->length = oldlist->length;
      list->head = node;
      oldnode = oldlist->head->next;
    }
  else return list;

  while(oldnode != NULL)
    {
#ifndef DMALLOC
      if((node->next = slist_node(oldnode->item, NULL)) == NULL)
#else
      if((node->next = slist_node(oldnode->item, NULL, file, line)) == NULL)
#endif
	{
	  goto err;
	}

      if(func != NULL) func(oldnode->item, param);

      oldnode = oldnode->next;
      node = node->next;
    }

  list->tail = node;

  return list;

 err:
  slist_free(list);
  return NULL;
}

void slist_concat(slist_t *first, slist_t *second)
{
  assert(first != NULL);
  assert(second != NULL);
  assert(first->lock == 0);
  assert(second->lock == 0);
  slist_assert(first);
  slist_assert(second);

  /* if there is nothing to concatenate, then return now */
  if(second->length == 0)
    {
      return;
    }

  /* shift the second list's nodes into the first */
  if(first->tail != NULL)
    {
      first->tail->next = second->head;
      first->length += second->length;
      first->tail = second->tail;
    }
  else
    {
      first->head = second->head;
      first->tail = second->tail;
      first->length = second->length;
    }

  /* reset the second list */
  second->length = 0;
  second->head = NULL;
  second->tail = NULL;

  slist_assert(first);
  slist_assert(second);
  return;
}

void slist_free(slist_t *list)
{
  slist_node_t *node;
  slist_node_t *next;

  assert(list != NULL);
  slist_assert(list);
  assert(list->lock == 0);

  node = list->head;
  while(node != NULL)
    {
      next = node->next;
      if(list->onremove != NULL)
	list->onremove(node->item);
      free(node);
      node = next;
    }

  free(list);

  return;
}

#ifndef DMALLOC
slist_node_t *slist_head_push(slist_t *list, void *item)
#else
slist_node_t *slist_head_push_dm(slist_t *list, void *item,
				 const char *file, const int line)
#endif
{
  slist_node_t *node;

  assert(list != NULL);
  slist_assert(list);
  assert(list->lock == 0);

#ifndef DMALLOC
  if((node = slist_node(item, list->head)) != NULL)
#else
  if((node = slist_node(item, list->head, file, line)) != NULL)
#endif
    {
      list->head = node;

      if(list->tail == NULL)
	{
	  list->tail = node;
	}

      list->length++;
    }

  slist_assert(list);

  return node;
}

#ifndef DMALLOC
slist_node_t *slist_tail_push(slist_t *list, void *item)
#else
slist_node_t *slist_tail_push_dm(slist_t *list, void *item,
				 const char *file, const int line)
#endif
{
  slist_node_t *node;

  assert(list != NULL);
  slist_assert(list);
  assert(list->lock == 0);

#ifndef DMALLOC
  if((node = slist_node(item, NULL)) != NULL)
#else
  if((node = slist_node(item, NULL, file, line)) != NULL)
#endif
    {
      if(list->tail != NULL)
	{
	  list->tail->next = node;
	  list->tail = node;
	}
      else
	{
	  list->head = list->tail = node;
	}

      list->length++;
    }

  slist_assert(list);

  return node;
}

void *slist_head_pop(slist_t *list)
{
  slist_node_t *node;
  void         *item = NULL;

  assert(list != NULL);
  slist_assert(list);
  assert(list->lock == 0);

  if(list->head != NULL)
    {
      node = list->head;
      item = node->item;

      /* if there are no nodes left ... */
      if((list->head = node->next) == NULL)
	{
	  list->tail = NULL;
	}
      free(node);

      list->length--;
    }

  if(list->onremove != NULL)
    list->onremove(item);

  slist_assert(list);

  return item;
}

void *slist_head_get(const slist_t *list)
{
  assert(list != NULL);
  if(list->head == NULL) return NULL;
  return list->head->item;
}

slist_node_t *slist_head_node(const slist_t *list)
{
  assert(list != NULL);
  return list->head;
}

void *slist_node_item(const slist_node_t *node)
{
  assert(node != NULL);
  return node->item;
}

slist_node_t *slist_node_next(const slist_node_t *node)
{
  assert(node != NULL);
  return node->next;
}

int slist_foreach(slist_t *list, const slist_foreach_t func, void *param)
{
  slist_node_t *node;
  slist_node_t *next;

  assert(list != NULL);
  slist_lock(list);
  slist_assert(list);

  node = list->head;
  while(node != NULL)
    {
      next = node->next;
      if(func(node->item, param) != 0)
	{
	  slist_unlock(list);
	  return -1;
	}
      node = next;
    }

  slist_assert(list);
  slist_unlock(list);

  return 0;
}

int slist_count(const slist_t *list)
{
  assert(list != NULL);
  slist_assert(list);
  return list->length;
}

#if !defined(NDEBUG) && defined(MJLLIST_DEBUG)
static void dlist_assert(const dlist_t *list)
{
  dlist_node_t *node;
  int i;

  if(list == NULL)
    return;

  assert(list->length >= 0);

  if(list->length == 0)
    {
      assert(list->head == NULL);
      assert(list->tail == NULL);
    }
  else if(list->length == 1)
    {
      assert(list->head != NULL);
      assert(list->tail != NULL);
      assert(list->head == list->tail);
      assert(list->head->next == NULL);
      assert(list->head->prev == NULL);
      assert(list->head->list == list);
    }
  else
    {
      assert(list->head->prev == NULL);
      assert(list->tail->next == NULL);

      i = 1; node = list->head;
      while(i < list->length-1)
	{
	  assert(node != NULL);
	  assert(node->next != NULL);
	  assert(node->next->prev == node);
	  assert(node->list == list);
	  node = node->next;
	  i++;
	}
      assert(node->next == list->tail);
      assert(node->list == list);
    }
  return;
}
#else
#define dlist_assert(list)((void)0)
#endif

void dlist_lock(dlist_t *list)
{
  assert(list != NULL);
  list->lock++;
  return;
}

void dlist_unlock(dlist_t *list)
{
  assert(list != NULL);
  assert(list->lock > 0);
  list->lock--;
  return;
}

int dlist_islocked(dlist_t *list)
{
  assert(list != NULL);
  return list->lock == 0 ? 0 : 1;
}

#ifndef DMALLOC
dlist_t *dlist_alloc(void)
#else
dlist_t *dlist_alloc_dm(const char *file, const int line)
#endif
{
  dlist_t *list;
  size_t len = sizeof(dlist_t);

#ifndef DMALLOC
  list = malloc(len);
#else
  list = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(list != NULL)
    {
      dlist_init(list);
    }

  return list;
}

void dlist_init(dlist_t *list)
{
  assert(list != NULL);
  list->head     = NULL;
  list->tail     = NULL;
  list->length   = 0;
  list->lock     = 0;
  list->onremove = NULL;
  return;
}

void dlist_onremove(dlist_t *list, dlist_onremove_t onremove)
{
  assert(list != NULL);
  list->onremove = onremove;
  return;
}

#ifndef DMALLOC
static dlist_node_t *dlist_node(void *i, dlist_node_t *p, dlist_node_t *n)
#else
static dlist_node_t *dlist_node(void *i, dlist_node_t *p, dlist_node_t *n,
				const char *file, const int line)
#endif
{
  dlist_node_t *node;
  size_t len = sizeof(dlist_node_t);

#ifndef DMALLOC
  node = malloc(len);
#else
  node = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(node != NULL)
    {
      node->item = i;
      node->prev = p;
      node->next = n;
      node->list = NULL;
    }

  return node;
}

#ifndef DMALLOC
dlist_node_t *dlist_node_alloc(void *item)
{
  return dlist_node(item, NULL, NULL);
}
#else
dlist_node_t *dlist_node_alloc_dm(void *item, const char *file, const int line)
{
  return dlist_node(item, NULL, NULL, file, line);
}
#endif

void dlist_free(dlist_t *list)
{
  dlist_node_t *node;
  dlist_node_t *next;

  assert(list != NULL);
  dlist_assert(list);
  assert(list->lock == 0);

  node = list->head;
  while(node != NULL)
    {
      next = node->next;
      if(list->onremove != NULL)
	list->onremove(node->item);
      free(node);
      node = next;
    }

  free(list);

  return;
}

void dlist_concat(dlist_t *first, dlist_t *second)
{
  dlist_node_t *p;

  assert(first != NULL);
  assert(first->lock == 0);
  assert(second != NULL);
  assert(second->lock == 0);
  dlist_assert(first);
  dlist_assert(second);

  /* if there's nothing to concatenate, then stop now */
  if(second->length == 0)
    {
      return;
    }
  else
    {
      for(p = second->head; p != NULL; p = p->next)
	{
	  p->list = first;
	}
    }

  /* shift the second list's nodes into the first */
  if(first->tail != NULL)
    {
      first->tail->next = second->head;
      second->head->prev = first->tail;
      first->tail = second->tail;
      first->length += second->length;
    }
  else
    {
      first->head = second->head;
      first->tail = second->tail;
      first->length = second->length;
    }

  /* reset the second list */
  second->length = 0;
  second->head = NULL;
  second->tail = NULL;

  return;
}

void dlist_node_head_push(dlist_t *list, dlist_node_t *node)
{
  assert(list != NULL);
  assert(list->lock == 0);
  assert(node != NULL);
  dlist_assert(list);

  /* eject the node from whatever list it is currently on */
  dlist_node_eject(node->list, node);

  /* if we don't have a head node, we don't have a tail node set either */
  if(list->head == NULL)
    {
      list->tail = node;
    }
  else
    {
      list->head->prev = node;
    }

  /* the current head node will be second on the list */
  node->next = list->head;
  node->list = list;

  list->head = node;
  list->length++;

  dlist_assert(list);

  return;
}

void dlist_node_tail_push(dlist_t *list, dlist_node_t *node)
{
  assert(list != NULL);
  assert(list->lock == 0);
  assert(node != NULL);
  dlist_assert(list);

  /* eject the node from whatever list it is currently on */
  dlist_node_eject(node->list, node);

  /* if we don't have a tail node, we don't have a head node set either */
  if(list->tail == NULL)
    {
      list->head = node;
    }
  else
    {
      list->tail->next = node;
    }

  /* the current tail node will be second to last on the list */
  node->prev = list->tail;
  node->list = list;

  list->tail = node;
  list->length++;

  dlist_assert(list);

  return;
}

#ifndef DMALLOC
dlist_node_t *dlist_head_push(dlist_t *list, void *item)
#else
dlist_node_t *dlist_head_push_dm(dlist_t *list, void *item,
				 const char *file, const int line)
#endif
{
  dlist_node_t *node;

  assert(list != NULL);
  assert(list->lock == 0);

#ifndef DMALLOC
  if((node = dlist_node(item, NULL, NULL)) != NULL)
#else
  if((node = dlist_node(item, NULL, NULL, file, line)) != NULL)
#endif
    {
      dlist_node_head_push(list, node);
    }

  return node;
}

#ifndef DMALLOC
dlist_node_t *dlist_tail_push(dlist_t *list, void *item)
#else
dlist_node_t *dlist_tail_push_dm(dlist_t *list, void *item,
				 const char *file, const int line)
#endif
{
  dlist_node_t *node;

  assert(list != NULL);
  assert(list->lock == 0);

#ifndef DMALLOC
  if((node = dlist_node(item, NULL, NULL)) != NULL)
#else
  if((node = dlist_node(item, NULL, NULL, file, line)) != NULL)
#endif
    {
      dlist_node_tail_push(list, node);
    }

  return node;
}

void *dlist_head_pop(dlist_t *list)
{
  dlist_node_t *node;
  void         *item;

  assert(list != NULL);
  assert(list->lock == 0);
  dlist_assert(list);

  if(list->head == NULL)
    {
      return NULL;
    }

  node = list->head;
  item = node->item;

  /*
   * if we have a non-null node to replace the head with, null its prev
   * pointer as the node is now at the head of the list
   */
  if((list->head = node->next) != NULL)
    {
      list->head->prev = NULL;
    }
  else
    {
      /* no nodes left in list */
      list->tail = NULL;
    }

  free(node);
  list->length--;

  if(list->onremove != NULL)
    list->onremove(item);

  dlist_assert(list);

  return item;
}

void *dlist_tail_pop(dlist_t *list)
{
  dlist_node_t *node;
  void         *item;

  assert(list != NULL);
  assert(list->lock == 0);
  dlist_assert(list);

  if(list->head == NULL)
    {
      return NULL;
    }

  node = list->tail;
  item = node->item;

  list->tail = node->prev;

  if(list->tail != NULL)
    {
      list->tail->next = NULL;
    }

  if(list->head == node)
    {
      list->head = NULL;
    }

  free(node);
  list->length--;

  if(list->onremove != NULL)
    list->onremove(item);

  dlist_assert(list);

  return item;
}

/*
 * dlist_node_detach
 *
 * a node is on a list.  detach it from the list, but do not free the
 * node.
 */
static void dlist_node_detach(dlist_t *list, dlist_node_t *node)
{
  assert(node != NULL);
  assert(list == NULL || list->lock == 0);
  assert(node->list == list);

  /* if the node is in the list, then we have to detach it */
  if(node->prev != NULL || node->next != NULL ||
     (list != NULL && list->head == node))
    {
      if(list->head == node)
	{
	  list->head = node->next;
	}

      if(list->tail == node)
	{
	  list->tail = node->prev;
	}

      if(node->prev != NULL) node->prev->next = node->next;
      if(node->next != NULL) node->next->prev = node->prev;

      list->length--;

      /* node has been detached, reset its pointers */
      node->next = NULL;
      node->prev = NULL;
      node->list = NULL;
    }

  return;
}

/*
 * dlist_node_pop
 *
 */
void *dlist_node_pop(dlist_t *list, dlist_node_t *node)
{
  void *item;

  assert(node != NULL);
  assert(node->list == list);
  assert(list == NULL || list->lock == 0);
  dlist_assert(list);

  dlist_node_detach(list, node);
  item = node->item;
  free(node);

  if(list != NULL && list->onremove != NULL)
    list->onremove(item);

  dlist_assert(list);

  return item;
}

void *dlist_node_item(const dlist_node_t *node)
{
  assert(node != NULL);
  return node->item;
}

dlist_node_t *dlist_node_next(const dlist_node_t *node)
{
  assert(node != NULL);
  return node->next;
}

dlist_node_t *dlist_node_prev(const dlist_node_t *node)
{
  assert(node != NULL);
  return node->prev;
}

/*
 * dlist_node_eject
 *
 * remove a specified dlist_node from the list.  do not actually free the
 * node structure itself, though.
 */
void dlist_node_eject(dlist_t *list, dlist_node_t *node)
{
  assert(node != NULL);
  assert(list == NULL || list->lock == 0);
  assert(list == node->list);
  dlist_assert(list);
  dlist_node_detach(list, node);
  dlist_assert(list);
  return;
}

void *dlist_head_get(const dlist_t *list)
{
  assert(list != NULL);
  if(list->head == NULL) return NULL;
  return list->head->item;
}

dlist_node_t *dlist_head_node(const dlist_t *list)
{
  assert(list != NULL);
  return list->head;
}

void *dlist_tail_get(const dlist_t *list)
{
  assert(list != NULL);
  if(list->tail == NULL) return NULL;
  return list->tail->item;
}

int dlist_foreach(dlist_t *list, const dlist_foreach_t func, void *param)
{
  dlist_node_t *node, *next;

  assert(list != NULL);
  assert(func != NULL);

  dlist_lock(list);
  dlist_assert(list);

  node = list->head;
  while(node != NULL)
    {
      next = node->next;
      if(func(node->item, param) != 0)
	{
	  dlist_unlock(list);
	  return -1;
	}
      node = next;
    }

  dlist_assert(list);
  dlist_unlock(list);

  return 0;
}

int dlist_count(const dlist_t *list)
{
  assert(list != NULL);
  dlist_assert(list);
  return list->length;
}

#if !defined(NDEBUG) && defined(MJLLIST_DEBUG)
static void clist_assert(const clist_t *list)
{
  clist_node_t *node;
  int i;

  if(list == NULL)
    return;

  assert(list->length >= 0);

  if(list->length == 0)
    {
      assert(list->head == NULL);
    }
  else if(list->length == 1)
    {
      assert(list->head != NULL);
      assert(list->head->next == list->head);
      assert(list->head->prev == list->head);
    }
  else
    {
      i = 1; node = list->head;
      while(i < list->length)
	{
	  assert(node != NULL);
	  assert(node->next != NULL);
	  assert(node->next->prev == node);

	  node = node->next;
	  i++;
	}

      assert(node->next == list->head);
    }
  return;
}
#else
#define clist_assert(list)((void)0)
#endif

#ifndef DMALLOC
clist_t *clist_alloc(void)
#else
clist_t *clist_alloc_dm(const char *file, const int line)
#endif
{
  clist_t *list;
  size_t len = sizeof(clist_t);

#ifndef DMALLOC
  list = malloc(len);
#else
  list = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(list != NULL)
    {
      clist_init(list);
    }

  return list;
}

void clist_init(clist_t *list)
{
  assert(list != NULL);
  list->head     = NULL;
  list->length   = 0;
  list->lock     = 0;
  list->onremove = NULL;
  return;
}

void clist_onremove(clist_t *list, clist_onremove_t onremove)
{
  assert(list != NULL);
  list->onremove = onremove;
  return;
}

void clist_lock(clist_t *list)
{
  assert(list != NULL);
  list->lock++;
  return;
}

void clist_unlock(clist_t *list)
{
  assert(list != NULL);
  assert(list->lock > 0);
  list->lock--;
  return;
}

int clist_islocked(clist_t *list)
{
  assert(list != NULL);
  return list->lock == 0 ? 0 : 1;
}

void clist_free(clist_t *list)
{
  clist_node_t *node;
  clist_node_t *next;

  assert(list != NULL);
  clist_assert(list);

  if((node = list->head) != NULL)
    {
      /* break the circle */
      list->head->prev->next = NULL;

      /* delete all the nodes */
      while(node != NULL)
	{
	  next = node->next;
	  if(list->onremove)
	    list->onremove(node->item);
	  free(node);
	  node = next;
	}
    }

  free(list);

  return;
}

#ifndef DMALLOC
clist_node_t *clist_tail_push(clist_t *list, void *item)
#else
clist_node_t *clist_tail_push_dm(clist_t *list, void *item,
				 const char *file, const int line)
#endif
{
  clist_node_t *node, *tail;
  size_t len = sizeof(clist_node_t);

  assert(list != NULL);
  clist_assert(list);

#ifndef DMALLOC
  node = malloc(len);
#else
  node = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(node == NULL)
    {
      return NULL;
    }
  node->item = item;

  if(list->head != NULL)
    {
      tail = list->head->prev;

      node->prev = tail;
      node->next = list->head;

      tail->next = node;
      list->head->prev = node;
    }
  else
    {
      list->head = node;
      node->prev = node->next = node;
    }

  list->length++;

  clist_assert(list);

  return node;
}

clist_node_t *clist_head_push(clist_t *list, void *item)
{
  clist_node_t *node;

  assert(list != NULL);
  if((node = clist_tail_push(list, item)) != NULL)
    {
      list->head = node;
    }

  return node;
}

void *clist_head_get(const clist_t *list)
{
  assert(list != NULL);
  if(list->head == NULL) return NULL;
  return list->head->item;
}

void *clist_tail_get(const clist_t *list)
{
  assert(list != NULL);
  if(list->head == NULL) return NULL;
  return list->head->prev->item;
}

void *clist_node_pop(clist_t *list, clist_node_t *node)
{
  void *item;

  assert(list != NULL);
  assert(list->lock == 0);
  clist_assert(list);

  item = node->item;

  if(node == node->prev)
    {
      list->head = NULL;
    }
  else
    {
      if(list->head == node)
	{
	  list->head = node->next;
	}
      node->prev->next = node->next;
      node->next->prev = node->prev;
    }

  free(node);
  list->length--;

  if(list->onremove != NULL)
    list->onremove(item);

  clist_assert(list);

  return item;
}

void *clist_tail_pop(clist_t *list)
{
  assert(list != NULL);
  if(list->head == NULL)
    {
      return NULL;
    }

  return clist_node_pop(list, list->head->prev);
}

void *clist_head_pop(clist_t *list)
{
  assert(list != NULL);
  if(list->head == NULL)
    {
      return NULL;
    }

  return clist_node_pop(list, list->head);
}

void *clist_node_item(const clist_node_t *node)
{
  assert(node != NULL);
  return node->item;
}

clist_node_t *clist_node_next(const clist_node_t *node)
{
  assert(node != NULL);
  return node->next;
}

clist_node_t *clist_head_left(clist_t *list)
{
  assert(list != NULL);
  if(list->head == NULL)
    {
      return NULL;
    }

  list->head = list->head->prev;
  return list->head;
}

clist_node_t *clist_head_right(clist_t *list)
{
  assert(list != NULL);
  if(list->head == NULL)
    {
      return NULL;
    }

  list->head = list->head->next;
  return list->head;
}

int clist_foreach(clist_t *list, const clist_foreach_t func, void *param)
{
  clist_node_t *node;
  clist_node_t *next;

  assert(list != NULL);
  clist_lock(list);
  clist_assert(list);

  node = list->head;
  if(node == NULL)
    {
      return 0;
    }

  for(;;)
    {
      next = node->next;
      if(func(node->item, param) != 0)
	{
	  clist_unlock(list);
	  return -1;
	}

      if(next != list->head)
	{
	  node = next;
	}
      else break;
    }

  clist_assert(list);
  clist_unlock(list);

  return 0;
}

int clist_count(const clist_t *list)
{
  assert(list != NULL);
  clist_assert(list);
  return list->length;
}
