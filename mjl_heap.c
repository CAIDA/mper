/*
 * heap routines
 * by Matthew Luckie
 *
 * Adapted from the priority queue in "Robert Sedgewick's Algorithms in C++"
 *
 * Copyright (C) 2006-2009 Matthew Luckie. All rights reserved
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
 * $Id: mjl_heap.c,v 1.6 2009/03/30 19:58:55 mjl Exp $
 *
 */

#include <stdlib.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "mjl_heap.h"

#define HEAP_GROWBY 128

struct heap_node
{
  int   id;
  void *item;
};

struct heap
{
  heap_node_t   **a;
  int             N;
  int             max;
  heap_cmp_t      cmp;
  heap_onremove_t onremove;
};

#if !defined(NDEBUG) && defined(MJLHEAP_DEBUG)
static void heap_assert(const heap_t *heap)
{
  int i;
  for(i=1; i <= heap->N; i++)
    {
      assert(heap->a[i]->id == i);

      /* parent has to have higher priority than its children */
      if(i+i <= heap->N)
	{
	  assert(heap->cmp(heap->a[i]->item, heap->a[i+i]->item) >= 0);
	}
      if(i+i+1 <= heap->N)
	{
	  assert(heap->cmp(heap->a[i]->item, heap->a[i+i+1]->item) >= 0);
	}
    }
  return;
}
#else
#define heap_assert(heap)((void)0)
#endif

static void upheap(heap_t *heap, int k)
{
  heap_node_t *v = heap->a[k];

  while(k > 1 && heap->cmp(heap->a[k/2]->item, v->item) <= 0)
    {
      heap->a[k] = heap->a[k/2];
      heap->a[k]->id = k;

      k = k/2;
    }

  heap->a[k] = v;
  v->id = k;

  return;
}

static void downheap(heap_t *heap, int k)
{
  heap_node_t *v = heap->a[k];
  int j;

  while(k <= heap->N/2)
    {
      j = k+k;

      if(j < heap->N && heap->cmp(heap->a[j]->item, heap->a[j+1]->item) < 0)
	{
	  j++;
	}

      if(heap->cmp(v->item, heap->a[j]->item) >= 0)
	{
	  break;
	}

      heap->a[k] = heap->a[j];
      heap->a[k]->id = k;

      k = j;
    }

  heap->a[k] = v;
  heap->a[k]->id = k;

  return;
}

heap_t *heap_alloc(heap_cmp_t cmp)
{
  heap_t *heap = NULL;

  if((heap = malloc(sizeof(heap_t))) == NULL)
    {
      goto err;
    }

  heap->N   = 0;
  heap->max = HEAP_GROWBY;
  heap->cmp = cmp;

  if((heap->a = malloc(sizeof(heap_node_t *) * heap->max)) == NULL)
    {
      goto err;
    }

  return heap;

 err:
  heap_free(heap, NULL);
  return NULL;
}

void heap_free(heap_t *heap, heap_free_t free_func)
{
  int i;

  if(heap != NULL)
    {
      if(heap->a != NULL)
	{
	  for(i=1; i <= heap->N; i++)
	    {
	      if(free_func != NULL)
		{
		  free_func(heap->a[i]->item);
		}
	      free(heap->a[i]);
	    }

	  free(heap->a);
	}
      free(heap);
    }

  return;
}

/*
 * heap_remake
 *
 * items in the heap might violate the heap condition.  remake the heap.
 */
void heap_remake(heap_t *heap)
{
  int i;

  for(i=1; i<=heap->N; i++)
    upheap(heap, i);

  return;
}

void heap_onremove(heap_t *heap, heap_onremove_t onremove)
{
  heap->onremove = onremove;
  return;
}

heap_node_t *heap_insert(heap_t *heap, void *ptr)
{
  heap_node_t *node = NULL;
  void *tmp;
  size_t size;

  heap_assert(heap);

  /* allocate a new node */
  if((node = malloc(sizeof(heap_node_t))) == NULL)
    {
      goto err;
    }
  node->id   = heap->N+1;
  node->item = ptr;

  /* determine if we need to increase the size of the array for this node */
  if(node->id >= heap->max)
    {
      size = (heap->max + HEAP_GROWBY) * sizeof(heap_node_t *);
      if((tmp = realloc(heap->a, size)) == NULL)
	{
	  goto err;
	}

      heap->max += HEAP_GROWBY;
      heap->a = (heap_node_t **)tmp;
    }

  /* insert the new node, and then satisfy the heap condition */
  heap->a[node->id] = node;
  heap->N++;
  upheap(heap, heap->N);

  heap_assert(heap);

  return node;

 err:
  if(node != NULL) free(node);
  return NULL;
}

/*
 * heap_head_node
 *
 * return the node at the top of the heap, without removing it.
 */
heap_node_t *heap_head_node(heap_t *heap)
{
  heap_assert(heap);

  if(heap->N == 0)
    {
      return NULL;
    }

  return heap->a[1];
}

/*
 * heap_head_item
 *
 * return the item at the top of the heap, without removing it.
 */
void *heap_head_item(heap_t *heap)
{
  heap_assert(heap);

  if(heap->N == 0)
    {
      return NULL;
    }

  return heap->a[1]->item;
}

void *heap_remove(heap_t *heap)
{
  heap_node_t *v;
  void *item;

  heap_assert(heap);

  if(heap->N == 0)
    {
      return NULL;
    }

  v = heap->a[1];

  heap->a[1] = heap->a[heap->N--];
  heap->a[1]->id = 1;

  downheap(heap, 1);

  item = v->item;
  free(v);

  heap_assert(heap);

  if(heap->onremove != NULL)
    heap->onremove(item);

  return item;
}

void heap_foreach(heap_t *heap, void *param, heap_foreach_t func)
{
  int i;

  for(i=1; i <= heap->N; i++)
    {
      func(param, heap->a[i]->item);
    }

  return;
}

int heap_count(heap_t *heap)
{
  return heap->N;
}

void *heap_node_item(heap_node_t *node)
{
  return node->item;
}

int heap_node_id(heap_node_t *node)
{
  return node->id;
}

/*
 * heap_delete
 *
 * take the last node in the heap and replace the node to be deleted with
 * it.  then, satisfy the heap condition.
 */
void heap_delete(heap_t *heap, heap_node_t *node)
{
  heap_node_t *v;
  int i;

  heap_assert(heap);

  if(node->id == heap->N)
    {
      heap->N--;
    }
  else
    {
      /*
       * take the last node and put it in the array where the value being
       * deleted is
       */
      heap->a[node->id] = v = heap->a[heap->N--];
      heap->a[node->id]->id = node->id;

      /* if the priority of the item being replaced is raised, upheap */
      if((i = heap->cmp(v->item, node->item)) > 0)
	{
	  upheap(heap, node->id);
	}
      /* if the priority of the item being replaced is lowered, downheap */
      else if(i < 0)
	{
	  downheap(heap, node->id);
	}
    }

  if(heap->onremove != NULL)
    heap->onremove(node->item);

  free(node);

  heap_assert(heap);

  return;
}
