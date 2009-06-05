/*
 * mjl_heap
 *
 * Copyright (C) 2006-2009 Matthew Luckie. All rights reserved.
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
 * $Id: mjl_heap.h,v 1.4 2009/03/13 10:10:01 mjl Exp $
 *
 */

#ifndef __MJL_HEAP_H
#define __MJL_HEAP_H

typedef struct heap heap_t;
typedef struct heap_node heap_node_t;

typedef int  (*heap_cmp_t)(const void *a, const void *b);
typedef int  (*heap_free_t)(void *ptr);
typedef void (*heap_foreach_t)(const void *param, const void *item);
typedef void (*heap_onremove_t)(void *ptr);

heap_t *heap_alloc(heap_cmp_t cmp);
void heap_free(heap_t *heap, heap_free_t free_func);
void heap_remake(heap_t *heap);
void heap_onremove(heap_t *heap, heap_onremove_t onremove);

heap_node_t *heap_insert(heap_t *heap, void *ptr);
void *heap_remove(heap_t *heap);
heap_node_t *heap_head_node(heap_t *heap);
void *heap_head_item(heap_t *heap);
void heap_delete(heap_t *heap, heap_node_t *node);
void heap_foreach(heap_t *heap, void *param, heap_foreach_t func);
int heap_count(heap_t *heap);

void *heap_node_item(heap_node_t *node);
int heap_node_id(heap_node_t *node);

#endif /* __MJL_HEAP_H */
