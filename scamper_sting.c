/*
 * scamper_dealias.c
 *
 * $Id: scamper_sting.c,v 1.3 2009/02/19 22:10:26 mjl Exp $
 *
 * Copyright (C) 2008 The University of Waikato
 * Author: Matthew Luckie
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the replye that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef _WIN32
#include <winsock2.h>
#endif

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_sting.h"
#include "utils.h"

int scamper_sting_data(scamper_sting_t *sting, const uint8_t *data)
{
  size_t len = sting->seqskip + sting->count;

  if(len != 0 && (sting->data = malloc(len)) != NULL)
    {
      memcpy(sting->data, data, len);
      return 0;
    }

  return -1;
}

int scamper_sting_probes(scamper_sting_t *sting, uint16_t probec)
{
  if((sting->probes = malloc(sizeof(scamper_sting_probe_t) * probec)) != NULL)
    {
      return 0;
    }

  return -1;
}

void scamper_sting_free(scamper_sting_t *sting)
{
  if(sting == NULL)
    return;

  if(sting->src != NULL)   scamper_addr_free(sting->src);
  if(sting->dst != NULL)   scamper_addr_free(sting->dst);
  if(sting->list != NULL)  scamper_list_free(sting->list);
  if(sting->cycle != NULL) scamper_cycle_free(sting->cycle);
  if(sting->data != NULL)  free(sting->data);

  free(sting);
  return;
}

scamper_sting_t *scamper_sting_alloc(void)
{
  return (scamper_sting_t *)malloc_zero(sizeof(scamper_sting_t));
}
