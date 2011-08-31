/*
 * scamper_tlv.c
 *
 * $Id: scamper_tlv.c,v 1.7 2009/02/19 22:10:26 mjl Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_tlv.h"
#include "utils.h"

scamper_tlv_t *scamper_tlv_alloc(const uint8_t type, const uint8_t len,
				 const void *value)
{
  scamper_tlv_t *tlv;

  if((tlv = malloc_zero(sizeof(struct scamper_tlv))) != NULL)
    {
      tlv->tlv_type = type;
      tlv->tlv_len  = len;

      if(len == 0)
	return tlv;

      if(len == 1)
	{
	  memcpy(&tlv->tlv_val_8, value, 1);
	}
      else if(len == 2)
	{
	  memcpy(&tlv->tlv_val_16, value, 2);
	}
      else if(len == 4)
	{
	  memcpy(&tlv->tlv_val_32, value, len);
	}
      else
	{
	  if((tlv->tlv_val_ptr = malloc(len)) == NULL)
	    {
	      free(tlv);
	      return NULL;
	    }

	  memcpy(tlv->tlv_val_ptr, value, len);
	}
    }

  return tlv;
}

void scamper_tlv_free(scamper_tlv_t *tlv)
{
  scamper_tlv_t *next;

  while(tlv != NULL)
    {
      next = tlv->tlv_next;
      if(tlv->tlv_len != 0 && tlv->tlv_len != 1 && tlv->tlv_len != 2 &&
	 tlv->tlv_len != 4 && tlv->tlv_val_ptr != NULL)
	{
	  free(tlv->tlv_val_ptr);
	}

      free(tlv);
      tlv = next;
    }

  return;
}

scamper_tlv_t *scamper_tlv_set(scamper_tlv_t **head,
			       const uint8_t t,const uint8_t l,const void *v)
{
  scamper_tlv_t *tlv;

  if((tlv = scamper_tlv_alloc(t, l, v)) != NULL)
    {
      tlv->tlv_next = *head;
      *head = tlv;
    }

  return tlv;
}

const scamper_tlv_t *scamper_tlv_get(const scamper_tlv_t *tlv,
				     const uint8_t type)
{
  while(tlv != NULL)
    {
      if(tlv->tlv_type == type) break;
      tlv = tlv->tlv_next;
    }

  return tlv;
}
