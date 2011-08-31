/*
 * scamper_icmpext.c
 *
 * $Id: scamper_icmpext.c,v 1.4 2009/03/13 20:51:26 mjl Exp $
 *
 * Copyright (C) 2008 The University of Waikato
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

#include "scamper_icmpext.h"

scamper_icmpext_t *scamper_icmpext_alloc(uint8_t cn, uint8_t ct, uint16_t dl,
					 const void *data)
{
  scamper_icmpext_t *ie;

  if((ie = malloc(sizeof(scamper_icmpext_t))) == NULL)
    {
      return NULL;
    }

  if(dl != 0)
    {
      if((ie->ie_data = malloc(dl)) != NULL)
	{
	  memcpy(ie->ie_data, data, dl);
	}
      else
	{
	  free(ie);
	  return NULL;
	}
    }
  else
    {
      ie->ie_data = NULL;
    }

  ie->ie_next = NULL;
  ie->ie_cn = cn;
  ie->ie_ct = ct;
  ie->ie_dl = dl;

  return ie;
}

void scamper_icmpext_free(scamper_icmpext_t *ie)
{
  scamper_icmpext_t *next;

  while(ie != NULL)
    {
      next = ie->ie_next;
      if(ie->ie_data != NULL)
	free(ie->ie_data);
      free(ie);
      ie = next;
    }

  return;
}

int scamper_icmpext_parse(scamper_icmpext_t **exts, void *data, uint16_t len)
{
  scamper_icmpext_t *ie, *next;
  uint8_t  *u8 = data;
  uint16_t  dl;
  uint8_t   cn, ct;
  int       off;

  *exts = NULL;
  next = *exts;

  /* start at offset 4 so the extension header is skipped */
  for(off = 4; off + 4 < len; off += dl)
    {
      /* extract the length field */
      memcpy(&dl, u8+off, 2);
      dl = ntohs(dl);

      /* make sure there is enough in the packet left */
      if(off + dl < len)
	break;

      cn = u8[off+2];
      ct = u8[off+3];

      if(dl < 8)
	{
	  continue;
	}

      if((ie = scamper_icmpext_alloc(cn, ct, dl-4, u8+off+4)) == NULL)
	{
	  return -1;
	}

      if(next == NULL)
	{
	  *exts = ie;
	}
      else
	{
	  next->ie_next = ie;
	}
      next = ie;
    }

  return 0;
}
