/*
 * scamper_tlv.h
 *
 * $Id: scamper_tlv.h,v 1.3 2008/03/11 00:31:58 mjl Exp $
 *
 * Copyright (C) 2005-2007 The University of Waikato
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

#ifndef __SCAMPER_TLV_H
#define __SCAMPER_TLV_H

/*
 * scamper_tlv
 *
 * useful for storing data conditionally with some scamper object
 */
typedef struct scamper_tlv
{
  uint8_t             tlv_type;
  uint8_t             tlv_len;

  /*
   * rather than malloc for tiny bits of data, if len <= 4 use a reserved
   * data field.  otherwise, the data will be pointed to
   */
  union
  {
    void             *val_ptr;
    uint8_t           val_8;
    uint16_t          val_16;
    uint32_t          val_32;
  } tlv_u;

#define tlv_val_ptr tlv_u.val_ptr
#define tlv_val_8   tlv_u.val_8
#define tlv_val_16  tlv_u.val_16
#define tlv_val_32  tlv_u.val_32

  struct scamper_tlv *tlv_next;
} scamper_tlv_t;

/*
 * scamper_tlv_alloc:
 *  allocate a new TLV structure and initialise the fields to those supplied.
 *  the values are copied into the new struct with its own malloc'd memory.
 */
scamper_tlv_t *scamper_tlv_alloc(const uint8_t type, const uint8_t len,
				 const void *value);

/*
 * scamper_tlv_free:
 *  free the memory associated with this tlv structure, and any tlv
 *  connected beneath it.
 */
void scamper_tlv_free(scamper_tlv_t *tlv);

/*
 * scamper_tlv_set:
 * insert a TLV into the TLV list pointed to by head.  this routine will
 * modify the head pointer if necessary, and will return the new TLV entry.
 */
scamper_tlv_t *scamper_tlv_set(scamper_tlv_t **head,
			       const uint8_t t,const uint8_t l,const void *v);

/*
 * scamper_tlv_get:
 *  search the TLV list for the type requested
 */
const scamper_tlv_t *scamper_tlv_get(const scamper_tlv_t *tlv,
				     const uint8_t type);

#endif /* __SCAMPER_TLV_H */
