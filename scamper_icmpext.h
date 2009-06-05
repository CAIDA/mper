/*
 * scamper_icmpext.h
 *
 * $Id: scamper_icmpext.h,v 1.1 2008/05/01 22:10:56 mjl Exp $
 *
 * Copyright (C) 2008 The University of Waikato
 * Author: Matthew Luckie
 *
 * Load-balancer traceroute technique authored by
 * Ben Augustin, Timur Friedman, Renata Teixeira; "Measuring Load-balanced
 *  Paths in the Internet", in Proc. Internet Measurement Conference 2007.
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

#ifndef __SCAMPER_ICMPEXT_H
#define __SCAMPER_ICMPEXT_H

/*
 * scamper_icmpext
 *
 * this structure holds an individual icmp extension
 */
typedef struct scamper_icmpext
{
  uint8_t                 ie_cn;   /* class number */
  uint8_t                 ie_ct;   /* class type */
  uint16_t                ie_dl;   /* data length */
  uint8_t                *ie_data; /* data */
  struct scamper_icmpext *ie_next;
} scamper_icmpext_t;

#define SCAMPER_ICMPEXT_IS_MPLS(ie)				\
 ((ie)->ie_cn == 1 && (ie)->ie_ct == 1)

#define SCAMPER_ICMPEXT_MPLS_COUNT(ie)				\
 ((ie)->ie_dl >> 2)

#define SCAMPER_ICMPEXT_MPLS_LABEL(ie, x)			\
 (( (ie)->ie_data[((x)<<2)+0] << 12) +				\
  ( (ie)->ie_data[((x)<<2)+1] <<  4) +				\
  (((ie)->ie_data[((x)<<2)+2] >>  4) & 0xff))

#define SCAMPER_ICMPEXT_MPLS_EXP(ie, x)				\
 (((ie)->ie_data[((x)<<2)+2] >> 1) & 0x7)

#define SCAMPER_ICMPEXT_MPLS_S(ie, x)				\
 ((ie)->ie_data[((x)<<2)+2] & 0x1)

#define SCAMPER_ICMPEXT_MPLS_TTL(ie, x)				\
 ((ie)->ie_data[((x)<<2)+3])

scamper_icmpext_t *scamper_icmpext_alloc(uint8_t cn, uint8_t ct, uint16_t dl,
					 const void *data);
int scamper_icmpext_parse(scamper_icmpext_t **ext, void *data, uint16_t len);
void scamper_icmpext_free(scamper_icmpext_t *exts);

#endif /* __SCAMPER_ICMPEXT_H */
