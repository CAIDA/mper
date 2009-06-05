/*
 * scamper_addr2mac.h: an implementation of two neighbour discovery methods
 *
 * $Id: scamper_addr2mac.h,v 1.4 2008/03/11 00:31:57 mjl Exp $
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

#ifndef __SCAMPER_ADDR2MAC_H
#define __SCAMPER_ADDR2MAC_H

void scamper_addr2mac_isat_v4(int ifindex, uint8_t *pkt, size_t len);
void scamper_addr2mac_isat_v6(int ifindex, uint8_t *pkt, size_t len);
int scamper_addr2mac_whohas(const int ifindex, const scamper_addr_t *src,
			    scamper_addr_t *dst, uint8_t *mac);
int scamper_addr2mac_init(void);
void scamper_addr2mac_cleanup(void);

#endif /* __SCAMPER_ADDR2MAC_H */
