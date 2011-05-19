/*
 * scamper_ip6.h
 *
 * $Id: scamper_ip4.h,v 1.1 2009/11/05 03:42:18 mjl Exp $
 *
 * Copyright (C) 2009 The University of Waikato
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

#ifndef __SCAMPER_IP4_H
#define __SCAMPER_IP4_H

int scamper_ip4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
int scamper_ip4_hlen(scamper_probe_t *probe, size_t *len);

#endif /* __SCAMPER_IP4_H */
