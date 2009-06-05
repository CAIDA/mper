/*
 * scamper_icmp4.h
 *
 * $Id: scamper_icmp4.h,v 1.18 2009/03/21 09:27:16 mjl Exp $
 *
 * Copyright (C) 2003-2009 The University of Waikato
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

#ifndef __SCAMPER_ICMP4_H
#define __SCAMPER_ICMP4_H

int scamper_icmp4_open(const void *addr);
void scamper_icmp4_close(int fd);

void scamper_icmp4_cleanup(void);
void scamper_icmp4_read_cb(const int fd, void *param);

#ifdef __SCAMPER_PROBE_H
int scamper_icmp4_probe(scamper_probe_t *probe);
int scamper_icmp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
uint16_t scamper_icmp4_cksum(scamper_probe_t *probe);
#endif

#ifdef __SCAMPER_ICMP_RESP_H
int scamper_icmp4_recv(int fd, scamper_icmp_resp_t *resp);
#endif

#endif /* __SCAMPER_ICMP4_H */
