/*
 * scamper_rtsock.h
 *
 * $Id: scamper_rtsock.h,v 1.13 2009/03/21 09:43:37 mjl Exp $
 *
 * Copyright (C) 2004-2009 The University of Waikato
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

#ifndef __SCAMPER_RTSOCK_H
#define __SCAMPER_RTSOCK_H

int scamper_rtsock_init(void);
void scamper_rtsock_cleanup(void);

#ifndef _WIN32
int scamper_rtsock_open(void);
int scamper_rtsock_open_fd(void);
void scamper_rtsock_read_cb(const int fd, void *param);
void scamper_rtsock_close(int fd);
#endif

#if defined(__SCAMPER_ADDR_H)
typedef struct scamper_rt_rec
{
  int             error;
  int             ifindex;
  scamper_addr_t *gwaddr;
} scamper_rt_rec_t;
#endif

#ifdef _WIN32
int scamper_rtsock_getroute(scamper_addr_t *addr, scamper_rt_rec_t *rec);
#endif

#if !defined (_WIN32) && defined(__SCAMPER_FD_H) && defined(__SCAMPER_ADDR_H)
int scamper_rtsock_getroute(scamper_fd_t *fdn, scamper_addr_t *addr);
#endif

#endif /* SCAMPER_RTSOCK_H */
