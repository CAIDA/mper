/*
 * scamper_writebuf.h: use in combination with select to send without blocking
 *
 * $Id: scamper_writebuf.h,v 1.8 2008/05/19 02:27:39 mjl Exp $
 *
 * Copyright (C) 2004-2008 The University of Waikato
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

#ifndef __SCAMPER_WRITEBUF_H
#define __SCAMPER_WRITEBUF_H

typedef struct scamper_writebuf scamper_writebuf_t;

/* allocate a writebuf */
scamper_writebuf_t *scamper_writebuf_alloc(void);

/* free a writebuf */
void scamper_writebuf_free(scamper_writebuf_t *wb);

/* queue data on the writebuf to be sent */
int scamper_writebuf_send(scamper_writebuf_t *wb, const void *data,size_t len);

/* write the buffered data to the specified file descriptor */
int scamper_writebuf_tx(scamper_writebuf_t *wb, int fd);

/* return the count of bytes buffered */
size_t scamper_writebuf_len(const scamper_writebuf_t *wb);

/*
 * out of convenience, some routines are provided that has the data queued
 * on the writebuf to be sent as required using the scamper_fd routines.
 *
 *  scamper_writebuf_attach:
 *   manage the scamper_fd_t write path based on data being queued to be sent
 *
 *  scamper_writebuf_detach:
 *   don't manage the scamper_fd_t write path any more
 *
 *  scamper_writebuf_flush:
 *   flush all the data that can be written out now to the scamper_fd_t
 */
void scamper_writebuf_attach(scamper_writebuf_t *wb,
			     scamper_fd_t *fdn, void *param,
			     void (*efunc)(void *, int, scamper_writebuf_t *),
			     void (*dfunc)(void *, scamper_writebuf_t *));
void scamper_writebuf_detach(scamper_writebuf_t *wb);
int scamper_writebuf_flush(scamper_writebuf_t *wb);

#endif
