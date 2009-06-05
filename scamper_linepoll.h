/*
 * scamper_linepoll
 *
 * $Id: scamper_linepoll.h,v 1.4 2008/03/11 00:31:57 mjl Exp $
 *
 * Copyright (C) 2004-2007 The University of Waikato
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

#ifndef __SCAMPER_LINEPOLL_H
#define __SCAMPER_LINEPOLL_H

typedef struct scamper_linepoll scamper_linepoll_t;
typedef int (*scamper_linepoll_handler_t)(void *param,uint8_t *buf,size_t len);

int scamper_linepoll_handle(scamper_linepoll_t *lp, uint8_t *buf, size_t len);

int scamper_linepoll_flush(scamper_linepoll_t *lp);

scamper_linepoll_t *scamper_linepoll_alloc(scamper_linepoll_handler_t handler,
					   void *param);

void scamper_linepoll_free(scamper_linepoll_t *lp, int feedlastline);

#endif
