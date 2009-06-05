/*
 * scamper_file.c
 *
 * $Id: scamper_file.h,v 1.20 2008/11/15 04:37:33 mjl Exp $
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

#ifndef __SCAMPER_FILE_H
#define __SCAMPER_FILE_H

/* handle for reading / writing files that scamper understands */
typedef struct scamper_file scamper_file_t;

/* handle for filtering objects from a file when reading */
typedef struct scamper_file_filter scamper_file_filter_t;

typedef int (*scamper_file_writefunc_t)(void *param,
					const void *data, size_t len);

/* types of objects that scamper understands */
#define SCAMPER_FILE_OBJ_LIST        0x01
#define SCAMPER_FILE_OBJ_CYCLE_START 0x02
#define SCAMPER_FILE_OBJ_CYCLE_DEF   0x03
#define SCAMPER_FILE_OBJ_CYCLE_STOP  0x04
#define SCAMPER_FILE_OBJ_ADDR        0x05
#define SCAMPER_FILE_OBJ_TRACE       0x06
#define SCAMPER_FILE_OBJ_PING        0x07
#define SCAMPER_FILE_OBJ_TRACELB     0x08
#define SCAMPER_FILE_OBJ_DEALIAS     0x09

scamper_file_t *scamper_file_open(char *fn, char mode, char *type);
scamper_file_t *scamper_file_openfd(int fd, char *fn, char mode, char *type);
void scamper_file_close(scamper_file_t *sf);
void scamper_file_free(scamper_file_t *sf);

scamper_file_filter_t *scamper_file_filter_alloc(uint16_t *types,uint16_t num);
void scamper_file_filter_free(scamper_file_filter_t *filter);
int scamper_file_filter_isset(scamper_file_filter_t *filter, uint16_t type);

int scamper_file_read(scamper_file_t *sf, scamper_file_filter_t *filter,
		      uint16_t *obj_type, void **obj_data);

struct scamper_cycle;
int scamper_file_write_cycle_start(scamper_file_t *sf,
				   struct scamper_cycle *cycle);
int scamper_file_write_cycle_stop(scamper_file_t *sf,
				  struct scamper_cycle *cycle);

struct scamper_trace;
int scamper_file_write_trace(scamper_file_t *sf,
			     const struct scamper_trace *trace);

struct scamper_tracelb;
int scamper_file_write_tracelb(scamper_file_t *sf,
			       const struct scamper_tracelb *trace);

struct scamper_ping;
int scamper_file_write_ping(scamper_file_t *sf,
			    const struct scamper_ping *ping);

struct scamper_sting;
int scamper_file_write_sting(scamper_file_t *sf,
			     const struct scamper_sting *sting);

struct scamper_dealias;
int scamper_file_write_dealias(scamper_file_t *sf,
			       const struct scamper_dealias *dealias);

char *scamper_file_type_tostr(scamper_file_t *sf, char *buf, size_t len);
char *scamper_file_getfilename(scamper_file_t *sf);

int   scamper_file_geteof(scamper_file_t *sf);
void  scamper_file_seteof(scamper_file_t *sf);

void  scamper_file_setwritefunc(scamper_file_t *sf, void *param,
				scamper_file_writefunc_t writefunc);
scamper_file_writefunc_t scamper_file_getwritefunc(const scamper_file_t *sf);
void *scamper_file_getwriteparam(const scamper_file_t *sf);

int   scamper_file_getfd(const scamper_file_t *sf);
void *scamper_file_getstate(const scamper_file_t *sf);
void  scamper_file_setstate(scamper_file_t *sf, void *state);

#endif /* __SCAMPER_FILE_H */
