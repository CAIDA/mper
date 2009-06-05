/*
 * scamper_file_warts.h
 *
 * the Waikato ARTS file format replacement
 *
 * $Id: scamper_file_warts.h,v 1.13 2008/11/15 04:37:33 mjl Exp $
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

#ifndef __SCAMPER_FILE_WARTS_H
#define __SCAMPER_FILE_WARTS_H

int scamper_file_warts_read(scamper_file_t *sf, scamper_file_filter_t *filter,
			    uint16_t *type, void **data);

int scamper_file_warts_write_trace(const scamper_file_t *file,
				   const scamper_trace_t *trace);

int scamper_file_warts_write_ping(const scamper_file_t *file,
				  const scamper_ping_t *ping);

int scamper_file_warts_write_cycle_start(const scamper_file_t *sf,
					 scamper_cycle_t *c);
int scamper_file_warts_write_cycle_stop(const scamper_file_t *sf,
					scamper_cycle_t *c);

int scamper_file_warts_write_tracelb(const scamper_file_t *file,
				     const scamper_tracelb_t *tracelb);

int scamper_file_warts_write_dealias(const scamper_file_t *file,
				     const scamper_dealias_t *dealias);

int scamper_file_warts_is(const scamper_file_t *file);
int scamper_file_warts_init_append(scamper_file_t *file);
int scamper_file_warts_init_read(scamper_file_t *file);
int scamper_file_warts_init_write(scamper_file_t *file);

void scamper_file_warts_free_state(scamper_file_t *file);

#endif /* __SCAMPER_FILE_WARTS_H */
