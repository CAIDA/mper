/*
 * scamper_file_traceroute.h
 *
 * $Id: scamper_file_traceroute.h,v 1.10 2008/07/07 22:28:46 mjl Exp $
 *
 * code to read scamper's traceroute-like file format into scamper_hop
 * structures.
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

#ifndef _SCAMPER_FILE_TRACEROUTE_H
#define _SCAMPER_FILE_TRACEROUTE_H

scamper_trace_t *scamper_file_traceroute_read_trace(const scamper_file_t *sf);

int scamper_file_traceroute_write_trace(const scamper_file_t *sf,
					const scamper_trace_t *trace);

int scamper_file_traceroute_write_ping(const scamper_file_t *sf,
				       const scamper_ping_t *ping);

int scamper_file_traceroute_write_tracelb(const scamper_file_t *sf,
					  const scamper_tracelb_t *trace);

int scamper_file_traceroute_write_sting(const scamper_file_t *sf,
					const scamper_sting_t *sting);

int scamper_file_traceroute_is(const scamper_file_t *sf);

int scamper_file_traceroute_init_read(scamper_file_t *file);

void scamper_file_traceroute_free_state(scamper_file_t *file);

#endif /* _SCAMPER_FILE_TRACEROUTE_H */
