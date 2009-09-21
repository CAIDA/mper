/*
 * scamper.h
 *
 * $Id: scamper.h,v 1.42 2009/02/21 00:44:48 mjl Exp $
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

#ifndef __SCAMPER_H
#define __SCAMPER_H

#define SCAMPER_HOLDTIME_MIN  0
#define SCAMPER_HOLDTIME_DEF  0
#define SCAMPER_HOLDTIME_MAX  255
int scamper_holdtime_get(void);
int scamper_holdtime_set(const int holdtime);

int scamper_interface_set(const int n);

#define SCAMPER_PPS_MIN       1
#define SCAMPER_PPS_DEF       20
#define SCAMPER_PPS_MAX       1000
int scamper_pps_get(void);
int scamper_pps_set(const int pps);

#define SCAMPER_WINDOW_MIN    0
#define SCAMPER_WINDOW_DEF    0
#define SCAMPER_WINDOW_MAX    65535
int scamper_window_get(void);
int scamper_window_set(const int window);

#define SCAMPER_COMMAND_DEF   "trace"
const char *scamper_command_get(void);
int scamper_command_set(const char *command);

const char *scamper_monitorname_get(void);
int scamper_monitorname_set(const char *monitorname);

int scamper_option_dl(void);

void scamper_exitwhendone(int on);

#define MPER_VERSION "0.0.1"
#define CLIENT_PROTOCOL_MAJOR 1
#define CLIENT_PROTOCOL_MINOR 0

#endif /* __SCAMPER_H */
