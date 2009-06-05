/*
 * scamper_control.h
 *
 * $Id: scamper_control.h,v 1.6 2008/03/11 00:31:57 mjl Exp $
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

#ifndef __SCAMPER_CONTROL_H
#define __SCAMPER_CONTROL_H

int scamper_control_init(int port);
void scamper_control_cleanup(void);

#endif
