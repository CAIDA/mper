/*
 * scamper_debug.h
 *
 * $Id: scamper_debug.h,v 1.13 2008/04/16 03:26:56 mjl Exp $
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

#ifndef __SCAMPER_DEBUG_H
#define __SCAMPER_DEBUG_H

void printerror(const int ecode, char *(*error_itoa)(int),
		const char *func, const char *format, ...);

/* only define scamper_debug if scamper is being built in debugging mode */
#if !defined(NDEBUG) && !defined(WITHOUT_DEBUGFILE)
void scamper_debug(const char *func, const char *format, ...);
#else
#define scamper_debug(func, format, ...) ((void)0)
#endif

#ifndef WITHOUT_DEBUGFILE
int scamper_debug_open(const char *debugfile);
void scamper_debug_close(void);
#endif

#endif /* scamper_debug.h */
