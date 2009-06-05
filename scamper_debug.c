/*
 * scamper_debug.c
 *
 * $Id: scamper_debug.c,v 1.24 2009/03/13 20:58:00 mjl Exp $
 *
 * routines to reduce the impact of debugging cruft in scamper's code.
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

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef int mode_t;
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <assert.h>

#ifdef _WIN32
#define snprintf _snprintf
#define open _open
#define fdopen _fdopen
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_privsep.h"
#include "utils.h"

#ifndef WITHOUT_DEBUGFILE
static FILE *debugfile = NULL;
#endif

static char *timestamp_str(char *buf, const size_t len)
{
  struct timeval  tv;
  struct tm      *tm;
  int             ms;
  time_t          t;

  buf[0] = '\0';
  gettimeofday_wrap(&tv);
  t = tv.tv_sec;
  if((tm = localtime(&t)) == NULL) return buf;

  ms = tv.tv_usec / 1000;
  snprintf(buf, len, "[%02d:%02d:%02d:%03d] ",
	   tm->tm_hour, tm->tm_min, tm->tm_sec, ms);

  return buf;
}

static char *error_str(const int e,
		       char *(*error_itoa)(int),
		       char *buf, const size_t len)
{
  char *str;

  if(error_itoa == NULL || (str = error_itoa(e)) == NULL)
    {
      buf[0] = '\0';
      return buf;
    }

  snprintf(buf, len, ": %s", str);
  return buf;
}

/*
 * printerror
 *
 * format a nice and consistent error string using the errno to string
 * conversion utilities and the arguments supplied
 */
void printerror(const int ecode, char *(*error_itoa)(int),
		const char *func, const char *format, ...)
{
  char     message[512];
  char     err[128];
  char     ts[16];
  char     fs[64];
  va_list  ap;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  error_str(ecode, error_itoa, err, sizeof(err));
  timestamp_str(ts, sizeof(ts));

  if(func != NULL) snprintf(fs, sizeof(fs), "%s: ", func);
  else             fs[0] = '\0';

  fprintf(stderr, "%s%s%s%s\n", ts, fs, message, err);
  fflush(stderr);

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s%s%s%s\n", ts, fs, message, err);
      fflush(debugfile);
    }
#endif

  return;
}

#if !defined(NDEBUG) && !defined(WITHOUT_DEBUGFILE)
void scamper_debug(const char *func, const char *format, ...)
{
  char     message[512];
  va_list  ap;
  char     ts[16];
  char     fs[64];

  assert(format != NULL);

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  timestamp_str(ts, sizeof(ts));

  if(func != NULL) snprintf(fs, sizeof(fs), "%s: ", func);
  else             fs[0] = '\0';

  fprintf(stderr, "%s%s%s\n", ts, fs, message);
  fflush(stderr);

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s%s%s\n", ts, fs, message);
      fflush(debugfile);
    }
#endif

  return;
}
#endif

#ifndef WITHOUT_DEBUGFILE
int scamper_debug_open(const char *file)
{
  mode_t mode; 
  int flags = O_WRONLY | O_APPEND | O_CREAT | O_TRUNC;
  int fd;

#if defined(WITHOUT_PRIVSEP) && !defined(_WIN32)
  uid_t uid = getuid();
#endif

#ifndef _WIN32
  mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
#else
  mode = _S_IREAD | _S_IWRITE;
#endif

#ifndef WITHOUT_PRIVSEP
  fd = scamper_privsep_open_file(file, flags, mode);
#else
  fd = open(file, flags, mode);
#endif

  if(fd == -1)
    {
      printerror(errno, strerror, __func__,
		 "could not open debugfile %s", file);
      return -1;
    }

  if((debugfile = fdopen(fd, "a")) == NULL)
    {
      printerror(errno, strerror, __func__,
		 "could not fdopen debugfile %s", file);
      return -1;
    }

#if defined(WITHOUT_PRIVSEP) && !defined(_WIN32)
  if(uid != geteuid() && fchown(fd, uid, -1) != 0)
    {
      printerror(errno, strerror, __func__, "could not fchown");
    }
#endif

  return 0;
}

void scamper_debug_close()
{
  if(debugfile != NULL)
    {
      fclose(debugfile);
      debugfile = NULL;
    }
  return;
}
#endif
