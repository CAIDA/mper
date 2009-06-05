/*
 * scamper_file.c
 *
 * $Id: scamper_file.c,v 1.42 2009/02/27 07:09:42 mjl Exp $
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

#ifdef _WIN32
#include <winsock2.h>
#include <time.h>
#include <io.h>
#define close _close
#define strcasecmp _stricmp
#define strdup _strdup
#define open _open
#define STDIN_FILENO 0
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define S_IFIFO _S_IFIFO
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#endif 

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include <assert.h>

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_trace.h"
#include "scamper_ping.h"
#include "scamper_tracelb.h"
#include "scamper_sting.h"
#include "scamper_dealias.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_file_traceroute.h"
#include "scamper_file_arts.h"
#include "utils.h"

#define SCAMPER_FILE_NONE       (-1)
#define SCAMPER_FILE_TRACEROUTE  0
#define SCAMPER_FILE_ARTS        1
#define SCAMPER_FILE_WARTS       2

struct scamper_file
{
  char                     *filename;
  int                       fd;
  void                     *state;
  int                       type;
  char                      error_str[256];
  uint32_t                  capability;
  int                       eof;
  scamper_file_writefunc_t  writefunc;
  void                     *writeparam;
};

struct scamper_file_filter
{
  uint32_t *flags;
  uint16_t  max;
};

struct handler
{
  char *type;
  int (*detect)(const scamper_file_t *sf);

  int (*init_read)(scamper_file_t *sf);
  int (*init_write)(scamper_file_t *sf);
  int (*init_append)(scamper_file_t *sf);

  int (*read)(scamper_file_t *sf, scamper_file_filter_t *filter,
	      uint16_t *type, void **data);

  int (*write_trace)(const scamper_file_t *sf,
		     const scamper_trace_t *trace);

  int (*write_cycle_start)(const scamper_file_t *sf,
			   scamper_cycle_t *cycle);

  int (*write_cycle_stop)(const scamper_file_t *sf,
			  scamper_cycle_t *cycle);

  int (*write_ping)(const scamper_file_t *sf,
		    const scamper_ping_t *ping);

  int (*write_tracelb)(const scamper_file_t *sf,
		       const scamper_tracelb_t *trace);

  int (*write_sting)(const scamper_file_t *sf,
		     const scamper_sting_t *sting);

  int (*write_dealias)(const scamper_file_t *sf,
		       const scamper_dealias_t *deal);

  void (*free_state)(scamper_file_t *sf);
};

static struct handler handlers[] = {
  {"traceroute",                         /* type */
   scamper_file_traceroute_is,           /* detect */
   scamper_file_traceroute_init_read,    /* init_read */
   NULL,                                 /* init_write */
   NULL,                                 /* init_append */
   NULL,                                 /* read */
   scamper_file_traceroute_write_trace,  /* write_trace */
   NULL,                                 /* write_cycle_start */
   NULL,                                 /* write_cycle_stop */
   scamper_file_traceroute_write_ping,   /* write_ping */
   scamper_file_traceroute_write_tracelb,/* write_tracelb */
   scamper_file_traceroute_write_sting,  /* write_sting */
   NULL,                                 /* write_dealias */
   scamper_file_traceroute_free_state,   /* free_state */
  },
  {"arts",                               /* type */
   scamper_file_arts_is,                 /* detect */
   scamper_file_arts_init_read,          /* init_read */
   NULL,                                 /* init_write */
   NULL,                                 /* init_append */
   scamper_file_arts_read,               /* read */
   NULL,                                 /* write_trace */
   NULL,                                 /* write_cycle_start */
   NULL,                                 /* write_cycle_stop */
   NULL,                                 /* write_ping */
   NULL,                                 /* write_tracelb */
   NULL,                                 /* write_sting */
   NULL,                                 /* write_dealias */
   scamper_file_arts_free_state,         /* free_state */
  },
  {"warts",                              /* type */
   scamper_file_warts_is,                /* detect */
   scamper_file_warts_init_read,         /* init_read */
   scamper_file_warts_init_write,        /* init_write */
   scamper_file_warts_init_append,       /* init_append */
   scamper_file_warts_read,              /* read */
   scamper_file_warts_write_trace,       /* write_trace */
   scamper_file_warts_write_cycle_start, /* write_cycle_start */
   scamper_file_warts_write_cycle_stop,  /* write_cycle_stop */
   scamper_file_warts_write_ping,        /* write_ping */
   scamper_file_warts_write_tracelb,     /* write_tracelb */
   NULL,                                 /* write_sting */
   scamper_file_warts_write_dealias,     /* write_dealias */
   scamper_file_warts_free_state,        /* free_state */
  }
};

static int handler_cnt = sizeof(handlers) / sizeof(struct handler);

int scamper_file_getfd(const scamper_file_t *sf)
{
  return sf->fd;
}

void *scamper_file_getstate(const scamper_file_t *sf)
{
  return sf->state;
}

char *scamper_file_getfilename(scamper_file_t *sf)
{
  return sf->filename;
}

void scamper_file_setstate(scamper_file_t *sf, void *state)
{
  sf->state = state;
  return;
}

void scamper_file_setwritefunc(scamper_file_t *sf,
			       void *param, scamper_file_writefunc_t wf)
{
  sf->writefunc  = wf;
  sf->writeparam = param;
  return;
}

scamper_file_writefunc_t scamper_file_getwritefunc(const scamper_file_t *sf)
{
  return sf->writefunc;
}

void *scamper_file_getwriteparam(const scamper_file_t *sf)
{
  return sf->writeparam;
}

int scamper_file_write_trace(scamper_file_t *sf, const scamper_trace_t *trace)
{
  int rc = -1;

  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_trace != NULL)
    {
      rc = handlers[sf->type].write_trace(sf, trace);
    }

  return rc;
}

int scamper_file_write_ping(scamper_file_t *sf, const scamper_ping_t *ping)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_ping != NULL)
    {
      return handlers[sf->type].write_ping(sf, ping);
    }
  return -1;
}

int scamper_file_write_tracelb(scamper_file_t *sf,
			       const scamper_tracelb_t *trace)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_tracelb != NULL)
    {
      return handlers[sf->type].write_tracelb(sf, trace);
    }
  return -1;
}

int scamper_file_write_sting(scamper_file_t *sf,
			     const scamper_sting_t *sting)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_sting != NULL)
    {
      return handlers[sf->type].write_sting(sf, sting);
    }
  return -1;
}

int scamper_file_write_dealias(scamper_file_t *sf,
			       const scamper_dealias_t *dealias)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_dealias != NULL)
    {
      return handlers[sf->type].write_dealias(sf, dealias);
    }
  return -1;
}

/*
 * scamper_file_read
 *
 *
 */
int scamper_file_read(scamper_file_t *sf, scamper_file_filter_t *filter,
		      uint16_t *type, void **object)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].read != NULL)
    {
      return handlers[sf->type].read(sf, filter, type, object);
    }

  return -1;
}

/*
 * scamper_file_filter_isset
 *
 * check to see if the particular type is set in the filter or not
 */
int scamper_file_filter_isset(scamper_file_filter_t *filter, uint16_t type)
{
  if(filter == NULL || type > filter->max)
    {
      return 0;
    }

  if((filter->flags[type/32] & (0x1 << ((type%32)-1))) == 0)
    {
      return 0;
    }

  return 1;
}

/*
 * scamper_file_filter_alloc
 *
 * allocate a filter for reading data objects from scamper files based on an
 * array of types the caller is interested in.
 */
scamper_file_filter_t *scamper_file_filter_alloc(uint16_t *types, uint16_t num)
{
  scamper_file_filter_t *filter = NULL;
  size_t size;
  int i, j, k;

  /* sanity checks */
  if(types == NULL || num == 0)
    {
      goto err;
    }

  /* allocate filter structure which will be returned to caller */
  if((filter = malloc_zero(sizeof(scamper_file_filter_t))) == NULL)
    {
      goto err;
    }

  /* first, figure out the maximum type value of interest */
  for(i=0; i<num; i++)
    {
      /* sanity check */
      if(types[i] == 0)
	{
	  goto err;
	}
      if(types[i] > filter->max)
	{
	  filter->max = types[i];
	}
    }

  /* sanity check */
  if(filter->max == 0)
    {
      goto err;
    }

  /* allocate the flags array */
  size = sizeof(uint32_t) * filter->max / 32;
  if((filter->max % 32) != 0) size += sizeof(uint32_t);
  if((filter->flags = malloc_zero(size)) == NULL)
    {
      goto err;
    }

  /* go through each type and set the appropriate flag */
  for(i=0; i<num; i++)
    {
      if(types[i] % 32 == 0)
	{
	  j = ((types[i]) / 32) - 1;
	  k = 32;
	}
      else
	{
	  j = types[i] / 32;
	  k = types[i] % 32;
	}

      filter->flags[j] |= (0x1 << (k-1));
    }

  return filter;

 err:
  if(filter != NULL)
    {
      if(filter->flags != NULL) free(filter->flags);
      free(filter);
    }
  return NULL;
}

void scamper_file_filter_free(scamper_file_filter_t *filter)
{
  if(filter != NULL)
    {
      if(filter->flags != NULL) free(filter->flags);
      free(filter);
    }

  return;
}

int scamper_file_write_cycle_start(scamper_file_t *sf, scamper_cycle_t *cycle)
{
  if(sf->type != SCAMPER_FILE_NONE &&
     handlers[sf->type].write_cycle_start != NULL)
    {
      return handlers[sf->type].write_cycle_start(sf, cycle);
    }
  return -1;
}

int scamper_file_write_cycle_stop(scamper_file_t *sf, scamper_cycle_t *cycle)
{
  if(sf->type != SCAMPER_FILE_NONE &&
     handlers[sf->type].write_cycle_stop != NULL)
    {
      return handlers[sf->type].write_cycle_stop(sf, cycle);
    }
  return -1;
}

/*
 * scamper_file_geteof
 *
 */
int scamper_file_geteof(scamper_file_t *sf)
{
  if(sf == NULL || sf->fd == -1) return -1;
  return sf->eof;
}

/*
 * scamper_file_seteof
 *
 */
void scamper_file_seteof(scamper_file_t *sf)
{
  if(sf != NULL && sf->fd != -1)
    sf->eof = 1;
  return;
}

/*
 * scamper_file_free
 *
 */
void scamper_file_free(scamper_file_t *sf)
{
  if(sf != NULL)
    {
      if(sf->filename) free(sf->filename);
      free(sf);
    }
  return;
}

/*
 * scamper_file_close
 *
 */
void scamper_file_close(scamper_file_t *sf)
{
  /* free state associated with the type of scamper_file_t */
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].free_state != NULL)
    {
      handlers[sf->type].free_state(sf);
    }

  /* close the file descriptor */
  if(sf->fd != -1)
    {
      close(sf->fd);
    }

  /* free general state associated */
  scamper_file_free(sf);

  return;
}

char *scamper_file_type_tostr(scamper_file_t *sf, char *buf, size_t len)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].type != NULL)
    {
      strncpy(buf, handlers[sf->type].type, len);
      return buf;
    }

  return NULL;
}

static int file_type_get(char *type)
{
  int i;

  if(type != NULL)
    {
      for(i=0; i<handler_cnt; i++)
	{
	  if(strcasecmp(type, handlers[i].type) == 0)
	    {
	      return i;
	    }
	}
    }

  return SCAMPER_FILE_NONE;
}

static int file_type_detect(scamper_file_t *sf)
{
  int i;

  for(i=0; i<handler_cnt; i++)
    {
      if(handlers[i].detect(sf) == 1)
	{
	  return i;
	}
    }

  return SCAMPER_FILE_NONE;
}

static int file_open_read(scamper_file_t *sf)
{
  struct stat sb;

  if(fstat(sf->fd, &sb) != 0)
    {
      return -1;
    }

  if(sb.st_size != 0 && (sb.st_mode & S_IFIFO) == 0 &&
     (sf->type = file_type_detect(sf)) == SCAMPER_FILE_NONE)
    {
      return -1;
    }

  if(handlers[sf->type].init_read != NULL)
    {
      return handlers[sf->type].init_read(sf);
    }

  return 0;
}

static int file_open_write(scamper_file_t *sf)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].init_write != NULL)
    {
      return handlers[sf->type].init_write(sf);
    }

  return 0;
}

static int file_open_append(scamper_file_t *sf)
{
  struct stat sb;

  if(fstat(sf->fd, &sb) != 0)
    {
      return -1;
    }

  if(sb.st_size == 0)
    {
      /* can only write warts and ascii files */
      if(sf->type == SCAMPER_FILE_WARTS)
	{
	  return handlers[sf->type].init_write(sf);
	}
      else if(sf->type == SCAMPER_FILE_TRACEROUTE)
	{
	  return 0;
	}
      return -1;
    }

  /* can't append to pipes */
  if((sb.st_mode & S_IFIFO) != 0)
    {
      return -1;
    }

  sf->type = file_type_detect(sf);
  if(handlers[sf->type].init_append != NULL)
    {
      return handlers[sf->type].init_append(sf);
    }
  else if(sf->type != SCAMPER_FILE_WARTS &&
	  sf->type != SCAMPER_FILE_TRACEROUTE)
    {
      return -1;
    }

  return 0;
}

static scamper_file_t *file_open(int fd, char *fn, char mode, int type)
{
  scamper_file_t *sf;
  int (*open_func)(scamper_file_t *);

  if(mode == 'r')      open_func = file_open_read;
  else if(mode == 'w') open_func = file_open_write;
  else if(mode == 'a') open_func = file_open_append;
  else return NULL;

  if((sf = (scamper_file_t *)malloc_zero(sizeof(scamper_file_t))) == NULL)
    {
      return NULL;
    }

  sf->type = type;
  sf->fd   = fd;

  if(fn != NULL && (sf->filename = strdup(fn)) == NULL)
    {
      return NULL;
    }

  if(open_func(sf) == -1)
    {
      scamper_file_close(sf);
      return NULL;
    }

  return sf;
}

scamper_file_t *scamper_file_openfd(int fd, char *fn, char mode, char *type)
{
  return file_open(fd, fn, mode, file_type_get(type));
}

/*
 * scamper_file_open
 *
 * open the file specified with the appropriate mode.
 * the modes that we know about are 'r' read-only, 'w' write-only on a
 * brand new file, and 'a' for appending.
 *
 * in 'w' mode [and conditionally for 'a'] an optional parameter may be
 * supplied that says what type of file should be written.
 *  'w' for warts
 *  't' for ascii traceroute
 *  'a' for arts [not implemented]
 *
 * when a file is opened for appending, this second parameter is only
 * used when the file is empty so that writes will be written in the
 * format expected.
 */
scamper_file_t *scamper_file_open(char *filename, char mode, char *type)
{
  scamper_file_t *sf;
  int ft = file_type_get(type);
  int flags = 0;
  int fd = -1;

  if(mode == 'r')
    {
      if(strcmp(filename, "-") == 0)
	{
	  fd = STDIN_FILENO;
	}
      else
	{
	  flags = O_RDONLY;
	}
    }
  else if(mode == 'w' || mode == 'a')
    {
      /* sanity check the type of file to be written */
      if(ft == SCAMPER_FILE_NONE || ft == SCAMPER_FILE_ARTS)
	{
	  return NULL;
	}

      if(strcmp(filename, "-") == 0)
	{
	  fd = STDIN_FILENO;
	}
      else
	{
	  if(mode == 'w') flags = O_WRONLY | O_TRUNC | O_CREAT;
	  else            flags = O_RDWR | O_APPEND | O_CREAT;
	}
    }
  else
    {
      return NULL;
    }

#ifdef _WIN32
  flags |= O_BINARY;
#endif

  if(fd == -1)
    {
      if(mode == 'r') fd = open(filename, flags);
      else            fd = open(filename, flags, S_IRUSR | S_IWUSR);

      if(fd == -1)
	{
	  return NULL;
	}
    }

  sf = file_open(fd, filename, mode, ft);

  return sf;
}
