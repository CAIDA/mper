/*
 * scamper_source_file.c
 *
 * $Id: scamper_source_file.c,v 1.8 2009/03/13 21:19:21 mjl Exp $
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

#include <sys/types.h>

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef int ssize_t;
#define __func__ __FUNCTION__
#endif

#ifndef _WIN32
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include <io.h>
#include <stdio.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#ifdef _WIN32
#define close _close
#define open _open
#define read _read
#define lseek _lseek
#define strdup _strdup
#endif

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_outfiles.h"
#include "scamper_task.h"
#include "scamper_sources.h"
#include "scamper_linepoll.h"
#include "scamper_fds.h"
#include "scamper_privsep.h"
#include "scamper_source_file.h"

#include "utils.h"

typedef struct scamper_source_file
{
  /* back-pointer to the parent source */
  scamper_source_t   *source;

  /* parameters for the file */
  char               *filename;
  char               *command;
  size_t              command_len;
  int                 cycles;
  int                 autoreload;

  /* run-time state */
  int                 reload;
  time_t              mtime;
  scamper_fd_t       *fd;
  scamper_linepoll_t *lp;

} scamper_source_file_t;

static int stdin_used = 0;

/*
 * ssf_free
 *
 * free up all resources related to an address-list-file.
 */
static void ssf_free(scamper_source_file_t *ssf)
{
  int fd = -1;

  if(ssf->lp != NULL)
    {
      scamper_linepoll_free(ssf->lp, 0);
      ssf->lp = NULL;
    }

  if(ssf->filename != NULL)
    {
      free(ssf->filename);
      ssf->filename = NULL;
    }

  if(ssf->command != NULL)
    {
      free(ssf->command);
      ssf->command = NULL;
    }

  if(ssf->fd != NULL)
    {
      fd = scamper_fd_fd_get(ssf->fd);
      scamper_fd_free(ssf->fd);
      ssf->fd = NULL;
    }

  if(fd != -1)
    {
      close(fd);
    }

  free(ssf);
  return;
}

static int ssf_open(const char *filename)
{
  int fd = -1;

  /* get a file descriptor to the file */
  if(strcmp(filename, "-") != 0)
    {
#if defined(WITHOUT_PRIVSEP)
      fd = open(filename, O_RDONLY);
#else
      fd = scamper_privsep_open_file(filename, O_RDONLY, 0);
#endif
    }
  else if(stdin_used == 0)
    {
      fd = 1;
      stdin_used = 1;
    }

  if(fd == -1)
    {
      goto err;
    }

#ifdef O_NONBLOCK
  if(fcntl_set(fd, O_NONBLOCK) == -1)
    {
      goto err;
    }
#endif

  return fd;

 err:
  if(fd != -1) close(fd);
  return -1;
}

/*
 * ssf_read_line
 *
 * this callback receives a single line per call, which should contain an
 * address in string form.  it combines that address with the source's
 * default command and then passes the string to source_command for further
 * processing.  the line eventually ends up in the commands queue.
 */
static int ssf_read_line(void *param, uint8_t *buf, size_t len)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)param;
  scamper_source_t *source = ssf->source;
  char *str = (char *)buf;
  char cmd_buf[256], *cmd = NULL;
  size_t reqd_len;

  /* make sure the string contains only printable characters */
  if(string_isprint(str, len) == 0)
    {
      goto err;
    }

  /* null terminate at these characters */
  string_nullterm(str, " \r\t#");
  len = strlen(str);

  /* make sure the line isn't blank or a comment line */
  if(str[0] == '\0' || str[0] == '#')
    {
      return 0;
    }

  /* figure out if the cmd_buf above is large enough */
  if(sizeof(cmd_buf) >= (reqd_len = ssf->command_len + 1 + len + 1))
    {
      cmd = cmd_buf;
    }
  else
    {
      if((cmd = malloc(reqd_len)) == NULL)
	{
	  goto err;
	}
    }

  /* build the command string */
  memcpy(cmd, ssf->command, ssf->command_len);
  cmd[ssf->command_len] = ' ';
  memcpy(cmd + ssf->command_len + 1, str, len+1);

  /* add the command to the source */
  if(scamper_source_command(source, cmd) != 0)
    {
      goto err;
    }

  if(cmd != cmd_buf) free(cmd);
  return 0;

 err:
  if(cmd != cmd_buf) free(cmd);
  return -1;
}

static void ssf_read(const int fd, void *param)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)param;
  scamper_source_t *source = ssf->source;
  uint8_t buf[1024];
  ssize_t rc;
  time_t mtime;
  int reload = 0;
  int newfd;

  assert(ssf->cycles != 0);

  if((rc = read(fd, buf, sizeof(buf))) > 0)
    {
      /* got data to read. parse the buffer for addresses, one per line. */
      scamper_linepoll_handle(ssf->lp, buf, (size_t)rc);

      /*
       * if probe queue for this source is sufficiently large, then
       * don't read any more for the time being
       */
      if(scamper_source_getcommandcount(source) >= scamper_pps_get())
	{
	  scamper_fd_read_pause(ssf->fd);
	}
    }
  else if(rc == 0 && ssf->cycles == 1)
    {
      /* got EOF; this is the last cycle over an input file */
      scamper_linepoll_flush(ssf->lp);
      ssf->cycles = 0;
      scamper_fd_read_pause(ssf->fd);
    }
  else if(rc == 0)
    {
      scamper_linepoll_flush(ssf->lp);

      /* a cycle value of -1 means cycle indefinitely */
      if(ssf->cycles != -1)
	{
	  ssf->cycles--;
	}

      /* decide if we should reload the file at this point */
      if(ssf->reload == 1)
	{
	  /* stat the file so we have an mtime value for later */
	  if(stat_mtime(ssf->filename, &mtime) == 0)
	    {
	      reload = 1;
	    }
	}
      else if(ssf->autoreload == 1)
	{
	  /*
	   * reload is conditional on being able to stat the file, and the
	   * mtime being different to whatever our record of the mtime is
	   */
	  if(stat_mtime(ssf->filename, &mtime) == 0 && ssf->mtime != mtime)
	    {
	      reload = 1;
	    }
	}

      /* we have to reload the file (if we can open it) */
      if(reload == 1 && (newfd = ssf_open(ssf->filename)) != -1)
	{
	  /* use the new file descriptor */
	  if(scamper_fd_fd_set(ssf->fd, newfd) == -1)
	    {
	      goto err;
	    }

	  /* close the existing file */
	  close(fd);

	  /* update file details; ensure reload is reset to zero */
	  ssf->mtime = mtime;
	  ssf->reload = 0;
	}
      else
	{
	  /* rewind the current file position */
	  if(lseek(fd, 0, SEEK_SET) == -1)
	    {
	      goto err;
	    }
	}

      /* check to see if we should pause, or allow reading to continue */
      if(scamper_source_getcyclecount(ssf->source) < 1)
	{
	  scamper_fd_read_unpause(ssf->fd);
	}
      else
	{
	  scamper_fd_read_pause(ssf->fd);
	}

      /* create a new cycle record, etc */
      if(scamper_source_cycle(source) != 0)
	{
	  goto err;
	}
    }
  else
    {
      assert(rc == -1);

      if(errno != EAGAIN && errno != EINTR)
	{
	  printerror(errno, strerror, __func__, "read failed");
	  goto err;
	}
    }

  return;

 err:
  /*
   * an error occurred.  the simplest way to cause the source to disappear
   * gracefully is to set the cycles parameter to zero, which will signal
   * to the sources code that there are no more commands to come
   */
  ssf->cycles = 0;
  return;
}

/*
 * ssf_take
 *
 * this function is used to quench the source from sending more commands
 */
static int ssf_take(void *data)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)data;

  if(scamper_source_getcyclecount(ssf->source) < 2 &&
     scamper_source_getcommandcount(ssf->source) < scamper_pps_get() &&
     ssf->cycles != 0)
    {
      scamper_fd_read_unpause(ssf->fd);
    }

  return 0;
}

static void ssf_freedata(void *data)
{
  ssf_free((scamper_source_file_t *)data);
  return;
}

/*
 * ssf_isfinished
 *
 * advise the caller if the source may be supplying more commands or not.
 * in the address-list-file case, more addresses will be supplied until
 * the cycles count reaches zero.
 */
static int ssf_isfinished(void *data)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)data;

  if(ssf->cycles != 0)
    {
      return 0;
    }

  return 1;
}

int scamper_source_file_getcycles(const scamper_source_t *source)
{
  scamper_source_file_t *ssf;

  if((ssf = (scamper_source_file_t *)scamper_source_getdata(source)) != NULL)
    {
      return ssf->cycles;
    }

  return -1;
}

int scamper_source_file_getautoreload(const scamper_source_t *source)
{
  scamper_source_file_t *ssf;

  if((ssf = (scamper_source_file_t *)scamper_source_getdata(source)) != NULL)
    {
      return ssf->autoreload;
    }

  return -1;
}

const char *scamper_source_file_getfilename(const scamper_source_t *source)
{
  scamper_source_file_t *ssf;

  if((ssf = (scamper_source_file_t *)scamper_source_getdata(source)) != NULL)
    {
      return ssf->filename;
    }

  return NULL;
}

int scamper_source_file_update(scamper_source_t *source,
			       const int *autoreload, const int *cycles)
{
  scamper_source_file_t *ssf;
  scamper_source_event_t sse;

  if(scamper_source_gettype(source) != SCAMPER_SOURCE_TYPE_FILE ||
     (ssf = (scamper_source_file_t *)scamper_source_getdata(source)) == NULL)
    {
      return -1;
    }

  memset(&sse, 0, sizeof(sse));

  if(autoreload != NULL)
    {
      sse.sse_update_flags |= 0x01;
      sse.sse_update_autoreload = *autoreload;
      ssf->autoreload = *autoreload;
    }

  if(cycles != NULL)
    {
      sse.sse_update_flags |= 0x02;
      sse.sse_update_cycles = *cycles;
      ssf->cycles = *cycles;
    }

  if(sse.sse_update_flags != 0)
    {
      scamper_source_event_post(source, SCAMPER_SOURCE_EVENT_UPDATE, &sse);
    }

  return 0;
}

scamper_source_t *scamper_source_file_alloc(scamper_source_params_t *ssp,
					    const char *filename,
					    const char *command,
					    int cycles, int autoreload)
{
  scamper_source_file_t *ssf = NULL;
  int fd = -1;

  /* sanity checks */
  if(ssp == NULL || filename == NULL)
    {
      goto err;
    }

  /* allocate the structure for keeping track of the address list file */
  if((ssf = malloc_zero(sizeof(scamper_source_file_t))) == NULL ||
     (ssf->filename = strdup(filename)) == NULL)
    {
      goto err;
    }
  ssf->cycles     = cycles;
  ssf->autoreload = autoreload;

  /* addresses are matched with a command to execute */
  if((ssf->command = strdup(command != NULL ?
			    command : scamper_command_get())) == NULL)
    {
      goto err;
    }
  ssf->command_len = strlen(ssf->command);

  if((fd = ssf_open(filename)) == -1)
    {
      goto err;
    }

  /* allocate a scamper_fd_t to monitor when new data is able to be read */
  if((ssf->fd = scamper_fd_private(fd, ssf_read, ssf, NULL, NULL)) == NULL)
    {
      goto err;
    }
  fd = -1;

  if((ssf->lp = scamper_linepoll_alloc(ssf_read_line, ssf)) == NULL)
    {
      goto err;
    }

  /*
   * data and callback functions that scamper_source_alloc needs to know about
   */
  ssp->data        = ssf;
  ssp->take        = ssf_take;
  ssp->freedata    = ssf_freedata;
  ssp->isfinished  = ssf_isfinished;
  ssp->type        = SCAMPER_SOURCE_TYPE_FILE;

  /* allocate the parent source structure */
  if((ssf->source = scamper_source_alloc(ssp)) == NULL)
    {
      goto err;
    }

  return ssf->source;

 err:
  assert(ssf->source == NULL);
  if(ssf != NULL) ssf_free(ssf);
  return NULL;
}
