/*
 * scamper_outfiles: hold a collection of output targets together
 *
 * $Id: scamper_outfiles.c,v 1.31 2009/03/13 21:03:45 mjl Exp $
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

#include <sys/stat.h>
#include <sys/types.h>

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef int mode_t;
#define __func__ __FUNCTION__
#endif

#ifdef _WIN32
#include <io.h>
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#endif

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#define close _close
#define fileno _fileno
#define open _open
#define strcasecmp _stricmp
#define strdup _strdup
#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_debug.h"
#include "scamper_file.h"
#include "scamper_privsep.h"
#include "scamper_outfiles.h"
#include "utils.h"
#include "mjl_splaytree.h"

struct scamper_outfile
{
  char           *name;
  scamper_file_t *sf;
  int             refcnt;
};

static struct splaytree  *outfiles;
static scamper_outfile_t *outfile_def;

static int outfile_cmp(const void *a, const void *b)
{
  return strcasecmp(((const scamper_outfile_t *)b)->name,
		    ((const scamper_outfile_t *)a)->name);
}

static scamper_outfile_t *outfile_alloc(char *name, scamper_file_t *sf)
{
  scamper_outfile_t *sof = NULL;

  if((sof = malloc_zero(sizeof(scamper_outfile_t))) == NULL)
    {
      goto err;
    }

  sof->sf = sf;
  sof->refcnt = 1;

  if((sof->name = strdup(name)) == NULL)
    {
      goto err;
    }

  if(splaytree_insert(outfiles, sof) == NULL)
    {
      goto err;
    }

  return sof;

 err:
  if(sof != NULL)
    {
      if(sof->name != NULL) free(sof->name);
      free(sof);
    }
  return NULL;
}

static void outfile_free(scamper_outfile_t *sof)
{
  if(sof->name != NULL)
    {
      splaytree_remove_item(outfiles, sof);
      free(sof->name);
    }

  if(sof->sf != NULL)
    {
      scamper_file_close(sof->sf);
    }

  free(sof);
  return;
}

int scamper_outfile_getrefcnt(const scamper_outfile_t *sof)
{
  return sof->refcnt;
}

scamper_file_t *scamper_outfile_getfile(scamper_outfile_t *sof)
{
  return sof->sf;
}

const char *scamper_outfile_getname(const scamper_outfile_t *sof)
{
  return sof->name;
}

scamper_outfile_t *scamper_outfile_use(scamper_outfile_t *sof)
{
  if(sof != NULL)
    {
      sof->refcnt++;
    }
  return sof;
}

void scamper_outfile_free(scamper_outfile_t *sof)
{
  assert(sof->refcnt > 0);

  if(--sof->refcnt == 0)
    {
      outfile_free(sof);
    }

  return;
}

int scamper_outfile_close(scamper_outfile_t *sof)
{
  if(sof->refcnt > 1)
    {
      return -1;
    }

  outfile_free(sof);

  return 0;
}

scamper_outfile_t *scamper_outfiles_get(const char *name)
{
  const scamper_outfile_t findme = {(char *)name, NULL, 0};
  scamper_outfile_t *sof;

  if(name == NULL)
    {
      return outfile_def;
    }

  sof = splaytree_find(outfiles, &findme);
  return sof;
}

/*
 * scamper_outfiles_swap
 *
 * swap the files around.  the name and refcnt parameters are unchanged.
 */
void scamper_outfiles_swap(scamper_outfile_t *a, scamper_outfile_t *b)
{
  scamper_file_t *sf;

  sf = b->sf;
  b->sf = a->sf;
  a->sf = sf;

  return;
}

scamper_outfile_t *scamper_outfile_open(char *name, char *file, char *mo)
{
  scamper_outfile_t *sof;
  scamper_file_t *sf;
  int flags;
  mode_t mode;
  char sf_mode;
  int fd;

#if defined(WITHOUT_PRIVSEP) && !defined(_WIN32)
  uid_t uid = getuid();
#endif

  if(name == NULL || file == NULL || mo == NULL)
    {
      return NULL;
    }

  if((sof = scamper_outfiles_get(name)) != NULL)
    {
      return NULL;
    }

  if(strcasecmp(mo, "append") == 0)
    {
      flags = O_RDWR | O_APPEND | O_CREAT;
      sf_mode = 'a';
    }
  else if(strcasecmp(mo, "truncate") == 0)
    {
      flags = O_WRONLY | O_TRUNC | O_CREAT;
      sf_mode = 'w';
    }
  else
    {
      return NULL;
    }

  mode = S_IRUSR | S_IWUSR;
#if defined(WITHOUT_PRIVSEP)
  fd = open(file, flags, mode);
#else
  fd = scamper_privsep_open_file(file, flags, mode);
#endif

  /* make sure the fd is valid, otherwise bail */
  if(fd == -1)
    {
      return NULL;
    }

#if defined(WITHOUT_PRIVSEP) && !defined(_WIN32)
  if(uid != geteuid() && fchown(fd, uid, -1) != 0)
    {
      printerror(errno, strerror, __func__, "could not fchown");
    }
#endif

  if((sf = scamper_file_openfd(fd, file, sf_mode, "warts")) == NULL)
    {
      close(fd);
      return NULL;
    }

  if((sof = outfile_alloc(name, sf)) == NULL)
    {
      scamper_file_close(sf);
      return NULL;
    }

  return sof;
}

static int outfile_opendef(char *filename, char *type)
{
  scamper_file_t *sf;
  int flags;
  mode_t mode;
  char sf_mode;
  int fd;

  flags = O_WRONLY | O_TRUNC | O_CREAT;
  sf_mode = 'w';
  mode = S_IRUSR | S_IWUSR;

  if(strcmp(filename, "-") == 0)
    {
      fd = fileno(stdout);
    }
  else
    {
#if defined(WITHOUT_PRIVSEP)
      fd = open(filename, flags, mode);
#else
      fd = scamper_privsep_open_file(filename, flags, mode);
#endif
    }

  if(fd == -1)
    {
      return -1;
    }

  if((sf = scamper_file_openfd(fd, filename, sf_mode, type)) == NULL)
    {
      close(fd);
      return -1;
    }

  if((outfile_def = outfile_alloc(filename, sf)) == NULL)
    {
      scamper_file_close(sf);
      return -1;
    }

  return 0;
}

scamper_outfile_t *scamper_outfile_openfd(char *name, int fd, char *type)
{
  scamper_outfile_t *sof = NULL;
  scamper_file_t *sf = NULL;

  if(fd == -1)
    {
      return NULL;
    }

  if((sf = scamper_file_openfd(fd, NULL, 'w', type)) == NULL)
    {
      return NULL;
    }

  if((sof = outfile_alloc(name, sf)) == NULL)
    {
      scamper_file_free(sf);
      return NULL;
    }

  return sof;
}

void scamper_outfiles_foreach(void *p,
			      int (*func)(void *p, scamper_outfile_t *sof))
{
  splaytree_inorder(outfiles, (splaytree_inorder_t)func, p);
  return;
}

int scamper_outfiles_init(char *def_filename, char *def_type)
{
  if((outfiles = splaytree_alloc(outfile_cmp)) == NULL)
    {
      return -1;
    }

  if(outfile_opendef(def_filename, def_type) != 0)
    {
      return -1;
    }

  return 0;
}

void scamper_outfiles_cleanup()
{
  if(outfile_def != NULL)
    {
      if(--outfile_def->refcnt > 0)
	{
	  scamper_debug(__func__,
			"default outfile refcnt %d", outfile_def->refcnt);
	}

      outfile_free(outfile_def);
      outfile_def = NULL;
    }

  if(outfiles != NULL)
    {
      splaytree_free(outfiles, NULL);
      outfiles = NULL;
    }

  return;
}
