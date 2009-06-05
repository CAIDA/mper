/*
 * warts-cat
 *
 * This is a utility program to concatenate warts data files together.
 *
 * $Id: warts-cat.c,v 1.10 2008/12/14 21:52:30 mjl Exp $
 *
 * Copyright (C) 2007 The University of Waikato
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

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tlv.h"
#include "scamper_trace.h"
#include "scamper_tracelb.h"
#include "scamper_ping.h"
#include "scamper_dealias.h"
#include "scamper_file.h"
#include "mjl_heap.h"
#include "utils.h"

#define OPT_OUTFILE 0x00000001 /* o: */
#define OPT_SORT    0x00000002 /* s: */
#define OPT_HELP    0x00000004 /* ?: */

static uint32_t                options    = 0;
static int                     infile_cnt = 0;
static scamper_file_t        **infiles    = NULL;
static scamper_file_t         *outfile    = NULL;
static scamper_file_filter_t  *filter     = NULL;

/*
 * sort_struct
 *
 * structure that is used when warts-cat has to sort input data items.
 */
typedef struct sort_struct
{
  /* type type and data just read from the file */
  uint16_t        type;
  void           *data;

  /* timestamp associated with the data object */
  struct timeval  tv;

  /* index into infiles array */
  int             file;
} sort_struct_t;

static void usage(const char *argv0, uint32_t opt_mask)
{
  fprintf(stderr, "usage: %s [-?] [-o outfile] <infile 1, 2, .. N>\n", argv0);

  if(opt_mask == 0) return;

  fprintf(stderr, "\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "    -? give an overview of the usage of sc_sorter\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "    -o output file to concatenate to\n");

  if(opt_mask & OPT_SORT)
    fprintf(stderr, "    -s sort objects in input file by timestamp\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  char  ch;
  int   i;
  char *opts = "o:s?";
  char *opt_outfile = NULL;

  while((i = getopt(argc, argv, opts)) != -1)
    {
      ch = (char)i;
      switch(ch)
	{
	case 'o':
	  options |= OPT_OUTFILE;
	  opt_outfile = optarg;
	  break;

	case 's':
	  options |= OPT_SORT;
	  break;

	case '?':
	default:
	  usage(argv[0], 0xffffffff);
	  return -1;
	}
    }

  /* figure out how many input files there are to process */
  if((infile_cnt = argc - optind) < 1)
    {
      usage(argv[0], 0);
      return -1;
    }
  if((infiles = malloc(sizeof(scamper_file_t *) * infile_cnt)) == NULL)
    {
      return -1;
    }
  memset(infiles, 0, sizeof(scamper_file_t *) * infile_cnt);

  /* open each input file */
  for(i=0; i<infile_cnt; i++)
    {
      if((infiles[i] = scamper_file_open(argv[optind+i], 'r', NULL)) == NULL)
	{
	  usage(argv[0], 0);
	  fprintf(stderr, "could not open infile %s\n", argv[optind+i]);
	  return -1;
	}
    }

  /* open the output file, which is a regular file */
  if(options & OPT_OUTFILE)
    {
      if((outfile = scamper_file_open(opt_outfile, 'a', "warts")) == NULL)
	{
	  usage(argv[0], OPT_OUTFILE);
	  return -1;
	}
    }
  else
    {
      /* writing to stdout; don't dump a binary structure to a tty. */
      if(isatty(1) != 0)
	{
	  fprintf(stderr, "not going to dump warts to a tty, sorry\n");
	  return -1;
	}

      if((outfile = scamper_file_openfd(1, "-", 'w', "warts")) == NULL)
	{
	  fprintf(stderr, "could not wrap scamper_file around stdout\n");
	  return -1;
	}
    }

  return 0;
}

static void cleanup(void)
{
  int i;

  if(filter != NULL)
    {
      scamper_file_filter_free(filter);
      filter = NULL;
    }

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  if(infiles != NULL)
    {
      for(i=0; i<infile_cnt; i++)
	{
	  if(infiles[i] != NULL)
	    {
	      scamper_file_close(infiles[i]);
	      infiles[i] = NULL;
	    }
	}
      free(infiles);
    }

  return;
}

static int write_obj(uint16_t type, void *data)
{
  /* write the object out */
  switch(type)
    {
    case SCAMPER_FILE_OBJ_TRACELB:
      if(scamper_file_write_tracelb(outfile, data) != 0)
	return -1;
      scamper_tracelb_free(data);
      break;

    case SCAMPER_FILE_OBJ_TRACE:
      if(scamper_file_write_trace(outfile, data) != 0)
	return -1;
      scamper_trace_free(data);
      break;

    case SCAMPER_FILE_OBJ_PING:
      if(scamper_file_write_ping(outfile, data) != 0)
	return -1;
      scamper_ping_free(data);
      break;

    case SCAMPER_FILE_OBJ_DEALIAS:
      if(scamper_file_write_dealias(outfile, data) != 0)
	return -1;
      scamper_dealias_free(data);
      break;

    case SCAMPER_FILE_OBJ_CYCLE_START:
      if(scamper_file_write_cycle_start(outfile, data) != 0)
	return -1;
      scamper_cycle_free(data);
      break;

    case SCAMPER_FILE_OBJ_CYCLE_STOP:
      if(scamper_file_write_cycle_stop(outfile, data) != 0)
	return -1;
      scamper_cycle_free(data);
      break;

    default:
      fprintf(stderr, "unhandled data object 0x%04x\n", type);
      break;
    }

  return 0;
}

static int simple_cat(void)
{
  uint16_t type;
  void *data;
  int i, rc;

  for(i=0; i<infile_cnt; i++)
    {
      while((rc = scamper_file_read(infiles[i], filter, &type, &data)) == 0)
	{
	  /* EOF */
	  if(data == NULL)
	    break;

	  if(write_obj(type, data) != 0)
	    {
	      return -1;
	    }
	}

      /* error when reading the input file */
      if(rc != 0)
	{
	  return -1;
	}

      scamper_file_close(infiles[i]);
      infiles[i] = NULL;
    }

  return 0;
}

/*
 * sort_struct_cmp
 *
 * prioritise sort_struct objects for output to file.
 */
static int sort_struct_cmp(const void *va, const void *vb)
{
  const sort_struct_t *a = (const sort_struct_t *)va;
  const sort_struct_t *b = (const sort_struct_t *)vb;
  int i;

  if((i = timeval_cmp(&b->tv, &a->tv)) != 0)
    {
      return i;
    }

  /* if timestamps are identical, cycle start objects have first priority */
  if(a->type == SCAMPER_FILE_OBJ_CYCLE_START)
    {
      if(b->type == SCAMPER_FILE_OBJ_CYCLE_START) return 0;
      else return 1;
    }
  if(b->type == SCAMPER_FILE_OBJ_CYCLE_START) return -1;

  /* if timestamps are identical, cycle start objects have second priority */
  if(a->type == SCAMPER_FILE_OBJ_CYCLE_STOP)
    {
      if(b->type == SCAMPER_FILE_OBJ_CYCLE_STOP) return 0;
      else return 1;
    }
  if(b->type == SCAMPER_FILE_OBJ_CYCLE_STOP) return -1;

  return 0;
}

static int sort_cat_fill(heap_t *heap, sort_struct_t *s)
{
  int i = s->file;

  if(scamper_file_read(infiles[i], filter, &s->type, &s->data) == 0)
    {
      /* EOF */
      if(s->data == NULL)
	{
	  scamper_file_close(infiles[i]);
	  infiles[i] = NULL;
	  return 0;
	}

      switch(s->type)
	{
	case SCAMPER_FILE_OBJ_TRACELB:
	  timeval_cpy(&s->tv, &((scamper_tracelb_t *)s->data)->start);
	  break;

	case SCAMPER_FILE_OBJ_TRACE:
	  timeval_cpy(&s->tv, &((scamper_trace_t *)s->data)->start);
	  break;

	case SCAMPER_FILE_OBJ_PING:
	  timeval_cpy(&s->tv, &((scamper_ping_t *)s->data)->start);
	  break;

	case SCAMPER_FILE_OBJ_DEALIAS:
	  timeval_cpy(&s->tv, &((scamper_dealias_t *)s->data)->start);
	  break;	

	case SCAMPER_FILE_OBJ_CYCLE_START:
	  s->tv.tv_sec = ((scamper_cycle_t *)s->data)->start_time;
	  s->tv.tv_usec = 0;
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_STOP:
	  s->tv.tv_sec = ((scamper_cycle_t *)s->data)->stop_time;
	  s->tv.tv_usec = 1000000;
	  break;
	}

      if(heap_insert(heap, s) == NULL)
	{
	  return -1;
	}
    }
  else return -1;

  return 0;
}

static int sort_cat(void)
{
  heap_t        *heap = NULL;
  sort_struct_t *ss = NULL;
  sort_struct_t *s;
  int i;

  if((heap = heap_alloc(sort_struct_cmp)) == NULL)
    {
      goto err;
    }

  if((ss = malloc(sizeof(sort_struct_t) * infile_cnt)) == NULL)
    {
      goto err;
    }
  memset(ss, 0, sizeof(sort_struct_t) * infile_cnt);

  /*
   * start by filling all file slots with the first data object from
   * each file
   */
  for(i=0; i<infile_cnt; i++)
    {
      ss[i].file = i;
      if(sort_cat_fill(heap, &ss[i]) != 0)
	{
	  goto err;
	}
    }

  /*
   * now, read each object off the heap in their appropriate priority and
   * replace each heap object with another from the file until there is
   * nothing left.
   */
  while((s = (sort_struct_t *)heap_remove(heap)) != NULL)
    {
      if(write_obj(s->type, s->data) != 0)
	{
	  goto err;
	}

      if(sort_cat_fill(heap, s) != 0)
	{
	  goto err;
	}
    }

  heap_free(heap, NULL);
  free(ss);

  return 0;

 err:
  if(heap != NULL) heap_free(heap, NULL);
  if(ss != NULL) free(ss);
  return -1;
}

int main(int argc, char *argv[])
{
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_DEALIAS,
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
  };
  uint16_t filter_cnt = sizeof(filter_types)/sizeof(uint16_t);

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) == -1)
    {
      return -1;
    }

  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      fprintf(stderr, "could not allocate filter\n");
      return -1;
    }

  if(options & OPT_SORT)
    {
      return sort_cat();
    }
  else
    {
      return simple_cat();
    }

  return 0;
}
