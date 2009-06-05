/*
 * scamper_source_cmdline.c
 *
 * $Id: scamper_source_cmdline.c,v 1.5 2009/02/28 09:02:42 mjl Exp $
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
#define __func__ __FUNCTION__
#endif

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_debug.h"
#include "scamper_task.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_source_cmdline.h"
#include "utils.h"

static int command_assemble(char **out, size_t *len,
			    const char *cmd, size_t cmdlen, const char *addr)
{
  size_t addrlen = strlen(addr);
  size_t reqlen = cmdlen + 1 + addrlen + 1;
  char  *tmp;

  if(reqlen > *len)
    {
      if(*len != 0)
	{
	  if((tmp = realloc(*out, reqlen)) == NULL)
	    {
	      printerror(errno, strerror, __func__,
			 "could not realloc %d bytes for tmp", reqlen);
	      return -1;
	    }
	}
      else
	{
	  if((tmp = malloc(reqlen)) == NULL)
	    {
	      printerror(errno, strerror, __func__,
			 "could not malloc %d bytes for tmp", reqlen);
	      return -1;
	    }

	  memcpy(tmp, cmd, cmdlen);
	  tmp[cmdlen] = ' ';
	}

      *out = tmp;
      *len = reqlen;
    }

  memcpy((*out)+cmdlen+1, addr, addrlen + 1);
  return 0;
}

scamper_source_t *scamper_source_cmdline_alloc(scamper_source_params_t *ssp,
					       const char *cmd,
					       char **arg, int arg_cnt)
{
  scamper_source_t *source = NULL;
  size_t cmd_len, len = 0;
  char *buf = NULL;
  int i;

  ssp->type = SCAMPER_SOURCE_TYPE_CMDLINE;

  if((source = scamper_source_alloc(ssp)) == NULL)
    {
      goto err;
    }

  if(cmd != NULL)
    {
      cmd_len = strlen(cmd);
      for(i=0; i<arg_cnt; i++)
	{
	  if(command_assemble(&buf, &len, cmd, cmd_len, arg[i]) != 0 ||
	     scamper_source_command(source, buf) != 0)
	    {
	      goto err;
	    }
	}
    }
  else
    {
      for(i=0; i<arg_cnt; i++)
	{
	  if(scamper_source_command(source, arg[i]) != 0)
	    goto err;
	}
    }

  if(buf != NULL)
    free(buf);

  return source;

 err:
  if(source != NULL) scamper_source_free(source);
  if(buf != NULL) free(buf);
  return NULL;
}
