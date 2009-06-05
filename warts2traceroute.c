#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tlv.h"
#include "scamper_trace.h"
#include "scamper_tracelb.h"
#include "scamper_ping.h"
#include "scamper_file.h"

int main(int argc, char *argv[])
{
  uint16_t types[] = {
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_PING,
  };
  scamper_file_t *in, *out;
  scamper_file_filter_t *filter;
  uint16_t type;
  void *data;
  int i;

  if(argc < 2)
    {
      fprintf(stderr, "usage: warts2traceroute <file0> <file1> .. <fileN>\n");
      return -1;
    }

  if((out = scamper_file_openfd(STDOUT_FILENO,NULL,'w',"traceroute")) == NULL)
    {
      fprintf(stderr, "could not associate stdout\n");
      return -1;
    }

  filter = scamper_file_filter_alloc(types, sizeof(types)/sizeof(uint16_t));
  if(filter == NULL)
    {
      fprintf(stderr, "could not allocate filter\n");
      return -1;
    }

  for(i=1; i<argc; i++)
    {
      if((in = scamper_file_open(argv[i], 'r', NULL)) == NULL)
	{
	  fprintf(stderr, "could not open %s: %s\n", argv[i], strerror(errno));
	  return -1;
	}

      while(scamper_file_read(in, filter, &type, (void *)&data) == 0)
	{
	  if(data == NULL) break; /* EOF */

	  if(type == SCAMPER_FILE_OBJ_TRACE)
	    {
	      scamper_file_write_trace(out, data);
	      scamper_trace_free(data);
	    }
	  else if(type == SCAMPER_FILE_OBJ_PING)
	    {
	      scamper_file_write_ping(out, data);
	      scamper_ping_free(data);
	    }
	  else if(type == SCAMPER_FILE_OBJ_TRACELB)
	    {
	      scamper_file_write_tracelb(out, data);
	      scamper_tracelb_free(data);
	    }
	}

      scamper_file_close(in);
    }

  scamper_file_close(out);
  return 0;
}
