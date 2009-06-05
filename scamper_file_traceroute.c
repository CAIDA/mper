/*
 * scamper_file_traceroute.c
 *
 * $Id: scamper_file_traceroute.c,v 1.64 2009/04/18 04:05:54 mjl Exp $
 *
 * code to read scamper's traceroute-like file format into scamper_hop
 * structures.
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

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned short sa_family_t;
#endif 

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#define __FAVOR_BSD
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#ifdef _WIN32
#define snprintf _snprintf
#define ftruncate _chsize
#define strdup _strdup
#define lseek _lseek
#define fdopen _fdopen
#endif

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tlv.h"
#include "scamper_trace.h"
#include "scamper_ping.h"
#include "scamper_tracelb.h"
#include "scamper_sting.h"
#include "scamper_file.h"
#include "scamper_file_traceroute.h"
#include "utils.h"

#define ISEOL(c)     ((c) == '\n' || (c) == '\0' || (c) == '\r')
#define ISSPACE(c)   isspace((int)c) /* ((c) == ' ' || (c) == '\t') */
#define ISQUOTE(c)   ((c) == '"')
#define ISCOMMENT(c) ((c) == '#')
#define ISNUMBER(c)  isdigit((int)c) /* ((c) >= '0' && (c) <= '9') */

/*
 * file_state
 *
 * this struct keeps state for reading / writing traceroute-like files.
 * this struct is only used when reading from these types of files.
 */
typedef struct file_state
{
  FILE *file;
} file_state_t;

/*
 * gettokens
 *
 * parse the line into tokens, modifying the contents of line in the
 * process and returning a pointer to the tokens, and how many tokens in there
 * are valid
 */
static int gettokens(char *line, char *tokens[], int *num_tokens)
{
  char *ptr;
  int i;

  /* sanity check */
  if(line == NULL || tokens == NULL || num_tokens == NULL)
    {
      return 0;
    }
  
  /* ignore any white space to begin with */
  ptr = line;
  while(ISSPACE(*ptr))
    {
      ptr++;
    }
  /*
   * if there are no tokens on this line, or this line is a comment then we
   * return now and say there are no tokens of interest
   */
  if(ISEOL(*ptr) || ISCOMMENT(*ptr))
    {
      *num_tokens = 0;
      return 1;
    }
  
  /*
   * find as many tokens as we can hold in the string
   */
  for(i = 0; i < *num_tokens; i++)
    {
      /*
       * we need to zip along to the next token, which could have arbirary
       * white space
       *
       */
      while(ISSPACE(*ptr) && !ISEOL(*ptr))
	{
	  ptr++;
	}
      if(ISEOL(*ptr))
	{
	  break;
	}
      
      /*
       * if the token starts with a quote it is a string so we parse it as such
       */
      if(ISQUOTE(*ptr))
	{
	  tokens[i] = ++ptr;
	  while(!ISEOL(*ptr) && !ISQUOTE(*ptr))
	    {
	      ptr++;
	    }
	  if(ISEOL(*ptr))
	    {
	      printf("gettokens: no matching '\"'\n");
	      return 0;
	    }
	  /*
	   * terminate this token, and then start looking for the next one
	   */
	  *ptr = '\0'; ptr++;
	}
      /*
       * its a string, but not in quotes so we stop this token as soon as we
       * get to whitespace
       */
      else
	{
	  tokens[i] = ptr++;
	  while(!ISSPACE(*ptr) && !ISEOL(*ptr))
	    {
	      ptr++;
	    }
	  
	  if(ISEOL(*ptr))
	    {
	      *ptr = '\0';
	    }
	  else
	    {
	      *ptr = '\0'; ptr++;
	    }
	}
    }
  
  *num_tokens = i;
  return 1;
}

/*
 * msec_to_timeval
 *
 * this function converts the ms string into a numerical representation
 * in tv.
 */
static int msec_to_timeval(const char *ms, struct timeval *tv)
{
  char *tmp;
  int   i;
  char *d;

  assert(ms != NULL);
  assert(tv != NULL);

  /* make a copy of the ms string, because we're going to be modifying it */
  if((d = strdup(ms)) == NULL)
    {
      return -1;
    }
  tmp = d;

  /* look for the decimal place */
  while(tmp[0] >= '0' && tmp[0] <= '9')
    {
      tmp++;
    }
  if(tmp[0] != '.')
    {
      free(d);
      return -1;
    }

  /*
   * once we've found the decimal place, shift the 3 digits to the right of
   * it over so we can convert the entire thing into a millisecond held in
   * an integer
   */
  i = 0;
  while((tmp[1] >= '0' && tmp[1] <= '9') && i < 3)
    {
      tmp[0] = tmp[1];
      tmp++; i++;
    }
  if(tmp[1] != '\0' || i != 3)
    {
      free(d);
      return -1;
    }
  tmp[0] = '\0';

  i = atoi(d); free(d);
  tv->tv_sec  = (i / 1000);
  tv->tv_usec = (i % 1000) * 1000;

  return 0;
}

static char *addr_str(const scamper_addr_t *addr,char *buf,const size_t len)
{
  if(addr != NULL)
    {
      scamper_addr_tostr(addr, buf, len);
    }
  else
    {
      snprintf(buf, len, "*");
    }

  return buf;
}

/*
 * icmp_tostr
 *
 * the caller must pass a pointer to a str buffer at least 14 chars in length
 * to be safe.
 */
static char *icmp_tostr(const scamper_trace_hop_t *hop,
			char *str, const size_t len)
{
  if((hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) != 0)
    {
      if((hop->hop_tcp_flags & TH_RST) != 0)
	{
	  snprintf(str, len, " [closed]");
	}
      else if((hop->hop_tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
	{
	  if((hop->hop_tcp_flags & TH_ECE) != 0)
	    snprintf(str, len, " [open, ecn]");
	  else
	    snprintf(str, len, " [open]");
	}
      else
	{
	  if(hop->hop_tcp_flags == 0)
	    snprintf(str, len, " [unknown, no flags]");
	  else
	    snprintf(str, len, " [unknown,%s%s%s%s%s%s%s%s]",
		     (hop->hop_tcp_flags & TH_RST)  ? " RST" : "",
		     (hop->hop_tcp_flags & TH_SYN)  ? " SYN" : "",
		     (hop->hop_tcp_flags & TH_ACK)  ? " ACK" : "",
		     (hop->hop_tcp_flags & TH_PUSH) ? " PSH" : "",
		     (hop->hop_tcp_flags & TH_FIN)  ? " FIN" : "",
		     (hop->hop_tcp_flags & TH_URG)  ? " URG" : "",
		     (hop->hop_tcp_flags & TH_CWR)  ? " CWR" : "",
		     (hop->hop_tcp_flags & TH_ECE)  ? " ECE" : "");
	}
    }
  else if(SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop) ||
	  SCAMPER_TRACE_HOP_IS_ICMP_ECHO_REPLY(hop))
    {
      str[0] = '\0';
    }
  else if(hop->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(hop->hop_icmp_type == ICMP_UNREACH)
	{
	  switch(hop->hop_icmp_code)
	    {
	    case ICMP_UNREACH_FILTER_PROHIB:
	      snprintf(str, len, " !X");
	      break;

	    case ICMP_UNREACH_HOST:
	      snprintf(str, len, " !H");
	      break;

	    case ICMP_UNREACH_NEEDFRAG:
	      snprintf(str, len, " !F");
	      break;

	    case ICMP_UNREACH_SRCFAIL:
	      snprintf(str, len, " !S");
	      break;

	    case ICMP_UNREACH_PROTOCOL:
	      snprintf(str, len, " !P");
	      break;

	    case ICMP_UNREACH_NET:
	      snprintf(str, len, " !N");
	      break;

	    case ICMP_UNREACH_PORT:
	      str[0] = '\0';
	      break;

	    default:
	      snprintf(str, len, " !<%d>", hop->hop_icmp_code);
	      break;
	    }
	}
      else
	{
	  snprintf(str,len," !<%d,%d>",hop->hop_icmp_type,hop->hop_icmp_code);
	}
    }
  else if(hop->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(hop->hop_icmp_type == ICMP6_DST_UNREACH)
	{
	  switch(hop->hop_icmp_code)
	    {
	    case ICMP6_DST_UNREACH_ADDR:
	      snprintf(str, len," !A");
	      break;

	    case ICMP6_DST_UNREACH_BEYONDSCOPE:
	      snprintf(str, len," !S");
	      break;

	    case ICMP6_DST_UNREACH_ADMIN:
	      snprintf(str, len," !P");
	      break;

	    case ICMP6_DST_UNREACH_NOROUTE:
	      snprintf(str, len," !N");
	      break;

	    case ICMP6_DST_UNREACH_NOPORT:
	      str[0] = '\0';
	      break;

	    default:
	      snprintf(str, len, " !<%d>", hop->hop_icmp_code);
	      break;
	    }
	}
      else if(hop->hop_icmp_type == ICMP6_PACKET_TOO_BIG)
	{
	  snprintf(str,len," !F");
	}
      else
	{
	  snprintf(str,len," !<%d,%d>",hop->hop_icmp_type,hop->hop_icmp_code);
	}
    }

  return str;
}

static char *rtt_tostr(const struct timeval *rtt, char *str, const size_t len)
{
  uint32_t usec = (rtt->tv_sec * 1000000) + rtt->tv_usec;
  snprintf(str, len, "%d.%03d", usec / 1000, usec % 1000);
  return str;
}

/*
 * header_tostr
 *
 */
static char *header_tostr(const scamper_trace_t *trace)
{
  char src[64], dst[64], header[192];

  if(trace->dst == NULL)
    {
      return NULL;
    }
  scamper_addr_tostr(trace->dst, dst, sizeof(dst));

  if(trace->src != NULL)
    {
      scamper_addr_tostr(trace->src, src, sizeof(src));
      snprintf(header, sizeof(header), "traceroute from %s to %s", src, dst);
    }
  else
    {
      snprintf(header, sizeof(header), "traceroute to %s", dst);
    }

  return strdup(header);
}

/*
 * hop_to_str
 *
 * given a hop (with other hops possibly linked to it) create a string that
 * holds the hop.
 */
static char *hop_tostr(const scamper_trace_t *trace, const int h)
{
  scamper_trace_hop_t *hop;
  char    *str = NULL;
  char   **str_addrs = NULL;
  size_t  *len_addrs = NULL;
  char   **str_rtts = NULL;
  size_t  *len_rtts = NULL;
  size_t   len;
  int      i;
  char     str_hop[128];
  char     str_addr[64];
  char     str_rtt[24];
  char     str_icmp[24];
  int      spare;
  int      replyc;

  /* if we got no responses at all for this hop */
  if(trace->hops[h] == NULL)
    {
      if((trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS) == 0)
	{
	  snprintf(str_hop, sizeof(str_hop), "%2d  *", h+1);
	  str = strdup(str_hop);
	}
      else if((str = malloc((len = 4 + (2 * trace->attempts)))) != NULL)
	{
	  snprintf(str, len, "%2d  ", h+1);
	  for(i=0; i<trace->attempts; i++)
	    {
	      str[4+(i*2)]   = '*';
	      str[4+(i*2)+1] = ' ';
	    }
	  str[4+((i-1)*2)+1] = '\0';
	}

      return str;
    }

  replyc = 0;
  for(hop=trace->hops[h]; hop != NULL; hop = hop->hop_next)
    {
      replyc++;
    }

  if(replyc == 1)
    {
      hop = trace->hops[h];
      scamper_addr_tostr(hop->hop_addr, str_addr, sizeof(str_addr));
      rtt_tostr(&hop->hop_rtt, str_rtt, sizeof(str_rtt));
      icmp_tostr(hop, str_icmp, sizeof(str_icmp));
      
      snprintf(str_hop, sizeof(str_hop),
	       "%2d  %s  %s ms%s", h+1, str_addr, str_rtt, str_icmp);
      return strdup(str_hop);
    }

  /* we have to print out all of the replies */
  len = sizeof(char *) * replyc;
  if((str_addrs = malloc_zero(len)) == NULL)
    {
      goto out;
    }
  if((str_rtts = malloc_zero(len)) == NULL)
    {
      goto out;
    }

  /* keep track of the length of each string in the arrays */
  len = sizeof(size_t) * replyc;
  if((len_addrs = malloc_zero(len)) == NULL)
    {
      goto out;
    }
  if((len_rtts = malloc_zero(len)) == NULL)
    {
      goto out;
    }

  /* for each response we have, record an entry in the array */
  i = 0;
  for(hop = trace->hops[h]; hop != NULL; hop = hop->hop_next)
    {
      /*
       * calculate the length of the address to record for this hop probe,
       * and then generate and store the string
       */
      addr_str(hop->hop_addr, str_addr, sizeof(str_addr));
      len = strlen(str_addr);
      if((str_addrs[i] = malloc(len+1)) == NULL)
	{
	  goto out;
	}
      memcpy(str_addrs[i], str_addr, len+1);
      len_addrs[i] = len;

      /*
       * calculate the length of the rtt and icmp data for this hop probe,
       * and then generate and store the string
       */
      rtt_tostr(&hop->hop_rtt, str_rtt, sizeof(str_rtt));
      icmp_tostr(hop, str_icmp, sizeof(str_icmp));
      len = strlen(str_rtt) + 3 + strlen(str_icmp);
      if((str_rtts[i] = malloc(len+1)) == NULL)
	{
	  goto out;
	}
      snprintf(str_rtts[i],len+1,"%s ms%s",str_rtt,str_icmp);
      len_rtts[i] = len;

      i++;
    }

  /*
   * go through and figure how long our string should be
   * we reserve 5 characters to start with so that we can print 3 digits
   * hop number + 2 digits space ahead of the hop information.
   */
  len = 5; spare = -1;
  for(i=0; i<replyc; i++)
    {
      /* if no data for this probe, then print '* ' */
      if(str_addrs[i] == NULL)
	{
	  len += 2;
	}
      /*
       * if we've printed an address before, check to see if it is the same
       * as the previous address printed.  if so, we just have to print the
       * rtt and be done
       */
      else if(spare != -1 && strcmp(str_addrs[spare], str_addrs[i]) == 0)
	{
	  len += len_rtts[i] + 2;
	}
      /* print out the IP address and the RTT to the hop */
      else
	{
	  spare = i;
	  len += len_addrs[i] + 2 + len_rtts[i] + 2;
	}
    }

  /* allocate a string long enough to store the hop data */
  if((str = malloc(len)) == NULL)
    {
      goto out;
    }

  /* build the string up */
  snprintf(str, len, "%2d  ", h+1);
  len = strlen(str); spare = -1;
  for(i=0; i<replyc; i++)
    {
      if(str_addrs[i] == NULL)
	{
	  str[len++] = '*'; str[len++] = ' ';
	}
      else if(spare != -1 && strcmp(str_addrs[spare], str_addrs[i]) == 0)
	{
	  memcpy(str+len, str_rtts[i], len_rtts[i]);
	  len += len_rtts[i];
	  str[len++] = ' '; str[len++] = ' ';
	}
      else
	{
	  spare = i;
	  memcpy(str+len, str_addrs[i], len_addrs[i]);
	  len += len_addrs[i];
	  str[len++] = ' '; str[len++] = ' ';
	  memcpy(str+len, str_rtts[i], len_rtts[i]);
	  len += len_rtts[i];
	  str[len++] = ' '; str[len++] = ' ';
	}
    }

  /* cut off the unnecessary trailing white space */
  while(str[len-1] == ' ') len--;
  str[len] = '\0';

 out:

  /* clean up */
  if(str_addrs != NULL)
    {
      for(i=0; i<replyc; i++)
	{
	  if(str_addrs[i] != NULL) free(str_addrs[i]);
	}
      free(str_addrs);
    }

  if(str_rtts != NULL)
    {
      for(i=0; i<replyc; i++)
	{
	  if(str_rtts[i]  != NULL) free(str_rtts[i]);
	}
      free(str_rtts);
    }

  if(len_addrs != NULL) free(len_addrs);
  if(len_rtts != NULL) free(len_rtts);

  return str;
}

static char *mtu_tostr(const int mtu, const int size)
{
  char str[24];
  if(mtu != size)
    {
      snprintf(str, sizeof(str), " [*mtu: %d]", size);
    }
  else
    {
      snprintf(str, sizeof(str), " [mtu: %d]", mtu);
    }
  return strdup(str);
}

/*
 * scamper_file_traceroute_write
 *
 * return 0 on successful write, -1 otherwise.
 */
int scamper_file_traceroute_write_trace(const scamper_file_t *sf,
					const scamper_trace_t *trace)
{
  /* current return code */
  int ret = -1;

  /* variables for creating the string representing the trace */
  int      i;
  size_t   len;
  char    *str      = NULL;
  char    *header   = NULL;
  char   **hops     = NULL;
  size_t  *hop_lens = NULL;
  char   **mtus     = NULL;
  size_t  *mtu_lens = NULL;

  /* variables for creating mtu strings */
  scamper_trace_hop_t *hop;
  uint16_t mtu;
  uint16_t size;
  uint8_t  turn_ttl;

  /* variables for writing to the file */
  off_t  off = 0;
  int    fd;
  size_t wc;

  if(trace->dst->type != SCAMPER_ADDR_TYPE_IPV4 &&
     trace->dst->type != SCAMPER_ADDR_TYPE_IPV6)
    {
      return -1;
    }

  /*
   * get the current offset into the file, incase the write fails and a
   * truncation is required
   */
  fd = scamper_file_getfd(sf);
  if(fd != 1 && (off = lseek(fd, 0, SEEK_CUR)) == -1)
    {
      return -1;
    }

  if((hops = malloc_zero(sizeof(char *) * trace->hop_count)) == NULL)
    {
      return -1;
    }

  if((hop_lens = malloc(sizeof(size_t) * trace->hop_count)) == NULL)
    {
      goto cleanup;
    }

  /* get a string that specifies the source and destination of the trace */
  header = header_tostr(trace);

  len = strlen(header) + 2; 
  for(i=0; i < trace->hop_count; i++)
    {
      if((hops[i] = hop_tostr(trace, i)) == NULL)
	{
	  goto cleanup;
	}

      hop_lens[i] = strlen(hops[i]);
      len += hop_lens[i];
    }

  /* if we have PMTU data to print for the trace, then write it too */
  if(trace->pmtud != NULL)
    {
      if((mtus = malloc_zero(sizeof(char *) * trace->hop_count)) == NULL)
	{
	  goto cleanup;
	}

      /*
       * if we did not get any responses from the path, then the path MTU
       * is zero
       */
      if((hop = trace->pmtud->hops) == NULL)
	{
	  mtu = size = trace->pmtud->pmtu;
	}
      else
	{
	  mtu = trace->pmtud->ifmtu;
	  SCAMPER_TRACE_PMTUD_GET_OUTMTU(trace->pmtud, size);
	}

      for(i=0; i<trace->hop_count; i++)
	{
	  /* no response for this hop */
	  if(trace->hops[i] == NULL)
	    {
	      mtus[i] = NULL;
	      continue;
	    }

	  /* if there is no pmtud data then skip this bit */
	  if(hop == NULL)
	    {
	      continue;
	    }

	  /*
	   * if this hop has the same address as an ICMP message, then
	   * change the MTU to reach the next hop after recording the size
	   * of the packet that reached this hop successfully
	   */
	  if(scamper_addr_cmp(hop->hop_addr, trace->hops[i]->hop_addr) == 0)
	    {
	      if((mtus[i] = mtu_tostr(mtu, size)) == NULL)
		{
		  goto cleanup;
		}

	      if(SCAMPER_TRACE_HOP_IS_ICMP_PACKET_TOO_BIG(hop))
		{
		  SCAMPER_TRACE_HOP_GET_NHMTU(hop, mtu);
		  size = mtu;
		}

	      hop = hop->hop_next;
	      if(hop == NULL) size = trace->pmtud->pmtu;
	      else size = hop->hop_probe_size;

	      continue;
	    }

	  /*
	   * if this hop has the same ttl as the probe packet, then the
	   * egress interface returned the frag required message.  record
	   * the MTU for the current working hop
	   */
	  SCAMPER_TRACE_HOP_GET_TURN_TTL(hop, turn_ttl);	  
	  if(i >= hop->hop_probe_ttl - turn_ttl)
	    {
	      if(SCAMPER_TRACE_HOP_IS_ICMP_PACKET_TOO_BIG(hop))
		{
		  SCAMPER_TRACE_HOP_GET_NHMTU(hop, mtu);
		  size = mtu;
		}

	      if((mtus[i] = mtu_tostr(mtu, size)) == NULL)
		{
		  goto cleanup;
		}

	      hop = hop->hop_next;
	      if(hop == NULL) size = trace->pmtud->pmtu;
	      else size = hop->hop_probe_size;

	      continue;
	    }

	  if((mtus[i] = mtu_tostr(mtu, size)) == NULL)
	    {
	      goto cleanup;
	    }	 
	}

      if((mtu_lens = malloc(sizeof(size_t) * trace->hop_count)) == NULL)
	{
	  goto cleanup;
	}

      for(i=0; i<trace->hop_count; i++)
	{
	  if(mtus[i] != NULL)
	    {
	      mtu_lens[i] = strlen(mtus[i]);
	      len += mtu_lens[i];
	    }
	}
    }

  /* \n on each line */
  len += trace->hop_count;
  if((str = malloc(len)) == NULL)
    {
      goto cleanup;
    }

  snprintf(str, len, "%s\n", header); 
  len = strlen(header) + 1;
  for(i=0; i < trace->hop_count; i++)
    {
      memcpy(str+len, hops[i], hop_lens[i]);
      len += hop_lens[i];
      if(trace->pmtud != NULL && mtus[i] != NULL)
	{
	  memcpy(str+len, mtus[i], mtu_lens[i]);
	  len += mtu_lens[i];
	}
      str[len++] = '\n';
    }

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(write_wrap(fd, str, &wc, len) != 0)
    {
      if(fd != 1) ftruncate(fd, off);
      goto cleanup;
    }

  ret = 0; /* we succeeded */

 cleanup:

  for(i=0; i<trace->hop_count; i++)
    {
      if(hops[i] != NULL) free(hops[i]);
    }
  if(hop_lens != NULL) free(hop_lens);
  if(hops != NULL) free(hops);

  if(mtus != NULL)
    {
      for(i=0; i<trace->hop_count; i++)
	{
	  if(mtus[i] != NULL) free(mtus[i]);
	}
      free(mtus);
      if(mtu_lens != NULL) free(mtu_lens);
    }

  if(header != NULL) free(header);
  if(str != NULL)    free(str);

  return ret;
}

/*
 * scamper_file_traceroute_read
 *
 * 
 */
scamper_trace_t *scamper_file_traceroute_read_trace(const scamper_file_t *sf)
{
  scamper_trace_t      *trace = NULL;
  scamper_trace_hop_t  *head, *hop;
  char                  line[256];
  char                 *tokens[20];
  int                   num_tokens;
  fpos_t                pos;
  int                   i;
  file_state_t         *state;
  sa_family_t           af;

  state = scamper_file_getstate(sf);

  /* read the first line, and parse the `traceroute to' line */
  if(fgets(line, sizeof(line), state->file) == NULL)
    {
      return NULL;
    }

  num_tokens = sizeof(tokens) / sizeof(char *);
  if(gettokens(line, tokens, &num_tokens) != 1)
    {
      printf("could not gettokens [1]\n");
      return NULL;
    }

  if(num_tokens == 0)
    {
      printf("num_tokens == 0\n");
      return NULL;
    }

  if(strcmp(tokens[0], "traceroute") != 0 || num_tokens < 3)
    {
      printf("%s != traceroute || %d < 3\n", tokens[0], num_tokens);
      return NULL;
    }

  if((trace = scamper_trace_alloc()) == NULL)
    {
      return NULL;
    }

  af = AF_UNSPEC;

  /* check to see if the file has the source address of the trace embedded */
  if(strcmp(tokens[1], "from") == 0)
    {
      if((trace->src = scamper_addr_resolve(af, tokens[2])) == NULL)
	{
	  goto err;
	}

      i = 3;
    }
  else
    {
      i = 1;
    }

  /* we expect to see a 'to' token now, followed with the target address */
  if(strcmp(tokens[i], "to") != 0)
    {
      goto err;
    }

  if((trace->dst = scamper_addr_resolve(af, tokens[i+1])) == NULL)
    {
      goto err;
    }

  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4) af = AF_INET;
  else if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV6) af = AF_INET6;
  else goto err;

  trace->start.tv_sec = 0;
  trace->start.tv_usec = 0;

  /* is this unnecessary? */
  fgetpos(state->file, &pos);
  i = 0;
  
  head = NULL;

  /* now, read every hop in the traceroute */
  while(fgets(line, sizeof(line), state->file) != NULL)
    {
      /*
       * break the traceroute ascii text up into tokens
       */
      num_tokens = sizeof(tokens)/sizeof(char *);
      if(gettokens(line, tokens, &num_tokens) != 1)
	{
	  printf("could not gettokens [2]\n");
	  goto err;
	}

      /* 
       * if we get to the next traceroute record, then we need
       * to rewind back to the start of this line so we're ready to read
       * the record when we're actually asked for it
       */
      if(num_tokens == 3 && strcmp(tokens[0], "traceroute") == 0)
	{
	  fsetpos(state->file, &pos);
	  break;
	}

      i++;

      /* did we get an answer for this hop? */
      if(num_tokens == 2 && tokens[1][0] == '*')
	{
	  fgetpos(state->file, &pos);
	  continue;
	}

      if(num_tokens < 4)
	{
	  printf("numtokens %d < 4\n", num_tokens);
	  goto err;
	}

      /* we got an answer */
      if((hop = scamper_trace_hop_alloc()) == NULL)
	{
	  goto err;
	}
      hop->hop_probe_ttl = i;
      hop->hop_next = head;
      head = hop;

      /* resolve the string to an address */
      if((hop->hop_addr = scamper_addr_resolve(af, tokens[1])) == NULL)
	{
	  goto err;
	}

      /* turn the ascii millisecond figure into a timeval structure */
      if(msec_to_timeval(tokens[2], &hop->hop_rtt) == -1)
	{
	  printf("couldn't convert the ms to a timeval for %s\n",
		 tokens[2]);
	  goto err;	  
	}

      if(num_tokens == 5 && tokens[4][0] == '!')
	{
	  switch(tokens[4][1])
	    {
	    case 'L':
	      trace->stop_reason = SCAMPER_TRACE_STOP_LOOP;
	      break;
		  
	    case 'D':
	      trace->stop_reason = SCAMPER_TRACE_STOP_GAPLIMIT;
	      break;
		  
	    case 'E':
	      trace->stop_reason = SCAMPER_TRACE_STOP_ERROR;
	      break;
	      
	    case 'N':
	      trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	      if(af == AF_INET6)
		trace->stop_data = ICMP6_DST_UNREACH_NOROUTE;
	      else /* AF_INET */
		trace->stop_data = ICMP_UNREACH_NET;
	      break;
	      
	    case 'P':
	      trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	      if(af == AF_INET6)
		trace->stop_data = ICMP6_DST_UNREACH_ADMIN;
	      else /* AF_INET */
		trace->stop_data = ICMP_UNREACH_PROTOCOL;
	      break;
	      
	    case 'S':
	      trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	      if(af == AF_INET6)
		trace->stop_data = ICMP6_DST_UNREACH_BEYONDSCOPE;
	      else /* AF_INET */
		trace->stop_data = ICMP_UNREACH_SRCFAIL;
	      break;
	      
	    case 'A':
	      trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	      trace->stop_data   = ICMP6_DST_UNREACH_ADDR;
	      break;
		  
	    case 'F':
	      trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	      trace->stop_data   = ICMP_UNREACH_NEEDFRAG;
	      break;
		  
	    case 'H':
	      trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	      trace->stop_data   = ICMP_UNREACH_HOST;
	      break;
		  
	    case 'X':
	      trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	      trace->stop_data   = ICMP_UNREACH_FILTER_PROHIB;
	      break;

	    default:/*
	      snprintf(file->error_str, sizeof(file->error_str),
	      "unknown stop reason !%c", tokens[4][1]);*/
	      break;
	    }
	}
      
      /*
       * before we read the next line, we need to know where we are
       * in the file, because we might start reading the next trace
       * record and need to go back.
       */
      fgetpos(state->file, &pos);
    }

  if(scamper_trace_hops_alloc(trace, i) == -1)
    {
      goto err;
    }

  trace->hop_count = i;

  while(head != NULL)
    {
      hop  = head;
      head = head->hop_next;

      trace->hops[hop->hop_probe_ttl-1] = hop;
      hop->hop_next = NULL;
    }

  return trace;

 err:
  if(trace != NULL) scamper_trace_free(trace);
  return NULL;
}

static char *ping_header(const scamper_ping_t *ping)
{
  char header[192], src[64], dst[64];

  snprintf(header, sizeof(header), "ping %s to %s: %d byte packets\n",
	   scamper_addr_tostr(ping->src, src, sizeof(src)),
	   scamper_addr_tostr(ping->dst, dst, sizeof(dst)),
	   ping->probe_size);

  return strdup(header);
}

static char *ping_reply(const scamper_ping_t *ping,
			const scamper_ping_reply_t *reply)
{
  char buf[192], addr[64], rtt[32], *tcp, flags[16];

  scamper_addr_tostr(reply->addr, addr, sizeof(addr));
  rtt_tostr(&reply->rtt, rtt, sizeof(rtt));

  if(SCAMPER_PING_REPLY_IS_ICMP(reply))
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  snprintf(buf, sizeof(buf),
		   "%d bytes from %s, icmp_seq=%d ttl=%d time=%s ms\n",
		   reply->reply_size, addr, reply->probe_id,
		   reply->reply_ttl, rtt);
	}
      else
	{
	  snprintf(buf, sizeof(buf),
		   "%d bytes from %s, seq=%d ttl=%d time=%s ms\n",
		   reply->reply_size, addr, reply->probe_id,
		   reply->reply_ttl, rtt);
	}
    }
  else if(SCAMPER_PING_REPLY_IS_TCP(reply))
    {
      if((reply->tcp_flags & TH_RST) != 0)
	{
	  tcp = "closed";
	}
      else if((reply->tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
	{
	  if((reply->tcp_flags & TH_ECE) != 0)
	    tcp = "open,ecn";
	  else
	    tcp = "open";
	}
      else
	{
	  snprintf(flags, sizeof(flags), "%0x02x", reply->tcp_flags);
	  tcp = flags;
	}

      snprintf(buf,sizeof(buf), "%d bytes from %s, tcp=%s ttl=%d time=%s ms\n",
	       reply->reply_size, addr, tcp, reply->reply_ttl, rtt);
    }
  else
    {
      return NULL;
    }

  return strdup(buf);
}

static char *ping_stats(const scamper_ping_t *ping)
{
  struct timeval min, max, avg, stddev;
  uint16_t loss;
  uint32_t replies, dups;
  char min_str[32], max_str[32], avg_str[32], stddev_str[32], dup_str[32];
  char buf[512];
  char dst[64];
  int rp;

  if(scamper_ping_stats(ping,&replies,&dups,&loss,&min,&max,&avg,&stddev) != 0)
    {
      return NULL;
    }

  if(dups != 0)
    {
      snprintf(dup_str, sizeof(dup_str), "+%d duplicates, ", dups);
    }
  else dup_str[0] = '\0';

  if(ping->ping_sent != 0)
    rp = ((ping->ping_sent - replies) * 100) / ping->ping_sent;
  else
    rp = 0;

  snprintf(buf, sizeof(buf),
	   "--- %s ping statistics ---\n"
	   "%d packets transmitted, %d packets received, %s%d%% packet loss\n"
	   "round-trip min/avg/max/stddev = %s/%s/%s/%s ms\n",
	   scamper_addr_tostr(ping->dst, dst, sizeof(dst)),
	   ping->ping_sent, replies, dup_str, rp,
	   rtt_tostr(&min,    min_str,    sizeof(min_str)),
	   rtt_tostr(&max,    max_str,    sizeof(max_str)),
	   rtt_tostr(&avg,    avg_str,    sizeof(avg_str)),
	   rtt_tostr(&stddev, stddev_str, sizeof(stddev_str)));

  return strdup(buf);
}

int scamper_file_traceroute_write_ping(const scamper_file_t *sf,
				       const scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  int       fd          = scamper_file_getfd(sf);
  off_t     off         = 0;
  uint32_t  reply_count = scamper_ping_reply_count(ping);
  char     *header      = NULL;
  size_t    header_len  = 0;
  char    **replies     = NULL;
  size_t   *reply_lens  = NULL;
  char     *stats       = NULL;
  size_t    stats_len   = 0;
  char     *str         = NULL;
  size_t    len         = 0;
  size_t    wc          = 0;
  int       ret         = -1;
  uint32_t  i,j;

  /* get current position incase trunction is required */
  if(fd != 1 && (off = lseek(fd, 0, SEEK_CUR)) == -1)
    {
      return -1;
    }

  /* get the header string */
  if((header = ping_header(ping)) == NULL)
    {
      goto cleanup;
    }
  len = (header_len = strlen(header));

  /* put together a string for each reply */
  if(reply_count > 0)
    {
      if((replies    = malloc_zero(sizeof(char *) * reply_count)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * reply_count)) == NULL)
	{
	  goto cleanup;
	}

      for(i=0, j=0; i<ping->ping_sent; i++)
	{
	  reply = ping->ping_replies[i];
	  while(reply != NULL)
	    {
	      /* build string representation of this reply */
	      if((replies[j] = ping_reply(ping, reply)) == NULL)
		{
		  goto cleanup;
		}
	      len += (reply_lens[j] = strlen(replies[j]));

	      reply = reply->next;
	      j++;
	    }
	}
    }

  /* put together the summary stats */
  stats = ping_stats(ping);
  len += (stats_len = strlen(stats));

  /* allocate a string long enough to combine the above strings */
  if((str = malloc(len)) == NULL)
    {
      goto cleanup;
    }

  /* combine the strings created above */
  memcpy(str+wc, header, header_len); wc += header_len;
  for(i=0; i<reply_count; i++)
    {
      memcpy(str+wc, replies[i], reply_lens[i]); wc += reply_lens[i];
    }
  memcpy(str+wc, stats, stats_len); wc += stats_len;

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(write_wrap(fd, str, &wc, len) != 0)
    {
      if(fd != 1) ftruncate(fd, off);
      goto cleanup;
    }

  ret = 0; /* we succeeded */

 cleanup:
  if(str != NULL) free(str);
  if(header != NULL) free(header);
  if(stats != NULL) free(stats);
  if(reply_lens != NULL) free(reply_lens);
  if(replies != NULL)
    {
      for(i=0; i<reply_count; i++)
	{
	  if(replies[i] != NULL) free(replies[i]);
	}
      free(replies);
    }

  return ret;
}

typedef struct probeset_summary
{
  scamper_addr_t **addrs;
  int              addrc;
  int              nullc;
} probeset_summary_t;

static int set_addr_cmp(const void *va, const void *vb)
{
  const scamper_addr_t *a = *((const scamper_addr_t **)va);
  const scamper_addr_t *b = *((const scamper_addr_t **)vb);
  return scamper_addr_cmp(a, b);
}

static probeset_summary_t *probeset_summary(scamper_tracelb_probeset_t *set)
{
  scamper_tracelb_probe_t *probe;
  scamper_addr_t *addr;
  probeset_summary_t *sum;
  uint16_t flowid, j;
  int i, x;

  if((sum = malloc_zero(sizeof(probeset_summary_t))) == NULL)
    {
      return NULL;
    }

  if(set->probec == 0)
    return sum;

  flowid = set->probes[0]->flowid;
  x = 0;
  for(i=0; i<=set->probec; i++)
    {
      if(i == set->probec)
	{
	  if(x == 0)
	    sum->nullc++;
	  break;
	}

      probe = set->probes[i];
      if(probe->flowid != flowid)
	{
	  /*
	   * if a unique flowid had no response (even with multiple
	   * attempts) then make a note of that.
	   */
	  if(x == 0)
	    sum->nullc++;

	  flowid = probe->flowid;
	  x = 0;
	}

      if(probe->rxc > 0)
	{
	  for(j=0; j<probe->rxc; j++)
	    {
	      addr = probe->rxs[j]->reply_from;
	      if(array_find((void **)sum->addrs, sum->addrc, addr,
			    set_addr_cmp) != NULL)
		continue;

	      array_insert((void ***)&sum->addrs, &sum->addrc,
			   addr, set_addr_cmp);
	    }
	  x++;
	}
    }

  return sum;
}

static void probeset_summary_tostr(probeset_summary_t *sum,
				   char *buf, size_t len, size_t *off)
{
  char dst[64];
  int k;

  if(sum->nullc > 0 && sum->addrc == 0)
    {
      string_concat(buf, len, off, "*");
      return;
    }

  scamper_addr_tostr(sum->addrs[0], dst, sizeof(dst));
  string_concat(buf, len, off, "(%s", dst);
  for(k=1; k<sum->addrc; k++)
    {
      scamper_addr_tostr(sum->addrs[k], dst, sizeof(dst));
      string_concat(buf, len, off, ", %s", dst);
    }
  if(sum->nullc > 0)
    string_concat(buf, len, off, ", *)");
  else
    string_concat(buf, len, off, ")");

  return;
}

int scamper_file_traceroute_write_tracelb(const scamper_file_t *sf,
					  const scamper_tracelb_t *trace)
{
  const scamper_tracelb_node_t *node;
  scamper_tracelb_link_t *link;
  probeset_summary_t *sum;
  size_t len;
  size_t off;
  char buf[192], src[64], dst[64];
  int fd = scamper_file_getfd(sf);
  int i, j;

  snprintf(buf, sizeof(buf),
	   "tracelb from %s to %s, %d nodes, %d links, %d probes, %d%%\n",
	   scamper_addr_tostr(trace->src, src, sizeof(src)),
	   scamper_addr_tostr(trace->dst, dst, sizeof(dst)),
	   trace->nodec, trace->linkc, trace->probec, trace->confidence);

  len = strlen(buf);
  write_wrap(fd, buf, NULL, len);

  for(i=0; i<trace->nodec; i++)
    {
      node = trace->nodes[i];
      scamper_addr_tostr(node->addr, src, sizeof(src));

      if(node->linkc > 1)
	{
	  for(j=0; j<node->linkc; j++)
	    {
	      scamper_addr_tostr(node->links[j]->to->addr, dst, sizeof(dst));
	      snprintf(buf, sizeof(buf), "%s -> %s\n", src, dst);
	      len = strlen(buf);
	      write_wrap(fd, buf, NULL, len);
	    }
	}
      else if(node->linkc == 1)
	{
	  link = node->links[0];
	  len = sizeof(buf);
	  off = 0;

	  string_concat(buf, len, &off, "%s -> ", src);
	  for(j=0; j<link->hopc-1; j++)
	    {
	      sum = probeset_summary(link->sets[j]);
	      probeset_summary_tostr(sum, buf, len, &off);
	      string_concat(buf, len, &off, " -> ");
	      if(sum->addrs != NULL) free(sum->addrs);
	      free(sum);
	    }

	  if(link->to != NULL)
	    {
	      scamper_addr_tostr(link->to->addr, dst, sizeof(dst));
	      string_concat(buf, len, &off, "%s", dst);
	    }
	  else
	    {
	      sum = probeset_summary(link->sets[link->hopc-1]);
	      probeset_summary_tostr(sum, buf, len, &off);
	      if(sum->addrs != NULL) free(sum->addrs);
	      free(sum);
	    }

	  string_concat(buf, len, &off, "\n");
	  write_wrap(fd, buf, NULL, off);
	}
    }

  return 0;
}

int scamper_file_traceroute_write_sting(const scamper_file_t *sf,
					const scamper_sting_t *sting)
{
  int    fd = scamper_file_getfd(sf);
  char   buf[192], src[64], dst[64];
  size_t len;
  int    i;

  snprintf(buf, sizeof(buf),
	   "sting from %s:%d to %s:%d, %d probes, %dms mean\n"
	   " data-ack count %d, holec %d\n",
	   scamper_addr_tostr(sting->src, src, sizeof(src)), sting->sport,
	   scamper_addr_tostr(sting->dst, dst, sizeof(dst)), sting->dport,
	   sting->count, sting->mean, sting->dataackc, sting->holec);

  len = strlen(buf);
  write_wrap(fd, buf, NULL, len);

  if(sting->holec > 0)
    {
      for(i=0; i<sting->probec; i++)
	{
	  if(sting->probes[i].flags & SCAMPER_STING_PROBE_FLAG_HOLE)
	    {
	      snprintf(buf, sizeof(buf), "  probe %d hole\n", i+1);
	      len = strlen(buf);
	      write_wrap(fd, buf, NULL, len);
	    }
	}
    }

  return 0;
}

int scamper_file_traceroute_init_read(scamper_file_t *sf)
{
  file_state_t *state;
  int fd;

  if((fd = scamper_file_getfd(sf)) == -1)
    {
      return -1;
    }

  if((state = malloc_zero(sizeof(file_state_t))) == NULL)
    {
      return -1;
    }

  if((state->file = fdopen(fd, "r")) == NULL)
    {
      goto err;
    }

  scamper_file_setstate(sf, state);
  return 0;

 err:
  free(state);
  return -1;
}

int scamper_file_traceroute_is(const scamper_file_t *sf)
{
  char buf[10];
  int fd;

  fd = scamper_file_getfd(sf);

  if(lseek(fd, 0, SEEK_SET) == -1)
    {
      return 0;
    }

  if(read_wrap(fd, buf, NULL, sizeof(buf)) != 0)
    {
      return 0;
    }

  if(strncmp(buf, "traceroute", 10) == 0)
    {
      if(lseek(fd, 0, SEEK_SET) == -1)
	{
	  return 0;
	}
      return 1;
    }

  return 0;
}

void scamper_file_traceroute_free_state(scamper_file_t *sf)
{
  file_state_t *state;

  if((state = scamper_file_getstate(sf)) != NULL)
    {
      free(state);
    }

  return;
}
