/*
 * scamper_ip4.c
 *
 * $Id: scamper_ip4.c,v 1.9 2010/09/11 22:10:42 mjl Exp $
 *
 * Copyright (C) 2009-2010 The University of Waikato
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

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_ip4.c,v 1.9 2010/09/11 22:10:42 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip4.h"
#include "scamper_tcp4.h"
#include "scamper_debug.h"
#include "utils.h"

int scamper_ip4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  scamper_probe_ipopt_t *opt;
  struct ip *ip;
  size_t off, ip4hlen;
  int i, j;

  ip4hlen = sizeof(struct ip);
  for(i=0; i<probe->pr_ipoptc; i++)
    {
      opt = &probe->pr_ipopts[i];
      if(opt->type == SCAMPER_PROBE_IPOPTS_V4RR)
	{
	  /*
	   * want the ability to record at least one IP address otherwise
	   * the option is useless.
	   */
	  if(ip4hlen + 8 > 60)
	    return -1;

	  /* for now assume this option fills the rest of the option space */
	  ip4hlen = 60;
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSPS)
	{
	  if((opt->len % 4) != 0 || opt->len == 0 || opt->len > 16)
	    return -1;

	  ip4hlen += (opt->len * 2) + 4;
	  if(ip4hlen > 60)
	    return -1;
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSO)
	{
	  ip4hlen += 40;
	  if(ip4hlen > 60)
	    return -1;
	}
      else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSAA)
	{
	  ip4hlen += 36;
	  if(ip4hlen > 60)
	    return -1;
	}      else return -1;
    }

  if(ip4hlen > *len)
    {
      *len = ip4hlen;
      return -1;
    }

  ip  = (struct ip *)buf;
  off = sizeof(struct ip);

#ifndef _WIN32
  ip->ip_v   = 4;
  ip->ip_hl  = (ip4hlen / 4);
#else
  ip->ip_vhl = 0x40 | (ip4hlen / 4);
#endif

  switch(probe->pr_ip_proto)
    {
    case IPPROTO_ICMP:
    case IPPROTO_UDP:
      ip->ip_len = htons(ip4hlen + 8 + probe->pr_len);
      break;

    case IPPROTO_TCP:
      ip->ip_len = htons(ip4hlen + scamper_tcp4_hlen(probe) + probe->pr_len);
      break;

    default:
      scamper_debug(__func__, "unimplemented pr %d", probe->pr_ip_proto);
      return -1;
    }

  ip->ip_tos = probe->pr_ip_tos;
  ip->ip_id  = htons(probe->pr_ip_id);
  ip->ip_off = htons(probe->pr_ip_off);
  ip->ip_ttl = probe->pr_ip_ttl;
  ip->ip_p   = probe->pr_ip_proto;
  ip->ip_sum = 0;
  memcpy(&ip->ip_src, probe->pr_ip_src->addr, sizeof(ip->ip_src));
  memcpy(&ip->ip_dst, probe->pr_ip_dst->addr, sizeof(ip->ip_dst));

  for(i=0; i<probe->pr_ipoptc; i++)
    {
      opt = &probe->pr_ipopts[i];
      if(opt->type == SCAMPER_PROBE_IPOPTS_V4RR)
	{
	  memset(buf+off+3, 0, 37);
	  buf[off+0] = 7;
	  buf[off+1] = 39;
	  buf[off+2] = 4;
	  off = 60;
	}
      if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSPS ||
	      opt->type == SCAMPER_PROBE_IPOPTS_V4TSO  ||
	      opt->type == SCAMPER_PROBE_IPOPTS_V4TSAA)
	{
	  buf[off+0] = 68;
	  buf[off+2] = 5;

	  if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSPS)
	    {
	      buf[off+1] = (opt->len * 2) + 4;
	      buf[off+3] = 3;
	      off += 4;
	      for(j=0; j<opt->len; j+=4)
		{
		  memcpy(buf+off, opt->val+j, 4); off += 4;
		  memset(buf+off, 0, 4); off += 4;
		}
	    }
	  else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSO)
	    {
	      buf[off+1] = 40;
	      memset(buf+off+3, 0, 41);
	      off += 40;
	    }
	  else if(opt->type == SCAMPER_PROBE_IPOPTS_V4TSAA)
	    {
	      buf[off+1] = 36;
	      buf[off+3] = 1;
	      memset(buf+off+4, 0, 36);
	      off += 36;
	    }
	}
      else return -1;
    }  

  assert(off == ip4hlen);
  ip->ip_sum = in_cksum(ip, ip4hlen);

  *len = off;
  return 0;
}

int scamper_ip4_hlen(scamper_probe_t *probe, size_t *ip4hlen)
{
  *ip4hlen = 0;
  return scamper_ip4_build(probe, NULL, ip4hlen);
}
