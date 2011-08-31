/*
 * scamper_ip6.c
 *
 * $Id: scamper_ip6.c,v 1.9 2009/02/28 06:40:10 mjl Exp $
 *
 * Copyright (C) 2006-2009 The University of Waikato
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip6.h"

#include "scamper_debug.h"
#include "utils.h"

/*
 * ip6_ext_route0
 *
 * this function builds an IPv6 Routing Header of Type 0, as defined by
 * RFC 2460.  It does not set bytes 5-8, which were defined in RFC 1883
 * as being a loose/strict bitmap.  In RFC 2460, these bits are just set
 * to zero.
 */
static int ip6_ext_route0(struct ip6_hdr *ip6,
			  const scamper_probe_ipopt_t *opt,
			  uint8_t *buf, size_t *len)
{
  int i, addrc;
  ssize_t off;

  /* the header value is always at least 16 bytes in length */
  assert(opt->len >= 16);

  if(*len < (size_t)(opt->len + 8))
    {
      *len = opt->len + 8;
      return -1;
    }

  /* calculate how many addresses will be in the routing header */
  addrc = opt->len / 16;

  /*
   * the length field counts number of 8 octets, excluding the first 8 bytes
   * of routing header.
   * RFC 2460 says this value is twice the number of addresses in the header
   */
  buf[1] = addrc * 2;

  /* routing type = 0 */
  buf[2] = 0;

  /* number of segments left */
  buf[3] = addrc;

  /* set the next four bytes to zero */
  memset(buf+4, 0, 4);

  off = 8;

  /*
   * copy in addresses 1 .. N, skipping over the first address which is
   * swapped with ip6->ip6_dst after this loop
   */
  for(i=1; i<addrc; i++)
    {
      memcpy(buf+off, opt->val+(16 * i), 16);
      off += 16;
    }

  /*
   * the current destination address becomes the last address in the routing
   * header
   */
  memcpy(buf+off, &ip6->ip6_dst, 16);
  off += 16;

  /* the first address in the option becomes the destination address */
  memcpy(&ip6->ip6_dst, opt->val, 16);

  *len = off;
  return 0;
}

static int ip6_ext_frag(struct ip6_hdr *ip6,
			const scamper_probe_ipopt_t *opt,
			uint8_t *buf, size_t *len)
{
  /* the header value is always 6 bytes in length */
  assert(opt->len == 6);

  /* make sure the pktbuf has at least enough space left for this */
  if(*len < 8)
    {
      *len = 8;
      return -1;
    }

  /* the length of this header is set to zero since it is of fixed size */
  buf[1] = 0;

  /* copy in the fragmentation value */
  memcpy(buf+2, opt->val, 6);

  *len = 8;
  return 0;
}

/*
 * scamper_ip6_build
 *
 * given a scamper probe structure, and a place in the pktbuf to dump the
 * header, write the header.
 *
 * return 0 on success, -1 on fail.
 * on entry, buflen contains the length of the pktbuf left for the header.
 * on exit, buflen contains the length of the space used if zero was returned,
 * or the space that would be necessary on fail.
 *
 * the caller is still required to set ip6->ip6_plen when it knows how much
 * payload is going to be included.
 */
int scamper_ip6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  static int (*const func[])(struct ip6_hdr *, const scamper_probe_ipopt_t *,
			     uint8_t *, size_t *) = {
    ip6_ext_route0,  /* SCAMPER_PROBE_IPOPTS_V6ROUTE0 */
    ip6_ext_frag,    /* SCAMPER_PROBE_IPOPTS_V6FRAG */
    NULL,            /* SCAMPER_PROBE_IPOPTS_V4RR */
  };

  static const int nxthdrval[] = {
    43, /* SCAMPER_PROBE_IPOPTS_V6ROUTE0 */
    44, /* SCAMPER_PROBE_IPOPTS_V6FRAG */
    -1, /* SCAMPER_PROBE_IPOPTS_V4RR */
  };

  struct ip6_hdr        *ip6;
  scamper_probe_ipopt_t *opt;
  size_t                 off, tmp;
  int                    i;

  /* get a pointer to the first byte of the buf for the IPv6 header */
  ip6 = (struct ip6_hdr *)buf;
  off = sizeof(struct ip6_hdr);

  if(off <= *len)
    {
      /* build the ip6 header */
      ip6->ip6_flow = htonl(0x60000000 | probe->pr_ip_flow);
      ip6->ip6_hlim = probe->pr_ip_ttl;
      memcpy(&ip6->ip6_src, probe->pr_ip_src->addr, 16);
      memcpy(&ip6->ip6_dst, probe->pr_ip_dst->addr, 16);
    }

  /*
   * if there are no IPv6 extension headers, then the ip6_nxt field is set
   * to the underlying type of the packet
   */
  if(probe->pr_ipoptc == 0)
    {
      if(off <= *len)
	{
	  ip6->ip6_nxt = probe->pr_ip_proto;
	}
      goto done;
    }

  /*
   * the next header field in the IPv6 header is set to the type of the
   * first extension header
   */
  if(off <= *len)
    {
      ip6->ip6_nxt = nxthdrval[probe->pr_ipopts[0].type];
    }

  /* build the body of the IPv6 extension headers area */
  for(i=0; i<probe->pr_ipoptc; i++)
    {
      if(off + 1 < *len)
	{
	  /* the last extension header uses the ip protocol value */
	  if(i == probe->pr_ipoptc-1)
	    {
	      buf[off] = probe->pr_ip_proto;
	    }
	  else
	    {
	      buf[off] = nxthdrval[probe->pr_ipopts[i+1].type];
	    }
	}

      /* obtain a handy pointer to the current extension header */
      opt = &probe->pr_ipopts[i];

      /* work out how much space is left in the buf */
      tmp = *len - off;

      /* handle the extension header */
      func[opt->type](ip6, opt, buf, &tmp);

      off += tmp;
    }

 done:
  /*
   * figure out what to return based on if there was enough space in the
   * packet payload to compose the IPv6 header
   */
  if(off > *len)
    {
      *len = off;
      return -1;
    }

  *len = off;
  return 0;
}

/*
 * scamper_ip6_hlen
 *
 * given an IPv6 header outline in the probe structure, return how large
 * the IPv6 header length will be.
 */
int scamper_ip6_hlen(scamper_probe_t *probe, size_t *ip6hlen)
{
  *ip6hlen = 0;
  return scamper_ip6_build(probe, NULL, ip6hlen);
}
