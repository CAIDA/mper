/*
 * scamper_probe.c
 *
 * $Id: scamper_probe.c,v 1.40 2009/05/09 09:41:51 mjl Exp $
 *
 * Copyright (C) 2005-2008 The University of Waikato
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

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_icmp_resp.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_tcp4.h"
#include "scamper_tcp6.h"
#include "scamper_dl.h"
#include "scamper_debug.h"
#include "utils.h"

/*
 * this pad macro determines the number of extra bytes we have to allocate
 * so that the next element (the IP header) of the buffer is aligned
 * appropriately after the datalink header.
 */
#define PAD(s) ((s > 0) ? (1 + ((s - 1) | (sizeof(long) - 1)) - s) : 0)

static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;

/*
 * scamper_probe_send
 *
 * this meta-function is responsible for
 *  1. sending a probe
 *  2. handling any error condition incurred when sending the probe
 *  3. recording details of the probe with the trace's state
 */
int scamper_probe(scamper_probe_t *probe)
{
  int    (*send_func)(scamper_probe_t *);
  int    (*build_func)(scamper_probe_t *, uint8_t *, size_t *);
  size_t   pad, len;
  uint8_t *buf;

#ifndef NDEBUG
  char addr[128];
  scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr));
#endif

  send_func = NULL;
  build_func = NULL;

  probe->pr_errno = 0;

  /* determine which function scamper should use to build or send the probe */
  if(probe->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      switch(probe->pr_ip_proto)
	{
	case IPPROTO_UDP:
	  send_func = scamper_udp4_probe;
	  build_func = scamper_udp4_build;
	  scamper_debug(__func__, "udp %s, ttl %d, %d:%d, ipid 0x%04x, len %d",
			addr, probe->pr_ip_ttl,
			probe->pr_udp_sport, probe->pr_udp_dport,
			probe->pr_ip_id, probe->pr_len + 28);
	  break;

	case IPPROTO_ICMP:
	  send_func = scamper_icmp4_probe;
	  build_func = scamper_icmp4_build;
	  if(probe->pr_icmp_sum != 0)
	    {
	      scamper_debug(__func__,
			    "icmp %s, ttl %d, sum 0x%04x, seq %d, len %d",
			    addr, probe->pr_ip_ttl, ntohs(probe->pr_icmp_sum),
			    probe->pr_icmp_seq, probe->pr_len + 28);
	    }
	  else
	    {
	      scamper_debug(__func__, "icmp %s, ttl %d, seq %d, len %d",
			    addr, probe->pr_ip_ttl, probe->pr_icmp_seq,
			    probe->pr_len + 28); 
	    }
	  break;

	case IPPROTO_TCP:
	  build_func = scamper_tcp4_build;
	  scamper_debug(__func__,
          "tcp %s, ttl %d, %d:%d, ipid 0x%04x, seq 0x%08x, ack 0x%08x, len %d",
			addr, probe->pr_ip_ttl,
			probe->pr_tcp_sport, probe->pr_tcp_dport,
			probe->pr_ip_id, probe->pr_tcp_seq, probe->pr_tcp_ack,
			probe->pr_len + 40);
	  break;
	}
    }
  else if(probe->pr_ip_dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      switch(probe->pr_ip_proto)
	{
	case IPPROTO_UDP:
	  send_func = scamper_udp6_probe;
	  build_func = scamper_udp6_build;
	  scamper_debug(__func__, "udp %s, ttl %d, %d:%d, len %d",
			addr, probe->pr_ip_ttl,
			probe->pr_udp_sport, probe->pr_udp_dport,
			probe->pr_len + 48);
	  break;

	case IPPROTO_ICMPV6:
	  send_func = scamper_icmp6_probe;
	  build_func = scamper_icmp6_build;
	  scamper_debug(__func__, "icmp %s, ttl %d, seq %d, len %d",
			addr, probe->pr_ip_ttl, probe->pr_icmp_seq,
			probe->pr_len + 48);
	  break;

	case IPPROTO_TCP:
	  build_func = scamper_tcp6_build;
	  scamper_debug(__func__, "tcp %s ttl %d, %d:%d, seq 0x%08x, len %d",
			addr, probe->pr_ip_ttl,
			probe->pr_tcp_sport, probe->pr_tcp_dport,
			probe->pr_ip_flow, probe->pr_len + 60);
	  break;
	}
    }

  /* if we're not using the datalink to send the packet, then send it now */
  if(probe->pr_dl == NULL)
    {
      if(send_func != NULL)
	{
	  return send_func(probe);
	}

      probe->pr_errno = EINVAL;
      return -1;
    }

  /* if the header type is not known (we cannot build it) then bail */
  if(build_func == NULL)
    {
      probe->pr_errno = EINVAL;
      return -1;
    }

  /*
   * calculate the number of pad bytes to put at the front of the packet
   * buffer so that the IP layer is properly aligned for the architecture
   */
  pad = PAD(probe->pr_dl_size);

  /* determine a suitable value for the length parameter */
  if(pad + probe->pr_dl_size >= pktbuf_len)
    {
      len = 0;
    }
  else
    {
      len = pktbuf_len - pad - probe->pr_dl_size;
    }

  /*
   * try building the probe.  if it returns -1, then hopefully the len field
   * will supply a clue as to what it should be
   */
  if(build_func(probe, pktbuf + pad + probe->pr_dl_size, &len) == -1)
    {
      assert(pktbuf_len < pad + probe->pr_dl_size + len);

      /* reallocate the packet buffer */
      len += pad + probe->pr_dl_size;
      if((buf = realloc(pktbuf, len)) == NULL)
	{
	  probe->pr_errno = errno;
	  printerror(errno, strerror, __func__, "could not realloc");
	  return -1;
	}
      pktbuf     = buf;
      pktbuf_len = len;

      len = pktbuf_len - pad - probe->pr_dl_size;
      if(build_func(probe, pktbuf + pad + probe->pr_dl_size, &len) == -1)
	{
	  probe->pr_errno = EINVAL;
	  return -1;
	}
    }

  /* add the datalink header size back to the length field */
  len += probe->pr_dl_size;

  /* pre-pend the datalink header, if there is one */
  if(probe->pr_dl_size > 0)
    {
      memcpy(pktbuf+pad, probe->pr_dl_hdr, probe->pr_dl_size);
    }

  gettimeofday_wrap(&probe->pr_tx);
  if(scamper_dl_tx(probe->pr_dl, pktbuf+pad, len) == -1)
    {
      probe->pr_errno = errno;
      return -1;
    }

  return 0;
}

void scamper_probe_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }
  
  pktbuf_len = 0;
  return;
}
