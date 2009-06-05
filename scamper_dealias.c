/*
 * scamper_dealias.c
 *
 * $Id: scamper_dealias.c,v 1.20 2009/05/15 21:32:33 mjl Exp $
 *
 * Copyright (C) 2008-2009 The University of Waikato
 * Author: Matthew Luckie
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the replye that it will be useful,
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
#endif

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "utils.h"

int scamper_dealias_ipid(const scamper_dealias_probe_t **probes,
			 uint32_t probec, scamper_dealias_ipid_t *ipid)
{
  const scamper_dealias_probe_t *p;
  const scamper_dealias_reply_t *r;
  uint32_t bs_mind = 0x30000;
  uint32_t bs_maxd = 0;
  uint32_t bs_sum  = 0;
  uint32_t mind = 0x30000;
  uint32_t maxd = 0;
  uint32_t sum  = 0;
  uint32_t diff;
  uint32_t cur, prev;
  uint32_t i;
  int echo, cons;

  ipid->type = SCAMPER_DEALIAS_IPID_UNKNOWN;

  echo = 1;
  cons = 1;

  if(probec == 0 || probes[0] == NULL || probes[0]->replyc != 1)
    return 0;

  prev = probes[0]->replies[0]->ipid;
  for(i=1; i<probec; i++)
    {
      if((p = probes[i]) == NULL)
	return 0;

      if(p->replyc != 1)
	return 0;

      if((r = p->replies[0]) == NULL)
	return 0;

      /* non byteswap case */
      cur = r->ipid;
      if(cur > prev)
	diff = cur - prev;
      else if(cur < prev)
	diff = 0x10000 + cur - prev;
      else
	diff = 0;
      if(diff < mind)
	mind = diff;
      if(diff > maxd)
	maxd = diff;
      sum += diff;
      
      /* byteswap case */
      cur = byteswap16(r->ipid);
      prev = byteswap16(prev);
      if(cur > prev)
	diff = cur - prev;
      else if(cur < prev)
	diff = 0x10000 + cur - prev;
      else
	diff = 0;
      if(diff < bs_mind)
	bs_mind = diff;
      if(diff > maxd)
	bs_maxd = diff;
      bs_sum += diff;

      if(echo != 0 && p->ipid != r->ipid && p->ipid != byteswap16(r->ipid))
	echo = 0;
      else if(cons != 0 && probes[i-1]->replies[0]->ipid != r->ipid)
	cons = 0;

      prev = r->ipid;
    }

  if(cons == 0 && echo == 0)
    {
      /* figure out which byte ordering best explains the sequence */
      if(sum < bs_sum)
	{
	  ipid->mind = mind;
	  ipid->maxd = maxd;
	}
      else
	{
	  ipid->mind = bs_mind;
	  ipid->maxd = bs_maxd;
	}
      ipid->type = SCAMPER_DEALIAS_IPID_INCR;
    }
  else if(cons != 0)
    {
      if(probes[0]->replies[0]->ipid == 0)
	ipid->type = SCAMPER_DEALIAS_IPID_ZERO;
      else
	ipid->type = SCAMPER_DEALIAS_IPID_CONST;
    }
  else if(echo != 0)
    {
      ipid->type = SCAMPER_DEALIAS_IPID_ECHO;
    }

  return 0;
}

static void dealias_probedef_free(scamper_dealias_probedef_t *probedef)
{
  if(probedef->src != NULL)
    {
      scamper_addr_free(probedef->src);
      probedef->src = NULL;
    }
  if(probedef->dst != NULL)
    {
      scamper_addr_free(probedef->dst);
      probedef->dst = NULL;
    }
  return;
}

static void dealias_mercator_free(void *data)
{
  scamper_dealias_mercator_t *mercator = (scamper_dealias_mercator_t *)data;
  dealias_probedef_free(&mercator->probedef);
  free(mercator);
  return;
}

static void dealias_ally_free(void *data)
{
  scamper_dealias_ally_t *ally = (scamper_dealias_ally_t *)data;
  dealias_probedef_free(&ally->probedefs[0]);
  dealias_probedef_free(&ally->probedefs[1]);
  free(ally);
  return;
}

static void dealias_radargun_free(void *data)
{
  scamper_dealias_radargun_t *radargun = (scamper_dealias_radargun_t *)data;
  uint32_t i;

  if(radargun->probedefs != NULL)
    {
      for(i=0; i<radargun->probedefc; i++)
	{
	  dealias_probedef_free(&radargun->probedefs[i]);
	}
      free(radargun->probedefs);
    }
  free(radargun);
  return; 
}

static void dealias_prefixscan_free(void *data)
{
  scamper_dealias_prefixscan_t *prefixscan = data;
  uint16_t i;

  if(prefixscan == NULL)
    return;

  if(prefixscan->a  != NULL) scamper_addr_free(prefixscan->a);
  if(prefixscan->b  != NULL) scamper_addr_free(prefixscan->b);
  if(prefixscan->ab != NULL) scamper_addr_free(prefixscan->ab);

  if(prefixscan->xs != NULL)
    {
      for(i=0; i<prefixscan->xc; i++)
	if(prefixscan->xs[i] != NULL)
	  scamper_addr_free(prefixscan->xs[i]);
      free(prefixscan->xs);
    }

  if(prefixscan->probedefs != NULL)
    {
      for(i=0; i<prefixscan->probedefc; i++)
	dealias_probedef_free(&prefixscan->probedefs[i]);
      free(prefixscan->probedefs);
    }

  free(prefixscan);

  return;
}

scamper_dealias_probedef_t *scamper_dealias_probedef_alloc(void)
{
  size_t size = sizeof(scamper_dealias_probedef_t);
  return (scamper_dealias_probedef_t *)malloc_zero(size);
}

void scamper_dealias_probedef_free(scamper_dealias_probedef_t *probedef)
{
  dealias_probedef_free(probedef);
  free(probedef);
  return;
}

scamper_dealias_probe_t *scamper_dealias_probe_alloc(void)
{
  size_t size = sizeof(scamper_dealias_probe_t);
  return (scamper_dealias_probe_t *)malloc_zero(size);
}

void scamper_dealias_probe_free(scamper_dealias_probe_t *probe)
{
  uint16_t i;

  if(probe->replies != NULL)
    {
      for(i=0; i<probe->replyc; i++)
	{
	  if(probe->replies[i] != NULL)
	    scamper_dealias_reply_free(probe->replies[i]);
	}
      free(probe->replies);
    }

  free(probe);
  return;
}

scamper_dealias_reply_t *scamper_dealias_reply_alloc(void)
{
  size_t size = sizeof(scamper_dealias_reply_t);
  return (scamper_dealias_reply_t *)malloc_zero(size);
}

void scamper_dealias_reply_free(scamper_dealias_reply_t *reply)
{
  if(reply->src != NULL)
    scamper_addr_free(reply->src);
  free(reply);
  return;
}

uint32_t scamper_dealias_reply_count(const scamper_dealias_t *dealias)
{
  uint32_t rc = 0;
  uint16_t i;
  for(i=0; i<dealias->probec; i++)
    {
      if(dealias->probes[i] != NULL)
	rc += dealias->probes[i]->replyc;
    }
  return rc;
}

int scamper_dealias_probe_add(scamper_dealias_t *dealias,
			      scamper_dealias_probe_t *probe)
{
  size_t size = (dealias->probec+1) * sizeof(scamper_dealias_probe_t *);
  if(realloc_wrap((void **)&dealias->probes, size) == 0)
    {
      dealias->probes[dealias->probec++] = probe;
      return 0;
    }
  return -1;  
}

int scamper_dealias_reply_add(scamper_dealias_probe_t *probe,
			      scamper_dealias_reply_t *reply)
{
  size_t size = (probe->replyc+1) * sizeof(scamper_dealias_reply_t *);
  if(realloc_wrap((void **)&probe->replies, size) == 0)
    {
      probe->replies[probe->replyc++] = reply;
      return 0;
    }
  return -1;
}

int scamper_dealias_ally_alloc(scamper_dealias_t *dealias)
{
  if((dealias->data = malloc_zero(sizeof(scamper_dealias_ally_t))) != NULL)
    {
      return 0;
    }

  return -1;
}

int scamper_dealias_mercator_alloc(scamper_dealias_t *dealias)
{
  if((dealias->data = malloc_zero(sizeof(scamper_dealias_mercator_t))) != NULL)
    {
      return 0;
    }

  return -1;
}

int scamper_dealias_radargun_alloc(scamper_dealias_t *dealias)
{
  if((dealias->data = malloc_zero(sizeof(scamper_dealias_radargun_t))) != NULL)
    {
      return 0;
    }

  return -1;
}

int scamper_dealias_prefixscan_alloc(scamper_dealias_t *dealias)
{
  dealias->data = malloc_zero(sizeof(scamper_dealias_prefixscan_t));
  if(dealias->data != NULL)
    return 0;
  return -1;
}

#if 0
/*
 * dealias_ipid_inrange:
 *
 * this function determines if two values are within a fudge value of each
 * other, allowing reordering and wrapping.  it is #if 0'd out as the
 * reordering check allows too many false positives.
 */
static int dealias_ipid_inrange(uint32_t a, uint32_t b, uint32_t fudge)
{
  if(a < b)
    {
      /* check if it is in range */
      if(b - a <= fudge)
	return 1;

      /* check for wrapping of 16 bit value */
      a += 0x10000;
      if(a - b <= fudge)
	return 1;
    }
  else if(a > b)
    {
      /* check if it is in range */
      if(a - b <= fudge)
	return 1;

      /* check for wrapping of 16 bit value */
      b += 0x10000;
      if(b - a <= fudge)
	return 1;
    }

  return 0;
}
#endif

static int dealias_ipid_inseq(uint32_t a, uint32_t b, uint32_t fudge)
{
  if(a > b)
    b += 0x10000;

  if(b - a <= fudge)
    return 1;

  return 0;
}

int scamper_dealias_ipid_inseq(scamper_dealias_probe_t **probes,
			       int probec, uint16_t fudge)
{
  uint16_t a, b;
  int i;

  for(i=1; i<probec; i++)
    {
      a = probes[i-1]->replies[0]->ipid;
      b = probes[i+0]->replies[0]->ipid;
      if(a == b || dealias_ipid_inseq(a, b, fudge) == 0)
	return 0;
    }

  return 1;
}

int scamper_dealias_ipid_inseqbs(scamper_dealias_probe_t **probes,
				 int probec, uint16_t fudge)
{
  uint16_t a, b, c;
  int i, bs;

  if(probec < 2)
    return -1;

  a = probes[0]->replies[0]->ipid;
  b = probes[1]->replies[0]->ipid;

  /*
   * do a preliminary check to see if the ipids could in insequence with
   * two samples.
   */
  if(probec == 2)
    {
      if(a == b)
	return 0;
      if(dealias_ipid_inseq(a, b, fudge) != 0)
	return 1;
      if(dealias_ipid_inseq(byteswap16(a), byteswap16(b), fudge) != 0)
	return 1;
      return 0;
    }

  c = probes[2]->replies[0]->ipid;

  /* all three numbers must be different */
  if(a == b || b == c || a == c)
    return 0;

  /* check if a < b < c, without doing any byte order changes */
  if(dealias_ipid_inseq(a, b, fudge) && dealias_ipid_inseq(b, c, fudge))
    {
      bs = 0;
    }
  else
    {
      /* check if a < b < c when byte order is changed */
      a = byteswap16(a);
      b = byteswap16(b);
      c = byteswap16(c);

      if(dealias_ipid_inseq(a,b,fudge) && dealias_ipid_inseq(b,c,fudge))
	bs = 1;
      else
	return 0;
    }

  for(i=0; i+2<probec; i+=2)
    {
      a = probes[i+0]->replies[0]->ipid;
      b = probes[i+1]->replies[0]->ipid;
      c = probes[i+2]->replies[0]->ipid;

      /* all three numbers must be different */
      if(a == b || b == c || a == c)
	return 0;

      /* change byte order if necessary */
      if(bs != 0)
	{
	  a = byteswap16(a);
	  b = byteswap16(b);
	  c = byteswap16(c);
	}

      if(dealias_ipid_inseq(a, b, fudge) == 0)
	return 0;
      if(dealias_ipid_inseq(b, c, fudge) == 0)
	return 0;
    }

  /* if there is two stragglers, then check them */
  if(i+2 == probec)
    {
      a = probes[i+0]->replies[0]->ipid;
      b = probes[i+1]->replies[0]->ipid;

      if(a == b)
	return 0;

      if(bs != 0)
	{
	  a = byteswap16(a);
	  b = byteswap16(b);
	}

      if(dealias_ipid_inseq(a, b, fudge) == 0)
	return 0;
    }

  return 1;
}

int scamper_dealias_ally_inseq(scamper_dealias_t *dealias, uint16_t fudge)
{
  return scamper_dealias_ipid_inseq(dealias->probes, dealias->probec, fudge);
}

int scamper_dealias_ally_inseqbs(scamper_dealias_t *dealias, uint16_t fudge)
{
  return scamper_dealias_ipid_inseqbs(dealias->probes, dealias->probec, fudge);
}

int scamper_dealias_probes_alloc(scamper_dealias_t *dealias, uint32_t cnt)
{
  size_t size = cnt * sizeof(scamper_dealias_probe_t *);
  if((dealias->probes = malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_replies_alloc(scamper_dealias_probe_t *probe, uint16_t cnt)
{
  size_t size = cnt * sizeof(scamper_dealias_reply_t *);
  if((probe->replies = malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_radargun_probedefs_alloc(scamper_dealias_radargun_t *rg,
					     uint32_t probedefc)
{
  size_t len = probedefc * sizeof(scamper_dealias_probedef_t);
  if((rg->probedefs = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

typedef struct dealias_resolv
{
  scamper_dealias_probe_t **probes;
  int                       probec;
  int                       probet;
} dealias_resolv_t;

static int dealias_fudge_inseq(scamper_dealias_probe_t *pr_a,
			       scamper_dealias_probe_t *pr_b,
			       int bs, int fudge)
{
  uint32_t a = pr_a->replies[0]->ipid;
  uint32_t b = pr_b->replies[0]->ipid;

  if(bs != 0)
    {
      a = byteswap16(a);
      b = byteswap16(b);
    }

  if(a > b)
    b += 0x10000;

  if(b - a > fudge)
    return 0;

  return 1;
}

static int xs_cmp(const void *va, const void *vb)
{
  const scamper_addr_t *a = *((const scamper_addr_t **)va);
  const scamper_addr_t *b = *((const scamper_addr_t **)vb);
  return scamper_addr_cmp(a, b);
}

int scamper_dealias_prefixscan_xs_add(scamper_dealias_t *dealias,
				      scamper_addr_t *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  int tmp;

  if(array_find((void **)prefixscan->xs, prefixscan->xc, addr, xs_cmp) != NULL)
    return 0;

  if((tmp = prefixscan->xc) == 65535)
    return -1;

  if(array_insert((void ***)&prefixscan->xs, &tmp, addr, xs_cmp) != 0)
    return -1;

  scamper_addr_use(addr);
  prefixscan->xc++;
  return 0;
}

int scamper_dealias_prefixscan_xs_in(scamper_dealias_t *dealias,
				     scamper_addr_t *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  if(array_find((void **)prefixscan->xs, prefixscan->xc, addr, xs_cmp) != NULL)
    return 1;
  return 0;
}

int scamper_dealias_prefixscan_xs_alloc(scamper_dealias_prefixscan_t *p,
					uint16_t xc)
{
  if((p->xs = malloc_zero(sizeof(scamper_addr_t *) * xc)) != NULL)
    return 0;
  return -1;
}

int scamper_dealias_prefixscan_probedefs_alloc(scamper_dealias_prefixscan_t *p,
					       uint32_t probedefc)
{
  size_t len = probedefc * sizeof(scamper_dealias_probedef_t);
  if((p->probedefs = malloc_zero(len)) != NULL)
    return 0;
  return -1;
}

int scamper_dealias_prefixscan_probedef_add(scamper_dealias_t *dealias,
					    scamper_addr_t *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probedef_t *def;
  size_t size;

  /* need at least one probedef to base the rest on */
  if(prefixscan->probedefc < 1)
    return -1;

  /* make the probedef array one bigger */
  size = sizeof(scamper_dealias_probedef_t) * (prefixscan->probedefc+1);
  if(realloc_wrap((void **)&prefixscan->probedefs, size) != 0)
    return -1;

  /* get the probedef we're working with */
  def = &prefixscan->probedefs[prefixscan->probedefc];
  memcpy(def, prefixscan->probedefs, sizeof(scamper_dealias_probedef_t));
  def->id  = prefixscan->probedefc++;
  def->dst = scamper_addr_use(addr);

  return 0;
}

int scamper_dealias_radargun_fudge(scamper_dealias_t *dealias,
				   scamper_dealias_probedef_t *def,
				   scamper_dealias_probedef_t **defs, int *cnt,
				   int fudge)
{
  scamper_dealias_radargun_t *rg = dealias->data;
  scamper_dealias_probe_t *pr, *pr_a, *pr_b;
  scamper_dealias_reply_t *re, *re_a, *re_b, *re_c;
  dealias_resolv_t *dr = NULL;
  dealias_resolv_t *drd;
  uint32_t pid;
  int i, j, k, bs, inseq, d = 0;

  if(dealias->method != SCAMPER_DEALIAS_METHOD_RADARGUN)
    goto err;

  if((dr = malloc_zero(sizeof(dealias_resolv_t) * rg->probedefc)) == NULL)
    goto err;

  for(i=0; i<dealias->probec; i++)
    {
      pr = dealias->probes[i];
      pid = pr->probedef->id;

      /*
       * if this probedef has already been determined to be useless for
       * alias resolution, skip it
       */
      if(dr[pid].probec < 0)
	continue;

      if(pr->replyc > 1)
	{
	  if(dr[pid].probes != NULL)
	    free(dr[pid].probes);
	  dr[pid].probec = -1;

	  if(pr->probedef == def)
	    goto done;
	  continue;
	}

      /* total number of probes transmitted */
      dr[pid].probet++;

      if(pr->replyc == 0)
	continue;

      re = pr->replies[0];

      /*
       * with three replies, do some basic checks to see if we should
       * continue considering this probedef.
       */
      if(dr[pid].probec == 2)
	{
	  pr_a = dr[pid].probes[0];
	  pr_b = dr[pid].probes[1];
	  re_a = pr_a->replies[0];
	  re_b = pr_b->replies[0];

	  if((re->ipid == pr->ipid && re_a->ipid == pr_a->ipid &&
	      re_b->ipid == pr_b->ipid) ||
	     (re->ipid == re_a->ipid && re->ipid == re_b->ipid))
	    {
	      free(dr[pid].probes);
	      dr[pid].probec = -1;

	      if(pr->probedef == def)
		goto done;
	      continue;
	    }
	}

      if(array_insert((void ***)&dr[pid].probes,&dr[pid].probec,pr,NULL) != 0)
	goto err;
    }

  /* figure out if we should byteswap the ipid sequence */
  if(dr[def->id].probec < 3)
    goto done;
  re_a = dr[def->id].probes[0]->replies[0];
  re_b = dr[def->id].probes[1]->replies[0];
  re_c = dr[def->id].probes[2]->replies[0];
  if(re_a->ipid < re_b->ipid)
    i = re_b->ipid - re_a->ipid;
  else
    i = 0x10000 + re_b->ipid - re_a->ipid;
  if(re_b->ipid < re_c->ipid)
    i += re_c->ipid - re_b->ipid;
  else
    i += 0x10000 + re_c->ipid - re_b->ipid;
  if(byteswap16(re_a->ipid) < byteswap16(re_b->ipid))
    j = byteswap16(re_b->ipid) - byteswap16(re_a->ipid);
  else
    j = 0x10000 + byteswap16(re_b->ipid) - byteswap16(re_a->ipid);
  if(byteswap16(re_b->ipid) < byteswap16(re_c->ipid))
    j += byteswap16(re_c->ipid) - byteswap16(re_b->ipid);
  else
    j += 0x10000 + byteswap16(re_c->ipid) - byteswap16(re_b->ipid);
  if(i < j)
    bs = 0;
  else
    bs = 1;

  /* for each probedef, consider if it could be an alias */
  drd = &dr[def->id]; d = 0;
  for(pid=0; pid<rg->probedefc; pid++)
    {
      if(&rg->probedefs[pid] == def || dr[pid].probec < 3)
	continue;

      j = 0; k = 0;

      /* get the first ipid */
      if(timeval_cmp(&drd->probes[j]->tx, &dr[pid].probes[k]->tx) < 0)
	pr_a = drd->probes[j++];
      else
	pr_a = dr[pid].probes[k++];

      for(;;)
	{
	  if(timeval_cmp(&drd->probes[j]->tx, &dr[pid].probes[k]->tx) < 0)
	    pr_b = drd->probes[j++];
	  else
	    pr_b = dr[pid].probes[k++];

	  if((inseq = dealias_fudge_inseq(pr_a, pr_b, bs, fudge)) == 0)
	    break;

	  if(j == drd->probec || k == dr[pid].probec)
	    break;
	}

      /*
       * if the pairs do not appear to have insequence IP-ID values, then
       * abandon
       */
      if(inseq == 0)
	continue;

      defs[d++] = &rg->probedefs[pid];
      if(d == *cnt)
	break;
    }

 done:
  *cnt = d;
  for(i=0; i<rg->probedefc; i++)
    if(dr[i].probec > 0)
      free(dr[i].probes);
  return 0;

 err:
  if(dr != NULL)
    {
      for(i=0; i<rg->probedefc; i++)
	if(dr[i].probec > 0)
	  free(dr[i].probes);
    }
  return -1;
}

void scamper_dealias_free(scamper_dealias_t *dealias)
{
  static void (*const func[])(void *) = {
    dealias_mercator_free,
    dealias_ally_free,
    dealias_radargun_free,
    dealias_prefixscan_free,
  };

  uint32_t i;

  if(dealias == NULL)
    return;

  if(dealias->probes != NULL)
    {
      for(i=0; i<dealias->probec; i++)
	{
	  if(dealias->probes[i] != NULL)
	    scamper_dealias_probe_free(dealias->probes[i]);
	}
      free(dealias->probes);
    }

  if(dealias->cycle != NULL) scamper_cycle_free(dealias->cycle);
  if(dealias->list != NULL)  scamper_list_free(dealias->list);

  if(dealias->data != NULL)
    {
      assert(dealias->method != 0);
      assert(dealias->method <= 4);
      func[dealias->method-1](dealias->data);
    }

  free(dealias);
  return;
}

scamper_dealias_t *scamper_dealias_alloc(void)
{
  return (scamper_dealias_t *)malloc_zero(sizeof(scamper_dealias_t));
}
