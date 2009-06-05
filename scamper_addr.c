/*
 * scamper_addr.c
 *
 * $Id: scamper_addr.c,v 1.41 2009/05/11 23:29:36 mjl Exp $
 *
 * Copyright (C) 2004-2008 The University of Waikato
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
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define snprintf _snprintf
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "mjl_splaytree.h"
#include "scamper_addr.h"
#include "utils.h"

#if defined(__sun__)
# define s6_addr32 _S6_un._S6_u32
#elif !defined(s6_addr32)
# define s6_addr32 __u6_addr.__u6_addr32
#endif

/*
 * convenient table for masking off portions of addresses for checking
 * if an address falls in a prefix
 */
static const uint32_t uint32_netmask[] = {
  0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
  0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
  0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
  0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
  0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
  0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
  0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
  0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff,
};

static const uint32_t uint32_hostmask[] = {
  0xffffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff,
  0x0fffffff, 0x07ffffff, 0x03ffffff, 0x01ffffff,
  0x00ffffff, 0x007fffff, 0x003fffff, 0x001fffff,
  0x000fffff, 0x0007ffff, 0x0003ffff, 0x0001ffff,
  0x0000ffff, 0x00007fff, 0x00003fff, 0x00001fff,
  0x00000fff, 0x000007ff, 0x000003ff, 0x000001ff,
  0x000000ff, 0x0000007f, 0x0000003f, 0x0000001f,
  0x0000000f, 0x00000007, 0x00000003, 0x00000001,
};

#ifdef _WIN32
static const uint16_t uint16_mask[] = {
  0x8000, 0xc000, 0xe000, 0xf000,
  0xf800, 0xfc00, 0xfe00, 0xff00,
  0xff80, 0xffc0, 0xffe0, 0xfff0,
  0xfff8, 0xfffc, 0xfffe, 0xffff,
};
#endif

static int ipv4_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int ipv4_human_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int ipv6_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int ipv6_human_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int ethernet_cmp(const scamper_addr_t *, const scamper_addr_t *);
static int firewire_cmp(const scamper_addr_t *, const scamper_addr_t *);

static void ipv4_tostr(const scamper_addr_t *, char *, const size_t);
static void ipv6_tostr(const scamper_addr_t *, char *, const size_t);
static void ethernet_tostr(const scamper_addr_t *, char *, const size_t);
static void firewire_tostr(const scamper_addr_t *, char *, const size_t);

static int ipv4_inprefix(const scamper_addr_t *, const void *, int len);
static int ipv6_inprefix(const scamper_addr_t *, const void *, int len);

static int ipv4_prefix(const scamper_addr_t *, const scamper_addr_t *);
static int ipv4_prefixhosts(const scamper_addr_t *, const scamper_addr_t *);

struct handler
{
  int     type;
  size_t  size;
  int    (*cmp)(const scamper_addr_t *sa, const scamper_addr_t *sb);
  int    (*human_cmp)(const scamper_addr_t *sa, const scamper_addr_t *sb);
  void   (*tostr)(const scamper_addr_t *addr, char *buf, const size_t len);
  int    (*inprefix)(const scamper_addr_t *addr, const void *prefix, int len);
  int    (*prefix)(const scamper_addr_t *a, const scamper_addr_t *b);
  int    (*prefixhosts)(const scamper_addr_t *a, const scamper_addr_t *b);
};

static const struct handler handlers[] = {
  {
    SCAMPER_ADDR_TYPE_IPV4,
    4,
    ipv4_cmp,
    ipv4_human_cmp,
    ipv4_tostr,
    ipv4_inprefix,
    ipv4_prefix,
    ipv4_prefixhosts,
  },
  {
    SCAMPER_ADDR_TYPE_IPV6,
    16,
    ipv6_cmp,
    ipv6_human_cmp,
    ipv6_tostr,
    ipv6_inprefix,
    NULL,
    NULL,
  },
  {
    SCAMPER_ADDR_TYPE_ETHERNET,
    6,
    ethernet_cmp,
    ethernet_cmp,
    ethernet_tostr,
    NULL,
    NULL,
    NULL,
  },
  {
    SCAMPER_ADDR_TYPE_FIREWIRE,
    8,
    firewire_cmp,
    firewire_cmp,
    firewire_tostr,
    NULL,
    NULL,
    NULL,
  }
};
    
struct scamper_addrcache
{
  splaytree_t *tree[sizeof(handlers)/sizeof(struct handler)];
};

#ifndef NDEBUG
#if 0
static void scamper_addr_debug(const scamper_addr_t *sa)
{
  char buf[128];
  fprintf(stderr, "scamper_addr_t: %s %d\n",
	  scamper_addr_tostr(sa,buf,sizeof(buf)), sa->refcnt);
  return;
}
#endif
#endif
#define scamper_addr_debug(sa) ((void)0)

static int ipv4_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  struct in_addr *a, *b;

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV4);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV4);

  a = (struct in_addr *)sa->addr;
  b = (struct in_addr *)sb->addr;

  if(a->s_addr < b->s_addr) return -1;
  if(a->s_addr > b->s_addr) return  1;

  return 0;
}

static int ipv4_human_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  uint32_t a, b;

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV4);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV4);

  a = ntohl(((struct in_addr *)sa->addr)->s_addr);
  b = ntohl(((struct in_addr *)sb->addr)->s_addr);

  if(a < b) return -1;
  if(a > b) return  1;

  return 0;
}

static void ipv4_tostr(const scamper_addr_t *addr, char *buf, const size_t len)
{
  addr_tostr(AF_INET, addr->addr, buf, len);
  return;
}

static int ipv4_inprefix(const scamper_addr_t *sa, const void *p, int len)
{
  const struct in_addr *addr = sa->addr;
  const struct in_addr *prefix = p;

  if(len == 0)
    return 1;

  if(len > 32)
    return -1;

  if(((addr->s_addr ^ prefix->s_addr) & htonl(uint32_netmask[len-1])) == 0)
    return 1;

  return 0;
}

static int ipv4_prefix(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const struct in_addr *a = sa->addr;
  const struct in_addr *b = sb->addr;
  int i;

  for(i=32; i>0; i--)
    {
      if(((a->s_addr ^ b->s_addr) & htonl(uint32_netmask[i-1])) == 0)
	break;
    }

  return i;
}

static int ipv4_prefixhosts(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  const struct in_addr *a = sa->addr;
  const struct in_addr *b = sb->addr;
  struct in_addr c;
  int i;

  for(i=32; i>0; i--)
    {
      if(((a->s_addr ^ b->s_addr) & htonl(uint32_netmask[i-1])) == 0)
	break;
    }
  if(i >= 31)
    return i;

  while(i>0)
    {
      c.s_addr = ntohl(a->s_addr) & uint32_hostmask[i];
      if(c.s_addr == 0 || c.s_addr == uint32_hostmask[i])
	{
	  i--;
	  continue;
	}

      c.s_addr = ntohl(b->s_addr) & uint32_hostmask[i];
      if(c.s_addr == 0 || c.s_addr == uint32_hostmask[i])
	{
	  i--;
	  continue;
	}

      break;
    }

  return i;
}

static int ipv6_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  struct in6_addr *a, *b;
  int i;

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV6);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV6);

  a = (struct in6_addr *)sa->addr;
  b = (struct in6_addr *)sb->addr;

#ifndef _WIN32
  for(i=0; i<4; i++)
    {
      if(a->s6_addr32[i] < b->s6_addr32[i]) return -1;
      if(a->s6_addr32[i] > b->s6_addr32[i]) return  1;
    }
#else
  for(i=0; i<8; i++)
    {
      if(a->u.Word[i] < b->u.Word[i]) return -1;
      if(a->u.Word[i] > b->u.Word[i]) return  1;
    }
#endif

  return 0;
}

static int ipv6_human_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  struct in6_addr *a, *b;
  int i;

#ifndef _WIN32
  uint32_t as, bs;
#else
  uint16_t as, bs;
#endif

  assert(sa->type == SCAMPER_ADDR_TYPE_IPV6);
  assert(sb->type == SCAMPER_ADDR_TYPE_IPV6);

  a = (struct in6_addr *)sa->addr;
  b = (struct in6_addr *)sb->addr;

#ifndef _WIN32
  for(i=0; i<4; i++)
    {
      as = ntohl(a->s6_addr32[i]);
      bs = ntohl(b->s6_addr32[i]);

      if(as < bs) return -1;
      if(as > bs) return  1;
    }
#else
  for(i=0; i<8; i++)
    {
      as = ntohs(a->u.Word[i]);
      bs = ntohs(b->u.Word[i]);

      if(as < bs) return -1;
      if(as > bs) return  1;
    }
#endif

  return 0;
}

static void ipv6_tostr(const scamper_addr_t *addr, char *buf, const size_t len)
{
  addr_tostr(AF_INET6, addr->addr, buf, len);
  return;
}

static int ipv6_inprefix(const scamper_addr_t *sa, const void *p, int len)
{
  const struct in6_addr *addr = sa->addr;
  const struct in6_addr *prefix = p;
  int i;

#ifndef _WIN32
  uint32_t mask;
#else
  uint16_t mask;
#endif

  if(len == 0)
    return 1;

  if(len > 128)
    return -1;

#ifndef _WIN32
  for(i=0; i<4; i++)
    {
      /*
       * handle the fact that we can only check 32 bits at a time.
       * no need to change byte order as all bytes are the same
       */
      if(len > 32)
	mask = uint32_netmask[31];
      else
	mask = htonl(uint32_netmask[len-1]);

      if(((addr->s6_addr32[i] ^ prefix->s6_addr32[i]) & mask) != 0)
	return 0;

      if(len <= 32)
	return 1;

      len -= 32;
    }
#else
  for(i=0; i<8; i++)
    {
      if(len > 16)
	mask = uint16_mask[15];
      else
	mask = htons(uint16_mask[len-1]);

      if(((addr->u.Word[i] ^ prefix->u.Word[i]) & mask) != 0)
	return 0;

      if(len <= 16)
	return 1;

      len -= 16;
    }
#endif

  /* we should never get to this return statement */
  return -1;
}

static int ethernet_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  assert(sa->type == SCAMPER_ADDR_TYPE_ETHERNET);
  assert(sb->type == SCAMPER_ADDR_TYPE_ETHERNET);

  return memcmp(sa->addr, sb->addr, 6);
}

static void ethernet_tostr(const scamper_addr_t *addr,
			   char *buf, const size_t len)
{
  uint8_t *mac = (uint8_t *)addr->addr;

  snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
	   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return;
}

static int firewire_cmp(const scamper_addr_t *sa, const scamper_addr_t *sb)
{
  assert(sa->type == SCAMPER_ADDR_TYPE_FIREWIRE);
  assert(sb->type == SCAMPER_ADDR_TYPE_FIREWIRE);

  return memcmp(sa->addr, sb->addr, 8);
}

static void firewire_tostr(const scamper_addr_t *addr,
			   char *buf, const size_t len)
{
  uint8_t *lla = (uint8_t *)addr->addr;

  snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
	   lla[0], lla[1], lla[2], lla[3], lla[4], lla[5], lla[6], lla[7]);

  return;
}

size_t scamper_addr_size(const scamper_addr_t *sa)
{
  return handlers[sa->type-1].size;
}

const char *scamper_addr_tostr(const scamper_addr_t *sa,
			       char *dst, const size_t size)
{
  handlers[sa->type-1].tostr(sa, dst, size);
  return dst;
}

scamper_addr_t *scamper_addr_alloc(const int type, const void *addr)
{
  scamper_addr_t *sa;

  assert(addr != NULL);
  assert(type-1 >= 0);
  assert((size_t)(type-1) < sizeof(handlers)/sizeof(struct handler));

  if((sa = malloc(sizeof(scamper_addr_t))) != NULL)
    {
      if((sa->addr = memdup(addr, handlers[type-1].size)) == NULL)
	{
	  free(sa);
	  return NULL;
	}

      sa->type = type;
      sa->refcnt = 1;
      sa->internal = NULL;
    }

  return sa;
}

/*
 * scamper_addr_resolve:
 *
 * resolve the address contained in addr to a sockaddr that
 * tells us what family the address belongs to, and has a binary
 * representation of the address
 */
scamper_addr_t *scamper_addr_resolve(const int af, const char *addr)
{
  struct addrinfo hints, *res, *res0;
  scamper_addr_t *sa = NULL;
  void *va;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = af;

  if(getaddrinfo(addr, NULL, &hints, &res0) != 0 || res0 == NULL)
    {
      return NULL;
    }

  for(res = res0; res != NULL; res = res->ai_next)
    {
      if(res->ai_family == PF_INET)
	{
	  va = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	  sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, va);
	  break;
	}
      else if(res->ai_family == PF_INET6)
	{
	  va = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	  sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6, va);
	  break;
	}
    }
  
  freeaddrinfo(res0);
  return sa;
}

int scamper_addr_inprefix(const scamper_addr_t *addr, const void *p, int len)
{
  if(handlers[addr->type-1].inprefix != NULL)
    return handlers[addr->type-1].inprefix(addr, p, len);
  return -1;
}

int scamper_addr_prefix(const scamper_addr_t *a, const scamper_addr_t *b)
{
  if(a->type != b->type || handlers[a->type-1].prefix == NULL)
    return -1;

  return handlers[a->type-1].prefix(a, b);
}

int scamper_addr_prefixhosts(const scamper_addr_t *a, const scamper_addr_t *b)
{
  if(a->type != b->type || handlers[a->type-1].prefixhosts == NULL)
    return -1;

  return handlers[a->type-1].prefixhosts(a, b);
}

int scamper_addr_af(const scamper_addr_t *sa)
{
  if(sa->type == SCAMPER_ADDR_TYPE_IPV4)
    return AF_INET;
  else if(sa->type == SCAMPER_ADDR_TYPE_IPV6)
    return AF_INET6;
  else
    return -1;
}

scamper_addr_t *scamper_addrcache_get(scamper_addrcache_t *ac,
				      const int type, const void *addr)
{
  scamper_addr_t *sa, findme;

  findme.type = type;
  findme.addr = (void *)addr;

  if((sa = splaytree_find(ac->tree[type-1], &findme)) != NULL)
    {
      assert(sa->internal == ac);
      sa->refcnt++;
      scamper_addr_debug(sa);
      return sa;
    }

  if((sa = scamper_addr_alloc(type, addr)) != NULL)
    {
      if(splaytree_insert(ac->tree[type-1], sa) == NULL)
	{
	  goto err;
	}
      sa->internal = ac;
    }

  scamper_addr_debug(sa);

  return sa;

 err:
  scamper_addr_free(sa);
  return NULL;
}

/*
 * scamper_addr_resolve:
 *
 * resolve the address contained in addr to a sockaddr that
 * tells us what family the address belongs to, and has a binary
 * representation of the address
 */
scamper_addr_t *scamper_addrcache_resolve(scamper_addrcache_t *addrcache,
					  const int af, const char *addr)
{
  struct addrinfo hints, *res, *res0;
  scamper_addr_t *sa = NULL;
  void *va;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = af;

  if(getaddrinfo(addr, NULL, &hints, &res0) != 0 || res0 == NULL)
    {
      return NULL;
    }

  for(res = res0; res != NULL; res = res->ai_next)
    {
      if(res->ai_family == PF_INET)
	{
	  va = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	  sa = scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV4, va);
	  break;
	}
      else if(res->ai_family == PF_INET6)
	{
	  va = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	  sa = scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV6, va);
	  break;
	}
    }
  
  freeaddrinfo(res0);
  return sa;
}

scamper_addr_t *scamper_addr_use(scamper_addr_t *sa)
{
  if(sa != NULL)
    {
      sa->refcnt++;
      scamper_addr_debug(sa);
    }
  return sa;
}

void scamper_addr_free(scamper_addr_t *sa)
{
  scamper_addrcache_t *ac;

  if(sa == NULL)
    {
      return;
    }

  assert(sa->refcnt > 0);

  if(--sa->refcnt > 0)
    {
      scamper_addr_debug(sa);
      return;
    }

  if((ac = sa->internal) != NULL)
    {
      splaytree_remove_item(ac->tree[sa->type-1], sa);
    }

  scamper_addr_debug(sa);

  free(sa->addr);
  free(sa);
  return;
}

int scamper_addr_cmp(const scamper_addr_t *a, const scamper_addr_t *b)
{
  assert(a->type > 0 && a->type <= sizeof(handlers)/sizeof(struct handler));
  assert(b->type > 0 && b->type <= sizeof(handlers)/sizeof(struct handler));

  /*
   * if the two address structures point to the same memory, then they are
   * a match
   */
  if(a == b)
    {
      return 0;
    }

  /*
   * if the two address types are the same, then do a comparison on the
   * underlying addresses
   */
  if(a->type == b->type)
    {
      return handlers[a->type-1].cmp(a, b);
    }

  /* otherwise, return a code based on the difference between the types */
  if(a->type < b->type)
    {
      return -1;
    }
  else
    {
      return 1;
    }
}

int scamper_addr_human_cmp(const scamper_addr_t *a, const scamper_addr_t *b)
{
  assert(a->type > 0 && a->type <= sizeof(handlers)/sizeof(struct handler));
  assert(b->type > 0 && b->type <= sizeof(handlers)/sizeof(struct handler));

  /*
   * if the two address structures point to the same memory, then they are
   * a match
   */
  if(a == b)
    {
      return 0;
    }

  /*
   * if the two address types are the same, then do a comparison on the
   * underlying addresses
   */
  if(a->type == b->type)
    {
      return handlers[a->type-1].human_cmp(a, b);
    }

  /* otherwise, return a code based on the difference between the types */
  if(a->type < b->type)
    {
      return -1;
    }
  else
    {
      return 1;
    }
}

int scamper_addr_raw_cmp(const scamper_addr_t *a, const void *raw)
{
  return memcmp(a->addr, raw, handlers[a->type-1].size);
}

static void free_cb(void *node)
{
  ((scamper_addr_t *)node)->internal = NULL;
  return;
}

void scamper_addrcache_free(scamper_addrcache_t *ac)
{
  int i;

  for(i=(sizeof(handlers)/sizeof(struct handler))-1; i>=0; i--)
    {
      if(ac->tree[i] != NULL) splaytree_free(ac->tree[i], free_cb);
    }
  free(ac);

  return;
}

scamper_addrcache_t *scamper_addrcache_alloc()
{
  scamper_addrcache_t *ac;
  int i;

  if((ac = malloc(sizeof(scamper_addrcache_t))) == NULL)
    {
      return NULL;
    }
  memset(ac, 0, sizeof(scamper_addrcache_t));

  for(i=(sizeof(handlers)/sizeof(struct handler))-1; i>=0; i--)
    {
      ac->tree[i] = splaytree_alloc((splaytree_cmp_t)handlers[i].cmp);
      if(ac->tree[i] == NULL) goto err;
    }

  return ac;

 err:
  scamper_addrcache_free(ac);
  return NULL;
}
