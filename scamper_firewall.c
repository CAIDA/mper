/*
 * scamper_firewall.c
 *
 * $Id: scamper_firewall.c,v 1.13 2009/03/13 21:07:20 mjl Exp $
 *
 * Copyright (C) 2008-2009 The University of Waikato
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

#if !defined(__sun__) && !defined(_WIN32)
#include <sys/sysctl.h>
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
#define HAVE_IPFW
#include <netinet/ip_fw.h>
#endif

#if defined(__linux__)
#define HAVE_IPTABLES
#include <linux/netfilter_ipv4/ip_tables.h>
#endif

#ifndef _WIN32
#include <unistd.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_addr.h"
#include "scamper_debug.h"
#include "scamper_firewall.h"
#include "mjl_heap.h"
#include "mjl_splaytree.h"
#include "utils.h"

struct scamper_firewall_entry
{
  int                      slot;
  int                      refcnt;
  splaytree_node_t        *node;
  scamper_firewall_rule_t *rule;
};

static splaytree_t *entries = NULL;

static int firewall_rule_cmp(const scamper_firewall_rule_t *a,
			     const scamper_firewall_rule_t *b)
{
  int i;

  assert(a->type == SCAMPER_FIREWALL_RULE_TYPE_5TUPLE);
  assert(b->type == SCAMPER_FIREWALL_RULE_TYPE_5TUPLE);

  if(a->type < b->type) return -1;
  if(a->type > b->type) return  1;

  if(a->type == SCAMPER_FIREWALL_RULE_TYPE_5TUPLE)
    {
      if(a->sfw_5tuple_proto < b->sfw_5tuple_proto) return -1;
      if(a->sfw_5tuple_proto > b->sfw_5tuple_proto) return  1;

      if(a->sfw_5tuple_sport < b->sfw_5tuple_sport) return -1;
      if(a->sfw_5tuple_sport > b->sfw_5tuple_sport) return  1;

      if(a->sfw_5tuple_dport < b->sfw_5tuple_dport) return -1;
      if(a->sfw_5tuple_dport > b->sfw_5tuple_dport) return  1;

      if((i = scamper_addr_cmp(a->sfw_5tuple_src, b->sfw_5tuple_src)) != 0)
	return i;

      if(a->sfw_5tuple_dst == NULL && b->sfw_5tuple_dst == NULL)
	return 0;
      if(a->sfw_5tuple_dst != NULL && b->sfw_5tuple_dst == NULL)
	return -1;
      if(a->sfw_5tuple_dst == NULL && b->sfw_5tuple_dst != NULL)
	return 1;

      return scamper_addr_cmp(a->sfw_5tuple_dst, b->sfw_5tuple_dst);
    }

  return 0;
}

static scamper_firewall_rule_t *firewall_rule_dup(scamper_firewall_rule_t *sfw)
{
  scamper_firewall_rule_t *dup;

  if((dup = memdup(sfw, sizeof(scamper_firewall_rule_t))) == NULL)
    return NULL;

  scamper_addr_use(dup->sfw_5tuple_src);
  if(dup->sfw_5tuple_dst != NULL)
    scamper_addr_use(dup->sfw_5tuple_dst);

  return dup;
}

static void firewall_rule_free(scamper_firewall_rule_t *sfw)
{
  if(sfw == NULL)
    {
      return;
    }

  if(sfw->sfw_5tuple_src != NULL)
    scamper_addr_free(sfw->sfw_5tuple_src);
  if(sfw->sfw_5tuple_dst != NULL)
    scamper_addr_free(sfw->sfw_5tuple_dst);
  free(sfw);

  return;
}

static int firewall_entry_cmp(const void *a, const void *b)
{
  return firewall_rule_cmp(((const scamper_firewall_entry_t *)a)->rule,
			   ((const scamper_firewall_entry_t *)b)->rule);
}

static void firewall_entry_free(scamper_firewall_entry_t *entry)
{
  if(entry->node != NULL)
    splaytree_remove_node(entries, entry->node);
  firewall_rule_free(entry->rule);
  free(entry);
  return;
}

#if defined(HAVE_IPFW)

/*
 * variables required to keep state with ipfw, which is rule-number based.
 */
static int fd = -1;
static heap_t *freeslots = NULL;

/*
 * freeslots_cmp
 *
 * provide ordering for the freeslots heap by returning the earliest available
 * slot number in a range
 */
static int freeslots_cmp(const void *va, const void *vb)
{
  scamper_firewall_entry_t *a = (scamper_firewall_entry_t *)va;
  scamper_firewall_entry_t *b = (scamper_firewall_entry_t *)vb;

  if(a->slot > b->slot) return -1;
  if(a->slot < b->slot) return 1;
  return 0;
}

#ifdef _IPFW2_H

static int ipfw_rule_5tuple(scamper_firewall_entry_t *entry)
{
  scamper_firewall_rule_t *sfw = entry->rule;
  ipfw_insn_u32 *insn_u32;
  ipfw_insn_u16 *insn_u16;
  struct ip_fw *fw = NULL;
  ipfw_insn *insn;
  socklen_t sl;
  size_t len;

#if defined(O_IP6_DST)
  ipfw_insn_ip6 *insn_ip6;
#endif

  /*
   * build ip_fw struct
   *
   * note that the ip_fw struct has one member reserved for
   * the first instruction, so that is not counted here
   */
  len = 2 + 2 + 1; /* O_PROTO + O_IP_SRCPORT + O_IP_DSTPORT + O_DENY */

  if(sfw->sfw_5tuple_src->type == SCAMPER_ADDR_TYPE_IPV4)
    len += 2; /* O_IP_SRC */
  else
#if defined(O_IP6_SRC)
    len += 5; /* O_IP6_SRC */
#else
    goto err;
#endif

  if(sfw->sfw_5tuple_dst == NULL)
    len += 1; /* O_IP_DST_ME -or- O_IP6_DST_ME */
  else if(sfw->sfw_5tuple_dst->type == SCAMPER_ADDR_TYPE_IPV4)
    len += 2; /* O_IP_DST */
  else
#if defined(O_IP6_DST)
    len += 5; /* O_IP6_DST */
#else
    goto err;
#endif

  if((fw = malloc_zero(sizeof(struct ip_fw) + (len * 4))) == NULL)
    {
      goto err;
    }
  sl = sizeof(struct ip_fw) + (len * 4);

  fw->rulenum = entry->slot;
  fw->act_ofs = len;
  fw->cmd_len = len+1;
  insn = fw->cmd;

  /* encode the O_PROTO parameter */
  insn->opcode = O_PROTO;
  insn->len    = 1;
  insn->arg1   = sfw->sfw_5tuple_proto;
  insn += insn->len;

  /* encode the O_IP_SRC parameter */
  if(sfw->sfw_5tuple_src->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      insn_u32 = (ipfw_insn_u32 *)insn;
      memcpy(insn_u32->d, sfw->sfw_5tuple_src->addr, 4);
      insn->opcode = O_IP_SRC;
      insn->len    = 2;
    }
#if defined(O_IP6_SRC)
  else
    {
      insn_ip6 = (ipfw_insn_ip6 *)insn;
      memcpy(&insn_ip6->addr6, sfw->sfw_5tuple_src->addr, 16);
      insn->opcode = O_IP6_SRC;
      insn->len    = 5;
    }
#endif
  insn += insn->len;

  /* encode the O_IP_SRCPORT parameter */
  insn_u16 = (ipfw_insn_u16 *)insn;
  insn->opcode = O_IP_SRCPORT;
  insn->len    = 2;
  insn_u16->ports[0] = sfw->sfw_5tuple_sport;
  insn_u16->ports[1] = sfw->sfw_5tuple_sport;
  insn += insn->len;

  /* encode the O_IP_DST parameter */
  if(sfw->sfw_5tuple_dst == NULL)
    {
      if(sfw->sfw_5tuple_src->type == SCAMPER_ADDR_TYPE_IPV4)
	insn->opcode = O_IP_DST_ME;
#if defined(O_IP6_DST)
      else
	insn->opcode = O_IP6_DST_ME;
#endif
      insn->len = 1;
    }
  else if(sfw->sfw_5tuple_dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      insn_u32 = (ipfw_insn_u32 *)insn;
      memcpy(insn_u32->d, sfw->sfw_5tuple_dst->addr, 4);
      insn->opcode = O_IP_DST;
      insn->len    = 2;
    }
#if defined(O_IP6_SRC)
  else
    {
      insn_ip6 = (ipfw_insn_ip6 *)insn;
      memcpy(&insn_ip6->addr6, sfw->sfw_5tuple_dst->addr, 16);
      insn->opcode = O_IP6_SRC;
      insn->len    = 5;
    }
#endif
  insn += insn->len;

  /* encode the O_IP_DSTPORT parameter */
  insn_u16 = (ipfw_insn_u16 *)insn;
  insn->opcode = O_IP_DSTPORT;
  insn->len    = 2;
  insn_u16->ports[0] = sfw->sfw_5tuple_dport;
  insn_u16->ports[1] = sfw->sfw_5tuple_dport;
  insn += insn->len;

  /* encode the O_DENY action */
  insn->opcode = O_DENY;
  insn->len    = 1;

  if(getsockopt(fd, IPPROTO_IP, IP_FW_ADD, fw, &sl) != 0)
    {
      printerror(errno, strerror, __func__, "could not add rule");
      goto err;
    }

  free(fw);
  return 0;

 err:
  if(fw != NULL) free(fw);
  return -1;
}

#endif /* _IPFW2_H */

#ifdef _IP_FW_H

static int ipfw_rule_5tuple(scamper_firewall_entry_t *entry)
{
  scamper_firewall_rule_t *sfw = entry->rule;
  struct ip_fw fw;

  if(sfw->sfw_5tuple_src->type != SCAMPER_ADDR_TYPE_IPV4)
    return -1;

  memset(&fw, 0, sizeof(fw));
  fw.fw_number = entry->slot;
  fw.fw_flg = IP_FW_F_DENY | IP_FW_F_IN;
  fw.fw_prot = sfw->sfw_5tuple_proto;
  memcpy(&fw.fw_src, sfw->sfw_5tuple_src->addr, 4);
  fw.fw_smsk.s_addr = ~0;
  memcpy(&fw.fw_dst, sfw->sfw_5tuple_dst->addr, 4);
  fw.fw_dmsk.s_addr = ~0;
  fw.fw_uar.fw_pts[0] = sfw->sfw_5tuple_dport;
  IP_FW_SETNSRCP(&fw, 1);
  fw.fw_uar.fw_pts[1] = sfw->sfw_5tuple_sport;
  IP_FW_SETNDSTP(&fw, 1);

  if(setsockopt(fd, IPPROTO_IP, IP_FW_ADD, &fw, sizeof(fw)) != 0)
    {
      printerror(errno, strerror, __func__, "could not add rule");
      return -1;
    }

  return 0;
}

#endif /* _IPFW_H */

static void firewall_rule_delete(scamper_firewall_entry_t *entry)
{
  uint32_t rule = entry->slot;

  /* remove the rule from the ipfw firewall */
  if(setsockopt(fd, IPPROTO_IP, IP_FW_DEL, &rule, sizeof(rule)) != 0)
    {
      printerror(errno, strerror, __func__, "could not delete rule %u", rule);
    }

  /* put the rule back into the freeslots heap */
  if(heap_insert(freeslots, entry) == NULL)
    {
      printerror(errno, strerror, __func__,
		 "could not add entry %d", entry->slot);
      firewall_entry_free(entry);
    }

  /* free up the firewall rule associated with the entry */
  firewall_rule_free(entry->rule);
  entry->rule = NULL;

  return;
}

static scamper_firewall_entry_t *firewall_entry_get(void)
{
  return heap_remove(freeslots);
}

static int ipfw_init(void)
{
  scamper_firewall_entry_t *entry;
  size_t len;
  int i;

  /* ipfw status is given by net.inet.ip.fw.enable for IPv4 */
  len = sizeof(i);
  if(sysctlbyname("net.inet.ip.fw.enable", &i, &len, NULL, 0) != 0)
    {
      printerror(errno, strerror, __func__,
		 "could not sysctl net.inet.ip.fw.enable");
      return -1;
    }

  /* ipfw status is given by net.inet6.ip6.fw.enable for IPv6 */
  len = sizeof(i);
  if(sysctlbyname("net.inet6.ip6.fw.enable", &i, &len, NULL, 0) != 0)
    {
      printerror(errno, strerror, __func__,
		 "could not sysctl net.inet6.ip6.fw.enable");
      return -1;
    }

  if((freeslots = heap_alloc(freeslots_cmp)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not create freeslots heap");
      return -1;
    }

  for(i=1; i<5; i++)
    {
      if((entry = malloc_zero(sizeof(scamper_firewall_entry_t))) == NULL)
	{
	  printerror(errno, strerror, __func__, "could not alloc entry %d", i);
	  goto err;
	}
      entry->slot = i;
      if(heap_insert(freeslots, entry) == NULL)
	{
	  printerror(errno, strerror, __func__, "could not add entry %d", i);
	  goto err;
	}
    }

  if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
      printerror(errno, strerror, __func__, "could not open socket for ipfw");
      goto err;
    }

  return 0;

 err:
  return -1;
}

static int ipfw_cleanup_foreach(void *param, void *item)
{
  scamper_firewall_entry_t *entry = item;

  firewall_rule_delete(entry);
  entry->slot = -1;

  return 0;
}

static void ipfw_cleanup(void)
{
  scamper_firewall_entry_t *entry;

  splaytree_inorder(entries, ipfw_cleanup_foreach, NULL);

  if(freeslots != NULL)
    {
      while((entry = heap_remove(freeslots)) != NULL)
	{
	  firewall_entry_free(entry);
	}

      heap_free(freeslots, NULL);
      freeslots = NULL;
    }

  if(fd != -1)
    {
      close(fd);
      fd = -1;
    }

  return;
}

#endif /* HAVE_IPFW */

#if defined(HAVE_IPTABLES) || defined(__sun__) || defined(_WIN32)
static scamper_firewall_entry_t *firewall_entry_get(void)
{
  return malloc_zero(sizeof(scamper_firewall_entry_t));
}

static void firewall_rule_delete(scamper_firewall_entry_t *entry)
{
  return;
}
#endif

void scamper_firewall_entry_free(scamper_firewall_entry_t *entry)
{
  entry->refcnt--;
  if(entry->refcnt > 0)
    {
      return;
    }

  /* remove the entry from the tree */
  splaytree_remove_node(entries, entry->node);
  entry->node = NULL;

  /*
   * if the entry is still loaded in the firewall, remove it now.
   * note that this code is to handle the case that scamper_firewall_cleanup
   * is called before this function is called.
   */
  if(entry->slot >= 0)
    {
      firewall_rule_delete(entry);
    }

  return;
}

scamper_firewall_entry_t *
scamper_firewall_entry_get(scamper_firewall_rule_t *sfw)
{
  scamper_firewall_entry_t findme, *entry = NULL;

  /* sanity check the rule */
  if((sfw->sfw_5tuple_proto != IPPROTO_TCP &&
      sfw->sfw_5tuple_proto != IPPROTO_UDP) ||
      sfw->sfw_5tuple_sport == 0 ||
      sfw->sfw_5tuple_dport == 0 ||
     (sfw->sfw_5tuple_dst == NULL ||
      sfw->sfw_5tuple_src->type != sfw->sfw_5tuple_dst->type) ||
     (sfw->sfw_5tuple_src->type != SCAMPER_ADDR_TYPE_IPV4 &&
      sfw->sfw_5tuple_src->type != SCAMPER_ADDR_TYPE_IPV6))
    {
      scamper_debug(__func__, "invalid 5tuple rule");
      goto err;
    }

  findme.rule = sfw;
  if((entry = splaytree_find(entries, &findme)) != NULL)
    {
      entry->refcnt++;
      return entry;
    }

  if((entry = firewall_entry_get()) == NULL)
    goto err;

  entry->refcnt = 1;
  if((entry->rule = firewall_rule_dup(sfw)) == NULL ||
     (entry->node = splaytree_insert(entries, entry)) == NULL)
    {
      goto err;
    }

#if defined(HAVE_IPFW)
  if(ipfw_rule_5tuple(entry) != 0)
    goto err;
#endif

  return entry;

 err:
  if(entry != NULL)
    {
      if(entry->rule != NULL)
	firewall_rule_free(entry->rule);
      free(entry);
    }
  return NULL;
}

void scamper_firewall_cleanup(void)
{
#if defined(HAVE_IPFW)
  ipfw_cleanup();
#elif defined(HAVE_IPTABLES)

#endif
  return;
}

int scamper_firewall_init(char *opt)
{
  if(opt == NULL)
    {
      return 0;
    }

  if((entries = splaytree_alloc(firewall_entry_cmp)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not create entries tree");
      return -1;
    }

#if defined(HAVE_IPFW)
  return ipfw_init();
#else
  return 0;
#endif
}
