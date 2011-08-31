/*
 * scamper_addr2mac.c: an implementation of two neighbour discovery methods
 *
 * $Id: scamper_addr2mac.c,v 1.25 2009/04/18 03:59:10 mjl Exp $
 *
 *  RFC 826:  ARP
 *  RFC 2461: Neighbour discovery for IPv6
 *
 * Copyright (C) 2005-2009 The University of Waikato
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

#if defined(__APPLE__)
#define HAVE_BSD_ARPCACHE
#include <stdint.h>
#endif

#if defined(__FreeBSD__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(__NetBSD__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(__OpenBSD__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(__DragonFly__)
#define HAVE_BSD_ARPCACHE
#endif

#if defined(HAVE_BSD_ARPCACHE)
#define ROUNDUP(size) \
        ((size > 0) ? (1 + ((size - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

#if defined(__linux__)

struct ndmsg
{
  unsigned char   ndm_family;
  unsigned char   ndm_pad1;
  unsigned short  ndm_pad2;
  int             ndm_ifindex;
  uint16_t        ndm_state;
  uint8_t         ndm_flags;
  uint8_t         ndm_type;
};

struct sockaddr_nl
{
  sa_family_t     nl_family;
  unsigned short  nl_pad;
  uint32_t        nl_pid;
  uint32_t        nl_groups;
};

struct nlmsghdr
{
  uint32_t        nlmsg_len;
  uint16_t        nlmsg_type;
  uint16_t        nlmsg_flags;
  uint32_t        nlmsg_seq;
  uint32_t        nlmsg_pid;
};

struct rtattr
{
  unsigned short  rta_len;
  unsigned short  rta_type;
};

#define NLMSG_ERROR         0x2
#define NLMSG_DONE          0x3
#define NLMSG_ALIGNTO       4
#define NLMSG_ALIGN(len)    (((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1))
#define NLMSG_LENGTH(len)   ((len)+NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_DATA(nlh)     ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_NEXT(nlh,len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                             (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len)   ((len) > 0 && (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
                             (nlh)->nlmsg_len <= (len))

#define RTA_ALIGNTO           4
#define RTA_ALIGN(len)        (((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1))
#define RTA_LENGTH(len)       (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_DATA(rta)         ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_OK(rta,len)       ((len) > 0 && (rta)->rta_len >= sizeof(struct rtattr) && \
                               (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen) ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                               (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_PAYLOAD(rta)      ((int)((rta)->rta_len) - RTA_LENGTH(0))

#define NDA_DST         1
#define NDA_LLADDR      2
#define NDA_MAX        (NDA_LLADDR+1)
#define NDA_RTA(r)      ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))

#define RTM_BASE        0x10
#define RTM_NEWNEIGH   (RTM_BASE+12)
#define RTM_GETNEIGH   (RTM_BASE+14)
#define NLM_F_REQUEST   1
#define NLM_F_ROOT      0x100 
#define NLM_F_MATCH     0x200
#define NETLINK_ROUTE   0 
#define NUD_REACHABLE   0x02

#endif /* __linux__ */

#include "scamper_addr.h"
#include "scamper_addr2mac.h"
#include "scamper_debug.h"
#include "utils.h"
#include "mjl_splaytree.h"

typedef struct addr2mac
{
  int             ifindex;
  scamper_addr_t *ip;
  scamper_addr_t *mac;
  time_t          expire;
} addr2mac_t;

static splaytree_t *tree = NULL;
extern scamper_addrcache_t *addrcache;

static int addr2mac_cmp(const addr2mac_t *a, const addr2mac_t *b)
{
  if(a->ifindex < b->ifindex) return -1;
  if(a->ifindex > b->ifindex) return  1;

  return scamper_addr_cmp(a->ip, b->ip);
}

static void addr2mac_free(addr2mac_t *addr2mac)
{
  if(addr2mac->ip != NULL) scamper_addr_free(addr2mac->ip);
  if(addr2mac->mac != NULL) scamper_addr_free(addr2mac->mac);
  free(addr2mac);
  return;
}

static addr2mac_t *addr2mac_alloc(const int ifindex, scamper_addr_t *ip,
				  scamper_addr_t *mac)
{
  addr2mac_t *addr2mac;

  if((addr2mac = malloc_zero(sizeof(addr2mac_t))) == NULL)
    {
      return NULL;
    }

  addr2mac->ifindex = ifindex;
  addr2mac->ip = scamper_addr_use(ip);
  addr2mac->mac = scamper_addr_use(mac);

  return addr2mac;
}

static int addr2mac_add(const int ifindex, const int type, const void *ip,
			const void *mac, const time_t expire)
{
  addr2mac_t *addr2mac;
  const int mt = SCAMPER_ADDR_TYPE_ETHERNET;

#ifndef NDEBUG
  char ipstr[128], macstr[128];
#endif

  if((addr2mac = malloc_zero(sizeof(struct addr2mac))) == NULL)
    {
      return -1;
    }

  if((addr2mac->ip = scamper_addrcache_get(addrcache, type, ip)) == NULL)
    {
      goto err;
    }

  if((addr2mac->mac = scamper_addrcache_get(addrcache, mt, mac)) == NULL)
    {
      goto err;
    }

  addr2mac->expire = expire;
  addr2mac->ifindex = ifindex;

  if(splaytree_insert(tree, addr2mac) == NULL)
    {
      goto err;
    }

  scamper_debug(__func__,
		"ifindex %d ip %s mac %s expire %d",
		ifindex,
		scamper_addr_tostr(addr2mac->ip, ipstr, sizeof(ipstr)),
		scamper_addr_tostr(addr2mac->mac, macstr, sizeof(macstr)),
		expire);

  return 0;

 err:
  addr2mac_free(addr2mac);
  return -1;
}

/*
 * scamper_addr2mac_isat_v4
 *
 */
void scamper_addr2mac_isat_v4(int ifindex, uint8_t *pkt, size_t len)
{
  addr2mac_t      findme, *addr2mac;
  scamper_addr_t  addr;
  uint16_t        junk16;
  uint16_t        pro;
  uint8_t         tha[6], tpa[16];
#if !defined(NDEBUG)
  char            buf[128];
#endif

  /*
   * make sure the hardware address space is ethernet, and that
   * we're dealing with 6 byte ethernet addresses
   */
  memcpy(&junk16, pkt+14+0, 2); junk16 = ntohs(junk16);
  if(junk16 != 0x0001 || pkt[14+4] != 6)
    {
      scamper_debug(__func__, "hrd 0x%04x hln %d", junk16, pkt[14+4]);
      return;
    }

  /* determine the protocol and length of each IP address */
  if(pkt[14+5] != 4)
    {
      scamper_debug(__func__, "pln == %d, expected 4", pkt[14+5]);
      return;
    }

  /* make sure the ethernet protocol type is IP */
  memcpy(&junk16, pkt+14+2, 2);
  if((pro = ntohs(junk16)) != ETHERTYPE_IP)
    {
      scamper_debug(__func__, "pln == 0x%04x, expected 0x%04x",
		    pro, ETHERTYPE_IP);
      return;
    }

  /* sanity check the length of the packet captured */
  if(len < 14 + 8 + 6 + 4 + 6 + 4)
    {
      scamper_debug(__func__, "len == %d", len);
      return;
    }

  /* extract the various data items out of the arp packet */
  memcpy(tha, pkt+14+8, 6);
  memcpy(tpa, pkt+14+8+6, 4);

  scamper_debug(__func__, "%s is-at %02x:%02x:%02x:%02x:%02x:%02x",
		addr_tostr(AF_INET, tpa, buf, sizeof(buf)),
		tha[0], tha[1], tha[2], tha[3], tha[4], tha[5]);

  addr.type = SCAMPER_ADDR_TYPE_IPV4;
  addr.addr = tpa;

  findme.ifindex = ifindex;
  findme.ip = &addr;

  if((addr2mac = splaytree_find(tree, &findme)) == NULL)
    {
      return;
    }

  return;
}

/*
 * scamper_addr2mac_isat_v6
 *
 */
void scamper_addr2mac_isat_v6(int ifindex, uint8_t *pkt, size_t len)
{
  struct ip6_hdr   *ip6;
  struct icmp6_hdr *icmp6;
  addr2mac_t        findme, *addr2mac;
  scamper_addr_t    addr;
  size_t            off;
  uint8_t           v6addr[16];
  uint8_t           mac[6];
#if !defined(NDEBUG)
  char              buf[128];
#endif

  /* check the length of the packet passed */
  if(len < (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)))
    {
      scamper_debug(__func__, "packet too small for icmp header");
      return;
    }
  len -= (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr));

  /* ensure it is an ICMPV6 packet */
  ip6 = (struct ip6_hdr *)pkt; off = sizeof(struct ip6_hdr);
  if(ip6->ip6_nxt != IPPROTO_ICMPV6)
    {
      scamper_debug(__func__, "not icmp6");
      return;
    }

  /* ensure the packet is a neighbour advertisement */
  icmp6 = (struct icmp6_hdr *)(pkt + off); off += sizeof(struct icmp6_hdr);
  if(icmp6->icmp6_type != ND_NEIGHBOR_ADVERT)
    {
      scamper_debug(__func__, "not neighbour advertisement");
      return;
    }

  /* make sure there is enough payload for what we can handle */
  if(len < 16 + 2 + 6)
    {
      scamper_debug(__func__, "packet too small for payload");
      return;
    }
  
  if(pkt[off+16] != 0x02 && pkt[off+17] != 0x01)
    {
      scamper_debug(__func__, "%02x%02x", pkt[off+16], pkt[off+17]);
      return;
    }

  memcpy(v6addr, pkt+off, 16);
  memcpy(mac, pkt+off+18, 6);

  scamper_debug(__func__, "%s is-at %02x:%02x:%02x:%02x:%02x:%02x",
		addr_tostr(AF_INET6, v6addr, buf, sizeof(buf)),
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  addr.type = SCAMPER_ADDR_TYPE_IPV6;
  addr.addr = v6addr;

  findme.ifindex = ifindex;
  findme.ip = &addr;

  if((addr2mac = splaytree_find(tree, &findme)) == NULL)
    {
      return;
    }

  return;
}

/*
 * addr2mac_whohas_v4
 *
 * form an ARP request packet for an IPv4 address
 *
 */
static void addr2mac_whohas_v4(uint8_t *pkt, size_t *len,
			       const int ifindex, const scamper_addr_t *src,
			       const scamper_addr_t *dst, uint8_t *mac)
{
  static const uint8_t pln = 4;
  static const uint8_t hln = 6;
  uint16_t pro = htons(ETHERTYPE_IP);
  uint16_t junk16;
  size_t off;

  /*
   * ethernet header: (14 bytes)
   *
   * 6 bytes: target mac address (broadcast)
   * 6 bytes: source mac address
   * 2 bytes: ethernet packet type (ARP)
   */
  memset(pkt, 0xff, 6); off = 6;
  memcpy(pkt+off, mac, 6); off += 6;
  junk16 = htons(ETHERTYPE_ARP);
  memcpy(pkt+off, &junk16, 2); off += 2;

  /*
   * arp request payload: (28 bytes)
   *
   * 2 bytes: ethernet address space: 0x0001
   * 2 bytes: protocol address space: 0x0800
   * 1 byte:  the length of an ethernet mac address
   * 1 byte:  the length of an ip address
   * 2 bytes: request packet
   * 6 bytes: our mac address
   * 4 bytes: our (src) IP address
   * 6 bytes: all zeros (don't know the mac address we're asking for)
   * 4 bytes: gateway (dst) IP address
   */
  junk16 = htons(0x0001);
  memcpy(pkt+off, &junk16, 2); off += 2;
  memcpy(pkt+off, &pro, 2); off += 2;
  pkt[off++] = hln;
  pkt[off++] = pln;
  memcpy(pkt+off, &junk16, 2); off += 2;
  memcpy(pkt+off, mac, 6); off += 6;
  memcpy(pkt+off, src->addr, pln); off += pln;
  memset(pkt+off, 0, 6); off += 6;
  memcpy(pkt+off, dst->addr, pln); off += pln;

  assert(off == 42);

  *len = off;
  return;
}

/*
 * addr2mac_whohas_v6
 *
 * form an ICMP6 neighbour solicitation packet for an IPv6 address
 *
 */
static void addr2mac_whohas_v6(uint8_t *pkt, size_t *len,
			       const int ifindex, const scamper_addr_t *src,
			       const scamper_addr_t *dst, uint8_t *mac)
{
  struct ip6_hdr *ip6;
  struct icmp6_hdr *icmp6;
  uint16_t junk16;
  size_t off = 0;
  uint8_t ip6_dst[16];
  uint8_t sol[4];

  /* figure out the lower 4 bytes of the solicited multicast address */
  memcpy(sol, ((uint8_t *)dst->addr)+12, 4);
  sol[0] = 0xff;

  /* figure out the destination IPv6 address of this message */
  ip6_dst[0] = 0xff;
  ip6_dst[1] = 0x02;
  memset(ip6_dst+2, 0, 9);
  ip6_dst[11] = 0x01;
  memcpy(ip6_dst+12, sol, 4);

  /*
   * ethernet header: (14 bytes)
   *
   * 6 bytes: target mac address (multicast)
   * 6 bytes: source mac address
   * 2 bytes: ethernet packet type (IPv6)
   */
  pkt[off++] = 0x33;
  pkt[off++] = 0x33;
  memcpy(pkt+off, sol, 4); off += 4;
  memcpy(pkt+off, mac, 6); off += 6;
  junk16 = htons(ETHERTYPE_IPV6);
  memcpy(pkt+off, &junk16, 2); off += 2;

  /*
   * IPv6 header: (40 bytes)
   *
   * 0.5 bytes: version
   * 1 byte:    traffic class
   * 2.5 bytes: flow label
   * 2 bytes:   payload length
   * 1 byte:    next header
   * 1 byte:    hoplimit
   * 16 bytes:  source address
   * 16 bytes:  destination address
   */
  ip6 = (struct ip6_hdr *)(pkt+off); off += sizeof(struct ip6_hdr);
  memset(ip6, 0, sizeof(struct ip6_hdr));
#ifndef _WIN32
  ip6->ip6_vfc  = 0x60;
#else
  ip6->ip6_vfc_flow = htonl(0x60000000);
#endif
  ip6->ip6_plen = htons(32);
  ip6->ip6_nxt  = IPPROTO_ICMPV6;
  ip6->ip6_hlim = 255;
  memcpy(&ip6->ip6_src, src->addr, 16);
  memcpy(&ip6->ip6_dst, ip6_dst, 16);

  /*
   * ICMP6 neighbour discovery: (32 bytes)
   *
   * 1 byte:   type
   * 1 byte:   code
   * 2 bytes:  checksum
   * 4 bytes:  zero
   * 16 bytes: address of neighbour to be queried
   * 8 bytes:  source link-layer address option
   */
  icmp6 = (struct icmp6_hdr *)(pkt+off); off += sizeof(struct icmp6_hdr);
  icmp6->icmp6_type = ND_NEIGHBOR_SOLICIT;
  icmp6->icmp6_code = 0;
#ifndef _WIN32
  icmp6->icmp6_data32[0] = 0;
#else
  icmp6->icmp6_data32 = 0;
#endif
  memcpy(pkt+off, dst->addr, 16); off += 16;
  pkt[off++] = 0x01;
  pkt[off++] = 0x01;
  memcpy(pkt+off, mac, 6); off += 6;
  icmp6->icmp6_cksum = 0;
  icmp6->icmp6_cksum = in_cksum(icmp6, 32);

  assert(off == 86);

  *len = off;
  return;
}

/*
 * scamper_addr2mac_whohas
 *
 * 
 */
int scamper_addr2mac_whohas(const int ifindex, const scamper_addr_t *src,
			    scamper_addr_t *dst, uint8_t *mac)
		    
{
  addr2mac_t findme, *addr2mac;
  uint8_t    pkt[86];
  size_t     len;

  findme.ifindex = ifindex;
  findme.ip = dst;

  if((addr2mac = splaytree_find(tree, &findme)) != NULL)
    {
      if(addr2mac->mac != NULL)
	{
	  memcpy(mac, addr2mac->mac->addr, 6);
	  return 1;
	}
      else return 0;
    }

  if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      addr2mac_whohas_v4(pkt, &len, ifindex, src, dst, mac);
    }
  else if(dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      addr2mac_whohas_v6(pkt, &len, ifindex, src, dst, mac);
    }
  else
    {
      return -1;
    }

  if((addr2mac = addr2mac_alloc(ifindex, dst, NULL)) == NULL)
    {
      return -1;
    }

  return 0;
}

#if defined(__linux__)
static int addr2mac_init_linux()
{
  struct nlmsghdr   *nlmsg;
  struct ndmsg      *ndmsg;
  struct rtattr     *rta, *tb[NDA_MAX];
  struct sockaddr_nl snl;
  struct msghdr      msg;
  struct iovec       iov;
  struct timeval     tv;
  pid_t              pid;
  uint8_t            buf[16384];
  ssize_t            ssize;
  ssize_t            len;
  int                rlen;
  int                fd = -1;
  void              *ip, *mac;
  int                iptype;

  pid = getpid();

  memset(buf, 0, sizeof(buf));
  nlmsg = (struct nlmsghdr *)buf;
  nlmsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg));
  nlmsg->nlmsg_type  = RTM_GETNEIGH;
  nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
  nlmsg->nlmsg_seq   = 0;
  nlmsg->nlmsg_pid   = pid;

  ndmsg = NLMSG_DATA(nlmsg);
  ndmsg->ndm_family = AF_UNSPEC;

  if((fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open netlink");
      goto err;
    }

  len = nlmsg->nlmsg_len;
  if((ssize = send(fd, buf, len, 0)) < len)
    {
      if(ssize == -1)
	{
	  printerror(errno, strerror, __func__, "could not send netlink");
	}
      goto err;
    }

  for(;;)
    {
      iov.iov_base = buf;
      iov.iov_len = sizeof(buf);

      msg.msg_name = &snl;
      msg.msg_namelen = sizeof(snl);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = NULL;
      msg.msg_controllen = 0;
      msg.msg_flags = 0;

      if((len = recvmsg(fd, &msg, 0)) == -1)
	{
	  if(errno == EINTR) continue;
	  printerror(errno, strerror, __func__, "could not recvmsg");
	  goto err;
	}

      gettimeofday_wrap(&tv);

      nlmsg = (struct nlmsghdr *)buf;
      while(NLMSG_OK(nlmsg, len))
	{
	  if(nlmsg->nlmsg_pid != pid || nlmsg->nlmsg_seq != 0)
	    {
	      goto skip;
	    }

	  if(nlmsg->nlmsg_type == NLMSG_DONE)
	    {
	      goto done;
	    }

	  if(nlmsg->nlmsg_type == NLMSG_ERROR)
	    {
	      scamper_debug(__func__, "nlmsg error");
	      goto err;
	    }

	  /* get current neighbour entries only */
	  if(nlmsg->nlmsg_type != RTM_NEWNEIGH)
	    {
	      goto skip;
	    }

	  /* make sure the address is reachable */
	  ndmsg = NLMSG_DATA(nlmsg);
	  if((ndmsg->ndm_state & NUD_REACHABLE) == 0)
	    {
	      goto skip;
	    }

	  /* make sure we can process this address type */
	  switch(ndmsg->ndm_family)
	    {
	    case AF_INET:
	      iptype = SCAMPER_ADDR_TYPE_IPV4;
	      break;

	    case AF_INET6:
	      iptype = SCAMPER_ADDR_TYPE_IPV6;
	      break;

	    default:
	      goto skip;
	    }

	  /* fill a table with parameters from the payload */
	  memset(tb, 0, sizeof(tb));
	  rlen = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
	  for(rta = NDA_RTA(ndmsg); RTA_OK(rta,rlen); rta = RTA_NEXT(rta,rlen))
	    {
	      if(rta->rta_type >= NDA_MAX)
		continue;
	      tb[rta->rta_type] = rta;
	    }

	  /*
	   * skip if we don't have a destination IP address, or if
	   * we don't have an ethernet mac address
	   */
	  if(tb[NDA_DST] == NULL ||
	     tb[NDA_LLADDR] == NULL || RTA_PAYLOAD(tb[NDA_LLADDR]) != 6)
	    {
	      goto skip;
	    }

	  ip = RTA_DATA(tb[NDA_DST]);
	  mac = RTA_DATA(tb[NDA_LLADDR]);

	  addr2mac_add(ndmsg->ndm_ifindex, iptype, ip, mac, tv.tv_sec+600);

	skip:
	  nlmsg = NLMSG_NEXT(nlmsg, len);
	}
    }

 done:
  close(fd);
  return 0;

 err:
  close(fd);
  return -1;
}
#endif

#if defined(HAVE_BSD_ARPCACHE)
static int addr2mac_init_bsd(void)
{
  struct rt_msghdr      *rtm;
  struct sockaddr_inarp *sin;
  struct sockaddr_in6   *sin6;
  struct sockaddr_dl    *sdl;
  int                    iptype;
  void                  *ip, *mac;
  int                    mib[6];
  void                  *vbuf = NULL;
  uint8_t               *buf;
  size_t                 i, j, size;

  /*
   * firstly, get the IPv4 ARP cache and load that.
   * we get it by using the sysctl interface to the cache and parsing each
   * entry
   */
  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;

  /*
   * freebsd8 removed the RTF_LLINFO mib branch.
   *
   */
#if defined(RTF_LLINFO)
  mib[5] = RTF_LLINFO;
#else
  mib[5] = 0;
#endif

  if(sysctl_wrap(mib, 6, &vbuf, &size) == -1)
    {
      printerror(errno, strerror, __func__, "sysctl arp cache");
      goto err;
    }

  iptype = SCAMPER_ADDR_TYPE_IPV4;

  for(i=0; i<size; i += rtm->rtm_msglen)
    {
      j = i;
      buf = (uint8_t *)vbuf;
      rtm = (struct rt_msghdr *)(buf + j); j += sizeof(struct rt_msghdr);
      sin = (struct sockaddr_inarp *)(buf + j); j += ROUNDUP(sin->sin_len);
      sdl = (struct sockaddr_dl *)(buf + j);

      /* don't deal with permanent arp entries at this time */
      if(sdl->sdl_type != IFT_ETHER ||
	 sdl->sdl_alen != ETHER_ADDR_LEN)
	{
	  continue;
	}

      ip = &sin->sin_addr;
      mac = sdl->sdl_data + sdl->sdl_nlen;

      addr2mac_add(sdl->sdl_index, iptype, ip, mac,
		   (time_t)rtm->rtm_rmx.rmx_expire);
    }
  if(vbuf != NULL)
    {
      free(vbuf);
      vbuf = NULL;
    }

  /* now it is time to get the IPv6 neighbour discovery cache */
  mib[3] = AF_INET6;

  if(sysctl_wrap(mib, 6, &vbuf, &size) == -1)
    {
      /*
       * assume that EINVAL means that IPv6 support is not provided on
       * this system
       */
      if(errno == EINVAL || errno == EAFNOSUPPORT)
	{
	  return 0;
	}
      printerror(errno, strerror, __func__, "sysctl ndp cache");
      goto err;
    }

  iptype = SCAMPER_ADDR_TYPE_IPV6;

  for(i=0; i<size; i += rtm->rtm_msglen)
    {
      j = i;
      buf = (uint8_t *)vbuf;
      rtm = (struct rt_msghdr *)(buf + j); j += sizeof(struct rt_msghdr);
      sin6 = (struct sockaddr_in6 *)(buf + j); j += ROUNDUP(sin6->sin6_len);
      sdl = (struct sockaddr_dl *)(buf + j);

      if(sdl->sdl_family != AF_LINK ||
	 sdl->sdl_type != IFT_ETHER ||
	 sdl->sdl_alen != ETHER_ADDR_LEN ||
	 (rtm->rtm_flags & RTF_HOST) == 0)
	{
	  continue;
	}

      /* clear out any embedded ifindex in a linklocal address */
      if(IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
	{
	  sin6->sin6_addr.s6_addr[2] = 0;
	  sin6->sin6_addr.s6_addr[3] = 0;
	}

      ip = &sin6->sin6_addr;
      mac = sdl->sdl_data + sdl->sdl_nlen;

      addr2mac_add(sdl->sdl_index, iptype, ip, mac,
		   (time_t)rtm->rtm_rmx.rmx_expire);
    }
  if(vbuf != NULL)
    {
      free(vbuf);
      vbuf = NULL;
    }

  return 0;

 err:
  if(vbuf != NULL) free(vbuf);
  return -1;
}
#endif

#ifdef _WIN32
static int GetIpNetTable_wrap(MIB_IPNETTABLE **table, ULONG *size)
{
  int rc;

  *table = NULL;
  *size  = 0;

  for(;;)
    {
      if(*size > 0 && (*table = malloc(*size)) == NULL)
	return -1;

      if((rc = GetIpNetTable(*table, size, FALSE)) == NO_ERROR)
	return 0;

      free(*table);
      *table = NULL;

      if(rc != ERROR_INSUFFICIENT_BUFFER)
	break;
    }

  return -1;
}

static int addr2mac_init_win32()
{
  MIB_IPNETTABLE *table;
  ULONG           size;
  DWORD           dw;
  int             iptype;

  iptype = SCAMPER_ADDR_TYPE_IPV4;
  if(GetIpNetTable_wrap(&table, &size) == 0 && table != NULL)
    {
      for(dw=0; dw<table->dwNumEntries; dw++)
	{
	  addr2mac_add(table->table[dw].dwIndex, iptype,
		       &table->table[dw].dwAddr,
		       table->table[dw].bPhysAddr, 0);
	}
      free(table);
    }

  return 0;
}
#endif

int scamper_addr2mac_init()
{
  if((tree = splaytree_alloc((splaytree_cmp_t)addr2mac_cmp)) == NULL)
    {
      return -1;
    }

#ifdef HAVE_BSD_ARPCACHE
  if(addr2mac_init_bsd() != 0)
    {
      return -1;
    }
#endif

#ifdef __linux__
  if(addr2mac_init_linux() != 0)
    {
      return -1;
    }
#endif

#ifdef _WIN32
  if(addr2mac_init_win32() != 0)
    {
      return -1;
    }
#endif

  return 0;
}

void scamper_addr2mac_cleanup()
{
  splaytree_free(tree, (splaytree_free_t)addr2mac_free);
  return;
}
