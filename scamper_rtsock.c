/*
 * scamper_rtsock: code to deal with a route socket or equivalent
 *
 * $Id: scamper_rtsock.c,v 1.54 2009/05/15 21:34:09 mjl Exp $
 *
 *          Matthew Luckie
 * 
 *          Supported by:
 *           The University of Waikato
 *           NLANR Measurement and Network Analysis
 *           CAIDA
 *           The WIDE Project
 *
 * The purpose of this code is to obtain the outgoing interface's index
 * using whatever mechanisms the operating system supports.  A route
 * socket is created where necessary and is kept open for the lifetime
 * of scamper.
 *
 * scamper_rtsock_getifindex returns the interface index on success.
 * if an error occurs, it returns -1.  as route sockets are unreliable
 * sockets, if we do not get an expected response, we return -2 to
 * indicate to the caller to try again.
 *
 * Copyright (C) 2003-2009 The University of Waikato
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

#if defined(__APPLE__)
#define _BSD_SOCKLEN_T_
#define HAVE_BSD_ROUTE_SOCKET
#include <stdint.h>
#endif

#if defined(__sun__)
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__FreeBSD__)
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__NetBSD__)
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__OpenBSD__)
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__DragonFly__)
#define HAVE_BSD_ROUTE_SOCKET
#endif

#include <sys/types.h>

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#endif

#ifndef _WIN32
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* include support for the routing socket */
#if defined(HAVE_BSD_ROUTE_SOCKET)
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#define ROUNDUP(size) \
        ((size > 0) ? (1 + ((size - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

#if defined(__sun__)
#define RTAX_MAX       RTA_NUMBITS
#define RTAX_GATEWAY   1
#define RTAX_IFP       4
#define ETHER_ADDR_LEN 6
#endif

/* include support for the netlink socket in linux */
#if defined(__linux__)

struct nlmsghdr
{
  uint32_t        nlmsg_len;
  uint16_t        nlmsg_type;
  uint16_t        nlmsg_flags;
  uint32_t        nlmsg_seq;
  uint32_t        nlmsg_pid;
};

struct nlmsgerr
{
  int             error;
  struct nlmsghdr msg;
};


struct rtattr
{
  unsigned short  rta_len;
  unsigned short  rta_type;
};

struct rtmsg
{
  unsigned char   rtm_family;
  unsigned char   rtm_dst_len;
  unsigned char   rtm_src_len;
  unsigned char   rtm_tos;
  unsigned char   rtm_table;
  unsigned char   rtm_protocol;
  unsigned char   rtm_scope;
  unsigned char   rtm_type;
  unsigned        rtm_flags;
};

#define NLMSG_ERROR         0x2
#define NLMSG_ALIGNTO       4
#define NLMSG_ALIGN(len)   (((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1))
#define NLMSG_LENGTH(len)  ((len)+NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_DATA(nlh)    ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))

#define RTA_ALIGNTO           4
#define RTA_ALIGN(len)        (((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1))
#define RTA_LENGTH(len)       (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_DATA(rta)         ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_OK(rta,len)       ((len) > 0 && (rta)->rta_len >= sizeof(struct rtattr) && \
                               (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen) ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                               (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_UNSPEC            0
#define RTA_DST               1
#define RTA_SRC               2
#define RTA_IIF               3
#define RTA_OIF               4
#define RTA_GATEWAY           5
#define RTA_PRIORITY          6
#define RTA_PREFSRC           7
#define RTA_METRICS           8
#define RTA_MULTIPATH         9
#define RTA_PROTOINFO         10
#define RTA_FLOW              11
#define RTA_CACHEINFO         12
#define RTA_SESSION           13

#define RTM_RTA(r)         ((struct rtattr*)(((char*)(r)) + \
                            NLMSG_ALIGN(sizeof(struct rtmsg))))
#define RTM_BASE            0x10
#define RTM_NEWROUTE       (RTM_BASE+8)
#define RTM_GETROUTE       (RTM_BASE+10)
#define NLM_F_REQUEST       1
#define NETLINK_ROUTE       0

#endif

#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_privsep.h"
#include "scamper_task.h"
#include "scamper_target.h"
#include "scamper_debug.h"
#include "utils.h"
#include "mjl_list.h"

extern scamper_addrcache_t *addrcache;

#ifndef _WIN32
typedef struct rtsock_msg
{
  /* the route record is passed to whatever handles it */
  scamper_rt_rec_t rr;

  /* these two parameters are used to identify who sent the get route msg */
  pid_t            pid;
  uint16_t         seq;
} rtsock_msg_t;

typedef struct rtsock_pair
{
  scamper_addr_t  *addr; /* the ultimate target of the outgoing route */
  uint16_t         seq;  /* sequence number used */
  dlist_node_t    *node; /* pointer to node used in pair dlist */
} rtsock_pair_t;

static pid_t    pid;           /* [unpriviledged] process id */
static int32_t  ack    = -1;   /* oldest unacknowledged sequence number */
static uint16_t seq    = 0;    /* next sequence number to use */
static dlist_t *pairs  = NULL; /* list of addresses queried with their seq */

static rtsock_pair_t *rtsock_pair_alloc(scamper_addr_t *addr)
{
  rtsock_pair_t *pair;

  if((pair = malloc(sizeof(rtsock_pair_t))) != NULL)
    {
      pair->addr = scamper_addr_use(addr);
      pair->seq = seq;
      pair->node = NULL;
    }

  return pair;
}

static void rtsock_pair_free(rtsock_pair_t *pair)
{
  if(pair->addr != NULL) scamper_addr_free(pair->addr);
  free(pair);
  return;
}

#if defined(HAVE_BSD_ROUTE_SOCKET)
/*
 * scamper_rtsock_getifindex
 *
 * figure out the outgoing interface id / route using route sockets
 *
 * route(4) gives an overview of the functions called in here
 */
static int scamper_rtsock_getifindex(int fd, struct sockaddr *dst)
{
  struct rt_msghdr   *rtm;
  int                 slen;
  struct sockaddr_dl *sdl;
  uint8_t             buf[1024];
  size_t              len;
  ssize_t             ss;

  if((slen = sockaddr_len(dst)) <= 0)
    {
      return -1;
    }

  len = sizeof(struct rt_msghdr) + ROUNDUP(slen) +
    ROUNDUP(sizeof(struct sockaddr_dl));

  memset(buf, 0, len);
  rtm = (struct rt_msghdr *)buf;
  rtm->rtm_msglen  = len;
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type    = RTM_GET;
  rtm->rtm_addrs   = RTA_DST | RTA_IFP;
  rtm->rtm_pid     = pid;
  rtm->rtm_seq     = seq;
  memcpy(buf + sizeof(struct rt_msghdr), dst, (size_t)slen);

  sdl = (struct sockaddr_dl *)(buf + sizeof(struct rt_msghdr) + ROUNDUP(slen));
  sdl->sdl_family = AF_LINK;

#if !defined(__sun__)
  sdl->sdl_len    = sizeof(struct sockaddr_dl);
#endif

  if((ss = write(fd, buf, len)) < 0 || (size_t)ss != len)
    {
      printerror(errno, strerror, __func__, "could not write routing socket");
      return -1;
    }

  return 0;
}
#endif /* HAVE_BSD_ROUTE_SOCKET */

#if defined(__linux__)
/*
 * scamper_rtsock_getifindex
 *
 * figure out the outgoing interface id / route using linux netlink
 *
 * this works on Linux systems with netlink compiled into the kernel.
 * i think netlink comes compiled into the kernel with most distributions
 * these days.
 *
 * the man pages netlink(3), netlink(7), rtnetlink(3), and rtnetlink(7)
 * give an overview of the functions and structures used in here, but the
 * documentation in those man pages is pretty crap.
 * you'd be better off studying netlink.h and rtnetlink.h
 */
static int scamper_rtsock_getifindex(int fd, struct sockaddr *dst)
{
  struct nlmsghdr *nlmsg;
  struct rtmsg    *rtmsg;
  struct rtattr   *rta;
  int              error;
  int              dst_len;
  void            *dst_addr;
  uint8_t          buf[1024];

  /* 
   * figure out the size of the sockaddr we were passed
   */
  if(dst->sa_family == AF_INET)
    {
      dst_addr = &((struct sockaddr_in *)dst)->sin_addr;
      dst_len = 4;
    }
  else if(dst->sa_family == AF_INET6)
    {
      dst_addr = &((struct sockaddr_in6 *)dst)->sin6_addr;
      dst_len = 16;
    }
  else
    {
      return -1;
    }

  /*
   * fill out a route request.
   * we use the standard netlink header, with a route msg subheader
   * to query for the outgoing interface.
   * the message includes one attribute - the destination address
   * we are querying the route for.
   */
  memset(buf, 0, sizeof(buf));
  nlmsg  = (struct nlmsghdr *)buf;
  nlmsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
  nlmsg->nlmsg_type  = RTM_GETROUTE;
  nlmsg->nlmsg_flags = NLM_F_REQUEST;
  nlmsg->nlmsg_seq   = seq;
  nlmsg->nlmsg_pid   = pid;

  /* netlink wants the bit length of each address */
  rtmsg = NLMSG_DATA(nlmsg);
  rtmsg->rtm_family  = dst->sa_family;
  rtmsg->rtm_flags   = 0;
  rtmsg->rtm_dst_len = dst_len * 8;

  rta = (struct rtattr *)(buf + NLMSG_ALIGN(nlmsg->nlmsg_len));
  rta->rta_type = RTA_DST;
  rta->rta_len  = RTA_LENGTH(dst_len);
  nlmsg->nlmsg_len += RTA_LENGTH(dst_len);
  memcpy(RTA_DATA(rta), dst_addr, dst_len);

  /* send the request */
  if((error = send(fd, buf, nlmsg->nlmsg_len, 0)) != nlmsg->nlmsg_len)
    {
      printerror(errno, strerror, __func__, "could not send");
      return -1;
    }

  return 0;
}
#endif

int scamper_rtsock_getroute(scamper_fd_t *fdn, scamper_addr_t *dst)
{
  struct sockaddr_storage ss;
  rtsock_pair_t *pair;
  int af, fd;

  if(dst->type == SCAMPER_ADDR_TYPE_IPV4) af = AF_INET;
  else if(dst->type == SCAMPER_ADDR_TYPE_IPV6) af = AF_INET6;
  else return -1;

  sockaddr_compose((struct sockaddr *)&ss, af, dst->addr, 0);

  if((fd = scamper_fd_fd_get(fdn)) == -1)
    {
      return -1;
    }

  if(scamper_rtsock_getifindex(fd, (struct sockaddr *)&ss) == -1)
    {
      return -1;
    }

  if((pair = rtsock_pair_alloc(dst)) == NULL)
    {
      return -1;
    }

  if((pair->node = dlist_tail_push(pairs, pair)) == NULL)
    {
      rtsock_pair_free(pair);
      return -1;
    }

  /* the next rtsock message we send needs to have a different sequence */
  seq++;

  return 0;
}

#if defined(__linux__)
#if 0
static void rtattr_dump(struct rtattr *rta)
{
  char *rta_type;
  char  rta_data[64];
  int   i;

  switch(rta->rta_type)
    {
    case RTA_UNSPEC:    rta_type = "unspec";    break;
    case RTA_DST:       rta_type = "dst";       break;
    case RTA_SRC:       rta_type = "src";       break;
    case RTA_IIF:       rta_type = "iif";       break;
    case RTA_OIF:       rta_type = "oif";       break;
    case RTA_GATEWAY:   rta_type = "gateway";   break;
    case RTA_PRIORITY:  rta_type = "priority";  break;
    case RTA_PREFSRC:   rta_type = "prefsrc";   break;
    case RTA_METRICS:   rta_type = "metrics";   break;
    case RTA_MULTIPATH: rta_type = "multipath"; break;
    case RTA_PROTOINFO: rta_type = "protoinfo"; break;
    case RTA_FLOW:      rta_type = "flow";      break;
    case RTA_CACHEINFO: rta_type = "cacheinfo"; break;
    case RTA_SESSION:   rta_type = "session";   break;
    default:            rta_type = "<unknown>"; break;
    }

  for(i=0;i<rta->rta_len-sizeof(struct rtattr)&&i<(sizeof(rta_data)/2)-1;i++)
    {
      snprintf(&rta_data[i*2], 3, "%02x",
	       *(uint8_t *)(((char *)rta) + sizeof(struct rtattr) + i));
    }

  if(i != 0)
    {
      scamper_debug(__func__, "type %s len %d data %s",
		    rta_type, rta->rta_len-sizeof(struct rtattr), rta_data);
    }
  else
    {
      scamper_debug(__func__, "type %s\n", rta_type);
    }

  return;
}
#endif

static int rtsock_parsemsg(uint8_t *buf, ssize_t len, rtsock_msg_t *rtsmsg)
{
  struct nlmsghdr *nlmsg;
  struct nlmsgerr *nlerr;
  struct rtmsg    *rtmsg;
  struct rtattr   *rta;
  void            *gwaddr = NULL;

  if(len < sizeof(struct nlmsghdr))
    {
      return -1;
    }

  nlmsg = (struct nlmsghdr *)buf;

#if 0
  scamper_debug(__func__, "nlmsghdr len %d type %d flags 0x%08x seq %d pid %d",
		nlmsg->nlmsg_len, nlmsg->nlmsg_type, nlmsg->nlmsg_flags,
		nlmsg->nlmsg_seq, nlmsg->nlmsg_pid);
#endif

  /* if the message isn't addressed to this pid, drop it */
  if(nlmsg->nlmsg_pid != pid)
    {
      return -1;
    }

  rtsmsg->rr.ifindex = -1;
  rtsmsg->rr.gwaddr = NULL;
  rtsmsg->rr.error = 0;

  if(nlmsg->nlmsg_type == RTM_NEWROUTE)
    {
      rtmsg = NLMSG_DATA(nlmsg);

#if 0
      scamper_debug(__func__, "rtmsg family %d dst_len %d src_len %d tos %d "
		    "table %d protocol %d scope %d type %d flags 0x%08x",
		    rtmsg->rtm_family, rtmsg->rtm_dst_len, rtmsg->rtm_src_len,
		    rtmsg->rtm_tos, rtmsg->rtm_table, rtmsg->rtm_protocol,
		    rtmsg->rtm_scope, rtmsg->rtm_type, rtmsg->rtm_flags);
#endif

      /* this is the payload length of the response packet */
      len = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));

      /* hunt through the payload for the RTA_OIF entry */
      rta = RTM_RTA(rtmsg);
      while(RTA_OK(rta, len))
	{
#if 0
	  rtattr_dump(rta);
#endif

	  switch(rta->rta_type)
	    {
	    case RTA_OIF:
	      rtsmsg->rr.ifindex = *(unsigned *)RTA_DATA(rta);
	      break;

	    case RTA_GATEWAY:
	      gwaddr = RTA_DATA(rta);
	      break;
	    }

	  rta = RTA_NEXT(rta, len);
	}
    }
  else if(nlmsg->nlmsg_type == NLMSG_ERROR)
    {
      nlerr = NLMSG_DATA(nlmsg);
      rtsmsg->rr.error = nlerr->error;
    }
  else return -1;

  if(gwaddr != NULL)
    {
      if(rtmsg->rtm_family == AF_INET)
	{
	  rtsmsg->rr.gwaddr = scamper_addrcache_get_ipv4(addrcache, gwaddr);
	}
      else if(rtmsg->rtm_family == AF_INET6)
	{
	  rtsmsg->rr.gwaddr = scamper_addrcache_get_ipv6(addrcache, gwaddr);
	}

      if(rtsmsg->rr.gwaddr == NULL)
	{
	  return -1;
	}
    }

  rtsmsg->pid        = nlmsg->nlmsg_pid;
  rtsmsg->seq        = nlmsg->nlmsg_seq;

  return 0;
}
#endif

#if defined(HAVE_BSD_ROUTE_SOCKET)
static int rtsock_parsemsg(uint8_t *buf, ssize_t len, rtsock_msg_t *rtsmsg)
{
  struct rt_msghdr   *rtm;
  struct sockaddr    *addrs[RTAX_MAX];
  struct sockaddr_dl *sdl;
  struct sockaddr    *sa;
  struct in6_addr    *ip6;
  ssize_t             off, tmp;
  int                 i;
  void               *addr;

  if(len < (ssize_t)sizeof(struct rt_msghdr))
    {
      scamper_debug(__func__, "len %d != %d", len, sizeof(struct rt_msghdr));
      return -1;
    }

  rtm = (struct rt_msghdr *)buf;

  /* if the message isn't addressed to this pid, drop it */
  if(rtm->rtm_pid != pid)
    {
      scamper_debug(__func__, "pid %d != %d", rtm->rtm_pid, pid);
      return -1;
    }

  /* if the message is not a response, we don't want it either */
  if((rtm->rtm_flags & RTF_DONE) == 0)
    {
      scamper_debug(__func__, "rtm->rtm_flags not done");
      return -1;
    }

  /* if the message is not a response to a GET message, throw it away */
  if(rtm->rtm_type != RTM_GET)
    {
      scamper_debug(__func__, "rtm->rtm_type not get");
      return -1;
    }

  rtsmsg->rr.ifindex = -1;
  rtsmsg->rr.gwaddr = NULL;

  off = sizeof(struct rt_msghdr);
  for(i=0; i<RTAX_MAX; i++)
    {
      if(rtm->rtm_addrs & (1 << i))
	{
	  addrs[i] = sa = (struct sockaddr *)(buf + off);

	  if((tmp = sockaddr_len(sa)) == -1)
	    {
	      scamper_debug(__func__, "unhandled af %d", sa->sa_family);
	      break;
	    }

	  off += ROUNDUP(tmp);
	}
      else addrs[i] = NULL;
    }

  if((sdl = (struct sockaddr_dl *)addrs[RTAX_IFP]) != NULL)
    {
      assert(sdl->sdl_family == AF_LINK);
      rtsmsg->rr.ifindex = sdl->sdl_index;
    }

  if((sa = addrs[RTAX_GATEWAY]) != NULL)
    {
      if(sa->sa_family == AF_INET)
	{
	  i = SCAMPER_ADDR_TYPE_IPV4;
	  addr = &((struct sockaddr_in *)sa)->sin_addr;
	}
      else if(sa->sa_family == AF_INET6)
	{
	  /*
	   * check to see if the gw address is a link local address.  if it
	   * is, then drop the embedded index from the gateway address
	   */
	  ip6 = &((struct sockaddr_in6 *)sa)->sin6_addr;
	  if(IN6_IS_ADDR_LINKLOCAL(ip6))
	    {
	      ip6->s6_addr[2] = 0;
	      ip6->s6_addr[3] = 0;
	    }

	  i = SCAMPER_ADDR_TYPE_IPV6;
	  addr = ip6;
	}
      else if(sa->sa_family == AF_LINK)
	{
	  sdl = (struct sockaddr_dl *)sa;
	  if(sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == ETHER_ADDR_LEN)
	    {
	      i = SCAMPER_ADDR_TYPE_ETHERNET;
	      addr = sdl->sdl_data + sdl->sdl_nlen;
	    }
	  else addr = NULL;
	}
      else
	{
	  addr = NULL;
	}

      /*
       * if we have got a gateway address that we know what to do with,
       * then store it here.
       */
      if(addr != NULL)
	{
	  rtsmsg->rr.gwaddr = scamper_addrcache_get(addrcache, i, addr);
	  if(rtsmsg->rr.gwaddr == NULL)
	    {
	      scamper_debug(__func__, "could not get rtsmsg->rr.gwaddr");
	      return -1;
	    }
	}
    }

  rtsmsg->pid      = rtm->rtm_pid;
  rtsmsg->seq      = rtm->rtm_seq;
  rtsmsg->rr.error = rtm->rtm_errno;

  return 0;
}
#endif

/*
 * rtsock_pairs_find
 *
 * given a message sequence number, find the corresponding message that
 * was sent.
 */
static rtsock_pair_t *rtsock_pairs_find(uint16_t ms)
{
  rtsock_pair_t *pair;
  int32_t        ps = (int32_t)seq - 1;
  void          *node;

  /* check to see if there's nothing in the window */
  if(ack == ps)
    {
      scamper_debug(__func__, "empty window %d : %d", ack, ps);
      return NULL;
    }

  if((ack <= ps && (ms < ack || ps < ms)) || !(ms >= ack || ms <= ps))
    {
      scamper_debug(__func__, "mseq %d OUT of sequence %d : %d\n", ms,ack,ps);
      return NULL;
    }

  /* see if the seq is for the most recently sent route lookup */
  if(ps == ms)
    {
      /* pop the last item off the tail of the list */
      pair = dlist_tail_pop(pairs);
      return pair;
    }

  node = dlist_head_node(pairs);
  while(node != NULL)
    {
      pair = dlist_node_item(node);

      if(pair->seq == ms)
	{
	  /* extract the node from the list */
	  dlist_node_pop(pairs, node);
	  return pair;
	}

      node = dlist_node_next(node);
    }

  return NULL;
}

/*
 * scamper_rtsock_read_cb
 *
 * this callback handles reading a message from the route socket.
 * we check to see if the message is something that we have sent by parsing
 * the message out.  if we did send the message, then we search for the
 * address-sequence pair, which matches the sequence number with a route
 * lookup.
 * if we get a pair back, then we remove it from the list and look for a 
 * trace matching the address.  we then take the result from the route
 * lookup and apply it to the trace.
 */
void scamper_rtsock_read_cb(const int fd, void *param)
{
  scamper_task_t *task;
  rtsock_pair_t *pair;
  rtsock_msg_t rtsmsg;
  uint8_t buf[2048];
  ssize_t len;

  /* read something from the route socket */
  if((len = recv(fd, buf, sizeof(buf), 0)) == -1)
    {
      printerror(errno, strerror, __func__, "recv failed");
      return;
    }

  /* check to see if the message passes basic filtering */
  if(rtsock_parsemsg(buf, len, &rtsmsg) == -1)
    {
      return;
    }

  /*
   * check to see if the message is in sequence; find the address-sequence
   * pair related to this message if it is determined to be in sequence
   */
  if((pair = rtsock_pairs_find(rtsmsg.seq)) == NULL)
    {
      scamper_debug(__func__, "pair not found");
      goto done;
    }

  assert(pair->seq == rtsmsg.seq);

  /* and now use it to lookup the trace */
  if((task = scamper_target_find(pair->addr)) == NULL)
    {
      scamper_debug(__func__, "target not found");
      goto done;
    }

  /* don't need this pair struct any longer, so dispose of it */
  rtsock_pair_free(pair);

  /*
   * if the target can't handle the route socket message, don't try
   * and pass it.
   */
  if(task->funcs->handle_rt == NULL)
    {
      goto done;
    }

  task->funcs->handle_rt(task, &rtsmsg.rr);

 done:
  if(rtsmsg.rr.gwaddr != NULL) scamper_addr_free(rtsmsg.rr.gwaddr);
  return;
}

void scamper_rtsock_close(int fd)
{
  close(fd);
  return;
}

int scamper_rtsock_open_fd()
{
#if defined(HAVE_BSD_ROUTE_SOCKET)
  return socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
#elif defined(__linux__)
  return socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
#else
#error "route socket support for this system not implemented"
#endif
}

int scamper_rtsock_open()
{
  int fd;

#if defined(WITHOUT_PRIVSEP)
  if((fd = scamper_rtsock_open_fd()) == -1)
#else
  if((fd = scamper_privsep_open_rtsock()) == -1)
#endif
    {
      printerror(errno, strerror, __func__, "could not open route socket");
      return -1;
    }

  return fd;
}
#endif

#ifdef _WIN32
static int scamper_rtsock_getroute4(scamper_addr_t *dst, scamper_rt_rec_t *rr)
{
  MIB_IPFORWARDROW fw;
  DWORD dw;

  dw = GetBestRoute(((struct in_addr *)dst->addr)->s_addr, 0, &fw);
  if(dw != NO_ERROR)
    {
      rr->error = dw;
      return -1;
    }

  rr->error   = 0;
  rr->gwaddr  = NULL;
  rr->ifindex = fw.dwForwardIfIndex;

  /* determine the gateway address to use, if one is specified */
  if((dw = fw.dwForwardNextHop) == 0)
    {
      rr->gwaddr = NULL;
      return 0;
    }
  if((rr->gwaddr = scamper_addrcache_get_ipv4(addrcache, &dw)) == NULL)
    {
      rr->error = errno;
      return -1;
    }

  return 0;
}

int scamper_rtsock_getroute(scamper_addr_t *dst, scamper_rt_rec_t *rr)
{
  if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
    return scamper_rtsock_getroute4(dst, rr);

  return -1;
}
#endif

int scamper_rtsock_init()
{
#ifndef _WIN32
  if((pairs = dlist_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not allocate pair list");
      return -1;
    }

  pid = getpid();
#endif

  return 0;
}

void scamper_rtsock_cleanup()
{
#ifndef _WIN32
  rtsock_pair_t *pair;

  if(pairs != NULL)
    {
      while((pair = dlist_head_pop(pairs)) != NULL)
	{
	  free(pair);
	}

      dlist_free(pairs);
      pairs = NULL;
    }
#endif

  return;
}
