/*
 * internal.h
 *
 * $Id: internal.h,v 1.11 2011/04/17 03:46:32 mjl Exp $
 *
 *        Matthew Luckie, WAND Group, Computer Science, University of Waikato
 *        mjl@wand.net.nz
 *
 * Copyright (C) 2003-2011 The University of Waikato
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
typedef unsigned __int64 uint64_t;
typedef __int16 int16_t;
typedef int ssize_t;
typedef int pid_t;
typedef int socklen_t;
typedef int mode_t;
typedef unsigned short sa_family_t;
#define __func__ __FUNCTION__
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <iphlpapi.h>
#include <process.h>
#include <direct.h>
#include "wingetopt.h"
#define _CRT_RAND_S
#endif

#if defined(__APPLE__)
#define _BSD_SOCKLEN_T_
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__FreeBSD__)
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__NetBSD__)
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__OpenBSD__)
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__DragonFly__)
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__linux__)
#define __FAVOR_BSD
#endif

#if defined(__sun__)
#define BSD_COMP
#define _XPG4_2
#define __EXTENSIONS__
#define HAVE_BSD_ROUTE_SOCKET
#define RTAX_MAX RTA_NUMBITS
#define RTAX_GATEWAY 1
#define RTAX_IFP 4
#endif

#ifndef _WIN32
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif

#if defined(HAVE_BPF)
#include <net/bpf.h>
#endif

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#if defined(__linux__)
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <limits.h>
#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif
#define HAVE_IPTABLES
#endif

#if defined(__sun__)
#define HAVE_DLPI
#define MAXDLBUF 8192
#include <sys/bufmod.h>
#include <sys/dlpi.h>
#include <stropts.h>
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
#define HAVE_IPFW
#include <netinet/ip_fw.h>
#if __FreeBSD_version < 700017 || defined(__APPLE__)
#include <netinet6/ip6_fw.h>
#endif
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>

#if defined(AF_UNIX) && !defined(_WIN32)
#define HAVE_SOCKADDR_UN
#endif

#if defined(_WIN32) || defined(__sun__) || defined(__linux__)
#define IP_HDR_HTONS
#endif
#if defined(__OpenBSD__) && OpenBSD >= 199706
#define IP_HDR_HTONS
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#ifdef _WIN32
#define SHUT_RDWR SD_BOTH
#define STDIN_FILENO 0
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define S_IFIFO _S_IFIFO
#define S_IFREG _S_IFREG
#define MAXHOSTNAMELEN 256
#define close _close
#define fdopen _fdopen
#define fileno _fileno
#define ftruncate _chsize
#define lseek _lseek
#define mkdir(dir,mode) _mkdir(dir)
#define open _open
#define read _read
#define snprintf _snprintf
#define strdup _strdup
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define write _write
#endif

#include <assert.h>

#if defined(__sun__) || defined(_WIN32)
struct ip6_ext
{
  uint8_t ip6e_nxt;
  uint8_t ip6e_len;
};
#endif

#ifdef _WIN32
struct ip
{
  uint8_t        ip_vhl;
  uint8_t        ip_tos;
  uint16_t       ip_len;
  uint16_t       ip_id;
  uint16_t       ip_off;
  uint8_t        ip_ttl;
  uint8_t        ip_p;
  uint16_t       ip_sum;
  struct in_addr ip_src;
  struct in_addr ip_dst;
};
struct ip6_hdr
{
  union
  {
    struct ip6_hdrctl
    {
      uint32_t flow;
      uint16_t plen;
      uint8_t  nxt;
      uint8_t  hlim;
    } hdr;
    uint8_t vfc;
  } ip6un;
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
};
struct ip6_frag
{
  uint8_t  ip6f_nxt;
  uint8_t  ip6f_reserved;
  uint16_t ip6f_offlg;
  uint32_t ip6f_ident;
};
struct icmp
{
  uint8_t   icmp_type;
  uint8_t   icmp_code;
  uint16_t  icmp_cksum;
  uint16_t  icmp_id;
  uint16_t  icmp_seq;
  struct ip icmp_ip;
};
struct icmp6_hdr
{
  uint8_t  icmp6_type;
  uint8_t  icmp6_code;
  uint16_t icmp6_cksum;
  union
  {
    uint32_t data32[0];
    uint16_t data16[1];
  } icmp6un;
};
struct udphdr
{
  uint16_t uh_sport;
  uint16_t uh_dport;
  uint16_t uh_ulen;
  uint16_t uh_sum;
};
struct tcphdr {
  uint16_t th_sport;
  uint16_t th_dport;
  uint32_t th_seq;
  uint32_t th_ack;
  uint8_t  th_offx2;
  uint8_t  th_flags;
  uint16_t th_win;
  uint16_t th_sum;
  uint16_t th_urp;
};
struct iovec
{
  void   *iov_base;
  size_t  iov_len;
};
#define icmp_nextmtu icmp_seq
#define ip6_vfc      ip6un.vfc
#define ip6_flow     ip6un.hdr.flow
#define ip6_plen     ip6un.hdr.plen
#define ip6_nxt      ip6un.hdr.nxt
#define ip6_hlim     ip6un.hdr.hlim
#define icmp6_data32 icmp6un.data32
#define icmp6_mtu    icmp6un.data32[0]
#define icmp6_id     icmp6un.data16[0]
#define icmp6_seq    icmp6un.data16[1]
#endif

#if defined(__sun__)
# define s6_addr32 _S6_un._S6_u32
#elif !defined(s6_addr32)
# define s6_addr32 __u6_addr.__u6_addr32
#endif

#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFREG) && ((m) & (S_IFIFO|S_IFCHR|S_IFDIR)) == 0)
#endif

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#ifndef ND_ROUTER_ADVERT
#define ND_ROUTER_ADVERT 134
#endif

#ifndef ND_NEIGHBOR_SOLICIT
#define ND_NEIGHBOR_SOLICIT 135
#endif

#ifndef ND_NEIGHBOR_ADVERT
#define ND_NEIGHBOR_ADVERT 136
#endif

#ifndef IP_DF
#define IP_DF 0x4000
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

#ifndef IPTOS_ECN_ECT1
#define IPTOS_ECN_ECT1 0x01
#endif

#ifndef IPTOS_ECN_ECT0
#define IPTOS_ECN_ECT0 0x02
#endif

#ifndef IPTOS_ECN_CE
#define IPTOS_ECN_CE 0x03
#endif

#ifndef IPTOS_ECN_MASK
#define	IPTOS_ECN_MASK 0x03
#endif

#ifndef TH_FIN
#define TH_FIN 0x01
#endif

#ifndef TH_SYN
#define TH_SYN 0x02
#endif

#ifndef TH_RST
#define TH_RST 0x04
#endif

#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif

#ifndef TH_ACK
#define TH_ACK 0x10
#endif

#ifndef TH_URG
#define TH_URG 0x20
#endif

#ifndef TH_ECE
#define TH_ECE 0x40
#endif

#ifndef TH_CWR
#define TH_CWR 0x80
#endif

#ifndef ICMP_MINLEN
#define	ICMP_MINLEN 8
#endif

#ifndef ICMP_UNREACH
#define ICMP_UNREACH 3
#endif

#ifndef ICMP_UNREACH_NET
#define ICMP_UNREACH_NET 0
#endif

#ifndef ICMP_UNREACH_HOST
#define ICMP_UNREACH_HOST 1
#endif

#ifndef ICMP_UNREACH_PROTOCOL
#define ICMP_UNREACH_PROTOCOL 2
#endif

#ifndef ICMP_UNREACH_PORT
#define ICMP_UNREACH_PORT 3
#endif

#ifndef ICMP_UNREACH_NEEDFRAG
#define ICMP_UNREACH_NEEDFRAG 4
#endif

#ifndef ICMP_UNREACH_SRCFAIL
#define ICMP_UNREACH_SRCFAIL 5
#endif

#ifndef ICMP_UNREACH_NET_UNKNOWN
#define ICMP_UNREACH_NET_UNKNOWN 6
#endif

#ifndef ICMP_UNREACH_HOST_UNKNOWN
#define ICMP_UNREACH_HOST_UNKNOWN 7
#endif

#ifndef ICMP_UNREACH_ISOLATED
#define ICMP_UNREACH_ISOLATED 8
#endif

#ifndef ICMP_UNREACH_NET_PROHIB
#define ICMP_UNREACH_NET_PROHIB 9
#endif

#ifndef ICMP_UNREACH_HOST_PROHIB
#define ICMP_UNREACH_HOST_PROHIB 10
#endif

#ifndef ICMP_UNREACH_TOSNET
#define ICMP_UNREACH_TOSNET 11
#endif

#ifndef ICMP_UNREACH_TOSHOST
#define ICMP_UNREACH_TOSHOST 12
#endif

#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB 13
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#ifndef ICMP_TIMXCEED
#define ICMP_TIMXCEED 11
#endif

#ifndef ICMP_TIMXCEED_INTRANS
#define ICMP_TIMXCEED_INTRANS 0
#endif

#ifndef ICMP_TIMXCEED_REASS
#define ICMP_TIMXCEED_REASS 1
#endif

#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH 1
#endif

#ifndef ICMP6_PACKET_TOO_BIG
#define ICMP6_PACKET_TOO_BIG 2
#endif

#ifndef ICMP6_TIME_EXCEEDED
#define ICMP6_TIME_EXCEEDED 3
#endif

#ifndef ICMP6_TIME_EXCEED_TRANSIT
#define ICMP6_TIME_EXCEED_TRANSIT 0
#endif

#ifndef ICMP6_TIME_EXCEED_REASSEMBLY
#define ICMP6_TIME_EXCEED_REASSEMBLY 1
#endif

#ifndef ICMP6_DST_UNREACH_NOROUTE
#define ICMP6_DST_UNREACH_NOROUTE 0
#endif

#ifndef ICMP6_DST_UNREACH_ADMIN
#define ICMP6_DST_UNREACH_ADMIN 1
#endif

#ifndef ICMP6_DST_UNREACH_BEYONDSCOPE
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2
#endif

#ifndef ICMP6_DST_UNREACH_ADDR
#define ICMP6_DST_UNREACH_ADDR 3
#endif

#ifndef ICMP6_DST_UNREACH_NOPORT
#define ICMP6_DST_UNREACH_NOPORT 4
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#endif

#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY 129
#endif
