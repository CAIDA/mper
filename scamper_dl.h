/*
 * scamper_dl.h
 *
 * $Id: scamper_dl.h,v 1.30 2009/04/21 04:15:19 mjl Exp $
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

#ifndef __SCAMPER_DL_H
#define __SCAMPER_DL_H

/*
 * these flags are set in scamper_dl_rec.dl_flags
 *
 * SCAMPER_DL_FLAG_TIMESTAMP: if set, the datalink record has a timestamp
 * obtained from the datalink.
 */
#define SCAMPER_DL_FLAG_TIMESTAMP 0x01

/*
 * these types are set in scamper_dl_rec.dl_type
 *
 * SCAMPER_DL_TYPE_RAW: datalink record off a raw interface, no L2 header
 * SCAMPER_DL_TYPE_NULL: datalink record off a null interface, no L2 recorded
 * SCAMPER_DL_TYPE_ETHERNET: datalink record off an ethernet interface
 * SCAMPER_DL_TYPE_FIREWIRE: datalink record off a firewire interface
 */
#define SCAMPER_DL_TYPE_RAW       0x01
#define SCAMPER_DL_TYPE_NULL      0x02
#define SCAMPER_DL_TYPE_ETHERNET  0x03
#define SCAMPER_DL_TYPE_FIREWIRE  0x04

#define SCAMPER_DL_IS_ICMP(dl) ( \
 (dl->dl_af == AF_INET && dl->dl_ip_proto == 1) || \
 (dl->dl_af == AF_INET6 && dl->dl_ip_proto == 58))

#define SCAMPER_DL_IS_ICMP_PROTO_ICMP_ECHO_REQ(dl) ( \
 (dl->dl_af == AF_INET && dl->dl_ip_proto == 1 && \
  dl->dl_icmp_ip_proto == 1 && dl->dl_icmp_icmp_type == 8) || \
 (dl->dl_af == AF_INET6 && dl->dl_ip_proto == 58 && \
  dl->dl_icmp_ip_proto == 58 && dl->dl_icmp_icmp_type == 128))

#define SCAMPER_DL_IS_ICMP_ECHO_REQUEST(dl) ( \
 (dl->dl_af == AF_INET && dl->dl_ip_proto == 1 && dl->dl_icmp_type == 8) || \
 (dl->dl_af == AF_INET6 && dl->dl_ip_proto == 58 && dl->dl_icmp_type == 128))

#define SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) ( \
 (dl->dl_af == AF_INET && dl->dl_ip_proto == 1 && dl->dl_icmp_type == 0) || \
 (dl->dl_af == AF_INET6 && dl->dl_ip_proto == 58 && dl->dl_icmp_type == 129))

#define SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ( \
 (dl->dl_af == AF_INET && dl->dl_ip_proto == 1 && dl->dl_icmp_type == 11) || \
 (dl->dl_af == AF_INET6 && dl->dl_ip_proto == 58 && dl->dl_icmp_type == 3))

#define SCAMPER_DL_IS_ICMP_UNREACH(dl) ( \
 (dl->dl_af == AF_INET && dl->dl_ip_proto == 1 && dl->dl_icmp_type == 3) || \
 (dl->dl_af == AF_INET6 && dl->dl_ip_proto == 58 && dl->dl_icmp_type == 1))

#define SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl) ( \
 (dl->dl_af == AF_INET && dl->dl_ip_proto == 1 && dl->dl_icmp_type == 3 && \
  dl->dl_icmp_code == 4) || \
 (dl->dl_af == AF_INET6 && dl->dl_ip_proto == 58 && dl->dl_icmp_type == 2))

/*
 * scamper_dl_rec
 *
 * this structure summarises details provided by the datalink of packets
 * that passed the filter.
 */
typedef struct scamper_dl_rec
{
  /* flags, meanings defined above */
  uint32_t         dl_flags;

  /* type of the datalink which passed the packet */
  uint32_t         dl_type;

  /* the time that the packet was seen on the datalink */
  union
  {
    struct timeval tv;
  } dl_time_un;

  /*
   * the index assigned by the OS that identifies the interface the
   * packet was pulled off
   */
  int            dl_ifindex;

  /*
   * category 1: the datalink frame
   *
   * scamper records the source and destination link local addresses if the
   * frame is ethernet or firewire; otherwise these fields are null;
   */
  uint8_t       *dl_lladdr_src;
  uint8_t       *dl_lladdr_dst;

  /* the address family of the frame: either AF_INET or AF_INET6 */
  int            dl_af;

  /*
   * category 2: the IP header
   *
   * scamper records the source and destination IP addresses, the size
   * of the packet, the ID and ToS if AF_INET, the TTL and the protocol
   * inside the packet.
   */
  uint8_t       *dl_ip_src;
  uint8_t       *dl_ip_dst;
  uint16_t       dl_ip_size;
  uint16_t       dl_ip_id;
  uint32_t       dl_ip_flow;
  uint8_t        dl_ip_tos;
  uint8_t        dl_ip_ttl;
  uint8_t        dl_ip_proto;

  /*
   * category 3: the transport header
   *
   * scamper records the details of the datalink in the following union
   * [if it understands it]
   */
  union
  {
    struct dl_udp
    {
      uint16_t sport;
      uint16_t dport;
      uint16_t sum;
    } dl_udp;

    struct dl_tcp
    {
      uint16_t sport;
      uint16_t dport;
      uint32_t seq;
      uint32_t ack;
      uint8_t  off;
      uint8_t  flags;
      uint16_t window;
    } dl_tcp;

    struct dl_icmp
    {
      
      uint8_t  type;
      uint8_t  code;

      union
      {
	struct idseq
	{
	  uint16_t id;
	  uint16_t seq;
	} idseq;

	uint16_t nhmtu;
      } icmp_un;

      uint8_t  *ip_src;
      uint8_t  *ip_dst;
      uint16_t  ip_size;
      uint16_t  ip_id;   /* IPv4 ID */
      uint32_t  ip_flow; /* IPv6 flow */
      uint8_t   ip_tos;
      uint8_t   ip_ttl;
      uint8_t   ip_proto;

      union
      {
	struct icmp_udp
	{
	  uint16_t sport;
	  uint16_t dport;
	  uint16_t sum;
	} icmp_udp;

	struct icmp_tcp
	{
	  uint16_t sport;
	  uint16_t dport;
	  uint32_t seq;
	} icmp_tcp;

	struct icmp_icmp
	{
	  uint8_t  type;
	  uint8_t  code;
	  uint16_t id;
	  uint16_t seq;
	} icmp_icmp;

      } trans_un;

    } dl_icmp;

  } dl_trans_un;

} scamper_dl_rec_t;

#define dl_flags              dl_flags
#define dl_tv                 dl_time_un.tv
#define dl_ifindex            dl_ifindex
#define dl_lladdr_src         dl_lladdr_src
#define dl_lladdr_dst         dl_lladdr_dst
#define dl_af                 dl_af
#define dl_ip_src             dl_ip_src
#define dl_ip_dst             dl_ip_dst
#define dl_ip_size            dl_ip_size
#define dl_ip_id              dl_ip_id
#define dl_ip_tos             dl_ip_tos
#define dl_ip_ttl             dl_ip_ttl
#define dl_ip_hlim            dl_ip_ttl
#define dl_ip_proto           dl_ip_proto
#define dl_udp_sport          dl_trans_un.dl_udp.sport
#define dl_udp_dport          dl_trans_un.dl_udp.dport
#define dl_udp_sum            dl_trans_un.dl_udp.sum
#define dl_tcp_sport          dl_trans_un.dl_tcp.sport
#define dl_tcp_dport          dl_trans_un.dl_tcp.dport
#define dl_tcp_seq            dl_trans_un.dl_tcp.seq
#define dl_tcp_ack            dl_trans_un.dl_tcp.ack
#define dl_tcp_off            dl_trans_un.dl_tcp.off
#define dl_tcp_flags          dl_trans_un.dl_tcp.flags
#define dl_tcp_window         dl_trans_un.dl_tcp.window
#define dl_icmp_type          dl_trans_un.dl_icmp.type
#define dl_icmp_code          dl_trans_un.dl_icmp.code
#define dl_icmp_id            dl_trans_un.dl_icmp.icmp_un.idseq.id
#define dl_icmp_seq           dl_trans_un.dl_icmp.icmp_un.idseq.seq
#define dl_icmp_nhmtu         dl_trans_un.dl_icmp.icmp_un.nhmtu
#define dl_icmp_ip_src        dl_trans_un.dl_icmp.ip_src
#define dl_icmp_ip_dst        dl_trans_un.dl_icmp.ip_dst
#define dl_icmp_ip_size       dl_trans_un.dl_icmp.ip_size
#define dl_icmp_ip_id         dl_trans_un.dl_icmp.ip_id
#define dl_icmp_ip_flow       dl_trans_un.dl_icmp.ip_flow
#define dl_icmp_ip_tos        dl_trans_un.dl_icmp.ip_tos
#define dl_icmp_ip_ttl        dl_trans_un.dl_icmp.ip_ttl
#define dl_icmp_ip_hlim       dl_trans_un.dl_icmp.ip_ttl
#define dl_icmp_ip_proto      dl_trans_un.dl_icmp.ip_proto
#define dl_icmp_udp_sport     dl_trans_un.dl_icmp.trans_un.icmp_udp.sport
#define dl_icmp_udp_dport     dl_trans_un.dl_icmp.trans_un.icmp_udp.dport
#define dl_icmp_udp_sum       dl_trans_un.dl_icmp.trans_un.icmp_udp.sum
#define dl_icmp_tcp_sport     dl_trans_un.dl_icmp.trans_un.icmp_tcp.sport
#define dl_icmp_tcp_dport     dl_trans_un.dl_icmp.trans_un.icmp_tcp.dport
#define dl_icmp_tcp_seq       dl_trans_un.dl_icmp.trans_un.icmp_tcp.seq
#define dl_icmp_icmp_type     dl_trans_un.dl_icmp.trans_un.icmp_icmp.type
#define dl_icmp_icmp_code     dl_trans_un.dl_icmp.trans_un.icmp_icmp.code
#define dl_icmp_icmp_id       dl_trans_un.dl_icmp.trans_un.icmp_icmp.id
#define dl_icmp_icmp_seq      dl_trans_un.dl_icmp.trans_un.icmp_icmp.seq

#define SCAMPER_DL_TX_UNSUPPORTED           0x00
#define SCAMPER_DL_TX_ETHERNET              0x01
#define SCAMPER_DL_TX_NULL                  0x02
#define SCAMPER_DL_TX_RAW                   0x03
#define SCAMPER_DL_TX_ETHLOOP               0x04

typedef struct scamper_dl scamper_dl_t;

/*
 * scamper_dl_init:    initialise scamper's datalink structures
 * scamper_dl_cleanup: cleanup scamper's datalink structures
 */
int scamper_dl_init(void);
void scamper_dl_cleanup(void);

/*
 * scamper_dl_open:    open datalink interface, use privsep if required
 * scamper_dl_open_fd: open datalink interface. for the benefit of privsep code
 */
int scamper_dl_open(const int ifindex);
int scamper_dl_open_fd(const int ifindex);
void scamper_dl_close(int fd);

/*
 * scamper_dl_state_alloc: allocate state to be held with fd
 * scamper_dl_state_free:  deallocate state
 */
#ifdef __SCAMPER_FD_H
scamper_dl_t *scamper_dl_state_alloc(scamper_fd_t *fdn);
void scamper_dl_state_free(scamper_dl_t *dl);
#endif

/*
 * scamper_dl_read_cb: callback for read events
 */
void scamper_dl_read_cb(const int fd, void *param);

/*
 * scamper_dl_tx:
 * transmit the packet, including relevant headers which are included, on
 * the datalink.
 */
int scamper_dl_tx(const scamper_dl_t *dl,
		  const uint8_t *pkt, const size_t len);

#ifdef _SCAMPER_ADDR_H
int scamper_dl_rec_src(scamper_dl_rec_t *dl, scamper_addr_t *addr);
#endif

/*
 * scamper_dl_hdr
 *
 * this struct holds appropriate layer-2 headers to prepend on a packet
 * to be transmitted with a datalink socket.
 */
typedef struct scamper_dl_hdr
{
  uint8_t  *dl_hdr;
  uint16_t  dl_size;
} scamper_dl_hdr_t;

/*
 * scamper_dl_hdr_alloc:
 *
 * given a datalink socket and a gateway address, form a datalink header
 * to use when framing a packet.
 */
#if defined(__SCAMPER_ADDR_H) && defined(__SCAMPER_FD_H)
scamper_dl_hdr_t *scamper_dl_hdr_alloc(scamper_fd_t *dl, scamper_addr_t *src,
				       scamper_addr_t *dst,
				       scamper_addr_t *gw);
#endif

/*
 * scamper_dl_hdr_free:
 *
 * don't need the dl_hdr any longer.
 */
void scamper_dl_hdr_free(scamper_dl_hdr_t *dlhdr);

#if !defined(NDEBUG) && !defined(WITHOUT_DEBUGFILE)
void    scamper_dl_rec_tcp_print(scamper_dl_rec_t *dl);
#else
#define scamper_dl_rec_tcp_print(dl) ((void)0)
#endif

#endif /* __SCAMPER_DL_H */
