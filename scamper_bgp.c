/*
 * scamper_bgp.c: an implementation of RFC 1654 BGP-4
 *
 *     Matthew Luckie
 *
 *
 * $Id: scamper_bgp.c,v 1.14 2006/11/29 03:06:41 mjl Exp $
 *
 */

#if defined(__APPLE__)
#define _BSD_SOCKLEN_T_
#include <stdint.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_bgp.h"
#include "scamper_debug.h"
#include "scamper_fds.h"
#include "utils.h"

#if defined(__sun__)
# define s6_addr32 _S6_un._S6_u32
#elif !defined(s6_addr32)
# define s6_addr32 __u6_addr.__u6_addr32
#endif

#define BGP_OPEN         1
#define BGP_UPDATE       2
#define BGP_NOTIFICATION 3
#define BGP_KEEPALIVE    4

#define BGP_STATE_CONNECT      0x00
#define BGP_STATE_OPEN_WAIT    0x01

uint32_t bits2netmask[33];

typedef struct bgp_conn
{
  /* the address of the BGP peer, and the ASN to use with it */
  struct sockaddr *sockaddr;
  uint16_t         our_asn;
  uint16_t         their_asn;

  /* current state of the connection, as held by the BGP server */
  int              state;

  /* fd handles that get read and write notifications */
  scamper_fd_t    *rfd;
  scamper_fd_t    *wfd;

  int              holdtime; 

  uint8_t         *rbuf;
  size_t           rbuflen;
} bgp_conn_t;

typedef struct bgp_prefix_ipv4
{
  struct in_addr prefix;
  uint8_t        len;
} bgp_prefix_ipv4_t;

typedef struct bgp_prefix_ipv6
{
  struct in6_addr prefix;
  uint8_t         len;
} bgp_prefix_ipv6_t;

static int prefix_ipv4_parse(const uint8_t *buf, bgp_prefix_ipv4_t *prefix)
{
  int bits, bytes;

  if((bits = buf[0]) > 0)
    {
      bytes = ((bits % 8) != 0 ? (bits/8) + 1 : bits/8);
      memcpy(&prefix->prefix, buf+1, bytes);
      prefix->len = bits;

      prefix->prefix.s_addr &= bits2netmask[bits];
    }
  else
    {
      bytes = 0;
      memset(prefix, 0, sizeof(bgp_prefix_ipv4_t));
    }

  return 1 + bytes;
}

static int prefix_ipv6_parse(const uint8_t *buf, bgp_prefix_ipv6_t *prefix)
{
  uint32_t nm;
  int bits, bytes;
  int i;

  if((bits = buf[0]) > 0)
    {
      bytes = ((bits % 8) != 0 ? (bits/8) + 1 : bits/8);
      memcpy(&prefix->prefix, buf+1, bytes);
      prefix->len = bits;

      for(i=0; i<4; i++)
	{
	  bits -= (nm = bits > 32 ? 32 : bits);
	  prefix->prefix.s6_addr[i] &= bits2netmask[nm];
	}
    }
  else
    {
      bytes = 0;
      memset(prefix, 0, sizeof(bgp_prefix_ipv6_t));
    }

  return 1 + bytes;
}

static void bgp_conn_free(bgp_conn_t *conn)
{
  int fd = -1;

  if(conn->rfd != NULL)
    {
      fd = scamper_fds_fd_get(conn->rfd);
      scamper_fds_del(conn->rfd);
    }

  if(conn->wfd != NULL)
    {
      if(fd == -1) fd = scamper_fds_fd_get(conn->wfd);
      scamper_fds_del(conn->wfd);
    }

  if(fd != -1) close(fd);

  if(conn->sockaddr != NULL) free(conn->sockaddr);
  if(conn->rbuf != NULL)     free(conn->rbuf);

  free(conn);
  return;
}

static bgp_conn_t *bgp_conn_alloc(const struct sockaddr *sa, const int asn)
{
  bgp_conn_t *conn;

  if((conn = malloc_zero(sizeof(bgp_conn_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc conn");
      goto err;
    }

  if((conn->sockaddr = sockaddr_dup(sa)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not dup sockaddr");
      goto err;
    }

  conn->state    = BGP_STATE_CONNECT;
  conn->holdtime = 4 * 60;
  conn->our_asn  = asn;

  return conn;

 err:
  if(conn != NULL) bgp_conn_free(conn);
  return NULL;
}

/*
 * bgp_send
 *
 * given a message type, some data, and the data's length, send a bgp message
 * using the fixed size header in section 4.1
 *
 */
static int bgp_send(const int fd, const uint8_t type,
		    const uint8_t *data, const uint16_t len)
{
  int      i;
  uint16_t junk16;
  uint8_t  hdr[16+2+1];

  assert(len < 4096 - 19);
  assert(type == 1 || type == 2 || type == 3 || type == 4);
  assert(len == 0 || data != NULL);

  /*
   * section 4.1: each message has a fixed size header
   * 128 bits of marker, 16 bits length, 8 bits type
   */
  junk16 = htons(len + 19);
  memset(hdr, 0xff, 16);
  memcpy(hdr+16, &junk16, 2);
  hdr[18] = type;
  if((i = send(fd, hdr, 19, 0)) != 19)
    {
      if(i == -1)
	{
	  printerror(errno, strerror, __func__, "send header failed");
	}
      else
	{
	  printerror(0, NULL, __func__, "sent %d bytes of header", i);
	}
      return -1;
    }

  /* send the data */
  if(len > 0 && (i = send(fd, data, len, 0)) != len)
    {
      if(i == -1)
	{
	  printerror(errno, strerror, __func__, "send data[%d] failed", len);
	}
      else
	{
	  fprintf(stderr, "bgp_send: sent %d of %d bytes data", i, len);
	}
      return -1;
    }

  return 0;
}

/*
 * bgp_send_open
 *
 * form an open message and send it.  to do this, we need to determine
 * our id and send it with the open message.
 */
static int bgp_send_open(const int fd, const bgp_conn_t *conn)
{
  struct sockaddr_storage sas;
  socklen_t socklen;
  uint16_t junk16;
  uint8_t buf[9];

  /*
   * get the source address that we use in this connection and use it as
   * our id
   */
  socklen = sizeof(sas);
  memset(&sas, 0, socklen);
  if(getsockname(fd, (struct sockaddr *)&sas, &socklen) == -1)
    {
      printerror(errno, strerror, __func__, "getsockname failed");
      return -1;
    }

  if(sas.ss_family != AF_INET)
    {
      scamper_debug(__func__, "require AF_INET socket, got af=%d socket",
		    sas.ss_family);
      return -1;
    }

  /* our ASN */
  junk16 = htons(conn->our_asn);
  memcpy(buf+0, &junk16, 2);

  /* hold time */
  junk16 = htons(conn->holdtime);
  memcpy(buf+2, &junk16, 2);

  /* our ID */
  memcpy(buf+4, &((struct sockaddr_in *)&sas)->sin_addr, 4);

  /* no parameters */
  buf[8] = 0;

  return bgp_send(fd, BGP_OPEN, buf, 9);
}

static int bgp_send_keepalive(const int fd, const bgp_conn_t *conn)
{
  return bgp_send(fd, BGP_KEEPALIVE, NULL, 0);
}

static int bgp_read_open(bgp_conn_t *conn,
			 const uint8_t *buf, const uint16_t len)
{
  uint16_t asn;
  uint16_t holdtime;

#ifndef NDEBUG
  char peer[128];
  char id[24];
#endif

  /*
   * 4.2: the minimum length of the open message is 29 bytes
   * this function has the length field passed without the header (19 bytes)
   */
  if(len < 10)
    {
      scamper_debug(__func__, "len %d < 10", len);
      return -1;
    }

  memcpy(&asn, buf+1, 2);
  memcpy(&holdtime, buf+3, 2);
  asn = ntohs(asn);
  holdtime = ntohs(holdtime);

  scamper_debug(__func__,
		"peer %s ver %d AS %d holdtime %d id %s auth %d len %d",
		sockaddr_tostr(conn->sockaddr, peer, sizeof(peer)),
		buf[0], asn, holdtime,
		inet_ntop(AF_INET, buf+5, id, sizeof(id)),
		buf[9], len);

  conn->their_asn = asn;
  if(conn->holdtime < holdtime)
    {
      conn->holdtime = holdtime;
    }

  return 0;
}

static int bgp_read_update(bgp_conn_t *conn,
			   const uint8_t *buf, const uint16_t len)
{
  bgp_prefix_ipv4_t  prefix;
  uint16_t           off;
  uint16_t           junk16;
  int                i;
  int                w_len, pa_len, nlri_len;
  uint8_t            attr_flags, attr_type;
  uint16_t           attr_len[8];
  uint8_t           *attr_val[8];

  if(len < 4)
    {
      scamper_debug(__func__, "len %d < 4", len);
      return -1;
    }

  /* figure out the length of the withdrawn routes section */
  memcpy(&junk16, buf, 2);
  if((w_len = ntohs(junk16)) + 2 > (int)len)
    {
      return -1;
    }

  /* figure out the length of the path attributes section */
  memcpy(&junk16, buf+w_len, 2);
  if(w_len + 4 + (pa_len = ntohs(junk16)) > (int)len)
    {
      return -1;
    }

  /*
   * figure out the length of the network layer reachability information
   * section.
   */
  nlri_len = (int)len - 4 - w_len - pa_len;

  /* parse the withdrawn routes */
  i=0; off=2;
  while(i < w_len)
    {
      i += prefix_ipv4_parse(buf+off+i, &prefix);
    }

  /* parse the path attributes */
  memset(attr_val, 0, sizeof(attr_val));
  memset(attr_len, 0, sizeof(attr_len));
  off += w_len + 2;
  while(i < pa_len)
    {
      attr_flags = buf[off+i];
      attr_type  = buf[off+i+1];

      /*
       * if the extended length bit is unset, then the attribute length
       * field is specified in one byte, otherwise it is specified in two.
       */
      if((attr_flags & 0x10) == 0)
	{
	  attr_len[0] = buf[off+i+2];
	  i += 3;
	}
      else
	{
	  memcpy(&junk16, buf+off+i+2, 2);
	  attr_len[0] = ntohs(junk16);
	  i += 4;
	}

      if(attr_type == 0 || attr_type > 8)
	{
	  attr_val[attr_type-1] = (uint8_t *)buf+off+i;
	  attr_len[attr_type-1] = attr_len[0];
	}

      i += attr_len[0];
    }

  /* parse the network-layer reachability information */
  off += pa_len + 2;
  while(i < nlri_len)
    {
      i += prefix_ipv4_parse(buf+off+i, &prefix);
    }

  return 0;
}

/*
 * bgp_read_notification_1
 *
 * handle the notification message for error type 1:
 *  "Message Header Error"
 *
 * RFC 1654 section 6.1
 */
static int bgp_read_notification_1(bgp_conn_t *conn, uint8_t subcode,
				   const uint8_t *buf, const uint16_t len)
{
  return 0;
}

/*
 * bgp_read_notification_2
 *
 * handle the notification message for error type 2:
 *  "OPEN Message Error"
 *
 * RFC 1654 section 6.2
 */
static int bgp_read_notification_2(bgp_conn_t *conn, uint8_t subcode,
				   const uint8_t *buf, const uint16_t len)
{
  return 0;
}

/*
 * bgp_read_notification_3
 *
 * handle the notification message for error type 3:
 *  "UPDATE Message Error"
 *
 * RFC 1654 section 6.3
 */
static int bgp_read_notification_3(bgp_conn_t *conn, uint8_t subcode,
				   const uint8_t *buf, const uint16_t len)
{
  return 0;
}

/*
 * bgp_read_notification_4
 *
 * handle the notification message for error type 4:
 *  "Hold Timer Expired"
 *
 * RFC 1654 section 6.5
 */
static int bgp_read_notification_4(bgp_conn_t *conn, uint8_t subcode,
				   const uint8_t *buf, const uint16_t len)
{
  return 0;
}

/*
 * bgp_read_notification_5
 *
 * handle the notification message for error type 5:
 *  "Finite State Machine Error"
 *
 * RFC 1654 section 6.6
 */
static int bgp_read_notification_5(bgp_conn_t *conn, uint8_t subcode,
				   const uint8_t *buf, const uint16_t len)
{
  return 0;
}

/*
 * bgp_read_notification_6
 *
 * handle the notification message for error type 6:
 *  "Cease"
 *
 * RFC 1654 section 6.7
 */
static int bgp_read_notification_6(bgp_conn_t *conn, uint8_t subcode,
				   const uint8_t *buf, const uint16_t len)
{
  return 0;
}

static int bgp_read_notification(bgp_conn_t *conn,
				 const uint8_t *buf, const uint16_t len)
{
  static int (*const func[])(bgp_conn_t *conn, uint8_t subcode,
			     const uint8_t *buf, const uint16_t len) = {
    bgp_read_notification_1,
    bgp_read_notification_2,
    bgp_read_notification_3,
    bgp_read_notification_4,
    bgp_read_notification_5,
    bgp_read_notification_6,
  };

  if(len < 2)
    {
      return -1;
    }

  if(buf[0] == 0 || buf[0] > 6)
    {
      return -1;
    }

  return func[buf[0]-1](conn, buf[1], buf+2, len-2);
}

static int bgp_read_keepalive(bgp_conn_t *conn,
			      const uint8_t *buf, const uint16_t len)
{
  return 0;
}

/*
 * bgp_read_cb
 *
 * select() is telling us that there is a read event of some kind on the
 * socket.
 */
static void bgp_read_cb(const int fd, void *param)
{
  static int (*const func[])(bgp_conn_t *conn,
			     const uint8_t *buf, const uint16_t len) = {
    bgp_read_open,
    bgp_read_update,
    bgp_read_notification,
    bgp_read_keepalive
  };

  bgp_conn_t *conn = (bgp_conn_t *)param;
  socklen_t   socklen;
  ssize_t     off, ssize;
  uint16_t    junk16;
  uint8_t     junk8;
  uint8_t     buf[4096];
  uint8_t    *tmp = NULL;
  int         error;

  /*
   * if we get a read notification during the connect state, it is because
   * the socket could not connect.  get the error and drop the connection.
   */
  if(conn->state == BGP_STATE_CONNECT)
    {
      socklen = sizeof(error);
      if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &socklen) == -1)
	{
	  printerror(errno, strerror, __func__, "could not getsockopt");
	}
      else
	{
	  printerror(error, strerror, __func__, "could not connect");
	}

      bgp_conn_free(conn);
      return;
    }

  /* call read and get whatever is able to be read */
  if((ssize = read(fd, buf, sizeof(buf))) < 1)
    {
      if(ssize < 0)
	{
	  printerror(errno, strerror, __func__, "read");
	}
      else
	{
	  scamper_debug(__func__, "peer disconnected");
	}
      bgp_conn_free(conn);
      return;
    }

  /*
   * if there is some portion of a message stored over from a previous
   * read, then merge the two buffers together.
   */
  if(conn->rbuflen > 0)
    {
      if((tmp = malloc(conn->rbuflen + ssize)) == NULL)
	{
	  goto err;
	}

      memcpy(tmp, conn->rbuf, conn->rbuflen);
      memcpy(tmp+conn->rbuflen, buf, ssize);
      ssize += conn->rbuflen;

      /* don't need the contents of the read buf any more */
      free(conn->rbuf); conn->rbuf = NULL;
      conn->rbuflen = 0;
    }
  else
    {
      tmp = buf;
    }

  /* read all the messages we can out */
  off = 0;
  while(ssize >= 16+2+1)
    {
      /* figure out if we have all of the message yet */
      memcpy(&junk16, tmp+off+16, 2);
      if((junk16 = ntohs(junk16)) > ssize)
	{
	  /*
	   * haven't got it all, so save the rest with the connection
	   * state and use it later
	   */
	  break;
	}

      if((junk8 = tmp[off+off+18] - 1) < 4 && func[junk8] != NULL)
	{
	  func[junk8](conn, tmp+off+19, junk16-19);
	}

      ssize -= junk16;
      off += junk16;
    }

  /*
   * if we couldn't deal with this portion of the message yet, then
   * save it for processing later
   */
  if(ssize >= 0)
    {
      if((conn->rbuf = malloc(ssize)) == NULL)
	{
	  goto err;
	}

      memcpy(conn->rbuf, tmp+off, ssize);
      conn->rbuflen = ssize;
    }

  if(tmp != buf) free(tmp);
  return;

 err:
  if(tmp != buf) free(tmp);
  bgp_conn_free(conn);
  return;
}

/*
 * bgp_write_cb
 *
 * select() is telling us that there is a write event of some kind on the
 * socket.
 */
static void bgp_write_cb(const int fd, void *param)
{
  bgp_conn_t *conn = (bgp_conn_t *)param;
  socklen_t socklen;
  int error;

  /*
   * if we get a write notification during the connect state, then check
   * to see if the connection succeeded (by no socket error).
   */
  if(conn->state == BGP_STATE_CONNECT)
    {
      socklen = sizeof(error);
      if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &socklen) == -1)
	{
	  printerror(errno, strerror, __func__, "could not getsockopt");
	  bgp_conn_free(conn);
	}
      else if(error == 0)
	{
	  /*
	   * if there is no error on the socket, then the connect succeeded.
	   * advance to the next state.
	   */
	  conn->state = BGP_STATE_OPEN_WAIT;
	}
      else
	{
	  printerror(error, strerror, __func__, "could not connect");
	  bgp_conn_free(conn);
	}
    }
  else
    {
      scamper_debug(__func__, "unhandled write event in state %d",
		    conn->state);
    }

  return;
}

/*
 * scamper_bgp_connect
 *
 * 
 */
int scamper_bgp_connect(const struct sockaddr *sa, const int asn)
{
  bgp_conn_t *conn;
  int         fd;

  if((conn = bgp_conn_alloc(sa, asn)) == NULL)
    {
      goto err;
    }

  if((fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open socket");
      goto err;
    }

  if(fcntl_set(fd, O_NONBLOCK) == -1)
    {
      printerror(errno, strerror, __func__, "could not set nonblock");
      goto err;
    }

  if(connect(fd, sa, sockaddr_len(sa)) == -1 && errno != EINPROGRESS)
    {
      printerror(errno, strerror, __func__, "could not connect");
      goto err;
    }

  if((conn->rfd = scamper_fds_read_add(fd, bgp_read_cb, conn)) == NULL)
    {
      goto err;
    }

  if((conn->wfd = scamper_fds_write_add(fd, bgp_write_cb, conn)) == NULL)
    {
      goto err;
    }

  return fd;

 err:
  if(conn != NULL)
    {
      if(conn->rfd == NULL && conn->wfd == NULL) close(fd);
      bgp_conn_free(conn);
    }
  return -1;
}

/*
 * scamper_bgp_init
 *
 * setup scamper's BGP related data structures.
 */
int scamper_bgp_init()
{
  int i;

  bits2netmask[0] = 0;
  for(i=1;i<=32; i++)
    {
      bits2netmask[i] = htonl(0xffffffff-((1<<(32-i))-1));
    }

  return 0;
}
