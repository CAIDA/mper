/*
 * scamper_privsep.c: code that does root-required tasks
 *
 * $Id: scamper_privsep.c,v 1.53 2009/03/10 00:35:31 mjl Exp $
 *
 * Copyright (C) 2004-2009 The University of Waikato
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

#ifndef WITHOUT_PRIVSEP

#include "internal.h"

#include "scamper_privsep.h"
#include "scamper_debug.h"
#include "utils.h"

#include "scamper_dl.h"
#include "scamper_rtsock.h"

typedef struct privsep_msg
{
  uint16_t plen;
  uint16_t type;
} privsep_msg_t;

struct privsep_handler
{
  uint8_t type;
  int (*handler)(const uint16_t len, const uint8_t *param);
};

static pid_t root_pid = -1; /* the process id of the root code */
static int   root_fd  = -1; /* the fd the root code send/recv on */
static int   lame_fd  = -1; /* the fd that the lame code uses */

/*
 * the privilege separation code works by allowing the lame process to send
 * request messages to the root process.  these define the messages that
 * the root process understands.
 */
#define SCAMPER_PRIVSEP_EXIT          0x00U
#define SCAMPER_PRIVSEP_OPEN_DATALINK 0x01U
#define SCAMPER_PRIVSEP_OPEN_FILE     0x02U
#define SCAMPER_PRIVSEP_OPEN_RTSOCK   0x03U
#define SCAMPER_PRIVSEP_OPEN_ICMP     0x04U
#define SCAMPER_PRIVSEP_OPEN_DIVERT   0x05U
#define SCAMPER_PRIVSEP_OPEN_SOCK     0x06U
#define SCAMPER_PRIVSEP_OPEN_RAWUDP   0x07U

/*
 * the privilege separation code permits both the privileged opening of file
 * descriptors and the execution of privileged operations.  the first half
 * of the operations are for opening file descriptors; the second half are
 * for doing a task.  At the moment, there are no tasks defined so the next
 * two #defines resolve to the same value.
 */
#define SCAMPER_PRIVSEP_MAXTYPE (SCAMPER_PRIVSEP_OPEN_RAWUDP)

/*
 * privsep_open_rawsock
 *
 * open a raw icmp socket.  one integer parameter corresponding to the 'type'
 * is supplied in param.
 *
 */
static int privsep_open_icmp(const uint16_t plen, const uint8_t *param)
{
  int type, protocol;

  if(plen != sizeof(type))
    {
      scamper_debug(__func__, "plen %d != %d", plen, sizeof(type));
      return -1;
    }

  memcpy(&type, param, sizeof(type));

  if(type == AF_INET)
    {
      protocol = IPPROTO_ICMP;
    }
  else if(type == AF_INET6)
    {
      protocol = IPPROTO_ICMPV6;
    }
  else
    {
      scamper_debug(__func__, "type %d != AF_INET || AF_INET6", type);
      errno = EINVAL;
      return -1;
    }

  return socket(type, SOCK_RAW, protocol);
}

/*
 * privsep_open_rtsock
 *
 * open a routing socket.  there are no parameters permitted to this
 * method call.
 */
static int privsep_open_rtsock(const uint16_t plen, const uint8_t *param)
{
  if(plen != 0)
    {
      scamper_debug(__func__, "plen %d != 0", plen, 0);
      errno = EINVAL;
      return -1;
    }

  return scamper_rtsock_open_fd();
}

/*
 * privsep_open_datalink
 *
 * open a BPF or PF_PACKET socket to the datalink.  the param has a single
 * field: the ifindex of the device to monitor.
 */
static int privsep_open_datalink(const uint16_t plen, const uint8_t *param)
{
  int ifindex;

  /* the payload should have an integer field - no more, no less. */
  if(plen != sizeof(ifindex))
    {
      scamper_debug(__func__, "plen %d != %d", plen, sizeof(ifindex));
      errno = EINVAL;
      return -1;
    }

  memcpy(&ifindex, param, sizeof(ifindex));

  return scamper_dl_open_fd(ifindex);
}

/*
 * privsep_open_divert
 *
 * open a divert socket.  bind it to the port supplied.
 */
static int privsep_open_divert(const uint16_t plen, const uint8_t *param)
{
  int fd = -1;

#if defined(IPPROTO_DIVERT)
  struct sockaddr_in sin;
  int port;

  if(plen != sizeof(port))
    {
      scamper_debug(__func__, "plen %d != %d", plen, sizeof(port));
      errno = EINVAL;
      return -1;
    }

  memcpy(&port, param, sizeof(port));

  if((fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open socket");
      return -1;
    }

  memset(&sin, 0, sizeof(sin));
  sin.sin_len = sizeof(sin);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(port);
  if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
    {
      printerror(errno, strerror, __func__, "could not bind socket");
      return -1;
    }
#else
  scamper_debug(__func__, "divert sockets not supported");
  errno = EINVAL;
#endif

  return fd;
}

static int privsep_open_sock(const uint16_t plen, const uint8_t *param)
{
  struct sockaddr_in sin4;
  struct sockaddr_in6 sin6;
  int domain, type, protocol, port;
  const size_t size = sizeof(domain) + sizeof(protocol) + sizeof(port);
  size_t off = 0;
  int fd = -1;

  if(plen != size)
    {
      scamper_debug(__func__, "plen %d != %d", plen, size);
      errno = EINVAL;
      goto err;
    }
  off = 0;
  memcpy(&domain,   param+off, sizeof(domain));   off += sizeof(domain);
  memcpy(&protocol, param+off, sizeof(protocol)); off += sizeof(protocol);
  memcpy(&port,     param+off, sizeof(port));

  if(port < 1 || port > 65535)
    {
      scamper_debug(__func__, "refusing to bind to port %d", port);
      errno = EINVAL;
      goto err;
    }

  if(protocol == IPPROTO_TCP)      type = SOCK_STREAM;
  else if(protocol == IPPROTO_UDP) type = SOCK_DGRAM;
  else
    {
      scamper_debug(__func__, "unhandled IPv4 protocol %d", protocol);
      errno = EINVAL;
      goto err;
    }

  if(domain == AF_INET)
    {
      if((fd = socket(AF_INET, type, protocol)) == -1)
	{
	  printerror(errno, strerror, __func__, "could not open IPv4 socket");
	  goto err;
	}
      sockaddr_compose((struct sockaddr *)&sin4, AF_INET, NULL, port);
      if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
	{
	  printerror(errno, strerror, __func__,
		     "could not bind to IPv4 protocol %d port %d",
		     protocol, port);
	  goto err;
	}
    }
  else if(domain == AF_INET6)
    {
      if((fd = socket(AF_INET6, type, protocol)) == -1)
	{
	  printerror(errno, strerror, __func__, "could not open IPv6 socket");
	  goto err;
	}
      sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, NULL, port);
      if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1)
	{
	  printerror(errno, strerror, __func__,
		     "could not bind to IPv6 protocol %d port %d",
		     protocol, port);
	  goto err;
	}
    }
  else return -1;

  return fd;

 err:
  if(fd != -1) close(fd);
  return -1;
}

static int privsep_open_rawudp(const uint16_t plen, const uint8_t *param)
{
  struct in_addr in;
  struct sockaddr_in sin4;
  int port, fd;
  char tmp[32];

  if(plen != 4 + sizeof(port))
    {
      scamper_debug(__func__, "plen %d != %d", plen, 4 + sizeof(port));
      errno = EINVAL;
      return -1;
    }

  memcpy(&in,   param+0, sizeof(in));
  memcpy(&port, param+4, sizeof(port));
  if(port < 1 || port > 65535)
    {
      scamper_debug(__func__, "refusing to bind to port %d", port);
      errno = EINVAL;
      return -1;
    }

  if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open socket");
      return -1;
    }

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, &in, port);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      printerror(errno, strerror, __func__, "could not bind %s:%d",
		 inet_ntop(AF_INET, &in, tmp, sizeof(tmp)), port);
      close(fd);
      return -1;
    }

  return fd;
}

/*
 * privsep_open_file
 *
 * switch to the user running the process and open the file specified.
 * the param has two fields in it: the mode of open, and the file to open.
 */
static int privsep_open_file(const uint16_t plen, const uint8_t *param)
{
  const char *file;
  uid_t       uid, euid;
  int         flags;
  mode_t      mode;
  uint16_t    off;
  int         fd;

  /*
   * if the payload of param is not large enough to hold the flags and a
   * filename, then don't go any further
   */
  if(plen < sizeof(int) + 2)
    {
      return -1;
    }

  memcpy(&flags, param, sizeof(int));
  off = sizeof(int);

  /* if the O_CREAT flag is set, we need to fetch the mode parameter too */
  if(flags & O_CREAT)
    {
      /*
       * the payload length of the parameter must be large enough to hold
       * the flags, mode, and a filename
       */
      if(plen < off + sizeof(mode_t) + 2)
	{
	  return -1;
	}

      memcpy(&mode, param+off, sizeof(mode));

      off += sizeof(mode_t);
    }

  file = (const char *)(param + off);

  /*
   * make sure the length of the file to open checks out.
   * the last byte of the string must be a null character.
   */
  if(file[plen-off-1] != '\0')
    {
      scamper_debug(__func__, "filename not terminated with a null");
      return -1;
    }

  uid  = getuid();
  euid = geteuid();

  /* set our effective uid to be the user who started scamper */
  if(seteuid(uid) == -1)
    {
      return -1;
    }

  if(flags & O_CREAT)
    {
      fd = open(file, flags, mode);
    }
  else
    {
      fd = open(file, flags);
    }

  /*
   * ask for our root permissions back.  if we can't get them back, then
   * this process is crippled and it might as well exit now.
   */
  if(seteuid(euid) == -1)
    {
      if(fd != -1) close(fd);
      exit(-errno);
    }

  return fd;
}

/*
 * privsep_send_fd
 *
 * send the fd created using the priviledged code.  if the fd was not
 * successfully created, we send the errno back in the payload of the
 * message.
 */
static int privsep_send_fd(const int fd,const int error,const uint8_t msg_type)
{
  uint8_t         buf[sizeof(int)];
  struct msghdr   msg;
  struct iovec    vec;

#if !defined(HAVE_ACCRIGHTS)
  struct cmsghdr *cmsg;
  uint8_t         tmp[CMSG_LEN(sizeof(int))];
#endif

  scamper_debug(__func__, "fd: %d error: %d msg_type: 0x%02x",
		fd, error, msg_type);

  memset(&vec, 0, sizeof(vec));
  memset(&msg, 0, sizeof(msg));

  memcpy(buf, &error, sizeof(int));
  vec.iov_base = buf;
  vec.iov_len  = sizeof(buf);

  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;

  if(fd != -1)
    {
#if defined(HAVE_ACCRIGHTS)
      msg.msg_accrights = (caddr_t)&fd;
      msg.msg_accrightslen = sizeof(fd);
#else
      msg.msg_control = (caddr_t)tmp;
      msg.msg_controllen = CMSG_LEN(sizeof(int));

      cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_len = CMSG_LEN(sizeof(int));
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      *(int *)CMSG_DATA(cmsg) = fd;
#endif
    }

  if(sendmsg(root_fd, &msg, 0) == -1)
    {
      return -1;
    }

  return 0;
}

static int privsep_recv_fd(void)
{
  struct msghdr   msg;
  struct iovec    vec;
  ssize_t         rc;
  int             fd = -1, error;

#if !defined(HAVE_ACCRIGHTS)
  struct cmsghdr *cmsg;
  uint8_t         tmp[CMSG_LEN(sizeof(int))];
#endif

  memset(&vec, 0, sizeof(vec));
  memset(&msg, 0, sizeof(msg));

  vec.iov_base = (char *)&error;
  vec.iov_len  = sizeof(error);

  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;

#if defined(HAVE_ACCRIGHTS)
  msg.msg_accrights = (caddr_t)&fd;
  msg.msg_accrightslen = sizeof(fd);
#else
  msg.msg_control = tmp;
  msg.msg_controllen = sizeof(tmp);
#endif

  if((rc = recvmsg(lame_fd, &msg, 0)) == -1)
    {
      printerror(errno, strerror, __func__, "recvmsg failed");
      return -1;
    }
  else if(rc != sizeof(error))
    {
      return -1;
    }

  if(error == 0)
    {
#if defined(HAVE_ACCRIGHTS)
      if(msg.msg_accrightslen != sizeof(fd))
	{
	  fd = -1;
	}
#else
      cmsg = CMSG_FIRSTHDR(&msg);
      if(cmsg != NULL && cmsg->cmsg_type == SCM_RIGHTS)
	{
	  fd = (*(int *)CMSG_DATA(cmsg));
	}
#endif
    }
  else
    {
      errno = error;
    }

  return fd;
}

/*
 * privsep_do
 *
 * this is the only piece of code with root priviledges.  we use it to
 * create raw sockets, routing/netlink sockets, BPF/PF_PACKET sockets, and
 * ordinary files that scamper itself cannot do by itself.
 */
static int privsep_do(void)
{
  static int (* const func[])(const uint16_t plen, const uint8_t *param) = {
    NULL,                          /* SCAMPER_PRIVSEP_EXIT */
    privsep_open_datalink,         /* SCAMPER_PRIVSEP_OPEN_DATALINK */
    privsep_open_file,             /* SCAMPER_PRIVSEP_OPEN_FILE */
    privsep_open_rtsock,           /* SCAMPER_PRIVSEP_OPEN_RTSOCK */
    privsep_open_icmp,             /* SCAMPER_PRIVSEP_OPEN_ICMP */
    privsep_open_divert,           /* SCAMPER_PRIVSEP_OPEN_DIVERT */
    privsep_open_sock,             /* SCAMPER_PRIVSEP_OPEN_SOCK */
    privsep_open_rawudp,           /* SCAMPER_PRIVSEP_OPEN_RAWUDP */
  };

  privsep_msg_t   msg;
  void           *data = NULL;
  int             ret = 0, error;
  int             fd;

#if defined(HAVE_SETPROCTITLE)
  setproctitle("%s", "[priv]");
#endif

  /* might as well set our copy of the root_pid to something useful */
  root_pid = getpid();

  /*
   * the priviledged process does not need the lame file descriptor for
   * anything, so get rid of it
   */
  close(lame_fd);
  lame_fd = -1;

  for(;;)
    {
      /* read the msg header */
      if((ret = read_wrap(root_fd, (uint8_t *)&msg, NULL, sizeof(msg))) != 0)
	{
	  if(ret == -1)
	    {
	      printerror(errno, strerror, __func__, "could not read msg hdr");
	    }
	  break;
	}

      /* if we've been told to exit, then do so now */
      if(msg.type == SCAMPER_PRIVSEP_EXIT)
	{
	  break;
	}

      if(msg.type > SCAMPER_PRIVSEP_MAXTYPE)
	{
	  scamper_debug(__func__, "msg %d > maxtype", msg.type);
	  ret = -EINVAL;
	  break;
	}

      /* if there is more data to read, read it now */
      if(msg.plen != 0)
	{
	  if((data = malloc(msg.plen)) == NULL)
	    {
	      printerror(errno, strerror, __func__, "couldnt malloc data");
	      ret = (-errno);
	      break;
	    }

	  if((ret = read_wrap(root_fd, data, NULL, msg.plen)) != 0)
	    {
	      printerror(errno, strerror, __func__, "couldnt read data");
	      free(data);
	      break;
	    }
	}
      else data = NULL;

      if((fd = func[msg.type](msg.plen, data)) == -1)
	{
	  error = errno;
	}
      else
	{
	  error = 0;
	}

      /* we don't need the data we read anymore */
      if(data != NULL)
	{
	  free(data);
	}

      /* send the file descriptor back to the lame process */
      if(privsep_send_fd(fd, error, msg.type) == -1)
	{
	  printerror(errno, strerror, __func__, "couldnt send fd");
	  break;
	}

      /*
       * if we have a file descriptor that has been passed to the parent
       * process, we don't need our copy any longer
       */
      if(fd != -1)
	{
	  close(fd);
	}
    }

  close(root_fd);
  return ret;
}

/*
 * privsep_lame_send
 *
 * compose and send the messages necessary to communicate with the root
 * process.
 */
static int privsep_lame_send(const uint16_t type, const uint16_t len,
			     const uint8_t *param)
{
  privsep_msg_t msg;

  assert(type != SCAMPER_PRIVSEP_EXIT);
  assert(type <= SCAMPER_PRIVSEP_MAXTYPE);

  /* send the header first */
  msg.type = type;
  msg.plen = len;
  if(write_wrap(lame_fd, &msg, NULL, sizeof(msg)) == -1)
    {
      printerror(errno, strerror, __func__, "could not send msg header");
      return -1;
    }

  /* if there is a parameter data to send, send it now */
  if(len != 0 && write_wrap(lame_fd, param, NULL, len) == -1)
    {
      printerror(errno, strerror, __func__, "could not send msg param");
      return -1;
    }

  return 0;
}

/*
 * privsep_getfd
 *
 * send a request to the piece of code running as root to do open a file
 * descriptor that requires priviledge to do.  return the file descriptor.
 */
static int privsep_getfd(const uint16_t type, const uint16_t len,
			 const uint8_t *param)
{
  if(privsep_lame_send(type, len, param) == -1)
    {
      return -1;
    }

  return privsep_recv_fd();
}

static int privsep_getfd_1int(const uint16_t type, const int p1)
{
  uint8_t param[sizeof(p1)];
  memcpy(param, &p1, sizeof(p1));
  return privsep_getfd(type, sizeof(param), param);
}

static int privsep_getfd_3int(const uint16_t type,
			      const int p1, const int p2, const int p3)
{
  uint8_t param[sizeof(p1)+sizeof(p2)+sizeof(p3)];
  size_t off = 0;
  memcpy(param+off, &p1, sizeof(p1)); off += sizeof(p1);
  memcpy(param+off, &p2, sizeof(p2)); off += sizeof(p2);
  memcpy(param+off, &p3, sizeof(p3)); off += sizeof(p3);
  assert(off == sizeof(param));
  return privsep_getfd(type, sizeof(param), param);
}

int scamper_privsep_open_datalink(const int ifindex)
{
  return privsep_getfd_1int(SCAMPER_PRIVSEP_OPEN_DATALINK, ifindex);
}

int scamper_privsep_open_file(const char *file,
			      const int flags, const mode_t mode)
{
  uint8_t *param;
  int off, len, fd;

  /*
   * decide how big the message is going to be.  don't pass it if the message
   * length parameter constrains us
   */
  len = sizeof(flags) + strlen(file) + 1;
  if(flags & O_CREAT)
    {
      len += sizeof(mode);
    }

  /*
   * the len is fixed because the length parameter used in the privsep
   * header is a 16-bit unsigned integer.
   */
  if(len > 65535)
    {
      return -1;
    }

  /* allocate the parameter */
  if((param = malloc(len)) == NULL)
    {
      return -1;
    }

  /* copy in the flags parameter, and the mode parameter if necessary */
  memcpy(param, &flags, sizeof(flags)); off = sizeof(flags);
  if(flags & O_CREAT)
    {
      memcpy(param+off, &mode, sizeof(mode));
      off += sizeof(mode);
    }

  /* finally copy in the name of the file to open */
  memcpy(param+off, file, len-off);

  /* get the file descriptor and return it */
  fd = privsep_getfd(SCAMPER_PRIVSEP_OPEN_FILE, len, param);
  free(param);
  return fd;
}

int scamper_privsep_open_rtsock(void)
{
  return privsep_getfd(SCAMPER_PRIVSEP_OPEN_RTSOCK, 0, NULL);
}

int scamper_privsep_open_icmp(const int domain)
{
  return privsep_getfd_1int(SCAMPER_PRIVSEP_OPEN_ICMP, domain);
}

int scamper_privsep_open_divert(const int port)
{
  return privsep_getfd_1int(SCAMPER_PRIVSEP_OPEN_DIVERT, port);
}

int scamper_privsep_open_tcp(const int domain, const int port)
{
  return privsep_getfd_3int(SCAMPER_PRIVSEP_OPEN_SOCK,domain,IPPROTO_TCP,port);
}

int scamper_privsep_open_udp(const int domain, const int port)
{
  return privsep_getfd_3int(SCAMPER_PRIVSEP_OPEN_SOCK,domain,IPPROTO_UDP,port);
}

int scamper_privsep_open_rawudp(const void *addr, const int port)
{
  uint8_t param[4+sizeof(port)];
  size_t off = 0;

  if(addr == NULL)
    memset(param+off, 0, 4);
  else
    memcpy(param+off, addr, 4);
  off += 4;

  memcpy(param+off, &port, sizeof(port)); off += sizeof(port);
  assert(off == sizeof(param));

  return privsep_getfd(SCAMPER_PRIVSEP_OPEN_RAWUDP, sizeof(param), param);
}

/*
 * scamper_privsep
 *
 * start a child process that has the root priviledges that scamper starts
 * with.  then, revoke scamper's priviledges to the minimum scamper can
 * obtain
 */
int scamper_privsep_init()
{
  struct addrinfo hints, *res0;
  struct timeval tv;
  struct passwd *pw;
  struct stat sb;
  mode_t mode;
  uid_t  uid;
  gid_t  gid;
  int    sockets[2];
  pid_t  pid;
  int    ret;
  time_t t;

  /* check to see if the PRIVSEP_DIR exists */
  if(stat(PRIVSEP_DIR, &sb) == -1)
    {
      /* if the directory does not exist, try and create it now */
      if(errno == ENOENT)
	{
	  /*
	   * get the uid of the user who will get ownership of the directory.
	   * by default, this will be root.
	   */
	  if((pw = getpwnam(PRIVSEP_DIR_USER)) == NULL)
	    {
	      printerror(errno, strerror, __func__,
			 "could not getpwnam " PRIVSEP_DIR_USER);
	      endpwent();
	      return -1;
	    }
	  uid = pw->pw_uid;
	  endpwent();

	  gid = 0; 

	  /* create the directory as 555 : no one can write to it */
	  mode = S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	  if(mkdir(PRIVSEP_DIR, mode) == -1)
	    {
	      printerror(errno, strerror, __func__,
			 "could not mkdir " PRIVSEP_DIR);
	      return -1;
	    }

	  /* assign ownership appropriately */
	  if(chown(PRIVSEP_DIR, uid, gid) == -1)
	    {
	      printerror(errno, strerror, __func__,
			 "could not chown " PRIVSEP_DIR);
	      rmdir(PRIVSEP_DIR);
	      return -1;
	    }
	}
      else
	{
	  printerror(errno, strerror, __func__, "could not stat " PRIVSEP_DIR);
	  return -1;
	}
    }

  /*
   * open up the unix domain sockets that will allow the prober to talk
   * with the priviledged process
   */
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1)
    {
      printerror(errno, strerror, __func__, "could not socketpair");
      return -1;
    }

  lame_fd = sockets[0];
  root_fd = sockets[1];

  if((pid = fork()) == -1)
    {
      printerror(errno, strerror, __func__, "could not fork");
      return -1;
    }
  else if(pid == 0) /* child */
    {
      /*
       * this is the process that will do the root tasks.
       * when this function exits, we call exit() on the forked process.
       */
      ret = privsep_do();
      exit(ret);
    }

  /* set our copy of the root_pid to the relevant process id */
  root_pid = pid;

  /*
   * we don't need our copy of the file descriptor passed to the priviledged
   * process any longer
   */
  close(root_fd);
  root_fd = -1;

  /*
   * get the details for the PRIVSEP_USER login, which the rest of scamper
   * will use to get things done
   */
  if((pw = getpwnam(PRIVSEP_USER)) == NULL)
    {
      printerror(errno, strerror, __func__,
		 "could not getpwnam " PRIVSEP_USER);
      return -1;
    }
  uid = pw->pw_uid;
  gid = pw->pw_gid;
  memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));
  endpwent();

  /*
   * call localtime now, as then the unpriviledged process will have the
   * local time zone information cached in the process, so localtime will
   * actually mean something
   */
  gettimeofday_wrap(&tv);
  t = tv.tv_sec;
  localtime(&t);

  /*
   * call getaddrinfo now, as then the unpriviledged process will load
   * whatever files it needs to to help resolve IP addresses; the need for
   * this was first noticed in SunOS
   */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = AF_INET;
  getaddrinfo("127.0.0.1", NULL, &hints, &res0);
  freeaddrinfo(res0);

  /* change the root directory of the unpriviledged directory */
#ifndef NDEBUG
  if(chroot(PRIVSEP_DIR) == -1)
    {
      printerror(errno, strerror, __func__,
		 "could not chroot to " PRIVSEP_DIR);
      return -1;
    }

  /* go into the chroot environment */
  if(chdir("/") == -1)
    {
      printerror(errno, strerror, __func__, "could not chdir /");
      return -1;
    }
#endif

  /* change the operating group */
  if(setgroups(1, &gid) == -1)
    {
      printerror(errno, strerror, __func__, "could not setgroups");
      return -1;
    }
  if(setgid(gid) == -1)
    {
      printerror(errno, strerror, __func__, "could not setgid");
      return -1;
    }

  /* change the operating user */
  if(setuid(uid) == -1)
    {
      printerror(errno, strerror, __func__, "could not setuid");
      return -1;
    }

  return lame_fd;
}

void scamper_privsep_cleanup()
{
  privsep_msg_t msg;

  if(root_pid != -1)
    {
      msg.plen = 0;
      msg.type = SCAMPER_PRIVSEP_EXIT;

      write_wrap(lame_fd, (uint8_t *)&msg, NULL, sizeof(msg));
      root_pid = -1;
    }

  if(lame_fd != -1)
    {
      close(lame_fd);
      lame_fd = -1;
    }

  return;
}

#endif /* ifndef WITHOUT_PRIVSEP */
