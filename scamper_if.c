/*
 * scamper_if.c
 *
 * $Id: scamper_if.c,v 1.4 2009/02/28 05:02:01 mjl Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_if.h"

/*
 * scamper_if_getmtu
 *
 * given an interface index, return the MTU of it.  return zero if
 * we can't get the interface's MTU.
 */
#ifndef _WIN32
int scamper_if_getmtu(const int ifindex, uint16_t *ifmtu)
{
  scamper_fd_t *fd;
  struct ifreq ifr;
  int mtu;

  assert(ifindex >= 0);

  /* given the index, return the interface name to query */
  if(if_indextoname((unsigned int)ifindex, ifr.ifr_name) == NULL)
    {
      printerror(errno, strerror, __func__, "could not if_indextoname");
      return -1;
    }

  if((fd = scamper_fd_ifsock()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not get ifsock");
      return -1;
    }

  if(ioctl(scamper_fd_fd_get(fd), SIOCGIFMTU, &ifr) == -1)
    {
      printerror(errno, strerror, __func__, "could not SIOCGIFMTU");
      return -1;
    }

#if defined(__sun__)
  mtu = ifr.ifr_metric;
#else
  mtu = ifr.ifr_mtu;
#endif

  if(mtu >= 0 && mtu <= 65535)
    {
      *ifmtu = mtu;
      return 0;
    }

  return -1;
}
#endif

#ifdef _WIN32
int scamper_if_getmtu(const int ifindex, uint16_t *ifmtu)
{
  MIB_IFROW row;
  row.dwIndex = ifindex;
  if(GetIfEntry(&row) != NO_ERROR)
    {
      printerror(errno,strerror,__func__, "could not GetIfEntry %d", ifindex);
      return -1;
    }
  *ifmtu = (uint16_t)row.dwMtu;
  return 0;
}
#endif

#if defined(__linux__) || defined(__sun__)
int scamper_if_getmac(const int ifindex, uint8_t *mac)
{
  scamper_fd_t *fd;
  struct ifreq ifr;

  if(if_indextoname(ifindex, ifr.ifr_name) == NULL)
    {
      printerror(errno, strerror, __func__, "could not if_indextoname");
      return -1;
    }

  if((fd = scamper_fd_ifsock()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not get ifsock");
      return -1;
    }

#if defined(__linux__)
  if(ioctl(scamper_fd_fd_get(fd), SIOCGIFHWADDR, &ifr) == -1)
    {
      printerror(errno, strerror, __func__, "could not SIOCGIFHWADDR");
      return -1;
    }
  memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
#elif defined(__sun__)
  if(ioctl(scamper_fd_fd_get(fd), SIOCGENADDR, &ifr) == -1)
    {
      printerror(errno, strerror, __func__, "could not SIOCGENADDR");
      return -1;
    }
  memcpy(mac, ifr.ifr_enaddr, 6);
#endif

  return 0;
}
#elif defined(_WIN32)
int scamper_if_getmac(const int ifindex, uint8_t *mac)
{
  MIB_IFROW row;
  row.dwIndex = ifindex;
  if(GetIfEntry(&row) != NO_ERROR)
    {
      printerror(errno,strerror,__func__, "could not GetIfEntry %d", ifindex);
      return -1;
    }
  memcpy(mac, row.bPhysAddr, 6);
  return 0;
}
#else
int scamper_if_getmac(const int ifindex, uint8_t *mac)
{
  struct sockaddr_dl *sdl;
  int                 mib[6];
  size_t              len;
  uint8_t            *buf;

  mib[0] = CTL_NET;
  mib[1] = AF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_LINK;
  mib[4] = NET_RT_IFLIST;
  mib[5] = ifindex;

  if(sysctl(mib, 6, NULL, &len, NULL, 0) == -1)
    {
      printerror(errno, strerror, __func__, "could not sysctl buflen");
      return -1;
    }

  if((buf = malloc(len)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc buf");
      return -1;
    }

  if(sysctl(mib, 6, buf, &len, NULL, 0) < 0)
    {
      printerror(errno, strerror, __func__, "could not sysctl data");
      free(buf);
      return -1;
    }

  sdl = (struct sockaddr_dl *)(buf+sizeof(struct if_msghdr));
  memcpy(mac, LLADDR(sdl), 6);

  free(buf);
  return 0;
}
#endif
