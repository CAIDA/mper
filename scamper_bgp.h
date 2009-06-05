/*
 * scamper_bgp.h
 *
 * $Id: scamper_bgp.h,v 1.4 2005/03/30 04:03:55 mjl Exp $
 *
 */

#ifndef __SCAMPER_BGP_H
#define __SCAMPER_BGP_H

int scamper_bgp_init(void);

int scamper_bgp_connect(const struct sockaddr *addr, const int asn);

#endif
