/*
 * scamper_sting.h
 *
 * $Id: scamper_sting.h
 *
 * Copyright (C) 2008 The University of Waikato
 * Author: Matthew Luckie
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
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

#ifndef __SCAMPER_STING_H
#define __SCAMPER_STING_H

#define SCAMPER_STING_DISTRIBUTION_EXPONENTIAL 1
#define SCAMPER_STING_DISTRIBUTION_PERIODIC    2
#define SCAMPER_STING_DISTRIBUTION_UNIFORM     3

/*
 * scamper_sting_probe
 *
 * state kept with each probe
 */
typedef struct scamper_sting_probe
{
  struct timeval tx;
  uint8_t        flags;
} scamper_sting_probe_t;

#define SCAMPER_STING_PROBE_FLAG_HOLE 0x01

/*
 * scamper_sting
 *
 * results of a measurement conducted with sting
 */
typedef struct scamper_sting
{
  /*
   * management
   */
  scamper_list_t        *list;     /* list corresponding to task */
  scamper_cycle_t       *cycle;    /* cycle corresponding to task */

  /*
   * parameters used in probing
   */
  scamper_addr_t        *src;      /* source address */
  scamper_addr_t        *dst;      /* destination address */
  uint16_t               sport;    /* source port */
  uint16_t               dport;    /* destination port */
  uint16_t               count;    /* number of probes to send */
  uint16_t               mean;     /* mean inter-packet delay, microseconds */
  uint16_t               inter;    /* inter-phase delay */
  uint8_t                dist;     /* inter-packet delay distribution to tx */
  uint8_t                synretx;  /* number of times to retransmit syn  */
  uint8_t                dataretx; /* number of times to retransmit data */
  uint8_t                seqskip;  /* size of initial hole */
  uint8_t               *data;     /* data to use; len = seqskip + count */

  /*
   * data collected
   */
  struct timeval         start;    /* time measurement commenced */
  scamper_sting_probe_t *probes;   /* array of probes sent */
  uint16_t               probec;   /* number of probes sent */
  struct timeval         hsrtt;    /* rtt of syn -> syn/ack */
  uint16_t               dataackc; /* number of acks rx'd in data-seeding */
  uint16_t               holec;    /* number of holes filled (fwd loss) */

} scamper_sting_t;

scamper_sting_t *scamper_sting_alloc(void);
void             scamper_sting_free(scamper_sting_t *);
scamper_addr_t  *scamper_sting_addr(const void *);
int              scamper_sting_data(scamper_sting_t *, const uint8_t *);
int              scamper_sting_probes(scamper_sting_t *, uint16_t);

#endif
