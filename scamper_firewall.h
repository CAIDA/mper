/*
 * scamper_firewall.h
 *
 * $Id: scamper_firewall.h,v 1.3 2008/07/09 04:45:31 mjl Exp $
 *
 * Copyright (C) 2008 The University of Waikato
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

#ifndef __SCAMPER_FIREWALL_H
#define __SCAMPER_FIREWALL_H

#define SCAMPER_FIREWALL_RULE_TYPE_5TUPLE 0x1

typedef struct scamper_firewall_rule
{
  uint16_t type;
  union
  {
    struct fivetuple
    {
      uint8_t         proto;
      scamper_addr_t *src;
      scamper_addr_t *dst;
      uint16_t        sport;
      uint16_t        dport;
    } fivetuple;
  } un;
} scamper_firewall_rule_t;

#define sfw_5tuple_proto un.fivetuple.proto
#define sfw_5tuple_src   un.fivetuple.src
#define sfw_5tuple_dst   un.fivetuple.dst
#define sfw_5tuple_sport un.fivetuple.sport
#define sfw_5tuple_dport un.fivetuple.dport

/* handle returned when a firewall entry is added to the table */
typedef struct scamper_firewall_entry scamper_firewall_entry_t;

/* routines to add/get and remove rules from the firewall table */
scamper_firewall_entry_t *
scamper_firewall_entry_get(scamper_firewall_rule_t *);
void scamper_firewall_entry_free(scamper_firewall_entry_t *);

/* routines to handle initialising structures to manage the firewall */
int scamper_firewall_init(char *opt);
void scamper_firewall_cleanup(void);

#endif /* __SCAMPER_FIREWALL_H */
