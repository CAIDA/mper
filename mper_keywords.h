/*
** gperf-generated perfect hashing for keywords used in the control socket
** request/response exchanges.
**
** --------------------------------------------------------------------------
** Author: Young Hyun
** Copyright (C) 2009 The Regents of the University of California.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
** 
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** 
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __MPER_KEYWORDS_H__
#define __MPER_KEYWORDS_H__

#define MPER_MSG_KEYWORD_MAXLEN 25  /* max length of a command or option name */

typedef enum {
  KC_NONE=0,
  KC_ERROR,     /* pseudo code representing a parse error */
  KC_REQNUM,    /* pseudo code representing the numeric request number */

  KC_CMD_MIN,
  KC_PING_CMD,
  KC_CMD_ERROR_CMD,      /* response: error parsing command */
  KC_SEND_ERROR_CMD,     /* response: couldn't send probe */
  KC_RESP_TIMEOUT_CMD,   /* response: response timed out */
  KC_PING_RESP_CMD,  /* response: valid response to ping command */
  KC_CMD_MAX,

  KC_OPT_MIN,
  KC_TXT_OPT,
  KC_PKT_OPT,
  KC_SRC_OPT,
  KC_DEST_OPT,
  KC_NET_OPT,
  KC_TTL_OPT,
  KC_METH_OPT,
  KC_CKSUM_OPT,
  KC_SPORT_OPT,
  KC_DPORT_OPT,
  KC_SPACING_OPT,
  KC_REPLY_CNT_OPT,
  KC_TIMEOUT_OPT,
  KC_TOS_OPT,
  KC_RR_OPT,
  KC_TSONLY_OPT,
  KC_TSANDADDR_OPT,
  KC_TSPS_IP1_OPT,
  KC_TSPS_IP2_OPT,
  KC_TSPS_IP3_OPT,
  KC_TSPS_IP4_OPT,
  KC_UDATA_OPT,
  KC_TX_OPT,
  KC_RX_OPT,

  KC_PROBE_TTL_OPT,
  KC_PROBE_IPID_OPT,
  KC_REPLY_SRC_OPT,
  KC_REPLY_TTL_OPT,
  KC_REPLY_IPID_OPT,
  KC_REPLY_ICMP_OPT,
  KC_REPLY_QTTL_OPT,
  KC_REPLY_TCP_OPT,
  KC_REPLY_RR_OPT,
  KC_REPLY_TSPS_TS1_OPT,
  KC_REPLY_TSPS_IP1_OPT,
  KC_REPLY_TSPS_TS2_OPT,
  KC_REPLY_TSPS_IP2_OPT,
  KC_REPLY_TSPS_TS3_OPT,
  KC_REPLY_TSPS_IP3_OPT,
  KC_REPLY_TSPS_TS4_OPT,
  KC_REPLY_TSPS_IP4_OPT,
  KC_STOP_REASON_OPT,
  KC_STOP_DATA_OPT,
  KC_OPT_MAX
} keyword_code;

typedef enum {
  KT_NONE=0,
  KT_UINT,
  KT_STR,
  KT_BLOB,
  KT_SYMBOL,
  KT_ADDRESS,
  KT_PREFIX,
  KT_TIMEVAL,
  KT_TYPE_MAX
} keyword_type;

struct keyword
{
  const char* name;
  keyword_code code;
  keyword_type type;
};

extern const char* keyword_code_names[];
extern const char* keyword_type_names[];

const struct keyword *in_word_set(const char *str, unsigned int len);

#endif /* __MPER_KEYWORDS_H__ */
