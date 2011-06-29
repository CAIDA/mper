/* C code produced by gperf version 3.0.4 */
/* Command-line: gperf mper_keywords.gperf  */
/* Computed positions: -k'1,12,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif

#line 6 "mper_keywords.gperf"

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

#include <string.h>

#include "mper_keywords.h"

const char* keyword_code_names[] = {
  "<NONE>",
  "<ERROR>",
  "<REQNUM>",

  "<CMD_MIN>",
  "ping",
  "cmd_error",
  "send_error",
  "resp_timeout",
  "ping_resp",
  "<CMD_MAX>",

  "<OPT_MIN>",
  "txt",
  "pkt",
  "src",
  "dest",
  "net",
  "ttl",
  "meth",
  "cksum",
  "sport",
  "dport",
  "spacing",
  "reply_cnt",
  "timeout",
  "tos",
  "rr",
  "tsonly",
  "tsandaddr",
  "tsps_ip1",
  "tsps_ip2",
  "tsps_ip3",
  "tsps_ip4",
  "udata",
  "tx",
  "rx",

  "probe_ttl",
  "probe_ipid",
  "reply_src",
  "reply_ttl",
  "reply_ipid",
  "reply_icmp",
  "reply_qttl",
  "reply_tcp",
  "reply_rr",
  "reply_tsps_ts1",
  "reply_tsps_ip1",
  "reply_tsps_ts2",
  "reply_tsps_ip2",
  "reply_tsps_ts3",
  "reply_tsps_ip3",
  "reply_tsps_ts4",
  "reply_tsps_ip4",
  "stop_reason",
  "stop_data",
  "<OPT_MAX>"
};

const char* keyword_type_names[] = {
  "<none>",
  "integer",
  "string",
  "blob",
  "symbol",
  "IP address",
  "IP prefix",
  "timeval"
};
#line 107 "mper_keywords.gperf"
struct keyword;

#define TOTAL_KEYWORDS 48
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 14
#define MIN_HASH_VALUE 2
#define MAX_HASH_VALUE 89
/* maximum key range = 88, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  static const unsigned char asso_values[] =
    {
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 50,
      45, 35, 20, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 31, 90, 27,
      30,  0, 90, 60,  0, 25, 90, 90, 20, 15,
       0, 30, 10, 15, 10,  0,  5,  5,  5, 90,
       0,  0, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
      90, 90, 90, 90, 90, 90, 90
    };
  register int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[11]];
      /*FALLTHROUGH*/
      case 11:
      case 10:
      case 9:
      case 8:
      case 7:
      case 6:
      case 5:
      case 4:
      case 3:
      case 2:
      case 1:
        hval += asso_values[(unsigned char)str[0]+1];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

#ifdef __GNUC__
__inline
#if defined __GNUC_STDC_INLINE__ || defined __GNUC_GNU_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
const struct keyword *
in_word_set (str, len)
     register const char *str;
     register unsigned int len;
{
  static const struct keyword wordlist[] =
    {
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 141 "mper_keywords.gperf"
      {"rx", KC_RX_OPT, KT_TIMEVAL},
      {"",KC_NONE,KT_NONE},
#line 124 "mper_keywords.gperf"
      {"meth", KC_METH_OPT, KT_SYMBOL},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 140 "mper_keywords.gperf"
      {"tx", KC_TX_OPT, KT_TIMEVAL},
#line 131 "mper_keywords.gperf"
      {"tos", KC_TOS_OPT, KT_UINT},
#line 121 "mper_keywords.gperf"
      {"dest", KC_DEST_OPT, KT_ADDRESS},
#line 127 "mper_keywords.gperf"
      {"dport", KC_DPORT_OPT, KT_UINT},
#line 133 "mper_keywords.gperf"
      {"tsonly", KC_TSONLY_OPT, KT_UINT},
#line 132 "mper_keywords.gperf"
      {"rr", KC_RR_OPT, KT_UINT},
#line 118 "mper_keywords.gperf"
      {"txt", KC_TXT_OPT, KT_STR},
#line 129 "mper_keywords.gperf"
      {"reply_cnt", KC_REPLY_CNT_OPT, KT_UINT},
#line 126 "mper_keywords.gperf"
      {"sport", KC_SPORT_OPT, KT_UINT},
#line 161 "mper_keywords.gperf"
      {"stop_reason", KC_STOP_REASON_OPT, KT_UINT},
#line 130 "mper_keywords.gperf"
      {"timeout", KC_TIMEOUT_OPT, KT_UINT},
#line 152 "mper_keywords.gperf"
      {"reply_rr", KC_REPLY_RR_OPT, KT_STR},
#line 151 "mper_keywords.gperf"
      {"reply_tcp", KC_REPLY_TCP_OPT, KT_UINT},
#line 149 "mper_keywords.gperf"
      {"reply_icmp", KC_REPLY_ICMP_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE},
#line 114 "mper_keywords.gperf"
      {"resp_timeout", KC_RESP_TIMEOUT_CMD, KT_NONE},
#line 119 "mper_keywords.gperf"
      {"pkt", KC_PKT_OPT, KT_BLOB},
#line 134 "mper_keywords.gperf"
      {"tsandaddr", KC_TSANDADDR_OPT, KT_UINT},
#line 113 "mper_keywords.gperf"
      {"send_error", KC_SEND_ERROR_CMD, KT_NONE},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 123 "mper_keywords.gperf"
      {"ttl", KC_TTL_OPT, KT_UINT},
#line 147 "mper_keywords.gperf"
      {"reply_ttl", KC_REPLY_TTL_OPT, KT_UINT},
#line 150 "mper_keywords.gperf"
      {"reply_qttl", KC_REPLY_QTTL_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 138 "mper_keywords.gperf"
      {"tsps_ip4", KC_TSPS_IP4_OPT, KT_ADDRESS},
#line 115 "mper_keywords.gperf"
      {"ping_resp", KC_PING_RESP_CMD, KT_NONE},
#line 120 "mper_keywords.gperf"
      {"src", KC_SRC_OPT, KT_ADDRESS},
#line 146 "mper_keywords.gperf"
      {"reply_src", KC_REPLY_SRC_OPT, KT_ADDRESS},
      {"",KC_NONE,KT_NONE},
#line 122 "mper_keywords.gperf"
      {"net", KC_NET_OPT, KT_PREFIX},
#line 159 "mper_keywords.gperf"
      {"reply_tsps_ts4", KC_REPLY_TSPS_TS4_OPT, KT_UINT},
#line 148 "mper_keywords.gperf"
      {"reply_ipid", KC_REPLY_IPID_OPT, KT_UINT},
#line 139 "mper_keywords.gperf"
      {"udata", KC_UDATA_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 144 "mper_keywords.gperf"
      {"probe_ttl", KC_PROBE_TTL_OPT, KT_UINT},
#line 162 "mper_keywords.gperf"
      {"stop_data", KC_STOP_DATA_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 137 "mper_keywords.gperf"
      {"tsps_ip3", KC_TSPS_IP3_OPT, KT_ADDRESS},
#line 112 "mper_keywords.gperf"
      {"cmd_error", KC_CMD_ERROR_CMD, KT_NONE},
#line 125 "mper_keywords.gperf"
      {"cksum", KC_CKSUM_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
      {"",KC_NONE,KT_NONE},
#line 157 "mper_keywords.gperf"
      {"reply_tsps_ts3", KC_REPLY_TSPS_TS3_OPT, KT_UINT},
#line 145 "mper_keywords.gperf"
      {"probe_ipid", KC_PROBE_IPID_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 136 "mper_keywords.gperf"
      {"tsps_ip2", KC_TSPS_IP2_OPT, KT_ADDRESS},
#line 160 "mper_keywords.gperf"
      {"reply_tsps_ip4", KC_REPLY_TSPS_IP4_OPT, KT_ADDRESS},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
      {"",KC_NONE,KT_NONE},
#line 135 "mper_keywords.gperf"
      {"tsps_ip1", KC_TSPS_IP1_OPT, KT_ADDRESS},
#line 155 "mper_keywords.gperf"
      {"reply_tsps_ts2", KC_REPLY_TSPS_TS2_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 153 "mper_keywords.gperf"
      {"reply_tsps_ts1", KC_REPLY_TSPS_TS1_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 128 "mper_keywords.gperf"
      {"spacing", KC_SPACING_OPT, KT_UINT},
      {"",KC_NONE,KT_NONE},
#line 158 "mper_keywords.gperf"
      {"reply_tsps_ip3", KC_REPLY_TSPS_IP3_OPT, KT_ADDRESS},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 111 "mper_keywords.gperf"
      {"ping", KC_PING_CMD, KT_NONE},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 156 "mper_keywords.gperf"
      {"reply_tsps_ip2", KC_REPLY_TSPS_IP2_OPT, KT_ADDRESS},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
      {"",KC_NONE,KT_NONE}, {"",KC_NONE,KT_NONE},
#line 154 "mper_keywords.gperf"
      {"reply_tsps_ip1", KC_REPLY_TSPS_IP1_OPT, KT_ADDRESS}
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key].name;

          if (*str == *s && !strcmp (str + 1, s + 1))
            return &wordlist[key];
        }
    }
  return 0;
}
#line 163 "mper_keywords.gperf"

/* functions */
