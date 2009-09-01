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

typedef enum {
  KC_NONE=0,
  KC_ERROR,     /* pseudo code representing a parse error */
  KC_REQNUM,    /* pseudo code representing the numeric request number */

  KC_CMD_MIN,
  KC_PING_CMD,
  KC_CMD_MAX,

  KC_OPT_MIN,
  KC_JUNKSTR_OPT,
  KC_JUNKPREF_OPT,
  KC_PKT_OPT,
  KC_DEST_OPT,
  KC_TTL_OPT,
  KC_METH_OPT,
  KC_DPORT_OPT,
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

extern const char* keyword_type_names[];

const struct keyword *in_word_set(const char *str, unsigned int len);

#endif /* __MPER_KEYWORDS_H__ */
