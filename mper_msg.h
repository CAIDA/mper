/*
** Defines for the client/server messages sent/received on the control socket.
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

#ifndef __MPER_MSG_H__
#define __MPER_MSG_H__

/*
** Note: Be careful when performing base64 encoding/decoding with
**       mper_base64.c.  First, base64_encode() will add a NUL terminator,
**       so the encode buffer must be MPER_MSG_MAX_ENCODED_VALUE_SIZE + 1
**       bytes long.  Second, base64_decode() does not add a NUL
**       terminator, but we manually add a NUL terminator when decoding
**       strings (vs. blobs), and so the decode buffer must be
**       MPER_MSG_MAX_RAW_VALUE_SIZE + 1 bytes long.
*/

#define MPER_MSG_MAX_WORDS 64
#define MPER_MSG_MAX_RAW_VALUE_SIZE 3072   /* max input for base64 encoding */
#define MPER_MSG_MAX_ENCODED_VALUE_SIZE 4096  /* decodes to max of 3072 bytes */
#define MPER_MSG_MAX_MESSAGE_SIZE 8192

/* Copy data out if needed for non-transient use. */
typedef struct {
  const char* cw_name;
  keyword_code cw_code;
  keyword_type cw_type;

  union {
    uint32_t u_uint;
    const char *u_str;
    const unsigned char *u_blob; /* same pointer as u_str but different type */
    const char *u_symbol;
    const char *u_address;
    const char *u_prefix;
    struct timeval u_timeval;
  } value_un;

  size_t cw_len;  /* length of u_str / u_blob */
} control_word_t;

#define cw_uint        value_un.u_uint
#define cw_str         value_un.u_str
#define cw_blob        value_un.u_blob
#define cw_symbol      value_un.u_symbol
#define cw_address     value_un.u_address
#define cw_prefix      value_un.u_prefix
#define cw_timeval     value_un.u_timeval

#endif /* __MPER_MSG_H__ */
