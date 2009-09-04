/*
** Routines to create client/server messages to send on the control socket.
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

#include "systypes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>

#include "mper_keywords.h"
#include "mper_msg.h"
#include "mper_msg_writer.h"
#include "mper_base64.h"

/* message_buf is also used to return error messages to the user */
static char message_buf[MPER_MSG_MAX_MESSAGE_SIZE + 1];  /* + NUL-term */
static char sprintf_buf[MPER_MSG_MAX_MESSAGE_SIZE + 1];  /* + NUL-term */

/*
** {name_buf} stores {words[i].cw_name} values synthesized during the execution
** of create_control_message().  This buffer contains a sequence of (adjacent)
** NUL-terminated strings (that is, name1\0name2\0name3\0...).
*/
static char name_buf[MPER_MSG_MAX_MESSAGE_SIZE + 1];  /* + NUL-term */

/* ====================================================================== */

static char *strcpy_p(char *s1, const char *s2);

/* ====================================================================== */


/* This macro assumes the error message has been written to message_buf. */
#define RETURN_ERROR \
  do { \
    *msg_length_out = 0; \
    return message_buf; \
  } while (0)


/* ====================================================================== */
const char *
create_control_message(control_word_t *words, size_t length,
		       size_t *msg_length_out)
{
  char *nbp = name_buf;
  const char *name;
  const struct keyword *keyword;
  size_t i;

  if (length < 2) {
    sprintf(message_buf, "invalid number of control words %d", (int)length);
    RETURN_ERROR;
  }

  if (words[0].cw_code != KC_REQNUM) {  /* sanity check */
    sprintf(message_buf,
	    "malformed control word at index 0; expected KC_REQNUM");
    RETURN_ERROR;
  }

  words[0].cw_name = nbp;  nbp = strcpy_p(nbp, keyword_code_names[KC_REQNUM]);
  words[0].cw_type = KT_UINT;

  if (words[1].cw_code <= KC_CMD_MIN || words[1].cw_code >= KC_CMD_MAX) {
    sprintf(message_buf,
	    "invalid command code %d in control word at index 0",
	    (int)words[1].cw_code);
    RETURN_ERROR;
  }

  /* XXX somewhat convoluted way of getting at the unexported type */
  name = keyword_code_names[words[1].cw_code];
  keyword = in_word_set(name, strlen(name));
  words[1].cw_name = nbp;  nbp = strcpy_p(nbp, name);
  words[1].cw_type = keyword->type;

  for (i = 2; i < length; i++) {
    if (words[i].cw_code <= KC_OPT_MIN || words[i].cw_code >= KC_OPT_MAX) {
      sprintf(message_buf,
	      "invalid option code %d in control word at index %d",
	      (int)words[i].cw_code, (int)i);
      RETURN_ERROR;
    }

    name = keyword_code_names[words[i].cw_code];
    keyword = in_word_set(name, strlen(name));
    words[i].cw_name = nbp;  nbp = strcpy_p(nbp, name);
    words[i].cw_type = keyword->type;
  }

  return marshal_control_message(words, length, msg_length_out);
}


/* ---------------------------------------------------------------------- */
#define APPEND_MSG(s, l)			\
  do { \
    if (l > 0) { \
      if (s + l - message_buf <= MPER_MSG_MAX_MESSAGE_SIZE) { \
        memcpy(s, sprintf_buf, l); \
        s += l; \
        *s = '\0'; \
      } \
      else { \
        sprintf(message_buf, "control word at index %d causes message to exceed the maximum length of %d bytes", \
		(int)i, MPER_MSG_MAX_MESSAGE_SIZE);			\
	RETURN_ERROR;							\
      } \
    } \
    else { \
      sprintf(message_buf, "ASSERTION FAILURE at %s:%d: sprintf returned %d", \
	      __FILE__, __LINE__, l);					\
      RETURN_ERROR;							\
    } \
  } while (0)

const char *
marshal_control_message(const control_word_t *words, size_t length,
			size_t *msg_length_out)
{
  const unsigned char *src;
  char *s = message_buf;
  size_t i = 0;
  int l = 0;

  if (length < 2) {
    sprintf(message_buf, "invalid number of control words %d", (int)length);
    RETURN_ERROR;
  }

  if (words[0].cw_code != KC_REQNUM) {  /* sanity check */
    sprintf(message_buf,
	    "malformed control word at index 0; expected KC_REQNUM");
    RETURN_ERROR;
  }

  if (words[1].cw_code <= KC_CMD_MIN || words[1].cw_code >= KC_CMD_MAX) {
    sprintf(message_buf, "invalid command code %d in control word at index 0",
	    (int)words[1].cw_code);
    RETURN_ERROR;
  }

  l = sprintf(sprintf_buf, "%lu %s", (unsigned long)words[0].cw_uint,
	      words[1].cw_name);
  APPEND_MSG(s, l);

  for (i = 2; i < length; i++) {
    if (words[i].cw_code <= KC_OPT_MIN || words[i].cw_code >= KC_OPT_MAX) {
      sprintf(message_buf, "invalid option code %d in control word at index %d",
	      (int)words[i].cw_code, (int)i);
      RETURN_ERROR;
    }

    l = sprintf(sprintf_buf, " %s=", words[i].cw_name);
    APPEND_MSG(s, l);

    switch (words[i].cw_type) {
    case KT_UINT:
      l = sprintf(sprintf_buf, "%lu", (unsigned long)words[i].cw_uint);
      break;

    case KT_STR:
    case KT_BLOB:
      if (words[i].cw_len == 0) {
	sprintf(message_buf,
		"%s/%s value has cw_len == 0 in control word at index %d",
		keyword_type_names[KT_STR], keyword_type_names[KT_BLOB],
		(int)i);
	RETURN_ERROR;
      }
      else if (words[i].cw_len > MPER_MSG_MAX_RAW_VALUE_SIZE) {
	sprintf(message_buf, "%s/%s value is too long in control word at index %d; max length = %d, got %d",
		keyword_type_names[KT_STR], keyword_type_names[KT_BLOB],
		(int)i, MPER_MSG_MAX_RAW_VALUE_SIZE, (int)words[i].cw_len);
	RETURN_ERROR;
      }

      src = (words[i].cw_type == KT_STR ?
	     (const unsigned char *)words[i].cw_str : words[i].cw_blob);
      *sprintf_buf = '$'; /* note: add 1 to l below to adjust for this '$' */
      l = (int)base64_encode(src, words[i].cw_len, sprintf_buf + 1) + 1;
      break;

    case KT_SYMBOL:
      l = sprintf(sprintf_buf, ":%s", words[i].cw_symbol);
      break;

    case KT_ADDRESS:
      l = sprintf(sprintf_buf, "@%s", words[i].cw_address);
      break;

    case KT_PREFIX:
      l = sprintf(sprintf_buf, "@%s", words[i].cw_prefix);
      break;

    case KT_TIMEVAL:
      if (words[i].cw_timeval.tv_sec < 0 || words[i].cw_timeval.tv_usec < 0) {
	sprintf(message_buf,
	       "timeval with negative component(s) in control word at index %d",
		(int)i);
	RETURN_ERROR;
      }
      l = sprintf(sprintf_buf, "T%lu:%lu",
		  (unsigned long)words[i].cw_timeval.tv_sec,
		  (unsigned long)words[i].cw_timeval.tv_usec);
      break;

    default:
      sprintf(message_buf, "invalid option type %d in control word at index %d",
	      (int)words[i].cw_type, (int)i);
      RETURN_ERROR;
    }

    APPEND_MSG(s, l);
  }

  *msg_length_out = s - message_buf;
  return message_buf;
}


/* ====================================================================== */
/* Returns a pointer to just past the \0 of {s1} after copying {s2} to {s1}. */
static char *
strcpy_p(char *s1, const char *s2)
{
  while (*s2) {
    *s1++ = *s2++;
  }

  *s1++ = '\0';
  return s1;
}
