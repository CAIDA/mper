/*
** Routines to parse client/server messages received on the control socket.
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
#include <limits.h>  /* needed for strtoul()? */
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include "mper_keywords.h"
#include "mper_msg.h"
#include "mper_msg_reader.h"
#include "mper_base64.h"

/* message_buf is also used to return error messages to the user */
static char message_buf[MPER_MSG_MAX_MESSAGE_SIZE + 1];  /* + NUL-term */
static control_word_t words[MPER_MSG_MAX_WORDS];
static unsigned char decode_buf[MPER_MSG_MAX_RAW_VALUE_SIZE + 1]; /* + NUL*/

/* ====================================================================== */

static int copy_message(const char *message);
static char *parse_reqnum(char *message);
static char *parse_command_name(char *name);
static char *parse_option(char *name, size_t word_index);
static char *parse_option_name(char *name, size_t word_index);
static int type_check_option(keyword_type actual_type, const char *value,
			     size_t word_index);
static int type_check_base64_option(const char *value, size_t word_index);
static char *parse_integer_option_value(char *value, size_t word_index);
static char *parse_base64_option_value(char *value, size_t word_index);
static char *parse_symbol_option_value(char *value, size_t word_index);
static char *parse_address_option_value(char *value, size_t word_index);
static char *parse_address_octet(char *value);
static char *parse_address_dot(char *value);
static char *parse_prefix_length(char *value);
static char *parse_timeval_option_value(char *value, size_t word_index);
static char *parse_timeval_sec(char *number, size_t word_index);
static char *parse_timeval_usec(char *number, size_t word_index);

void dump_parsed_message(const control_word_t *control_words, size_t length);
static const char *get_type_name(keyword_type type);
static void print_escaped(const unsigned char *s, size_t len);


/* ====================================================================== */

/* This macro assumes the error message has been written to message_buf. */
#define RETURN_ERROR \
  do { \
    *length_out = 0; \
    memset(&words[1], 0, sizeof(control_word_t)); \
    words[1].cw_name = "<error>"; \
    words[1].cw_code = KC_ERROR; \
    words[1].cw_type = KT_STR; \
    words[1].cw_str = message_buf; \
    return words; \
  } while (0)


const control_word_t *
parse_control_message(const char *message, size_t *length_out)
{
  char *s = message_buf;
  size_t length;

  memset(&words[0], 0, sizeof(control_word_t));

  if (!copy_message(message)) RETURN_ERROR;
  
  if ((s = parse_reqnum(s)) == NULL) RETURN_ERROR;

  while (*s && *s == ' ') ++s;
  if ((s = parse_command_name(s)) == NULL) RETURN_ERROR;

  for (length = 2; length < MPER_MSG_MAX_WORDS; length++) {
    while (*s && *s == ' ') ++s;

    if (*s == '\0') {
      *length_out = length;
      return words;
    }
    else {
      if ((s = parse_option(s, length)) == NULL) RETURN_ERROR;
    }
  }

  /* assert(length >= MPER_MSG_MAX_WORDS); */
  sprintf(message_buf, "message has too many options; max options = %d",
	  MPER_MSG_MAX_WORDS - 2);
  RETURN_ERROR;
}


/* ====================================================================== */
static int
copy_message(const char *message)
{
  const char *s = message;
  char *d = message_buf;
  char *dend = &message_buf[MPER_MSG_MAX_MESSAGE_SIZE];

  while (*s && d < dend) {
    *d++ = *s++;
  }

  if (*s == '\0') {
    *d = '\0';
    return 1;
  }
  else {
    sprintf(message_buf, "message too long; max length = %d",
	    MPER_MSG_MAX_MESSAGE_SIZE);
    return 0;
  }
}


/* ====================================================================== */
static char *
parse_reqnum(char *message)
{
  char *s = message;

  if (*s == '\0') {
    sprintf(message_buf, "empty message");
    return NULL;
  }
  else if (isdigit(*s)) {
    while (*s && isdigit(*s)) ++s;

    if (*s == '\0') {
      sprintf(message_buf, "truncated message; nothing after request num");
      return NULL;
    }
    else if (*s == ' ') {
      *s++ = '\0';
      memset(&words[0], 0, sizeof(control_word_t));
      words[0].cw_name = "<reqnum>";
      words[0].cw_code = KC_REQNUM;
      words[0].cw_type = KT_UINT;
      words[0].cw_uint = (uint32_t)strtoul(message, NULL, 10);
      return s;
    }
    else {
      sprintf(message_buf, "illegal character in request num at pos %d",
	      (int)(s - message_buf));
      return NULL;
    }
  }
  else if (*s == ' ') {
    sprintf(message_buf, "missing request num, or request num not at pos 0");
    return NULL;
  }
  else {
    sprintf(message_buf,
	    "expected request num but found illegal charcter at pos 0");
    return NULL;
  }
}


/* ====================================================================== */
/* The caller should guarantee that {name} is advanced past whitespace. */
static char *
parse_command_name(char *name)
{
  const struct keyword *keyword;
  char *s = name;

  if (*s == '\0') {
    sprintf(message_buf, "missing command name");
    return NULL;
  }
  else if (*s == '_' || isalpha(*s)) {
    while (*s && (*s == '_' || isalnum(*s))) ++s;

    if (*s == '\0' || *s == ' ') {  /* note: command may not have options */
      if (*s == ' ') *s++ = '\0';

      keyword = in_word_set(name, strlen(name));
      if (keyword && keyword->code > KC_CMD_MIN && keyword->code < KC_CMD_MAX) {
	memset(&words[1], 0, sizeof(control_word_t));
	words[1].cw_name = name;
	words[1].cw_code = keyword->code;
	words[1].cw_type = keyword->type;
	return s;
      }
      else {
	sprintf(message_buf, "invalid command name at pos %d",
		(int)(name - message_buf));
	return NULL;
      }
    }
    else {
      sprintf(message_buf, "illegal character in command name at pos %d",
	      (int)(s - message_buf));
      return NULL;
    }
  }
  else {
    sprintf(message_buf,
	    "expected command name but found illegal character at pos %d",
	    (int)(s - message_buf));
    return NULL;
  }
}


/* ====================================================================== */
/* The caller should guarantee that {*name != '\0'}. */
/* The caller should guarantee that {name} is advanced past whitespace. */
static char *
parse_option(char *name, size_t word_index)
{
  char *s = NULL;

  if ((s = parse_option_name(name, word_index)) == NULL) return NULL;

  switch (*s) {
  case '\0':
    sprintf(message_buf, "missing option value at pos %d",
	    (int)(s - message_buf));
    return NULL;

  case '0': case '1': case '2': case '3': case '4': case '5': case '6':
  case '7': case '8': case '9':
    return parse_integer_option_value(s, word_index);

  case '$': return parse_base64_option_value(s, word_index);
  case ':': return parse_symbol_option_value(s, word_index);
  case '@': return parse_address_option_value(s, word_index);
  case 'T': return parse_timeval_option_value(s, word_index);

  default:
    sprintf(message_buf, "invalid option value at pos %d",
	    (int)(s - message_buf));
    return NULL;
  }
}


/* ---------------------------------------------------------------------- */
/* The caller should guarantee that {*name != '\0'}. */
/* The caller should guarantee that {name} is advanced past whitespace. */
static char *
parse_option_name(char *name, size_t word_index)
{
  const struct keyword *keyword;
  char *s = name;

  if (*s == '_' || isalpha(*s)) {
    while (*s && (*s == '_' || isalnum(*s))) ++s;

    if (*s == '\0' || *s == ' ') {
      sprintf(message_buf, "missing option value at pos %d; expected '='",
	      (int)(s - message_buf));
      return NULL;
    }
    else if (*s == '=') {
      *s++ = '\0';

      keyword = in_word_set(name, strlen(name));
      if (keyword && keyword->code > KC_OPT_MIN && keyword->code < KC_OPT_MAX) {
	memset(&words[word_index], 0, sizeof(control_word_t));
	words[word_index].cw_name = name;
	words[word_index].cw_code = keyword->code;
	words[word_index].cw_type = keyword->type;
	return s;
      }
      else {
	sprintf(message_buf, "invalid option name at pos %d",
		(int)(name - message_buf));
	return NULL;
      }
    }
    else {
      sprintf(message_buf, "illegal character in option name at pos %d",
	      (int)(s - message_buf));
      return NULL;
    }
  }
  else {
    sprintf(message_buf,
	    "expected option name but found illegal character at pos %d",
	    (int)(s - message_buf));
    return NULL;
  }
}


/* ---------------------------------------------------------------------- */
static int
type_check_option(keyword_type actual_type, const char *value,
		  size_t word_index)
{
  keyword_type expected_type = words[word_index].cw_type;

  if (actual_type != expected_type) {
    char name[MPER_MSG_KEYWORD_MAXLEN + 1];
    strncpy(name, words[word_index].cw_name, MPER_MSG_KEYWORD_MAXLEN);
    name[MPER_MSG_KEYWORD_MAXLEN] = '\0';

    sprintf(message_buf,
	 "value at pos %d has wrong type for option '%s': expected %s, got %s",
	    (int)(value - message_buf), name, 
	    keyword_type_names[expected_type],
	    keyword_type_names[actual_type]);
    return 0;
  }
  return 1;
}


/* ---------------------------------------------------------------------- */
static int
type_check_base64_option(const char *value, size_t word_index)
{
  keyword_type expected_type = words[word_index].cw_type;

  if (expected_type != KT_STR && expected_type != KT_BLOB) {
    char name[MPER_MSG_KEYWORD_MAXLEN + 1];
    strncpy(name, words[word_index].cw_name, MPER_MSG_KEYWORD_MAXLEN);
    name[MPER_MSG_KEYWORD_MAXLEN] = '\0';

    sprintf(message_buf,
      "value at pos %d has wrong type for option '%s': expected %s, got %s/%s",
	    (int)(value - message_buf), name, 
	    keyword_type_names[expected_type],
	    keyword_type_names[KT_STR], keyword_type_names[KT_BLOB]);
    return 0;
  }
  return 1;
}


/* ---------------------------------------------------------------------- */
/*
** There is no overflow checking by design; the client protocol leaves the
** behavior undefined for an integer that doesn't fit in uint32_t.
**
** The caller should guarantee that {*value != '\0'}.
*/
static char *
parse_integer_option_value(char *value, size_t word_index)
{
  char *s = value;

  /* assert(isdigit(*s)); */
  while (*s && isdigit(*s)) ++s;  

  if (*s == '\0' || *s == ' ') {
    if (*s == ' ') *s++ = '\0';
    if (!type_check_option(KT_UINT, value, word_index)) return NULL;
    words[word_index].cw_uint = (uint32_t)strtoul(value, NULL, 10);
    return s;
  }
  else {
    sprintf(message_buf, "illegal character in %s option value at pos %d",
	    keyword_type_names[KT_UINT], (int)(s - message_buf));
    return NULL;
  }
}


/* ---------------------------------------------------------------------- */
/*
** Syntax: $[a-zA-Z0-9+/=]+  (the base64 decoder performs a stricter check)
**
** The caller should guarantee that {*value != '\0'}.
**
** We decode a str/blob in place, which is always safe since the encoded
** form of a str/blob will always be longer than the decoded form.  In
** particular, base64 encoding produces strings that are at least 1 byte
** longer than the input string, since every 3 bytes of input become 4
** bytes of output and since the output is always rounded up to the next
** multiple of 4 output bytes.  Hence, we can always decode a base64 string
** in the same amount of space as the input string and still have space to
** NUL-terminate the decoded string.
*/
static char *
parse_base64_option_value(char *value, size_t word_index)
{
  keyword_type expected_type = words[word_index].cw_type;
  size_t decode_len;
  char *s = value;

  /* assert(*s == '$'); */
  ++s;
  if (*s == '\0' || *s == ' ') {
    sprintf(message_buf, "incomplete %s/%s option value at pos %d",
	    keyword_type_names[KT_STR], keyword_type_names[KT_BLOB],
	    (int)(s - message_buf));
    return NULL;
  }
  else if (isalnum(*s) || *s == '+' || *s == '/') {  /* can't start with '=' */
    while (*s && (isalnum(*s) || *s == '+' || *s == '/' || *s == '=')) ++s;

    if (*s == '\0' || *s == ' ') {
      if (s - (value + 1) > MPER_MSG_MAX_ENCODED_VALUE_SIZE) {
	sprintf(message_buf, "%s/%s option value at pos %d is too long in encoded form; %d bytes of base64 encoding > %d max bytes of encoding",
		keyword_type_names[KT_STR], keyword_type_names[KT_BLOB],
		(int)(s - message_buf), (int)(s - (value + 1)),
		MPER_MSG_MAX_ENCODED_VALUE_SIZE);
	return NULL;
      }
      if (*s == ' ') *s++ = '\0';

      decode_len = base64_decode(value + 1, decode_buf);
      if (decode_len > 0) {
	if (!type_check_base64_option(value, word_index)) return NULL;
	memcpy(value + 1, decode_buf, decode_len);
	if (expected_type == KT_STR) {
	  words[word_index].cw_str = value + 1;
	  *(value + 1 + decode_len) = '\0';
	}
	else {
	  words[word_index].cw_blob = (const unsigned char *)value + 1;
	}
	words[word_index].cw_len = decode_len;
	return s;
      }
      else {
	sprintf(message_buf,
		"malformed base64 encoding of option value at pos %d",
		(int)(value - message_buf));
	return NULL;
      }
    }
    /* else fall through */
  }
  /* else fall through */

  sprintf(message_buf, "illegal character in %s/%s option value at pos %d",
	  keyword_type_names[KT_STR], keyword_type_names[KT_BLOB],
	  (int)(s - message_buf));
  return NULL;
}


/* ---------------------------------------------------------------------- */
/*
** Syntax: :[_a-zA-Z][-_a-zA-Z0-9]*
**
** The caller should guarantee that {*value != '\0'}.
*/
static char *
parse_symbol_option_value(char *value, size_t word_index)
{
  char *s = value;

  /* assert(*s == ':'); */
  ++s;
  if (*s == '\0' || *s == ' ') {
    sprintf(message_buf, "incomplete %s option value at pos %d",
	    keyword_type_names[KT_SYMBOL], (int)(s - message_buf));
    return NULL;
  }
  else if (*s == '_' || isalpha(*s)) {
    while (*s && (*s == '_' || *s == '-' || isalnum(*s))) ++s;

    if (*s == '\0' || *s == ' ') {
      if (*s == ' ') *s++ = '\0';
      if (!type_check_option(KT_SYMBOL, value, word_index)) return NULL;
      words[word_index].cw_symbol = value + 1;  /* exclude leading ':' */
      return s;
    }
    /* else fall through */
  }
  /* else fall through */

  sprintf(message_buf, "illegal character in %s option value at pos %d",
	  keyword_type_names[KT_SYMBOL], (int)(s - message_buf));
  return NULL;
}


/* ---------------------------------------------------------------------- */
/*
** Syntax: @\d+\.\d+\.\d+\.\d+(/\d+)?
**
** The caller should guarantee that {*value != '\0'}.
*/
static char *
parse_address_option_value(char *value, size_t word_index)
{
  char *s = value;

  /* assert(*s == '@'); */
  ++s;
  if (*s == '\0' || *s == ' ') {
    sprintf(message_buf, "incomplete %s/%s option value at pos %d",
	    keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	    (int)(s - message_buf));
    return NULL;
  }
  else if (isdigit(*s)) {
    if ((s = parse_address_octet(s)) == NULL) return NULL;
    if ((s = parse_address_dot(s)) == NULL) return NULL;
    if ((s = parse_address_octet(s)) == NULL) return NULL;
    if ((s = parse_address_dot(s)) == NULL) return NULL;
    if ((s = parse_address_octet(s)) == NULL) return NULL;
    if ((s = parse_address_dot(s)) == NULL) return NULL;
    if ((s = parse_address_octet(s)) == NULL) return NULL;

    if (*s == '\0' || *s == ' ') {
      if (*s == ' ') *s++ = '\0';
      if (!type_check_option(KT_ADDRESS, value, word_index)) return NULL;
      words[word_index].cw_address = value + 1;  /* exclude leading '@' */
      return s;
    }
    else if (*s == '/') {  /* prefix */
      ++s;
      if (*s == '\0' || *s == ' ') {
	sprintf(message_buf,
		"incomplete %s option value at pos %d; expected prefix length",
		keyword_type_names[KT_PREFIX], (int)(s - message_buf));
	return NULL;
      }
      else if (isdigit(*s)) {
	if ((s = parse_prefix_length(s)) == NULL) return NULL;
	if (*s == '\0' || *s == ' ') {
	  if (*s == ' ') *s++ = '\0';
	  if (!type_check_option(KT_PREFIX, value, word_index)) return NULL;
	  words[word_index].cw_prefix = value + 1;  /* exclude leading '@' */
	  return s;
	}
	/* else fall through */
      }
      /* else fall through */
    }
    /* else fall through */
  }
  /* else fall through */

  sprintf(message_buf, "illegal character in %s/%s option value at pos %d",
	  keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	  (int)(s - message_buf));
  return NULL;
}


/*
** Parses one octet of an IP address.  This also validates that the octet X
** is in the range 0 <= X <= 255.  This does NOT allow leading zeros
** (e.g., "023"), since some library routines will interpret such a value
** as an octal number.
*/
static char *
parse_address_octet(char *octet)
{
  char *s = octet;
  size_t len;

  if (*s == '\0' || *s == ' ') {
    sprintf(message_buf,
	    "incomplete %s/%s option value at pos %d; expected next octet",
	    keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	    (int)(s - message_buf));
    return NULL;
  }
  else if (isdigit(*s)) {
    while (*s && isdigit(*s)) ++s;

    len = s - octet;
    if (len == 1) return s;
    else if (len == 2) {
      if (*octet != '0') return s;
      /* else fall through */
    }
    else if (len == 3) {
      if (*octet == '1') return s;
      else if (*octet == '2') {
	if (octet[1] <= '4' || (octet[1] == '5' && octet[2] <= '5')) return s;
	/* else fall through */
      }
      /* else fall through */
    }
    /* else len > 3: fall through */

    sprintf(message_buf, "invalid %s/%s option value at pos %d; octet is out of range or has leading zeros",
	    keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	    (int)(octet - message_buf));
    return NULL;
  }
  else {
    sprintf(message_buf, "illegal character in %s/%s option value at pos %d",
	    keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	    (int)(s - message_buf));
    return NULL;
  }
}


/*
** Parses the dot separating the octets of an IP address.
*/
static char *
parse_address_dot(char *dot)
{
  if (*dot == '\0' || *dot == ' ') {
    sprintf(message_buf,
	    "incomplete %s/%s option value at pos %d; expected '.'",
	    keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	    (int)(dot - message_buf));
    return NULL;
  }
  else if (*dot == '.') {
    return dot + 1;
  }
  else {
    sprintf(message_buf,
	    "illegal character in %s/%s option value at pos %d; expected '.'",
	    keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	    (int)(dot - message_buf));
    return NULL;
  }
}


/*
** Parses a prefix length.  This also validates that the length X is in the
** range 0 <= X <= 32.  This does NOT allow leading zeros (e.g., "023"),
** since some library routines will interpret such a value as an octal number.
*/
static char *
parse_prefix_length(char *number)
{
  char *s = number;
  size_t len;

  /* assert(isdigit(*s)); */
  while (*s && isdigit(*s)) ++s;

  len = s - number;
  if (len == 1) return s;
  else if (len == 2) {
    if (*number == '1' || *number == '2'
	|| (*number == '3' && number[1] <= '2')) return s;
    /* else fall through */
  }
  /* else len > 2: fall through */

  sprintf(message_buf, "invalid %s option value at pos %d; prefix length is out of range or has leading zeros",
	  keyword_type_names[KT_PREFIX], (int)(number - message_buf));
  return NULL;
}


/* ---------------------------------------------------------------------- */
/*
** Syntax: T[0-9]+:[0-9]+   (both sec and usec must be positive)
**
** The caller should guarantee that {*value != '\0'}.
*/
static char *
parse_timeval_option_value(char *value, size_t word_index)
{
  char *s = value;

  /* assert(*s == 'T'); */
  ++s;
  if ((s = parse_timeval_sec(s, word_index)) == NULL) return NULL;
  if ((s = parse_timeval_usec(s, word_index)) == NULL) return NULL;
  if (!type_check_option(KT_TIMEVAL, value, word_index)) return NULL;
  return s;
}


/*
** Parses the tv_sec field of a timeval value and the following ':' delimiter.
*/
static char *
parse_timeval_sec(char *number, size_t word_index)
{
  char *s = number;

  if (*s == '\0' || *s == ' ') {
    sprintf(message_buf, "incomplete %s option value at pos %d",
	    keyword_type_names[KT_TIMEVAL], (int)(s - message_buf));
    return NULL;
  }
  else if (isdigit(*s)) {
    while (*s && isdigit(*s)) ++s;

    if (*s == '\0' || *s == ' ') {
      sprintf(message_buf, "incomplete %s option value at pos %d; expected ':'",
	      keyword_type_names[KT_TIMEVAL], (int)(s - message_buf));
      return NULL;
    }
    else if (*s == ':') {
      *s++ = '\0';
      words[word_index].cw_timeval.tv_sec = (time_t)strtol(number, NULL, 10);
      return s;
    }
    /* else fall through */
  }
  /* else fall through */

  sprintf(message_buf, "illegal character in %s option value at pos %d",
	  keyword_type_names[KT_TIMEVAL], (int)(s - message_buf));
  return NULL;
}


/*
** Parses the tv_usec field of a timeval value.
** The caller should have advanced {number} past the ':' delimiter.
*/
static char *
parse_timeval_usec(char *number, size_t word_index)
{
  char *s = number;

  if (*s == '\0' || *s == ' ') {
    sprintf(message_buf, "incomplete %s option value at pos %d; missing usec",
	    keyword_type_names[KT_TIMEVAL], (int)(s - message_buf));
    return NULL;
  }
  else if (isdigit(*s)) {
    while (*s && isdigit(*s)) ++s;

    if (*s == '\0' || *s == ' ') {
      if (*s == ' ') *s++ = '\0';
      words[word_index].cw_timeval.tv_usec = strtol(number, NULL, 10);
      return s;
    }
    /* else fall through */
  }
  /* else fall through */

  sprintf(message_buf, "illegal character in %s option value at pos %d",
	  keyword_type_names[KT_TIMEVAL], (int)(s - message_buf));
  return NULL;
}


/* ====================================================================== */
#define DUMP_ASSERT(expr) \
  do { \
    if (!(expr)) {				       \
      fprintf(stderr, "ASSERTION FAILED in %s:%d: %s\n",	\
	      __FILE__, __LINE__, #expr);			\
      exit(1);							\
    } \
  } while (0)

void
dump_parsed_message(const control_word_t *control_words, size_t length)
{
  size_t i;

  if (length == 0) {  /* parse error */
    DUMP_ASSERT(control_words[1].cw_code == KC_ERROR);
    if (control_words[0].cw_code != KC_REQNUM) {
      fprintf(stderr, "PARSE ERROR: reqnum ??: %s\n", control_words[1].cw_str);
    }
    else {
      fprintf(stderr, "PARSE ERROR: reqnum %lu: %s\n",
	      (unsigned long)control_words[0].cw_uint, control_words[1].cw_str);
    }
  }
  else {
    DUMP_ASSERT(length >= 2);
    DUMP_ASSERT(control_words[0].cw_code == KC_REQNUM);
    DUMP_ASSERT(control_words[1].cw_code > KC_CMD_MIN
		&& control_words[1].cw_code < KC_CMD_MAX);

    fprintf(stderr, "Control message: %lu/0x%08lx %s\n",
	    (unsigned long)control_words[0].cw_uint,
	    (unsigned long)control_words[0].cw_uint,
	    control_words[1].cw_name);

    if (length >= 3) {
      for (i = 2; i < length; i++) {
	DUMP_ASSERT(control_words[i].cw_code > KC_OPT_MIN
		    && control_words[i].cw_code < KC_OPT_MAX);
	fprintf(stderr, "\t%s : %s", control_words[i].cw_name,
		get_type_name(control_words[i].cw_type));

	switch (control_words[i].cw_type) {
	case KT_NONE:
	  fprintf(stderr, " = <none>\n");
	  break;

	case KT_UINT:
	  fprintf(stderr, " = %lu\n", (unsigned long)control_words[i].cw_uint);
	  break;

	case KT_STR:
	  fprintf(stderr, "[%lu]", (unsigned long)control_words[i].cw_len);
	  if (strlen(control_words[i].cw_str) != control_words[i].cw_len) {
	      fprintf(stderr, " (WARN: strlen=%lu)",
		      (unsigned long)strlen(control_words[i].cw_str));
	  }
	  fprintf(stderr, " = \"");
	  print_escaped((unsigned char *)control_words[i].cw_str,
			control_words[i].cw_len);
	  fprintf(stderr, "\"\n");
	  break;

	case KT_BLOB:
	  fprintf(stderr, "[%lu] = |", (unsigned long)control_words[i].cw_len);
	  print_escaped(control_words[i].cw_blob, control_words[i].cw_len);
	  fprintf(stderr, "|\n");
	  break;

	case KT_SYMBOL:
	  fprintf(stderr, " = %s\n", control_words[i].cw_symbol);
	  break;

	case KT_ADDRESS:
	  fprintf(stderr, " = %s\n", control_words[i].cw_address);
	  break;

	case KT_PREFIX:
	  fprintf(stderr, " = %s\n", control_words[i].cw_prefix);
	  break;

	case KT_TIMEVAL:
	  fprintf(stderr, " = %ld sec, %ld usec\n",
		  (long)control_words[i].cw_timeval.tv_sec,
		  (long)control_words[i].cw_timeval.tv_usec);
	  break;

	default: DUMP_ASSERT(0);
	}
      }
    }
  }
}


static const char *
get_type_name(keyword_type type)
{
  static char buf[128];

  if (type >= KT_NONE && type < KT_TYPE_MAX) {
    return keyword_type_names[type];
  }
  else {
    sprintf(buf, "<invalid type %d>", type);
    return buf;
  }
}


/*
** If {len} > 0, then print exactly {len} bytes, even if there are NUL
** characters.  Otherwise, print up to the first NUL character.
*/
static void
print_escaped(const unsigned char *s, size_t len)
{
  if (len == 0) len = strlen((const char *)s);

  for (; len > 0; len--, s++) {
    switch (*s) {
    case '\\': fprintf(stderr, "\\\\"); break;
    case '\t': fprintf(stderr, "\\t"); break;
    case '\v': fprintf(stderr, "\\v"); break;
    case '\f': fprintf(stderr, "\\f"); break;
    case '\r': fprintf(stderr, "\\r"); break;
    case '\n': fprintf(stderr, "\\n"); break;
    default:
      if (isprint(*s)) {
	fputc(*s, stderr);
      }
      else {
	fprintf(stderr, "\\x%02X", *s);
      }
      break;
    }
  }
}
