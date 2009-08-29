/*
** Routines to parse client commands received on the control socket.
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
#include "mper_parser.h"
#include "mper_base64.h"

#define MAX_WORDS 32
#define MAX_ENCODED_SIZE 4096  /* allows 3072 bytes to be encoded */
#define MAX_COMMAND_SIZE 8192

/* command_buf is also used to return error messages to the user */
static char command_buf[MAX_COMMAND_SIZE + 1];  /* + NUL-term */
static control_word_t words[MAX_WORDS];
static unsigned char decode_buf[MAX_ENCODED_SIZE + 1];  /* + NUL-term */

/* ====================================================================== */

static int copy_command(const char *command);
static char *parse_reqnum(char *command);
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

/* ====================================================================== */
/*
** Base64 encoding produces strings that are at least 1 byte longer than
** the input string, since every 3 bytes of input become 4 bytes of output
** and since the output is always a multiple of 4 output bytes (by being
** padded out if the input length is 1 or 2 mod 3).  Hence, we can always
** decode a base64 string in the same amount of space as the input string
** and still have space to NUL-terminate the decoded string.
*/

/* This macro assumes the error message has been written to command_buf. */
#define RETURN_ERROR \
  do { \
    *length_out = 0; \
    memset(&words[0], 0, sizeof(control_word_t)); \
    words[0].cw_name = "<error>"; \
    words[0].cw_code = KC_ERROR; \
    words[0].cw_type = KT_STR; \
    words[0].cw_str = command_buf; \
    return words; \
  } while (0)


/* ====================================================================== */
control_word_t *
parse_control_command(const char *command, size_t *length_out)
{
  char *s = command_buf;
  size_t length;

  if (!copy_command(command)) RETURN_ERROR;
  
  if ((s = parse_reqnum(s)) == NULL) RETURN_ERROR;

  while (*s && *s == ' ') ++s;
  if ((s = parse_command_name(s)) == NULL) RETURN_ERROR;

  for (length = 2; length < MAX_WORDS; length++) {
    while (*s && *s == ' ') ++s;

    if (*s == '\0') {
      *length_out = length;
      return words;
    }
    else {
      if ((s = parse_option(s, length)) == NULL) RETURN_ERROR;
    }
  }

  /* assert(length >= MAX_WORDS); */
  sprintf(command_buf, "command has too many options; max options = %d",
	  MAX_WORDS - 2);
  RETURN_ERROR;
}


/* ====================================================================== */
static int
copy_command(const char *command)
{
  const char *s = command;
  char *d = command_buf;
  char *dend = &command_buf[MAX_COMMAND_SIZE];

  while (*s && d <= dend) {
    *d++ = *s++;
  }

  if (*s == '\0') {
    *d = '\0';
    return 1;
  }
  else {
    sprintf(command_buf, "command too long; max length = %d", MAX_COMMAND_SIZE);
    return 0;
  }
}


/* ====================================================================== */
static char *
parse_reqnum(char *command)
{
  char *s = command;

  if (*s == '\0') {
    sprintf(command_buf, "empty command");
    return NULL;
  }
  else if (isdigit(*s)) {
    while (*s && isdigit(*s)) ++s;

    if (*s == '\0') {
      sprintf(command_buf, "truncated command; nothing after request num");
      return NULL;
    }
    else if (*s == ' ') {
      *s++ = '\0';
      memset(&words[0], 0, sizeof(control_word_t));
      words[0].cw_name = "<reqnum>";
      words[0].cw_code = KC_REQNUM;
      words[0].cw_type = KT_UINT;
      words[0].cw_uint = (uint32_t)strtoul(command, NULL, 10);
      return s;
    }
    else {
      sprintf(command_buf, "illegal character in request num at pos %d",
	      (int)(command_buf - s));
      return NULL;
    }
  }
  else if (*s == ' ') {
    sprintf(command_buf, "missing request num, or request num not at pos 0");
    return NULL;
  }
  else {
    sprintf(command_buf,
	    "expected request num but found illegal charcter at pos 0");
    return NULL;
  }
}


/* ====================================================================== */
/* The caller should guarantee that {name} is advanced past whitespace. */
static char *
parse_command_name(char *name)
{
  char *s = name;

  if (*s == '\0') {
    sprintf(command_buf, "missing command name");
    return NULL;
  }
  else if (*s == '_' || isalpha(*s)) {
    while (*s && (*s == '_' || isalnum(*s))) ++s;

    if (*s == '\0' || *s == ' ') {  /* note: command may not have options */
      if (*s == ' ') *s++ = '\0';

      const keyword_t *keyword = in_word_set(name, strlen(name));
      if (keyword && keyword->code > KC_CMD_MIN && keyword->code < KC_CMD_MAX) {
	memset(&words[1], 0, sizeof(control_word_t));
	words[1].cw_name = name;
	words[1].cw_code = keyword->code;
	words[1].cw_type = keyword->type;
	return s;
      }
      else {
	sprintf(command_buf, "invalid command name at pos %d",
		(int)(command_buf - name));
	return NULL;
      }
    }
    else {
      sprintf(command_buf, "illegal character in command name at pos %d",
	      (int)(command_buf - s));
      return NULL;
    }
  }
  else {
    sprintf(command_buf,
	    "expected command name but found illegal character at pos %d",
	    (int)(command_buf - s));
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
    sprintf(command_buf, "missing option value at pos %d",
	    (int)(command_buf - s));
    return NULL;

  case '0': case '1': case '2': case '3': case '4': case '5': case '6':
  case '7': case '8': case '9':
    return parse_integer_option_value(s, word_index);

  case '$': return parse_base64_option_value(s, word_index);
  case ':': return parse_symbol_option_value(s, word_index);
  case '@': return parse_address_option_value(s, word_index);
  case 'T': return parse_timeval_option_value(s, word_index);

  default:
    sprintf(command_buf, "invalid option value at pos %d",
	    (int)(command_buf - s));
    return NULL;
  }
}


/* ---------------------------------------------------------------------- */
/* The caller should guarantee that {*name != '\0'}. */
/* The caller should guarantee that {name} is advanced past whitespace. */
static char *
parse_option_name(char *name, size_t word_index)
{
  char *s = name;

  if (*s == '_' || isalpha(*s)) {
    while (*s && (*s == '_' || isalnum(*s))) ++s;

    if (*s == '=') {
      *s++ = '\0';

      const keyword_t *keyword = in_word_set(name, strlen(name));
      if (keyword && keyword->code > KC_OPT_MIN && keyword->code < KC_OPT_MAX) {
	memset(&words[word_index], 0, sizeof(control_word_t));
	words[word_index].cw_name = name;
	words[word_index].cw_code = keyword->code;
	words[word_index].cw_type = keyword->type;
	return s;
      }
      else {
	sprintf(command_buf, "invalid option name at pos %d",
		(int)(command_buf - name));
	return NULL;
      }
    }
    else {
      sprintf(command_buf, "illegal character in option name at pos %d",
	      (int)(command_buf - s));
      return NULL;
    }
  }
  else {
    sprintf(command_buf,
	    "expected option name but found illegal character at pos %d",
	    (int)(command_buf - s));
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
    sprintf(command_buf,
	 "value at pos %d has wrong type for option '%s': expected %s, got %s",
	    (int)(command_buf - value), words[word_index].cw_name, 
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
    sprintf(command_buf,
      "value at pos %d has wrong type for option '%s': expected %s, got %s/%s",
	    (int)(command_buf - value), words[word_index].cw_name, 
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
    sprintf(command_buf, "illegal character in %s option value at pos %d",
	    keyword_type_names[KT_UINT], (int)(command_buf - s));
    return NULL;
  }
}


/* ---------------------------------------------------------------------- */
/*
** Syntax: $[a-zA-Z0-9+/=]+  (the base64 decoder performs a stricter check)
**
** The caller should guarantee that {*value != '\0'}.
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
    sprintf(command_buf, "incomplete %s/%s option value at pos %d",
	    keyword_type_names[KT_STR], keyword_type_names[KT_BLOB],
	    (int)(command_buf - s));
    return NULL;
  }
  else if (isalnum(*s) || *s == '+' || *s == '/') {  /* can't start with '=' */
    while (*s && (isalnum(*s) || *s == '+' || *s == '/' || *s == '=')) ++s;

    if (*s == '\0' || *s == ' ') {
      if (*s == ' ') *s++ = '\0';

      decode_len = base64_decode(value + 1, decode_buf);
      if (decode_len > 0) {
	if (!type_check_base64_option(value, word_index)) return NULL;
	if (expected_type == KT_STR) {
	  words[word_index].cw_str = (const char *)decode_buf;
	  decode_buf[decode_len] = '\0';
	}
	else {
	  words[word_index].cw_blob = decode_buf;
	}
	words[word_index].cw_len = decode_len;
	return s;
      }
      else {
	sprintf(command_buf,
		"malformed base64 encoding of option value at pos %d",
		(int)(command_buf - value));
	return NULL;
      }
    }
    /* else fall through */
  }
  /* else fall through */

  sprintf(command_buf, "illegal character in %s/%s option value at pos %d",
	  keyword_type_names[KT_STR], keyword_type_names[KT_BLOB],
	  (int)(command_buf - s));
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
    sprintf(command_buf, "incomplete %s option value at pos %d",
	    keyword_type_names[KT_SYMBOL], (int)(command_buf - s));
    return NULL;
  }
  else if (*s == '_' || isalpha(*s)) {
    while (*s && (*s == '_' || *s == '-' || isalnum(*s))) ++s;

    if (*s == '\0' || *s == ' ') {
      if (*s == ' ') *s++ = '\0';
      if (!type_check_option(KT_SYMBOL, value, word_index)) return NULL;
      words[word_index].cw_sym = value + 1;  /* exclude leading ':' */
      return s;
    }
    /* else fall through */
  }
  /* else fall through */

  sprintf(command_buf, "illegal character in %s option value at pos %d",
	  keyword_type_names[KT_SYMBOL], (int)(command_buf - s));
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
    sprintf(command_buf, "incomplete %s/%s option value at pos %d",
	    keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	    (int)(command_buf - s));
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
      words[word_index].cw_addrstr = value + 1;  /* exclude leading '@' */
      return s;
    }
    else if (*s == '/') {  /* prefix */
      ++s;
      if (*s == '\0') {
	sprintf(command_buf, "incomplete %s option value at pos %d",
		keyword_type_names[KT_PREFIX], (int)(command_buf - s));
	return NULL;
      }
      else if (isdigit(*s)) {
	if ((s = parse_prefix_length(s)) == NULL) return NULL;
	if (*s == '\0' || *s == ' ') {
	  if (*s == ' ') *s++ = '\0';
	  if (!type_check_option(KT_PREFIX, value, word_index)) return NULL;
	  words[word_index].cw_prefixstr = value + 1;  /* exclude leading '@' */
	  return s;
	}
	/* else fall through */
      }
      /* else fall through */
    }
    /* else fall through */
  }
  /* else fall through */

  sprintf(command_buf, "illegal character in %s/%s option value at pos %d",
	  keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	  (int)(command_buf - s));
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

  /* assert(isdigit(*s)); */
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

  sprintf(command_buf, "invalid %s/%s option value at pos %d; octet is out of range or has leading zeros",
	  keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	  (int)(command_buf - octet));
  return NULL;
}


/*
** Parses the dot separating the octets of an IP address.
*/
static char *
parse_address_dot(char *dot)
{
  if (*dot == '.') return dot + 1;
  else {
    sprintf(command_buf,
	    "illegal character in %s/%s option value at pos %d; expected '.'",
	    keyword_type_names[KT_ADDRESS], keyword_type_names[KT_PREFIX],
	    (int)(command_buf - dot));
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

  sprintf(command_buf, "invalid %s option value at pos %d; prefix length is out of range or has leading zeros",
	  keyword_type_names[KT_PREFIX], (int)(command_buf - number));
  return NULL;
}


/* ---------------------------------------------------------------------- */
/*
** Syntax: T[0-9]+:[0-9]+
**
** The caller should guarantee that {*value != '\0'}.
*/
static char *
parse_timeval_option_value(char *value, size_t word_index)
{
  return NULL;  /* NOT IMPLEMENTED */
}
