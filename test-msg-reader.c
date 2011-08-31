/*
** Tests mper_msg_reader and mper_keywords.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "mper_keywords.h"
#include "mper_msg.h"
#include "mper_msg_reader.h"
#include "mper_base64.h"

int echo_message = 1;  /* whether to echo the message in test() */

/* ====================================================================== */

static void test_parse_control_message(void);
static void pass(const char *message, size_t expected_length, ...);
static const char *create_long_msg(const char *start, const char *end,
				   size_t length);
static void pass_long_base64(size_t encoded_length);
static const char *create_long_base64(size_t length);
static void check_value(const control_word_t *value,
			const control_word_t *expected, size_t i);
static void fail(const char *message);
static size_t test(const char *message, const control_word_t **words_out);

/* ====================================================================== */
int
main(int argc, char *argv[])
{
  if (argc == 1) {
    test_parse_control_message();
    fprintf(stderr, "\n\n=== ALL PASSED ===\n");
  }
  else if (argc == 2) {
    test(argv[1], NULL);
  }
  else {
    fprintf(stderr, "usage: test-parser [<message>]\n");
    exit(1);
  }

  exit(0);
}


/* ====================================================================== */
static void
test_parse_control_message(void)
{
  /* test parsing of basic message fields and options */
  fail("");
  fail("A123");
  fail("1ABC8");
  fail("  123");
  fail("123");
  fail("1234 nosuchcommand");
  fail("1234 5678");
  fail("1234 pi-ng");
  pass("1234 ping", 2);
  fail("1234 dest");

  fail("1234 ping ^xyz");
  fail("1234 ping xyz");
  fail("1234 ping pi^g=5");
  fail("1234 ping ^pi=5");
  fail("1234 ping ping=5");

  pass("1234 ping ttl=5", 3, KT_UINT, 5);
  fail("1234 ping ttl= 1234");
  fail("1234 ping ttl=-1234");
  fail("1234 ping ttl=___");
  fail("1234 ping ttl=^@$T");
  fail("1234 ping ttl=123_4");
  fail("1234 ping ttl=123.4");

  /* $ ruby -e 'p [ "Hello, World!" ].pack("m0")' */
  fail("1234 ping pkt=$");
  fail("1234 ping pkt=$ ");
  fail("1234 ping pkt=$=");
  fail("1234 ping pkt=$!@#$");
  fail("1234 ping pkt=$abcdef^^1234ABC");
  fail("1234 ping pkt=$abcdef^^1234ABC");

  pass("1234 ping pkt=$SGVsbG8sIFdvcmxkIQ==", 3,
       KT_BLOB, "Hello, World!", 13);

  pass("1234 ping pkt=$SGVsbG8sCgpXb3JsZCE=", 3,
       KT_BLOB, "Hello,\n\nWorld!", 14);

  pass("1234 ping pkt=$SGVsbG8sAFdvcmxkIQ==", 3,
       KT_BLOB, "Hello,\0World!", 13);

  fail("1234 ping pkt=$SGVsbG8sIFdvcmxkIQ=");  /* malformed base64 encoding */

  pass("1234 ping txt=$SGVsbG8sIFdvcmxkIQ==", 3,
       KT_STR, "Hello, World!", 13);

  pass("1234 ping txt=$SGVsbG8sCgpXb3JsZCE=", 3,
       KT_STR, "Hello,\n\nWorld!", 14);

  pass("1234 ping txt=$SGVsbG8sAFdvcmxkIQ==", 3,
       KT_STR, "Hello,\0World!", 13);

  fail("1234 ping meth=:");
  fail("1234 ping meth=: ");
  fail("1234 ping meth=:123");
  fail("1234 ping meth=:^!@");
  pass("1234 ping meth=:__123456", 3, KT_SYMBOL, "__123456");
  pass("1234 ping meth=:ab-cd_f-234", 3, KT_SYMBOL, "ab-cd_f-234");
  fail("1234 ping meth=:ab-cd_f-234@");

  fail("1234 ping dest=@");
  fail("1234 ping dest=@ ");
  fail("1234 ping dest=@.");
  fail("1234 ping dest=@.1.2.3.4");
  fail("1234 ping dest=@^!@#");
  fail("1234 ping dest=@aaabcd");
  fail("1234 ping dest=@123.456");
  fail("1234 ping dest=@123.123");
  fail("1234 ping dest=@123.123..");
  fail("1234 ping dest=@123..123");
  fail("1234 ping dest=@01.2.3.4");
  fail("1234 ping dest=@001.2.3.4");
  fail("1234 ping dest=@300.2.3.4");
  fail("1234 ping dest=@256.2.3.4");
  fail("1234 ping dest=@1111.2.3.4");
  pass("1234 ping dest=@255.199.99.249", 3, KT_ADDRESS, "255.199.99.249");

  fail("1234 ping net=@1.2.3/");
  fail("1234 ping net=@1.2.3./");
  fail("1234 ping net=@1.2.3.4/");
  fail("1234 ping net=@1.2.3.4/ ");
  fail("1234 ping net=@1.2.3.4/.");
  fail("1234 ping net=@1.2.3.4/0000");
  fail("1234 ping net=@1.2.3.4/01");
  fail("1234 ping net=@1.2.3.4/001");
  fail("1234 ping net=@1.2.3.4/33");
  fail("1234 ping net=@1.2.3.4/34");
  fail("1234 ping net=@1.2.3.4/45");
  pass("1234 ping net=@1.2.3.4/0", 3, KT_PREFIX, "1.2.3.4/0");
  pass("1234 ping net=@1.2.3.4/13", 3, KT_PREFIX, "1.2.3.4/13");
  pass("1234 ping net=@1.2.3.4/32", 3, KT_PREFIX, "1.2.3.4/32");

  fail("1234 ping tx=T");
  fail("1234 ping tx=T ");
  fail("1234 ping tx=T^234");
  fail("1234 ping tx=T234");
  fail("1234 ping tx=T234.");
  fail("1234 ping tx=T234:");
  fail("1234 ping tx=T234: ");
  fail("1234 ping tx=T234:567x");
  pass("1234 ping tx=T234:567", 3, KT_TIMEVAL, (time_t)234, 567);

  /* test non-interference of multiple str/blobs */
  pass("1234 ping pkt=$SGVsbG8s txt=$IFdvcmxkIQ==", 4,
       KT_BLOB, "Hello,", 6, KT_STR, " World!", 7);
  pass("1234 ping txt=$IFdvcmxkIQ== pkt=$SGVsbG8s", 4,
       KT_STR, " World!", 7, KT_BLOB, "Hello,", 6);

  /* test type checking */
  fail("1234 ping ttl=:foo");
  fail("1234 ping ttl=$SGVsbG8sIFdvcmxkIQ==");
  fail("1234 ping dest=$SGVsbG8sIFdvcmxkIQ==");
  fail("1234 ping dest=255");
  fail("1234 ping meth=123456");
  fail("1234 ping meth=@1.2.3.4/0");
  fail("1234 ping net=@1.2.3.4");
  fail("1234 ping net=:hey");
  fail("1234 ping pkt=555");
  fail("1234 ping pkt=:hi");
  fail("1234 ping pkt=T123:456");
  fail("1234 ping tx=123");
  fail("1234 ping tx=$SGVsbG8sIFdvcmxkIQ==");

  /* test parsing of options in different positions */
  pass("1234 ping dport=1234 ttl=5 pkt=$SGVsbG8sIFdvcmxkIQ== meth=:__123456 dest=@255.199.99.249 net=@1.2.3.4/13", 8,
       KT_UINT, 1234, KT_UINT, 5, KT_BLOB, "Hello, World!", 13,
       KT_SYMBOL, "__123456", KT_ADDRESS, "255.199.99.249",
       KT_PREFIX, "1.2.3.4/13");

  pass("1234 ping meth=:__123456 dport=1234 net=@1.2.3.4/13 ttl=5 dest=@255.199.99.249 pkt=$SGVsbG8sIFdvcmxkIQ==", 8,
       KT_SYMBOL, "__123456", KT_UINT, 1234, KT_PREFIX, "1.2.3.4/13",
       KT_UINT, 5, KT_ADDRESS, "255.199.99.249", KT_BLOB, "Hello, World!", 13);

  /* test length limits */
  echo_message = 0;
  pass(create_long_msg("1234 ping tx=T234:567", "ttl=5",
		       MPER_MSG_MAX_MESSAGE_SIZE), 4,
       KT_TIMEVAL, (time_t)234, 567, KT_UINT, 5);
  fail(create_long_msg("1234 ping tx=T234:567", "ttl=5",
		       MPER_MSG_MAX_MESSAGE_SIZE + 1));
  fail(create_long_msg("1234 ping tx=T234:567", "ttl=5",
		       MPER_MSG_MAX_MESSAGE_SIZE + 2));
  fail(create_long_msg("1234 ping tx=T234:567", "ttl=5",
		       MPER_MSG_MAX_MESSAGE_SIZE + 512));

  pass_long_base64(MPER_MSG_MAX_ENCODED_VALUE_SIZE);
  fail(create_long_base64(MPER_MSG_MAX_ENCODED_VALUE_SIZE + 4));
  fail(create_long_base64(MPER_MSG_MAX_ENCODED_VALUE_SIZE + 512));
  echo_message = 1;
}


/* ---------------------------------------------------------------------- */
static const char *
create_long_msg(const char *start, const char *end, size_t length)
{
  static char msgbuf[MPER_MSG_MAX_MESSAGE_SIZE + 1024];

  size_t fieldlen = length - strlen(end);
  sprintf(msgbuf, "%-*s%s", (int)fieldlen, start, end);
  return msgbuf;
}


/* ---------------------------------------------------------------------- */
static void
pass_long_base64(size_t encoded_length)
{
  static char raw_value[MPER_MSG_MAX_RAW_VALUE_SIZE + 512];
  size_t raw_length = 3 * (encoded_length / 4);

  memset(raw_value, '.', raw_length);
  raw_value[raw_length] = '\0';

  pass(create_long_base64(encoded_length), 3, KT_BLOB, raw_value, raw_length);
}


static const char *
create_long_base64(size_t encoded_length)
{
  static char msgbuf[MPER_MSG_MAX_MESSAGE_SIZE + 1];
  static char encodebuf[MPER_MSG_MAX_ENCODED_VALUE_SIZE + 1024];
  size_t raw_length = 3 * (encoded_length / 4);

  fprintf(stderr, "\ncreating blob: %d bytes encoded, %d bytes decoded\n",
	  (int)encoded_length, (int)raw_length);
  memset(msgbuf, '.', sizeof(msgbuf));
  base64_encode((const unsigned char *)msgbuf, raw_length, encodebuf);
  strcpy(msgbuf, "1234 ping pkt=$");
  strcat(msgbuf, encodebuf);
  return msgbuf;
}


/* ====================================================================== */
static void
pass(const char *message, size_t expected_length, ...)
{
  va_list ap;
  const control_word_t *words;
  size_t length = test(message, &words);

  if (length == 0) {
    fprintf(stderr, "FAIL: parsing failed on well-formed input\n");
    exit(1);
  }
  else if (length != expected_length) {
    fprintf(stderr, "FAIL: mismatched length: expected length=%lu, actual length=%lu\n", (unsigned long)expected_length, (unsigned long)length);
    exit(1);
  }
  else {
    control_word_t w;
    size_t i;

    va_start(ap, expected_length);
    for (i = 2; i < expected_length; i++) {
      memset(&w, 0, sizeof(w));
      w.cw_type = va_arg(ap, keyword_type);
      switch (w.cw_type) {
      case KT_UINT: w.cw_uint = va_arg(ap, uint32_t); break;

      case KT_STR:
	w.cw_str = va_arg(ap, const char *);
	w.cw_len = va_arg(ap, size_t);
	break;

      case KT_BLOB:
	w.cw_blob = va_arg(ap, const unsigned char *);
	w.cw_len = va_arg(ap, size_t);
	break;

      case KT_SYMBOL: w.cw_symbol = va_arg(ap, const char *); break;
      case KT_ADDRESS: w.cw_address = va_arg(ap, const char *); break;
      case KT_PREFIX: w.cw_prefix = va_arg(ap, const char *); break;

      case KT_TIMEVAL:
	w.cw_timeval.tv_sec = va_arg(ap, time_t);
	w.cw_timeval.tv_usec = va_arg(ap, long);
	break;

      default: fprintf(stderr, "ASSERTION FAILURE at %s:%d",
		       __FILE__, __LINE__); exit(1);
      }

      check_value(&words[i], &w, i);
    }
    va_end(ap);

    fprintf(stderr, "ok\n");
  }
}


static void
check_value(const control_word_t *value, const control_word_t *expected,
	    size_t i)
{
  if (value->cw_type != expected->cw_type) {
    fprintf(stderr, "FAIL: '%s' option at index %d has wrong type: expected %s, got %s\n",
	    value->cw_name, (int)i, keyword_type_names[expected->cw_type],
	    keyword_type_names[value->cw_type]);
    exit(1);
  }

  switch (value->cw_type) {
  case KT_UINT:
    if (value->cw_uint == expected->cw_uint) return;
    break;

  case KT_STR:
    if (value->cw_len == expected->cw_len
	&& memcmp(value->cw_str, expected->cw_str, expected->cw_len) == 0)
      return;
    break;

  case KT_BLOB:
    if (value->cw_len == expected->cw_len
	&& memcmp(value->cw_blob, expected->cw_blob, expected->cw_len) == 0)
      return;
    break;

  case KT_SYMBOL:
    if (strcmp(value->cw_symbol, expected->cw_symbol) == 0) return;
    break;

  case KT_ADDRESS:
    if (strcmp(value->cw_address, expected->cw_address) == 0) return;
    break;

  case KT_PREFIX:
    if (strcmp(value->cw_prefix, expected->cw_prefix) == 0) return;
    break;

  case KT_TIMEVAL:
    if (value->cw_timeval.tv_sec == expected->cw_timeval.tv_sec
	&& value->cw_timeval.tv_usec == expected->cw_timeval.tv_usec) return;
    break;

  default: fprintf(stderr, "ASSERTION FAILURE at %s:%d",
		   __FILE__, __LINE__); exit(1);
  }

  fprintf(stderr, "FAIL: '%s' option at index %d has wrong value\n",
	  value->cw_name, (int)i);
  exit(1);
}


/* ====================================================================== */
static void
fail(const char *message)
{
  if (test(message, NULL)) {
    fprintf(stderr, "FAIL: parsing succeeded on malformed input\n");
    exit(1);
  }
  else {
    fprintf(stderr, "ok\n");
  }
}


/* ====================================================================== */
static size_t
test(const char *message, const control_word_t **words_out)
{
  const control_word_t *words;
  size_t length;

  if (echo_message) {
    fprintf(stderr, "\n>> %s\n", message);
    words = parse_control_message(message, &length);
    dump_parsed_message(words, length);
  }
  else {
    fprintf(stderr, "\n>> ### %d-byte message\n", (int)strlen(message));
    words = parse_control_message(message, &length);
    if (length == 0) fprintf(stderr, "PARSE ERROR: %s\n", words[1].cw_str);
    else fprintf(stderr, "parsing succeeded\n");
  }

  if (words_out) *words_out = words;
  return length;
}
