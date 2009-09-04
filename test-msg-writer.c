/*
** Tests mper_msg_writer.
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
#include "mper_msg_reader.h"
#include "mper_msg_writer.h"
#include "mper_base64.h"

static control_word_t words[MPER_MSG_MAX_WORDS + 10];  /* +10 for testing */
static int echo_message = 1;  /* whether to echo the message in test() */

/* ====================================================================== */

static void test_create_control_message(void);
static void pass(size_t length, const char *expected_msg);
static void fail(size_t length);
static size_t test(size_t length, const char **message_out);
static void reset_words(uint32_t reqnum, keyword_code command, size_t length);

/* ====================================================================== */
int
main(int argc, char *argv[])
{
  if (argc == 1) {
    test_create_control_message();
    fprintf(stderr, "\n\n=== ALL PASSED ===\n");
  }

  exit(0);
}


/* ====================================================================== */
static void
test_create_control_message(void)
{
  /* test parsing of basic message fields and options */
  memset(&words[0], 0, sizeof(control_word_t));
  memset(&words[1], 0, sizeof(control_word_t));
  memset(&words[2], 0, sizeof(control_word_t));
  fail(0);
  fail(1);
  fail(2);

  reset_words(1234, KC_PING_CMD, 2);
  words[1].cw_code = KC_TXT_OPT;
  fail(2);

  reset_words(1234, KC_PING_CMD, 2);
  pass(2, "1234 ping");

  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_PING_CMD;
  fail(3);

  /*    uint */
  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_TTL_OPT;
  words[2].cw_uint = 5;
  pass(3, "1234 ping ttl=5");

  /*    blob */
  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_PKT_OPT;
  words[2].cw_blob = (const unsigned char *)"Hello, World!";
  words[2].cw_len = 0;  /* illegal */
  fail(3);

  words[2].cw_len = 13;
  pass(3, "1234 ping pkt=$SGVsbG8sIFdvcmxkIQ==");

  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_PKT_OPT;
  words[2].cw_blob = (const unsigned char *)"Hello,\n\nWorld!";
  words[2].cw_len = 14;
  pass(3, "1234 ping pkt=$SGVsbG8sCgpXb3JsZCE=");

  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_PKT_OPT;
  words[2].cw_blob = (const unsigned char *)"Hello,\0World!";
  words[2].cw_len = 13;
  pass(3, "1234 ping pkt=$SGVsbG8sAFdvcmxkIQ==");

  /*    str */
  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_TXT_OPT;
  words[2].cw_str = "Hello, World!";
  words[2].cw_len = 13;
  pass(3, "1234 ping txt=$SGVsbG8sIFdvcmxkIQ==");

  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_TXT_OPT;
  words[2].cw_str = "Hello,\n\nWorld!";
  words[2].cw_len = 14;
  pass(3, "1234 ping txt=$SGVsbG8sCgpXb3JsZCE=");

  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_TXT_OPT;
  words[2].cw_str = "Hello,\0World!";
  words[2].cw_len = 13;
  pass(3, "1234 ping txt=$SGVsbG8sAFdvcmxkIQ==");

  /*    symbol */
  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_METH_OPT;
  words[2].cw_symbol = "__123456";
  pass(3, "1234 ping meth=:__123456");

  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_METH_OPT;
  words[2].cw_symbol = "ab-cd_f-234";
  pass(3, "1234 ping meth=:ab-cd_f-234");

  /*    address and prefix */
  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_DEST_OPT;
  words[2].cw_address = "255.199.99.249";
  pass(3, "1234 ping dest=@255.199.99.249");

  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_NET_OPT;
  words[2].cw_address = "1.2.3.4/5";
  pass(3, "1234 ping net=@1.2.3.4/5");

  /*    timeval */
  reset_words(1234, KC_PING_CMD, 3);
  words[2].cw_code = KC_TX_OPT;
  words[2].cw_timeval.tv_sec = 234;
  words[2].cw_timeval.tv_usec = 567;
  pass(3, "1234 ping tx=T234:567");


  /* test non-interference of multiple str/blobs */
  reset_words(1234, KC_PING_CMD, 4);
  words[2].cw_code = KC_PKT_OPT;
  words[2].cw_blob = (const unsigned char *)"Hello,";
  words[2].cw_len = 6;
  words[3].cw_code = KC_TXT_OPT;
  words[3].cw_str = " World!";
  words[3].cw_len = 7;
  pass(4, "1234 ping pkt=$SGVsbG8s txt=$IFdvcmxkIQ==");

  reset_words(1234, KC_PING_CMD, 4);
  words[2].cw_code = KC_TXT_OPT;
  words[2].cw_str = " World!";
  words[2].cw_len = 7;
  words[3].cw_code = KC_PKT_OPT;
  words[3].cw_blob = (const unsigned char *)"Hello,";
  words[3].cw_len = 6;
  pass(4, "1234 ping txt=$IFdvcmxkIQ== pkt=$SGVsbG8s");
}


/* ====================================================================== */
static void
pass(size_t length, const char *expected_msg)
{
  const char *message;

  if (!test(length, &message)) {
    fprintf(stderr, "FAIL: creation failed on well-formed input\n");
    exit(1);
  }
  else {
    if (strcmp(message, expected_msg) == 0) {
      fprintf(stderr, "ok\n");
    }
    else {
      fprintf(stderr, "FAIL: created message is incorrect\n");
      fprintf(stderr, "   created >> %s\n", message);
      fprintf(stderr, "  expected >> %s\n", expected_msg);
      exit(1);
    }
  }
}


/* ====================================================================== */
static void
fail(size_t length)
{
  if (test(length, NULL)) {
    fprintf(stderr, "FAIL: creation succeeded on malformed input\n");
    exit(1);
  }
  else {
    fprintf(stderr, "ok\n");
  }
}


/* ====================================================================== */
static size_t
test(size_t length, const char **message_out)
{
  size_t msg_length;
  const char *message;

  message = create_control_message(words, length, &msg_length);
  
  fputc('\n', stderr);
  if (msg_length == 0) {
    fprintf(stderr, "CREATE ERROR: %s\n", message);
  }
  else {
    if (echo_message) {
      fprintf(stderr, ">> %s\n", message);
      dump_parsed_message(words, length);
    }
    else {
      fprintf(stderr, ">> ### %d-byte message\n", (int)strlen(message));
    }
    fprintf(stderr, "creation succeeded\n");
  }

  if (message_out) *message_out = message;
  return msg_length;
}


/* ====================================================================== */
static void
reset_words(uint32_t reqnum, keyword_code command, size_t length)
{
  size_t i;
  for (i = 0; i < length; i++) {
    memset(&words[i], 0, sizeof(control_word_t));
  }

  words[0].cw_code = KC_REQNUM;
  words[0].cw_uint = reqnum;
  words[1].cw_code = command;
}
