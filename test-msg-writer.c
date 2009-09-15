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
  memset(words, 0, 3 * sizeof(control_word_t));
  fail(0);
  fail(1);
  fail(2);

  INIT_CMESSAGE(words, 1234, PING);
  words[1].cw_code = KC_TXT_OPT;
  fail(CMSG_LEN(0));

  INIT_CMESSAGE(words, 1234, PING);
  pass(CMSG_LEN(0), "1234 ping");

  INIT_CMESSAGE(words, 1234, PING);
  words[2].cw_code = KC_PING_CMD;
  fail(CMSG_LEN(1));

  /*    uint */
  INIT_CMESSAGE(words, 1234, PING);
  SET_UINT_CWORD(words, 1, TTL, 5);
  pass(CMSG_LEN(1), "1234 ping ttl=5");

  /*    blob */
  INIT_CMESSAGE(words, 1234, PING);
  SET_BLOB_CWORD(words, 1, PKT, (const unsigned char *)"Hello, World!", 0);
  fail(CMSG_LEN(1));  /* cw_len of 0 is illegal */

  words[2].cw_len = 13;
  pass(CMSG_LEN(1), "1234 ping pkt=$SGVsbG8sIFdvcmxkIQ==");

  INIT_CMESSAGE(words, 1234, PING);
  SET_BLOB_CWORD(words, 1, PKT, (const unsigned char *)"Hello,\n\nWorld!", 14);
  pass(CMSG_LEN(1), "1234 ping pkt=$SGVsbG8sCgpXb3JsZCE=");

  INIT_CMESSAGE(words, 1234, PING);
  SET_BLOB_CWORD(words, 1, PKT, (const unsigned char *)"Hello,\0World!", 13);
  pass(CMSG_LEN(1), "1234 ping pkt=$SGVsbG8sAFdvcmxkIQ==");

  /*    str */
  INIT_CMESSAGE(words, 1234, PING);
  SET_STR_CWORD(words, 1, TXT, "Hello, World!", 13);
  pass(CMSG_LEN(1), "1234 ping txt=$SGVsbG8sIFdvcmxkIQ==");

  INIT_CMESSAGE(words, 1234, PING);
  SET_STR_CWORD(words, 1, TXT, "Hello,\n\nWorld!", 14);
  pass(CMSG_LEN(1), "1234 ping txt=$SGVsbG8sCgpXb3JsZCE=");

  INIT_CMESSAGE(words, 1234, PING);
  SET_STR_CWORD(words, 1, TXT, "Hello,\0World!", 13);
  pass(CMSG_LEN(1), "1234 ping txt=$SGVsbG8sAFdvcmxkIQ==");

  /*    symbol */
  INIT_CMESSAGE(words, 1234, PING);
  SET_SYMBOL_CWORD(words, 1, METH, "__123456");
  pass(CMSG_LEN(1), "1234 ping meth=:__123456");

  INIT_CMESSAGE(words, 1234, PING);
  SET_SYMBOL_CWORD(words, 1, METH, "ab-cd_f-234");
  pass(CMSG_LEN(1), "1234 ping meth=:ab-cd_f-234");

  /*    address and prefix */
  INIT_CMESSAGE(words, 1234, PING);
  SET_ADDRESS_CWORD(words, 1, DEST, "255.199.99.249");
  pass(CMSG_LEN(1), "1234 ping dest=@255.199.99.249");

  INIT_CMESSAGE(words, 1234, PING);
  SET_PREFIX_CWORD(words, 1, NET, "1.2.3.4/5");
  pass(CMSG_LEN(1), "1234 ping net=@1.2.3.4/5");

  /*    timeval */
  INIT_CMESSAGE(words, 1234, PING);
  SET_TIMEVAL2_CWORD(words, 1, TX, 234, 567);
  pass(CMSG_LEN(1), "1234 ping tx=T234:567");

  /* test non-interference of multiple str/blobs */
  INIT_CMESSAGE(words, 1234, PING);
  SET_BLOB_CWORD(words, 1, PKT, (const unsigned char *)"Hello,", 6);
  SET_STR_CWORD(words, 2, TXT, " World!", 7);
  pass(CMSG_LEN(2), "1234 ping pkt=$SGVsbG8s txt=$IFdvcmxkIQ==");

  INIT_CMESSAGE(words, 1234, PING);
  SET_STR_CWORD(words, 1, TXT, " World!", 7);
  SET_BLOB_CWORD(words, 2, PKT, (const unsigned char *)"Hello,", 6);
  pass(CMSG_LEN(2), "1234 ping txt=$IFdvcmxkIQ== pkt=$SGVsbG8s");

  /* test options in different positions */
  INIT_CMESSAGE(words, 1234, PING);
  SET_UINT_CWORD(words, 1, DPORT, 1234);
  SET_UINT_CWORD(words, 2, TTL, 5);
  SET_BLOB_CWORD(words, 3, PKT, (const unsigned char *)"Hello, World!", 13);
  SET_SYMBOL_CWORD(words, 4, METH, "__123456");
  SET_ADDRESS_CWORD(words, 5, DEST, "255.199.99.249");
  SET_PREFIX_CWORD(words, 6, NET, "1.2.3.4/13");
  pass(CMSG_LEN(6), "1234 ping dport=1234 ttl=5 pkt=$SGVsbG8sIFdvcmxkIQ== meth=:__123456 dest=@255.199.99.249 net=@1.2.3.4/13");

  INIT_CMESSAGE(words, 1234, PING);
  SET_SYMBOL_CWORD(words, 1, METH, "__123456");
  SET_UINT_CWORD(words, 2, DPORT, 1234);
  SET_PREFIX_CWORD(words, 3, NET, "1.2.3.4/13");
  SET_UINT_CWORD(words, 4, TTL, 5);
  SET_ADDRESS_CWORD(words, 5, DEST, "255.199.99.249");
  SET_BLOB_CWORD(words, 6, PKT, (const unsigned char *)"Hello, World!", 13);
  pass(CMSG_LEN(6), "1234 ping meth=:__123456 dport=1234 net=@1.2.3.4/13 ttl=5 dest=@255.199.99.249 pkt=$SGVsbG8sIFdvcmxkIQ==");
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
