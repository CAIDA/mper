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
static void fail(size_t length);
static size_t test(size_t length, const char **message_out);
static void reset_words(uint32_t reqnum, keyword_code command);

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

  reset_words(1234, KC_PING_CMD);
  words[1].cw_code = KC_TXT_OPT;
  fail(2);
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
reset_words(uint32_t reqnum, keyword_code command)
{
  memset(&words[0], 0, sizeof(control_word_t));
  memset(&words[1], 0, sizeof(control_word_t));
  words[0].cw_code = KC_REQNUM;
  words[0].cw_uint = reqnum;
  words[1].cw_code = command;
}
