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

#include "systypes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include "mper_keywords.h"
#include "mper_msg_reader.h"
#include "mper_base64.h"

static void test_parse_control_message(void);
static void pass(const char *message, size_t expected_length);
static void fail(const char *message);
static size_t test(const char *message);

/* ====================================================================== */
int
main(int argc, char *argv[])
{
  if (argc == 1) {
    test_parse_control_message();
  }
  else if (argc == 2) {
    test(argv[1]);
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

  pass("1234 ping ttl=5", 3);
  fail("1234 ping ttl= 1234");
  fail("1234 ping ttl=-1234");
  fail("1234 ping ttl=___");
  fail("1234 ping ttl=^@$T");
  fail("1234 ping ttl=123_4");
  fail("1234 ping ttl=123.4");

  fail("1234 ping pkt=$");
  fail("1234 ping pkt=$ ");
  fail("1234 ping pkt=$=");
  fail("1234 ping pkt=$!@#$");
  fail("1234 ping pkt=$abcdef^^1234ABC");
  fail("1234 ping pkt=$abcdef^^1234ABC");
  pass("1234 ping pkt=$SGVsbG8sIFdvcmxkIQ==", 3);  /* "Hello, World!" */
  pass("1234 ping pkt=$SGVsbG8sCgpXb3JsZCE=", 3);  /* "Hello,\n\nWorld!" */
  pass("1234 ping pkt=$SGVsbG8sAFdvcmxkIQ==", 3);  /* "Hello,\0World!" */
  fail("1234 ping pkt=$SGVsbG8sIFdvcmxkIQ=");

  pass("1234 ping junkstr=$SGVsbG8sIFdvcmxkIQ==", 3);  /* "Hello, World!" */
  pass("1234 ping junkstr=$SGVsbG8sCgpXb3JsZCE=", 3);  /* "Hello,\n\nWorld!" */
  pass("1234 ping junkstr=$SGVsbG8sAFdvcmxkIQ==", 3);  /* "Hello,\0World!" */

  fail("1234 ping meth=:");
  fail("1234 ping meth=: ");
  fail("1234 ping meth=:123");
  fail("1234 ping meth=:^!@");
  pass("1234 ping meth=:__123456", 3);
  pass("1234 ping meth=:ab-cd_f-234", 3);
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
  pass("1234 ping dest=@255.199.99.249", 3);

  fail("1234 ping junkpref=@1.2.3/");
  fail("1234 ping junkpref=@1.2.3./");
  fail("1234 ping junkpref=@1.2.3.4/");
  fail("1234 ping junkpref=@1.2.3.4/ ");
  fail("1234 ping junkpref=@1.2.3.4/.");
  fail("1234 ping junkpref=@1.2.3.4/0000");
  fail("1234 ping junkpref=@1.2.3.4/01");
  fail("1234 ping junkpref=@1.2.3.4/001");
  fail("1234 ping junkpref=@1.2.3.4/33");
  fail("1234 ping junkpref=@1.2.3.4/34");
  fail("1234 ping junkpref=@1.2.3.4/45");
  pass("1234 ping junkpref=@1.2.3.4/0", 3);
  pass("1234 ping junkpref=@1.2.3.4/13", 3);
  pass("1234 ping junkpref=@1.2.3.4/32", 3);

  fail("1234 ping tx=T");
  fail("1234 ping tx=T ");
  fail("1234 ping tx=T^234");
  fail("1234 ping tx=T234");
  fail("1234 ping tx=T234.");
  fail("1234 ping tx=T234:");
  fail("1234 ping tx=T234: ");
  fail("1234 ping tx=T234:567x");
  pass("1234 ping tx=T234:567", 3);

  /* test type checking */
  fail("1234 ping ttl=:foo");
  fail("1234 ping ttl=$SGVsbG8sIFdvcmxkIQ==");
  fail("1234 ping dest=$SGVsbG8sIFdvcmxkIQ==");
  fail("1234 ping dest=255");
  fail("1234 ping meth=123456");
  fail("1234 ping meth=@1.2.3.4/0");
  fail("1234 ping junkpref=@1.2.3.4");
  fail("1234 ping junkpref=:hey");
  fail("1234 ping pkt=555");
  fail("1234 ping pkt=:hi");
  fail("1234 ping pkt=T123:456");
  fail("1234 ping tx=123");
  fail("1234 ping tx=$SGVsbG8sIFdvcmxkIQ==");

  /* test parsing of options in different positions */
  pass("1234 ping dport=1234 ttl=5 pkt=$SGVsbG8sIFdvcmxkIQ== meth=:__123456 dest=@255.199.99.249 junkpref=@1.2.3.4/13", 8);
  pass("1234 ping meth=:__123456 dport=1234 junkpref=@1.2.3.4/13 ttl=5 dest=@255.199.99.249 pkt=$SGVsbG8sIFdvcmxkIQ==", 8);
}


/* ====================================================================== */
static void
pass(const char *message, size_t expected_length)
{
  size_t length = test(message);

  if (length == 0) {
    fprintf(stderr, "FAIL: parsing failed on well-formed input\n");
    exit(1);
  }
  else if (length != expected_length) {
    fprintf(stderr, "FAIL: mismatched length: expected length=%lu, actual length=%lu\n", (unsigned long)expected_length, (unsigned long)length);
    exit(1);
  }
  else {
    fprintf(stderr, "ok\n");
  }
}


/* ====================================================================== */
static void
fail(const char *message)
{
  if (test(message)) {
    fprintf(stderr, "FAIL: parsing succeeded on malformed input\n");
    exit(1);
  }
  else {
    fprintf(stderr, "ok\n");
  }
}


/* ====================================================================== */
static size_t
test(const char *message)
{
  const control_word_t *words;
  size_t length;

  fprintf(stderr, "\n>> %s\n", message);
  words = parse_control_message(message, &length);
  dump_parsed_message(words, length);
  return length;
}
