/*
** A specialized implementation of base64 encoding and decoding.
**
** See
**  + RFC 1421 - Privacy Enhancement for Internet Electronic Mail:
**    Part I: Message Encryption and Authentication Procedures,
**  + RFC3548 - The Base16, Base32, and Base64 Data Encodings, and
**  + Wikipedia http://en.wikipedia.org/wiki/Base64
**
** NOTE: This implementation encodes data into a single long line and
**       expects a single long line to decode.
**
** --------------------------------------------------------------------------
** Copyright (C) 2009 Young Hyun
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

#include <stddef.h>
#include "mper_base64.h"

static const char encode_tbl[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** A base64-decoding table for mapping an encoded 'digit' into the 6-bit
** value it represents.  A non-base64 character maps to 64 (this works for
** the full unsigned 8-bit range, including NUL).
*/
static const unsigned char decode_tbl[256] =
{
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
  64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
  64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
};


/*
** Encodes {len} bytes at {src} into {dst}, and returns the number of base64
** bytes written to {dst} (not counting terminating NUL).
**
** There must be {4 * round[(len + 1) / 3] + 1} bytes available at {dst},
** which will be NUL-terminated.  This outputs a single long line.  Thus,
** you can't directly use this encoder for situations demanding compatibility
** with RFC 1421, which requires the encoded output to be split into lines of
** exactly 64 printable characters each (except the last line).
*/
size_t
base64_encode(const unsigned char *src, size_t len, char *dst)
{
  char *dst_start = dst;

  while (len > 0) {
    if (len >= 3) {  /* A[6:2], B[4:4], C[2:6] */
      unsigned char i, j, k, l;
      i =   src[0] >> 2;
      j = ((src[0] & 0x3) << 4) | (src[1] >> 4);
      k = ((src[1] & 0xf) << 2) | (src[2] >> 6);
      l =   src[2] & 0x3f;
      src += 3;

      *dst++ = encode_tbl[i];
      *dst++ = encode_tbl[j];
      *dst++ = encode_tbl[k];
      *dst++ = encode_tbl[l];
      len -= 3;
    }
    else if (len == 2) {  /* A[6:2], B[4:4], 0[2:_], = */
      unsigned char i, j, k;
      i =   src[0] >> 2;
      j = ((src[0] & 0x3) << 4) | (src[1] >> 4);
      k =  (src[1] & 0xf) << 2;
      src += 2;

      *dst++ = encode_tbl[i];
      *dst++ = encode_tbl[j];
      *dst++ = encode_tbl[k];
      *dst++ = '=';
      len -= 2;
    }
    else {  /* len == 1: A[6:2], 0[4:_], == */
      unsigned char i, j;
      i =   src[0] >> 2;
      j =  (src[0] & 0x3) << 4;
      src += 1;

      *dst++ = encode_tbl[i];
      *dst++ = encode_tbl[j];
      *dst++ = '=';
      *dst++ = '=';
      len -= 1;
    }
  }

  *dst = '\0';
  return dst - dst_start;
}


/*
** Decodes {src} into {dst}, and returns the number of bytes written to {dst}.
**
** If the input is malformed in any way, this returns 0.  This also returns
** 0 if {src} is an empty string, so be careful of the minor ambiguity in
** 0.  This decoder is strict about the input and will abort on
**
**   * embedded whitespace or any other non-base64 character,
**   * extra padding characters ('='), and
**   * anything beyond the padding.
**
** No more than {strlen(src) * 3/4} bytes are needed in {dst} (which will
** NOT be NUL-terminated).  The contents of {src} must be a single long line
** of base64 'digits'; there must not be embedded whitespace or a trailing
** newline.  This input format is different than RFC 1421, which specifies
** multiple lines of 64 printable characters each (except the last, which
** may also be terminated with a newline).
*/
size_t
base64_decode(const char *src, unsigned char *dst)
{
  unsigned char *dst_start = dst;
  unsigned char v1, v2, v3, v4;

  while (*src != '\0') {
    v1 = decode_tbl[(unsigned char)*src++];  if (v1 == 64) return 0;
    v2 = decode_tbl[(unsigned char)*src++];  if (v2 == 64) return 0;
    *dst++ = (v1 << 2) | (v2 >> 4);

    if (*src == '=') {  /* 1 byte: A[6:2], 0[4:_], == */
      if (src[1] == '=' && src[2] == '\0') break;
      else return 0;
    }
    else {
      v3 = decode_tbl[(unsigned char)*src++];  if (v3 == 64) return 0;
      *dst++ = (v2 << 4) | (v3 >> 2);

      if (*src == '=') {  /* 2 bytes: A[6:2], B[4:4], 0[2:_], = */
	if (src[1] == '\0') break;
	else return 0;
      }
      else {  /* 3 bytes: A[6:2], B[4:4], C[2:6] */
	v4 = decode_tbl[(unsigned char)*src++];  if (v4 == 64) return 0;
	*dst++ = (v3 << 6) | v4;
      }
    }
  }

  *dst = '\0';
  return dst - dst_start;
}


/*==========================================================================*/

#ifdef TEST_BASE64
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/*
** If {len} > 0, then print exactly {len} bytes, even if there are NUL
** characters.  Otherwise, print up to the first NUL character.
*/
void
print_escaped(const unsigned char *s, size_t len)
{
  if (len == 0) len = strlen((const char *)s);

  for (; len > 0; len--, s++) {
    switch (*s) {
    case '\\': printf("\\\\"); break;
    case '\t': printf("\\t"); break;
    case '\v': printf("\\v"); break;
    case '\f': printf("\\f"); break;
    case '\r': printf("\\r"); break;
    case '\n': printf("\\n"); break;
    default:
      if (isprint(*s)) {
	putchar(*s);
      }
      else {
	printf("\\x%02X", *s);
      }
      break;
    }
  }
}


void
test_encode(const unsigned char *s, size_t len, char *buf, const char *expect)
{
  base64_encode(s, len, buf);

  printf("'");
  print_escaped(s, len);
  printf("' => '");
  print_escaped((unsigned char *)buf, 0);
  printf("'");

  if (strcmp(buf, expect) == 0) {
    printf(" OK\n");
  }
  else {
    printf(" FAILED: expected '%s'\n", expect);
  }
}


void
test_decode(const char *s, unsigned char *buf, const unsigned char *expect,
	    size_t expect_len)
{
  size_t len = base64_decode(s, buf);

  printf("'");
  print_escaped((const unsigned char *)s, 0);
  printf("' => '");
  print_escaped(buf, len);
  printf("' (%lu)", (unsigned long)len);

  if (*s == '\0') {
    if (len == 0) {
      printf(" OK\n");
    }
    else {
      printf(" FAILED: expected len == 0 for empty src\n");
    }
  }
  else if (len == 0) {
    printf(" FAILED: malformed input (len == 0)\n");
  }
  else if (len == expect_len && memcmp(buf, expect, len) == 0) {
    printf(" OK\n");
  }
  else {
    printf(" FAILED: expected '");
    print_escaped(expect, expect_len);
    printf("' (%lu)\n", (unsigned long)expect_len);
  }
}


int
main(int argc, char *argv[])
{
  unsigned char data_buf[2000];
  char base64_buf[3000+1];

  printf("=== escaping ===\n");
  print_escaped((unsigned char *)"abcdef", 0);
  putchar('\n');
  print_escaped((unsigned char *)"abc\ndef\n", 0);
  putchar('\n');
  print_escaped((unsigned char *)"\\ac\td\vef\f\r\nblah \106\117\107 \010\033", 0);
  printf("\n\n");

  printf("=== encode ===\n");
  test_encode((unsigned char *)"", 0, base64_buf, "");

  /* Wikipedia samples */
  test_encode((unsigned char *)"leasure.", 8, base64_buf, "bGVhc3VyZS4=");
  test_encode((unsigned char *)"easure.", 7, base64_buf, "ZWFzdXJlLg==");
  test_encode((unsigned char *)"asure.", 6, base64_buf, "YXN1cmUu");
  test_encode((unsigned char *)"sure.", 5, base64_buf, "c3VyZS4=");

  /* RFC 3548 samples */
  test_encode((unsigned char *)"\x14\xfb\x9c\x03\xd9\x7e", 6, base64_buf,
	      "FPucA9l+");
  test_encode((unsigned char *)"\x14\xfb\x9c\x03\xd9", 5, base64_buf,
	      "FPucA9k=");
  test_encode((unsigned char *)"\x14\xfb\x9c\x03", 4, base64_buf,
	      "FPucAw==");

   /* https://svn.parrot.org/parrot/trunk/t/library/mime_base64.t */
  test_encode((unsigned char *)"Hello, World!\n", 14, base64_buf, "SGVsbG8sIFdvcmxkIQo=");
  test_encode((unsigned char *)"\t", 1, base64_buf, "CQ==");
  test_encode((unsigned char *)"\n", 1, base64_buf, "Cg==");
  test_encode((unsigned char *)"\f", 1, base64_buf, "DA==");
  test_encode((unsigned char *)"\r", 1, base64_buf, "DQ==");
  test_encode((unsigned char *)"a", 1, base64_buf, "YQ==");
  test_encode((unsigned char *)"aa", 2, base64_buf, "YWE=");
  test_encode((unsigned char *)"aaa", 3, base64_buf, "YWFh");

  printf("\n=== decode ===\n");
  test_decode("", data_buf, (unsigned char *)"", 0);

  /* Wikipedia samples */
  test_decode("bGVhc3VyZS4=", data_buf, (unsigned char *)"leasure.", 8);
  test_decode("ZWFzdXJlLg==", data_buf, (unsigned char *)"easure.", 7);
  test_decode("YXN1cmUu", data_buf, (unsigned char *)"asure.", 6);
  test_decode("c3VyZS4=", data_buf, (unsigned char *)"sure.", 5);

  /* RFC 3548 samples */
  test_decode("FPucA9l+", data_buf,
	      (unsigned char *)"\x14\xfb\x9c\x03\xd9\x7e", 6);
  test_decode("FPucA9k=", data_buf,
	      (unsigned char *)"\x14\xfb\x9c\x03\xd9", 5);
  test_decode("FPucAw==", data_buf,
	      (unsigned char *)"\x14\xfb\x9c\x03", 4);

   /* https://svn.parrot.org/parrot/trunk/t/library/mime_base64.t */
  test_decode("SGVsbG8sIFdvcmxkIQo=", data_buf, (unsigned char *)"Hello, World!\n", 14);
  test_decode("CQ==", data_buf, (unsigned char *)"\t", 1);
  test_decode("Cg==", data_buf, (unsigned char *)"\n", 1);
  test_decode("DA==", data_buf, (unsigned char *)"\f", 1);
  test_decode("DQ==", data_buf, (unsigned char *)"\r", 1);
  test_decode("YQ==", data_buf, (unsigned char *)"a", 1);
  test_decode("YWE=", data_buf, (unsigned char *)"aa", 2);
  test_decode("YWFh", data_buf, (unsigned char *)"aaa", 3);

  /* tests generated with gen-base64-tests */
  printf("\n=== randomly generated encode/decode ===\n");
  test_encode((unsigned char *)"\253\207=Jy\367", 6, base64_buf, "q4c9Snn3");
  test_encode((unsigned char *)"\311\204>\300\r\306\273\315\221x", 10, base64_buf, "yYQ+wA3Gu82ReA==");
  test_encode((unsigned char *)"\213\312K\271)\224\315X\231A!", 11, base64_buf, "i8pLuSmUzViZQSE=");
  test_encode((unsigned char *)"k\304\305", 3, base64_buf, "a8TF");
  test_encode((unsigned char *)"V\2336.+\200\264P\311\251\027U\230", 13, base64_buf, "Vps2LiuAtFDJqRdVmA==");
  test_encode((unsigned char *)"N\307DK\304\231@S\362\323\026\273\262\240\275\314X", 17, base64_buf, "TsdES8SZQFPy0xa7sqC9zFg=");
  test_encode((unsigned char *)"\257\312\247\235I.0\371&!,\344t\227\341K\220A&", 19, base64_buf, "r8qnnUkuMPkmISzkdJfhS5BBJg==");
  test_encode((unsigned char *)"\222\324E", 3, base64_buf, "ktRF");
  test_encode((unsigned char *)"I\261\334\037\254", 5, base64_buf, "SbHcH6w=");
  test_encode((unsigned char *)"*\271\233\223b\377\341\364\\\3620\036M\225b5k/\373\236\237", 21, base64_buf, "Krmbk2L/4fRc8jAeTZViNWsv+56f");
  test_encode((unsigned char *)"\321^YL\313\231\371(", 8, base64_buf, "0V5ZTMuZ+Sg=");
  test_encode((unsigned char *)"i\tv\234\261e\371\207\322\225\275\230", 12, base64_buf, "aQl2nLFl+YfSlb2Y");
  test_encode((unsigned char *)"\223.\323=z", 5, base64_buf, "ky7TPXo=");
  test_encode((unsigned char *)"\367\244\f\237Fe\322\b\231\360\323\207\302\036N\r", 16, base64_buf, "96QMn0Zl0giZ8NOHwh5ODQ==");
  test_encode((unsigned char *)"\364\314", 2, base64_buf, "9Mw=");
  test_encode((unsigned char *)"\260\200\371f9m\343\240\3338~6\017A\b\205\337\223", 18, base64_buf, "sID5Zjlt46DbOH42D0EIhd+T");
  test_encode((unsigned char *)"\2673\244\226r\243\267\017\223\335\312\310\017,", 14, base64_buf, "tzOklnKjtw+T3crIDyw=");
  test_encode((unsigned char *)"\246\372K\356\030\336\230\226t", 9, base64_buf, "pvpL7hjemJZ0");
  test_encode((unsigned char *)"\n\026f\365Fax\273\2138", 10, base64_buf, "ChZm9UZheLuLOA==");
  test_encode((unsigned char *)"\226\375s\320Z\366\300\205\225", 9, base64_buf, "lv1z0Fr2wIWV");
  test_encode((unsigned char *)"\020\252\0041\266Pl;\322\213\265%\374(\270ko\375\261$\214\230", 22, base64_buf, "EKoEMbZQbDvSi7Ul/Ci4a2/9sSSMmA==");
  test_encode((unsigned char *)"Z\202cv(\340f\"", 8, base64_buf, "WoJjdijgZiI=");
  test_encode((unsigned char *)"I\260\360\2319\252\245\251L\262h\260", 12, base64_buf, "SbDwmTmqpalMsmiw");
  test_encode((unsigned char *)"x\0355\224\320;zdqw\236O\222\023(\2717\215\037n", 20, base64_buf, "eB01lNA7emRxd55PkhMouTeNH24=");
  test_encode((unsigned char *)")\346\353r{v\300ad\262AT", 12, base64_buf, "Kebrcnt2wGFkskFU");
  test_encode((unsigned char *)"\205\335\304\240\026\023\272\020\324m6\367_f\370", 15, base64_buf, "hd3EoBYTuhDUbTb3X2b4");
  test_encode((unsigned char *)"\250\334%\211", 4, base64_buf, "qNwliQ==");
  test_encode((unsigned char *)"\234\020<\377\254\205\ag6\203\231BS\206", 14, base64_buf, "nBA8/6yFB2c2g5lCU4Y=");
  test_encode((unsigned char *)"D\317\220^\363\214Y\373f\223\350\252", 12, base64_buf, "RM+QXvOMWftmk+iq");
  test_encode((unsigned char *)"B\024\323:\340j\357\204\037\361y\311 \035\v!%Jx\367\035", 21, base64_buf, "QhTTOuBq74Qf8XnJIB0LISVKePcd");
  test_encode((unsigned char *)"\005\277oE\317\017\354Y\3623\323f?\\\273\301", 16, base64_buf, "Bb9vRc8P7FnyM9NmP1y7wQ==");
  test_encode((unsigned char *)"@=c@7\205\252y\211\350c\273\354", 13, base64_buf, "QD1jQDeFqnmJ6GO77A==");
  test_encode((unsigned char *)"\220\321\211+\037Md-", 8, base64_buf, "kNGJKx9NZC0=");
  test_encode((unsigned char *)"0\322\372\271\367\001\214A\227\0046\024\022\366\037Be\257\f\231\n\202", 22, base64_buf, "MNL6ufcBjEGXBDYUEvYfQmWvDJkKgg==");
  test_encode((unsigned char *)")", 1, base64_buf, "KQ==");
  test_encode((unsigned char *)"fd)r<\322\257", 7, base64_buf, "ZmQpcjzSrw==");
  test_encode((unsigned char *)"$\306\312\210\247\273\311\225dB\247", 11, base64_buf, "JMbKiKe7yZVkQqc=");
  test_encode((unsigned char *)"\227", 1, base64_buf, "lw==");
  test_encode((unsigned char *)"o\276O\313\036p\212\027", 8, base64_buf, "b75Pyx5wihc=");
  test_encode((unsigned char *)"\024~\321\365\237]x\227\\BW@\254H", 14, base64_buf, "FH7R9Z9deJdcQldArEg=");
  test_encode((unsigned char *)"bR+\220\373\273\031\e\221@\207\271\222\"~", 15, base64_buf, "YlIrkPu7GRuRQIe5kiJ+");
  test_encode((unsigned char *)"\3456\374\250", 4, base64_buf, "5Tb8qA==");
  test_encode((unsigned char *)"{\271B]2\356", 6, base64_buf, "e7lCXTLu");
  test_encode((unsigned char *)"H\365(\212\307h\327\020\b\030\177\004k\2062y\354x\003", 19, base64_buf, "SPUoisdo1xAIGH8Ea4Yyeex4Aw==");
  test_encode((unsigned char *)"\356\275uj\265\227\371]\264\177q{\313", 13, base64_buf, "7r11arWX+V20f3F7yw==");
  test_encode((unsigned char *)"\177\254{\251~d\350y\316z\262", 11, base64_buf, "f6x7qX5k6HnOerI=");
  test_encode((unsigned char *)"\355\034\233\273g\251\250\345\006\324\243\362\335)\340\331\f\236\366", 19, base64_buf, "7Rybu2epqOUG1KPy3Sng2Qye9g==");
  test_encode((unsigned char *)"\271G\2019\037\273K~\322\340\220@\271I\006v\225t", 18, base64_buf, "uUeBOR+7S37S4JBAuUkGdpV0");
  test_encode((unsigned char *)"\354\301\302\214\020\227\034\027)", 9, base64_buf, "7MHCjBCXHBcp");
  test_encode((unsigned char *)"\342`\263\3709\360\213\305rX", 10, base64_buf, "4mCz+Dnwi8VyWA==");
  test_encode((unsigned char *)"i\031\324", 3, base64_buf, "aRnU");
  test_encode((unsigned char *)"\217\304\246k#\004\231\r\034a\367\364\252sl\253\234", 17, base64_buf, "j8SmayMEmQ0cYff0qnNsq5w=");
  test_encode((unsigned char *)"6\003b\217\360f\273\026Z\263{f\376\366W\376\314\240\334\215\217", 21, base64_buf, "NgNij/BmuxZas3tm/vZX/syg3I2P");
  test_encode((unsigned char *)"\330\223\213\272\242h\245\227GE\035*\026}\347j\376", 17, base64_buf, "2JOLuqJopZdHRR0qFn3nav4=");
  test_encode((unsigned char *)"\307>\276\r>\023\320\253:\342?\n\373\327\273\306-\250", 18, base64_buf, "xz6+DT4T0Ks64j8K+9e7xi2o");
  test_encode((unsigned char *)"-\276\\N\025\357", 6, base64_buf, "Lb5cThXv");
  test_encode((unsigned char *)"<;\340\215)Y\270\252\326", 9, base64_buf, "PDvgjSlZuKrW");
  test_encode((unsigned char *)"EX\277\035\rK}?P\006\n\2055\342q\027\330", 17, base64_buf, "RVi/HQ1LfT9QBgqFNeJxF9g=");
  test_encode((unsigned char *)"\347\203\222B\232\352R\242PW[\207", 12, base64_buf, "54OSQprqUqJQV1uH");
  test_encode((unsigned char *)"\323L2K\302\031.\201\222_{\223\265z\221\027[\243\271\222", 20, base64_buf, "00wyS8IZLoGSX3uTtXqRF1ujuZI=");
  test_encode((unsigned char *)"\034g\b\315\355\300\301\335s\235\231(D", 13, base64_buf, "HGcIze3Awd1znZkoRA==");
  test_encode((unsigned char *)"\320\apu[^\025\326", 8, base64_buf, "0AdwdVteFdY=");
  test_encode((unsigned char *)"9\244b\355O\354\bh[\235\246\324v\302\303Fv\a\023", 19, base64_buf, "OaRi7U/sCGhbnabUdsLDRnYHEw==");
  test_encode((unsigned char *)"$2\367u\210s\321\310\261\177", 10, base64_buf, "JDL3dYhz0cixfw==");
  test_encode((unsigned char *)":D\353\275\340\246\006}\316|\2205qF\257\"%", 17, base64_buf, "OkTrveCmBn3OfJA1cUavIiU=");
  test_encode((unsigned char *)"\336\n\231j\360\bA\v", 8, base64_buf, "3gqZavAIQQs=");
  test_encode((unsigned char *)"\n\021\262)\217\305", 6, base64_buf, "ChGyKY/F");
  test_encode((unsigned char *)"3\2104", 3, base64_buf, "M4g0");
  test_encode((unsigned char *)"\202Kfr[_", 6, base64_buf, "gktmcltf");
  test_encode((unsigned char *)"\2102\315\005*\263\307\375N_\330\337\276", 13, base64_buf, "iDLNBSqzx/1OX9jfvg==");
  test_encode((unsigned char *)"\227\211\031\267\315<\316\3337", 9, base64_buf, "l4kZt808zts3");
  test_encode((unsigned char *)"\234%\304\202\243\363p\271\016\001 \305H\255[\322\352\026\356", 19, base64_buf, "nCXEgqPzcLkOASDFSK1b0uoW7g==");
  test_encode((unsigned char *)"\273\r\260,H\261\365\300d\225;9z\000\212\333\232", 17, base64_buf, "uw2wLEix9cBklTs5egCK25o=");
  test_encode((unsigned char *)"\003\003\2758\256\214:", 7, base64_buf, "AwO9OK6MOg==");
  test_encode((unsigned char *)")\205\342\370\221\211\333\260\003\261q\304Mo\264", 15, base64_buf, "KYXi+JGJ27ADsXHETW+0");
  test_encode((unsigned char *)"D~\311", 3, base64_buf, "RH7J");
  test_encode((unsigned char *)"[\262S;\\#1/\326\037\241", 11, base64_buf, "W7JTO1wjMS/WH6E=");
  test_encode((unsigned char *)"h\310T\266\251\321\f", 7, base64_buf, "aMhUtqnRDA==");
  test_encode((unsigned char *)"\\Uj", 3, base64_buf, "XFVq");
  test_encode((unsigned char *)"\311K\026un\354\004c\252\"\037w\325u\261", 15, base64_buf, "yUsWdW7sBGOqIh931XWx");
  test_encode((unsigned char *)"\177\307t,_O\342\250\tN\357", 11, base64_buf, "f8d0LF9P4qgJTu8=");
  test_encode((unsigned char *)"\200\2115\006\322\334\377\026\303\225=\277,TM\n\350", 17, base64_buf, "gIk1BtLc/xbDlT2/LFRNCug=");
  test_encode((unsigned char *)"PG\377\351\324x\3205\322P\372@+K\t\355W\223pn", 20, base64_buf, "UEf/6dR40DXSUPpAK0sJ7VeTcG4=");
  test_encode((unsigned char *)"7\340\347\374\337-5\016\020~\314\303\374\b\224", 15, base64_buf, "N+Dn/N8tNQ4QfszD/AiU");
  test_encode((unsigned char *)"\v\r\216\275\224\263\315E\316\356", 10, base64_buf, "Cw2OvZSzzUXO7g==");
  test_encode((unsigned char *)"\363h\315T\211\205\246\027f\235@\351?\320H\020\233\333G\354", 20, base64_buf, "82jNVImFphdmnUDpP9BIEJvbR+w=");
  test_encode((unsigned char *)"=\016l@\221\350\022?", 8, base64_buf, "PQ5sQJHoEj8=");
  test_encode((unsigned char *)"\241\306\023'\332\251%\277v\205\v\361]%\337\266L\270\206$\240\371", 22, base64_buf, "ocYTJ9qpJb92hQvxXSXftky4hiSg+Q==");
  test_encode((unsigned char *)"e\253\217\365\300\342\376\257\322\262q\265\330\256VdAI'r", 20, base64_buf, "ZauP9cDi/q/SsnG12K5WZEFJJ3I=");
  test_encode((unsigned char *)"Lk", 2, base64_buf, "TGs=");
  test_encode((unsigned char *)"`\375\365\311\272", 5, base64_buf, "YP31ybo=");
  test_encode((unsigned char *)"j$\212\342'\267\217\232\235A", 10, base64_buf, "aiSK4ie3j5qdQQ==");
  test_encode((unsigned char *)"8\234\261u\203\260\353\226u\205-K~X\e\250T\254:", 19, base64_buf, "OJyxdYOw65Z1hS1LflgbqFSsOg==");
  test_encode((unsigned char *)"Je\316", 3, base64_buf, "SmXO");
  test_encode((unsigned char *)"\307\360(\274\213\256\025\377+\036\315\357\314a%\264Yy\304\233", 20, base64_buf, "x/AovIuuFf8rHs3vzGEltFl5xJs=");
  test_encode((unsigned char *)"\3644\236\036e\267\340\334\367\205", 10, base64_buf, "9DSeHmW34Nz3hQ==");
  test_encode((unsigned char *)"\216\350\242\340\r\326", 6, base64_buf, "juii4A3W");
  test_encode((unsigned char *)"\302=\200?\323}m\256\270\257l\276\206\004B}\374\305\245\001d\f", 22, base64_buf, "wj2AP9N9ba64r2y+hgRCffzFpQFkDA==");
  test_encode((unsigned char *)"\"\346\b\322U\262\305\025", 8, base64_buf, "IuYI0lWyxRU=");
  test_encode((unsigned char *)"\2312\267&Q\236%\003\211(\3147\024\335\3315u", 17, base64_buf, "mTK3JlGeJQOJKMw3FN3ZNXU=");
  test_encode((unsigned char *)"\000\331\201", 3, base64_buf, "ANmB");
  test_encode((unsigned char *)"\000\330\000\000\205\000\000\000\000\000\000\000\000\263\000\"\000\000", 18, base64_buf, "ANgAAIUAAAAAAAAAALMAIgAA");
  test_encode((unsigned char *)")d\272\000\000\000\000\000\000\000\000A", 12, base64_buf, "KWS6AAAAAAAAAABB");
  test_encode((unsigned char *)"\327V\000\000\v\314", 6, base64_buf, "11YAAAvM");
  test_encode((unsigned char *)"\000\000\336\000\000\000\000\000\000\000\376\000\000\000\000", 15, base64_buf, "AADeAAAAAAAAAP4AAAAA");
  test_encode((unsigned char *)"\000\000\000\000\000\000\000\221\000\263\000\000\025", 13, base64_buf, "AAAAAAAAAJEAswAAFQ==");
  test_encode((unsigned char *)"U\027\000\000\000\000\201\000\000\000\000\000", 12, base64_buf, "VRcAAAAAgQAAAAAA");
  test_encode((unsigned char *)"\000\277\000\000\000}\\\000\000\026\000", 11, base64_buf, "AL8AAAB9XAAAFgA=");
  test_encode((unsigned char *)"J\000\021\000\000", 5, base64_buf, "SgARAAA=");
  test_encode((unsigned char *)"\000E\000q\000\000\000\347\262\000\000\000\000", 13, base64_buf, "AEUAcQAAAOeyAAAAAA==");
  test_encode((unsigned char *)"\340\000\000F\000\000\000\376\000Q\217\000^\202\000", 15, base64_buf, "4AAARgAAAP4AUY8AXoIA");
  test_encode((unsigned char *)"\000\000\000\302\037\000\000\000", 8, base64_buf, "AAAAwh8AAAA=");
  test_encode((unsigned char *)"\000\000\000u\000\000\000\000q\000\005\321\327\000", 14, base64_buf, "AAAAdQAAAABxAAXR1wA=");
  test_encode((unsigned char *)"\000\000\202\000\211\000\000\000\000\000\026\270\000\241_\000\000", 17, base64_buf, "AACCAIkAAAAAABa4AKFfAAA=");
  test_encode((unsigned char *)"\000\000X\000\000\030\325\321\000", 9, base64_buf, "AABYAAAY1dEA");
  test_encode((unsigned char *)"\000\000\000$", 4, base64_buf, "AAAAJA==");
  test_encode((unsigned char *)"]\000\000\000", 4, base64_buf, "XQAAAA==");
  test_encode((unsigned char *)"\000\303\000\000", 4, base64_buf, "AMMAAA==");
  test_encode((unsigned char *)"J\000\000\000\0002\000(\301\000\000#\000\000", 14, base64_buf, "SgAAAAAyACjBAAAjAAA=");
  test_encode((unsigned char *)"\000\000\000\000\000\000\255\000\000\000\000", 11, base64_buf, "AAAAAAAArQAAAAA=");
  test_encode((unsigned char *)"\000\000\000\373\000\037\000\000\000\000\000\000\000", 13, base64_buf, "AAAA+wAfAAAAAAAAAA==");
  test_encode((unsigned char *)"Q\317\342a\376\000\336\311\000\000\000e\000\000\000\000\201\271\000", 19, base64_buf, "Uc/iYf4A3skAAABlAAAAAIG5AA==");
  test_encode((unsigned char *)"r\000\000\000\000\215\000\000\000\000", 10, base64_buf, "cgAAAACNAAAAAA==");
  test_encode((unsigned char *)"\266\000\000\000D\000\316\000\000\000\000", 11, base64_buf, "tgAAAEQAzgAAAAA=");
  test_encode((unsigned char *)"<\000\000\000\000\000\000p\000\000\000\031!\000\000M\313", 17, base64_buf, "PAAAAAAAAHAAAAAZIQAATcs=");
  test_encode((unsigned char *)"\000\000\000\000[\000\000\233\203\000q\000\236\366", 14, base64_buf, "AAAAAFsAAJuDAHEAnvY=");
  test_encode((unsigned char *)"\000M,\f\000\000\345\v/\000\000\000\000\000\000\000\326\000\000\304", 20, base64_buf, "AE0sDAAA5QsvAAAAAAAAANYAAMQ=");
  test_encode((unsigned char *)"T\000\000\000\000\000\240w\000\223\027\000\235\000\000\261~\000", 18, base64_buf, "VAAAAAAAoHcAkxcAnQAAsX4A");
  test_encode((unsigned char *)"\000\326\000\000\000\000\000\031\000\000\000\346\000", 13, base64_buf, "ANYAAAAAABkAAADmAA==");
  test_encode((unsigned char *)"\000\000\000\230\027\000)\000\000\000\357", 11, base64_buf, "AAAAmBcAKQAAAO8=");
  test_encode((unsigned char *)"\000\000\000\253\000\373\000\000\000\000*\247\243\000\000K\000\000\000\370r\000", 22, base64_buf, "AAAAqwD7AAAAACqnowAASwAAAPhyAA==");
  test_encode((unsigned char *)"\000\000\337\000\000\000\000\000\255", 9, base64_buf, "AADfAAAAAACt");
  test_encode((unsigned char *)"\377\000\000\000\000\333\000\000\230\371\\\000\000\341\000\000\000\000\000\000\000\354", 22, base64_buf, "/wAAAADbAACY+VwAAOEAAAAAAAAA7A==");
  test_encode((unsigned char *)"<\327l\000\000\000", 6, base64_buf, "PNdsAAAA");
  test_encode((unsigned char *)"\000.\000\214\343.\000\000\000X$\000\000\000\000(\000\000\000\000\000", 21, base64_buf, "AC4AjOMuAAAAWCQAAAAAKAAAAAAA");
  test_encode((unsigned char *)"\000\000\304\000\000\000\000\000\000\000\000\000i\000\351\000\000\231\000\000\000", 21, base64_buf, "AADEAAAAAAAAAAAAaQDpAACZAAAA");
  test_encode((unsigned char *)"\020\000\207\370\001\000\000\000", 8, base64_buf, "EACH+AEAAAA=");
  test_encode((unsigned char *)"\000\371\000\263\000\000\000", 7, base64_buf, "APkAswAAAA==");
  test_encode((unsigned char *)"\000", 1, base64_buf, "AA==");
  test_encode((unsigned char *)"\000\000:\000\000", 5, base64_buf, "AAA6AAA=");
  test_encode((unsigned char *)"\027\000\000\000\000<\000\251\000\000\000\000W*\000\000N\000\000\000", 20, base64_buf, "FwAAAAA8AKkAAAAAVyoAAE4AAAA=");
  test_encode((unsigned char *)"\000\000\023\000\000\000\000\267\000\000\000", 11, base64_buf, "AAATAAAAALcAAAA=");
  test_encode((unsigned char *)"\203\r\000\231\000\000\000\000\000\313\000\000", 12, base64_buf, "gw0AmQAAAAAAywAA");
  test_encode((unsigned char *)"\227\000\000\000\203\000\301\000\000\000\000\302\000\000\000\000\000\336\031\000\000", 21, base64_buf, "lwAAAIMAwQAAAADCAAAAAADeGQAA");
  test_encode((unsigned char *)"T\016\000\177\000\375\000G\000\000H\000\350\000\347\000\000\000\000", 19, base64_buf, "VA4AfwD9AEcAAEgA6ADnAAAAAA==");
  test_encode((unsigned char *)"\335\000", 2, base64_buf, "3QA=");
  test_encode((unsigned char *)"\000", 1, base64_buf, "AA==");
  test_encode((unsigned char *)"y\000\024\021\000\000U\000\000\000\000\000\000\000\000\000\303", 17, base64_buf, "eQAUEQAAVQAAAAAAAAAAAMM=");
  test_encode((unsigned char *)"\000\000\000\000\000\000\000\000\205\000\000\000", 12, base64_buf, "AAAAAAAAAACFAAAA");
  test_encode((unsigned char *)"\000\267\000\000\354", 5, base64_buf, "ALcAAOw=");

  test_decode("q4c9Snn3", data_buf, (unsigned char *)"\253\207=Jy\367", 6);
  test_decode("yYQ+wA3Gu82ReA==", data_buf, (unsigned char *)"\311\204>\300\r\306\273\315\221x", 10);
  test_decode("i8pLuSmUzViZQSE=", data_buf, (unsigned char *)"\213\312K\271)\224\315X\231A!", 11);
  test_decode("a8TF", data_buf, (unsigned char *)"k\304\305", 3);
  test_decode("Vps2LiuAtFDJqRdVmA==", data_buf, (unsigned char *)"V\2336.+\200\264P\311\251\027U\230", 13);
  test_decode("TsdES8SZQFPy0xa7sqC9zFg=", data_buf, (unsigned char *)"N\307DK\304\231@S\362\323\026\273\262\240\275\314X", 17);
  test_decode("r8qnnUkuMPkmISzkdJfhS5BBJg==", data_buf, (unsigned char *)"\257\312\247\235I.0\371&!,\344t\227\341K\220A&", 19);
  test_decode("ktRF", data_buf, (unsigned char *)"\222\324E", 3);
  test_decode("SbHcH6w=", data_buf, (unsigned char *)"I\261\334\037\254", 5);
  test_decode("Krmbk2L/4fRc8jAeTZViNWsv+56f", data_buf, (unsigned char *)"*\271\233\223b\377\341\364\\\3620\036M\225b5k/\373\236\237", 21);
  test_decode("0V5ZTMuZ+Sg=", data_buf, (unsigned char *)"\321^YL\313\231\371(", 8);
  test_decode("aQl2nLFl+YfSlb2Y", data_buf, (unsigned char *)"i\tv\234\261e\371\207\322\225\275\230", 12);
  test_decode("ky7TPXo=", data_buf, (unsigned char *)"\223.\323=z", 5);
  test_decode("96QMn0Zl0giZ8NOHwh5ODQ==", data_buf, (unsigned char *)"\367\244\f\237Fe\322\b\231\360\323\207\302\036N\r", 16);
  test_decode("9Mw=", data_buf, (unsigned char *)"\364\314", 2);
  test_decode("sID5Zjlt46DbOH42D0EIhd+T", data_buf, (unsigned char *)"\260\200\371f9m\343\240\3338~6\017A\b\205\337\223", 18);
  test_decode("tzOklnKjtw+T3crIDyw=", data_buf, (unsigned char *)"\2673\244\226r\243\267\017\223\335\312\310\017,", 14);
  test_decode("pvpL7hjemJZ0", data_buf, (unsigned char *)"\246\372K\356\030\336\230\226t", 9);
  test_decode("ChZm9UZheLuLOA==", data_buf, (unsigned char *)"\n\026f\365Fax\273\2138", 10);
  test_decode("lv1z0Fr2wIWV", data_buf, (unsigned char *)"\226\375s\320Z\366\300\205\225", 9);
  test_decode("EKoEMbZQbDvSi7Ul/Ci4a2/9sSSMmA==", data_buf, (unsigned char *)"\020\252\0041\266Pl;\322\213\265%\374(\270ko\375\261$\214\230", 22);
  test_decode("WoJjdijgZiI=", data_buf, (unsigned char *)"Z\202cv(\340f\"", 8);
  test_decode("SbDwmTmqpalMsmiw", data_buf, (unsigned char *)"I\260\360\2319\252\245\251L\262h\260", 12);
  test_decode("eB01lNA7emRxd55PkhMouTeNH24=", data_buf, (unsigned char *)"x\0355\224\320;zdqw\236O\222\023(\2717\215\037n", 20);
  test_decode("Kebrcnt2wGFkskFU", data_buf, (unsigned char *)")\346\353r{v\300ad\262AT", 12);
  test_decode("hd3EoBYTuhDUbTb3X2b4", data_buf, (unsigned char *)"\205\335\304\240\026\023\272\020\324m6\367_f\370", 15);
  test_decode("qNwliQ==", data_buf, (unsigned char *)"\250\334%\211", 4);
  test_decode("nBA8/6yFB2c2g5lCU4Y=", data_buf, (unsigned char *)"\234\020<\377\254\205\ag6\203\231BS\206", 14);
  test_decode("RM+QXvOMWftmk+iq", data_buf, (unsigned char *)"D\317\220^\363\214Y\373f\223\350\252", 12);
  test_decode("QhTTOuBq74Qf8XnJIB0LISVKePcd", data_buf, (unsigned char *)"B\024\323:\340j\357\204\037\361y\311 \035\v!%Jx\367\035", 21);
  test_decode("Bb9vRc8P7FnyM9NmP1y7wQ==", data_buf, (unsigned char *)"\005\277oE\317\017\354Y\3623\323f?\\\273\301", 16);
  test_decode("QD1jQDeFqnmJ6GO77A==", data_buf, (unsigned char *)"@=c@7\205\252y\211\350c\273\354", 13);
  test_decode("kNGJKx9NZC0=", data_buf, (unsigned char *)"\220\321\211+\037Md-", 8);
  test_decode("MNL6ufcBjEGXBDYUEvYfQmWvDJkKgg==", data_buf, (unsigned char *)"0\322\372\271\367\001\214A\227\0046\024\022\366\037Be\257\f\231\n\202", 22);
  test_decode("KQ==", data_buf, (unsigned char *)")", 1);
  test_decode("ZmQpcjzSrw==", data_buf, (unsigned char *)"fd)r<\322\257", 7);
  test_decode("JMbKiKe7yZVkQqc=", data_buf, (unsigned char *)"$\306\312\210\247\273\311\225dB\247", 11);
  test_decode("lw==", data_buf, (unsigned char *)"\227", 1);
  test_decode("b75Pyx5wihc=", data_buf, (unsigned char *)"o\276O\313\036p\212\027", 8);
  test_decode("FH7R9Z9deJdcQldArEg=", data_buf, (unsigned char *)"\024~\321\365\237]x\227\\BW@\254H", 14);
  test_decode("YlIrkPu7GRuRQIe5kiJ+", data_buf, (unsigned char *)"bR+\220\373\273\031\e\221@\207\271\222\"~", 15);
  test_decode("5Tb8qA==", data_buf, (unsigned char *)"\3456\374\250", 4);
  test_decode("e7lCXTLu", data_buf, (unsigned char *)"{\271B]2\356", 6);
  test_decode("SPUoisdo1xAIGH8Ea4Yyeex4Aw==", data_buf, (unsigned char *)"H\365(\212\307h\327\020\b\030\177\004k\2062y\354x\003", 19);
  test_decode("7r11arWX+V20f3F7yw==", data_buf, (unsigned char *)"\356\275uj\265\227\371]\264\177q{\313", 13);
  test_decode("f6x7qX5k6HnOerI=", data_buf, (unsigned char *)"\177\254{\251~d\350y\316z\262", 11);
  test_decode("7Rybu2epqOUG1KPy3Sng2Qye9g==", data_buf, (unsigned char *)"\355\034\233\273g\251\250\345\006\324\243\362\335)\340\331\f\236\366", 19);
  test_decode("uUeBOR+7S37S4JBAuUkGdpV0", data_buf, (unsigned char *)"\271G\2019\037\273K~\322\340\220@\271I\006v\225t", 18);
  test_decode("7MHCjBCXHBcp", data_buf, (unsigned char *)"\354\301\302\214\020\227\034\027)", 9);
  test_decode("4mCz+Dnwi8VyWA==", data_buf, (unsigned char *)"\342`\263\3709\360\213\305rX", 10);
  test_decode("aRnU", data_buf, (unsigned char *)"i\031\324", 3);
  test_decode("j8SmayMEmQ0cYff0qnNsq5w=", data_buf, (unsigned char *)"\217\304\246k#\004\231\r\034a\367\364\252sl\253\234", 17);
  test_decode("NgNij/BmuxZas3tm/vZX/syg3I2P", data_buf, (unsigned char *)"6\003b\217\360f\273\026Z\263{f\376\366W\376\314\240\334\215\217", 21);
  test_decode("2JOLuqJopZdHRR0qFn3nav4=", data_buf, (unsigned char *)"\330\223\213\272\242h\245\227GE\035*\026}\347j\376", 17);
  test_decode("xz6+DT4T0Ks64j8K+9e7xi2o", data_buf, (unsigned char *)"\307>\276\r>\023\320\253:\342?\n\373\327\273\306-\250", 18);
  test_decode("Lb5cThXv", data_buf, (unsigned char *)"-\276\\N\025\357", 6);
  test_decode("PDvgjSlZuKrW", data_buf, (unsigned char *)"<;\340\215)Y\270\252\326", 9);
  test_decode("RVi/HQ1LfT9QBgqFNeJxF9g=", data_buf, (unsigned char *)"EX\277\035\rK}?P\006\n\2055\342q\027\330", 17);
  test_decode("54OSQprqUqJQV1uH", data_buf, (unsigned char *)"\347\203\222B\232\352R\242PW[\207", 12);
  test_decode("00wyS8IZLoGSX3uTtXqRF1ujuZI=", data_buf, (unsigned char *)"\323L2K\302\031.\201\222_{\223\265z\221\027[\243\271\222", 20);
  test_decode("HGcIze3Awd1znZkoRA==", data_buf, (unsigned char *)"\034g\b\315\355\300\301\335s\235\231(D", 13);
  test_decode("0AdwdVteFdY=", data_buf, (unsigned char *)"\320\apu[^\025\326", 8);
  test_decode("OaRi7U/sCGhbnabUdsLDRnYHEw==", data_buf, (unsigned char *)"9\244b\355O\354\bh[\235\246\324v\302\303Fv\a\023", 19);
  test_decode("JDL3dYhz0cixfw==", data_buf, (unsigned char *)"$2\367u\210s\321\310\261\177", 10);
  test_decode("OkTrveCmBn3OfJA1cUavIiU=", data_buf, (unsigned char *)":D\353\275\340\246\006}\316|\2205qF\257\"%", 17);
  test_decode("3gqZavAIQQs=", data_buf, (unsigned char *)"\336\n\231j\360\bA\v", 8);
  test_decode("ChGyKY/F", data_buf, (unsigned char *)"\n\021\262)\217\305", 6);
  test_decode("M4g0", data_buf, (unsigned char *)"3\2104", 3);
  test_decode("gktmcltf", data_buf, (unsigned char *)"\202Kfr[_", 6);
  test_decode("iDLNBSqzx/1OX9jfvg==", data_buf, (unsigned char *)"\2102\315\005*\263\307\375N_\330\337\276", 13);
  test_decode("l4kZt808zts3", data_buf, (unsigned char *)"\227\211\031\267\315<\316\3337", 9);
  test_decode("nCXEgqPzcLkOASDFSK1b0uoW7g==", data_buf, (unsigned char *)"\234%\304\202\243\363p\271\016\001 \305H\255[\322\352\026\356", 19);
  test_decode("uw2wLEix9cBklTs5egCK25o=", data_buf, (unsigned char *)"\273\r\260,H\261\365\300d\225;9z\000\212\333\232", 17);
  test_decode("AwO9OK6MOg==", data_buf, (unsigned char *)"\003\003\2758\256\214:", 7);
  test_decode("KYXi+JGJ27ADsXHETW+0", data_buf, (unsigned char *)")\205\342\370\221\211\333\260\003\261q\304Mo\264", 15);
  test_decode("RH7J", data_buf, (unsigned char *)"D~\311", 3);
  test_decode("W7JTO1wjMS/WH6E=", data_buf, (unsigned char *)"[\262S;\\#1/\326\037\241", 11);
  test_decode("aMhUtqnRDA==", data_buf, (unsigned char *)"h\310T\266\251\321\f", 7);
  test_decode("XFVq", data_buf, (unsigned char *)"\\Uj", 3);
  test_decode("yUsWdW7sBGOqIh931XWx", data_buf, (unsigned char *)"\311K\026un\354\004c\252\"\037w\325u\261", 15);
  test_decode("f8d0LF9P4qgJTu8=", data_buf, (unsigned char *)"\177\307t,_O\342\250\tN\357", 11);
  test_decode("gIk1BtLc/xbDlT2/LFRNCug=", data_buf, (unsigned char *)"\200\2115\006\322\334\377\026\303\225=\277,TM\n\350", 17);
  test_decode("UEf/6dR40DXSUPpAK0sJ7VeTcG4=", data_buf, (unsigned char *)"PG\377\351\324x\3205\322P\372@+K\t\355W\223pn", 20);
  test_decode("N+Dn/N8tNQ4QfszD/AiU", data_buf, (unsigned char *)"7\340\347\374\337-5\016\020~\314\303\374\b\224", 15);
  test_decode("Cw2OvZSzzUXO7g==", data_buf, (unsigned char *)"\v\r\216\275\224\263\315E\316\356", 10);
  test_decode("82jNVImFphdmnUDpP9BIEJvbR+w=", data_buf, (unsigned char *)"\363h\315T\211\205\246\027f\235@\351?\320H\020\233\333G\354", 20);
  test_decode("PQ5sQJHoEj8=", data_buf, (unsigned char *)"=\016l@\221\350\022?", 8);
  test_decode("ocYTJ9qpJb92hQvxXSXftky4hiSg+Q==", data_buf, (unsigned char *)"\241\306\023'\332\251%\277v\205\v\361]%\337\266L\270\206$\240\371", 22);
  test_decode("ZauP9cDi/q/SsnG12K5WZEFJJ3I=", data_buf, (unsigned char *)"e\253\217\365\300\342\376\257\322\262q\265\330\256VdAI'r", 20);
  test_decode("TGs=", data_buf, (unsigned char *)"Lk", 2);
  test_decode("YP31ybo=", data_buf, (unsigned char *)"`\375\365\311\272", 5);
  test_decode("aiSK4ie3j5qdQQ==", data_buf, (unsigned char *)"j$\212\342'\267\217\232\235A", 10);
  test_decode("OJyxdYOw65Z1hS1LflgbqFSsOg==", data_buf, (unsigned char *)"8\234\261u\203\260\353\226u\205-K~X\e\250T\254:", 19);
  test_decode("SmXO", data_buf, (unsigned char *)"Je\316", 3);
  test_decode("x/AovIuuFf8rHs3vzGEltFl5xJs=", data_buf, (unsigned char *)"\307\360(\274\213\256\025\377+\036\315\357\314a%\264Yy\304\233", 20);
  test_decode("9DSeHmW34Nz3hQ==", data_buf, (unsigned char *)"\3644\236\036e\267\340\334\367\205", 10);
  test_decode("juii4A3W", data_buf, (unsigned char *)"\216\350\242\340\r\326", 6);
  test_decode("wj2AP9N9ba64r2y+hgRCffzFpQFkDA==", data_buf, (unsigned char *)"\302=\200?\323}m\256\270\257l\276\206\004B}\374\305\245\001d\f", 22);
  test_decode("IuYI0lWyxRU=", data_buf, (unsigned char *)"\"\346\b\322U\262\305\025", 8);
  test_decode("mTK3JlGeJQOJKMw3FN3ZNXU=", data_buf, (unsigned char *)"\2312\267&Q\236%\003\211(\3147\024\335\3315u", 17);
  test_decode("ANmB", data_buf, (unsigned char *)"\000\331\201", 3);
  test_decode("ANgAAIUAAAAAAAAAALMAIgAA", data_buf, (unsigned char *)"\000\330\000\000\205\000\000\000\000\000\000\000\000\263\000\"\000\000", 18);
  test_decode("KWS6AAAAAAAAAABB", data_buf, (unsigned char *)")d\272\000\000\000\000\000\000\000\000A", 12);
  test_decode("11YAAAvM", data_buf, (unsigned char *)"\327V\000\000\v\314", 6);
  test_decode("AADeAAAAAAAAAP4AAAAA", data_buf, (unsigned char *)"\000\000\336\000\000\000\000\000\000\000\376\000\000\000\000", 15);
  test_decode("AAAAAAAAAJEAswAAFQ==", data_buf, (unsigned char *)"\000\000\000\000\000\000\000\221\000\263\000\000\025", 13);
  test_decode("VRcAAAAAgQAAAAAA", data_buf, (unsigned char *)"U\027\000\000\000\000\201\000\000\000\000\000", 12);
  test_decode("AL8AAAB9XAAAFgA=", data_buf, (unsigned char *)"\000\277\000\000\000}\\\000\000\026\000", 11);
  test_decode("SgARAAA=", data_buf, (unsigned char *)"J\000\021\000\000", 5);
  test_decode("AEUAcQAAAOeyAAAAAA==", data_buf, (unsigned char *)"\000E\000q\000\000\000\347\262\000\000\000\000", 13);
  test_decode("4AAARgAAAP4AUY8AXoIA", data_buf, (unsigned char *)"\340\000\000F\000\000\000\376\000Q\217\000^\202\000", 15);
  test_decode("AAAAwh8AAAA=", data_buf, (unsigned char *)"\000\000\000\302\037\000\000\000", 8);
  test_decode("AAAAdQAAAABxAAXR1wA=", data_buf, (unsigned char *)"\000\000\000u\000\000\000\000q\000\005\321\327\000", 14);
  test_decode("AACCAIkAAAAAABa4AKFfAAA=", data_buf, (unsigned char *)"\000\000\202\000\211\000\000\000\000\000\026\270\000\241_\000\000", 17);
  test_decode("AABYAAAY1dEA", data_buf, (unsigned char *)"\000\000X\000\000\030\325\321\000", 9);
  test_decode("AAAAJA==", data_buf, (unsigned char *)"\000\000\000$", 4);
  test_decode("XQAAAA==", data_buf, (unsigned char *)"]\000\000\000", 4);
  test_decode("AMMAAA==", data_buf, (unsigned char *)"\000\303\000\000", 4);
  test_decode("SgAAAAAyACjBAAAjAAA=", data_buf, (unsigned char *)"J\000\000\000\0002\000(\301\000\000#\000\000", 14);
  test_decode("AAAAAAAArQAAAAA=", data_buf, (unsigned char *)"\000\000\000\000\000\000\255\000\000\000\000", 11);
  test_decode("AAAA+wAfAAAAAAAAAA==", data_buf, (unsigned char *)"\000\000\000\373\000\037\000\000\000\000\000\000\000", 13);
  test_decode("Uc/iYf4A3skAAABlAAAAAIG5AA==", data_buf, (unsigned char *)"Q\317\342a\376\000\336\311\000\000\000e\000\000\000\000\201\271\000", 19);
  test_decode("cgAAAACNAAAAAA==", data_buf, (unsigned char *)"r\000\000\000\000\215\000\000\000\000", 10);
  test_decode("tgAAAEQAzgAAAAA=", data_buf, (unsigned char *)"\266\000\000\000D\000\316\000\000\000\000", 11);
  test_decode("PAAAAAAAAHAAAAAZIQAATcs=", data_buf, (unsigned char *)"<\000\000\000\000\000\000p\000\000\000\031!\000\000M\313", 17);
  test_decode("AAAAAFsAAJuDAHEAnvY=", data_buf, (unsigned char *)"\000\000\000\000[\000\000\233\203\000q\000\236\366", 14);
  test_decode("AE0sDAAA5QsvAAAAAAAAANYAAMQ=", data_buf, (unsigned char *)"\000M,\f\000\000\345\v/\000\000\000\000\000\000\000\326\000\000\304", 20);
  test_decode("VAAAAAAAoHcAkxcAnQAAsX4A", data_buf, (unsigned char *)"T\000\000\000\000\000\240w\000\223\027\000\235\000\000\261~\000", 18);
  test_decode("ANYAAAAAABkAAADmAA==", data_buf, (unsigned char *)"\000\326\000\000\000\000\000\031\000\000\000\346\000", 13);
  test_decode("AAAAmBcAKQAAAO8=", data_buf, (unsigned char *)"\000\000\000\230\027\000)\000\000\000\357", 11);
  test_decode("AAAAqwD7AAAAACqnowAASwAAAPhyAA==", data_buf, (unsigned char *)"\000\000\000\253\000\373\000\000\000\000*\247\243\000\000K\000\000\000\370r\000", 22);
  test_decode("AADfAAAAAACt", data_buf, (unsigned char *)"\000\000\337\000\000\000\000\000\255", 9);
  test_decode("/wAAAADbAACY+VwAAOEAAAAAAAAA7A==", data_buf, (unsigned char *)"\377\000\000\000\000\333\000\000\230\371\\\000\000\341\000\000\000\000\000\000\000\354", 22);
  test_decode("PNdsAAAA", data_buf, (unsigned char *)"<\327l\000\000\000", 6);
  test_decode("AC4AjOMuAAAAWCQAAAAAKAAAAAAA", data_buf, (unsigned char *)"\000.\000\214\343.\000\000\000X$\000\000\000\000(\000\000\000\000\000", 21);
  test_decode("AADEAAAAAAAAAAAAaQDpAACZAAAA", data_buf, (unsigned char *)"\000\000\304\000\000\000\000\000\000\000\000\000i\000\351\000\000\231\000\000\000", 21);
  test_decode("EACH+AEAAAA=", data_buf, (unsigned char *)"\020\000\207\370\001\000\000\000", 8);
  test_decode("APkAswAAAA==", data_buf, (unsigned char *)"\000\371\000\263\000\000\000", 7);
  test_decode("AA==", data_buf, (unsigned char *)"\000", 1);
  test_decode("AAA6AAA=", data_buf, (unsigned char *)"\000\000:\000\000", 5);
  test_decode("FwAAAAA8AKkAAAAAVyoAAE4AAAA=", data_buf, (unsigned char *)"\027\000\000\000\000<\000\251\000\000\000\000W*\000\000N\000\000\000", 20);
  test_decode("AAATAAAAALcAAAA=", data_buf, (unsigned char *)"\000\000\023\000\000\000\000\267\000\000\000", 11);
  test_decode("gw0AmQAAAAAAywAA", data_buf, (unsigned char *)"\203\r\000\231\000\000\000\000\000\313\000\000", 12);
  test_decode("lwAAAIMAwQAAAADCAAAAAADeGQAA", data_buf, (unsigned char *)"\227\000\000\000\203\000\301\000\000\000\000\302\000\000\000\000\000\336\031\000\000", 21);
  test_decode("VA4AfwD9AEcAAEgA6ADnAAAAAA==", data_buf, (unsigned char *)"T\016\000\177\000\375\000G\000\000H\000\350\000\347\000\000\000\000", 19);
  test_decode("3QA=", data_buf, (unsigned char *)"\335\000", 2);
  test_decode("AA==", data_buf, (unsigned char *)"\000", 1);
  test_decode("eQAUEQAAVQAAAAAAAAAAAMM=", data_buf, (unsigned char *)"y\000\024\021\000\000U\000\000\000\000\000\000\000\000\000\303", 17);
  test_decode("AAAAAAAAAACFAAAA", data_buf, (unsigned char *)"\000\000\000\000\000\000\000\000\205\000\000\000", 12);
  test_decode("ALcAAOw=", data_buf, (unsigned char *)"\000\267\000\000\354", 5);

  return 0;
}
#endif
