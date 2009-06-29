/*
** A specialized implementation of base64 encoding and decoding.
**
** See RFC 1421 (Privacy Enhancement for Internet Electronic Mail:
** Part I: Message Encryption and Authentication Procedures) and
** Wikipedia http://en.wikipedia.org/wiki/Base64
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
** Encodes {len} bytes at {src} into {dst}.
**
** There must be {4 * round[(len + 1) / 3] + 1} bytes available at {dst},
** which will be NUL-terminated.  This outputs a single long line.  Thus,
** you can't directly use this encoder for situations demanding compatibility
** with RFC 1421, which requires the encoded output to be split into lines of
** exactly 64 printable characters each (except the last line).
*/
void
base64_encode(const unsigned char *src, size_t len, char *dst)
{
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
}


/*
** Decodes {src} into {dst}, returning the number of bytes written to {dst}.
**
** There must be {strlen(src) * 3/4} bytes available at {dst} (which will
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
    v1 = decode_tbl[*src++];  if (v1 == 64) return 0;
    v2 = decode_tbl[*src++];  if (v2 == 64) return 0;
    *dst++ = (v1 << 2) | (v2 >> 4);

    if (*src == '=') {  /* 1 byte: A[6:2], 0[4:_], == */
      if (src[1] == '=' && src[2] == '\0') break;
      else return 0;
    }
    else {
      v3 = decode_tbl[*src++];  if (v3 == 64) return 0;
      *dst++ = (v2 << 4) | (v3 >> 2);

      if (*src == '=') {  /* 2 bytes: A[6:2], B[4:4], 0[2:_], = */
	if (src[1] == '\0') break;
	else return 0;
      }
      else {  /* 3 bytes: A[6:2], B[4:4], C[2:6] */
	v4 = decode_tbl[*src++];
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

void
test_str_encode(const char *s, char *buf, const char *expect)
{
  size_t len = strlen(s);

  base64_encode((const unsigned char *)s, len, buf);
  printf("'%s' => '%s'", s, buf);
  if (strcmp(buf, expect) == 0) {
    printf(" OK\n");
  }
  else {
    printf(" FAILED: expected '%s'\n", expect);
  }
}


void
test_str_decode(const char *s, char *buf, const char *expect)
{
  size_t len = base64_decode(s, (unsigned char *)buf);
  printf("'%s' => '%s' (%d)", s, buf, len);
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
  else if (strcmp(buf, expect) == 0) {
    printf(" OK\n");
  }
  else {
    printf(" FAILED: expected '%s'\n", expect);
  }
}


int
main(int argc, char *argv[])
{
  unsigned char data_buf[2000];
  char base64_buf[3000+1];

  /* Wikipedia samples */
  printf("=== encode ===\n");
  test_str_encode("", base64_buf, "");
  test_str_encode("leasure.", base64_buf, "bGVhc3VyZS4=");
  test_str_encode("easure.", base64_buf, "ZWFzdXJlLg==");
  test_str_encode("asure.", base64_buf, "YXN1cmUu");
  test_str_encode("sure.", base64_buf, "c3VyZS4=");

  printf("\n=== decode ===\n");
  test_str_decode("", base64_buf, "");
  test_str_decode("bGVhc3VyZS4=", base64_buf, "leasure.");
  test_str_decode("ZWFzdXJlLg==", base64_buf, "easure.");
  test_str_decode("YXN1cmUu", base64_buf, "asure.");
  test_str_decode("c3VyZS4=", base64_buf, "sure.");

  return 0;
}
#endif

