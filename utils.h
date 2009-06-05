/*
 * utils.h
 *
 * $Id: utils.h,v 1.79 2009/05/13 06:14:58 mjl Exp $
 *
 * Copyright (C) 2004-2009 The University of Waikato
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

#ifndef __UTILS_H
#define __UTILS_H

/*
 * Functions for dealing with time and timestamps
 */

int timeval_cmp(const struct timeval *a, const struct timeval *b);

int timeval_diff_ms(const struct timeval *a, const struct timeval *b);
int timeval_diff_us(const struct timeval *a, const struct timeval *b);
void timeval_diff_tv(struct timeval *rtt,
		     const struct timeval *from, const struct timeval *to);

void timeval_add_cs(struct timeval *out, const struct timeval *in, int cs);
void timeval_add_ms(struct timeval *out, const struct timeval *in, int ms);
void timeval_add_us(struct timeval *out, const struct timeval *in, int us);
void timeval_add_tv(struct timeval *tv, const struct timeval *add);
void timeval_add_s(struct timeval *out, const struct timeval *in, int s);
void timeval_sub_us(struct timeval *out, const struct timeval *in, int us);
void timeval_cpy(struct timeval *dst, const struct timeval *src);
int timeval_inrange_us(const struct timeval *a,const struct timeval *b,int c);

void gettimeofday_wrap(struct timeval *tv);

int fstat_mtime(int fd, time_t *mtime);
int stat_mtime(const char *filename, time_t *mtime);

/*
 * Functions for dealing with memory allocation
 */
#ifndef DMALLOC
void *malloc_zero(const size_t size);
void *memdup(const void *ptr, const size_t len);
int   realloc_wrap(void **ptr, size_t len);
#else
int   realloc_wrap_dm(void **ptr,size_t len, const char *file,const int line);
#define realloc_wrap(ptr, len) realloc_wrap_dm((ptr),(len), __FILE__,__LINE__)
#define malloc_zero(size) memset(malloc(size), 0, size)
#define memdup(ptr, len) memcpy(malloc(len), ptr, len)
#endif

void *array_find(void **a, int nmemb, const void *item,
		 int (*cmp)(const void *, const void *));

int array_findpos(void **a, int nmemb, const void *item,
		  int (*cmp)(const void *, const void *));

void array_remove(void **, int *nmemb, int pos);

void array_qsort(void **array,int nmemb,int (*cmp)(const void *,const void *));

#ifndef DMALLOC
int array_insert(void ***a, int *nmemb, void *item,
		 int (*cmp)(const void *, const void *));
#else
int array_insert_dm(void ***a, int *nmemb, void *item,
		    int (*cmp)(const void *, const void *),
		    const char *file, const int line);
#define array_insert(a, nmemb, item, cmp) \
  array_insert_dm((a), (nmemb), (item), (cmp), __FILE__, __LINE__)
#endif

/*
 * Functions for dealing with raw IPv4/IPv6 addresses
 */

int addr6_cmp(const void *a, const void *b);
int addr4_cmp(const void *a, const void *b);
int addr_cmp(const int af, const void *a, const void *b);
void *addr_dup(const int af, const void *addr);
const char *addr_tostr(int af, const void *addr, char *buf, size_t len);

/*
 * Functions for dealing with sockaddr addresses
 */

int sockaddr_compose(struct sockaddr *sa,
		     const int af, const void *addr, const int port);
int sockaddr_len(const struct sockaddr *sa);
struct sockaddr *sockaddr_dup(const struct sockaddr *sa);
char *sockaddr_tostr(const struct sockaddr *sa, char *buf, const size_t len);

/*
 * Functions for dealing with fcntl flags on a file descriptor
 */

int fcntl_set(const int fd, const int flags);
int fcntl_unset(const int fd, const int flags);

/*
 * Functions for parsing strings
 */

char *string_nextword(char *str);
char *string_nullterm(char *str, const char *delim);
char *string_nullterm_char(char *str, const char delim);
int   string_isprint(const char *str, const size_t len);
int   string_isnumber(const char *str);
int   string_isfloat(const char *str);
int   string_tolong(const char *str, long *l);
char *string_lastof(char *str, const char *delim);
char *string_lastof_char(char *str, const char delim);
char *string_concat(char *str, size_t len, size_t *off, const char *fs, ...);

/* check the character to see if it is possibly hex */
int ishex(char c);
uint8_t hex2byte(char a, char b);
void byte2hex(uint8_t byte, char *a);

/*
 * Functions for doing I/O
 */

int read_wrap(const int fd, void *ptr, size_t *rc, const size_t rt);
int write_wrap(const int fd, const void *ptr, size_t *wc, const size_t wt);

#ifndef _WIN32
int mkdir_wrap(const char *path, mode_t mode);
#else
int mkdir_wrap(const char *path);
#endif

/*
 * Functions for dealing with sysctls
 */

#if !defined(__sun__) && !defined (_WIN32)
int sysctl_wrap(int *mib, u_int len, void **buf, size_t *size);
#endif

/* function for formatting an off_t */
char *offt_tostr(char *buf, size_t len, off_t off, int lz, char m);

/*
 * Function for computing an Internet checksum
 */

uint16_t in_cksum(const void *buf, const size_t len);

/* generate a 32-bit random number and return it */
int random_u32(uint32_t *r);
int random_u16(uint16_t *r);

/*
 * Functions for uuencode and uudecode.
 */
int uuencode(const uint8_t *in, const size_t ilen, uint8_t **out, size_t *olen);
void *uudecode(const char *in, const size_t len);
int uudecode_line(const char *in,const size_t ilen,uint8_t *out,size_t *olen);

/*
 * Function for swapping two bytes in a 16-bit word
 */

uint16_t byteswap16(const uint16_t word);

/*
 * Method and apparatus for parsing the output from uname(3)
 */

#define SCAMPER_OSINFO_OS_NULL     0
#define SCAMPER_OSINFO_OS_FREEBSD  1
#define SCAMPER_OSINFO_OS_OPENBSD  2
#define SCAMPER_OSINFO_OS_NETBSD   3
#define SCAMPER_OSINFO_OS_SUNOS    4
#define SCAMPER_OSINFO_OS_LINUX    5
#define SCAMPER_OSINFO_OS_DARWIN   6

typedef struct scamper_osinfo
{
  /* name of the OS, and an ID for it */
  char *os;
  int   os_id;

  /* parse the OS version string into integers */
  long *os_rel;
  int   os_rel_dots;

} scamper_osinfo_t;

scamper_osinfo_t *uname_wrap(void);
void scamper_osinfo_free(scamper_osinfo_t *osinfo);

#endif /* __UTILS_H */
