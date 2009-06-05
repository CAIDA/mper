/*
 * sc_attach : scamper driver to collect data by connecting to scamper on
 *             a specified port and supplying it with commands.
 *
 * Author    : Matthew Luckie.
 *
 * $Id: sc_attach.c,v 1.2 2008/11/17 20:38:17 mjl Exp $
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include <assert.h>

#include "scamper_file.h"
#include "mjl_list.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_INFILE      0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008

static uint32_t               options       = 0;
static char                  *infile        = NULL;
static unsigned int           port          = 0;
static int                    scamper_fd    = -1;
static char                  *readbuf       = NULL;
static size_t                 readbuf_len   = 0;
static char                  *outfile_name  = NULL;
static int                    outfile_fd    = -1;
static int                    data_left     = 0;
static int                    more          = 0;
static slist_t               *commands      = NULL;
static char                  *lastcommand   = NULL;

static void cleanup(void)
{
  char *command;

  if(lastcommand != NULL)
    {
      free(lastcommand);
      lastcommand = NULL;
    }

  if(commands != NULL)
    {
      while((command = slist_head_pop(commands)) != NULL)
	{
	  free(command);
	}
      slist_free(commands);
      commands = NULL;
    }

  if(outfile_fd != -1)
    {
      close(outfile_fd);
      outfile_fd = -1;
    }

  if(scamper_fd != -1)
    {
      close(scamper_fd);
      scamper_fd = -1;
    }

  if(readbuf != NULL)
    {
      free(readbuf);
      readbuf = NULL;
    }

  return;
}

static void usage(const char *argv0, uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: %s [-?] [-i infile] [-o outfile] [-p port]\n", argv0);

  if(opt_mask == 0) return;

  fprintf(stderr, "\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_attach\n");

  if(opt_mask & OPT_INFILE)
    fprintf(stderr, "     -i input command file\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int       ch;
  long      lo;
  char     *opts = "-i:o:p:?";
  char     *opt_port = NULL;
  uint32_t  mandatory = OPT_INFILE | OPT_OUTFILE | OPT_PORT;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'i':
	  options |= OPT_INFILE;
	  infile = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case '?':
	default:
	  usage(argv[0], 0xffffffff);
	  return -1;
	}
    }

  /* these options are mandatory */
  if((options & mandatory) != mandatory)
    {
      if(options == 0) usage(argv[0], 0);
      else             usage(argv[0], mandatory);
      return -1;
    }

  /* find out which port scamper can be found listening on */
  if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
    {
      usage(argv[0], OPT_PORT);
      return -1;
    }
  port = lo;

  return 0;
}

/*
 * do_infile
 *
 * read the contents of the infile in one hit.
 */
static int do_infile(void)
{
  struct stat sb;
  size_t off, start;
  char *readbuf = NULL;
  char *command;
  int fd = -1;

  if((commands = slist_alloc()) == NULL)
    {
      return -1;
    }

  if((fd = open(infile, O_RDONLY)) < 0)
    {
      fprintf(stderr, "could not open %s\n", infile);
      goto err;
    }

  if(fstat(fd, &sb) != 0)
    {
      fprintf(stderr, "could not fstat %s\n", infile);
      goto err;
    }
  if(sb.st_size == 0)
    {
      fprintf(stderr, "zero length file %s\n", infile);
      goto err;
    }
  if((readbuf = malloc(sb.st_size+1)) == NULL)
    {
      fprintf(stderr, "could not malloc %d bytes to read %s\n",
	      (int)sb.st_size, infile);
      goto err;
    }
  if(read_wrap(fd, readbuf, NULL, sb.st_size) != 0)
    {
      fprintf(stderr, "could not read %d bytes from %s\n",
	      (int)sb.st_size, infile);
      goto err;
    }
  readbuf[sb.st_size] = '\0';
  close(fd); fd = -1;

  /* parse the contents of the file */
  start = 0; off = 0;
  while(off < sb.st_size+1)
    {
      if(readbuf[off] == '\n' || readbuf[off] == '\0')
	{
	  if(start == off || readbuf[start] == '#')
	    {
	      start = ++off;
	      continue;
	    }

	  readbuf[off] = '\0';

	  if((command = malloc(off-start+2)) == NULL)
	    {
	      fprintf(stderr, "could not malloc command\n");
	      goto err;
	    }
	  memcpy(command, readbuf+start, off-start);
	  command[off-start+0] = '\n';
	  command[off-start+1] = '\0';

	  if(slist_tail_push(commands, command) == NULL)
	    {
	      fprintf(stderr, "could not push command onto list\n");
	      free(command);
	      goto err;
	    }

	  start = ++off;
	}
      else
	{
	  ++off;
	}
    }

  free(readbuf);
  return 0;

 err:
  if(readbuf != NULL) free(readbuf);
  if(fd != -1) close(fd);
  return -1;
}

/*
 * do_files
 *
 * open a file to send the binary warts data file to.
 */
static int do_files(void)
{
  mode_t mode   = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  int    flags  = O_WRONLY | O_CREAT | O_TRUNC;

  if((outfile_fd = open(outfile_name, flags, mode)) == -1)
    {
      return -1;
    }

  return 0;
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
  struct sockaddr_in sin;
  struct in_addr in;

  inet_aton("127.0.0.1", &in);
  sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);

  if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      fprintf(stderr, "could not allocate new socket\n");
      return -1;
    }

  if(connect(scamper_fd, (const struct sockaddr *)&sin, sizeof(sin)) != 0)
    {
      fprintf(stderr, "could not connect to scamper process\n");
      return -1;
    }

  return 0;
}

static int do_method(void)
{
  struct timeval tv;
  char *command;

  if(slist_count(commands) <= 0)
    return 0;

  gettimeofday_wrap(&tv);
  command = slist_head_pop(commands);
  write_wrap(scamper_fd, command, NULL, strlen(command));
  more--;
  printf("%ld: %s", (long int)tv.tv_sec, command);

  if(lastcommand != NULL)
    free(lastcommand);
  lastcommand = command;

  if(slist_count(commands) == 0)
    write_wrap(scamper_fd, "done\n", NULL, 5);

  return 0;
}

/*
 * do_scamperread
 *
 * the fd for the scamper process is marked as readable, so do a read
 * on it.
 */
static int do_scamperread(void)
{
  ssize_t rc;
  uint8_t uu[64];
  char   *ptr, *head;
  char    buf[512];
  void   *tmp;
  long    l;
  size_t  i, uus, linelen;

  if((rc = read(scamper_fd, buf, sizeof(buf))) > 0)
    {
      if(readbuf_len == 0)
	{
	  if((readbuf = memdup(buf, rc)) == NULL)
	    {
	      return -1;
	    }
	  readbuf_len = rc;
	}
      else
	{
	  if((tmp = realloc(readbuf, readbuf_len + rc)) != NULL)
	    {
	      readbuf = tmp;
	      memcpy(readbuf+readbuf_len, buf, rc);
	      readbuf_len += rc;
	    }
	  else return -1;
	}
    }
  else if(rc == 0)
    {
      close(scamper_fd);
      scamper_fd = -1;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }
  else
    {
      fprintf(stderr, "could not read: errno %d\n", errno);
      return -1;
    }

  /* process whatever is in the readbuf */
  if(readbuf_len == 0)
    {
      goto done;
    }

  head = readbuf;
  for(i=0; i<readbuf_len; i++)
    {
      if(readbuf[i] == '\n')
	{
	  /* skip empty lines */
	  if(head == &readbuf[i])
	    {
	      head = &readbuf[i+1];
	      continue;
	    }

	  /* calculate the length of the line, excluding newline */
	  linelen = &readbuf[i] - head;

	  /* if currently decoding data, then pass it to uudecode */
	  if(data_left > 0)
	    {
	      uus = sizeof(uu);
	      if(uudecode_line(head, linelen, uu, &uus) != 0)
		{
		  fprintf(stderr, "could not uudecode_line\n");
		  goto err;
		}

	      if(uus != 0)
		{
		  write_wrap(outfile_fd, uu, NULL, uus);
		}

	      data_left -= (linelen + 1);
	    }
	  /* if the scamper process is asking for more tasks, give it more */
	  else if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
	    {
	      more++;
	      do_method();
	    }
	  /* new piece of data */
	  else if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
	    {
	      l = strtol(head+5, &ptr, 10);
	      if(*ptr != '\n' || l < 1)
		{
		  head[linelen] = '\0';
		  fprintf(stderr, "could not parse %s\n", head);
		  goto err;
		}

	      data_left = l;
	    }
	  /* feedback letting us know that the command was accepted */
	  else if(linelen >= 2 && strncasecmp(head, "OK", 2) == 0)
	    {
	      /* err, nothing to do */
	    }
	  /* feedback letting us know that the command was not accepted */
	  else if(linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
	    {
	      if(lastcommand != NULL)
		{
		  fprintf(stderr, "command not accepted: %s", lastcommand);
		  more++;
		}
	      else
		{
		  goto err;
		}
	    }
	  else
	    {
	      head[linelen] = '\0';
	      fprintf(stderr, "unknown response '%s'\n", head);
	      goto err;
	    }

	  head = &readbuf[i+1];
	}
    }

  if(head != &readbuf[readbuf_len])
    {
      readbuf_len = &readbuf[readbuf_len] - head;
      ptr = memdup(head, readbuf_len);
      free(readbuf);
      readbuf = ptr;
    }
  else
    {
      readbuf_len = 0;
      free(readbuf);
      readbuf = NULL;
    }

 done:
  return 0;

 err:
  return -1;
}

int main(int argc, char *argv[])
{
  fd_set rfds;
  int nfds;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    {
      return -1;
    }

  /*
   * read the list of addresses in the address list file.
   */
  if(do_infile() != 0)
    {
      return -1;
    }

  /*
   * connect to the scamper process
   */
  if(do_scamperconnect() != 0)
    {
      return -1;
    }

  /*
   * sort out the files that we'll be working with.
   */
  if(do_files() != 0)
    {
      return -1;
    }

  /* attach */
  if(write_wrap(scamper_fd, "attach\n", NULL, 7) != 0)
    {
      fprintf(stderr, "could not attach to scamper process\n");
      return -1;
    }

  for(;;)
    {
      nfds = 0;
      FD_ZERO(&rfds);

      if(scamper_fd < 0)
	{
	  break;
	}

      if(scamper_fd >= 0)
	{
	  FD_SET(scamper_fd, &rfds);
	  if(nfds < scamper_fd) nfds = scamper_fd;
	}

      if(more > 0)
	{
	  do_method();
	}

      if(select(nfds+1, &rfds, NULL, NULL, NULL) < 0)
	{
	  if(errno == EINTR) continue;
	  break;
	}

      if(FD_ISSET(scamper_fd, &rfds))
	{
	  if(do_scamperread() != 0)
	    return -1;
	}
    }

  return 0;
}
