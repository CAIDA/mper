#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"

int main(int argc, char *argv[])
{
  struct stat sb;
  mode_t mode;
  uint16_t u16;
  uint32_t u32;
  uint8_t hdr[8];
  uint8_t *tmp;
  char *fixname = NULL;
  ssize_t rc;
  size_t len;
  int in, out;
  off_t off = 0;
  char offs[16];

  if(argc != 2)
    {
      goto err;
    }

  len = strlen(argv[1]);
  len += 5;
  if((fixname = malloc(len)) == NULL)
    {
      goto err;
    }
  snprintf(fixname, len, "%s.fix", argv[1]);

  /* open the file to be repaired.  get file properties. */
  if((in = open(argv[1], O_RDONLY)) < 0)
    {
      goto err;
    }
  fstat(in, &sb);
  mode = sb.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);

  /*
   * open the file that will hold the recovered data.  set it to be
   * identical in mode and owner to the file that is being repaired
   */
  if((out = open(fixname, O_WRONLY | O_TRUNC | O_CREAT | O_EXCL, mode)) < 0)
    {
      goto err;
    }
  free(fixname); fixname = NULL;
  fchown(out, sb.st_uid, sb.st_gid);

  for(;;)
    {
      /* read header in */
      rc = read(in, hdr, 8);
      if(rc == 0)
	{
	  fprintf(stderr, "%s is intact\n", argv[1]);
	  break;
	}
      if(rc < 0 || rc != 8)
	{
	  break;
	}

      /* check magic field */
      memcpy(&u16, hdr, 2); u16 = ntohs(u16);
      if(u16 != 0x1205)
	{
	  break;
	}

      /* figure out how much to read */
      memcpy(&u32, hdr+4, 4); u32 = ntohl(u32);
      if(u32 > 0)
	{
	  len = u32 + 8;
	  if((tmp = malloc(len)) == NULL)
	    {
	      goto err;
	    }

	  memcpy(tmp, hdr, 8);
	  rc = read(in, tmp+8, u32);
	  if(rc != u32)
	    break;
	}
      else
	{
	  len = 8;
	  tmp = hdr;
	}

      /* write record out */
      rc = write(out, tmp, len);
      if(rc != len)
	{
	  perror("could not write");
	  ftruncate(out, off);
	  break;
	}

      off += len;
      if(len > 8)
	free(tmp);
    }

  fprintf(stderr, "stop at %s\n", offt_tostr(offs, sizeof(offs), off, 0, 'd'));
  return 0;

 err:
  if(fixname != NULL) free(fixname);
  return -1;
}
