/* name_to_handle_at support probe: exits 0 iff the filesystem at argv[1]
 * can encode file handles (the fanotify-FID prerequisite). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <path>\n", argv[0]); return 2; }
  struct file_handle *fh = malloc(sizeof(*fh) + MAX_HANDLE_SZ);
  fh->handle_bytes = MAX_HANDLE_SZ;
  int mount_id = 0;
  if (name_to_handle_at(AT_FDCWD, argv[1], fh, &mount_id, 0) != 0) {
    fprintf(stderr, "name_to_handle_at(%s): %s\n", argv[1], strerror(errno));
    return 1;
  }
  printf("handle ok: bytes=%u type=%d mount_id=%d\n",
         fh->handle_bytes, fh->handle_type, mount_id);
  return 0;
}
