/* fanotify golden-set probe (design §5 rows 2-4): exits 0 iff
 * fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME | FAN_REPORT_TARGET_FID)
 * and fanotify_mark(FAN_MARK_FILESYSTEM, ... | FAN_CREATE | FAN_RENAME) both
 * succeed on argv[1] — the kernel-5.17 feature set the Auto table requires.
 * Distinguishes EPERM (no CAP_SYS_ADMIN: exit 3) from EINVAL/EOPNOTSUPP
 * (kernel/filesystem too old: exit 4). */
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#ifndef FAN_REPORT_TARGET_FID
#define FAN_REPORT_TARGET_FID 0x00001000
#endif
#ifndef FAN_RENAME
#define FAN_RENAME 0x10000000
#endif

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <path>\n", argv[0]); return 2; }
  /* FAN_REPORT_TARGET_FID requires FAN_REPORT_FID in addition to
   * FAN_REPORT_DFID_NAME — the kernel's composite FAN_REPORT_DFID_NAME_TARGET.
   * (Validation finding: the design §4.1 list omits FAN_REPORT_FID; the L4
   * probe and init must use the full composite or EINVAL.) */
  int fd = fanotify_init(
      FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DFID_NAME |
          FAN_REPORT_TARGET_FID | FAN_CLOEXEC,
      O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "fanotify_init: %s\n", strerror(errno));
    return errno == EPERM ? 3 : 4;
  }
  if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                    FAN_CREATE | FAN_DELETE | FAN_MODIFY | FAN_ATTRIB |
                    FAN_RENAME | FAN_DELETE_SELF | FAN_MOVE_SELF | FAN_ONDIR,
                    AT_FDCWD, argv[1]) != 0) {
    fprintf(stderr, "fanotify_mark: %s\n", strerror(errno));
    close(fd);
    return errno == EPERM ? 3 : 4;
  }
  printf("fanotify golden set ok on %s\n", argv[1]);
  close(fd);
  return 0;
}
