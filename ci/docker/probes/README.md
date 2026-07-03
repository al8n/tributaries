# Capability probes

Validation-only C helpers (the image's base gcc compiles them ad hoc; they are
not built into the image):

- `probe_handle.c` — does `name_to_handle_at` work on a mount? Prints the
  handle size and type (ext4 and btrfs answer differently — the fsid-quirk
  fixture the fanotify suites rely on).
- `probe_fanotify.c` — does the fanotify golden feature set
  (`FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DFID_NAME |
  FAN_REPORT_TARGET_FID`, then a `FAN_MARK_FILESYSTEM` mark with `FAN_RENAME`)
  initialize on this kernel/filesystem? Exit 0 = full support; exit 3 = the
  mark was refused (`EPERM` without `CAP_SYS_ADMIN` — the `Backend::Auto`
  fallback row). Note the composite: `FAN_REPORT_TARGET_FID` without
  `FAN_REPORT_FID` is `EINVAL` even fully privileged.
