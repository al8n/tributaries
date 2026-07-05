use std::path::Path;

use tributary_proto::WatchId;

use super::{
  attribute_events, fs_type_is_remote,
  inotify::{
    decode::{IN_CREATE, IN_IGNORED, IN_ISDIR, IN_Q_OVERFLOW, InotifyMask, RawInotifyEvent},
    table::WdTable,
  },
  parse_mountinfo,
};

fn watch(n: u64) -> WatchId {
  WatchId::new(core::num::NonZeroU64::new(n).unwrap())
}

fn event(wd: i32, mask: u32, name: Option<&[u8]>) -> RawInotifyEvent {
  RawInotifyEvent {
    wd,
    mask: InotifyMask(mask),
    cookie: 0,
    name: name.map(<[u8]>::to_vec),
  }
}

#[test]
fn attribution_fans_out_per_alias() {
  let mut table = WdTable::new();
  table.register(3, watch(1));
  table.alias(3, watch(2));

  let batch = attribute_events(vec![event(3, IN_CREATE | IN_ISDIR, Some(b"d"))], &mut table);
  assert!(!batch.lost);
  assert_eq!(batch.events.len(), 1);
  let (anchors, raw) = batch.events[0].as_inotify().unwrap();
  assert_eq!(anchors, &[watch(1), watch(2)]);
  assert_eq!(raw.name.as_deref(), Some(b"d".as_slice()));
}

#[test]
fn overflow_sentinel_marks_lost_and_is_not_forwarded() {
  let mut table = WdTable::new();
  table.register(3, watch(1));

  let batch = attribute_events(
    vec![
      event(-1, IN_Q_OVERFLOW, None),
      event(3, IN_CREATE, Some(b"x")),
    ],
    &mut table,
  );
  assert!(batch.lost);
  // ATTRIBUTION drops only the sentinel itself and still attributes the following
  // record — that is attribution's contract. The reader then holds the loss as an
  // ordering barrier and drops the WHOLE attributed batch behind the `Overflow`
  // (see `forward_attributed`), so this post-sentinel event is attributed here but
  // never forwarded.
  assert_eq!(
    batch.events.len(),
    1,
    "the sentinel itself is not an event (the reader drops the rest behind the barrier)"
  );
}

#[test]
fn ignored_consumes_the_entry_and_attributes_live_anchors() {
  let mut table = WdTable::new();
  table.register(3, watch(1));

  let batch = attribute_events(vec![event(3, IN_IGNORED, None)], &mut table);
  assert_eq!(
    batch.events.len(),
    1,
    "kernel-initiated teardown is forwarded"
  );
  assert!(!table.contains(3), "IGNORED is the authoritative erase");

  // The next IGNORED-less record on the erased wd attributes to nothing.
  let batch = attribute_events(vec![event(3, IN_CREATE, Some(b"x"))], &mut table);
  assert!(batch.events.is_empty());
  assert!(!batch.lost, "records for dropped watches are not loss");
}

#[test]
fn draining_wd_attributes_nothing_until_ignored() {
  let mut table = WdTable::new();
  table.register(3, watch(1));
  let _ = table.begin_drain(watch(1));

  let batch = attribute_events(vec![event(3, IN_CREATE, Some(b"x"))], &mut table);
  assert!(batch.events.is_empty());

  // The self-induced teardown's IGNORED erases silently (anchors drained).
  let batch = attribute_events(vec![event(3, IN_IGNORED, None)], &mut table);
  assert!(batch.events.is_empty());
  assert!(!table.contains(3));
}

#[test]
fn mountinfo_extracts_mounts_strictly_under_root() {
  let content = "\
36 25 0:32 / /mnt/a rw,relatime shared:1 - tmpfs tmpfs rw
37 25 0:33 / /mnt/a/inner rw,relatime shared:2 - ext4 /dev/loop0 rw
38 25 0:34 / /mnt/b rw,relatime shared:3 - tmpfs tmpfs rw
39 25 0:35 / / rw,relatime shared:4 - ext4 /dev/root rw
malformed line
40 25 0:36 /
";
  let mounts = parse_mountinfo(content, Path::new("/mnt/a"));
  assert_eq!(mounts, vec![std::path::PathBuf::from("/mnt/a/inner")]);
}

#[test]
fn mountinfo_unescapes_octal_fields() {
  let content = "36 25 0:32 / /mnt/with\\040space rw shared:1 - tmpfs tmpfs rw\n";
  let mounts = parse_mountinfo(content, Path::new("/mnt"));
  assert_eq!(mounts, vec![std::path::PathBuf::from("/mnt/with space")]);
}

/// The shared locality gate's decision function — the pure kernel the linux
/// spawn dispatcher runs ONCE before backend selection (so Auto, forced
/// Fanotify, and forced Inotify all refuse a denied magic identically, and no
/// denied root ever reaches the fanotify probe or its spawn). Every denylisted
/// magic must refuse; representative local filesystems must pass.
#[test]
fn remote_fs_magics_are_refused_and_local_ones_pass() {
  // The whole denylist (each `REMOTE_FS_MAGICS` entry) must be refused — a gap
  // here is a filesystem that would go live blind to other hosts' writes.
  for (magic, name) in [
    (0x6969_i64, "NFS"),
    (0x517B, "SMB"),
    (0xFE53_4D42, "SMB2"),
    (0xFF53_4D42, "CIFS"),
    (0x6573_5546, "FUSE"),
    (0x0102_1997, "9P"),
    (0x5346_414F, "AFS"),
    (0x7375_7245, "CODA"),
    (0x00C3_6400, "CEPH"),
    (0x564C, "NCP"),
  ] {
    assert!(fs_type_is_remote(magic), "{name} must be refused");
  }
  // Representative local/native filesystems must pass unchanged.
  assert!(!fs_type_is_remote(0xEF53), "ext4 is local");
  assert!(!fs_type_is_remote(0x0102_1994), "tmpfs is local");
  assert!(!fs_type_is_remote(0x9123_683E), "btrfs is local");
  assert!(
    !fs_type_is_remote(0x794C_7630),
    "overlayfs is local (a probe refusal, not a locality one)"
  );
}

/// The spawn dispatcher's root pin and the object-grounded identity reads it
/// hands to both backends. These exercise real syscalls, so they run only on a
/// Linux host (the container `unit` suite); the pure decode/parse cells above
/// compile and run everywhere.
#[cfg(all(target_os = "linux", not(miri)))]
mod pin {
  use std::os::unix::fs::MetadataExt;

  use super::super::{ancestor_identities, pin_root, pin_root_walk, root_is_remote};
  use crate::os::SourceError;

  /// A fresh empty scratch directory under `TMPDIR`, canonicalized so the pin's
  /// `RESOLVE_NO_SYMLINKS` open matches a symlink-free path.
  fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir()
      .canonicalize()
      .expect("canonicalize temp dir")
      .join(format!(
        "tributary-fs-pin-{}-{}-{}",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
      ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  /// The pin over a real directory succeeds and `fstat` on it reads the SAME
  /// `(dev, ino)` a path `metadata` sees — the object-grounded identity the
  /// dispatcher hands to both backends is the root's true identity.
  #[test]
  fn pin_root_grounds_identity_on_the_true_object() {
    let dir = scratch("ident");
    let fd = pin_root(&dir).expect("pinning a real directory succeeds");
    let stat = rustix::fs::fstat(&fd).expect("fstat the pin");
    let meta = std::fs::metadata(&dir).expect("stat the path");
    assert_eq!(stat.st_dev, meta.dev(), "the pin's device is the root's");
    assert_eq!(stat.st_ino, meta.ino(), "the pin's inode is the root's");
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A root that vanished before the pin is a typed `RootUnavailable` race — the
  /// dispatcher never commits a source on a gone root.
  #[test]
  fn pin_root_on_a_missing_path_is_typed() {
    let dir = scratch("missing");
    let _ = std::fs::remove_dir_all(&dir);
    let err = pin_root(&dir).expect_err("a missing root cannot be pinned");
    assert!(
      matches!(err, SourceError::RootUnavailable { .. }),
      "a vanished root is a typed RootUnavailable race, not a panic: {err:?}"
    );
  }

  /// A root retargeted to a NON-DIRECTORY fails the pin (`O_DIRECTORY` → ENOTDIR)
  /// as a typed race — a recursive stream is never committed on a file.
  #[test]
  fn pin_root_on_a_non_directory_is_typed() {
    let dir = scratch("file-parent");
    let file = dir.join("f");
    std::fs::write(&file, b"x").expect("create a file");
    let err = pin_root(&file).expect_err("a non-directory root cannot be pinned");
    assert!(
      matches!(err, SourceError::RootUnavailable { .. }),
      "a non-directory root is a typed refusal: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The pin's whole point: a SYMLINK at the root path is refused by
  /// `RESOLVE_NO_SYMLINKS` (ELOOP) rather than silently followed to its target. A
  /// symlink dropped at the canonical root after canonicalization can no longer
  /// redirect the pin (and thus the gate, the mark, and the identity) to another
  /// object; it fails typed instead.
  #[test]
  fn pin_root_refuses_a_symlink_at_the_root() {
    let dir = scratch("symlink");
    let real = dir.join("real");
    std::fs::create_dir_all(&real).expect("create the real dir");
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("create a symlink to it");
    let err = pin_root(&link).expect_err("a symlink at the root must not be followed by the pin");
    assert!(
      matches!(err, SourceError::RootUnavailable { .. }),
      "RESOLVE_NO_SYMLINKS refuses the symlinked root typed, never follows it: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The locality gate reads the PINNED fd: a local temp filesystem is not
  /// refused. (The denylist itself is row-tested pure above; this asserts the
  /// fd-relative read path wires through to the same decision.)
  #[test]
  fn root_is_remote_reads_the_pin_and_passes_local() {
    let dir = scratch("local");
    let fd = pin_root(&dir).expect("pin the local dir");
    assert!(
      !root_is_remote(&fd, &dir).expect("fstatfs the pin"),
      "a local temp filesystem passes the fd-relative locality gate"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The ancestors are object-grounded (`O_PATH` + `RESOLVE_NO_SYMLINKS` + fstat)
  /// and reproduce the parent chain's true identities — the containment evidence
  /// disjointness decides on, with no path stat left to a swap.
  #[test]
  fn ancestor_identities_reproduce_the_parent_chain() {
    let base = scratch("anc");
    let nested = base.join("a/b");
    std::fs::create_dir_all(&nested).expect("create a nested dir");
    let ancestors = ancestor_identities(&nested).expect("pin and stat the ancestor chain");
    // Each strict ancestor's identity matches a path stat of that ancestor.
    for (ancestor, identity) in nested.ancestors().skip(1).zip(&ancestors) {
      let meta = std::fs::metadata(ancestor).expect("stat the ancestor path");
      assert_eq!(identity.dev(), meta.dev(), "ancestor device matches");
      assert_eq!(identity.ino(), meta.ino(), "ancestor inode matches");
    }
    assert_eq!(
      ancestors.len(),
      nested.ancestors().skip(1).count(),
      "every strict ancestor is pinned and identified"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// A symlink swapped in for an ANCESTOR component is refused
  /// (`RESOLVE_NO_SYMLINKS` → ELOOP) rather than recording the swapped-in
  /// object's identity — the ancestor chain cannot be corrupted by a mid-path
  /// symlink swap.
  #[test]
  fn ancestor_identities_refuse_a_symlinked_ancestor() {
    let base = scratch("anc-symlink");
    let real = base.join("real");
    std::fs::create_dir_all(real.join("leaf")).expect("create real/leaf");
    let link = base.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink link -> real");
    // `base/link/leaf` reaches a real directory THROUGH a symlinked ancestor
    // (`link`). The pin over `leaf` would succeed via canonicalize, but walking
    // the ancestors of this UN-canonicalized path must refuse the symlink hop.
    let via_link = link.join("leaf");
    let err = ancestor_identities(&via_link)
      .expect_err("a symlinked ancestor must be refused, not silently identified");
    assert!(
      matches!(err, SourceError::RootUnavailable { .. }),
      "a symlink swapped in for an ancestor fails the no-symlink open typed: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// The pre-`openat2` fallback pin (`pin_root_walk`, the pre-5.6 floor path)
  /// pins the SAME object the `openat2` fast path pins: the component walk and
  /// the one-shot resolve land on one identity. This is the direct-row coverage
  /// the finding calls for — the `ENOSYS` routing itself needs a pre-5.6 kernel
  /// to exercise, so the walk is tested on its own here, and `pin_root` is proven
  /// to agree with it.
  #[test]
  fn pin_root_walk_pins_the_same_object_as_openat2() {
    let base = scratch("walk-ident");
    let nested = base.join("a/b/c");
    std::fs::create_dir_all(&nested).expect("create a nested dir");

    let fast = pin_root(&nested).expect("the openat2 fast path pins");
    let walked = pin_root_walk(&nested).expect("the component walk pins");
    let fast_stat = rustix::fs::fstat(&fast).expect("fstat the fast pin");
    let walked_stat = rustix::fs::fstat(&walked).expect("fstat the walked pin");
    assert_eq!(
      (fast_stat.st_dev, fast_stat.st_ino),
      (walked_stat.st_dev, walked_stat.st_ino),
      "the component walk and openat2 pin the identical object"
    );
    // And the walked pin's identity is the true object's.
    let meta = std::fs::metadata(&nested).expect("stat the path");
    assert_eq!(
      walked_stat.st_dev,
      meta.dev(),
      "walked device is the root's"
    );
    assert_eq!(walked_stat.st_ino, meta.ino(), "walked inode is the root's");
    let _ = std::fs::remove_dir_all(&base);
  }

  /// A symlink at ANY component of the walked path is refused (`ELOOP`) — the
  /// per-hop `O_NOFOLLOW` rebuilds the fast path's whole-path no-symlink
  /// guarantee, so the fallback can never redirect the pin to a symlink's target.
  #[test]
  fn pin_root_walk_refuses_a_symlink_component() {
    let base = scratch("walk-symlink");
    let real = base.join("real");
    std::fs::create_dir_all(real.join("leaf")).expect("create real/leaf");
    let link = base.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink link -> real");
    // `base/link/leaf` reaches a real directory THROUGH a symlinked component.
    let via_link = link.join("leaf");
    let err = pin_root_walk(&via_link)
      .expect_err("a symlink component must be refused, not followed to its target");
    assert!(
      matches!(err, SourceError::RootUnavailable { .. }),
      "a symlink component fails the per-hop no-symlink open typed: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// A missing final component is a typed `RootUnavailable` (`ENOENT`) — the walk
  /// surfaces a vanished root exactly like the fast path, never a panic.
  #[test]
  fn pin_root_walk_on_a_missing_path_is_typed() {
    let base = scratch("walk-missing");
    let gone = base.join("nope");
    let err = pin_root_walk(&gone).expect_err("a missing component cannot be walked");
    assert!(
      matches!(err, SourceError::RootUnavailable { .. }),
      "a vanished component is a typed RootUnavailable race: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// A component swapped for a NON-DIRECTORY fails the walk (`O_DIRECTORY` →
  /// `ENOTDIR`) typed — the fallback never pins through a file, matching the fast
  /// path's `O_DIRECTORY` refusal.
  #[test]
  fn pin_root_walk_refuses_a_non_directory_component() {
    let base = scratch("walk-file");
    let file = base.join("f");
    std::fs::write(&file, b"x").expect("create a file");
    // Walking "f/child" hits a file where a directory must be.
    let through_file = file.join("child");
    let err = pin_root_walk(&through_file).expect_err("a non-directory component cannot be walked");
    assert!(
      matches!(err, SourceError::RootUnavailable { .. }),
      "a non-directory component is a typed refusal: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }
}
