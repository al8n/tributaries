use std::path::Path;

use tributary_proto::WatchId;

use super::{
  attribute_events, excluded, fs_type_is_local, fs_type_is_remote,
  inotify::{
    decode::{IN_CREATE, IN_IGNORED, IN_ISDIR, IN_Q_OVERFLOW, InotifyMask, RawInotifyEvent},
    table::WdTable,
  },
  locality_refusal, parse_mountinfo,
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

/// The exclusion predicate both Linux backends' fences read.
///
/// It is deliberately the SAME predicate the sync-cookie birth refusal uses, so a
/// directory `sync_root` refuses to write into is exactly a directory the backend
/// refuses to report from. These rows pin the properties that matter at a walk
/// fence: component-wise containment (not a byte prefix), the exclusion directory
/// itself counted as excluded, and the empty set excluding nothing.
#[test]
fn the_exclusion_predicate_matches_the_subtree_and_nothing_beside_it() {
  let exclusions = vec![std::path::PathBuf::from("/root/cache")];

  assert!(
    excluded(&exclusions, Path::new("/root/cache")),
    "the exclusion directory itself is excluded"
  );
  assert!(
    excluded(&exclusions, Path::new("/root/cache/deep/leaf")),
    "everything under the exclusion is excluded"
  );
  assert!(
    !excluded(&exclusions, Path::new("/root/cachex")),
    "a SIBLING sharing a byte prefix is not under the exclusion — containment is \
     component-wise, or `/root/cachex` would silently vanish"
  );
  assert!(
    !excluded(&exclusions, Path::new("/root/other")),
    "an unrelated sibling is reported"
  );
  assert!(
    !excluded(&exclusions, Path::new("/root")),
    "the ancestor of an exclusion is not excluded"
  );
  assert!(
    !excluded(&[], Path::new("/root/cache")),
    "no exclusions excludes nothing"
  );
}

/// The shared locality gate's decision function — the pure kernel the linux
/// spawn dispatcher runs ONCE before backend selection (so Auto, forced
/// Fanotify, and forced Inotify all refuse identically, and no refused root ever
/// reaches the fanotify probe or its spawn). Every known-remote magic must
/// refuse; the local filesystems the suites and shipped hosts actually run on
/// must pass.
#[test]
fn remote_fs_magics_are_refused_and_local_ones_pass() {
  // Each `REMOTE_FS_MAGICS` entry must be refused — one going live is a source
  // blind to other hosts' (or peer nodes') writes.
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
    (0x0116_1970, "GFS2"),
    (0x7461_636F, "OCFS2"),
  ] {
    assert!(
      locality_refusal(magic, Path::new("/root")).is_some(),
      "{name} must be refused"
    );
    assert!(!fs_type_is_local(magic), "{name} is not local");
  }
  // Representative local/native filesystems must pass unchanged.
  for (magic, name) in [
    (0xEF53_i64, "ext4"),
    (0x0102_1994, "tmpfs"),
    (0x9123_683E, "btrfs"),
    (0x5846_5342, "xfs"),
    (
      0x794C_7630,
      "overlayfs (a probe refusal, not a locality one)",
    ),
  ] {
    assert!(
      locality_refusal(magic, Path::new("/root")).is_none(),
      "{name} must pass the locality gate"
    );
  }
}

/// The gate FAILS CLOSED: a filesystem on neither list is refused, not admitted.
///
/// This is the whole point of the allowlist shape. A denylist answers "is this
/// one of the ten distributed filesystems someone enumerated", so every
/// filesystem nobody thought about — an out-of-tree module, a magic minted after
/// this list was written, a stacking filesystem over a remote backing store —
/// goes live claiming coverage it cannot prove. The unknown magic below is
/// deliberately not in either list.
#[test]
fn an_unknown_filesystem_magic_is_refused_rather_than_admitted() {
  const UNKNOWN: i64 = 0x1234_5678;
  assert!(!fs_type_is_local(UNKNOWN), "the magic is not allowlisted");
  assert!(
    !fs_type_is_remote(UNKNOWN),
    "nor is it on the known-remote list — this is the fail-open case"
  );
  let refusal = locality_refusal(UNKNOWN, Path::new("/root"))
    .expect("an unrecognized filesystem is refused, never admitted");
  match refusal {
    crate::os::SourceError::RootUnavailable { root, source } => {
      assert_eq!(root, Path::new("/root"));
      assert_eq!(
        source.kind(),
        std::io::ErrorKind::Unsupported,
        "the refusal matches the macOS `!MNT_LOCAL` shape: RootUnavailable + Unsupported"
      );
    }
    other => panic!("an unrecognized filesystem must refuse RootUnavailable: {other:?}"),
  }
}

/// The message selector is a message selector only: a known-remote magic and an
/// unrecognized one both refuse, and both refuse the SAME way — only the text
/// differs. A reader who mistakes `fs_type_is_remote` for the verdict would
/// reintroduce the fail-open default.
#[test]
fn the_remote_list_only_names_the_refusal_it_never_grants_one() {
  let named = locality_refusal(0x6969, Path::new("/root")).expect("NFS refuses");
  let unknown = locality_refusal(0x1234_5678, Path::new("/root")).expect("an unknown fs refuses");
  for refusal in [named, unknown] {
    let crate::os::SourceError::RootUnavailable { source, .. } = refusal else {
      panic!("both refusals are RootUnavailable");
    };
    assert_eq!(source.kind(), std::io::ErrorKind::Unsupported);
  }
}

/// The spawn dispatcher's root pin and the object-grounded identity reads it
/// hands to both backends. These exercise real syscalls, so they run only on a
/// Linux host (the container `unit` suite); the pure decode/parse cells above
/// compile and run everywhere.
#[cfg(all(target_os = "linux", not(miri)))]
mod pin {
  use std::os::{fd::AsFd, unix::fs::MetadataExt};

  use rustix::fs::OFlags;

  use super::super::{
    ancestor_identities, locality_refusal, mnt_id_from_mask, open_no_symlinks, pin_root,
    require_statx, root_fs_type, root_mount_id, statx_gate_error, statx_unavailable,
  };
  use crate::os::{RootIdentity, SourceError};

  /// The `pin_root` fast path's final-component flags — `O_RDONLY | O_DIRECTORY`,
  /// the shape its `ENOSYS` walk must reproduce.
  fn pin_final_flags() -> OFlags {
    OFlags::RDONLY
      .union(OFlags::DIRECTORY)
      .union(OFlags::NOFOLLOW)
      .union(OFlags::CLOEXEC)
  }

  /// The `ancestor_identities` final-component flags — `O_PATH | O_DIRECTORY`,
  /// search permission only.
  fn ancestor_final_flags() -> OFlags {
    OFlags::PATH
      .union(OFlags::NOFOLLOW)
      .union(OFlags::DIRECTORY)
      .union(OFlags::CLOEXEC)
  }

  /// The `(dev, ino)` a path currently resolves to — what a caller's pin would
  /// have captured.
  fn identity_of(path: &std::path::Path) -> RootIdentity {
    let meta = std::fs::metadata(path).expect("stat the path");
    RootIdentity::new(meta.dev(), meta.ino().into())
  }

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

  /// The locality gate reads the PINNED fd: the suites' own temp filesystem is
  /// not refused. (The allowlist itself is row-tested pure above; this asserts
  /// the fd-relative read path wires through to the same decision, and that the
  /// filesystem the container suites actually run on is allowlisted.)
  #[test]
  fn the_locality_gate_reads_the_pin_and_passes_the_suites_own_filesystem() {
    let dir = scratch("local");
    let fd = pin_root(&dir).expect("pin the local dir");
    let f_type = root_fs_type(&fd, &dir).expect("fstatfs the pin");
    assert!(
      locality_refusal(f_type, &dir).is_none(),
      "the suites' temp filesystem (magic {f_type:#x}) must be allowlisted, or every \
       Linux spawn in this repository refuses"
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
    let ancestors =
      ancestor_identities(&nested, identity_of(&nested)).expect("pin and stat the ancestor chain");
    // Each strict ancestor's identity matches a path stat of that ancestor.
    for (ancestor, identity) in nested.ancestors().skip(1).zip(&ancestors) {
      let meta = std::fs::metadata(ancestor).expect("stat the ancestor path");
      assert_eq!(identity.dev(), meta.dev(), "ancestor device matches");
      assert_eq!(
        identity.ino(),
        u128::from(meta.ino()),
        "ancestor inode matches"
      );
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
    // The expected identity is the object the path DOES reach when symlinks are
    // followed, so the refusal below is provably the no-symlink hop firing and not
    // the closing identity equality.
    let err = ancestor_identities(&via_link, identity_of(&via_link))
      .expect_err("a symlinked ancestor must be refused, not silently identified");
    assert!(
      matches!(err, SourceError::RootUnavailable { .. }),
      "a symlink swapped in for an ancestor fails the no-symlink open typed: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// The pre-`openat2` fallback walk (`open_no_symlinks`, the pre-5.6 floor path)
  /// pins the SAME object the `openat2` fast path pins, under BOTH callers' final
  /// flags: the component walk and the one-shot resolve land on one identity
  /// whether the final open is `pin_root`'s `O_RDONLY` or `ancestor_identities`'
  /// `O_PATH`. The `ENOSYS` routing itself needs a pre-5.6 kernel to exercise, so the
  /// walk is tested on its own here and `pin_root` is proven to agree with it.
  #[test]
  fn open_no_symlinks_pins_the_same_object_as_openat2() {
    let base = scratch("walk-ident");
    let nested = base.join("a/b/c");
    std::fs::create_dir_all(&nested).expect("create a nested dir");

    let fast = pin_root(&nested).expect("the openat2 fast path pins");
    let fast_stat = rustix::fs::fstat(&fast).expect("fstat the fast pin");
    let meta = std::fs::metadata(&nested).expect("stat the path");

    // Both final-flag shapes pin the identical object the fast path did.
    for (label, flags) in [
      ("O_RDONLY (pin_root)", pin_final_flags()),
      ("O_PATH (ancestor)", ancestor_final_flags()),
    ] {
      let walked = open_no_symlinks(&nested, flags).expect("the component walk pins");
      let walked_stat = rustix::fs::fstat(&walked).expect("fstat the walked pin");
      assert_eq!(
        (fast_stat.st_dev, fast_stat.st_ino),
        (walked_stat.st_dev, walked_stat.st_ino),
        "{label}: the component walk and openat2 pin the identical object"
      );
      assert_eq!(
        walked_stat.st_dev,
        meta.dev(),
        "{label}: walked device is the root's"
      );
      assert_eq!(
        walked_stat.st_ino,
        meta.ino(),
        "{label}: walked inode is the root's"
      );
    }
    let _ = std::fs::remove_dir_all(&base);
  }

  /// A symlink at ANY component of the walked path is refused — the per-hop
  /// `O_NOFOLLOW` rebuilds the fast path's whole-path no-symlink guarantee, so the
  /// fallback can never redirect the pin to a symlink's target. Whether the symlink
  /// is an INTERMEDIATE hop or the FINAL component, the `O_NOFOLLOW | O_DIRECTORY`
  /// open declines to traverse it: `O_PATH | O_NOFOLLOW` opens the link object
  /// itself and `O_DIRECTORY` then rejects it (`ENOTDIR`), or the resolver refuses
  /// the link outright (`ELOOP`). The exact errno is a kernel detail; both are
  /// no-follow refusals, and the positive control proves following WOULD have
  /// reached a real directory — so the error is the refusal, not a broken link.
  #[test]
  fn open_no_symlinks_refuses_a_symlink_component() {
    let base = scratch("walk-symlink");
    let real = base.join("real");
    std::fs::create_dir_all(real.join("leaf")).expect("create real/leaf");
    let link = base.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink link -> real");

    // Positive control: `link` and `link/leaf` DO resolve to real directories when
    // symlinks are followed, so any refusal below is the no-follow guard firing.
    assert!(
      link.join("leaf").is_dir(),
      "the symlink target chain is real"
    );

    let refusal = |errno: rustix::io::Errno| {
      matches!(errno, rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP)
    };

    // INTERMEDIATE symlink: `base/link/leaf` reaches a real directory THROUGH the
    // symlinked `link` — refused without following it to `real`.
    let via_link = link.join("leaf");
    let intermediate = open_no_symlinks(&via_link, pin_final_flags())
      .expect_err("an intermediate symlink must be refused, not followed to its target");
    assert!(
      refusal(intermediate),
      "an intermediate symlink component is refused without following it: {intermediate:?}"
    );

    // FINAL symlink: `base/link` IS the requested object — refused, never followed.
    let final_link = open_no_symlinks(&link, pin_final_flags())
      .expect_err("a final-component symlink must be refused, not followed");
    assert!(
      refusal(final_link),
      "a final-component symlink is refused without following it: {final_link:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// A missing final component is `ENOENT` — the walk surfaces a vanished root as
  /// the raw errno the caller maps to `RootUnavailable`, exactly like the fast path.
  #[test]
  fn open_no_symlinks_on_a_missing_path_is_enoent() {
    let base = scratch("walk-missing");
    let gone = base.join("nope");
    let err =
      open_no_symlinks(&gone, pin_final_flags()).expect_err("a missing component cannot be walked");
    assert_eq!(
      err,
      rustix::io::Errno::NOENT,
      "a vanished component is ENOENT (the caller's NotFound race): {err:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// A component swapped for a NON-DIRECTORY fails the walk (`O_DIRECTORY` →
  /// `ENOTDIR`) — the fallback never pins through a file, matching the fast path's
  /// `O_DIRECTORY` refusal.
  #[test]
  fn open_no_symlinks_refuses_a_non_directory_component() {
    let base = scratch("walk-file");
    let file = base.join("f");
    std::fs::write(&file, b"x").expect("create a file");
    // Walking "f/child" hits a file where a directory must be.
    let through_file = file.join("child");
    let err = open_no_symlinks(&through_file, pin_final_flags())
      .expect_err("a non-directory component cannot be walked");
    assert_eq!(
      err,
      rustix::io::Errno::NOTDIR,
      "a non-directory component is ENOTDIR: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// The anchor-only path `"/"` (no `Normal` components) pins the filesystem root
  /// itself: the anchor open carries `final_flags`, so the walker still returns the
  /// target rather than tripping over an empty component list.
  #[test]
  fn open_no_symlinks_pins_the_root_itself() {
    let fd = open_no_symlinks(std::path::Path::new("/"), ancestor_final_flags())
      .expect("the filesystem root pins");
    let stat = rustix::fs::fstat(&fd).expect("fstat the root pin");
    let meta = std::fs::metadata("/").expect("stat /");
    assert_eq!(stat.st_dev, meta.dev(), "the root pin's device is /'s");
    assert_eq!(stat.st_ino, meta.ino(), "the root pin's inode is /'s");
  }

  /// On an UNRACED tree the one coherent walk records exactly what independently
  /// pinning each strict ancestor records. Coherence is a guarantee about what
  /// happens under a concurrent exchange; it must not change the honest answer,
  /// and this is the cell that says so.
  #[test]
  fn the_coherent_walk_agrees_with_independent_ancestor_pins() {
    let base = scratch("anc-walk");
    let nested = base.join("a/b");
    std::fs::create_dir_all(&nested).expect("create a nested dir");

    let coherent =
      ancestor_identities(&nested, identity_of(&nested)).expect("the coherent ancestor walk");
    let walked: Vec<_> = nested
      .ancestors()
      .skip(1)
      .map(|ancestor| {
        let fd = open_no_symlinks(ancestor, ancestor_final_flags())
          .expect("the component walk pins the ancestor");
        let stat = rustix::fs::fstat(&fd).expect("fstat the walked ancestor");
        RootIdentity::new(stat.st_dev, stat.st_ino.into())
      })
      .collect();
    assert_eq!(
      coherent, walked,
      "the coherent walk reproduces the per-ancestor pins exactly on an honest chain"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// The closing equality: the chain is only evidence if the walk that produced it
  /// ENDED on the object the pin, the mark and the seed vouched for. Here the
  /// pathname is honest and every ancestor resolves, but it reaches a DIFFERENT
  /// object than the caller pinned — the exact residue a pathname exchange leaves
  /// behind — and the snapshot must refuse rather than hand back a chain that
  /// describes someone else's parents.
  #[test]
  fn the_containment_snapshot_refuses_a_chain_that_does_not_end_on_the_pinned_root() {
    let base = scratch("anc-mixed");
    let live = base.join("live/root");
    let replacement = base.join("replacement/root");
    std::fs::create_dir_all(&live).expect("create base/live/root");
    std::fs::create_dir_all(&replacement).expect("create base/replacement/root");

    // Control: the walk succeeds when it lands on the object it was told to expect.
    ancestor_identities(&live, identity_of(&live))
      .expect("an honest chain ending on the pinned root is accepted");

    let err = ancestor_identities(&live, identity_of(&replacement))
      .expect_err("a chain that does not end on the pinned root must be refused");
    assert!(
      matches!(err, SourceError::RootReplaced { .. }),
      "reaching a different object at the root pathname is RootReplaced: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
  }

  /// The reported trace, made deterministic: two REAL parent directories are
  /// atomically exchanged (`renameat2(RENAME_EXCHANGE)` — no symlink anywhere, so
  /// every no-symlink fence passes) after the root was pinned. The pinned object is
  /// now reachable only under the OTHER pathname, so a snapshot taken for the
  /// original pathname must refuse instead of publishing the replacement's ancestor
  /// chain beside the original root identity.
  #[test]
  fn the_containment_snapshot_refuses_an_exchanged_parent_chain() {
    let base = scratch("anc-exchange");
    let live = base.join("live");
    let replacement = base.join("replacement");
    std::fs::create_dir_all(live.join("root")).expect("create base/live/root");
    std::fs::create_dir_all(replacement.join("root")).expect("create base/replacement/root");
    let live_root = live.join("root");
    let replacement_root = replacement.join("root");

    // What the pin, the mark and the seed grounded on, captured BEFORE the exchange.
    let pinned = identity_of(&live_root);

    if let Err(errno) = rustix::fs::renameat_with(
      rustix::fs::CWD,
      &live,
      rustix::fs::CWD,
      &replacement,
      rustix::fs::RenameFlags::EXCHANGE,
    ) {
      // RENAME_EXCHANGE needs a filesystem that implements it; skip loudly rather
      // than pass vacuously where it does not.
      eprintln!("SKIP: RENAME_EXCHANGE unavailable on this filesystem ({errno:?})");
      let _ = std::fs::remove_dir_all(&base);
      return;
    }

    // The pathname the spawn would report now denotes the OTHER object.
    let err = ancestor_identities(&live_root, pinned)
      .expect_err("after the exchange the original pathname no longer reaches the pinned root");
    assert!(
      matches!(err, SourceError::RootReplaced { .. }),
      "an exchanged parent chain is refused, never published beside the old identity: {err:?}"
    );

    // And the pinned object is exactly where the exchange put it, so the refusal is
    // about coherence and not about the object having vanished.
    assert_eq!(
      identity_of(&replacement_root),
      pinned,
      "the pinned object moved with its parent"
    );
    ancestor_identities(&replacement_root, pinned)
      .expect("the pathname that now reaches the pinned root snapshots cleanly");
    let _ = std::fs::remove_dir_all(&base);
  }

  /// The inotify floor classifier's rows: only the statx-UNAVAILABLE errnos
  /// (`NOSYS`, the pre-4.11 kernel, and `EOPNOTSUPP`) trip the spawn gate; a genuine
  /// `NOENT`/`EACCES`/`EPERM`/… is NOT the floor and passes through to the barrier
  /// with its meaning intact. `EPERM` in particular is NOT the floor — it stays a
  /// real error rather than a below-floor refusal.
  #[test]
  fn statx_unavailable_classifies_only_the_floor_errnos() {
    use rustix::io::Errno;
    for errno in [Errno::NOSYS, Errno::OPNOTSUPP] {
      assert!(
        statx_unavailable(errno),
        "{errno:?} means statx is unavailable — the below-floor spawn refusal"
      );
    }
    for errno in [
      Errno::NOENT,
      Errno::ACCESS,
      Errno::PERM,
      Errno::IO,
      Errno::NOTDIR,
      Errno::LOOP,
    ] {
      assert!(
        !statx_unavailable(errno),
        "{errno:?} is a real error, not the floor — it must pass through to the barrier"
      );
    }
  }

  /// The floor gate wired through the pin: on a `statx`-capable host (every
  /// supported kernel is 4.11+) `require_statx` on the pinned root passes, so a real
  /// spawn is never falsely refused. The below-floor refusal itself is carried by
  /// the classifier row above — a modern kernel cannot be made to answer `NOSYS` to
  /// exercise the failing branch here.
  #[test]
  fn require_statx_passes_on_a_statx_capable_host() {
    let dir = scratch("floor");
    let fd = pin_root(&dir).expect("pin the local dir");
    require_statx(fd.as_fd(), &dir).expect("statx is available on a 4.11+ host");
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The statx spawn gate is FAIL-CLOSED: EVERY errno refuses the spawn with a typed
  /// `RootUnavailable`, so an injected statx-`EPERM` (a seccomp policy blocking
  /// statx) can never slip past the gate and go live with the mount-id fence silently
  /// off. The errno only selects the message — the below-4.11 floor set
  /// (`NOSYS`/`EOPNOTSUPP`) carries the `Unsupported` floor text, every other errno
  /// (`EPERM`/`EACCES`/`EIO`) surfaces as an ordinary spawn failure — but NEITHER
  /// returns Ok. This is the hole the fix closes at the gate seam.
  #[test]
  fn statx_gate_error_fails_closed_on_every_error() {
    use rustix::io::Errno;
    use std::io::ErrorKind;
    let path = std::path::Path::new("/watched/root");

    // The below-floor set names the 4.11 floor (an `Unsupported` refusal).
    for errno in [Errno::NOSYS, Errno::OPNOTSUPP] {
      match statx_gate_error(errno, path) {
        SourceError::RootUnavailable { source, .. } => assert_eq!(
          source.kind(),
          ErrorKind::Unsupported,
          "{errno:?} is the below-4.11 floor: an Unsupported RootUnavailable"
        ),
        other => panic!("{errno:?} must refuse the spawn typed, got {other:?}"),
      }
    }

    // Every OTHER statx error is an ORDINARY spawn failure (`RootUnavailable`) — NOT
    // the floor message and NOT Ok. A statx-`EPERM` seccomp profile refuses to spawn
    // rather than going live with the fence off.
    for errno in [Errno::PERM, Errno::ACCESS, Errno::IO] {
      match statx_gate_error(errno, path) {
        SourceError::RootUnavailable { source, .. } => assert_ne!(
          source.kind(),
          ErrorKind::Unsupported,
          "{errno:?} is an ordinary spawn failure, not the below-floor message"
        ),
        other => panic!("{errno:?} must refuse the spawn typed, got {other:?}"),
      }
    }
  }

  /// The mount-id mask split (PURE): a SUCCESSFUL statx whose mask lacks the
  /// `STATX_MNT_ID` bit yields `None` (the legitimate pre-5.8 device belt), while a
  /// present bit yields `Some(id)`. `None` therefore has exactly ONE source — a
  /// mask-absent success — so `root_mount_id` can never launder a statx SYSCALL
  /// failure into the belt (a failure is `Err`, propagated by the caller, never this
  /// `None`).
  #[test]
  fn mnt_id_from_mask_splits_present_from_absent() {
    use rustix::fs::StatxFlags;
    assert_eq!(
      mnt_id_from_mask(0, 42),
      None,
      "a successful statx with the MNT_ID bit unset is the pre-5.8 belt (None)"
    );
    assert_eq!(
      mnt_id_from_mask(StatxFlags::MNT_ID.bits(), 42),
      Some(42),
      "the MNT_ID bit set reports the mount id"
    );
    assert_eq!(
      mnt_id_from_mask(StatxFlags::TYPE.bits(), 42),
      None,
      "an unrelated mask bit does not stand in for MNT_ID — only the MNT_ID bit gates"
    );
  }

  /// `root_mount_id` on a live pin is `Ok` — a healthy statx never yields `Err`, so
  /// the read is the belt decision (`Some` on 5.8+, `None` below), never a
  /// spawn-killing failure on a supported kernel. The `Err` path is the fail-closed
  /// spawn refusal the gate row proves; here the SUCCESS path is proven to stay `Ok`
  /// rather than the old `.ok()?` that swallowed any error into the belt.
  #[test]
  fn root_mount_id_reads_ok_on_a_pin() {
    let dir = scratch("mnt-id");
    let fd = pin_root(&dir).expect("pin the local dir");
    let read = root_mount_id(fd.as_fd());
    assert!(
      read.is_ok(),
      "a statx-capable host reads the mount id without error: {read:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }
}

/// The control port's reply seam: what a caller can and cannot conclude from a
/// batch that comes back. These drive a real `ControlPort` with the test thread
/// playing the reader, so they run only on a Linux host (the container `unit`
/// suite).
#[cfg(all(target_os = "linux", not(miri)))]
mod control_port {
  use std::{ffi::OsString, sync::mpsc, thread};

  use super::{
    super::{
      AnchorRequest, BatchOutcome, ControlOp, ControlPort, WatchOutcome, inotify::reader::Control,
      wake::WakeState,
    },
    watch,
  };

  /// Sends `ops` through a port whose reader DEQUEUES the batch and then dies
  /// without replying — dropping the reply sender is exactly what an unwinding
  /// reader does, including one that dies part-way through the cut it owes the
  /// batch. Returns what the caller, running on its own thread, came back with.
  fn dequeued_then_died(ops: Vec<ControlOp>) -> BatchOutcome {
    let (control_tx, control_rx) = mpsc::channel();
    let wake = WakeState::new().expect("an eventfd backs the port's wake state");
    let port = ControlPort::detached(control_tx, wake);
    let caller = thread::spawn(move || port.batch(ops));
    let dequeued = control_rx
      .recv()
      .expect("the batch reaches the reader before the caller blocks on its reply");
    assert!(
      matches!(dequeued, Control::Batch { .. }),
      "the message the port sends is the batch itself"
    );
    drop(dequeued);
    caller
      .join()
      .expect("the caller RETURNS on a dead reader rather than unwinding")
  }

  /// An ordering-proof round trip carries no arms, so it resolves none whether the
  /// reader served it or died holding it: both come back as an empty vector. That
  /// vector is why the answer cannot live inside the replies — read as one, a dead
  /// reader's return certifies the pre-reply cut that never happened, and a barrier
  /// settles clean over records nobody read.
  #[test]
  fn an_empty_batch_a_reader_died_holding_is_not_answered() {
    let outcome = dequeued_then_died(Vec::new());
    assert!(
      outcome.replies.is_empty(),
      "an empty batch resolves no arm — which is exactly what makes the replies mute here"
    );
    assert!(
      !outcome.answered,
      "a reader that died before replying answered NOTHING, and the empty vector cannot say so"
    );
  }

  /// The arms of an unanswered batch are still replied to, one `Failed(Io)` each.
  /// A Monitor node parked on its watch acknowledgement must be released whichever
  /// way the reader went, so the answer is reported BESIDE the replies and never by
  /// withholding them.
  #[test]
  fn every_arm_of_an_unanswered_batch_is_still_refused() {
    let ops = vec![
      ControlOp::Arm(AnchorRequest {
        watch: watch(1),
        parent: None,
        name: OsString::from("/r"),
        expected: None,
      }),
      ControlOp::Disarm(watch(2)),
      ControlOp::Arm(AnchorRequest {
        watch: watch(3),
        parent: None,
        name: OsString::from("/r/child"),
        expected: None,
      }),
    ];

    let outcome = dequeued_then_died(ops);
    assert!(
      !outcome.answered,
      "the reader died holding the batch, so nothing in it is known to have run"
    );
    let refusals: Vec<_> = outcome
      .replies
      .iter()
      .map(|reply| (reply.outcome, reply.anchor.is_some()))
      .collect();
    assert_eq!(
      refusals,
      vec![
        (WatchOutcome::Failed(tributary_proto::WatchError::Io), false),
        (WatchOutcome::Failed(tributary_proto::WatchError::Io), false),
      ],
      "one refusal per ARM, index-aligned and anchorless — the disarm contributes none"
    );
  }
}
