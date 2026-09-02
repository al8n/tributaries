use std::path::Path;

use tributary_proto::WatchId;

use super::{
  attribute_events, excluded, fs_type_is_local, fs_type_is_remote,
  inotify::{
    decode::{IN_CREATE, IN_IGNORED, IN_ISDIR, IN_Q_OVERFLOW, InotifyMask, RawInotifyEvent},
    table::WdTable,
  },
  locality_refusal, mounts_from_file, parse_mountinfo,
};

fn watch(n: u64) -> WatchId {
  WatchId::new(core::num::NonZeroU64::new(n).unwrap())
}

/// One expected parse result, spelled the way mountinfo spells it: the mount
/// point, the mount id (field 1), the PARENT mount's id (field 2), and the
/// `major:minor` (field 3).
fn row(location: &str, mnt_id: u64, parent_id: u64, major: u64, minor: u64) -> crate::os::MountRow {
  crate::os::MountRow {
    location: std::path::PathBuf::from(location),
    mnt_id: Some(mnt_id),
    parent_id: Some(parent_id),
    dev: Some(super::makedev(major, minor)),
  }
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

/// Only rows STRICTLY under the root come back: the root's own row, its
/// ancestors and every mount outside its cone are all filtered out.
///
/// The ancestors were RETAINED while the parse resolved visibility — a shadowing
/// sibling can sit at the root or above it — and with no resolution left there is
/// nothing to ask them. Retaining them now would only allocate a mount point per
/// ancestor, per refresh, per watched root, for rows no consumer can use: a
/// boundary AT or ABOVE the root is not a boundary inside it.
///
/// MUTATION WITNESS (cone restored): retain `root.starts_with(&path)` as well and
/// this FAILS at `nothing at or above the root is a row` — the rootfs and `/mnt/a`
/// itself both back in the answer.
#[test]
fn mountinfo_extracts_mounts_strictly_under_root() {
  let content = "\
25 25 0:35 / / rw,relatime shared:4 - ext4 /dev/root rw
36 25 0:32 / /mnt/a rw,relatime shared:1 - tmpfs tmpfs rw
37 36 0:33 / /mnt/a/inner rw,relatime shared:2 - ext4 /dev/loop0 rw
38 25 0:34 / /mnt/b rw,relatime shared:3 - tmpfs tmpfs rw
malformed line
40 25 0:36 /
";
  let mounts = parse_mountinfo(content.as_bytes(), Path::new("/mnt/a"));
  assert_eq!(
    mounts,
    vec![row("/mnt/a/inner", 37, 36, 0, 33)],
    "nothing at or above the root is a row, a mount outside its cone never \
     enters, and a line short of five fields is skipped"
  );
}

/// The parse keeps the three IDENTITY fields it used to discard, and all three
/// are on every line it was already scanning: field 1 is the mount id, field 2
/// the id of the mount this one hangs off, and field 3 the `major:minor`. Without
/// them the table is paths-only and a mount REPLACED at an unchanged path is
/// invisible to every reader of it.
///
/// The parent travels as IDENTITY, not as hierarchy — nothing here resolves it to
/// another row — and it is what narrows the window a lowest-free mount id leaves
/// open: a recycled id re-attached under a DIFFERENT mount is a different
/// vfsmount, which the core reads as a replacement rather than as continuity.
///
/// The device is packed the way `dev_t` packs it, so the number a row carries is
/// the number a `stat` on that filesystem reports rather than a private encoding
/// that only ever compares against itself.
///
/// MUTATION WITNESS (parent dropped): write `parent_id: None` in the pushed row
/// and this FAILS at `each row carries its own ids and device` — the half that
/// tells a recycled id from a continuous one, silently absent.
#[test]
fn mountinfo_carries_the_identity_of_every_row() {
  let content = "\
36 25 0:32 / /mnt rw,relatime shared:1 - tmpfs tmpfs rw
41 36 259:3 / /mnt/nvme rw,relatime shared:9 - ext4 /dev/nvme0n1p3 rw
42 36 0:57 /sub /mnt/bind rw,relatime shared:7 - btrfs /dev/sda1 rw
";
  let mounts = parse_mountinfo(content.as_bytes(), Path::new("/mnt"));
  assert_eq!(
    mounts,
    vec![
      row("/mnt/nvme", 41, 36, 259, 3),
      row("/mnt/bind", 42, 36, 0, 57)
    ],
    "each row carries its own ids and device, not just its location"
  );
  assert_eq!(
    mounts[0].dev,
    Some(0x0001_0303),
    "major:minor is packed the way dev_t packs it, so the value is comparable \
     with a stat-read device"
  );
}

/// **Several rows can render ONE mount point, and every one of them comes back**
/// — with its own id, at that same location, in file order.
///
/// Two shapes, both ordinary and both stable. A plain STACK is a chain: each
/// member is mounted on the one below it, so each names the one below as its
/// parent. The second shape is not a chain at all — mount `A` at `/root/x/y`,
/// mount `C` over `/root/x`, then mount `B` at the `y` that `C` now shows there:
/// `A` hangs off the root mount and `B` off `C`, so neither is the other's
/// parent, yet both render `/root/x/y`.
///
/// Naming ONE of them was the whole of the old design, and every rule for it (line
/// order, the parent chain, a same-path group, the full parent graph) was found
/// wrong on a shape the previous rule had not considered, because the kernel
/// exports no visibility to be faithful to. Returning all of them retires the
/// question: the core keys its census by mount id, so two rows at one location
/// are two keys, and each one's own arrival, move and departure is a transition
/// on its own key. A hidden member's transition costs one redundant cover of
/// ground that was covered anyway — the safe direction, and the only cost.
///
/// MUTATION WITNESS (grouping restored): collapse rows by location, keeping the
/// last at each — and this FAILS at `every member of the stack is a row` with a
/// single-element `left`, which is one mount whose departure would never be
/// derived.
#[test]
fn mountinfo_returns_every_row_at_one_location() {
  // 44 is mounted OVER 40 at `/mnt/stack`, so 44's parent is 40 — not the `/mnt`
  // that carries the mount point's directory entry.
  let stack = "\
36 25 0:32 / /mnt rw,relatime shared:1 - tmpfs tmpfs rw
40 36 0:44 / /mnt/stack rw,relatime shared:5 - tmpfs lower rw
44 40 0:48 / /mnt/stack rw,relatime shared:6 - tmpfs upper rw
";
  let mounts = parse_mountinfo(stack.as_bytes(), Path::new("/mnt"));
  assert_eq!(
    mounts,
    vec![
      row("/mnt/stack", 40, 36, 0, 44),
      row("/mnt/stack", 44, 40, 0, 48),
    ],
    "every member of the stack is a row, with its own id and the location they \
     share"
  );
  assert_ne!(
    mounts[0].mnt_id, mounts[1].mnt_id,
    "and the two are told apart by the only thing that tells them apart"
  );

  // The rootfs (self-parented, as the initial namespace spells it) carries the
  // plain directory `/root`; `A` and the overmount `C` both hang off it, and `B`
  // hangs off `C`. Creation order lists `A` first, exactly as it happened.
  let unrelated = "\
1 1 0:1 / / rw,relatime shared:1 - ext4 /dev/root rw
40 1 0:44 / /root/x/y rw,relatime shared:5 - tmpfs first rw
41 1 0:45 / /root/x rw,relatime shared:6 - tmpfs overmount rw
42 41 0:46 / /root/x/y rw,relatime shared:7 - tmpfs revealed rw
43 1 0:47 / /root/other rw,relatime shared:8 - tmpfs elsewhere rw
";
  assert_eq!(
    parse_mountinfo(unrelated.as_bytes(), Path::new("/root")),
    vec![
      row("/root/x/y", 40, 1, 0, 44),
      row("/root/x", 41, 1, 0, 45),
      row("/root/x/y", 42, 41, 0, 46),
      row("/root/other", 43, 1, 0, 47),
    ],
    "two rows at one mount point that are not a stack at all are still simply \
     two rows, and the unrelated mount beside them is untouched"
  );
}

/// **Issue #74's transition, at a stacked mount point.** The line order of
/// `/proc/self/mountinfo` is mount CREATION order, and `mount --move`
/// re-parents a mount without minting a new one — so a mount moved onto an
/// occupied mount point keeps its OLDER id and is listed BEFORE the mount it now
/// hides.
///
/// A parse that answered one row per location had to decide which of the two, and
/// deciding by line order recorded the HIDDEN mount: lazily unmounting the other
/// then left the selected row byte-identical across both reads, the core saw no
/// transition, fired no cover, and the revealed subtree stayed dark for the life
/// of the scope. With both rows returned there is nothing to decide — the
/// departed mount's id is simply absent from the second read, whichever of the
/// two it was.
///
/// MUTATION WITNESS (grouping restored): collapse by location keeping the last row
/// at each and this FAILS at `the departure is a TRANSITION the two reads carry`,
/// `left != right` with both sides `[MountRow { .., mnt_id: Some(55), .. }]` —
/// two reads straddling an unmount that cannot be told apart.
#[test]
fn a_stacked_mounts_departure_is_a_transition_between_two_reads() {
  // 55 was mounted at `/mnt/vol`; 20 — older, created elsewhere long before — was
  // then `mount --move`d onto the same mount point, so 20's parent is 55.
  // Creation order lists 20 first.
  let stacked = "\
20 55 0:48 / /mnt/vol rw,relatime shared:7 - tmpfs moved rw
36 25 0:32 / /mnt rw,relatime shared:1 - tmpfs tmpfs rw
55 36 0:44 / /mnt/vol rw,relatime shared:3 - tmpfs hidden rw
";
  let before = parse_mountinfo(stacked.as_bytes(), Path::new("/mnt"));

  // `umount -l /mnt/vol` detaches the moved mount; the mount it hid is revealed.
  let unstacked = "\
36 25 0:32 / /mnt rw,relatime shared:1 - tmpfs tmpfs rw
55 36 0:44 / /mnt/vol rw,relatime shared:3 - tmpfs hidden rw
";
  let after = parse_mountinfo(unstacked.as_bytes(), Path::new("/mnt"));

  // Asserted FIRST: it is what the defect costs, so it is what a parse that
  // collapses the location has to trip on.
  assert_ne!(
    before, after,
    "the departure is a TRANSITION the two reads carry — the only thing that \
     makes the core cover the ground it revealed"
  );
  assert_eq!(
    before,
    vec![
      row("/mnt/vol", 20, 55, 0, 48),
      row("/mnt/vol", 55, 36, 0, 44),
    ],
    "both members come back in FILE order, however creation order arranged them"
  );
  assert_eq!(
    after,
    vec![row("/mnt/vol", 55, 36, 0, 44)],
    "and the survivor is byte-identical, so the diff names exactly the mount \
     that left"
  );
}

/// A torn read can list one mount id TWICE — the kernel drops the namespace lock
/// between the `read(2)` calls that generate the file, so a mount can be rendered
/// once, moved, and rendered again. The parse returns both rows: it validates no
/// uniqueness and drops nothing, because a row it dropped is a location it would
/// never answer for.
///
/// Deduplication belongs to the census, which is where the key exists: `census_of`
/// keeps the FIRST row of a repeated key, so one mount enters one census once
/// however many times a torn table named it. Doing it here instead would mean
/// choosing between two locations for one id, which is the same guess the whole
/// visibility resolution was.
#[test]
fn mountinfo_returns_both_rows_of_a_torn_read_with_a_duplicate_id() {
  let torn = "\
36 25 0:32 / /mnt rw,relatime shared:1 - tmpfs tmpfs rw
44 36 0:48 / /mnt/before rw,relatime shared:5 - tmpfs twice rw
44 36 0:48 / /mnt/after rw,relatime shared:5 - tmpfs twice rw
";
  assert_eq!(
    parse_mountinfo(torn.as_bytes(), Path::new("/mnt")),
    vec![
      row("/mnt/before", 44, 36, 0, 48),
      row("/mnt/after", 44, 36, 0, 48),
    ],
    "both rows come back verbatim — the parse refuses nothing and resolves \
     nothing, and the census keys and dedupes them"
  );
}

/// A line short of five fields is skipped, but a line whose LOCATION parses and
/// whose identity does not is kept with that identity unknown. The location is
/// the load-bearing half — losing it under-covers a real mount — while an
/// unknown id is exactly the honest `None` every non-Linux table reports, and an
/// unknown half never reads as a difference anywhere it is compared.
///
/// Each of the four fields degrades on its own: an unparsable mount id leaves the
/// row keyed by its location, an unparsable PARENT leaves the replacement test
/// deciding on the device alone, and either half of `major:minor` takes only the
/// device with it.
#[test]
fn mountinfo_keeps_a_row_whose_identity_will_not_parse() {
  let content = "\
zz 25 0:32 / /mnt/bad-id rw,relatime shared:1 - tmpfs tmpfs rw
37 25 nope / /mnt/bad-dev rw,relatime shared:2 - tmpfs tmpfs rw
38 25 0:x / /mnt/bad-minor rw,relatime shared:3 - tmpfs tmpfs rw
39 -1 0:37 / /mnt/bad-parent rw,relatime shared:4 - tmpfs tmpfs rw
";
  let mounts = parse_mountinfo(content.as_bytes(), Path::new("/mnt"));
  assert_eq!(
    mounts,
    vec![
      crate::os::MountRow {
        location: std::path::PathBuf::from("/mnt/bad-id"),
        mnt_id: None,
        parent_id: Some(25),
        dev: Some(super::makedev(0, 32)),
      },
      crate::os::MountRow {
        location: std::path::PathBuf::from("/mnt/bad-dev"),
        mnt_id: Some(37),
        parent_id: Some(25),
        dev: None,
      },
      crate::os::MountRow {
        location: std::path::PathBuf::from("/mnt/bad-minor"),
        mnt_id: Some(38),
        parent_id: Some(25),
        dev: None,
      },
      crate::os::MountRow {
        location: std::path::PathBuf::from("/mnt/bad-parent"),
        mnt_id: Some(39),
        parent_id: None,
        dev: Some(super::makedev(0, 37)),
      },
    ],
    "an unparsable identity field is UNKNOWN, never a dropped row"
  );
}

#[test]
fn mountinfo_unescapes_octal_fields() {
  let content = "36 25 0:32 / /mnt/with\\040space rw shared:1 - tmpfs tmpfs rw\n";
  let mounts = parse_mountinfo(content.as_bytes(), Path::new("/mnt"));
  assert_eq!(mounts, vec![row("/mnt/with space", 36, 25, 0, 32)]);
}

/// **R8 F2.** mountinfo escapes exactly FOUR bytes inside a path field — space,
/// tab, newline and backslash, as `\040`, `\011`, `\012`, `\134` — and separates
/// its fields with the literal space. Every other ASCII whitespace byte is legal
/// pathname data the kernel emits RAW: vertical tab `0x0b`, form feed `0x0c` and
/// carriage return `0x0d` all name perfectly ordinary directories.
///
/// Splitting fields on `u8::is_ascii_whitespace` truncates such a mount point and
/// records the row at a PHANTOM location. Because a successful read is
/// authoritative, that phantom is admitted like any other row: a mount that appears
/// and then departs silently is covered at a path that never existed, while the
/// real revealed subtree is never mapped at all.
///
/// All three raw bytes are in the fixture, though that predicate only eats two of
/// them: Rust's `u8::is_ascii_whitespace` is tab, newline, form feed, carriage
/// return and space, so `0x0b` survived it by accident. Accident is not a rule, and
/// the delimiter rule this pins — the literal `0x20`, nothing else — is what makes
/// all three ordinary path data rather than two of them lucky.
///
/// The escaped space rides alongside deliberately. The two encodings must stay
/// DISTINCT — `\040` is four bytes that become one space INSIDE a field, a raw
/// `0x0d` is one byte that was never an escape — and a rule that confuses them
/// either splits a path in half or glues two fields together.
///
/// MUTATION WITNESS (delimiter): restore `.split(u8::is_ascii_whitespace)` and this
/// FAILS at `every raw whitespace byte is path data` with `left: [MountRow {
/// location: "/mnt/we\u{b}i", mnt_id: Some(36), dev: Some(32) }, ...]` — the mount
/// point truncated at the form feed, two components short of where the mount is.
/// MUTATION WITNESS (empty-run filter): drop `.filter(|field| !field.is_empty())`
/// and this FAILS at the same site with `left: [MountRow { location:
/// "/mnt/we\u{b}i\u{c}r\rd", .. }, MountRow { location: "/mnt/with space", .. }]`
/// — the DOUBLED-space row gone entirely, the empty run having shifted every
/// positional index past it. That is what the filter is for, and why scoping it to
/// the delimiter had to keep it.
#[test]
fn mountinfo_keeps_the_raw_whitespace_bytes_of_a_mount_point() {
  // `\x0b`, `\x0c` and `\x0d` are ASCII whitespace that mountinfo does NOT escape;
  // the last line separates two fields with a doubled space.
  let content = "\
36 25 0:32 / /mnt/we\x0bi\x0cr\x0dd rw,relatime shared:1 - tmpfs tmpfs rw
37 25 0:33 / /mnt/with\\040space rw,relatime shared:2 - tmpfs tmpfs rw
38  25 0:34 / /mnt/doubled rw,relatime shared:3 - tmpfs tmpfs rw
";
  let mounts = parse_mountinfo(content.as_bytes(), Path::new("/mnt"));
  assert_eq!(
    mounts,
    vec![
      row("/mnt/we\u{0b}i\u{0c}r\u{0d}d", 36, 25, 0, 32),
      row("/mnt/with space", 37, 25, 0, 33),
      row("/mnt/doubled", 38, 25, 0, 34),
    ],
    "every raw whitespace byte is path data, an octal triple is the only escape, \
     and a doubled DELIMITER still shifts nothing"
  );
  let full = std::path::PathBuf::from("/mnt/we\u{0b}i\u{0c}r\u{0d}d");
  assert!(
    !mounts.iter().any(|mount| {
      mount.location != full
        && full
          .as_os_str()
          .as_encoded_bytes()
          .starts_with(mount.location.as_os_str().as_encoded_bytes())
    }),
    "no row lands at a TRUNCATION of the mount point, wherever a split would have \
     cut it — the phantom is a path no mount ever had, and covering it leaves the \
     real one unmapped"
  );
}

/// **R7 F2.** A Linux pathname is arbitrary bytes, so ANY mount in the namespace
/// may sit at a mount point that is not valid UTF-8 — and the parser must read it
/// as itself rather than failing the whole table.
///
/// The `&str` form this replaced made the failure NAMESPACE-WIDE: one such mount
/// point anywhere, and the read of `/proc/self/mountinfo` failed outright, every
/// refresh was marked non-authoritative, and issue #74's arrival/departure diff —
/// the primary detector for a mount that departs below the root — never ran on
/// any watched root on the host, however ordinary that root's own names were.
///
/// The staging line is what ties this cell to that failure: the buffer really is
/// undecodable, so a parser that decodes before it splits cannot pass.
///
/// MUTATION WITNESS (representability): reject a line whose mount point is not
/// UTF-8 (`std::str::from_utf8(&bytes).ok()?`) and this FAILS at `a non-UTF-8
/// mount point is a row like any other` with the middle row missing — the row
/// whose departure nothing would then derive.
/// MUTATION WITNESS (totality): fail the whole parse on such a line instead
/// (return an empty vec) and it FAILS at the same site with an EMPTY left — one
/// unrelated mount point blinding every row in the table, which is the shape of
/// the finding itself.
#[test]
fn mountinfo_parses_a_non_utf8_mount_point_and_keeps_the_rows_around_it() {
  // `\xff` is not a valid UTF-8 lead byte anywhere, so no decode of this buffer
  // succeeds — and the ordinary rows on either side are what prove the failure is
  // per-row rather than whole-file.
  let mut content: Vec<u8> = Vec::new();
  content.extend_from_slice(b"36 25 0:32 / /mnt/before rw shared:1 - tmpfs tmpfs rw\n");
  content.extend_from_slice(b"37 25 0:33 / /mnt/od\xffd rw shared:2 - ext4 /dev/loop0 rw\n");
  content.extend_from_slice(b"38 25 0:34 / /mnt/after rw shared:3 - tmpfs tmpfs rw\n");
  assert!(
    std::str::from_utf8(&content).is_err(),
    "staging: this is exactly the buffer a `read_to_string` of the live table \
     would refuse"
  );

  let mounts = parse_mountinfo(&content, Path::new("/mnt"));
  assert_eq!(
    mounts,
    vec![
      row("/mnt/before", 36, 25, 0, 32),
      crate::os::MountRow {
        location: odd_mount_point(),
        mnt_id: Some(37),
        parent_id: Some(25),
        dev: Some(super::makedev(0, 33)),
      },
      row("/mnt/after", 38, 25, 0, 34),
    ],
    "a non-UTF-8 mount point is a row like any other, and it does not take the \
     rows around it down with it"
  );
}

/// The bytes `/mnt/od\xffd` names, spelled the way each host can spell it: unix
/// carries a pathname verbatim, and the cross-platform half of the parser's gate
/// (which only ever sees UTF-8 fixtures in production) does the lossy decode the
/// parser itself does there.
fn odd_mount_point() -> std::path::PathBuf {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStrExt;
    std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/mnt/od\xffd"))
  }
  #[cfg(not(unix))]
  {
    std::path::PathBuf::from(String::from_utf8_lossy(b"/mnt/od\xffd").into_owned())
  }
}

/// **R7 F2**, the half the parser alone cannot answer: the READ must stay
/// AUTHORITATIVE over such a table.
///
/// `None` out of this function is not a smaller answer — it is what marks the
/// refresh non-authoritative, and a non-authoritative refresh runs no mount diff
/// at all, so a lazily-unmounted subtree stays dark indefinitely. The defect was
/// in the read (`read_to_string`), not in the parse, so this drives the read over
/// a file whose bytes no decode accepts.
///
/// MUTATION WITNESS: restore `std::fs::read_to_string(path).ok()?` (parsing
/// `content.as_bytes()`) and this FAILS at `the read stays AUTHORITATIVE` with
/// `left: None, right: Some(..)` — one undecodable mount point silently retiring
/// the whole detector.
#[test]
fn a_mountinfo_file_with_a_non_utf8_mount_point_still_reads_authoritative() {
  let path = std::env::temp_dir().join(format!(
    "tributary-fs-mountinfo-{}-{:?}.txt",
    std::process::id(),
    std::thread::current().id()
  ));
  let mut content: Vec<u8> = Vec::new();
  content.extend_from_slice(b"36 25 0:32 / /mnt rw shared:1 - tmpfs tmpfs rw\n");
  // Parented on `/mnt`'s own mount, as the kernel records a mount INSIDE it.
  content.extend_from_slice(b"37 36 0:33 / /mnt/od\xffd rw shared:2 - ext4 /dev/loop0 rw\n");
  std::fs::write(&path, &content).expect("the fixture table writes");

  let read = mounts_from_file(&path, Path::new("/mnt"));
  let _ = std::fs::remove_file(&path);

  assert_eq!(
    read,
    Some(vec![crate::os::MountRow {
      location: odd_mount_point(),
      mnt_id: Some(37),
      parent_id: Some(36),
      dev: Some(super::makedev(0, 33)),
    }]),
    "the read stays AUTHORITATIVE over a table no decode accepts: `None` here is \
     what silences the mount diff on every watched root"
  );
}

/// A missing file answers `None` — the honest unreadable-table signal the
/// authority rule is built on, kept distinct from "the bytes were surprising",
/// and the ONLY thing that produces it. The parse decides nothing and refuses
/// nothing, so no arrangement of mounts and no malformed line can make a readable
/// table answer `None` here.
#[test]
fn an_unreadable_mountinfo_file_answers_none() {
  let missing = std::env::temp_dir().join(format!(
    "tributary-fs-mountinfo-absent-{}-{:?}",
    std::process::id(),
    std::thread::current().id()
  ));
  assert!(
    mounts_from_file(&missing, Path::new("/mnt")).is_none(),
    "a table that could not be READ is the unknown the caller closes trust for"
  );
}

/// Parsing a table must stay near-linear in its rows, because a watched root of
/// `/` sees the whole namespace and Linux permits `fs.mount-max` — 100 000 by
/// default — mounts in one.
///
/// Nothing bounds a single mount point's stack below that limit either: every
/// `mount --bind X /r/vol` adds one more row at the SAME location. Two shapes
/// this parse has already worn were quadratic in exactly that case — asking, per
/// member, whether any OTHER member named it as a parent — and a full stack then
/// cost 10^10 comparisons, per refresh, per watched root, on the blocking pool.
/// A driver stalled there is how the queue loss the whole mount design exists to
/// avoid actually happens. One pass per line, one row pushed per line, is what
/// this pins.
///
/// # The cost verdict is a RATIO, and it is calibrated by the run itself
///
/// An absolute wall clock cannot state this property, and an early version of
/// this cell tried. It has to sit above the linear form on the slowest
/// instrumented build and below the quadratic form on the fastest native one, and
/// those two bounds are nearly an order of magnitude apart here: the linear parse
/// of a full stack took 0.26 s natively and 3.4 s under TSan (both measured),
/// against 41 s for a quadratic form. A ceiling with real margin over TSan has
/// almost none left under the defect, and the same ceiling was a hard RED under
/// miri.
///
/// So the cell measures the SAME work at two sizes an octave apart and asks how
/// the cost grew. A linear parse grows with the input — about 8x. A quadratic one
/// grows with its square — about 64x. The threshold sits between them, and
/// because both halves are measured on the machine running them, no interpreter,
/// sanitizer, container or loaded runner moves the verdict: it divides out.
///
/// Under miri the sizes drop to a token stack — one 32-bit address space is
/// shared by the whole shard — and the RATIO is skipped there, because at sixteen
/// rows the fixed costs are the measurement. What is asserted unconditionally at
/// both sizes is that every member came back.
#[test]
fn a_full_namespace_stack_is_parsed_in_linear_time() {
  // The kernel's own default `fs.mount-max`, and an octave below it. Miri gets a
  // token stack: the interpreted cost of the real one would fall on the shard
  // that shares a single 32-bit address space.
  let (small, big): (u64, u64) = if cfg!(miri) {
    (4, 16)
  } else {
    (12_500, 100_000)
  };

  // One mount point's whole stack as mountinfo spells it, plus the elapsed of the
  // PARSE alone — the fixture is built outside the measurement.
  fn parse(members: u64, base: u64) -> (std::time::Duration, Vec<crate::os::MountRow>) {
    let mut table = String::from("36 25 0:32 / /mnt rw,relatime shared:1 - tmpfs tmpfs rw\n");
    for member in 0..members {
      // Each mount sits on the one below it, so the group is one chain; the
      // bottom row hangs off `/mnt`'s own mount, exactly as the kernel records it.
      let id = base + member;
      let parent = if member == 0 { 36 } else { id - 1 };
      table.push_str(&format!(
        "{id} {parent} 0:{} / /mnt/vol rw,relatime shared:9 - tmpfs stacked rw\n",
        40 + member
      ));
    }
    let started = std::time::Instant::now();
    let mounts = parse_mountinfo(table.as_bytes(), Path::new("/mnt"));
    (started.elapsed(), mounts)
  }

  let whole_stack = |base: u64, members: u64| -> Vec<crate::os::MountRow> {
    (0..members)
      .map(|member| {
        row(
          "/mnt/vol",
          base + member,
          if member == 0 { 36 } else { base + member - 1 },
          0,
          40 + member,
        )
      })
      .collect()
  };

  let (small_elapsed, small_mounts) = parse(small, 1_100_000);
  let (big_elapsed, big_mounts) = parse(big, 2_200_000);
  assert_eq!(
    small_mounts,
    whole_stack(1_100_000, small),
    "every member of the stack is a row of its own, in file order"
  );
  assert_eq!(
    big_mounts,
    whole_stack(2_200_000, big),
    "and that holds at the namespace's own limit, however deep the stack is"
  );

  // 8x the input. Linear grows about 8x with it; quadratic grows about 64x. The
  // threshold is the geometric middle, and every machine-speed factor divides out
  // — which is what an absolute ceiling could not do here.
  let grew = big_elapsed.as_secs_f64() / small_elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
  assert!(
    cfg!(miri) || grew < 24.0,
    "the cost of parsing a stack grows with the stack, not with its square — \
     this refresh runs on the blocking pool, and a driver stalled there is the \
     queue loss the mount design exists to avoid ({small} rows took \
     {small_elapsed:?}, {big} rows took {big_elapsed:?}, a factor of {grew:.1})"
  );
}

/// **R9 F1, the coherence half.** The refresh marks the mount TABLE and the
/// root's own stat authoritative as ONE snapshot, and they are two samples: the
/// kernel generates `/proc/self/mountinfo` across many `read(2)` calls and drops
/// the namespace lock between them, and the root's `statx` is a separate syscall
/// after all of them. A mount transition anywhere in that window makes the pair
/// describe two different worlds.
///
/// What that costs is not abstract, because mount ids are allocated LOWEST-FREE
/// and freed on umount: an id the older table half still lists can be the very id
/// the newer root stat reports. Every predicate the core writes against "a row's
/// id versus the root's" then reads a coincidence as evidence — the exemption a
/// btrfs subvolume gets, and the confirmation that moves a record out of it.
///
/// So an attempt the namespace moved under is REJECTED, and the retry is bounded:
/// a namespace in constant motion must degrade to the honest non-authoritative
/// answer rather than spin the blocking pool. This drives that policy directly;
/// the live half — the `mountinfo` fd whose `poll` reports the generation — is
/// `a_freshly_opened_mountinfo_fd_polls_clean` below.
///
/// MUTATION WITNESS (accept the unstable pair): answer `(sample.rows, sample.root)`
/// unconditionally in `coherent_mount_sample` and this FAILS at `a namespace that
/// never held still answers NO table` with `left: Some([MountRow { location:
/// "/mnt/c", mnt_id: Some(3), parent_id: None, dev: Some(3) }]), right: None`.
/// MUTATION WITNESS (drop the retry): take exactly one sample (`let sample =
/// take();` with the loop deleted) and this FAILS at `staging: the unstable
/// attempt is re-taken` with `left: 1, right: 2` — one lost race permanently
/// costing a refresh its table.
/// MUTATION WITNESS (retry a table-less read too): loop while `!sample.stable ||
/// sample.rows.is_none()` and this FAILS at `a STABLE read is not re-taken` with
/// `left: 3, right: 1` — three reads of `/proc` per refresh, forever, for a
/// `/proc` that no re-read would open either.
#[test]
fn a_mount_sample_the_namespace_moved_under_is_not_a_table() {
  fn attempt(rows: Option<&str>, stable: bool, root: u64) -> super::MountSample<u64> {
    super::MountSample {
      rows: rows.map(|at| {
        vec![crate::os::MountRow {
          location: std::path::PathBuf::from(at),
          mnt_id: Some(root),
          parent_id: None,
          dev: Some(root),
        }]
      }),
      root,
      stable,
      namespace: None,
    }
  }

  // Unstable, then stable: the second attempt is the answer, and its ROOT sample
  // travels with it.
  let taken = std::cell::Cell::new(0u64);
  let crate::os::MountReading { rows, root, .. } =
    super::coherent_mount_sample(super::MAX_MOUNT_SAMPLE_ATTEMPTS, || {
      taken.set(taken.get() + 1);
      match taken.get() {
        1 => attempt(Some("/mnt/a"), false, 1),
        n => attempt(Some("/mnt/b"), true, n),
      }
    });
  assert_eq!(taken.get(), 2, "staging: the unstable attempt is re-taken");
  assert_eq!(
    rows.as_deref(),
    Some(
      [crate::os::MountRow {
        location: std::path::PathBuf::from("/mnt/b"),
        mnt_id: Some(2),
        parent_id: None,
        dev: Some(2),
      }]
      .as_slice()
    ),
    "the table that comes back is the one the namespace held still for"
  );
  assert_eq!(
    root, 2,
    "and the root sample is the ACCEPTED attempt's, never an earlier world's"
  );

  // Never stable: the bound is spent, the table is refused, and the root sample
  // still travels — the death gate reads it and death is terminal whatever the
  // table did.
  let taken = std::cell::Cell::new(0u64);
  let crate::os::MountReading { rows, root, .. } =
    super::coherent_mount_sample(super::MAX_MOUNT_SAMPLE_ATTEMPTS, || {
      taken.set(taken.get() + 1);
      attempt(Some("/mnt/c"), false, taken.get())
    });
  assert_eq!(
    taken.get() as usize,
    super::MAX_MOUNT_SAMPLE_ATTEMPTS,
    "staging: the retry is BOUNDED — a churning namespace cannot spin the \
     blocking pool"
  );
  assert_eq!(
    rows, None,
    "a namespace that never held still answers NO table: non-authoritative \
     installs no frame and diffs nothing, which is the degrade that cannot lose \
     a cover"
  );
  assert_eq!(
    root,
    super::MAX_MOUNT_SAMPLE_ATTEMPTS as u64,
    "the LAST attempt's root sample still travels: liveness is terminal \
     regardless of what the table did"
  );

  // Stable and unreadable: not a tear, so re-reading it would only pay for the
  // same answer twice more. (This is the ONLY way rows come back `None` — the
  // parse always answers a table, whatever the bytes hold.)
  let taken = std::cell::Cell::new(0u64);
  let crate::os::MountReading { rows, .. } =
    super::coherent_mount_sample(super::MAX_MOUNT_SAMPLE_ATTEMPTS, || {
      taken.set(taken.get() + 1);
      attempt(None, true, taken.get())
    });
  assert_eq!(taken.get(), 1, "a STABLE read is not re-taken");
  assert_eq!(rows, None, "and an unreadable one is still no table");
}

/// The live half of the coherence check, and the FALSE GREEN it exists to rule
/// out: if `poll` raised `POLLERR | POLLPRI` on every call — because the fd was
/// polled twice, because the flag were requested wrongly, because a `/proc`
/// implementation answered differently — then every refresh on every Linux host
/// would answer non-authoritative, the mount diff would never run again, and
/// nothing else in the suite would notice. A freshly opened `mountinfo` fd polled
/// once must read CLEAN.
///
/// The positive direction only. Driving the negative needs a real mount
/// transition inside the window, which needs privileges the unit suite does not
/// have; the policy above is where the rejection itself is pinned.
#[cfg(all(target_os = "linux", not(miri)))]
#[test]
fn a_freshly_opened_mountinfo_fd_polls_clean() {
  let file = std::fs::File::open("/proc/self/mountinfo").expect("the live table opens");
  assert!(
    super::namespace_unchanged(&file),
    "an fd opened and polled with nothing in between reports an UNCHANGED mount \
     namespace — a check that always answered `changed` would silently retire \
     the whole mount detector on every host"
  );

  // And the seam the refresh actually calls hands back the caller's own sample.
  let namespace = super::NamespaceWatch::default();
  let reading = super::mount_sample(Path::new("/"), &namespace, || 7u8);
  let sampled = reading.root;
  assert_eq!(
    sampled, 7,
    "the root sample is the caller's, passed through"
  );
  assert!(
    reading.stable,
    "a quiet namespace answers a STABLE window — an always-unstable one would \
     withhold the incarnation token on every refresh of every host"
  );
  assert!(
    reading.namespace.is_some(),
    "and a token comes back: `None` here means the fallback the pre-6.8 hosts \
     depend on is silently absent"
  );
}

/// The token's EXACT form, and the false green that would hide its absence:
/// `statx(STATX_MNT_ID_UNIQUE)` must actually be requested and actually be read
/// back on a kernel that has it (Linux 6.8).
///
/// The bit is not in `rustix`'s `StatxFlags`, so it is named by value and passed
/// through `from_bits_retain` — and `rustix::fs::statx` masks the request with
/// `StatxFlags::all()` before the syscall. That intersection keeps the bit only
/// because the flag set carries bitflags' externally-defined-flags escape hatch
/// (`const _ = !0`). If that ever changes, or the constant is wrong, or the mask
/// bit is read from the wrong word, this reads `None` on every host — and NOTHING
/// else fails: the incarnation token silently degrades to the namespace fallback,
/// which is coarser and still correct, so every cell about the token keeps
/// passing while the exact leg it is supposed to prefer is dead.
///
/// So the presence assertion is gated on the running kernel rather than skipped:
/// below 6.8 there is genuinely no unique id to read and the cell says so loudly
/// (the container this repo verifies in runs 6.4, which is exactly why the gate is
/// a version check and not a `#[cfg]`), and at 6.8 or above a `None` is a defect.
///
/// MUTATION WITNESS (the mask drops the bit): narrow the intersection to
/// `StatxFlags::ALL` — the real `STATX_ALL`, which predates 6.8 and does not carry
/// this flag — and this FAILS at `the unique-id bit survives the mask` with `left:
/// 0, right: 16384`. This leg runs on EVERY Linux host, kernel version or not, and
/// it is the one that catches a `rustix` whose flag set stops covering unknown
/// bits.
/// MUTATION WITNESS (bit not requested): pass `StatxFlags::empty()` as the mask in
/// `root_mnt_unique_id` and this FAILS on any 6.8+ host at `a 6.8+ kernel answers
/// a unique mount id`. It CANNOT fail below 6.8 — there is no unique id to miss —
/// which is why the skip line is printed rather than the cell silently reading
/// green: the verify container runs 6.4, so this leg is proved on CI and on any
/// modern host, not here.
#[cfg(all(target_os = "linux", not(miri)))]
#[test]
fn a_unique_mount_id_is_read_where_the_kernel_has_one() {
  fn kernel_at_least(major: u32, minor: u32) -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
      return false;
    };
    let mut parts = release.trim().split(['.', '-']);
    let read = |p: Option<&str>| p.and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let (found_major, found_minor) = (read(parts.next()), read(parts.next()));
    (found_major, found_minor) >= (major, minor)
  }

  // The one link this host can prove whatever its kernel: `rustix::fs::statx`
  // intersects the requested mask with `StatxFlags::all()`, so a flag set without
  // the externally-defined-flags escape hatch would drop this bit on the floor and
  // the request would silently ask for nothing on EVERY host.
  use rustix::fs::StatxFlags;
  assert_eq!(
    (StatxFlags::from_bits_retain(super::STATX_MNT_ID_UNIQUE) & StatxFlags::all()).bits()
      & super::STATX_MNT_ID_UNIQUE,
    super::STATX_MNT_ID_UNIQUE,
    "the unique-id bit survives the mask rustix applies before the syscall — \
     without it the request reaches the kernel asking for nothing and the token \
     degrades to the namespace fallback in silence"
  );

  let first = super::root_mnt_unique_id(Path::new("/"));
  let second = super::root_mnt_unique_id(Path::new("/"));
  assert_eq!(
    first, second,
    "one mount answers ONE unique id: a token that varied per call would move the \
     frame on every refresh"
  );
  if kernel_at_least(6, 8) {
    assert!(
      first.is_some(),
      "a 6.8+ kernel answers a unique mount id, and the request has to reach it: \
       a `None` here is the exact leg silently falling back to the coarser \
       namespace token on every host"
    );
  } else {
    println!(
      "TRIBUTARY-SKIP a_unique_mount_id_is_read_where_the_kernel_has_one: kernel \
       below 6.8 has no STATX_MNT_ID_UNIQUE — the namespace fallback is what runs \
       here, and it has its own cell"
    );
    assert!(
      first.is_none(),
      "and a kernel WITHOUT the field must not appear to answer one: a value read \
       out of an unset mask bit is a token invented from uninitialised meaning"
    );
  }
}

/// The FALSE GREEN of the incarnation token's pre-6.8 fallback, and the mirror of
/// the cell above: [`NamespaceWatch`] must not count a transition where none
/// happened.
///
/// Its generation drives the core's frame epoch, and a frame that moved is a
/// coverage set owed a fresh whole-root generation and every outstanding round
/// trip refused. A watch that bumped on every call would therefore buy a
/// whole-root reseed per refresh, for every fanotify scope holding an exempt
/// record, on every host — and it would do it while every cell about the token
/// still passed, because "the frame moved" is exactly what those cells stage.
///
/// The negative direction (a real mount transition BETWEEN two observations moving
/// the count) needs privileges the unit suite does not have; the core-side cells
/// pin what a moved token means, and this pins that a quiet namespace does not
/// produce one.
///
/// MUTATION WITNESS: bump unconditionally in `NamespaceWatch::observe` (drop the
/// `if !namespace_unchanged(file)` guard) and this FAILS at `a quiet namespace
/// counts NO transition` with `left: 2, right: 1`.
#[cfg(all(target_os = "linux", not(miri)))]
#[test]
fn a_quiet_namespace_holds_its_transition_count_still() {
  let watch = super::NamespaceWatch::default();
  let first = watch.observe().expect("the live mountinfo opens");
  let second = watch.observe().expect("and stays open");
  assert_eq!(
    second, first,
    "a quiet namespace counts NO transition: this number is what the core reads \
     as a frame move, so a count that advanced on its own would put every scope \
     in a permanent whole-root reseed"
  );
  assert_eq!(
    watch.observe().expect("still open"),
    first,
    "and it stays still across repeated observations — the fd is HELD, so each \
     poll answers for the gap since the last one rather than for its own open"
  );
}

/// The octal unescape reads three digits into ONE byte, and the arithmetic that
/// does it must not overflow. `(octal[0] - b'0') * 64` in `u8` PANICS in a debug
/// build for any leading digit above 3 — unreachable while the kernel is the only
/// writer (it emits `\040`, `\011`, `\012`, `\134`), and reachable the moment the
/// parser reads whatever bytes `/proc` handed back rather than a decoded string.
///
/// A triple that does not fit a byte is left VERBATIM rather than truncated into
/// a different byte: inventing a byte would move the mount point.
///
/// MUTATION WITNESS: compute the value in `u8` again and this cell PANICS at
/// `attempt to multiply with overflow` inside `unescape_mountinfo` rather than
/// asserting — the debug-build crash the widening exists to prevent.
#[test]
fn mountinfo_unescape_survives_an_out_of_range_octal_triple() {
  let content = b"36 25 0:32 / /mnt/hi\\777there rw shared:1 - tmpfs tmpfs rw\n";
  let mounts = parse_mountinfo(content, Path::new("/mnt"));
  assert_eq!(
    mounts,
    vec![row("/mnt/hi\\777there", 36, 25, 0, 32)],
    "an out-of-range triple is not an escape the kernel wrote, so it stays as \
     the four bytes it is"
  );
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
        frame: crate::os::ScopeFrame::default(),
      }),
      ControlOp::Disarm(watch(2)),
      ControlOp::Arm(AnchorRequest {
        watch: watch(3),
        parent: None,
        name: OsString::from("/r/child"),
        expected: None,
        frame: crate::os::ScopeFrame::default(),
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
