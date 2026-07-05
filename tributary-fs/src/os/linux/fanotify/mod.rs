//! The fanotify-FILESYSTEM backend: kernel-recursive, privileged, riding the
//! same DriverCore shape the FSEvents loop hardened.
//!
//! Pure machinery — the FID wire decode ([`fid`]) and the admission/intern map
//! ([`map`]) — compiles everywhere tests run (including miri), mirroring the
//! inotify precedent; the FFI Source (the superblock mark, its reader thread,
//! and the seeding walk) is `cfg(all(target_os = "linux", not(miri)))`.
//!
//! A single `FAN_MARK_FILESYSTEM` mark scopes to the whole superblock, so the
//! reader admits by directory-FID membership in a per-root [`FidMap`] before an
//! event ever reaches the seam: an unknown handle is provably outside the root
//! and dropped. Admitted events cross the driver's queue as
//! [`AdmittedEvent`]s inside [`RawLinuxEvent::Fanotify`](super::RawLinuxEvent),
//! carrying paths already resolved against the map — the compile path only
//! lowers each absolute path to its root-relative form. No node identity rides
//! with them: under the kernel-recursive profile record identity is inert
//! (design §4.9), exactly as the FSEvents lowering attaches none.
//!
//! Root UNMOUNT carries NO in-tree fanotify signal — an unmounted
//! `FAN_MARK_FILESYSTEM` superblock stays alive under the mark and the fd simply
//! goes quiet (design §7, container-validated L4.1). Detection is the mount
//! refresh's folded-in root re-stat (`FsOps::refresh_mounts` →
//! `MountRefresh.root`), compared against the barrier identity in
//! `DriverCore::on_mounts_refreshed`: a missing/replaced root lowers the same
//! `DeleteSelf`/`MoveSelf` death lifecycle a macOS `RootChanged` probe uses.
//! (An in-tree delete/replace of the ROOT object itself, by contrast, DOES
//! arrive as `FAN_DELETE_SELF`/`FAN_MOVE_SELF`.)
//!
//! That refresh runs at scope birth and on every loss signal — but a QUIET
//! unmount produces neither, so those triggers alone would never observe it.
//! The composition therefore adds ONE timer: the periodic root-liveness tick
//! (`WatcherOptions::root_liveness_interval`, fanotify-only — see the
//! per-backend death-signal table in the `core` module docs), which re-stats the
//! root on a bounded cadence so a signal-silent unmount is detected within the
//! interval. A loss-triggered refresh still catches it immediately when one
//! occurs; the tick only bounds the otherwise-unobservable quiet case, and
//! `Duration::ZERO` disables it (back to quiet-but-alive until re-access fails).

pub(crate) mod fid;
pub(crate) mod map;

#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, path::PathBuf};

pub(crate) use fid::{FanMask, RawFanotifyEvent};
use fid::{Fid, RenameInfo};
use map::FidMap;

/// One `FAN_RENAME`'s two admitted halves: each resolved absolute path. Both
/// halves are always present (the kernel reports the atomic pair in one event),
/// so the lowering emits adjacent `MovedFrom`/`MovedTo` with no pairing window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedRename {
  /// The source's absolute path (old directory + old name).
  pub(crate) old_path: PathBuf,
  /// The destination's absolute path (new directory + new name).
  pub(crate) new_path: PathBuf,
}

/// One fanotify event after admission: its mask, the affected object's absolute
/// path (resolved from the directory FID + name against the [`FidMap`]), and —
/// for a rename — the atomic pair. No node identity: under the kernel-recursive
/// profile record identity is inert (design §4.9).
///
/// A single-object dirent event carries `path`; a `FAN_RENAME` carries `rename`
/// and leaves the single-object fields empty; a self-event
/// (`DELETE_SELF`/`MOVE_SELF`) whose object is the admitted directory carries
/// that directory's `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedEvent {
  pub(crate) mask: FanMask,
  pub(crate) path: Option<PathBuf>,
  pub(crate) rename: Option<AdmittedRename>,
}

/// A per-read-batch admission memo (design §4.9): caches the ADMITTED
/// `(directory handle → resolved absolute path)` of the events in one
/// [`decode_events`](fid::decode_events) buffer, the storm win when many events
/// address few directories (a rename storm under one parent).
///
/// Soundness rests on the [`FidMap`]'s generation counter. Each cached entry is
/// tagged with the map generation it was resolved against; a lookup is a hit only
/// when the tag still equals the map's current generation. Because EVERY map
/// mutation (`learn`/`forget`/`reseed`/an orphan eviction) bumps that counter,
/// any mutation `admit` performs mid-batch invalidates the whole memo by making
/// every prior tag stale — so the memo can never serve a path the map has since
/// re-parented or pruned. The reader is single-threaded and owns both the map and
/// the memo, so no other writer exists; a fresh `MemoBatch` is used per buffer, so
/// it is also cleared at batch end by construction.
pub(crate) struct MemoBatch {
  /// The admitted `directory handle → (generation, resolved path)` cache. A miss
  /// (an out-of-root directory) is never inserted, so the memo stays bounded by
  /// the distinct in-root directories the batch touched.
  entries: BTreeMap<Box<[u8]>, (u64, PathBuf)>,
  /// How many lookups were served from the cache — an operator-facing counter.
  pub(crate) hits: u64,
  /// How many lookups fell through to a fresh [`FidMap::admit`] (a cold directory
  /// or a stale-generation entry).
  pub(crate) misses: u64,
}

impl MemoBatch {
  /// A fresh, empty memo for one read batch.
  pub(crate) fn new() -> Self {
    Self {
      entries: BTreeMap::new(),
      hits: 0,
      misses: 0,
    }
  }

  /// Resolves a directory FID to its admitted path THROUGH the memo. A cached
  /// entry whose generation still matches the map's is returned directly (a hit);
  /// otherwise the lookup falls to [`FidMap::admit`] (which resolves-or-evicts and
  /// may itself bump the generation), and a resolved path is cached under the
  /// map's post-lookup generation. A miss (`None`) is not cached — the next event
  /// under that handle re-checks membership, honoring a later `learn` of it.
  fn admit(&mut self, map: &mut FidMap, fid: &Fid) -> Option<PathBuf> {
    let generation = map.generation();
    if let Some((tagged, path)) = self.entries.get(fid.handle())
      && *tagged == generation
    {
      self.hits += 1;
      return Some(path.clone());
    }
    self.misses += 1;
    let path = map.admit(fid)?;
    // `admit` may have evicted an orphan on a miss and bumped the generation, but
    // this is the hit branch (a path resolved), which mutates nothing — so the
    // post-call generation still equals the one captured above and correctly tags
    // the entry.
    self
      .entries
      .insert(fid.handle().into(), (map.generation(), path.clone()));
    Some(path)
  }
}

/// The single ACTION one decoded event is classified into — the seam's single
/// source of truth. [`classify`] consults the mask, the event's field PRESENCE,
/// and the map (directory membership + the root anchor) to select EXACTLY one
/// variant, and the variant's OWN required fields are the validation: an action
/// whose field is absent is [`Lossy`](Self::Lossy) by construction, so there is no
/// separate decode-side required-field matrix to drift out of step with the field
/// consumers. The classifier applies each action's map self-maintenance inline
/// (learn/forget/re-parent), so the returned event is already resolved against the
/// post-mutation map; the reader only forwards it (and, for a move-in, walks the
/// subtree). Decode, admission, and the death path therefore cannot disagree —
/// every event shape resolves to one action here.
#[derive(Debug)]
pub(crate) enum Admission {
  /// An admitted event whose admission mutated NO directory node — a file
  /// (non-`ONDIR`) create/delete/modify/attrib, a non-structural directory
  /// modify/attrib, or a directory's own name-less `MOVE_SELF` (a self-move rescan;
  /// the moved node is re-parented by its rename/dirent, not here). Forward the
  /// resolved path. REQUIRES an admitted directory FID and — for a dirent — a name.
  Forward(AdmittedEvent),
  /// A new in-root child directory `learn`ed into the map (ALREADY applied), then
  /// forwarded — an `ONDIR` create. REQUIRES dir_fid (admitted) + name + the
  /// child's own `target_fid` (the node key); absent → [`Lossy`](Self::Lossy),
  /// because a create whose child cannot enter the map would blind that subtree.
  LearnDir(AdmittedEvent),
  /// A departed in-root directory `forget`/pruned from the map (ALREADY applied),
  /// then forwarded — a parent-reported `DELETE|ONDIR`/move-out dirent, or a
  /// directory's own name-less `DELETE_SELF`. REQUIRES the departing directory's
  /// FID (a dirent's `target_fid`; a self-event's own FID); a dirent absent it →
  /// [`Lossy`](Self::Lossy), because an un-pruned subtree resolves stale forever.
  ForgetDir(AdmittedEvent),
  /// A `FAN_RENAME` resolved and its map self-maintenance applied (in-root
  /// re-parent / move-out `forget` / move-in `learn`). `seed` is the moved
  /// directory's FID when it arrived from OUTSIDE the root and the reader must walk
  /// its pre-existing descendants in before forwarding (`None` for an in-root
  /// re-parent, a move-out, or a file/boundary rename). REQUIRES both halves (+
  /// `target_fid` when `ONDIR`, else → [`Lossy`](Self::Lossy)).
  ///
  /// The move-in `seed` carries the moved FID, NOT a captured path: the reader
  /// resolves the directory's CURRENT path through the map at walk time, because an
  /// in-root rename in the SAME batch may have re-parented it since this admission.
  Rename {
    /// The resolved move to forward once any subtree is mapped.
    event: AdmittedEvent,
    /// The moved directory's own FID when its subtree must be walked in (a move-IN
    /// from outside), else `None`.
    seed: Option<Fid>,
  },
  /// A self-event (`DELETE_SELF`/`MOVE_SELF`) on the WATCHED ROOT object — its
  /// self-FID (the `DFID` shape's `dir_fid`, or the `FID`-only shape's
  /// `target_fid`) is the map's root anchor ([`FidMap::is_root`](map::FidMap::is_root)).
  /// Forward the root's OWN path, which compile lowers to the death lifecycle
  /// (`Ignored` → terminal Removed + Rescan). First-class and `target_fid`-aware —
  /// checked BEFORE any firehose drop — so a FID-only root self-event (dir_fid =
  /// None) reaches death even when the periodic liveness tick is disabled, rather
  /// than being dropped and left forever blind (the R25 closure).
  RootDeath(AdmittedEvent),
  /// Provably outside the watched root, and not a root self-event: no admitted
  /// directory FID matched (or the self-FID is unknown to the map). The
  /// superblock-firehose filter — a clean drop, never a loss, so the sb's constant
  /// foreign self/attrib traffic never reseeds.
  ForeignDrop,
  /// The action the event's mask names needs a field the event does not carry (a
  /// named dirent with no/empty name; a directory create/delete/move/rename with no
  /// child `target_fid`) — a missing field would silently mishandle the map, so the
  /// buffer is lossy: the reader takes the ordered `Overflow` barrier and reseeds,
  /// exactly as a wire-level decode loss.
  Lossy,
}

/// Classifies one decoded event into its [`Admission`] action against the per-root
/// map: resolves directory FID(s) to path(s) through the batch [`MemoBatch`], and
/// applies the action's map self-maintenance inline (learn on a directory create,
/// forget on a delete/move-out, re-parent on a rename). PURE — the reader calls
/// this single-threaded between reads; the FFI side owns nothing but the fd and the
/// seeding walk. No node identity is produced; admission is membership + path
/// resolution only (design §4.9).
///
/// The classification is EXHAUSTIVE and TOTAL: every `(mask, field-presence,
/// map-state)` maps to exactly one action, with no catch-all silent fall-through —
/// an unrecognized shape is explicitly [`Admission::ForeignDrop`] or
/// [`Admission::Lossy`], never a wrong forward. The order is deliberate:
///
/// 1. a `FAN_RENAME` is its own event shape ([`classify_rename`]);
/// 2. a name-less self-event is resolved by its SELF-FID first — a root self-event
///    is [`Admission::RootDeath`] BEFORE any membership drop (so the FID-only shape
///    is never wrongly dropped), a known non-root directory's own delete `forget`s
///    it, and an unknown self-FID is [`Admission::ForeignDrop`];
/// 3. otherwise the directory FID is the admittance gate — absent or out-of-root →
///    [`Admission::ForeignDrop`] — after which the action's own required field
///    (name, then `target_fid` for a directory mutation) decides forward vs
///    [`Admission::Lossy`].
pub(crate) fn classify(
  map: &mut FidMap,
  event: &RawFanotifyEvent,
  memo: &mut MemoBatch,
) -> Admission {
  if let Some(rename) = &event.rename {
    return classify_rename(map, event, rename, memo);
  }

  let mask = event.mask;
  // A name-less self-event: the object reports its OWN deletion/move, its handle
  // arriving as a bare `DFID` (`dir_fid`) or a bare `FID` (`target_fid`). Resolve
  // by that self-FID FIRST, before the directory-membership gate below, so a root
  // self-event routes to death even in the FID-only shape (`dir_fid = None`) that
  // the gate would otherwise drop.
  if (mask.delete_self() || mask.move_self()) && event.name.is_none() {
    let Some(self_fid) = event.dir_fid.as_ref().or(event.target_fid.as_ref()) else {
      // No FID at all: unaddressable firehose noise.
      return Admission::ForeignDrop;
    };
    let is_root = map.is_root(self_fid);
    return match memo.admit(map, self_fid) {
      // The watched root's own death — route to the death lifecycle.
      Some(path) if is_root => Admission::RootDeath(self_event(mask, path)),
      // A known non-root directory's own self-event: a delete_self is a child
      // forget; a move_self is a self-rescan (the rename/dirent re-parents the node).
      Some(path) => {
        if mask.delete_self() {
          map.forget(self_fid);
          Admission::ForgetDir(self_event(mask, path))
        } else {
          Admission::Forward(self_event(mask, path))
        }
      }
      // A self-FID unknown to the map — a foreign object elsewhere on the sb.
      None => Admission::ForeignDrop,
    };
  }

  // A dirent event (or a self-event that also names a child). The directory FID is
  // the admittance gate: absent or out-of-root, the event is provably outside the
  // watched root — the firehose filter, a clean drop.
  let Some(dir_fid) = event.dir_fid.as_ref() else {
    return Admission::ForeignDrop;
  };
  let Some(dir_path) = memo.admit(map, dir_fid) else {
    return Admission::ForeignDrop;
  };

  // In-root. Every non-self dirent resolves `<dir>/<name>`, so it REQUIRES a name;
  // an absent or empty one (decode folds an empty name to `None`) cannot address a
  // target, so the action lacks its field → lossy.
  let Some(name) = event.name.as_ref() else {
    return Admission::Lossy;
  };
  let path = Some(join_name(&dir_path, name));

  if mask.ondir() {
    if mask.created() {
      // Learn the new child directory — REQUIRES its own FID to key the node, else
      // the create would forward while its subtree stays unmapped (blind).
      let Some(child) = event.target_fid.as_ref() else {
        return Admission::Lossy;
      };
      map.learn(dir_fid, name, Some(child));
      return Admission::LearnDir(AdmittedEvent {
        mask,
        path,
        rename: None,
      });
    }
    if mask.removed() || mask.move_self() {
      // Forget/prune the departing child subtree — REQUIRES the child's own FID,
      // else the departed subtree would resolve through stale links forever.
      let Some(child) = event.target_fid.as_ref() else {
        return Admission::Lossy;
      };
      map.forget(child);
      return Admission::ForgetDir(AdmittedEvent {
        mask,
        path,
        rename: None,
      });
    }
    // An `ONDIR` modify/attrib changes content/metadata, not the tree — no mutation.
  }

  // A file (non-`ONDIR`) dirent, or a non-structural directory modify/attrib.
  Admission::Forward(AdmittedEvent {
    mask,
    path,
    rename: None,
  })
}

/// Builds the admitted form of a resolved self-event (its own path, no child).
fn self_event(mask: FanMask, path: PathBuf) -> AdmittedEvent {
  AdmittedEvent {
    mask,
    path: Some(path),
    rename: None,
  }
}

/// Classifies a `FAN_RENAME`: resolves both directory FIDs and applies the moved
/// DIRECTORY's map self-maintenance (no identity — see [`classify`]).
///
/// Membership is the filter: BOTH ends outside the root is a rename elsewhere on
/// the superblock ([`Admission::ForeignDrop`]). With at least one end in-root, an
/// `ONDIR` rename mutates the tree and so REQUIRES the moved object's own
/// `target_fid` (absent → [`Admission::Lossy`], for every move shape — decode
/// cannot know which end is in-root, but classification can, so a targetless ONDIR
/// rename that would re-parent / walk / forget a subtree it cannot key is refused).
/// The four move flavors, keyed on whether the destination parent is in-root and
/// whether the MOVED OBJECT was already a known directory (its descendants already
/// mapped):
///
/// - **in-root rename** (moved dir known, destination in-root): re-parent the one
///   node in place; every descendant follows via the updated parent link — complete
///   by construction, no walk (`seed = None`).
/// - **move-in from outside** (moved dir unknown, destination in-root): the moved
///   directory carries pre-existing descendants the seed walk never saw, so after
///   learning the moved dir itself as a `pending_walk` top this returns `seed =
///   Some(moved)` — the reader resolves the dir's current path through the map and
///   walks the subtree in before forwarding, keeping the completeness invariant even
///   if a later in-root rename in the same batch re-parents the node first.
/// - **move-out** (moved dir known, destination outside): forget the moved dir; its
///   descendants' parent links now point at an absent handle, so their walks break
///   and they evict lazily — the map stops admitting the departed subtree naturally.
/// - **move-out of an already-unknown subtree** (moved dir unknown, destination
///   outside): nothing to maintain; only the in-root SOURCE end resolves, and the
///   move forwards as a boundary crossing.
fn classify_rename(
  map: &mut FidMap,
  event: &RawFanotifyEvent,
  rename: &RenameInfo,
  memo: &mut MemoBatch,
) -> Admission {
  let old_dir = memo.admit(map, &rename.old_dir);
  let new_dir = memo.admit(map, &rename.new_dir);
  if old_dir.is_none() && new_dir.is_none() {
    // Both ends outside the root: a rename elsewhere on the superblock.
    return Admission::ForeignDrop;
  }

  let old_path = old_dir
    .as_ref()
    .map(|dir| join_name(dir, &rename.old_name))
    .unwrap_or_else(|| PathBuf::from(&os_name(&rename.old_name)));
  let new_path = new_dir
    .as_ref()
    .map(|dir| join_name(dir, &rename.new_name))
    .unwrap_or_else(|| PathBuf::from(&os_name(&rename.new_name)));

  let admitted = AdmittedEvent {
    mask: event.mask,
    path: None,
    rename: Some(AdmittedRename { old_path, new_path }),
  };

  if event.mask.ondir() {
    // An `ONDIR` rename mutates the directory tree — it REQUIRES the moved object's
    // own FID to re-parent / walk-in / forget the node. Absent (with at least one
    // end in-root, proven above) → the buffer is lossy, exactly as the pre-inversion
    // decode matrix made a targetless ONDIR rename lossy — now caught AT the action.
    let Some(moved) = event.target_fid.as_ref() else {
      return Admission::Lossy;
    };
    if new_dir.is_some() {
      // Destination in-root. Whether the moved object was ALREADY a known in-root
      // directory (its descendants already mapped) splits the two flavors — read it
      // BEFORE `learn` overwrites the node.
      if map.contains(moved) {
        // In-root re-parent: `learn` overwrites the node in place, and its
        // already-mapped descendants follow via the updated parent link — no walk.
        map.learn(&rename.new_dir, &rename.new_name, Some(moved));
        return Admission::Rename {
          event: admitted,
          seed: None,
        };
      }
      // Moved IN from outside: learn the top as a `pending_walk` node, then hand the
      // reader its FID to walk the pre-existing descendants in (no per-descendant
      // creates arrive for a rename, so the map is complete only once the walk runs).
      map.learn_moved_in(&rename.new_dir, &rename.new_name, moved);
      return Admission::Rename {
        event: admitted,
        seed: Some(moved.clone()),
      };
    }
    // Moved OUT of the root: forget the departed subtree. A later move back is a
    // fresh move-in — walked in — the conservative direction.
    map.forget(moved);
    return Admission::Rename {
      event: admitted,
      seed: None,
    };
  }

  // A file / boundary rename: no directory-tree mutation.
  Admission::Rename {
    event: admitted,
    seed: None,
  }
}

/// Joins a raw fanotify child name onto its resolved directory path. A
/// non-UTF-8 or non-component name still produces a path the lowering can
/// escalate to a located rescan (coverage-honest), never a panic.
fn join_name(dir: &std::path::Path, name: &[u8]) -> PathBuf {
  dir.join(os_name(name))
}

/// Interprets a raw fanotify name as an `OsString` path component. On unix the
/// bytes pass through verbatim; elsewhere (test builds) a lossy form keeps the
/// pure paths decodable.
fn os_name(name: &[u8]) -> std::ffi::OsString {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(name.to_vec())
  }
  #[cfg(not(unix))]
  {
    std::ffi::OsString::from(String::from_utf8_lossy(name).into_owned())
  }
}

/// The composite `fanotify_init` flag set (design §4.1, container-validated):
/// `FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DFID_NAME |
/// FAN_REPORT_TARGET_FID`. `TARGET_FID` without `REPORT_FID` is `EINVAL` — the
/// full composite is mandatory. Restated locally so the pure module carries no
/// libc dependency; the FFI layer cross-asserts it against the composite.
///
/// `FAN_CLASS_NOTIF` is `0x0` (the notification class is the flag word's
/// default), so it contributes no bits and is omitted from the OR.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) const FAN_INIT_FLAGS: u32 = 0x0000_0200 // FAN_REPORT_FID
  | 0x0000_0400 // FAN_REPORT_DIR_FID  (half of DFID_NAME)
  | 0x0000_0800 // FAN_REPORT_NAME     (half of DFID_NAME)
  | 0x0000_1000; // FAN_REPORT_TARGET_FID

/// The mark mask armed on the superblock (design §4.1): every dirent verb plus
/// the self-events and `FAN_ONDIR` so directory events are reported.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) const FAN_MARK_MASK: u64 = fid::FAN_CREATE
  | fid::FAN_DELETE
  | fid::FAN_MODIFY
  | fid::FAN_ATTRIB
  | fid::FAN_RENAME
  | fid::FAN_DELETE_SELF
  | fid::FAN_MOVE_SELF
  | fid::FAN_ONDIR;

/// Encodes the file handle of the directory `dirfd` ITSELF via
/// `name_to_handle_at(dirfd, "", AT_EMPTY_PATH)` — the fd-relative encoder every
/// caller uses (the pre-live `Backend::Auto` probe on the pinned root, and the
/// live seed/reseed walk on each pinned directory). Because it names no path, no
/// name resolution can redirect it: the handle is taken from exactly the object
/// the caller pinned (opened `O_NOFOLLOW`/`RESOLVE_NO_SYMLINKS` and
/// fstat-verified), so neither a swap of the root path at spawn nor a foreign
/// directory swapped in for a listed name post-live can have its handle seed the
/// admission map (the scope-fence invariant on [`source`]). See
/// [`encode_handle_sized`] for the dynamic `EOVERFLOW`-retry sizing and the
/// returned byte layout.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) fn encode_handle_at(
  dirfd: std::os::fd::BorrowedFd<'_>,
) -> Option<std::boxed::Box<[u8]>> {
  use std::os::fd::AsRawFd;

  // SAFETY: the empty C string literal lives for the call; `dirfd` is a live open
  // directory fd (the caller pins it before this); AT_EMPTY_PATH makes the call
  // operate on `dirfd` directly rather than resolving a name under it.
  unsafe { encode_handle_sized(dirfd.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH) }
}

/// The shared `name_to_handle_at` core, DYNAMICALLY sizing the buffer: `struct
/// file_handle` is a flexible-array type, and a filesystem whose handle exceeds
/// the initial `MAX_HANDLE_SZ` request answers `EOVERFLOW` with the true size
/// written back into `handle_bytes` — so a single fixed buffer would turn an
/// oversized-handle filesystem (which CAN export handles) into a spurious
/// "unsupported". The loop grows to the reported size and retries exactly once;
/// a second `EOVERFLOW` is a lying kernel and fails.
///
/// `dirfd`/`cpath`/`at_flags` are passed straight to `name_to_handle_at`: the
/// path encoder passes `(AT_FDCWD, path, 0)`, the fd encoder passes `(fd, "",
/// AT_EMPTY_PATH)`. Returns the FID handle bytes — `handle_type` (native-endian)
/// followed by the opaque bytes — byte-identical to the event-side decode, so a
/// seed FID matches the kernel's event FIDs exactly. `None` when the filesystem
/// cannot encode a handle for this object (a non-exporting fs, a
/// permission/transient failure, or the double-`EOVERFLOW` broken-kernel case).
///
/// # Safety
///
/// `cpath` must be a valid NUL-terminated pointer that stays live for the call,
/// and `dirfd` must be `AT_FDCWD` or a valid open directory fd matching
/// `at_flags` (an empty path requires `AT_EMPTY_PATH`).
#[cfg(all(target_os = "linux", not(miri)))]
unsafe fn encode_handle_sized(
  dirfd: libc::c_int,
  cpath: *const libc::c_char,
  at_flags: libc::c_int,
) -> Option<std::boxed::Box<[u8]>> {
  let prefix = std::mem::size_of::<libc::file_handle>();
  // Start at MAX_HANDLE_SZ (the common case fits in one try); a larger handle
  // grows the buffer to the kernel-reported size on the single retry below.
  let mut cap = libc::MAX_HANDLE_SZ as usize;
  let mut grown = false;
  loop {
    // The backing buffer is `u64` so the pointer is 8-aligned — a `Vec<u8>` is
    // only 1-aligned, and writing a `file_handle` (align 4) through such a
    // pointer would be undefined behavior.
    let words = prefix.div_ceil(8) + cap.div_ceil(8) + 1;
    let mut storage = vec![0u64; words];
    let mut mount_id: libc::c_int = 0;
    let handle = storage.as_mut_ptr().cast::<libc::file_handle>();
    // SAFETY: storage is 8-aligned and sized for the fixed prefix plus `cap`
    // opaque bytes; this write stays within it.
    unsafe {
      (*handle).handle_bytes = cap as libc::c_uint;
    }
    // SAFETY: handle points at a correctly-sized, aligned file_handle; cpath is
    // a valid NUL-terminated pointer for `at_flags`; mount_id is a valid
    // out-param; dirfd is AT_FDCWD or a live directory fd (caller contract).
    let rc = unsafe { libc::name_to_handle_at(dirfd, cpath, handle, &mut mount_id, at_flags) };
    let errno = (rc != 0)
      .then(|| std::io::Error::last_os_error().raw_os_error())
      .flatten();
    match fid::classify_handle_attempt(rc, errno, grown) {
      fid::HandleAttempt::Encoded => {
        // SAFETY: the call succeeded, so the prefix and `handle_bytes` opaque
        // bytes are initialized.
        let (handle_bytes, handle_type) =
          unsafe { ((*handle).handle_bytes as usize, (*handle).handle_type) };
        if handle_bytes > cap {
          // The kernel reported success yet a length past the buffer it filled:
          // structurally impossible, refuse rather than read out of bounds.
          return None;
        }
        // SAFETY: the opaque handle begins right after the prefix and spans
        // handle_bytes (bounded by cap above); reading it as bytes is in-range.
        let opaque = unsafe {
          std::slice::from_raw_parts(storage.as_ptr().cast::<u8>().add(prefix), handle_bytes)
        };
        let mut bytes = Vec::with_capacity(4 + opaque.len());
        bytes.extend_from_slice(&handle_type.to_ne_bytes());
        bytes.extend_from_slice(opaque);
        return Some(bytes.into_boxed_slice());
      }
      fid::HandleAttempt::Grow => {
        // EOVERFLOW wrote the required size back into handle_bytes; retry once
        // at exactly that size.
        // SAFETY: the prefix is initialized on an EOVERFLOW return (the kernel
        // fills handle_bytes with the needed length).
        cap = unsafe { (*handle).handle_bytes as usize };
        grown = true;
      }
      fid::HandleAttempt::Unsupported => return None,
    }
  }
}

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) mod reader;

#[cfg(all(target_os = "linux", not(miri)))]
#[allow(unused_imports)]
pub(crate) use source::{FanotifySpawn, Source, SourceHandle};

#[cfg(all(target_os = "linux", not(miri)))]
mod source;
