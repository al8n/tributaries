//! The USN change-journal source's pure machinery: the reason vocabulary,
//! the cumulative-mask delta table, and the FRN-keyed rename pairing.
//!
//! NTFS writes a journal record only when a change of a kind NOT ALREADY
//! RECORDED happens on the open file. Each record carries the OR of every
//! reason accumulated since the first open, and a repeat of a kind already in
//! that mask produces NO RECORD AT ALL — "several write operations with no
//! intervening close and reopen operations result in only one change record".
//! The last close appends one final record: the same accumulated mask plus
//! `USN_REASON_CLOSE`, a summary that says nothing about the order or the
//! count of what it summarizes. The next opener starts a fresh accumulator.
//! See
//! <https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records>.
//!
//! Two consequences shape everything here. Emitting each record's full mask
//! would re-report every earlier fact on every later record, so the session
//! table remembers the last mask emitted per subject and lowers only the
//! DELTA. And because a repeat is INVISIBLE — write, write, close is two
//! records, not three — the delta alone can leave a consumer permanently
//! describing a mid-write file; only the close summary can repair that, so it
//! replays every class it carries whose replay is safe (see
//! [`SessionTable::observe`]).
//!
//! # THE REPEAT RULE IS A RULE ABOUT WRITES, AND THE JOURNAL SAYS SO
//!
//! The reference states the rule for WRITE operations and never for renames.
//! This module used to apply it to renames anyway, as the conservative
//! reading, and paid for that reading with covers. THE READING IS FALSE, and
//! it is false by measurement rather than by argument: the
//! `usn_repeat_rename_on_one_handle_writes_which_records` cell in
//! `tributary-fs/tests/windows_rdcw.rs` renames one file TWICE through one
//! held handle on a real journal-armed NTFS volume and prints every record the
//! session wrote. On the `windows-2022` and `windows-2025` runners, verbatim:
//!
//! ```text
//! moves: repeat-first.txt -> repeat-second.txt -> repeat-third.txt, one handle held across both
//! record usn=38264 reason=0x00000100 name=repeat-first.txt
//! record usn=38360 reason=0x00001100 name=repeat-first.txt
//! record usn=38456 reason=0x00002100 name=repeat-second.txt
//! record usn=38552 reason=0x00001100 name=repeat-second.txt
//! record usn=38648 reason=0x00002100 name=repeat-third.txt
//! record usn=38744 reason=0x80002100 CLOSE name=repeat-third.txt
//! ANSWER arriving halves before the close=2 (departing=2) => RECORDED
//! ```
//!
//! TWO FACTS ARE READABLE THERE AND BOTH ARE LOAD-BEARING. The second move
//! wrote BOTH of its halves, so a rename already in a session's history
//! suppresses nothing. And the two rename bits ALTERNATE rather than
//! accumulate — `0x1100`, `0x2100`, `0x1100`, `0x2100`, `FILE_CREATE` standing
//! throughout — so the rename path CLEARS the opposite half as it sets its
//! own, and each move's bits are therefore fresh at the instant they are
//! written. The suppression this module used to reason around has no state to
//! happen in: a mask carrying both halves at once is not a mask the rename
//! path produces.
//!
//! The companion cell `usn_close_record_carries_which_name`, same suite and
//! same runners, settles the other open question — which name a close summary
//! carries:
//!
//! ```text
//! name the session was OPENED under: close-name-before.txt
//! name the subject had at CLOSE:      close-name-after.txt
//! record usn=37568 reason=0x80002102 CLOSE name=close-name-after.txt
//! ANSWER close FileName=close-name-after.txt => CURRENT NAME
//! ```
//!
//! A close names a LIVE path, never a retired one. Between them the two
//! measurements retire every cover this module used to pay for an invisible
//! move; what went with them, and the one shape the measurement does not
//! itself reach, is recorded on [`SessionTable::observe`].
//!
//! # WHAT WAS MEASURED, ON WHAT, AND WHAT IS STILL UNMEASURED
//!
//! ALL THREE CELLS RUN ON ONE FILESYSTEM: the `NTFS` zoo volume the Windows
//! integration job prepares, on the `windows-2022` and `windows-2025` runners.
//! NTFS is what was measured, and NTFS is the whole of what was measured.
//!
//! The source, however, accepts ANY volume with an active journal speaking
//! record version 2 or 3 — which includes ReFS, whose journal emits V3 and
//! whose rename accounting nobody here has ever observed. If ReFS's rename
//! bits ACCUMULATE where NTFS's alternate, a second move on one open handle
//! writes a word production's delta discards, and the move reaches no
//! consumer: a file's location goes stale silently, and a mapped directory
//! takes every descendant path with it.
//!
//! So the retirement is scoped to the evidence rather than to the arm. The
//! source reads the volume's filesystem name from the root's own open handle
//! and hands the admission a [`RenameSemantics`]; only [`RenameSemantics::Measured`]
//! — NTFS — gets the debt-free path, and every other filesystem keeps the
//! conservative location and topology debt this module used to pay everywhere.
//! An unproven filesystem therefore costs cover rate and never correctness, and
//! it costs it only where the proof is missing.
//!
//! And the proof is ENFORCED where it is claimed. The premise the retirement
//! rests on is a decidable property of a record stream, stated once in
//! [`premise::moves_are_recorded_afresh`] and decided through this module's own
//! machines rather than beside them: [`SessionTable`] says which halves are
//! FRESH and [`UsnPairer`] says which of them the source joins into a move. A
//! predicate that reused one and re-derived the other passed the very
//! coalesced-mask stream the gate exists to fence, so both are reused and
//! neither is approximated — over the stream the source READS, which is the
//! whole volume's, because the drain that widows a parked half fires on records
//! of other file references and a stream filtered to one subject is a stream
//! that rule can never fire in. The real-journal cell asserts on that verdict,
//! so an NTFS runner whose journal stopped behaving as measured fails the job
//! instead of printing a line nobody reads.
//!
//! A session is keyed by the OBJECT (its file reference), but every delivery
//! is routed by a record's LINK — the parent directory and name that record
//! carries. For a file with one link those agree and nothing more is needed.
//! For a hard-linked file they do not: the journal writes each record under
//! `Open.Link.Name`, the link the operating handle was opened through, and the
//! close record names the LAST handle's link (see [MS-FSA] 2.1.5.4, phase 6).
//! A write through `/watched/a` and a final close through `/outside/b`
//! therefore produced a replay that admission routed at `b` and dropped as
//! out-of-root, stranding the notice already delivered at `a`. So each live
//! session also retains the in-root links its replayable notices went to, and
//! the close pays whatever its own link does not reach (see [`ReplayLinks`]).
//!
//! [MS-FSA]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/d142c93a-72bc-4b05-9d96-8e00371c3308>
//!
//! A LIVE SESSION IS NOT ONE FACT, IT IS THREE OBLIGATIONS, and they are held
//! apart because they are lost in three different ways:
//!
//! - **what has already been reported** — a noise filter, and only that.
//!   Evicting it re-reports already-reported bits and loses none.
//! - **where a repair must be delivered** — the in-root links the session's
//!   replayable notices went to. An obligation: an eviction surrenders it as a
//!   cover, and a rename RETARGETS it, because the name it was registered under
//!   is exactly what a rename retires.
//! - **what is owed once the table stops tracking the session at all** — the
//!   orphan ledger, because the cap frees an ENTRY and frees no DEBT.
//!
//! There were FOUR. The fourth — whether the subject's location was still
//! provable, and its latent half for a subject whose reported hard links this
//! module cannot enumerate — existed ONLY to answer a second move that writes
//! no record, and the measurement above says every move writes its own two
//! records. It is retired, with everything that fed it; nothing else on this
//! list changes, because nothing else on this list was ever about renames.
//!
//! Holding them as one record is what let each be discharged by a change to
//! another — a link snapshot outliving the name it snapshotted, an eviction
//! read as proof nothing was owed. Every one of them is BOUNDED, and every
//! bound's behaviour when it bites is a covering rescan: bounded ingress is not
//! bounded retention, and the only honest answer to a retention bound is a
//! coarser location, never a quieter stream.
//!
//! A DEBT'S SIZE AND ITS SUBJECT'S LIFETIME ARE TWO DIFFERENT FACTS, and every
//! bound here that failed failed by confusing them. A debt whose subject has
//! CLOSED is a fixed quantity: paying it once settles it, because the journal
//! will never write another record for that open. A debt whose subject is still
//! OPEN is not a quantity at all — it is a standing promise about records NTFS
//! has not written yet, and paying it the moment a bound bites says nothing
//! about the write, the rename or the link that follows. The close that would
//! have said so then finds nothing left to surrender. So no bound in this file
//! answers pressure by settling a debt: at the ledger's bound (see
//! [`OrphanLedger`]) a debt loses its NAME, never its existence.
//!
//! AND A DEBT THAT EXISTS IS STILL ONLY AS GOOD AS THE ORDER IT IS BOOKED IN.
//! Registering an obligation and accounting for it are two stages of one step,
//! and the step is one record wide: no record may be accounted while an earlier
//! one is still waiting to register what it owes, and no record may be lowered
//! after its own accounting has disowned the name it would speak at. See
//! [`UsnAdmission::admit`] for what happens at each end when they come apart.

pub(crate) mod decode;
pub(crate) mod map;
pub(crate) mod premise;

use decode::{UsnName, UsnRecord};
use map::{FrnMap, LearnOutcome};

/// `USN_REASON_*` bits (the stable journal ABI).
pub(crate) mod reason {
  pub(crate) const DATA_OVERWRITE: u32 = 0x1;
  pub(crate) const DATA_EXTEND: u32 = 0x2;
  pub(crate) const DATA_TRUNCATION: u32 = 0x4;
  pub(crate) const NAMED_DATA_OVERWRITE: u32 = 0x10;
  pub(crate) const NAMED_DATA_EXTEND: u32 = 0x20;
  pub(crate) const NAMED_DATA_TRUNCATION: u32 = 0x40;
  pub(crate) const FILE_CREATE: u32 = 0x100;
  pub(crate) const FILE_DELETE: u32 = 0x200;
  pub(crate) const EA_CHANGE: u32 = 0x400;
  pub(crate) const SECURITY_CHANGE: u32 = 0x800;
  pub(crate) const RENAME_OLD_NAME: u32 = 0x1000;
  pub(crate) const RENAME_NEW_NAME: u32 = 0x2000;
  pub(crate) const INDEXABLE_CHANGE: u32 = 0x4000;
  pub(crate) const BASIC_INFO_CHANGE: u32 = 0x8000;
  pub(crate) const HARD_LINK_CHANGE: u32 = 0x1_0000;
  pub(crate) const COMPRESSION_CHANGE: u32 = 0x2_0000;
  pub(crate) const ENCRYPTION_CHANGE: u32 = 0x4_0000;
  pub(crate) const OBJECT_ID_CHANGE: u32 = 0x8_0000;
  pub(crate) const REPARSE_POINT_CHANGE: u32 = 0x10_0000;
  pub(crate) const STREAM_CHANGE: u32 = 0x20_0000;
  pub(crate) const TRANSACTED_CHANGE: u32 = 0x40_0000;
  pub(crate) const INTEGRITY_CHANGE: u32 = 0x80_0000;
  pub(crate) const DESIRED_STORAGE_CLASS_CHANGE: u32 = 0x100_0000;
  pub(crate) const CLOSE: u32 = 0x8000_0000;

  /// The bits this vocabulary deliberately never lowers: object-id and
  /// transaction bookkeeping is filesystem-internal, invisible to a
  /// consumer's tree.
  ///
  /// `INDEXABLE_CHANGE` is NOT among them despite the name: Microsoft defines
  /// it as a change to `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`, a user-settable
  /// attribute the RDCW arm reports through `FILE_NOTIFY_CHANGE_ATTRIBUTES`.
  /// Filtering it here made one Windows backend silent about a mutation the
  /// other reports, which is the drift this vocabulary exists to prevent.
  pub(crate) const FILTERED: u32 = OBJECT_ID_CHANGE | TRANSACTED_CHANGE;

  /// Content mutations that lower to `Modified`.
  pub(crate) const MODIFY: u32 = DATA_OVERWRITE | DATA_EXTEND | DATA_TRUNCATION;

  /// Metadata mutations that lower to `Attrib` (named streams deliberately
  /// among them: an ADS write changes the OWNER file's metadata surface,
  /// never a child object).
  pub(crate) const ATTRIB: u32 = EA_CHANGE
    | SECURITY_CHANGE
    | BASIC_INFO_CHANGE
    | COMPRESSION_CHANGE
    | ENCRYPTION_CHANGE
    | INTEGRITY_CHANGE
    | INDEXABLE_CHANGE
    | DESIRED_STORAGE_CLASS_CHANGE
    | NAMED_DATA_OVERWRITE
    | NAMED_DATA_EXTEND
    | NAMED_DATA_TRUNCATION
    | STREAM_CHANGE;

  /// Structural bits the map (and the lowering's verb choice) act on.
  pub(crate) const STRUCTURAL: u32 =
    FILE_CREATE | FILE_DELETE | RENAME_OLD_NAME | RENAME_NEW_NAME | HARD_LINK_CHANGE;

  /// The two halves of a move.
  ///
  /// Unlike a create or a delete, a move can happen MANY times to one file
  /// reference — and ON NTFS EVERY ONE OF THEM WRITES ITS OWN TWO RECORDS.
  /// Measured, not assumed: the two bits alternate in the accumulated mask
  /// (`0x1100`, `0x2100`, `0x1100`, `0x2100` across two moves on one held
  /// handle), so the rename path clears the opposite half as it sets its own
  /// and neither half is ever suppressed as a repeat. The module header
  /// carries the record stream verbatim — and names the filesystem it was taken
  /// on, which is why the retirement that reads it is scoped by
  /// [`RenameSemantics`] rather than applied to every volume with a journal.
  ///
  /// The set is still named because the PAIRING turns on it — the halves share
  /// a subject and arrive adjacent — and no longer because a re-asserted bit is
  /// evidence of anything.
  pub(crate) const RENAME: u32 = RENAME_OLD_NAME | RENAME_NEW_NAME;

  /// What a rename record proves BESIDES the move — the evidence a naming
  /// verb neither subsumes nor can stand in for.
  ///
  /// A rename lowers to a naming verb, and naming is not evidence: a
  /// `RENAME_OLD_NAME | DATA_OVERWRITE` record proves a move AND a content
  /// change, and NTFS coalescing can make that rename record the ONLY one the
  /// content class ever gets before the close summary. Dropping it leaves a
  /// modified-only or attrib-only subscription told nothing at all, and
  /// narrows what the close replay then has to reconcile against.
  ///
  /// Every rename shape carries this same mask — paired, widowed, and
  /// boundary-degraded alike — so what survives is a property of the record
  /// NTFS wrote rather than of whether the partner half happened to land in
  /// the same read.
  pub(crate) const CONTENT: u32 = MODIFY | ATTRIB;

  /// The classes a session's final `CLOSE` may REPLAY — the answer to NTFS
  /// coalescing every repeat of an already-recorded kind into silence.
  ///
  /// Membership is a property, not a partition: a class belongs here when its
  /// delivery is an instruction to LOOK AGAIN rather than a naming verb, and
  /// when admission derives no map mutation from it. Both halves matter — a
  /// replayed verb would re-announce a create or a delete to every subscriber,
  /// and a replayed map action would re-run a learn or a forget against a
  /// topology that already applied it.
  ///
  /// `HARD_LINK_CHANGE` qualifies despite living in [`STRUCTURAL`]: the
  /// lowering spends it on a located rescan, never on a verb, and admission
  /// reads no map action from it — so it repeats as harmlessly as a content
  /// bit, and a second link change inside one open is precisely the repeat
  /// NTFS writes no record for.
  ///
  /// `FILE_CREATE` and `FILE_DELETE` are absent for a reason stronger than
  /// safety: each can happen at most ONCE in one file reference's lifetime, so
  /// coalescing can never swallow a second one — there is no second one. The
  /// rename halves are now absent for that same stronger reason rather than
  /// because their replay would be unsafe: coalescing swallows no move either,
  /// since every move writes both of its halves (see [`RENAME`]). A replay of
  /// them would announce a naming verb the journal already announced.
  ///
  /// `REPARSE_POINT_CHANGE` is absent because it needs no close-only
  /// treatment: it passes through on EVERY record unconditionally, close
  /// included (see [`SessionTable::delta`](super::SessionTable::delta)).
  pub(crate) const REPLAYABLE: u32 = MODIFY | ATTRIB | HARD_LINK_CHANGE;
}

/// How many DISTINCT in-root links one live session retains as replay
/// targets. Retention is a fixed-size array inside the session entry, so the
/// whole table's link footprint is the product of two constants — a session
/// that keeps naming new links saturates rather than growing.
const REPLAY_LINK_CAP: usize = 4;

/// How many bytes of a link's name one retained target holds inline.
///
/// Inline rather than owned so retention allocates nothing and its ceiling is
/// arithmetic rather than a hope about name lengths. A name that does not fit
/// (or has no Unicode spelling) is ELIDED: the target keeps its parent alone,
/// can never afterwards be PROVEN identical to a closing link, and is
/// therefore covered at its directory — coarser, never wrong, never silent.
const REPLAY_NAME_BYTES: usize = 32;

/// One in-root link a live session's replayable notices were delivered
/// through: the parent directory's reference and the subject's name in it.
///
/// The parent is kept as a reference rather than as resolved components so a
/// directory renamed later in the session still covers at its CURRENT
/// location — the map is the resolver, here as everywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayLink {
  parent: u128,
  name: [u8; REPLAY_NAME_BYTES],
  /// The retained name's length, or `None` when the name was elided.
  name_len: Option<u8>,
}

impl ReplayLink {
  const EMPTY: Self = Self {
    parent: 0,
    name: [0; REPLAY_NAME_BYTES],
    name_len: None,
  };

  fn new(parent: u128, name: &UsnName) -> Self {
    let mut bytes = [0u8; REPLAY_NAME_BYTES];
    let name_len = match name {
      UsnName::Utf8(text) if text.len() <= REPLAY_NAME_BYTES => {
        bytes[..text.len()].copy_from_slice(text.as_bytes());
        u8::try_from(text.len()).ok()
      }
      _ => None,
    };
    Self {
      parent,
      name: bytes,
      name_len,
    }
  }

  /// The retained name, or `None` when it was elided.
  fn name(&self) -> Option<&str> {
    let len = usize::from(self.name_len?);
    std::str::from_utf8(&self.name[..len]).ok()
  }

  /// Whether a record routed at `(parent, name)` names EXACTLY this link — the
  /// one case in which the record's own delivery already reaches it.
  ///
  /// An elided name answers `false`: "cannot prove it is the same link" earns
  /// the same treatment as "proved it is a different one", because the
  /// alternative is to assume a notice was delivered that may not have been.
  fn is(&self, parent: u128, name: &UsnName) -> bool {
    self.parent == parent
      && match (self.name(), name) {
        (Some(retained), UsnName::Utf8(text)) => retained == text,
        _ => false,
      }
  }
}

/// The bounded set of in-root links one live session owes its close replay to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayLinks {
  links: [ReplayLink; REPLAY_LINK_CAP],
  len: u8,
  saturated: bool,
}

impl ReplayLinks {
  const EMPTY: Self = Self {
    links: [ReplayLink::EMPTY; REPLAY_LINK_CAP],
    len: 0,
    saturated: false,
  };

  /// Whether nothing at all is owed (no target retained AND none dropped).
  fn owes_nothing(&self) -> bool {
    self.len == 0 && !self.saturated
  }

  /// The retained targets.
  fn held(&self) -> &[ReplayLink] {
    &self.links[..usize::from(self.len)]
  }

  /// Whether the session named more distinct in-root links than the ceiling
  /// holds. The retained set is then no longer the whole truth, so anything
  /// owed to it is paid with one root-scoped cover instead of an enumeration
  /// that would be silently short.
  fn saturated(&self) -> bool {
    self.saturated
  }

  fn record(&mut self, link: ReplayLink) {
    if self.held().contains(&link) {
      return;
    }
    if usize::from(self.len) == REPLAY_LINK_CAP {
      self.saturated = true;
      return;
    }
    self.links[usize::from(self.len)] = link;
    self.len += 1;
  }

  /// Moves the target retained for one link onto another — a rename's duty.
  ///
  /// A retained target is a NAME, and a rename retires the name it was written
  /// under. Left alone, the repair the session still owes would be aimed at a
  /// path that no longer exists while the live one — the path the consumer's
  /// own state moved to when the move was delivered — receives nothing. So the
  /// debt moves with the link, on every admitted rename, whether or not the
  /// rename record carried any evidence of its own: the debt was established by
  /// an EARLIER record, and a move that proves nothing new still changes where
  /// that earlier notice's repair has to land.
  ///
  /// The bound's behaviour: a retained target in the departed link's directory
  /// whose name was ELIDED can be neither proven to be the moved link nor
  /// proven not to be, and so can neither be retargeted nor left alone with a
  /// clear conscience. The set latches [saturated](Self::saturated) instead, so
  /// the close pays one root-wide cover rather than enumerating a set that may
  /// name a retired path and miss the live one. The same applies when the
  /// DEPARTING name has no Unicode spelling: nothing can be compared against it.
  fn retarget(&mut self, from_parent: u128, from_name: &UsnName, to: ReplayLink) {
    let comparable = matches!(from_name, UsnName::Utf8(_));
    let mut moved = false;
    for slot in 0..usize::from(self.len) {
      let held = self.links[slot];
      if held.is(from_parent, from_name) {
        self.links[slot] = to;
        moved = true;
      } else if held.parent == from_parent && (!comparable || held.name().is_none()) {
        self.saturated = true;
      }
    }
    if moved {
      self.dedupe();
    }
  }

  /// Collapses targets a retarget made identical. Retention counts DISTINCT
  /// links, and a retarget can land one on top of another, so the count is
  /// re-established rather than left to drift above the truth.
  fn dedupe(&mut self) {
    let mut kept = 0usize;
    for slot in 0..usize::from(self.len) {
      let link = self.links[slot];
      if self.links[..kept].contains(&link) {
        continue;
      }
      self.links[kept] = link;
      kept += 1;
    }
    for slot in kept..usize::from(self.len) {
      self.links[slot] = ReplayLink::EMPTY;
    }
    self.len = u8::try_from(kept).unwrap_or(self.len);
  }
}

/// Replay targets that outlived the session state holding them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stranded {
  /// Nothing was surrendered.
  Nothing,
  /// THIS record's session retired at its close. The record's own link may be
  /// among the targets, in which case its ordinary delivery already reaches it.
  Retired(ReplayLinks),
  /// The table evicted an UNRELATED live session to make room for this record.
  /// Nothing in this record's routing reaches those targets, so every one of
  /// them is owed.
  Evicted(ReplayLinks),
}

/// Whether THIS VOLUME'S filesystem is the one the rename measurement was taken
/// on — the single switch that scopes the repeat-rename retirement to the
/// evidence that licensed it.
///
/// The measurement (module header) renamed one file twice through one held
/// handle on NTFS and watched the two rename bits ALTERNATE, which is what makes
/// every move's halves fresh and every move therefore self-reporting. Nothing
/// was measured on any other filesystem, and the source admits any volume whose
/// journal speaks record version 2 or 3 — ReFS among them. On a filesystem whose
/// bits might instead ACCUMULATE, a second move on one open handle writes a word
/// production's delta discards, and the location it changed goes unreported.
///
/// So the retirement is a property of the VOLUME, not of the arm, and this type
/// is where a source states which volume it is on. The conservative behaviour it
/// selects is not a new invention: it is the location and topology debt this
/// module paid everywhere before the measurement existed, kept alive for exactly
/// the filesystems the measurement does not speak for.
///
/// DELIBERATELY NOT [`Default`]. `Measured` is the answer the crate's own cells
/// want and the answer a real volume must EARN, and those are not the same
/// thing: a type that hands out the retirement to whoever forgets to ask is the
/// shape of the defect this switch exists to close. It is named at each
/// construction instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenameSemantics {
  /// NTFS: the filesystem the record stream on this module's header came from,
  /// where every move writes both of its halves and both are fresh. The
  /// retirement applies and no location debt is booked.
  Measured,
  /// Any other filesystem with an active V2/V3 journal. Its rename accounting is
  /// unobserved, so a session that renamed and then closed may have moved again
  /// in silence, and the close pays the cover that possibility requires.
  Unmeasured,
}

impl RenameSemantics {
  /// Whether a session that renamed on this volume may have moved again without
  /// writing a record — the question the whole retirement turns on.
  const fn a_second_move_may_be_silent(self) -> bool {
    matches!(self, Self::Unmeasured)
  }
}

/// An obligation the table can still NAME nothing for — the debt survived the
/// links (or the entry) that said where it was owed.
///
/// Every field here is paid at the ROOT, because the root is the only location
/// that is provably a superset of a location nobody can name. That is the
/// standing rule for every bound in this file: a bound that bites degrades to a
/// cover, never to silence. "Bounded ingress is not bounded retention" — the
/// cap on how many sessions are TRACKED says nothing about how much is OWED,
/// and the two are accounted separately for exactly that reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Unnamed {
  /// A [replayable](reason::REPLAYABLE) repair is owed and the in-root links it
  /// was owed to are gone. Paid with one root-scoped cover.
  pub(crate) replay: bool,
  /// A subject's own LOCATION can no longer be proven current: it renamed inside
  /// a session, and on this volume a further move may have written nothing. Paid
  /// with one root-scoped cover, because the move nobody saw named no link
  /// anything here can enumerate.
  ///
  /// Raised only where [`RenameSemantics::Unmeasured`] says the volume's rename
  /// accounting is unobserved. On NTFS — the filesystem the measurement was
  /// taken on — every move writes its own two records, so this is never owed and
  /// the source pays nothing for it.
  pub(crate) location: bool,
  /// The map itself can no longer be trusted, so every path resolved through it
  /// is a guess. Paid with the reseed spine — the root-wide cover the map
  /// verdict already lowers to, plus the fresh walk that rebuilds what the cover
  /// disowned.
  ///
  /// Two producers. The [ledger's](OrphanLedger) anonymous residue, which is not
  /// about any subject's location and which every close pays until a reseed lets
  /// it stop standing; and — on an [unmeasured](RenameSemantics::Unmeasured)
  /// volume only — a mapped DIRECTORY whose rename may have been followed by one
  /// that wrote no record, since a directory's stale parent link makes every
  /// path beneath it a guess rather than just its own.
  pub(crate) topology: bool,
}

impl Unnamed {
  const NOTHING: Self = Self {
    replay: false,
    location: false,
    topology: false,
  };

  /// The reseed spine — what the [ledger's](OrphanLedger) anonymous residue is
  /// paid with, because it is the only statement that also lets the residue stop
  /// standing.
  const RESEED: Self = Self {
    replay: false,
    location: false,
    topology: true,
  };

  /// Whether nothing at all is owed.
  fn owes_nothing(self) -> bool {
    self == Self::NOTHING
  }

  /// Every obligation held here, since none of them discharges another.
  fn with(self, other: Self) -> Self {
    Self {
      replay: self.replay || other.replay,
      location: self.location || other.location,
      topology: self.topology || other.topology,
    }
  }

  /// Whether anything owed here is paid by ONE root-scoped cover. Both such
  /// obligations name no location, and the root is the only place provably a
  /// superset of a location nobody can name, so one cover settles both.
  fn covers_at_root(self) -> bool {
    self.replay || self.location
  }

  /// Whether the RECORD whose accounting raised this debt may still be lowered
  /// against the tree it names.
  ///
  /// Both fields answering here are statements about a NAME nothing can prove
  /// current — a subject's own [location](Self::location), or the
  /// [map](Self::topology) every name is resolved THROUGH — and the record that
  /// pays for such a cover would speak at exactly the name the cover calls
  /// unprovable. Paying the cover and then delivering at that name is strictly
  /// worse than either alone: the consumer re-enumerates at the rescan and is
  /// immediately re-diverged by an event the rescan exists BECAUSE nobody can
  /// trust. So the cover is that record's last word.
  ///
  /// [`replay`](Self::replay) is deliberately absent. It says a repair is owed
  /// somewhere nobody can name; it says nothing about whether THIS record's own
  /// name is current, and suppressing an honest delivery over it would spend
  /// convergence to buy nothing.
  fn disowns_its_record(self) -> bool {
    self.location || self.topology
  }
}

/// What one record's arrival did to the bounded session table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionOutcome {
  /// The reason bits this record reports: its fresh bits, plus — at the
  /// session's final `CLOSE` — the unconditional replay.
  pub(crate) mask: u32,
  /// Replay targets the table surrendered while admitting this record — a
  /// debt whose destinations are still NAMED.
  pub(crate) stranded: Stranded,
  /// Debt whose destinations are not. Paid at the root.
  pub(crate) unnamed: Unnamed,
}

/// One live open session's retained state — TWO obligations, held apart
/// because they are lost in two different ways and each one's loss has to
/// degrade to its own cover.
///
/// Holding them as one undifferentiated record is what let each of them be
/// discharged by a change to another: a link snapshot outlived the name it
/// snapshotted, and an eviction that freed the entry was read as proof nothing
/// was owed.
///
/// A THIRD FIELD IS DELIBERATELY ABSENT. This entry used to also carry whether
/// the subject's location was still provable — a rename having been accounted
/// meant a further move on the same handle would write no record — plus the
/// LATENT half of that flag for a subject whose reported hard links this module
/// cannot enumerate, plus the `is_dir` that decided which cover the loss bought.
/// All three answered an unrecorded second move, and on NTFS the journal writes
/// every move's two records (this module's header carries the measurement). They
/// are retired, and the entry that once described "what may have happened in
/// silence" now describes only what was delivered and where.
///
/// KEEPING THE COVER FOR UNMEASURED FILESYSTEMS BROUGHT NONE OF THEM BACK, and
/// that is a property of where the evidence lives rather than a lucky escape.
/// The cover's trigger is a `CLOSE` whose rename bits its session already held,
/// which is `last` — already here. Which cover it buys is the subject's kind,
/// which the CLOSING RECORD's own attributes state. Neither question needs a
/// memory of its own, so [`RenameSemantics`] costs the TABLE one byte and costs
/// the entry nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Session {
  /// WHAT HAS ALREADY BEEN REPORTED. A noise filter and nothing else: losing
  /// it re-reports bits the consumer already heard, which is why an eviction
  /// may drop it freely.
  last: u32,
  /// WHERE A REPAIR MUST BE DELIVERED — the in-root links this session's
  /// replayable notices went to. An obligation, not an observation: losing it
  /// silently is a consumer left describing a half-written file.
  links: ReplayLinks,
}

impl Session {
  const EMPTY: Self = Self {
    last: 0,
    links: ReplayLinks::EMPTY,
  };
}

/// The debts of sessions the table no longer tracks, held until the one record
/// that proves nothing more can be added to them.
///
/// THIS TYPE HAS NO OPERATION THAT LETS GO OF A DEBT. [`owe`](Self::owe) only
/// ever adds; there is no `evict`, no `trim`, no `clear`, and the single removal
/// — [`settle`](Self::settle) — takes the file reference off a `CLOSE` record,
/// which is the one proof this arm can obtain that a debt has stopped growing.
/// "The bound bit, so a record was dropped and one cover paid" is therefore not
/// a thing that can be written against this store: at the bound the only
/// reachable operation is still `owe`.
///
/// # The behaviour at the bound
///
/// A marker drains only at a close, and a session that is never closed (a log, a
/// database) never produces one, so the NAMED set has to stop growing. Past it a
/// debt keeps everything except its subject's identity and joins one ANONYMOUS
/// residue — "some session this table stopped tracking owes a cover, and goes on
/// owing it until it closes". One flag, O(1), and it cannot be exhausted, which
/// is the whole reason the naming is what gets surrendered.
///
/// A residue that names nobody is owed at EVERY close while it stands, because
/// any of them may be the debtor's — including a close whose own session the
/// table tracked from birth, since a record arriving after the eviction rebuilds
/// an entry that knows nothing of what preceded it. And it is paid with the
/// [reseed spine](Unnamed::RESEED) rather than the plain root cover most of the
/// folded debts asked for. Not because a reseed is what they asked for, but
/// because it is the only payment that also lets the residue stop standing: a
/// residue paid with a cover would still be owed afterwards, and every close on
/// the volume would buy another one for as long as the source lived. The reseed
/// re-establishes the map, the tree and this table together, and
/// [`reset_sessions`](super::UsnAdmission::reset_sessions) is where the residue
/// is finally let go — the one place in this file where what is forgotten was
/// published first.
///
/// The cost is stated rather than hidden: reaching the bound costs one full
/// re-walk at the next close. Reaching it at all takes `cap` distinct evicted
/// sessions owing covers at once with none of them closed.
#[derive(Debug)]
struct OrphanLedger {
  named: std::collections::BTreeMap<u128, Unnamed>,
  /// Whether a debt has been folded in whose subject can no longer be named.
  anonymous: bool,
  cap: usize,
}

impl OrphanLedger {
  /// An empty ledger holding at most `cap` NAMED debts (and, past that, one
  /// residue).
  fn new(cap: usize) -> Self {
    Self {
      named: std::collections::BTreeMap::new(),
      anonymous: false,
      cap,
    }
  }

  /// Adds `debt` to what `frn` owes.
  ///
  /// The only way in, and it is monotone: an existing marker takes the union
  /// (nothing an earlier eviction established can be undone by a later one), and
  /// at the bound the debt is folded into the anonymous residue rather than
  /// displacing a marker. Displacing one would settle the displaced session's
  /// debt while that session was still open, which is the defect the residue
  /// exists to make unreachable.
  fn owe(&mut self, frn: u128, debt: Unnamed) {
    if debt.owes_nothing() {
      // The ledger is an obligation store, not an eviction log: filling its
      // bound with sessions that delivered nothing would spend the whole thing
      // on covers nobody is owed.
      return;
    }
    if let Some(standing) = self.named.get_mut(&frn) {
      *standing = standing.with(debt);
      return;
    }
    if self.named.len() >= self.cap {
      self.anonymous = true;
      return;
    }
    self.named.insert(frn, debt);
  }

  /// What the `CLOSE` of `frn` must pay: this subject's own marker, which the
  /// close settles, plus the residue, which it does not.
  ///
  /// The asymmetry is the point. Removing the marker is safe because the close
  /// proves this session can add nothing further; the residue names nobody, so
  /// no close proves that about it and it stays standing.
  fn settle(&mut self, frn: u128) -> Unnamed {
    let named = self.named.remove(&frn).unwrap_or_default();
    if self.anonymous {
      named.with(Unnamed::RESEED)
    } else {
      named
    }
  }

  /// How many evicted sessions the ledger can still name a debt for.
  fn named_len(&self) -> usize {
    self.named.len()
  }
}

/// The bounded per-session table that turns cumulative reasons into deltas and
/// remembers where the close replay is owed.
///
/// One entry per live open session. Nothing about the CHANGES is remembered
/// beyond the last mask, because nothing else is KNOWABLE — the journal never
/// reports a repeat, so no amount of bookkeeping over the records that do
/// arrive can tell a session that kept changing from one that stopped. What is
/// remembered besides is where its notices WENT and whether its name still
/// stands, which the records do state.
///
/// Alongside the live entries the table keeps an [ORPHAN LEDGER](OrphanLedger):
/// the file references whose entry the cap took while the session was still
/// open. The entry is what the cap buys back, so the ledger holds no links and
/// no mask — only the fact THAT something is owed. Without it the cap converts
/// pressure into permanent loss: an evicted session goes on changing, NTFS
/// writes no record for a class already in its mask, and the close that finally
/// arrives finds no entry, surrenders nothing, and the change is never reported
/// at all. With it the close pays at the root. The ledger is bounded too, and at
/// its bound a debt gives up its NAME and nothing else.
#[derive(Debug)]
pub(crate) struct SessionTable {
  live: std::collections::BTreeMap<u128, Session>,
  owed: OrphanLedger,
  /// Whether this volume is the one the rename measurement was taken on. NOT
  /// per entry: it is a fact about the filesystem, so it costs one byte for the
  /// whole table and leaves the entry the measured constant it has to stay.
  renames: RenameSemantics,
  pub(self) cap: usize,
}

impl SessionTable {
  /// A table bounded at `cap` live sessions (and at `cap` named orphan debts),
  /// for a volume whose rename semantics are the MEASURED ones.
  ///
  /// The default names NTFS because that is the filesystem every cell in this
  /// crate models and the only one the measurement speaks for. A source reading
  /// a REAL volume is the only caller that can know, and states what it read
  /// with [`with_rename_semantics`](Self::with_rename_semantics).
  pub(crate) fn new(cap: usize) -> Self {
    Self {
      live: std::collections::BTreeMap::new(),
      owed: OrphanLedger::new(cap),
      renames: RenameSemantics::Measured,
      cap,
    }
  }

  /// Returns this table accounting for a volume whose rename semantics are
  /// `renames` — the switch that scopes the repeat-rename retirement to the
  /// filesystem it was measured on.
  #[must_use]
  pub(crate) fn with_rename_semantics(mut self, renames: RenameSemantics) -> Self {
    self.renames = renames;
    self
  }

  /// The mask bits `record` reports that the consumer has not already been
  /// told — plus, at the session's final `CLOSE`, an UNCONDITIONAL replay of
  /// every [replayable](reason::REPLAYABLE) class the summary carries, and the
  /// [links](ReplayLinks) that replay is owed to. A full table evicts an
  /// arbitrary session first, surrendering ITS links the same way (the evicted
  /// subject's mask is free to go: its next record re-reports, never
  /// under-reports).
  ///
  /// The replay is what makes the journal arm CONVERGE, and it is
  /// unconditional because NTFS gives it nothing to be conditional ON. A
  /// repeat of an already-recorded kind writes no record: `write, write,
  /// close` is `DATA_OVERWRITE`, then nothing at all, then
  /// `DATA_OVERWRITE | CLOSE`. That is byte-for-byte the stream `write, close`
  /// produces, so at the close the source can prove "this class changed at
  /// least once during the session" and can NEVER prove "and not since your
  /// last notice". Arming the replay off an observation — a record whose mask
  /// was entirely repeated — armed it off traffic the filesystem does not
  /// emit: the flag stayed clear, the close re-reported nothing, and a
  /// consumer that read the file at the first write described it mid-write
  /// forever.
  ///
  /// The cost is a duplicate, and it is chosen. A one-write session now
  /// delivers a `Modified` at the write AND at the close. Delivering only at
  /// the close would spend nothing extra, but a file that stays open — a log,
  /// a database — produces no close record for as long as it is held, and even
  /// then only once the LAST opener leaves, so close-only delivery has no
  /// latency bound at all. A duplicate is noise a consumer reads through;
  /// silence is a consumer describing a half-written file with nothing left in
  /// the stream to correct it, and that is the trade this arm refuses.
  ///
  /// Per-class separation therefore holds by CONSTRUCTION rather than by
  /// bookkeeping: the close replays the whole replayable mask, so no fresh
  /// record of one evidence class can discharge another class's debt. It once
  /// could — `DATA_EXTEND`, an unheard repeat, then
  /// `DATA_EXTEND | BASIC_INFO_CHANGE` — after which the close was silent
  /// about content and a modified-only subscriber, which never hears an
  /// `Attrib` at all, had nothing left to correct its newest delivery.
  ///
  /// WHERE the replay lands is a separate question from what it carries, and
  /// the summary answers it about the closing handle's link only. The retired
  /// session's [`ReplayLinks`] answer it about every in-root link the session's
  /// earlier notices actually went to; the caller pays the difference.
  ///
  /// # A CLOSE BUYS NO COVER FOR THE RENAME BITS IT CARRIES ON NTFS, AND WHY
  ///
  /// It used to. A summary re-asserting a [rename](reason::RENAME) bit its
  /// session already held was read as proof those bits were STANDING before the
  /// close, and a move made while they stand was believed to write no record —
  /// so the subject's location was treated as unproven and paid for with a
  /// root-scoped cover, plus a reseed when the subject was a mapped directory.
  /// A second, LATENT debt rode alongside it for a FILE whose observed rename
  /// endpoints were all outside the reported tree, because a file reference can
  /// carry hard links this module cannot enumerate and the silent move might
  /// have been of a watched one.
  ///
  /// BOTH RESTED ON A SILENT SECOND MOVE, AND THERE IS NO SILENT SECOND MOVE.
  /// The journal was measured on real NTFS — two moves through one held handle —
  /// and wrote every half of both: `0x1100`, `0x2100`, `0x1100`, `0x2100`, then
  /// `0x80002100 CLOSE`. The record stream, the runners it came from and the
  /// cell that takes it are on this module's header. The rename bits ALTERNATE
  /// rather than accumulate, so the rename path clears the opposite half as it
  /// sets its own and no move ever meets its own bits already standing.
  ///
  /// WHAT THE MEASUREMENT COVERS, AND WHAT RESTS ON THE MECHANISM IT SHOWS. It
  /// renamed one FILE, twice, through one handle, with nothing interleaved. The
  /// three shapes it does not itself perform are answered by the mechanism it
  /// exposes rather than by a second assumption:
  ///
  /// - ANOTHER HARD LINK of the same reference — the case the latent debt
  ///   existed for. The accumulated reason word belongs to the OPEN, which is
  ///   the file object, not to a link; a rename of any link runs the same
  ///   journal path and applies the same clear-then-set. There is no state in
  ///   which link B's move finds its bits standing, because link A's move left
  ///   exactly one of the two set and B's departing half is the other.
  ///   `usn_repeat_rename_across_two_hard_links_writes_which_records` measures
  ///   this directly, and ENFORCES it: the cell fails unless link B's move
  ///   arrives as an ordered, correctly named pair whose halves are fresh under
  ///   this very table's delta AND joined by the very pairer the source pairs
  ///   with (see [`premise`](super::premise)). A gate that cannot fail licenses
  ///   nothing, and this one is load-bearing for a deletion.
  /// - A RENAME INTERLEAVED with other classes. A write between two moves ORs a
  ///   content bit into the word and touches neither rename bit, so the second
  ///   move's departing half is still fresh.
  /// - A DIRECTORY. Same journal path, and a directory has exactly one link, so
  ///   the link question does not even arise for it.
  ///
  /// So on NTFS a close's rename bits are read as nothing at all here, and every
  /// move a session makes is reported by the two records the move itself writes.
  /// [`UsnAdmission::admit`](super::UsnAdmission::admit) states what that
  /// retirement returns.
  ///
  /// # AND ON A FILESYSTEM NOBODY MEASURED, THE COVER STAYS
  ///
  /// Every sentence above is a claim about NTFS, because NTFS is the only thing
  /// the cells ran on. The source admits any volume with an active V2/V3
  /// journal, ReFS included, and a filesystem whose rename bits ACCUMULATE would
  /// make a second move on one open handle write a word this table's delta
  /// discards — the exact silence the retired cover existed for.
  ///
  /// So on an [unmeasured](RenameSemantics::Unmeasured) volume the cover is
  /// still paid, off the same evidence it always was: a `CLOSE` whose rename
  /// bits its session ALREADY held. A file's stale name is one root-scoped cover
  /// ([`Unnamed::location`]); a mapped directory's is the reseed spine
  /// ([`Unnamed::topology`]), because a directory's stale parent link makes every
  /// path beneath it a guess as well. Which of the two is read off the CLOSING
  /// RECORD's own attributes rather than remembered per session — the subject is
  /// the same object either way, and reading it from the record keeps the entry
  /// the fixed-size constant a bounded table needs.
  pub(crate) fn observe(&mut self, record: &UsnRecord) -> SessionOutcome {
    let seen = self.live.get(&record.frn).map_or(0, |session| session.last);
    let fresh = record.reason & !seen;
    if record.reason & reason::CLOSE != 0 {
      let retired = self.live.remove(&record.frn);
      // The ledger's marker comes due HERE: the close is the one record that
      // proves the session the cap forgot is finally over — and, for a debt the
      // ledger's own bound left anonymous, the one record that MIGHT be that
      // proof, which is why the residue rides along on every close.
      let mut unnamed = self.owed.settle(record.frn);
      // The retired cover, kept alive exactly where its retirement is unproven.
      // The evidence is what it always was — a summary re-asserting rename bits
      // the session already held — and it is read only when this volume's rename
      // accounting was never observed. `retired.is_some()` is implied by a
      // non-zero `seen`, so the entry is not consulted for it.
      if self.renames.a_second_move_may_be_silent() && record.reason & seen & reason::RENAME != 0 {
        unnamed = unnamed.with(Unnamed {
          replay: false,
          location: !record.is_dir(),
          topology: record.is_dir(),
        });
      }
      let links = retired.map_or(ReplayLinks::EMPTY, |session| session.links);
      // The replay is taken from the RECORD's mask, not from what was
      // emitted: a cumulative summary already contains everything the session
      // ever carried, and an evicted or reseeded session remembers nothing
      // while the summary still knows it all.
      return SessionOutcome {
        mask: (fresh & !reason::CLOSE)
          | (record.reason & reason::REPLAYABLE)
          | (record.reason & reason::REPARSE_POINT_CHANGE),
        stranded: if links.owes_nothing() {
          Stranded::Nothing
        } else {
          Stranded::Retired(links)
        },
        unnamed,
      };
    }
    let mut stranded = Stranded::Nothing;
    if fresh != 0 {
      if self.live.len() >= self.cap && !self.live.contains_key(&record.frn) {
        // An evicted session's MASK is free to go — its subject's next record
        // re-reports rather than under-reports. Its replay TARGETS are not:
        // dropping them silently is the same stranded notice a foreign closing
        // link produces, reachable at the cap instead of through hard links.
        // They are surrendered to the caller, which covers them in-band.
        let evict = self.live.keys().next().copied();
        if let Some(evict) = evict
          && let Some(session) = self.live.remove(&evict)
        {
          if !session.links.owes_nothing() {
            stranded = Stranded::Evicted(session.links);
          }
          // Surrendering the links covers what the session changed BEFORE the
          // eviction, and nothing else. The subject is still open: a repeat of
          // a class already in its mask writes no record, and the close that
          // would have repaired it now finds no entry to surrender. So the FACT
          // of the debt outlives the entry — the ledger keeps the file
          // reference and nothing else, and the close pays it at the root.
          //
          // ON NTFS A RENAME LEAVES NOTHING HERE, and that is the retirement
          // rather than an omission. The entry used to also carry that a rename
          // bit had been accounted, because the close would otherwise find no
          // entry to compare its re-asserted bits against; every move writes its
          // own two records, so the move that happens after the eviction reports
          // itself and needs no memory of the one before it. What still cannot
          // report itself is a REPEATED WRITE, and that is exactly what survives
          // here.
          //
          // On an unmeasured volume it does leave something, and it leaves the
          // COARSER of the two forms on purpose: the entry the cap takes is the
          // only place that knew whether the subject was a directory, and the
          // ledger's marker deliberately holds nothing but the fact of a debt.
          // Guessing the kind here would be guessing about the one thing the
          // cover exists to stop guessing about, so the debt is booked as
          // topology — the reseed dominates the plain cover, and paying more at
          // a bound that has already bitten is the standing rule in this file.
          let debt = Unnamed {
            replay: !session.links.owes_nothing(),
            location: false,
            topology: self.renames.a_second_move_may_be_silent()
              && session.last & reason::RENAME != 0,
          };
          self.owed.owe(evict, debt);
        }
      }
      let session = self.live.entry(record.frn).or_insert(Session::EMPTY);
      session.last = record.reason;
    }
    // A record whose mask is entirely repeated is not traffic NTFS produces,
    // so nothing is learned from one and the remembered mask is left alone:
    // overwriting it with a SUBSET would un-report bits already delivered.
    //
    // The reparse bit is TOPOLOGY, and it is the one class whose second
    // transition inside a session must reach the map: an add-then-remove
    // writes only the first record, so the close summary is where the removal
    // surfaces — and the record's own `attributes` word, not the bit, says
    // which way the boundary now stands. It therefore passes through on every
    // record including the close (its map actions are safe to re-run).
    SessionOutcome {
      mask: fresh | (record.reason & reason::REPARSE_POINT_CHANGE),
      stranded,
      // An eviction pays no unnamed debt in band. What it surrendered is
      // covered through `stranded`; what it could not name is owed by a session
      // that is still open, and the only record that can honestly settle that
      // is the one proving the session is over.
      unnamed: Unnamed::NOTHING,
    }
  }

  /// Remembers the in-root link one delivery was routed through, so the
  /// session's close can still reach it when the closing record names another.
  ///
  /// A no-op for a subject with no live session, which is exactly the CLOSE
  /// record's own delivery: [`observe`](Self::observe) has already retired that
  /// session, and a notice delivered BY the replay is owed no further replay.
  ///
  /// EVERY site that reaches an in-root link with a [replayable](reason::REPLAYABLE)
  /// class in play calls this, and the list is closed — a site that delivers
  /// without registering strands its own repair:
  ///
  /// - [`admit_single`](super::UsnAdmission::admit_single), which also carries
  ///   the widowed rename halves (they lower through it as synthetics on the
  ///   same link);
  /// - [`admit_rename`](super::UsnAdmission::admit_rename), for the paired shape
  ///   and for both boundary degrades — the halves' `*_content` masks are
  ///   delivered evidence exactly as a widow's are.
  ///
  /// "In play" is the session's CUMULATIVE history, not the record's own bits:
  /// see [`owes_replay`](Self::owes_replay). A link the subject merely arrives
  /// at mid-session is a link everything further it does is silent at.
  /// [`retarget_link`](Self::retarget_link) is the other half of the same duty —
  /// registering where a notice lands is worth nothing if the registration
  /// cannot follow the name.
  ///
  /// Two sites deliver replayable classes and deliberately register NOTHING,
  /// each because it provably cannot strand:
  ///
  /// - the ROOT anchor's own self-event arm. Records naming the root subject are
  ///   routed by `is_root`, never by their link, so every later record for that
  ///   subject — its close included — lands at the root's own location; NTFS
  ///   also forbids hard links to directories, so no second name exists to
  ///   strand a notice at.
  /// - [`cover_stranded`](super::UsnAdmission::cover_stranded), whose deliveries
  ///   ARE the replay. Its session is already retired or evicted, so a call here
  ///   would be a proven no-op.
  ///
  /// THIS ONE BELONGS IN THE LOWERING, and the distinction is worth stating
  /// because it is what makes the placement safe rather than merely convenient.
  /// What is registered here is a place a NOTICE WENT, so it is CREATED BY the
  /// delivery: a lowering discarded for naming an endpoint outside the reported
  /// tree delivered nothing there, left no consumer state there, and owes no
  /// repair there. There is nothing for a discarded lowering to lose, which is
  /// exactly why a discard may reach this registration and may not reach the
  /// [ACCOUNTING](Self::observe) — every record passes through the accounting
  /// once, in journal order, whatever its lowering later does with it.
  /// [`retarget_link`](Self::retarget_link) sits on this side too: it moves a
  /// debt registered HERE, and a name past the fence can never have been
  /// registered here to begin with.
  pub(crate) fn note_link(&mut self, frn: u128, parent: u128, name: &UsnName) {
    if let Some(session) = self.live.get_mut(&frn) {
      session.links.record(ReplayLink::new(parent, name));
    }
  }

  /// Moves the debt retained for one link onto another — the duty of EVERY
  /// admitted rename, and deliberately not conditioned on the rename record
  /// carrying evidence of its own.
  ///
  /// The debt belongs to the SUBJECT, and a rename retires the name it was
  /// registered under. A move that proves nothing new still moves where the
  /// consumer's state for that subject lives, so a repair still owed from an
  /// earlier record has to follow it; leaving it behind aims the close's cover
  /// at a path the rename retired and leaves the live one uncorrected.
  ///
  /// See [`ReplayLinks::retarget`] for the behaviour when the departed link
  /// cannot be told apart from another retained one.
  pub(crate) fn retarget_link(
    &mut self,
    frn: u128,
    from_parent: u128,
    from_name: &UsnName,
    to_parent: u128,
    to_name: &UsnName,
  ) {
    if let Some(session) = self.live.get_mut(&frn) {
      session
        .links
        .retarget(from_parent, from_name, ReplayLink::new(to_parent, to_name));
    }
  }

  /// Whether this session's CUMULATIVE history already contains a
  /// [replayable](reason::REPLAYABLE) class — that is, whether a further change
  /// of that class would now be written as no record at all.
  ///
  /// The question a delivery site asks before deciding whether the link it is
  /// about to deliver at needs retaining. A fresh replayable bit obviously does;
  /// so does a link the session ARRIVES at with such a bit already standing,
  /// because everything it can still do to that link is already silent.
  pub(crate) fn owes_replay(&self, frn: u128) -> bool {
    self
      .live
      .get(&frn)
      .is_some_and(|session| session.last & reason::REPLAYABLE != 0)
  }

  /// How many sessions the table currently tracks.
  pub(crate) fn len(&self) -> usize {
    self.live.len()
  }

  /// How many evicted sessions the ledger can still NAME a root cover for.
  /// Debts past that bound are owed by the anonymous residue and are not
  /// counted here — nothing about them is countable.
  pub(crate) fn orphans(&self) -> usize {
    self.owed.named_len()
  }
}

/// One journal event after pairing — what the source lowers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsnEvent {
  /// A non-rename record (its delta mask attached by the session table).
  Single(UsnRecord),
  /// An atomically paired rename: the OLD and NEW halves share the FRN.
  Renamed {
    /// The departing half (`RENAME_OLD_NAME` in its delta).
    old: UsnRecord,
    /// The arriving half (`RENAME_NEW_NAME` in its delta).
    new: UsnRecord,
  },
  /// An OLD half whose NEW never arrived.
  WidowOld(UsnRecord),
  /// A NEW half with no OLD held.
  WidowNew(UsnRecord),
}

/// The FRN-keyed rename pairing state: at most one OLD half carried between
/// records (and across read boundaries) — the RDCW carry-slot shape, with
/// the journal's stronger key (rename halves SHARE the subject FRN).
#[derive(Debug, Default)]
pub(crate) struct UsnPairer {
  pending_old: Option<UsnRecord>,
}

impl UsnPairer {
  /// A fresh pairer with an empty carry slot.
  pub(crate) const fn new() -> Self {
    Self { pending_old: None }
  }

  /// Feeds one record (with `delta` as its fresh mask) in journal order,
  /// appending completed events to `out`.
  pub(crate) fn push(&mut self, record: UsnRecord, delta: u32, out: &mut Vec<UsnEvent>) {
    let is_old = delta & reason::RENAME_OLD_NAME != 0;
    let is_new = delta & reason::RENAME_NEW_NAME != 0;
    if is_old && !is_new {
      self.flush(out);
      self.pending_old = Some(record);
      return;
    }
    if is_new {
      match self.pending_old.take() {
        Some(old) if old.frn == record.frn => {
          out.push(UsnEvent::Renamed { old, new: record });
        }
        Some(stranger) => {
          out.push(UsnEvent::WidowOld(stranger));
          out.push(UsnEvent::WidowNew(record));
        }
        None => out.push(UsnEvent::WidowNew(record)),
      }
      return;
    }
    // Any other record breaks adjacency: the held OLD widows first.
    self.flush(out);
    out.push(UsnEvent::Single(record));
  }

  /// Widows the held OLD, if any — the read-boundary, loss-barrier, and
  /// teardown flush.
  pub(crate) fn flush(&mut self, out: &mut Vec<UsnEvent>) {
    if let Some(old) = self.pending_old.take() {
      out.push(UsnEvent::WidowOld(old));
    }
  }

  /// Whether an OLD half is parked — the source's cue to bound its next
  /// journal wait.
  pub(crate) fn holds_old(&self) -> bool {
    self.pending_old.is_some()
  }

  /// Whether the parked OLD half must be LOWERED before `record` is accounted
  /// — whether accounting for `record` takes away the session entry the half's
  /// own registrations have to be made against.
  ///
  /// A carry is an earlier record already observed and not yet lowered, so
  /// everything its DELIVERY owes in-root is still UNBOOKED: the link that
  /// delivery reaches, and the retarget its move owes an earlier delivery. Both
  /// are booked against a LIVE entry for the subject, so the carry may wait only
  /// for a record that leaves that entry standing. Two shapes do not:
  ///
  /// - A record for ANOTHER subject. It can never complete this half — halves
  ///   pair on the subject's file reference — and at the table's cap it can
  ///   EVICT the entry to make room for its own.
  /// - This subject's own `CLOSE`. It may well complete the half; a merged
  ///   `RENAME_NEW_NAME | CLOSE` is one record carrying both. But
  ///   [`observe`](SessionTable::observe) RETIRES the entry before the pairing
  ///   is decided, and retirement is exactly the moment the registrations are
  ///   read out — the only moment. "It cannot pair" was never the question; "its
  ///   obligations are still unbooked and this record ends the subject" is.
  ///
  /// What this guard does NOT reach, and what nothing of its shape could: a half
  /// whose own endpoint is not in the reported tree registers nothing however
  /// punctually it is drained. That is not a loss — a delivery that never
  /// happened owes no repair — so the drain's whole subject is the LINK
  /// registrations of the halves that DID deliver in-root.
  ///
  /// Both halves are answerable off the RAW record, before its mask has been
  /// turned into a delta, which is what lets the admission ask this ahead of
  /// everything else it does: the subject is a file reference, and a `CLOSE`
  /// bit is a `CLOSE` bit whether or not it is fresh.
  pub(crate) fn holds_old_whose_entry_this_record_takes(&self, record: &UsnRecord) -> bool {
    self
      .pending_old
      .as_ref()
      .is_some_and(|old| old.frn != record.frn || record.reason & reason::CLOSE != 0)
  }
}

/// A resolved event target: the subject's root-relative components, or the
/// deepest location the escalation can still name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsnTarget {
  /// The subject, root-relative (empty = the root itself — a self-event).
  Resolved(Vec<String>),
  /// COVER this location rather than name a verb at it — the deepest place the
  /// escalation can still point to (empty = the whole root).
  ///
  /// Two shapes reach it. A subject whose name has no Unicode spelling can
  /// only name its parent. And a notice whose verb cannot be attributed to the
  /// location — a close replay owed to a link the closing record does not name
  /// — points at that link itself: the class changed at least once, but not at
  /// a moment or through a handle this record can speak for.
  EscalateAt(Vec<String>),
}

/// One admitted journal event — membership-checked, map-mutated, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsnAdmitted {
  /// A single-subject event with its fresh reason bits.
  Single {
    /// The fresh (delta) reason bits.
    delta: u32,
    /// The resolved target.
    target: UsnTarget,
    /// Whether the subject is a directory.
    is_dir: bool,
  },
  /// An in-root rename, both ends resolved.
  ///
  /// The two [`CONTENT`](reason::CONTENT) masks are what each HALF's own
  /// record proved besides the move, kept apart rather than unioned: a
  /// journal record is written under the link it operated on, so the
  /// departing record speaks for the old name and the arriving one for the
  /// new, and the lowering pays each end the evidence its own record carried.
  /// A widowed half carries exactly the same mask at exactly the same
  /// location, so pairing changes only whether the two ends are announced
  /// together — never what either one proves.
  ///
  /// They cannot double-report the same fact: the session table hands each
  /// record its FRESH bits, so a class already in the departing half's mask is
  /// no longer fresh by the time the arriving half is observed.
  Renamed {
    /// The departing end.
    old: UsnTarget,
    /// What the DEPARTING record proved besides the move.
    old_content: u32,
    /// The arriving end.
    new: UsnTarget,
    /// What the ARRIVING record proved besides the move.
    new_content: u32,
    /// Whether the subject is a directory.
    is_dir: bool,
  },
  /// The subject IS the root anchor and the record is structural: the
  /// scope's death (delete or rename of the watched root).
  RootDeath,
  /// A directory moved IN from outside the root: its subtree is unmapped
  /// until the source walks it, and the walk window is covered by a located
  /// rescan at the target. The lowering emits the cover; the source runs
  /// the walk (or escalates to a full reseed when it cannot complete).
  MovedInSubtree {
    /// The directory's FRN — the walk's map anchor.
    frn: u128,
    /// The directory's root-relative components — the walk's path anchor
    /// and the rescan's location.
    target: Vec<String>,
  },
  /// The map could no longer stay complete (a live learn overflowed the
  /// directory cap): the source must die rather than go blind.
  MapOverflow,
  /// A record contradicted the map's standing topology (see
  /// [`LearnOutcome::Inconsistent`]). The map is STALE, not overfull, so the
  /// answer is the reseed spine — an ordered loss, a fresh walk, a cursor
  /// re-anchored at the live edge — and not the source's death.
  MapInconsistent,
}

impl UsnAdmitted {
  /// Whether this event ENDS the trust of the batch carrying it: after it,
  /// nothing the map resolves may still be delivered.
  ///
  /// The two map verdicts say so directly — one declares the topology
  /// contradicted, the other declares it forever incomplete — and both lower
  /// to a root-wide cover. `RootDeath` says it structurally: every later
  /// record's components are root-relative to an anchor that just stopped
  /// being the watched object, and the source returns rather than reseeding,
  /// so nothing downstream will ever correct them.
  pub(crate) fn ends_the_batchs_trust(&self) -> bool {
    matches!(
      self,
      Self::MapOverflow | Self::MapInconsistent | Self::RootDeath
    )
  }
}

/// The ONE place a refused `learn` becomes an admitted outcome, so the four
/// sites that grow the map cannot disagree about what a refusal costs.
///
/// `OutsideRoot` is not reachable from any of them — each has already resolved
/// the parent through the map — and is not a refusal in any case: it is the
/// firehose's ordinary membership drop.
fn learn_refusal(outcome: LearnOutcome) -> Option<UsnAdmitted> {
  match outcome {
    LearnOutcome::Learned | LearnOutcome::OutsideRoot => None,
    LearnOutcome::OverCapacity => Some(UsnAdmitted::MapOverflow),
    LearnOutcome::Inconsistent => Some(UsnAdmitted::MapInconsistent),
  }
}

/// The same ledger for a site that has ALREADY RESOLVED the parent it is
/// learning under — and has since mutated the map.
///
/// `OutsideRoot` there is not the ordinary membership drop: the parent was in
/// the map a statement ago, so the map is disagreeing with what it just said
/// about itself. The only way to reach it is for an intervening mutation to
/// have taken the destination down (a `forget` whose subtree contained the
/// proposed parent is exactly that), and the answer is the same as for any
/// other contradicted topology — the reseed, never a silent skip that leaves
/// the subtree unmapped and unmentioned.
fn learn_refusal_below_a_resolved_parent(outcome: LearnOutcome) -> Option<UsnAdmitted> {
  match outcome {
    LearnOutcome::OutsideRoot => Some(UsnAdmitted::MapInconsistent),
    other => learn_refusal(other),
  }
}

/// The caller's exclusions, resolved against the watched root — the reported
/// tree stated as a predicate.
///
/// The USN map is a BUDGETED structure: it holds every in-root directory, it is
/// capped, and exceeding the cap kills the whole source. The exclusion option is
/// documented to guarantee that excluded churn consumes none of that budget, and
/// a fence that only drops compiled DELIVERIES cannot deliver on it — by the
/// time a record is compiled the map has already learned, re-parented or walked
/// whatever the record named. So the decision has to sit where the growth is:
/// ahead of every `learn`, `reparent` and demanded walk, on both the cold walk
/// and the live stream.
///
/// It does not re-derive the matching rule. Every answer here comes from
/// [`crate::driver::excluded`], the same predicate the sync-cookie refusal, the
/// fanotify admission fence and the common layer's own suppression consult, so
/// "a path the walk declines", "a path admission drops" and "a path the core
/// refuses to cover" are ONE set by construction. A second rule here could drift
/// out of step with the fence one layer up and re-open the hole from the other
/// side.
///
/// Paths are absolute: the map resolves root-relative components, so the fence
/// joins them onto the root the walk itself descends from. Matching is otherwise
/// the documented lexical subtree test on the paths as supplied.
///
/// The empty set — the overwhelmingly common case — short-circuits before any
/// resolution or allocation, so an unexcluded watch pays nothing per record.
#[derive(Debug, Clone)]
pub(crate) struct UsnFence {
  root: std::path::PathBuf,
  exclusions: Vec<std::path::PathBuf>,
}

impl UsnFence {
  /// The fence for a root watched with `exclusions` (empty = unfenced).
  pub(crate) fn new(root: std::path::PathBuf, exclusions: Vec<std::path::PathBuf>) -> Self {
    Self { root, exclusions }
  }

  /// A fence that excludes nothing.
  pub(crate) fn unfenced() -> Self {
    Self {
      root: std::path::PathBuf::new(),
      exclusions: Vec::new(),
    }
  }

  /// Whether an ABSOLUTE path lies at or under an exclusion — the walk's
  /// per-child decision, made before the child is learned, opened or descended.
  pub(crate) fn excludes_path(&self, path: &std::path::Path) -> bool {
    crate::driver::excluded(&self.exclusions, path)
  }

  /// The absolute path of `name` inside the root-relative directory `dir`.
  ///
  /// A name with no Unicode spelling contributes nothing, leaving the
  /// DIRECTORY's own path: the fence can then only answer for the directory,
  /// which is the fail-OPEN direction the exclusion option is documented to take
  /// (a delivery the caller did not want costs an event; a suppression on an
  /// unproven path costs one it may have needed).
  fn joined(&self, dir: &[String], name: &UsnName) -> std::path::PathBuf {
    let mut path = self.root.clone();
    for component in dir {
      path.push(component);
    }
    if let UsnName::Utf8(text) = name {
      path.push(text);
    }
    path
  }

  /// Whether one resolved endpoint — a directory plus a name in it — is outside
  /// the reported tree.
  fn excludes_end(&self, dir: &[String], name: &UsnName) -> bool {
    !self.exclusions.is_empty() && self.excludes_path(&self.joined(dir, name))
  }

  /// Whether the link one record was written under is outside the reported tree.
  ///
  /// A parent the map cannot resolve is OUT OF ROOT, not excluded, and never
  /// contributes a suppression: admission's own membership gate owns that case,
  /// and conflating the two would let a boundary rename lose the in-root half it
  /// is supposed to report.
  fn excludes_link(&self, map: &FrnMap, record: &UsnRecord) -> bool {
    let Some(dir) = map.resolve_dir(record.parent) else {
      return false;
    };
    self.excludes_end(&dir, &record.name)
  }

  /// Whether `event` reports NOTHING inside the reported tree — the fence's
  /// admission-side verdict, read-only and ahead of every map mutation.
  ///
  /// The root anchor's own records are never suppressed, whatever the caller
  /// excluded — including a caller who excluded the very tree it asked to watch.
  /// They are routed by the anchor rather than by a link, they are the one
  /// signal that says the watch is over, and the guard is a superset of that
  /// outcome by construction rather than by coincidence.
  ///
  /// A rename is suppressed only when BOTH ends are excluded. A move ACROSS the
  /// boundary is a real change to the reported tree — an object leaving the
  /// excluded subtree appears, one entering it disappears — and the consumer
  /// needs the half it can see. The MAP side of a crossing is handled where the
  /// mutation is, in [`UsnAdmission::admit_rename`]: an excluded endpoint is
  /// nulled out there, which routes it into the same arms an OUT-OF-ROOT
  /// endpoint already takes.
  fn excludes_event(&self, map: &FrnMap, event: &UsnEvent) -> bool {
    if self.exclusions.is_empty() {
      return false;
    }
    match event {
      UsnEvent::Single(record) | UsnEvent::WidowOld(record) | UsnEvent::WidowNew(record) => {
        !map.is_root(record.frn) && self.excludes_link(map, record)
      }
      UsnEvent::Renamed { old, new } => {
        !map.is_root(new.frn) && self.excludes_link(map, old) && self.excludes_link(map, new)
      }
    }
  }

  /// Whether moving a mapped directory from `source` to `destination` CHANGES
  /// which of its descendants the fence covers — the one condition under which
  /// an in-root re-parent is not complete without a fresh walk.
  ///
  /// Exclusions match on path prefixes, so which descendants of a subtree lie
  /// under one is a function of the subtree's OWN path. A re-parent rewrites
  /// exactly that path while carrying every mapped descendant across untouched,
  /// so a move whose endpoints sit on different sides of an exclusion leaves the
  /// map describing a tree the fence no longer agrees with — in BOTH directions,
  /// and permanently, because nothing later re-walks it:
  ///
  /// - **out of an exclusion.** The excluded subtree was never walked, so a bare
  ///   re-parent adds nothing and the newly reportable descendants stay absent
  ///   from the map — every record beneath them resolves no parent and is
  ///   dropped as out-of-root: a visible subtree, blind forever.
  /// - **into an exclusion.** The descendants ARE mapped, and a bare re-parent
  ///   leaves them there, holding exactly the capped budget the exclusion exists
  ///   to shed.
  ///
  /// The test is the fence's own containment run the other way round: an
  /// exclusion is relevant exactly when it lies at or under one of the two
  /// endpoints, which is the same predicate with the endpoints as the exclusion
  /// set. Deliberately CONSERVATIVE — an exclusion under both endpoints at the
  /// same relative offset costs one needless walk — because comparing the two
  /// sides exactly would buy nothing on a path this rare and would add the
  /// second matching rule this deliberately avoids.
  ///
  /// The endpoints are joined INSIDE the empty-set check, so an unexcluded watch
  /// pays no allocation per directory rename.
  fn geometry_changed(
    &self,
    old_dir: &[String],
    old_name: &UsnName,
    new_dir: &[String],
    new_name: &UsnName,
  ) -> bool {
    if self.exclusions.is_empty() {
      return false;
    }
    let endpoints = [
      self.joined(old_dir, old_name),
      self.joined(new_dir, new_name),
    ];
    self
      .exclusions
      .iter()
      .any(|exclusion| crate::driver::excluded(&endpoints, exclusion))
  }
}

/// The admission state one journal source owns.
#[derive(Debug)]
pub(crate) struct UsnAdmission {
  map: FrnMap,
  sessions: SessionTable,
  pairer: UsnPairer,
  fence: UsnFence,
}

impl UsnAdmission {
  /// A fresh UNFENCED admission over a seeded map. A source watching a root with
  /// exclusions adds them with [`with_fence`](Self::with_fence).
  pub(crate) fn new(map: FrnMap, session_cap: usize) -> Self {
    Self {
      map,
      sessions: SessionTable::new(session_cap),
      pairer: UsnPairer::new(),
      fence: UsnFence::unfenced(),
    }
  }

  /// Returns this admission enforcing `fence` — the reported tree's boundary,
  /// consulted ahead of every map mutation and every delivery.
  #[must_use]
  pub(crate) fn with_fence(mut self, fence: UsnFence) -> Self {
    self.fence = fence;
    self
  }

  /// Returns this admission accounting for a volume whose rename semantics are
  /// `renames` — the switch that scopes the repeat-rename retirement to the
  /// filesystem the measurement was taken on.
  ///
  /// [`new`](Self::new) leaves it [`Measured`](RenameSemantics::Measured)
  /// because that is the volume every cell in this crate models. The one caller
  /// that reads a REAL volume says what it found, and says it from the
  /// filesystem name the root's own handle reports.
  #[must_use]
  pub(crate) fn with_rename_semantics(mut self, renames: RenameSemantics) -> Self {
    self.sessions = self.sessions.with_rename_semantics(renames);
    self
  }

  /// The map, for the reseed swap.
  pub(crate) fn map_mut(&mut self) -> &mut FrnMap {
    &mut self.map
  }

  /// Whether a rename OLD half is parked (the read-wait bound cue).
  pub(crate) fn holds_old(&self) -> bool {
    self.pairer.holds_old()
  }

  /// Admits one decoded record in journal order, appending admitted events.
  ///
  /// Two shapes NTFS coalescing can produce are KNOWN NOT to be repaired here,
  /// and neither has a repair this layer can make honestly.
  ///
  /// A file kept open and changed only in ways already recorded emits nothing
  /// at all — no record, no close — for as long as it is held. There is no
  /// signal to lower, so the arm reports the first change of each kind and
  /// then waits; convergence arrives with the close record, whenever the last
  /// opener produces one. That is the journal's own floor, not a gap in the
  /// delta table.
  ///
  /// A hard-linked file changed ONLY through links outside the root is the
  /// second and deeper one. Every record names the operating handle's link, so
  /// a session that never touches an in-root link writes nothing an in-root
  /// parent can resolve — the change is invisible to this scope, exactly as it
  /// is to `ReadDirectoryChangesW`, which notifies the operated link's parent
  /// too. Nothing at this layer can invent a notice the journal never wrote;
  /// what [`cover_stranded`](Self::cover_stranded) repairs is the narrower and
  /// fixable case where a notice DID go out in-root and only its repair was
  /// routed elsewhere.
  ///
  /// # THE REPEAT-RENAME COVER IS RETIRED ON NTFS, AND WHAT THAT RETURNS
  ///
  /// This arm used to answer a `CLOSE` that re-asserted its session's
  /// [rename](reason::RENAME) bits with a cover: one root-scoped rescan for a
  /// file, the reseed spine for a mapped directory, and — through the LATENT
  /// half — one root-scoped rescan for a FILE whose observed rename endpoints
  /// were all outside the reported tree, on the argument that a hard link this
  /// module cannot enumerate might have been the one that silently moved.
  ///
  /// EVERY ONE OF THOSE COVERS ANSWERED A MOVE THAT WRITES NO RECORD, AND THERE
  /// IS NO SUCH MOVE. The journal was measured (this module's header carries the
  /// record stream, the runners, and the cell): two moves through one held
  /// handle wrote four rename records, `0x1100 0x2100 0x1100 0x2100`, and the
  /// two halves alternate rather than accumulate. The second move is not silent,
  /// it is an ordinary pair — and this admission already lowers it as one,
  /// because the session table hands each record its FRESH bits and a rename
  /// half is fresh exactly when the journal wrote it.
  ///
  /// WHAT THE RETIREMENT RETURNS, against the costs that were stated when the
  /// class landed:
  ///
  /// - EVERY FILE RENAME ANYWHERE ON THE VOLUME used to cost the watched tree
  ///   one root-scoped `Rescan` at its close, because the journal is volume-wide
  ///   and the latent debt was not scoped to the reported tree. That rate goes
  ///   to zero. A busy volume no longer rescans a quiet watched root at all.
  /// - EVERY IN-ROOT RENAME whose close this source observed used to cost one
  ///   root cover; every in-root DIRECTORY rename cost a root cover AND a full
  ///   re-walk. Both go to zero: the move is reported as a `Moved` pair, and a
  ///   directory's re-parent keeps the map correct without re-walking it.
  /// - A close that MERGED its arriving half now NAMES the destination instead
  ///   of covering the root and refusing to name it. The cover used to disown
  ///   the very record that carried the arrival, so the consumer was sent back
  ///   to the filesystem instead of being told where the subject went.
  ///
  /// WHAT DOES NOT CHANGE, because the measurement does not touch it: the close
  /// still replays every [replayable](reason::REPLAYABLE) class its summary
  /// carries, unconditionally. That replay answers a REPEATED WRITE, which is
  /// the rule the reference actually documents, and it is the reason this arm
  /// converges at all. The stranded-link covers, the ledger, and every bound's
  /// degrade to a cover are likewise untouched — none of them was ever about
  /// renames.
  ///
  /// EVERY LINE ABOVE IS SCOPED TO THE FILESYSTEM THE CELLS RAN ON, which is
  /// NTFS and only NTFS. A volume the source admits and nobody measured — ReFS
  /// speaks V3 and qualifies — keeps the whole class: its close still buys a
  /// root-scoped cover for a file and the reseed spine for a mapped directory,
  /// exactly as before, selected by [`RenameSemantics`] at the one point that can
  /// know. The retirement's return above is therefore a return on PROVEN
  /// volumes; on unproven ones the old rate stands, which is the honest price of
  /// evidence that does not reach them.
  ///
  /// THE ONE SHAPE THE MEASUREMENT DOES NOT ITSELF PERFORM is a rename of a
  /// DIFFERENT HARD LINK of an already-renamed reference. It is answered by the
  /// mechanism the measurement exposes rather than by an assumption — the
  /// accumulated reason word belongs to the open file object and the rename path
  /// clears the opposite half as it sets its own, so link B's departing half is
  /// fresh whatever link A did — and
  /// `usn_repeat_rename_across_two_hard_links_writes_which_records` now ENFORCES
  /// it: the cell fails unless link B's move arrives as an ordered, correctly
  /// named pair whose halves are fresh under the session table's own delta and
  /// joined by this very pairer — including the drain rule below, so a merged
  /// `RENAME_NEW_NAME | CLOSE` is read there exactly as it is read here.
  /// [`premise`](super::premise) is where that question is decided, so the cell
  /// and this arm cannot drift apart.
  ///
  /// # One record at a time, whole
  ///
  /// ACCOUNT AND LOWER THE SAME RECORD, IN THE SAME STEP, ACCOUNTING FIRST.
  /// This function has two stages that look independent and are not: the
  /// session table's ACCOUNTING (what a record retires, evicts, strands and
  /// owes) and the LOWERING (what a record delivers, and — through
  /// [`note_link`](SessionTable::note_link) and
  /// [`retarget_link`](SessionTable::retarget_link) — where it registers a
  /// repair as owed). A DELIVERY's obligations do not exist until its lowering
  /// makes them, and a record's name is only as good as its accounting says. Let
  /// the two stages come apart and the table is read at a point in the stream
  /// that no record occupies.
  ///
  /// It came apart at BOTH ends, and each end lost the same thing in mirror
  /// image:
  ///
  /// - AHEAD OF THE ACCOUNTING. A pairing carry is a record already observed
  ///   and not yet lowered, so its in-root registrations are still unmade. An
  ///   unrelated record observed while it sits there could evict its session at
  ///   its emptiest — no links registered — and the ledger, correctly, recorded
  ///   no debt for a session that owed none YET. The carry then widowed into
  ///   `note_link` calls with no entry left to reach, and the close found
  ///   neither a live session nor a marker: an in-root change with nothing
  ///   anywhere left to repair it. So the carry is drained BEFORE anything else
  ///   is observed, and the question the drain asks is [whether this record
  ///   takes the carry's
  ///   entry](UsnPairer::holds_old_whose_entry_this_record_takes) — never
  ///   whether it can pair. Asking about pairing let the SUBJECT'S OWN `CLOSE`
  ///   through, because it can pair: a merged `RENAME_NEW_NAME | CLOSE` is one
  ///   record carrying the half's partner AND the retirement, and retirement
  ///   runs first. Eviction and retirement remove the same entry; only
  ///   retirement also reads it, so retirement is the stricter of the two and
  ///   the guard covers both.
  /// - BEHIND THE ACCOUNTING. A record whose accounting
  ///   [disowns its own name](Unnamed::disowns_its_record) was still lowered
  ///   against it, so a paid root cover was followed by a create at the stale
  ///   name that cover exists because nobody can prove. The batch-trust stop
  ///   already says "nothing after this is trustworthy" for a contradicted map;
  ///   a disowning verdict says it about one record, and it says it about that
  ///   record too. The covers stay — they are owed to LINKS, which the record's
  ///   own name has nothing to do with — and the record itself does not lower.
  ///
  /// The same rule orders the two: a disowned record can complete no parked
  /// half either, so that half widows AHEAD of the covers rather than trailing
  /// them, which is the one placement that keeps a delivery from landing behind
  /// a rescan that dominates it.
  ///
  /// THE ACCOUNTING NO LONGER JUDGES A RECORD'S ENDPOINT, and that is a
  /// consequence of the retirement rather than a relaxation. It used to, because
  /// one obligation was a statement about the SUBJECT rather than about a
  /// delivery — whether the session's location was still provable — and a
  /// lowering DISCARDED for naming an out-of-root or excluded endpoint could
  /// book nothing, so the booking had to live where every record passes exactly
  /// once. That obligation is retired; nothing else was ever booked from the
  /// endpoint, so the accounting is now the mask, the links and the ledger, and
  /// the ordering rules above stand unchanged over them.
  pub(crate) fn admit(&mut self, record: UsnRecord, out: &mut Vec<UsnAdmitted>) {
    if self.pairer.holds_old_whose_entry_this_record_takes(&record) {
      self.flush(out);
    }
    let outcome = self.sessions.observe(&record);
    let disowned = outcome.unnamed.disowns_its_record();
    // Kept as the standing guarantee rather than as a live path. Only a `CLOSE`
    // can raise an unnamed location or topology debt — the residue rides on one,
    // and so does the cover an unmeasured volume's re-asserted rename bits buy;
    // the other arm of [`observe`](SessionTable::observe) answers
    // `Unnamed::NOTHING` in band. And every `CLOSE` was already drained ahead of
    // the accounting, for a stranger's subject (its file reference differs from
    // the carry's) and for the carry's own (the `CLOSE` bit itself). The rule it
    // states is still the rule: a disowned record can complete no parked half,
    // so that half widows AHEAD of the covers rather than trailing them.
    if disowned {
      self.flush(out);
    }
    // Covers come after every record that PRECEDES this one has been lowered
    // and before this record's own events: they repair notices that predate
    // this record, they resolve through the map exactly as it stands at this
    // point in the journal, and sitting ahead of the record keeps them on the
    // trusted side of a batch stop this very record might raise.
    self.cover_stranded(&record, &outcome, out);
    if disowned {
      return;
    }
    let fresh = outcome.mask & !reason::FILTERED;
    if fresh == 0 {
      return;
    }
    // The record forwards its FRESH bits only: cumulative masks would
    // re-report every prior session fact on each new record, and structural
    // priority would then eat the genuinely new content bit.
    let record = UsnRecord {
      reason: fresh,
      ..record
    };
    let mut paired = Vec::new();
    self.pairer.push(record, fresh, &mut paired);
    for event in paired {
      self.lower_paired(event, out);
    }
  }

  /// Admits ONE decoded buffer's records in journal order, stopping at the
  /// first event that [ends the batch's trust](UsnAdmitted::ends_the_batchs_trust)
  /// and returning it. `None` = the whole buffer was admitted.
  ///
  /// The stop is the point. A `MapInconsistent` is the map's own statement
  /// that the topology every LATER record resolves through is untrustworthy,
  /// and the lowering answers it with a root-wide cover. Admitting the rest of
  /// the buffer anyway left that cover in the MIDDLE of the batch: a consumer
  /// re-read at the `Rescan`, believed itself consistent again, and was
  /// immediately re-diverged by suffix paths the very same verdict had
  /// disowned — with the reseed's own loss signal arriving only afterwards,
  /// too late to dominate them. So the verdict is the batch's LAST word: the
  /// untrusted suffix is discarded, and the reseed (or, for the other two
  /// verdicts, the source's death) re-establishes everything behind the cover.
  ///
  /// The pairing carry widows AHEAD of the cover — it predates the verdict
  /// exactly as the admitted prefix does, and the cover dominates it too. In
  /// practice the pairer is already empty at every verdict (a record that
  /// reaches the map either consumed the carry or widowed it first), so this
  /// is a standing guarantee rather than a live path: no half may stay parked
  /// against a map that is about to be replaced.
  pub(crate) fn admit_batch<I>(
    &mut self,
    records: I,
    out: &mut Vec<UsnAdmitted>,
  ) -> Option<UsnAdmitted>
  where
    I: IntoIterator<Item = UsnRecord>,
  {
    for record in records {
      let before = out.len();
      self.admit(record, out);
      // Only the events THIS record produced are new, and a verdict is not
      // always the last of them (one record can widow a carry, lower its own
      // half, and refuse in between).
      let Some(offset) = out[before..]
        .iter()
        .position(UsnAdmitted::ends_the_batchs_trust)
      else {
        continue;
      };
      let verdict = out[before + offset].clone();
      out.truncate(before + offset);
      self.flush(out);
      out.push(verdict.clone());
      return Some(verdict);
    }
    None
  }

  /// Widows the pairing carry (read boundary / loss barrier / teardown).
  pub(crate) fn flush(&mut self, out: &mut Vec<UsnAdmitted>) {
    let mut paired = Vec::new();
    self.pairer.flush(&mut paired);
    for event in paired {
      self.lower_paired(event, out);
    }
  }

  /// Resets the cumulative-reason history — the reseed boundary's duty.
  /// The cursor jumps across an unobserved interval, so a session's
  /// remembered bits may describe an open that CLOSEd inside the gap; a
  /// post-gap session re-reporting the same bit must not be suppressed.
  ///
  /// The retained replay links go with them, uncovered, and so does the orphan
  /// ledger — its named debts and its anonymous residue alike. This is the ONE
  /// place in this file an obligation may be dropped rather than degraded, and
  /// it is worth being exact about what buys that: a reseed is published behind
  /// a root-wide cover, an ordered loss AND a fresh walk that rebuilds the map,
  /// so at the instant it lands there is no location a surviving link could
  /// name, and no map entry a topology debt could impeach, that has not just
  /// been re-established from the filesystem itself.
  ///
  /// What it does not reach is a session that OUTLIVES it and then changes in
  /// silence: a reseed is a statement about now, and an open handle's next
  /// unrecorded write is not. That residual belongs to the reseed boundary
  /// itself and is identical for a session the table was tracking and for one
  /// the ledger was — which is exactly why the ledger's own bound escalates
  /// HERE, to the statement this arm already recognises as dominating, instead
  /// of inventing a weaker discharge of its own.
  ///
  /// The volume's [rename semantics](RenameSemantics) survive the reset: they
  /// describe the FILESYSTEM, not the session history, and a reseed re-reads the
  /// tree rather than remounting it.
  pub(crate) fn reset_sessions(&mut self) {
    self.sessions =
      SessionTable::new(self.sessions.cap).with_rename_semantics(self.sessions.renames);
  }

  /// Pays the replay targets a session surrendered — the in-root links whose
  /// notices this record's own routing does not reach.
  ///
  /// A record is routed by its LINK; a session is keyed by its OBJECT. The
  /// close summary that repairs a session therefore names only the last
  /// handle's link, and for a hard-linked file that can be a different in-root
  /// link, or none at all: a write through `/watched/a` closed through
  /// `/outside/b` produced a replay admission dropped as out-of-root, leaving
  /// the consumer that read at the first write describing a half-written file
  /// with nothing left in the stream to correct it.
  ///
  /// Each unreached link is paid with a COVER rather than a verb. The summary
  /// proves the class changed at least once in the session and can prove
  /// nothing about when or through which handle, so "look at this again" is
  /// the strongest honest statement about a link the record does not name.
  ///
  /// Three degradations, all of them bounded and none of them silent:
  ///
  /// - A [saturated](ReplayLinks::saturated) set means the session named more
  ///   distinct links than the ceiling holds. Enumerating what survived would
  ///   be silently short, so the whole root is covered once instead.
  /// - An elided name (too long to retain inline, or unspellable) covers the
  ///   link's DIRECTORY instead of the link.
  /// - A link whose parent no longer resolves has left the watched tree —
  ///   deleted, or moved out — and took every in-root path to that notice with
  ///   it. Its departure was itself a delivered structural event; there is no
  ///   in-root location left to point at, so nothing is emitted.
  ///
  /// Ahead of all three sits the [unnamed](Unnamed) debt: an obligation the
  /// table can enumerate no targets for at all, because the entry that held them
  /// is gone — a stranded repair, or the ledger's anonymous residue. There is
  /// nothing to degrade — the root IS the degrade — so it is paid first and
  /// unconditionally.
  ///
  /// Every cover here is owed to a LINK (or, unnamed, to the root), never to the
  /// covered record's own name, which is why the whole set survives a record
  /// [its own accounting disowns](Unnamed::disowns_its_record): the record stops
  /// speaking for where its subject IS, and says nothing either way about the
  /// links its session's earlier notices already went to.
  fn cover_stranded(
    &mut self,
    record: &UsnRecord,
    outcome: &SessionOutcome,
    out: &mut Vec<UsnAdmitted>,
  ) {
    // A root cover for a debt whose subject the table can no longer name — a
    // stranded repair, an unproven file location on a volume nobody measured, or
    // both, which one cover settles. Its `is_dir` is `false` because nothing here
    // knows: an `EscalateAt` names a LOCATION, and the lowering reads neither
    // verb nor class from one.
    if outcome.unnamed.covers_at_root() {
      out.push(UsnAdmitted::Single {
        delta: reason::REPLAYABLE,
        target: UsnTarget::EscalateAt(Vec::new()),
        is_dir: false,
      });
    }
    if outcome.unnamed.topology {
      // Either the ledger's anonymous residue — some session this table stopped
      // tracking still owes a repair and cannot be named, so every path the map
      // resolves is only as good as a debt nobody can attribute — or, on a volume
      // whose rename accounting nobody measured, a mapped directory whose
      // location cannot be proven current, which makes every path BENEATH it a
      // guess. Both are the map being stale, which is what the reseed spine
      // repairs, and it is the one payment that also lets the residue stop
      // standing.
      out.push(UsnAdmitted::MapInconsistent);
    }
    // A cover names a LOCATION rather than classifying an object, and the
    // lowering reads no verb (and no class) from one — but the fields are
    // still filled with what is actually known, never with a convenient guess:
    // a retirement's subject IS this record's, an eviction's is a stranger.
    let (links, owed, is_dir) = match &outcome.stranded {
      Stranded::Nothing => return,
      Stranded::Retired(links) => (links, outcome.mask & reason::REPLAYABLE, record.is_dir()),
      // An eviction surrenders an UNRELATED subject's targets, and its mask
      // went with them: every replayable class may be owed.
      Stranded::Evicted(links) => (links, reason::REPLAYABLE, false),
    };
    if links.saturated() {
      out.push(UsnAdmitted::Single {
        delta: owed,
        target: UsnTarget::EscalateAt(Vec::new()),
        is_dir,
      });
      return;
    }
    // Only a RETIRED session's own closing record can already reach one of its
    // targets, and only when that record's link is in-root at all — an
    // out-of-root closing link delivers nothing, so it discharges nothing.
    //
    // A record this function's own covers disowned delivers nothing either, and
    // the skip still stands: disowning it required an unproven LOCATION, which
    // is paid above with the root cover — a rescan over everything, carrying
    // every [replayable](reason::REPLAYABLE) class, so it is a superset of the
    // located one this skip declines to emit. Nothing is owed twice and nothing
    // is dropped.
    let reached = matches!(outcome.stranded, Stranded::Retired(_))
      && self.map.resolve_dir(record.parent).is_some();
    for link in links.held() {
      if reached && link.is(record.parent, &record.name) {
        continue;
      }
      let Some(mut components) = self.map.resolve_dir(link.parent) else {
        continue;
      };
      if let Some(name) = link.name() {
        components.push(name.to_owned());
      }
      out.push(UsnAdmitted::Single {
        delta: owed,
        target: UsnTarget::EscalateAt(components),
        is_dir,
      });
    }
  }

  /// Lowers one paired event — and is THE exclusion fence's seat.
  ///
  /// The fence runs as this function's first statement, ahead of every shape
  /// dispatch below and therefore ahead of every map mutation the source can
  /// make from a journal record: `admit_single` learns, forgets and re-learns
  /// across a reparse toggle, `admit_rename` re-parents, forgets and demands
  /// walks, and every one of them is reached from here. It reads an IMMUTABLE
  /// map, so the decision is made against exactly the state the shapes will act
  /// on and nothing is mutated to reach it.
  ///
  /// The EVENT — not the record — is the unit, because a rename is only decided
  /// once both halves are in hand: a crossing of the boundary is always
  /// reported, so a half whose partner is reportable must reach the rename arms
  /// rather than be dropped on its own.
  ///
  /// The session machinery deliberately runs OUTSIDE this fence, in
  /// [`admit`](Self::admit). It mutates no map, so it cannot grow the budget the
  /// fence protects, and what it produces is owed at links the fence did NOT
  /// exclude: a close arriving on an excluded hard link still retires its
  /// session, and a record inside an exclusion that evicts an unrelated session
  /// still surrenders that session's targets. Fencing it too would strand
  /// exactly the notices the close replay exists to repair.
  fn lower_paired(&mut self, event: UsnEvent, out: &mut Vec<UsnAdmitted>) {
    if self.fence.excludes_event(&self.map, &event) {
      return;
    }
    match event {
      UsnEvent::Single(record) => self.admit_single(record, out),
      UsnEvent::Renamed { old, new } => self.admit_rename(old, new, out),
      // A widowed OLD names an object that LEFT its slot with no arriving
      // end: membership-wise it is a delete (out-of-root moves and deletes
      // are indistinguishable from inside), and the lowering degrades the
      // same way. The RENAME bit RIDES ALONG rather than being replaced by the
      // degrade: a rename provably happened, and a subscription that asked
      // only about moves would otherwise be told nothing at all — the degrade
      // is a choice of VERB, and a verb choice must not narrow admission.
      UsnEvent::WidowOld(record) => {
        let synthetic = UsnRecord {
          reason: reason::FILE_DELETE | reason::RENAME_OLD_NAME | (record.reason & reason::CONTENT),
          ..record
        };
        self.admit_single(synthetic, out);
      }
      // A widowed NEW arrived from nowhere visible: a create — and for a
      // directory, a MOVE-IN: whatever subtree it carried was never
      // mapped (a startup or reseed cursor can fall between rename
      // halves), so the walk must be demanded like any other arrival.
      UsnEvent::WidowNew(record) => {
        let is_dir = record.is_dir();
        let frn = record.frn;
        let synthetic = UsnRecord {
          reason: reason::FILE_CREATE | reason::RENAME_NEW_NAME | (record.reason & reason::CONTENT),
          ..record
        };
        self.admit_single(synthetic, out);
        // The ROOT anchor is excluded: a widowed NEW naming it is the scope's
        // own rename, which `admit_single` already answered with the terminal
        // death. Demanding a walk of a subtree whose anchor just died would
        // send the source enumerating a root it no longer watches, behind a
        // verdict that already covers everything.
        if is_dir
          && !self.map.is_root(frn)
          && let Some(components) = self.map.resolve_dir(frn)
        {
          out.push(UsnAdmitted::MovedInSubtree {
            frn,
            target: components,
          });
        }
      }
    }
  }

  fn admit_single(&mut self, record: UsnRecord, out: &mut Vec<UsnAdmitted>) {
    if self.map.is_root(record.frn) {
      // Structural facts about the root anchor are the scope's death; pure
      // metadata on the root is an ordinary self-event.
      //
      // The ARRIVING half counts too. A rename of the watched root moves the
      // object out from under the path the scope bound, and which half of the
      // pair survives the read window is an accident of where the cursor fell:
      // an OLD whose NEW landed in the next read widows into the delete shape
      // and dies here, while a NEW whose OLD fell BELOW the cursor used to
      // reach this branch as a synthetic create and be published as a
      // self-`Created` on a root that had already gone. Both halves prove the
      // same rename, so both end the scope.
      const DEATH: u32 = reason::FILE_DELETE | reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME;
      if record.reason & DEATH != 0 {
        out.push(UsnAdmitted::RootDeath);
        return;
      }
      out.push(UsnAdmitted::Single {
        delta: record.reason,
        target: UsnTarget::Resolved(Vec::new()),
        is_dir: true,
      });
      return;
    }

    // Membership: the parent decides. An unmapped parent is outside the
    // root — dropped, not an error (the superblock-firehose admission).
    let Some(parent_components) = self.map.resolve_dir(record.parent) else {
      return;
    };
    let target = match &record.name {
      UsnName::Utf8(name) => {
        let mut components = parent_components;
        components.push(name.clone());
        UsnTarget::Resolved(components)
      }
      UsnName::Escalate => UsnTarget::EscalateAt(parent_components),
    };

    // Membership just proved this link in-root, so a replayable class going
    // out here is a notice the session's close still owes a repair to — at
    // THIS link, whichever link the closing handle turns out to hold. The
    // table drops the note for a subject with no live session, which is
    // exactly the close's own delivery: it IS the repair.
    //
    // A link the session merely ARRIVES at owes the same repair, and that is
    // what the second half asks. Once a replayable class is in the session's
    // cumulative mask, every further change of that class is written as no
    // record at all — so a subject that reaches a new in-root link with such a
    // mask already standing can go on changing there in complete silence, and
    // the close is the only thing left that can repair it. Registering off the
    // ARRIVING record's own bits alone missed exactly that: a pure move-in
    // carries none.
    if record.reason & reason::REPLAYABLE != 0 || self.sessions.owes_replay(record.frn) {
      self
        .sessions
        .note_link(record.frn, record.parent, &record.name);
    }

    // Map maintenance BEFORE emission order does not matter here (the map
    // answers membership for LATER records; this record's own resolution
    // used the pre-state), but keeping it adjacent keeps journal order and
    // map state in lockstep.
    if record.is_dir() {
      if record.reason & reason::FILE_CREATE != 0 {
        let UsnName::Utf8(name) = &record.name else {
          // A structural directory whose name the vocabulary cannot carry
          // can never anchor resolvable children: the map cannot stay
          // complete, so the source dies under the root cover.
          out.push(UsnAdmitted::MapOverflow);
          return;
        };
        if let Some(refusal) =
          learn_refusal(self.map.learn(record.frn, record.parent, name.clone()))
        {
          out.push(refusal);
          return;
        }
      }
      if record.reason & reason::FILE_DELETE != 0 {
        self.map.forget(record.frn);
      }
      if record.reason & reason::REPARSE_POINT_CHANGE != 0 {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if record.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
          // The directory BECAME a reparse boundary: drop the subtree; the
          // located rescan re-establishes what is really below.
          self.map.forget(record.frn);
        } else {
          // The boundary was REMOVED — an ordinary directory now stands
          // where the map holds nothing: learn the anchor and demand its
          // walk, exactly like a move-in, or the subtree stays blind. A
          // name the vocabulary cannot carry cannot anchor children — map
          // death, never a silent skip.
          let UsnName::Utf8(name) = &record.name else {
            out.push(UsnAdmitted::MapOverflow);
            return;
          };
          if let Some(refusal) =
            learn_refusal(self.map.learn(record.frn, record.parent, name.clone()))
          {
            out.push(refusal);
            return;
          }
          if let UsnTarget::Resolved(components) = &target {
            out.push(UsnAdmitted::MovedInSubtree {
              frn: record.frn,
              target: components.clone(),
            });
          }
        }
      }
    }

    out.push(UsnAdmitted::Single {
      delta: record.reason,
      target,
      is_dir: record.is_dir(),
    });
  }

  fn admit_rename(&mut self, old: UsnRecord, new: UsnRecord, out: &mut Vec<UsnAdmitted>) {
    if self.map.is_root(new.frn) {
      out.push(UsnAdmitted::RootDeath);
      return;
    }
    // An endpoint the fence excludes is OUTSIDE THE REPORTED TREE, and saying so
    // by nulling its resolution is the whole enforcement: every arm below —
    // forget the departed subtree, learn-and-walk the arriving one, report the
    // surviving half as its membership verb, report nothing when neither half
    // survives — already handles an endpoint that is not in the reported tree,
    // because that is exactly what an out-of-root endpoint is. A crossing INTO
    // an exclusion therefore takes the move-out arm (forget, no walk, still
    // report the departure) and a crossing OUT of one takes the move-in arm
    // (learn, walk, report the arrival), with no second set of arms to drift.
    //
    // Decided here, on the map's resolutions and before the mutation block, so
    // no `reparent`, `learn` or demanded walk can run for an excluded end.
    let old_parent = self
      .map
      .resolve_dir(old.parent)
      .filter(|dir| !self.fence.excludes_end(dir, &old.name));
    let new_parent = self
      .map
      .resolve_dir(new.parent)
      .filter(|dir| !self.fence.excludes_end(dir, &new.name));
    let is_dir = new.is_dir();

    let resolve_end = |parent: Option<Vec<String>>, name: &UsnName| {
      parent.map(|components| match name {
        UsnName::Utf8(text) => {
          let mut full = components;
          full.push(text.clone());
          UsnTarget::Resolved(full)
        }
        UsnName::Escalate => UsnTarget::EscalateAt(components),
      })
    };
    let old_end = resolve_end(old_parent.clone(), &old.name);
    let new_end = resolve_end(new_parent.clone(), &new.name);

    // Map maintenance mirrors the boundary shape.
    if is_dir {
      match (old_parent.is_some(), new_parent.is_some()) {
        (true, true) => {
          let UsnName::Utf8(name) = &new.name else {
            // An in-root directory whose new name has no spelling cannot
            // stay mapped — and the STANDING tree below it would go blind
            // the moment it is forgotten. The map cannot stay complete:
            // map death under the root cover.
            out.push(UsnAdmitted::MapOverflow);
            return;
          };
          // CONTAINMENT IS DECIDED FIRST, against the map as it still stands.
          //
          // A re-parent refuses a link that would knot the parent chain, and
          // that refusal is only DETECTABLE while the moved entry's own chain is
          // there to be walked. Every path below that discards the subtree —
          // the exclusion-geometry re-walk does exactly that — turns the entry
          // into a leaf, and a leaf's proposed parent is never inside it: the
          // contradiction stops being provable, `learn` accepts the cycle (or,
          // once the discard has taken the proposed parent down with the
          // subtree, answers `OutsideRoot` and looks like an ordinary
          // membership drop), and the source neither reseeds nor reports.
          //
          // So the question is asked here, before any mutation, and a
          // contradicted topology takes the reseed spine whatever else this
          // rename would have done to the map.
          if self.map.knots(new.frn, new.parent) {
            out.push(UsnAdmitted::MapInconsistent);
            return;
          }
          // Both endpoints are in the reported tree, but an exclusion may sit
          // BENEATH one of them, in which case the mapped subtree a re-parent
          // would carry across untouched is no longer the subtree the fence
          // reports. Discarding it and re-walking from the top is the one
          // complete answer, and the discard happens BEFORE the re-parent
          // could carry it anywhere.
          let geometry_moved = self.fence.geometry_changed(
            old_parent.as_deref().unwrap_or_default(),
            &old.name,
            new_parent.as_deref().unwrap_or_default(),
            &new.name,
          );
          if geometry_moved {
            self.map.forget(new.frn);
          }
          if geometry_moved || !self.map.reparent(new.frn, new.parent, name.clone()) {
            // The FRN was absent (a directory the seed walk raced past —
            // renamed between its parent's enumeration and its own): its
            // descendants were never mapped, so learning the top alone
            // would leave a blind subtree. Demand the walk exactly like
            // an out-to-in move — which is also what a subtree whose
            // exclusion geometry moved now needs.
            //
            // The destination parent resolved a statement ago, so `OutsideRoot`
            // is not the firehose's membership drop here — it is the map
            // disagreeing with what it said about itself, which is a
            // contradiction and takes the reseed.
            if let Some(refusal) = learn_refusal_below_a_resolved_parent(self.map.learn(
              new.frn,
              new.parent,
              name.clone(),
            )) {
              out.push(refusal);
              return;
            }
            // The walk is demanded only once the anchor is PROVEN to stand.
            // The source resolves the walk's FRN through the map and skips a
            // walk it cannot resolve, so a demand made over an anchor that
            // never landed is a subtree left unmapped with nothing in the
            // stream saying so.
            let Some(components) = self.map.resolve_dir(new.frn) else {
              out.push(UsnAdmitted::MapInconsistent);
              return;
            };
            out.push(UsnAdmitted::MovedInSubtree {
              frn: new.frn,
              target: components,
            });
          }
        }
        (true, false) => self.map.forget(new.frn),
        (false, true) => {
          // A directory arriving from outside with a name the vocabulary
          // cannot carry could never anchor its standing tree: map death,
          // exactly like its in-root sibling cells.
          let UsnName::Utf8(name) = &new.name else {
            out.push(UsnAdmitted::MapOverflow);
            return;
          };
          if let Some(refusal) = learn_refusal(self.map.learn(new.frn, new.parent, name.clone())) {
            out.push(refusal);
            return;
          }
          // A directory moved IN brings an unmapped subtree: demand the
          // walk and cover its window with a located rescan at the target.
          if let Some(new_target) = &new_end
            && let UsnTarget::Resolved(components) = new_target
          {
            out.push(UsnAdmitted::MovedInSubtree {
              frn: new.frn,
              target: components.clone(),
            });
          }
        }
        (false, false) => {}
      }
    }

    // Each end is paid the [`CONTENT`](reason::CONTENT) its OWN record proved
    // — the identical mask the widow arm keeps, at the identical location — so
    // a rename's content evidence never depends on whether the partner half
    // reached the same read. Naming is a choice this layer makes; evidence is
    // a fact the record carried, and the choice must not consume the fact.
    let old_content = old.reason & reason::CONTENT;
    let new_content = new.reason & reason::CONTENT;
    // ROUTING DEBT FOLLOWS THE OBJECT, NOT THE RECORD THAT ESTABLISHED IT.
    //
    // Two duties, and they are separate because they fail separately.
    //
    // RETARGET runs on EVERY admitted rename with a destination in the reported
    // tree, with or without evidence on this record. A retained target is a
    // NAME, and the rename retires it: an earlier write registered `old`, the
    // repeat NTFS wrote no record for left the debt standing, and this pure
    // move — carrying no fresh content at all — moved the consumer's own state
    // to `new`. Conditioning the retarget on this record's evidence left the
    // close covering a path that no longer exists while the live one, the one
    // the consumer is actually holding, received nothing.
    //
    // ESTABLISH registers the destination as a target of its own. It asks the
    // session's CUMULATIVE history rather than this record's bits, because that
    // is what decides whether the subject can go on changing at its new link in
    // silence: with a replayable class already in the mask, every further change
    // of it is written as no record. A move-in carrying no evidence still lands
    // a subject that is mid-session and already silent.
    //
    // The link established is where the notice LANDS, which for a rename is not
    // always the link its record was written under. A pair with both ends
    // in-root lowers to ONE `Moved` change whose location is the DESTINATION
    // and whose fact set is the union of the two halves' evidence (the
    // departing end survives only as `moved_from`), so a consumer that acted on
    // a departing record's `DATA_OVERWRITE` acted on the NEW path. A degraded
    // end has no partner to be paired with, so its own link is its delivery.
    //
    // A destination OUTSIDE the reported tree retargets nothing: there is no
    // in-root location to move the debt to, the departure was itself delivered
    // as a structural verb, and aiming a later cover at an excluded or
    // out-of-root path would report inside a tree the caller fenced off. The
    // retained target simply stays where it was — a cover at a retired name is
    // noise the delivered departure already dominates.
    //
    // These are no-ops for a subject whose session the record's own CLOSE
    // already retired: a notice delivered BY the replay is owed no further one.
    let delivered = |content: u32| content & reason::REPLAYABLE != 0;
    let owes = delivered(old_content | new_content) || self.sessions.owes_replay(new.frn);
    match (&old_end, &new_end) {
      (_, Some(_)) => {
        self
          .sessions
          .retarget_link(new.frn, old.parent, &old.name, new.parent, &new.name);
        if owes {
          self.sessions.note_link(new.frn, new.parent, &new.name);
        }
      }
      // A departure delivers a membership verb at a link the subject is
      // LEAVING, so only evidence riding THIS record can still be owed there.
      // The session's standing history cannot: whatever it goes on doing after
      // the move happens somewhere this scope does not report, and any OTHER
      // in-root link it still holds registered itself when it delivered.
      (Some(_), None) => {
        if delivered(old_content) {
          self.sessions.note_link(old.frn, old.parent, &old.name);
        }
      }
      (None, None) => {}
    }
    // Either end inside the reported tree puts this session's mapped location in
    // play — from here on a SECOND move on the same handle writes no record —
    // and both halves booked exactly that when they were ACCOUNTED, each off its
    // own record's end. Nothing is registered here, because a booking made from
    // a lowering is a booking a half whose endpoint is not reportable never
    // makes: see [`SessionTable::observe`].
    match (old_end, new_end) {
      (Some(old_target), Some(new_target)) => out.push(UsnAdmitted::Renamed {
        old: old_target,
        old_content,
        new: new_target,
        new_content,
        is_dir,
      }),
      // Boundary renames: the in-root end alone, as a single (the lowering
      // covers it — a located rescan for a moved-in dir, the plain verb
      // otherwise). The RENAME bit rides along with the membership verb for
      // the same reason a widow keeps it: this genuinely IS a move, and a
      // move-only subscription must not be silently excluded by the choice to
      // NAME it a create or a removal.
      (Some(old_target), None) => out.push(UsnAdmitted::Single {
        delta: reason::FILE_DELETE | reason::RENAME_OLD_NAME | old_content,
        target: old_target,
        is_dir,
      }),
      (None, Some(new_target)) => out.push(UsnAdmitted::Single {
        delta: reason::FILE_CREATE | reason::RENAME_NEW_NAME | new_content,
        target: new_target,
        is_dir,
      }),
      (None, None) => {}
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{
    decode::{UsnName, UsnRecord},
    *,
  };

  impl SessionTable {
    /// The mask half of [`SessionTable::observe`], for the cells whose subject
    /// is the delta arithmetic rather than the replay's routing.
    fn delta(&mut self, record: &UsnRecord) -> u32 {
      self.observe(record).mask
    }
  }

  fn record(frn: u128, reason_mask: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent: 1,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: 0x20,
      name: UsnName::Utf8(name.into()),
    }
  }

  #[test]
  fn cumulative_masks_emit_as_deltas() {
    let mut table = SessionTable::new(16);
    let first = record(7, reason::DATA_EXTEND, "f");
    assert_eq!(table.delta(&first), reason::DATA_EXTEND);
    let second = record(7, reason::DATA_EXTEND | reason::DATA_OVERWRITE, "f");
    assert_eq!(
      table.delta(&second),
      reason::DATA_OVERWRITE,
      "only the new bit"
    );
    let third = record(
      7,
      reason::DATA_EXTEND | reason::DATA_OVERWRITE | reason::CLOSE,
      "f",
    );
    assert_eq!(
      table.delta(&third),
      reason::DATA_EXTEND | reason::DATA_OVERWRITE,
      "the close replays the summary's whole content mask"
    );
    assert_eq!(table.len(), 0, "CLOSE retires the session");
    // A fresh session after CLOSE re-reports from zero.
    let reopened = record(7, reason::DATA_EXTEND, "f");
    assert_eq!(table.delta(&reopened), reason::DATA_EXTEND);
  }

  /// The whole coalescing shape, as the change-journal reference documents it:
  /// write, set the time stamp, write, truncate, write, close. NTFS writes a
  /// record only for a kind it has not recorded yet, so the second and third
  /// writes produce NOTHING and this six-step session is four records. Anything
  /// that expects to observe a repeat is expecting traffic that never arrives.
  #[test]
  fn the_documented_session_is_four_records_for_six_changes() {
    let mut table = SessionTable::new(16);
    // 1. Initial write.
    assert_eq!(
      table.delta(&record(7, reason::DATA_OVERWRITE, "f")),
      reason::DATA_OVERWRITE
    );
    // 2. Time stamp set.
    assert_eq!(
      table.delta(&record(
        7,
        reason::DATA_OVERWRITE | reason::BASIC_INFO_CHANGE,
        "f"
      )),
      reason::BASIC_INFO_CHANGE
    );
    // 3. Second write: NTFS writes no record, so there is nothing to feed.
    // 4. Truncation.
    assert_eq!(
      table.delta(&record(
        7,
        reason::DATA_OVERWRITE | reason::BASIC_INFO_CHANGE | reason::DATA_TRUNCATION,
        "f"
      )),
      reason::DATA_TRUNCATION
    );
    // 5. Third write: again no record.
    // 6. Close.
    let closed = table.delta(&record(
      7,
      reason::DATA_OVERWRITE | reason::BASIC_INFO_CHANGE | reason::DATA_TRUNCATION | reason::CLOSE,
      "f",
    ));
    assert_eq!(
      closed,
      reason::DATA_OVERWRITE | reason::BASIC_INFO_CHANGE | reason::DATA_TRUNCATION,
      "the two unrecorded writes are repaired by the close summary: {closed:#x}"
    );
  }

  /// The reviewer's scenario, at the table. Two writes and a close is TWO
  /// records — the second write writes none — so nothing in the stream ever
  /// reports a repeat. A close repair armed by observing one therefore never
  /// armed, the close emitted nothing, and a consumer that read the file at
  /// the first record described it mid-write forever.
  #[test]
  fn two_writes_then_close_converges_with_no_repeat_to_observe() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::DATA_OVERWRITE, "f")),
      reason::DATA_OVERWRITE,
      "write one"
    );
    // Write two: NTFS writes no record. The stream jumps straight to close.
    let closed = table.delta(&record(7, reason::DATA_OVERWRITE | reason::CLOSE, "f"));
    assert_ne!(
      closed & reason::MODIFY,
      0,
      "the close must still report content: {closed:#x}"
    );
    assert_eq!(table.len(), 0, "and still retires the session");
  }

  /// The duplicate this arm accepts, stated as a test so it cannot be
  /// "optimized" back into the silence it replaced. One write and a close is
  /// indistinguishable in the stream from a hundred writes and a close, so the
  /// close replays regardless and the single-write session pays one repeat.
  #[test]
  fn a_one_write_session_pays_a_duplicate_at_its_close() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::DATA_EXTEND, "f")),
      reason::DATA_EXTEND
    );
    assert_eq!(
      table.delta(&record(7, reason::DATA_EXTEND | reason::CLOSE, "f")),
      reason::DATA_EXTEND,
      "the price of never leaving a consumer mid-write"
    );
  }

  /// A naming verb never replays: re-announcing a create or a delete would
  /// tell every subscriber the object appeared or vanished twice, and would
  /// re-run the map mutation keyed on it. It also needs no replay — a file
  /// reference is created once and deleted once, so coalescing has no second
  /// occurrence to swallow.
  #[test]
  fn the_close_replay_never_announces_a_naming_verb() {
    let mut table = SessionTable::new(16);
    let created = record(7, reason::FILE_CREATE | reason::DATA_EXTEND, "f");
    assert_eq!(
      table.delta(&created),
      reason::FILE_CREATE | reason::DATA_EXTEND
    );
    let closed = record(
      7,
      reason::FILE_CREATE | reason::DATA_EXTEND | reason::CLOSE,
      "f",
    );
    let delta = table.delta(&closed);
    assert_eq!(delta & reason::FILE_CREATE, 0, "no create replays");
    assert_eq!(delta, reason::DATA_EXTEND);

    // A delete first seen ON the close record is FRESH, not a replay, and
    // still reports — alongside the content the session is owed.
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(9, reason::DATA_OVERWRITE, "g")),
      reason::DATA_OVERWRITE
    );
    assert_eq!(
      table.delta(&record(
        9,
        reason::DATA_OVERWRITE | reason::FILE_DELETE | reason::CLOSE,
        "g"
      )),
      reason::DATA_OVERWRITE | reason::FILE_DELETE
    );
  }

  /// A link change is structural by partition but is spent on a LOCATED
  /// RESCAN, never on a verb, and admission reads no map action from it — so
  /// it replays like a content bit. It has to: a second link change inside one
  /// open records nothing, and the close summary is the only place it can
  /// still be covered.
  #[test]
  fn a_close_replays_a_link_change_the_journal_coalesced_away() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::HARD_LINK_CHANGE, "f")),
      reason::HARD_LINK_CHANGE
    );
    // The second link change writes no record; the close is the next thing
    // the stream carries.
    let closed = table.delta(&record(7, reason::HARD_LINK_CHANGE | reason::CLOSE, "f"));
    assert_eq!(
      closed,
      reason::HARD_LINK_CHANGE,
      "the close re-covers the link topology: {closed:#x}"
    );
  }

  /// The reference explicitly notes that no record is written for a repeated
  /// kind, so a record whose whole mask is already known is not traffic this
  /// table can meet. If one ever does arrive, it must not SHRINK the
  /// remembered mask — overwriting with a subset would make already-delivered
  /// bits look fresh again on the next record.
  #[test]
  fn a_wholly_repeated_mask_never_un_reports() {
    let mut table = SessionTable::new(16);
    let both = reason::DATA_EXTEND | reason::BASIC_INFO_CHANGE;
    assert_eq!(table.delta(&record(7, both, "f")), both);
    assert_eq!(
      table.delta(&record(7, reason::DATA_EXTEND, "f")),
      0,
      "a strict subset says nothing new"
    );
    assert_eq!(
      table.delta(&record(7, both, "f")),
      0,
      "and did not un-report the metadata bit"
    );
  }

  /// Content and metadata are separately observable — a modified-only
  /// subscription never hears an `Attrib`, and vice versa — so a fresh bit in
  /// ONE class can never stand in for an unrecorded repeat in the OTHER. The
  /// scenario that proved it: write, an unrecorded second write, then a time
  /// stamp set. Only the metadata bit is fresh, and a repair that treated any
  /// fresh bit as compensation went quiet about content at the close.
  #[test]
  fn a_fresh_metadata_bit_does_not_stand_in_for_a_content_change() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::DATA_EXTEND, "f")),
      reason::DATA_EXTEND
    );
    // The second write records nothing at all.
    assert_eq!(
      table.delta(&record(
        7,
        reason::DATA_EXTEND | reason::BASIC_INFO_CHANGE,
        "f"
      )),
      reason::BASIC_INFO_CHANGE,
      "only the metadata bit is fresh"
    );
    let closed = table.delta(&record(
      7,
      reason::DATA_EXTEND | reason::BASIC_INFO_CHANGE | reason::CLOSE,
      "f",
    ));
    assert_ne!(
      closed & reason::MODIFY,
      0,
      "the close still owes the write nobody was told about: {closed:#x}"
    );
    assert_eq!(table.len(), 0, "and still retires the session");
  }

  /// The mirror case: an unrecorded METADATA change survives a fresh content
  /// bit, so an attrib-only subscription converges the same way.
  #[test]
  fn a_fresh_content_bit_does_not_stand_in_for_a_metadata_change() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::BASIC_INFO_CHANGE, "f")),
      reason::BASIC_INFO_CHANGE
    );
    assert_eq!(
      table.delta(&record(
        7,
        reason::BASIC_INFO_CHANGE | reason::DATA_EXTEND,
        "f"
      )),
      reason::DATA_EXTEND
    );
    let closed = table.delta(&record(
      7,
      reason::BASIC_INFO_CHANGE | reason::DATA_EXTEND | reason::CLOSE,
      "f",
    ));
    assert_ne!(
      closed & reason::ATTRIB,
      0,
      "the close still owes the metadata change nobody was told about: {closed:#x}"
    );
  }

  /// Every replayable class in the summary replays, together: the close
  /// proves each of them happened at least once and can prove nothing about
  /// when, so covering one and not the other would be a guess.
  #[test]
  fn a_close_replays_every_class_its_summary_carries() {
    let mut table = SessionTable::new(16);
    let both = reason::DATA_EXTEND | reason::BASIC_INFO_CHANGE;
    assert_eq!(table.delta(&record(7, both, "f")), both);
    let closed = table.delta(&record(7, both | reason::CLOSE, "f"));
    assert_eq!(
      closed, both,
      "both classes replay at the close: {closed:#x}"
    );
  }

  /// A later record in the same class does NOT settle it. It reports its own
  /// new bit, but the write that produced no record at all could have landed
  /// after it just as easily as before, and nothing in the stream says which —
  /// so the close still replays the class.
  #[test]
  fn a_fresh_bit_of_the_same_class_does_not_settle_it_either() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::DATA_EXTEND, "f")),
      reason::DATA_EXTEND
    );
    assert_eq!(
      table.delta(&record(
        7,
        reason::DATA_EXTEND | reason::DATA_TRUNCATION,
        "f"
      )),
      reason::DATA_TRUNCATION,
      "the truncation is the only fresh bit"
    );
    let closed = table.delta(&record(
      7,
      reason::DATA_EXTEND | reason::DATA_TRUNCATION | reason::CLOSE,
      "f",
    ));
    assert_eq!(
      closed,
      reason::DATA_EXTEND | reason::DATA_TRUNCATION,
      "an extend after the truncation would have recorded nothing: {closed:#x}"
    );
  }

  #[test]
  fn eviction_rereports_but_never_loses() {
    let mut table = SessionTable::new(1);
    let a = record(1, reason::DATA_EXTEND, "a");
    assert_eq!(table.delta(&a), reason::DATA_EXTEND);
    let b = record(2, reason::DATA_OVERWRITE, "b");
    assert_eq!(table.delta(&b), reason::DATA_OVERWRITE, "b evicts a");
    let a_again = record(1, reason::DATA_EXTEND, "a");
    assert_eq!(
      table.delta(&a_again),
      reason::DATA_EXTEND,
      "the evicted session re-reports — noisy, never silent"
    );
  }

  #[test]
  fn frn_keyed_halves_pair() {
    let mut pairer = UsnPairer::new();
    let mut out = Vec::new();
    let mut table = SessionTable::new(16);

    let old = record(7, reason::RENAME_OLD_NAME, "before");
    let delta = table.delta(&old);
    pairer.push(old, delta, &mut out);
    assert!(out.is_empty());
    assert!(pairer.holds_old());

    // The NEW half is a fresh session (the OLD closed its own record), so
    // its cumulative mask stands alone.
    let new = record(7, reason::RENAME_NEW_NAME, "after");
    let delta = table.delta(&new);
    pairer.push(new, delta, &mut out);
    assert_eq!(out.len(), 1);
    assert!(matches!(&out[0], UsnEvent::Renamed { old, new }
      if old.name == UsnName::Utf8("before".into())
        && new.name == UsnName::Utf8("after".into())));
  }

  #[test]
  fn a_different_frn_widows_both() {
    let mut pairer = UsnPairer::new();
    let mut out = Vec::new();
    pairer.push(
      record(7, reason::RENAME_OLD_NAME, "x"),
      reason::RENAME_OLD_NAME,
      &mut out,
    );
    pairer.push(
      record(9, reason::RENAME_NEW_NAME, "y"),
      reason::RENAME_NEW_NAME,
      &mut out,
    );
    assert_eq!(out.len(), 2);
    assert!(matches!(&out[0], UsnEvent::WidowOld(rec) if rec.frn == 7));
    assert!(matches!(&out[1], UsnEvent::WidowNew(rec) if rec.frn == 9));
  }

  #[test]
  fn an_intervening_record_widows_in_order() {
    let mut pairer = UsnPairer::new();
    let mut out = Vec::new();
    pairer.push(
      record(7, reason::RENAME_OLD_NAME, "x"),
      reason::RENAME_OLD_NAME,
      &mut out,
    );
    pairer.push(
      record(8, reason::FILE_CREATE, "z"),
      reason::FILE_CREATE,
      &mut out,
    );
    assert_eq!(out.len(), 2);
    assert!(matches!(&out[0], UsnEvent::WidowOld(_)));
    assert!(matches!(&out[1], UsnEvent::Single(rec) if rec.frn == 8));
    pairer.flush(&mut out);
    assert_eq!(out.len(), 2, "flush on empty is a no-op");
  }

  /// A record is routed by its LINK; a session is keyed by its OBJECT. The
  /// table therefore remembers where a session's replayable notices went, and
  /// hands that back at the close — where the closing record names only the
  /// LAST handle's link, which for a hard-linked file need not be any of them.
  #[test]
  fn a_retired_session_surrenders_the_links_its_notices_went_to() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::DATA_OVERWRITE, "in.txt")),
      reason::DATA_OVERWRITE
    );
    table.note_link(7, 10, &UsnName::Utf8("in.txt".into()));
    // The second write records nothing; the close arrives through the file's
    // OTHER link.
    let outcome = table.observe(&record(
      7,
      reason::DATA_OVERWRITE | reason::CLOSE,
      "out.txt",
    ));
    assert_eq!(
      outcome.mask,
      reason::DATA_OVERWRITE,
      "the replay still fires"
    );
    let Stranded::Retired(links) = outcome.stranded else {
      panic!(
        "the close must surrender its targets: {:?}",
        outcome.stranded
      );
    };
    assert_eq!(links.held().len(), 1);
    assert!(links.held()[0].is(10, &UsnName::Utf8("in.txt".into())));
    assert!(
      !links.held()[0].is(10, &UsnName::Utf8("out.txt".into())),
      "one directory holding both links does not make them one link"
    );
  }

  /// Nothing replayable delivered means nothing owed: a purely structural
  /// session surrenders no targets and buys no covers.
  #[test]
  fn a_session_that_delivered_nothing_replayable_strands_nothing() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::FILE_CREATE, "f")),
      reason::FILE_CREATE
    );
    let outcome = table.observe(&record(7, reason::FILE_CREATE | reason::CLOSE, "f"));
    assert_eq!(outcome.stranded, Stranded::Nothing);
  }

  /// Retention is bounded by construction and SAYS SO when the bound bites: a
  /// session naming more distinct links than the ceiling holds keeps the first
  /// few and latches saturation, so the caller degrades to one root-wide cover
  /// instead of enumerating a set that is silently short.
  #[test]
  fn the_link_ceiling_saturates_rather_than_growing() {
    let mut table = SessionTable::new(16);
    assert_eq!(
      table.delta(&record(7, reason::DATA_OVERWRITE, "l0")),
      reason::DATA_OVERWRITE
    );
    for n in 0..=REPLAY_LINK_CAP {
      let parent = 100 + n as u128;
      table.note_link(7, parent, &UsnName::Utf8(format!("l{n}")));
    }
    let outcome = table.observe(&record(7, reason::DATA_OVERWRITE | reason::CLOSE, "l0"));
    let Stranded::Retired(links) = outcome.stranded else {
      panic!("{:?}", outcome.stranded);
    };
    assert_eq!(
      links.held().len(),
      REPLAY_LINK_CAP,
      "retention stops at the ceiling"
    );
    assert!(links.saturated(), "and reports that it did");
  }

  /// The same link named over and over is one target: the ceiling bounds
  /// DISTINCT links, so ordinary repeated traffic can never saturate it.
  #[test]
  fn repeating_one_link_never_consumes_the_ceiling() {
    let mut table = SessionTable::new(16);
    table.delta(&record(7, reason::DATA_OVERWRITE, "f"));
    for _ in 0..64 {
      table.note_link(7, 10, &UsnName::Utf8("f".into()));
    }
    let outcome = table.observe(&record(7, reason::DATA_OVERWRITE | reason::CLOSE, "f"));
    let Stranded::Retired(links) = outcome.stranded else {
      panic!("{:?}", outcome.stranded);
    };
    assert_eq!(links.held().len(), 1);
    assert!(!links.saturated());
  }

  /// The cap is where a bound usually turns into the loss it exists to
  /// survive. An evicted session's MASK may go — its subject re-reports — but
  /// its replay targets are an obligation, so they are handed to the caller to
  /// cover rather than dropped where nobody can see it.
  #[test]
  fn an_eviction_surrenders_its_links_rather_than_dropping_them() {
    let mut table = SessionTable::new(1);
    table.delta(&record(1, reason::DATA_OVERWRITE, "a"));
    table.note_link(1, 10, &UsnName::Utf8("a".into()));
    let outcome = table.observe(&record(2, reason::DATA_OVERWRITE, "b"));
    let Stranded::Evicted(links) = outcome.stranded else {
      panic!(
        "the cap must surrender what it forgets: {:?}",
        outcome.stranded
      );
    };
    assert_eq!(links.held().len(), 1);
    assert!(links.held()[0].is(10, &UsnName::Utf8("a".into())));
  }

  /// The cap frees an ENTRY; it frees no DEBT. An evicted session is still
  /// OPEN, so a repeat of a class already in its mask goes on writing no record
  /// — and the close that finally arrives finds nothing to surrender. The
  /// one-time cover the eviction itself emitted repairs only what preceded it,
  /// so the ledger keeps the file reference and the close pays at the root.
  #[test]
  fn an_evicted_sessions_debt_outlives_the_entry_that_named_it() {
    let mut table = SessionTable::new(1);
    table.delta(&record(1, reason::DATA_OVERWRITE, "a"));
    table.note_link(1, 10, &UsnName::Utf8("a".into()));
    let evicting = table.observe(&record(2, reason::DATA_OVERWRITE, "b"));
    assert!(
      matches!(evicting.stranded, Stranded::Evicted(_)),
      "the premise: the cap took the entry: {evicting:?}"
    );
    assert_eq!(table.orphans(), 1, "and the debt was remembered");
    // The evicted session goes on writing (no records at all) and closes.
    let closed = table.observe(&record(1, reason::DATA_OVERWRITE | reason::CLOSE, "a"));
    assert!(
      closed.unnamed.replay,
      "the close pays what the cap can no longer name: {closed:?}"
    );
    assert_eq!(
      table.orphans(),
      0,
      "and the marker is discharged exactly once"
    );
  }

  /// THE MEASURED STREAM, fed record for record, with the reason words exactly
  /// as the journal wrote them on `windows-2022` and `windows-2025`:
  /// `repeat-first.txt -> repeat-second.txt -> repeat-third.txt` through ONE
  /// held handle. This is the witness the whole repeat-rename retirement rests
  /// on, so it is driven off the hardware trace rather than off a model of it.
  ///
  /// Two things are asserted, and the second is why the covers are gone. Each
  /// move's halves arrive FRESH — the two rename bits alternate, so the second
  /// move's departing half meets a mask holding only the arriving one — and the
  /// close, which re-asserts `RENAME_NEW_NAME`, owes nothing at all. The second
  /// move is not something to be covered for; it is something already reported.
  #[test]
  fn the_measured_two_move_session_reports_every_move_and_owes_no_cover() {
    let mut table = SessionTable::new(16);
    // usn=38264 reason=0x00000100 name=repeat-first.txt
    assert_eq!(
      table.delta(&record(7, 0x0000_0100, "repeat-first.txt")),
      0x0000_0100
    );
    // usn=38360 reason=0x00001100 name=repeat-first.txt
    assert_eq!(
      table.delta(&record(7, 0x0000_1100, "repeat-first.txt")),
      reason::RENAME_OLD_NAME,
      "the first move's departing half is fresh"
    );
    // usn=38456 reason=0x00002100 name=repeat-second.txt
    assert_eq!(
      table.delta(&record(7, 0x0000_2100, "repeat-second.txt")),
      reason::RENAME_NEW_NAME,
      "and its arriving half"
    );
    // usn=38552 reason=0x00001100 name=repeat-second.txt — the SECOND move,
    // which the retired class believed the journal never wrote.
    assert_eq!(
      table.delta(&record(7, 0x0000_1100, "repeat-second.txt")),
      reason::RENAME_OLD_NAME,
      "the second move's departing half is fresh too: writing the arriving half \
       cleared the departing bit, so nothing about it is a repeat"
    );
    // usn=38648 reason=0x00002100 name=repeat-third.txt
    assert_eq!(
      table.delta(&record(7, 0x0000_2100, "repeat-third.txt")),
      reason::RENAME_NEW_NAME,
      "and so is its arriving half"
    );
    // usn=38744 reason=0x80002100 CLOSE name=repeat-third.txt
    let closed = table.observe(&record(7, 0x8000_2100, "repeat-third.txt"));
    assert_eq!(
      closed.unnamed,
      Unnamed::NOTHING,
      "the close re-asserts RENAME_NEW_NAME and owes nothing for it: both moves \
       were already reported by the four records above: {closed:?}"
    );
    assert_eq!(
      closed.mask & reason::RENAME,
      0,
      "and it announces no naming verb of its own: {closed:?}"
    );
  }

  /// The same verdict asked of every shape the retired cover used to fire on,
  /// held together in one cell because they were one class: a rename whose
  /// endpoints this scope reported, one whose endpoints it did not, and the same
  /// pair for a DIRECTORY — which used to buy the reseed spine rather than a
  /// plain cover. All four now owe nothing, because in all four the moves that
  /// happened wrote the records that report them.
  #[test]
  fn no_close_buys_a_cover_for_the_rename_bits_it_carries() {
    for attributes in [0x20u32, 0x10] {
      for name in ["in.txt", "outside.txt"] {
        let mut table = SessionTable::new(16);
        let mut departing = record(7, reason::RENAME_OLD_NAME, name);
        departing.attributes = attributes;
        table.observe(&departing);
        let mut arriving = record(7, reason::RENAME_NEW_NAME, name);
        arriving.attributes = attributes;
        table.observe(&arriving);
        let mut closing = record(7, reason::RENAME_NEW_NAME | reason::CLOSE, name);
        closing.attributes = attributes;
        let closed = table.observe(&closing);
        assert_eq!(
          closed.unnamed,
          Unnamed::NOTHING,
          "attributes={attributes:#x} name={name}: a re-asserted rename bit is \
           evidence of nothing: {closed:?}"
        );
      }
    }
  }

  /// And an EVICTION stores no rename marker either. The cap took the entry
  /// while the session was open, which used to matter because the entry was the
  /// only place remembering that a further move would be silent. It would not be
  /// silent, so there is nothing to remember — and the ledger's bound is left for
  /// the debts that are real, which is what a repeated WRITE still owes.
  #[test]
  fn an_evicted_pure_rename_leaves_no_marker() {
    for attributes in [0x20u32, 0x10] {
      let mut table = SessionTable::new(1);
      let mut renamed = record(1, reason::RENAME_NEW_NAME, "moved");
      renamed.attributes = attributes;
      table.observe(&renamed);
      let evicting = table.observe(&record(2, reason::DATA_OVERWRITE, "b"));
      assert_eq!(
        evicting.stranded,
        Stranded::Nothing,
        "the premise: a pure rename retains no link to surrender: {evicting:?}"
      );
      assert_eq!(
        table.orphans(),
        0,
        "attributes={attributes:#x}: nothing about a reported move is owed later"
      );
      let mut closing = record(1, reason::RENAME_NEW_NAME | reason::CLOSE, "moved");
      closing.attributes = attributes;
      let closed = table.observe(&closing);
      assert_eq!(
        closed.unnamed,
        Unnamed::NOTHING,
        "and the close finds nothing to pay: {closed:?}"
      );
    }
  }

  /// And the same four shapes on a volume NOBODY MEASURED, where every one of
  /// them owes again.
  ///
  /// The measurement was taken on NTFS and speaks for NTFS. The source admits
  /// any active V2/V3 journal — ReFS emits V3 — so a volume whose rename bits
  /// might accumulate instead of alternating keeps the cover the measurement
  /// retired: a file's stale name is one root-scoped cover, a mapped directory's
  /// is the reseed spine, and the closing record's own attributes say which.
  ///
  /// Whether the endpoints were inside the reported tree is deliberately NOT
  /// asked. The retired booking asked, and discharged a directory whose every
  /// observed endpoint lay outside the root on the grounds that a directory has
  /// exactly one link — which is a fact about NTFS, on a volume that is not
  /// NTFS. So the unmeasured path books off the mask alone: strictly more covers
  /// than the class ever paid, on strictly fewer volumes than it ever ran on.
  #[test]
  fn an_unmeasured_volume_still_covers_a_re_asserted_rename() {
    for (attributes, expected) in [
      (
        0x20u32,
        Unnamed {
          replay: false,
          location: true,
          topology: false,
        },
      ),
      (
        0x10,
        Unnamed {
          replay: false,
          location: false,
          topology: true,
        },
      ),
    ] {
      for name in ["in.txt", "outside.txt"] {
        let mut table = SessionTable::new(16).with_rename_semantics(RenameSemantics::Unmeasured);
        let mut departing = record(7, reason::RENAME_OLD_NAME, name);
        departing.attributes = attributes;
        table.observe(&departing);
        let mut arriving = record(7, reason::RENAME_NEW_NAME, name);
        arriving.attributes = attributes;
        table.observe(&arriving);
        let mut closing = record(7, reason::RENAME_NEW_NAME | reason::CLOSE, name);
        closing.attributes = attributes;
        let closed = table.observe(&closing);
        assert_eq!(
          closed.unnamed, expected,
          "attributes={attributes:#x} name={name}: an unmeasured volume's \
           re-asserted rename bit is evidence the location may have moved in \
           silence: {closed:?}"
        );
        assert!(
          closed.unnamed.disowns_its_record(),
          "and the record that paid for the cover does not then speak at the \
           name the cover calls unprovable: {closed:?}"
        );
      }
    }
  }

  /// A close whose rename bits are all FRESH owes nothing even on an unmeasured
  /// volume: the move it carries is the move it reports, and the cover answers a
  /// SECOND move that wrote nothing — not a first one that wrote this.
  #[test]
  fn an_unmeasured_volume_owes_nothing_for_a_renames_own_close() {
    let mut table = SessionTable::new(16).with_rename_semantics(RenameSemantics::Unmeasured);
    table.observe(&record(7, reason::DATA_OVERWRITE, "f"));
    let closed = table.observe(&record(
      7,
      reason::DATA_OVERWRITE | reason::RENAME_NEW_NAME | reason::CLOSE,
      "f2",
    ));
    assert_eq!(
      closed.unnamed,
      Unnamed::NOTHING,
      "a first move announces itself: {closed:?}"
    );
    assert_eq!(
      closed.mask & reason::RENAME_NEW_NAME,
      reason::RENAME_NEW_NAME,
      "and is lowered as the naming verb it is: {closed:?}"
    );
  }

  /// An EVICTION on an unmeasured volume leaves the marker the entry used to
  /// carry — and leaves the coarser of the two forms, because the entry the cap
  /// took was the only thing that knew the subject's kind and the ledger holds
  /// no kind at all.
  #[test]
  fn an_evicted_rename_on_an_unmeasured_volume_leaves_a_marker() {
    for attributes in [0x20u32, 0x10] {
      let mut table = SessionTable::new(1).with_rename_semantics(RenameSemantics::Unmeasured);
      let mut renamed = record(1, reason::RENAME_NEW_NAME, "moved");
      renamed.attributes = attributes;
      table.observe(&renamed);
      table.observe(&record(2, reason::DATA_OVERWRITE, "b"));
      assert_eq!(
        table.orphans(),
        1,
        "attributes={attributes:#x}: the cap freed the entry and freed no debt"
      );
      let mut closing = record(1, reason::RENAME_NEW_NAME | reason::CLOSE, "moved");
      closing.attributes = attributes;
      let closed = table.observe(&closing);
      assert!(
        closed.unnamed.topology,
        "and the close pays the reseed the ledger could not narrow: {closed:?}"
      );
      assert_eq!(
        table.orphans(),
        0,
        "settled by the one record that proves it"
      );
    }
  }

  /// The ledger's OWN bound, and its behaviour at it. A marker drains only at a
  /// close and a session that is never closed never produces one, so the named
  /// set has to stop growing — but the sessions behind those markers are still
  /// OPEN, and paying an open session's debt settles nothing: it covers what
  /// preceded the payment and says nothing about the next unrecorded write. So
  /// the bound takes a debt's NAME and never the debt. The markers already held
  /// stay exactly where they are, and what overflows becomes an anonymous
  /// residue that every later close pays.
  #[test]
  fn the_orphan_ledgers_bound_takes_a_debts_name_never_the_debt() {
    let mut table = SessionTable::new(1);
    for frn in 1..=3u128 {
      // One live slot: each record evicts its predecessor, which owes a repair
      // to the link it just registered.
      let evicting = table.observe(&record(frn, reason::DATA_OVERWRITE, "f"));
      assert_eq!(
        evicting.unnamed,
        Unnamed::NOTHING,
        "no bound may settle an open session's debt in band: {evicting:?}"
      );
      table.note_link(frn, 10, &UsnName::Utf8(format!("l{frn}")));
    }
    assert_eq!(
      table.orphans(),
      1,
      "the named set stopped growing at its bound"
    );
    assert!(
      table.owed.anonymous,
      "and what overflowed it kept everything but its name"
    );

    // The FIRST evicted session — the one a displacing bound would have
    // forgotten — writes again in silence and closes on a foreign link.
    let first = table.observe(&record(
      1,
      reason::DATA_OVERWRITE | reason::CLOSE,
      "elsewhere",
    ));
    assert!(
      first.unnamed.replay,
      "a marker already held is never displaced: {first:?}"
    );

    // And a session the ledger can no longer name at all still gets covered,
    // because the residue cannot tell whose close this is.
    let stranger = table.observe(&record(
      99,
      reason::DATA_OVERWRITE | reason::CLOSE,
      "stranger",
    ));
    assert!(
      stranger.unnamed.topology,
      "the residue is owed at every close while it stands: {stranger:?}"
    );
    assert!(
      table.owed.anonymous,
      "and paying it once proves nothing about the sessions still open"
    );
  }

  /// A session that owed nothing leaves no marker: the ledger is an obligation
  /// store, not an eviction log, and filling it with sessions that delivered
  /// nothing would spend its whole bound on covers nobody is owed.
  #[test]
  fn an_eviction_that_owed_nothing_leaves_no_marker() {
    let mut table = SessionTable::new(1);
    table.delta(&record(1, reason::FILE_CREATE, "a"));
    let evicting = table.observe(&record(2, reason::DATA_OVERWRITE, "b"));
    assert_eq!(evicting.stranded, Stranded::Nothing);
    assert_eq!(evicting.unnamed, Unnamed::NOTHING);
    assert_eq!(table.orphans(), 0);
  }

  /// A retarget that cannot PROVE which retained link the rename moved degrades
  /// the whole set to the root cover. Leaving an elided target alone would aim
  /// the close at a name the rename may have retired; retargeting it blindly
  /// would aim it at one the subject may never have occupied. Neither is a
  /// statement this layer can make, so it stops naming links at all.
  #[test]
  fn a_retarget_that_cannot_prove_which_link_moved_covers_the_root() {
    let mut table = SessionTable::new(16);
    table.delta(&record(7, reason::DATA_OVERWRITE, "f"));
    table.note_link(7, 10, &UsnName::Utf8("n".repeat(REPLAY_NAME_BYTES + 1)));
    table.retarget_link(
      7,
      10,
      &UsnName::Utf8("some-other-name".into()),
      10,
      &UsnName::Utf8("moved".into()),
    );
    let outcome = table.observe(&record(7, reason::DATA_OVERWRITE | reason::CLOSE, "f"));
    let Stranded::Retired(links) = outcome.stranded else {
      panic!("{:?}", outcome.stranded);
    };
    assert!(
      links.saturated(),
      "an unprovable retarget stops enumerating: {links:?}"
    );
  }

  /// The ordinary retarget moves the debt and spends no retention: one link
  /// before, one link after, at the new name, with no saturation.
  #[test]
  fn a_retarget_moves_the_debt_without_spending_a_second_target() {
    let mut table = SessionTable::new(16);
    table.delta(&record(7, reason::DATA_OVERWRITE, "f"));
    table.note_link(7, 10, &UsnName::Utf8("old".into()));
    table.retarget_link(
      7,
      10,
      &UsnName::Utf8("old".into()),
      11,
      &UsnName::Utf8("new".into()),
    );
    let outcome = table.observe(&record(7, reason::DATA_OVERWRITE | reason::CLOSE, "f"));
    let Stranded::Retired(links) = outcome.stranded else {
      panic!("{:?}", outcome.stranded);
    };
    assert_eq!(links.held().len(), 1, "{links:?}");
    assert!(links.held()[0].is(11, &UsnName::Utf8("new".into())));
    assert!(!links.saturated());
  }

  /// A retarget onto a link the session ALREADY holds collapses to one target.
  /// Retention counts DISTINCT links, and a count left above the truth would
  /// saturate a session into a root-wide cover on ordinary traffic.
  #[test]
  fn a_retarget_onto_a_held_link_collapses_rather_than_double_counting() {
    let mut table = SessionTable::new(16);
    table.delta(&record(7, reason::DATA_OVERWRITE, "f"));
    table.note_link(7, 10, &UsnName::Utf8("one".into()));
    table.note_link(7, 10, &UsnName::Utf8("two".into()));
    table.retarget_link(
      7,
      10,
      &UsnName::Utf8("one".into()),
      10,
      &UsnName::Utf8("two".into()),
    );
    let outcome = table.observe(&record(7, reason::DATA_OVERWRITE | reason::CLOSE, "f"));
    let Stranded::Retired(links) = outcome.stranded else {
      panic!("{:?}", outcome.stranded);
    };
    assert_eq!(links.held().len(), 1, "{links:?}");
    assert!(links.held()[0].is(10, &UsnName::Utf8("two".into())));
  }

  /// A name is retained inline or not at all — never truncated, because a
  /// truncated name compares equal to nothing and would be indistinguishable
  /// from a different link. An elided target can therefore never be PROVEN
  /// identical to a closing link, so it is covered rather than assumed paid.
  #[test]
  fn a_name_past_the_inline_ceiling_elides_and_is_never_assumed_covered() {
    let long = "n".repeat(REPLAY_NAME_BYTES + 1);
    let elided = ReplayLink::new(10, &UsnName::Utf8(long.clone()));
    assert_eq!(elided.name(), None);
    assert!(
      !elided.is(10, &UsnName::Utf8(long)),
      "an elided name proves nothing about identity"
    );
    let unspellable = ReplayLink::new(10, &UsnName::Escalate);
    assert_eq!(unspellable.name(), None);
    assert!(!unspellable.is(10, &UsnName::Escalate));

    let exact = "n".repeat(REPLAY_NAME_BYTES);
    let fits = ReplayLink::new(10, &UsnName::Utf8(exact.clone()));
    assert_eq!(
      fits.name(),
      Some(exact.as_str()),
      "the ceiling is inclusive"
    );
    assert!(fits.is(10, &UsnName::Utf8(exact.clone())));
    assert!(
      !fits.is(11, &UsnName::Utf8(exact)),
      "the parent is half of a link's identity"
    );
  }

  /// The retained footprint is arithmetic, not a hope. One session entry is a
  /// fixed-size record — a mask, a fixed array of fixed-size targets and the
  /// obligation flags — so the table's whole cost is that constant times the
  /// session cap, and a workload that keeps naming new links saturates instead
  /// of buying memory. The ceiling is asserted rather than described so a target
  /// that starts owning its name (a `String`, a `PathBuf`) cannot slip in
  /// unnoticed.
  ///
  /// The entry measures 288 bytes, and RETIRING THREE FLAGS RETURNED NONE OF
  /// THEM. `ReplayLink` aligns to 16 for its `u128` parent, so the array leaves
  /// tail padding the booleans sat inside: the entry was 288 bytes with the
  /// location obligation, its latent half and `is_dir`, and it is 288 bytes
  /// without them. The retirement's return is a COVER RATE, not memory, and
  /// saying so here is the point of asserting a ceiling rather than an exact
  /// size — "one more flag" was free, and so was one fewer.
  ///
  /// KEEPING THE COVER FOR UNMEASURED FILESYSTEMS ADDED NOTHING HERE EITHER. It
  /// reads its trigger off `last` and its shape off the closing record, so the
  /// entry is untouched; what it costs is one byte on the TABLE, once, for the
  /// whole volume. The orphan marker carries the third obligation again and is
  /// three bools once more — three bytes against a ceiling of sixteen, which is
  /// what the assertion below exists to keep true.
  #[test]
  fn one_sessions_retained_state_is_a_constant() {
    const CEILING: usize = 512;
    assert!(
      std::mem::size_of::<Session>() <= CEILING,
      "a session entry must stay a small constant: {}",
      std::mem::size_of::<Session>()
    );
    assert_eq!(
      std::mem::size_of::<ReplayLinks>(),
      std::mem::size_of::<[ReplayLink; REPLAY_LINK_CAP]>() + std::mem::align_of::<ReplayLink>(),
      "the target set is the array and its two counters, with nothing owned \
       elsewhere"
    );
    // The orphan ledger's entry is a file reference and three bits. It is
    // measured for the same reason: a marker that started carrying the links it
    // exists to have LOST would give the cap nothing back.
    assert!(
      std::mem::size_of::<Unnamed>() <= std::mem::size_of::<u128>(),
      "an orphan marker must stay smaller than what it replaced: {}",
      std::mem::size_of::<Unnamed>()
    );
    // And the ledger's overflow is a FLAG, not a second store. What the bound
    // surrenders is a debt's name; if the residue ever grew a container it
    // would have a bound of its own, and a bound whose overflow is another
    // bound is how "pay once and forget" gets back in.
    assert!(
      std::mem::size_of::<OrphanLedger>()
        <= std::mem::size_of::<std::collections::BTreeMap<u128, Unnamed>>()
          + std::mem::size_of::<usize>() * 2,
      "the residue is a flag beside the named map and its cap, never a second \
       store: {}",
      std::mem::size_of::<OrphanLedger>()
    );
  }

  #[test]
  fn vocabulary_partitions_are_disjoint() {
    assert_eq!(reason::MODIFY & reason::ATTRIB, 0);
    assert_eq!(reason::MODIFY & reason::STRUCTURAL, 0);
    assert_eq!(reason::ATTRIB & reason::STRUCTURAL, 0);
    assert_eq!(reason::FILTERED & reason::MODIFY, 0);
    assert_eq!(reason::FILTERED & reason::ATTRIB, 0);
    assert_eq!(reason::FILTERED & reason::STRUCTURAL, 0);
    assert_eq!(
      reason::CLOSE & (reason::MODIFY | reason::ATTRIB | reason::STRUCTURAL),
      0
    );
  }
}

#[cfg(test)]
mod admission_tests {
  use super::{
    RenameSemantics, UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  const ROOT: u128 = 1;

  fn admission() -> UsnAdmission {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into()), (20, 10, "b".into())]);
    UsnAdmission::new(map, 64)
  }

  fn record(frn: u128, parent: u128, reason_mask: u32, attrs: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: attrs,
      name: UsnName::Utf8(name.into()),
    }
  }

  #[test]
  fn membership_is_the_parent_map() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(50, 20, reason::FILE_CREATE, 0x20, "f.txt"), &mut out);
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), is_dir: false, .. }
      if c == &["a".to_owned(), "b".to_owned(), "f.txt".to_owned()])
    );

    out.clear();
    adm.admit(
      record(60, 999, reason::FILE_CREATE, 0x20, "alien"),
      &mut out,
    );
    assert!(out.is_empty(), "an unmapped parent is outside the root");
  }

  #[test]
  fn directory_lifecycle_maintains_the_map() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(30, 20, reason::FILE_CREATE, 0x10, "c"), &mut out);
    out.clear();
    adm.admit(
      record(70, 30, reason::FILE_CREATE, 0x20, "under-c"),
      &mut out,
    );
    assert_eq!(out.len(), 1, "the freshly-learned dir admits its children");

    out.clear();
    adm.admit(
      record(30, 20, reason::FILE_DELETE | reason::CLOSE, 0x10, "c"),
      &mut out,
    );
    assert_eq!(out.len(), 1);
    out.clear();
    adm.admit(record(80, 30, reason::FILE_CREATE, 0x20, "ghost"), &mut out);
    assert!(out.is_empty(), "the forgotten dir no longer admits");
  }

  #[test]
  fn an_in_root_rename_resolves_both_ends_and_reparents() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(20, 10, reason::RENAME_OLD_NAME, 0x10, "b"), &mut out);
    assert!(out.is_empty(), "the OLD half parks");
    adm.admit(
      record(20, ROOT, reason::RENAME_NEW_NAME, 0x10, "b2"),
      &mut out,
    );
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], UsnAdmitted::Renamed { old: UsnTarget::Resolved(o), new: UsnTarget::Resolved(n), is_dir: true, .. }
      if o == &["a".to_owned(), "b".to_owned()] && n == &["b2".to_owned()])
    );

    out.clear();
    adm.admit(record(90, 20, reason::FILE_CREATE, 0x20, "x"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["b2".to_owned(), "x".to_owned()]),
      "children resolve through the reparented chain: {out:?}"
    );
  }

  #[test]
  fn root_structural_records_are_the_scopes_death() {
    // A root delete is immediate.
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(ROOT, 999, reason::FILE_DELETE | reason::CLOSE, 0x10, "root"),
      &mut out,
    );
    assert!(matches!(out.as_slice(), [UsnAdmitted::RootDeath]));

    // A root rename's OLD half parks like any other; whether its NEW pairs
    // or the carry widows (the synthetic delete), the death still surfaces.
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(ROOT, 999, reason::RENAME_OLD_NAME, 0x10, "root"),
      &mut out,
    );
    assert!(out.is_empty(), "the OLD half parks first");
    adm.flush(&mut out);
    assert!(matches!(out.as_slice(), [UsnAdmitted::RootDeath]));
  }

  #[test]
  fn widows_degrade_to_membership_verbs() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(20, 10, reason::RENAME_OLD_NAME, 0x10, "b"), &mut out);
    let mut flushed = Vec::new();
    adm.flush(&mut flushed);
    assert_eq!(flushed.len(), 1);
    assert!(
      matches!(&flushed[0], UsnAdmitted::Single { delta, is_dir: true, .. }
      if delta & reason::FILE_DELETE != 0),
      "a widowed OLD is membership-wise a delete: {flushed:?}"
    );
  }

  #[test]
  fn filtered_bits_never_admit() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        20,
        reason::OBJECT_ID_CHANGE | reason::TRANSACTED_CHANGE,
        0x20,
        "f",
      ),
      &mut out,
    );
    assert!(out.is_empty(), "{out:?}");
  }

  /// A rename half the pairer could not pair is DEGRADED to a membership verb
  /// — but the rename it proves rides along. Without it, admission is decided
  /// by `Removed`/`Created` alone and a subscription asking only about moves
  /// receives neither half of the rename and no rescan.
  #[test]
  fn a_widowed_rename_half_keeps_its_move_evidence() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::RENAME_OLD_NAME, 0x20, "before"),
      &mut out,
    );
    assert!(out.is_empty(), "the OLD parks in the carry slot");
    adm.flush(&mut out);
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { delta, .. }]
        if delta & reason::FILE_DELETE != 0 && delta & reason::RENAME_OLD_NAME != 0),
      "the widowed OLD names a removal AND proves the move: {out:?}"
    );

    out.clear();
    adm.admit(
      record(60, 20, reason::RENAME_NEW_NAME, 0x20, "after"),
      &mut out,
    );
    assert!(
      out
        .iter()
        .any(|event| matches!(event, UsnAdmitted::Single { delta, .. }
        if delta & reason::FILE_CREATE != 0 && delta & reason::RENAME_NEW_NAME != 0)),
      "the widowed NEW names a create AND proves the move: {out:?}"
    );
  }

  /// A rename that crosses the root boundary is pre-degraded to its in-root
  /// end's membership verb, and carries the same move evidence for the same
  /// reason.
  #[test]
  fn a_boundary_rename_keeps_its_move_evidence() {
    let mut adm = admission();
    let mut out = Vec::new();
    // OLD in-root, NEW under an unmapped parent: the object left the root.
    adm.admit(
      record(50, 20, reason::RENAME_OLD_NAME, 0x20, "here"),
      &mut out,
    );
    adm.admit(
      record(50, 999, reason::RENAME_NEW_NAME, 0x20, "elsewhere"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { delta, .. }]
        if delta & reason::FILE_DELETE != 0 && delta & reason::RENAME_OLD_NAME != 0),
      "{out:?}"
    );
  }

  /// A rename of the watched ROOT ends the scope whichever half survives the
  /// read window. The departing half already did; the arriving half — the
  /// shape a cursor that fell between the two produces — used to be published
  /// as a self-`Created` on a root that had already moved away.
  #[test]
  fn either_half_of_a_root_rename_is_the_scopes_death() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(ROOT, 999, reason::RENAME_OLD_NAME, 0x10, "root"),
      &mut out,
    );
    adm.flush(&mut out);
    assert!(matches!(&out[..], [UsnAdmitted::RootDeath]), "{out:?}");

    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(ROOT, 999, reason::RENAME_NEW_NAME, 0x10, "renamed"),
      &mut out,
    );
    assert!(matches!(&out[..], [UsnAdmitted::RootDeath]), "{out:?}");

    // Pure metadata on the root is still an ordinary self-event.
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(ROOT, 999, reason::BASIC_INFO_CHANGE, 0x10, "root"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target, .. }] if *target == UsnTarget::Resolved(vec![])),
      "{out:?}"
    );
  }

  /// A replayed create that contradicts the map's standing topology asks for
  /// the RESEED, not the source's death: the map is stale, not overfull.
  #[test]
  fn a_contradicting_record_asks_to_reseed_rather_than_die() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "A".into()), (20, 10, "P".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    // History: "A was created under P" — replayed against a map where P is
    // already inside A.
    adm.admit(record(10, 20, reason::FILE_CREATE, 0x10, "A"), &mut out);
    assert!(
      matches!(&out[..], [UsnAdmitted::MapInconsistent]),
      "{out:?}"
    );

    // The map is untouched by the refusal, so nothing resolves through a knot.
    let mut out = Vec::new();
    adm.admit(record(50, 20, reason::FILE_CREATE, 0x20, "f"), &mut out);
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }]
        if c == &["A".to_owned(), "P".to_owned(), "f".to_owned()]),
      "{out:?}"
    );
  }

  /// A contradiction voids everything the map resolves after it, so admission
  /// STOPS there and the cover is the batch's last word. Admitting the whole
  /// buffer left the root `Rescan` in the MIDDLE: a consumer re-read at it,
  /// believed itself consistent, and the suffix — paths resolved through the
  /// very topology the verdict disowned — re-diverged it on the spot, with the
  /// reseed's own loss signal arriving only afterwards.
  #[test]
  fn a_contradiction_stops_the_batch_and_the_cover_is_its_last_word() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "A".into()), (20, 10, "P".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    let verdict = adm.admit_batch(
      vec![
        record(50, 20, reason::FILE_CREATE, 0x20, "before"),
        // History replayed out of order: "A was created under P", against a
        // map where P already sits inside A.
        record(10, 20, reason::FILE_CREATE, 0x10, "A"),
        record(60, 20, reason::FILE_CREATE, 0x20, "after"),
      ],
      &mut out,
    );
    assert!(
      matches!(verdict, Some(UsnAdmitted::MapInconsistent)),
      "{verdict:?}"
    );
    assert_eq!(out.len(), 2, "the untrusted suffix is discarded: {out:?}");
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
        if c == &["A".to_owned(), "P".to_owned(), "before".to_owned()]),
      "the pre-verdict prefix still delivers: {out:?}"
    );
    assert!(
      matches!(out.last(), Some(UsnAdmitted::MapInconsistent)),
      "and the cover dominates everything in the batch: {out:?}"
    );
    assert!(
      !adm.holds_old(),
      "no half stays parked against a map about to be replaced"
    );
  }

  /// The other two verdicts end the batch the same way. An overfull map is
  /// permanently incomplete, and a dead root re-bases every later resolution
  /// on an anchor that is gone; neither is followed by a reseed that could
  /// correct a suffix, so neither may be given one.
  #[test]
  fn an_overflow_and_a_root_death_end_the_batch_too() {
    let mut adm = admission();
    let mut out = Vec::new();
    let verdict = adm.admit_batch(
      vec![
        record(50, 20, reason::FILE_CREATE, 0x20, "before"),
        UsnRecord {
          name: UsnName::Escalate,
          ..record(70, 20, reason::FILE_CREATE, 0x10, "")
        },
        record(60, 20, reason::FILE_CREATE, 0x20, "after"),
      ],
      &mut out,
    );
    assert!(
      matches!(verdict, Some(UsnAdmitted::MapOverflow)),
      "{verdict:?}"
    );
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(
      matches!(out.last(), Some(UsnAdmitted::MapOverflow)),
      "{out:?}"
    );

    let mut adm = admission();
    let mut out = Vec::new();
    let verdict = adm.admit_batch(
      vec![
        record(50, 20, reason::FILE_CREATE, 0x20, "before"),
        record(ROOT, 999, reason::FILE_DELETE | reason::CLOSE, 0x10, "root"),
        record(60, 20, reason::FILE_CREATE, 0x20, "after"),
      ],
      &mut out,
    );
    assert!(
      matches!(verdict, Some(UsnAdmitted::RootDeath)),
      "{verdict:?}"
    );
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(
      matches!(out.last(), Some(UsnAdmitted::RootDeath)),
      "{out:?}"
    );
  }

  /// The stop is exactly a stop: a buffer nothing contradicted admits whole,
  /// in journal order, and reports no verdict.
  #[test]
  fn an_uncontradicted_buffer_admits_whole() {
    let mut adm = admission();
    let mut out = Vec::new();
    let verdict = adm.admit_batch(
      vec![
        record(50, 20, reason::FILE_CREATE, 0x20, "one"),
        record(60, 20, reason::FILE_CREATE, 0x20, "two"),
        record(70, 20, reason::DATA_EXTEND, 0x20, "three"),
      ],
      &mut out,
    );
    assert!(verdict.is_none(), "{verdict:?}");
    assert_eq!(out.len(), 3, "{out:?}");
  }

  /// A rename half parked when the verdict lands widows AHEAD of the cover: it
  /// predates the verdict exactly as the admitted prefix does, so the cover
  /// dominates it too — never the other way round.
  #[test]
  fn a_parked_half_widows_ahead_of_the_cover() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "A".into()), (20, 10, "P".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    let verdict = adm.admit_batch(
      vec![
        record(50, 20, reason::RENAME_OLD_NAME, 0x20, "leaving"),
        record(10, 20, reason::FILE_CREATE, 0x10, "A"),
      ],
      &mut out,
    );
    assert!(
      matches!(verdict, Some(UsnAdmitted::MapInconsistent)),
      "{verdict:?}"
    );
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, .. } if delta & reason::FILE_DELETE != 0),
      "the widow comes first: {out:?}"
    );
    assert!(
      matches!(out.last(), Some(UsnAdmitted::MapInconsistent)),
      "{out:?}"
    );
    assert!(!adm.holds_old());
  }

  /// The hard-link scenario in full: a file linked as `a/b/in.txt` inside the
  /// watched tree and as `out.txt` under an unmapped parent, written through
  /// the in-root link, written AGAIN with no record at all (the repeat NTFS
  /// never writes), and closed last through the outside link.
  ///
  /// The close summary is the only convergence the journal offers, and it
  /// names `Open.Link.Name` — the closing handle's link. Routed there it was
  /// dropped as out-of-root, and the consumer that read the file at the first
  /// write held its half-written contents with nothing left in the stream to
  /// correct them. The repair is owed to the link the notice went to.
  #[test]
  fn a_close_through_an_out_of_root_hard_link_still_repairs_the_watched_one() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::DATA_OVERWRITE, 0x20, "in.txt"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::Resolved(c), delta, .. }]
        if c == &["a".to_owned(), "b".to_owned(), "in.txt".to_owned()]
          && delta & reason::MODIFY != 0),
      "the first write delivers at the in-root link: {out:?}"
    );

    // The second write records nothing. The close names the OUTSIDE link.
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "out.txt",
      ),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }]
        if c == &["a".to_owned(), "b".to_owned(), "in.txt".to_owned()]),
      "the replay must reach the link its notice went to: {out:?}"
    );
  }

  /// The retirement seen from OUTSIDE the table, and its scope.
  ///
  /// One in-root move followed by the close that re-asserts its arriving bit —
  /// the exact sequence the retired cover class fired on. On NTFS, the volume
  /// the measurement was taken on, the move is delivered and the close says
  /// nothing further. On a volume nobody measured, the same three records also
  /// buy the cover: a plain root rescan for a FILE, the reseed spine for a
  /// mapped DIRECTORY, and in neither case does the close then speak at a name
  /// the cover has just called unprovable.
  #[test]
  fn the_retirement_applies_only_where_its_premise_was_measured() {
    // (attributes, subject, parent, before, after)
    for (attrs, frn, parent, before, after) in [
      (0x20u32, 50u128, 20u128, "f.txt", "g.txt"),
      (0x10, 20, 10, "b", "c"),
    ] {
      for renames in [RenameSemantics::Measured, RenameSemantics::Unmeasured] {
        let mut adm = admission().with_rename_semantics(renames);
        let mut out = Vec::new();
        adm.admit(
          record(frn, parent, reason::RENAME_OLD_NAME, attrs, before),
          &mut out,
        );
        adm.admit(
          record(frn, parent, reason::RENAME_NEW_NAME, attrs, after),
          &mut out,
        );
        assert!(
          out.iter().any(|e| matches!(e, UsnAdmitted::Renamed { .. })),
          "{renames:?} attrs={attrs:#x}: the move itself is always reported: {out:?}"
        );

        out.clear();
        adm.admit(
          record(
            frn,
            parent,
            reason::RENAME_NEW_NAME | reason::CLOSE,
            attrs,
            after,
          ),
          &mut out,
        );
        match (renames, attrs) {
          (RenameSemantics::Measured, _) => assert!(
            out.is_empty(),
            "attrs={attrs:#x}: a re-asserted rename bit is evidence of nothing \
             where every move writes its own records: {out:?}"
          ),
          (RenameSemantics::Unmeasured, 0x10) => assert!(
            matches!(&out[..], [UsnAdmitted::MapInconsistent]),
            "a mapped directory that may have moved in silence takes every path \
             beneath it with it: {out:?}"
          ),
          (RenameSemantics::Unmeasured, _) => assert!(
            matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }]
              if c.is_empty()),
            "a file that may have moved in silence is covered at the root, the \
             only place provably a superset of a location nobody can name: {out:?}"
          ),
        }
      }
    }
  }

  /// The common shape pays nothing for the repair: one link, closed through
  /// itself, still delivers exactly one replay at that link and no cover.
  #[test]
  fn a_close_through_the_same_link_adds_no_cover() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::DATA_OVERWRITE, 0x20, "f.txt"),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(
        50,
        20,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "f.txt",
      ),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::Resolved(c), delta, .. }]
        if c == &["a".to_owned(), "b".to_owned(), "f.txt".to_owned()]
          && delta & reason::MODIFY != 0),
      "one delivery, at the link the close itself names: {out:?}"
    );
  }

  /// Both links in-root: the close's own routing repairs the one it names, and
  /// the other is covered. Neither consumer is left describing a stale file
  /// because the last handle happened to hold the other name.
  #[test]
  fn a_close_through_a_second_in_root_link_repairs_both() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::DATA_OVERWRITE, 0x20, "one.txt"),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(
        50,
        10,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "two.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c == &["a".to_owned(), "b".to_owned(), "one.txt".to_owned()])
      ),
      "the first link is covered: {out:?}"
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::Resolved(c), delta, .. }
          if c == &["a".to_owned(), "two.txt".to_owned()] && delta & reason::MODIFY != 0)
      ),
      "and the closing link takes the ordinary replay: {out:?}"
    );
  }

  /// A RENAME whose link would knot the parent chain is history replayed out of
  /// order, and the reseed spine — not a silently applied cycle — is its answer.
  ///
  /// The refusal is only DETECTABLE while the entry still stands: `reparent`
  /// declines the containment, and `learn` declines it again for the same
  /// reason. Discarding the subtree before either of them runs would leave
  /// `learn` looking at a leaf, and a leaf's new parent is never inside it — so
  /// the contradiction would apply, the chain would close into a cycle, and the
  /// next resolution would walk it. Pins the ordering the exclusion-geometry
  /// branch has to respect.
  #[test]
  fn a_rename_that_would_knot_the_chain_still_asks_to_reseed() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(10, ROOT, reason::RENAME_OLD_NAME, 0x10, "a"),
      &mut out,
    );
    adm.admit(
      record(
        10,
        20,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        0x10,
        "a",
      ),
      &mut out,
    );
    assert!(
      out
        .iter()
        .any(|e| matches!(e, UsnAdmitted::MapInconsistent)),
      "the contradiction reaches the reseed spine: {out:?}"
    );
  }

  /// A RENAME delivers replayable evidence too, and a delivery that never
  /// registers its link strands its own repair.
  ///
  /// The whole shape in one stream: a paired in-root rename whose departing
  /// record also carried `DATA_OVERWRITE` — evidence the pairing widens into the
  /// one `Moved` it becomes — then a repeat of that same class, which NTFS
  /// writes NO record for because the bit is already in the session's
  /// cumulative mask, then the close through an out-of-root hard link. With the
  /// rename's endpoints unregistered the session retires owing nothing, the
  /// close's own routing is dropped as out-of-root, and the consumer that read
  /// the file at the rename holds half-written contents forever.
  ///
  /// The link owed is the pairing's DESTINATION: that is where the `Moved` the
  /// consumer acted on was located, and the departing name no longer exists.
  #[test]
  fn a_paired_renames_evidence_is_owed_a_repair_at_the_link_it_reached() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        20,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "old.txt",
      ),
      &mut out,
    );
    adm.admit(
      record(
        50,
        20,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE | reason::RENAME_NEW_NAME,
        0x20,
        "new.txt",
      ),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Renamed { old_content, new, .. }]
        if old_content & reason::MODIFY != 0
          && matches!(new, UsnTarget::Resolved(c)
            if c == &["a".to_owned(), "b".to_owned(), "new.txt".to_owned()])),
      "the premise: the pair really did deliver content evidence: {out:?}"
    );

    // The second write records nothing — its class is already in the mask. The
    // close names a link outside the root entirely.
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE | reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "out.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), delta, .. }
          if c == &["a".to_owned(), "b".to_owned(), "new.txt".to_owned()]
            && delta & reason::MODIFY != 0)
      ),
      "the surviving in-root link is covered: {out:?}"
    );
    // And the located repair is the WHOLE of what the close owes. The close
    // re-asserts rename bits its session already held, which used to buy a
    // root-scoped cover alongside — an entire-tree rescan riding on an ordinary
    // one-move session, on every close this source observed.
    assert!(
      !out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c.is_empty())
      ),
      "and nothing rides alongside it at the root: {out:?}"
    );
  }

  /// The same duty on the DEGRADED shapes. A rename with one end out of root
  /// lowers to the in-root end's membership verb carrying that half's evidence,
  /// which is a delivery like any other — the arriving degrade here, whose
  /// surviving link is its destination.
  #[test]
  fn a_boundary_renames_evidence_is_owed_a_repair_too() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        999,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "outside.txt",
      ),
      &mut out,
    );
    adm.admit(
      record(
        50,
        20,
        reason::RENAME_OLD_NAME
          | reason::DATA_OVERWRITE
          | reason::RENAME_NEW_NAME
          | reason::BASIC_INFO_CHANGE,
        0x20,
        "arrived.txt",
      ),
      &mut out,
    );
    // The departing end is out of root, so the pair degrades to a create at the
    // arriving one — carrying the metadata fact its OWN record first proved
    // (the write was already spent on the departing half, which delivered
    // nothing because its link is outside the root).
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::Resolved(c), delta, .. }]
        if c == &["a".to_owned(), "b".to_owned(), "arrived.txt".to_owned()]
          && delta & reason::FILE_CREATE != 0
          && delta & reason::ATTRIB != 0),
      "the premise: the degrade delivered content evidence: {out:?}"
    );

    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::RENAME_OLD_NAME
          | reason::DATA_OVERWRITE
          | reason::RENAME_NEW_NAME
          | reason::BASIC_INFO_CHANGE
          | reason::CLOSE,
        0x20,
        "outside.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c == &["a".to_owned(), "b".to_owned(), "arrived.txt".to_owned()])
      ),
      "the in-root link the create landed at is covered: {out:?}"
    );
  }

  /// A rename that proves NOTHING replayable spends no RETENTION: the ceiling
  /// is four links per session, and spending one on a move that carried no
  /// evidence would saturate sessions into root-wide covers for free.
  ///
  /// The cell reads a cover naming a LOCATION inside the tree as the proof that
  /// retention was spent, and there is no other kind left to confuse it with:
  /// the close pays nothing at the root for the rename bits it re-asserts.
  #[test]
  fn a_rename_with_no_evidence_spends_no_retention() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::RENAME_OLD_NAME, 0x20, "old.txt"),
      &mut out,
    );
    adm.admit(
      record(
        50,
        20,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        0x20,
        "new.txt",
      ),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "out.txt",
      ),
      &mut out,
    );
    assert!(
      !out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if !c.is_empty())
      ),
      "no notice went out at a link, so no link is owed a repair: {out:?}"
    );
  }

  /// A rename retires the name its subject's earlier notices were registered
  /// under, and it does so whether or not the rename record proves anything of
  /// its own.
  ///
  /// The stream in full: a write at `old.txt`, the repeat NTFS writes NO record
  /// for, then a PURE `old.txt → new.txt` — no fresh content anywhere on either
  /// half — and finally the close through an out-of-root hard link. The
  /// consumer's state for this subject moved to `new.txt` when the `Moved` was
  /// delivered. Registering the debt only when a rename carried fresh
  /// replayable content left it standing at `old.txt`: the close covered a path
  /// the rename had already retired, and the live one — the one the consumer is
  /// actually holding, mid-write — received nothing at all.
  #[test]
  fn a_pure_rename_moves_the_repair_to_the_name_the_consumer_moved_to() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::DATA_OVERWRITE, 0x20, "old.txt"),
      &mut out,
    );
    // The second write records nothing. Then a move carrying no fresh bit but
    // the naming ones.
    adm.admit(
      record(
        50,
        20,
        reason::DATA_OVERWRITE | reason::RENAME_OLD_NAME,
        0x20,
        "old.txt",
      ),
      &mut out,
    );
    adm.admit(
      record(
        50,
        20,
        reason::DATA_OVERWRITE | reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        0x20,
        "new.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Renamed { new, old_content, new_content, .. }
        if matches!(new, UsnTarget::Resolved(c)
          if c == &["a".to_owned(), "b".to_owned(), "new.txt".to_owned()])
          && *old_content == 0
          && *new_content == 0)
      ),
      "the premise: the move proved nothing but itself: {out:?}"
    );

    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "out.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), delta, .. }
          if c == &["a".to_owned(), "b".to_owned(), "new.txt".to_owned()]
            && delta & reason::MODIFY != 0)
      ),
      "the repair follows the name the move delivered: {out:?}"
    );
    assert!(
      !out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c == &["a".to_owned(), "b".to_owned(), "old.txt".to_owned()])
      ),
      "and nothing is aimed at the name the rename retired: {out:?}"
    );
  }

  /// The other half of the same duty: a link the subject ARRIVES at owes a
  /// repair too, decided off the session's cumulative history rather than off
  /// the arriving record's own bits.
  ///
  /// A file written through a link outside the root delivers nothing here — but
  /// the class is now in its session mask, so every further write of it is
  /// written as no record at all. It then moves IN, carrying no fresh evidence,
  /// and its arrival IS delivered. From that moment the consumer holds a path
  /// whose contents can go on changing in complete silence, and only the close
  /// can repair it — which it cannot do if nothing registered the destination.
  #[test]
  fn a_move_in_mid_session_owes_its_destination_the_repair_its_own_record_cannot_prove() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 999, reason::DATA_OVERWRITE, 0x20, "outside.txt"),
      &mut out,
    );
    assert!(
      out.is_empty(),
      "the premise: the out-of-root write delivers nothing: {out:?}"
    );
    adm.admit(
      record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::RENAME_OLD_NAME,
        0x20,
        "outside.txt",
      ),
      &mut out,
    );
    adm.admit(
      record(
        50,
        20,
        reason::DATA_OVERWRITE | reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        0x20,
        "arrived.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::Resolved(c), delta, .. }
          if c == &["a".to_owned(), "b".to_owned(), "arrived.txt".to_owned()]
            && delta & reason::FILE_CREATE != 0
            && delta & reason::MODIFY == 0)
      ),
      "the premise: the arrival is delivered and proves no content: {out:?}"
    );

    // A further write records nothing at all; the close names the outside link.
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "outside.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), delta, .. }
          if c == &["a".to_owned(), "b".to_owned(), "arrived.txt".to_owned()]
            && delta & reason::MODIFY != 0)
      ),
      "the destination the subject arrived at is repaired: {out:?}"
    );
  }

  /// The cap surrenders an entry, and the entry is not the debt. The eviction's
  /// own cover repairs what happened BEFORE it; the session is still open, so
  /// everything it changes afterwards is written as no record, and the close is
  /// the only place left to repair it. Finding no entry there, the close used
  /// to say nothing — the bound converting pressure into permanent loss instead
  /// of into noise.
  #[test]
  fn an_evicted_session_still_owes_its_close_a_cover() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 1);
    let mut out = Vec::new();
    adm.admit(
      record(50, 10, reason::DATA_OVERWRITE, 0x20, "held.txt"),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(60, 10, reason::DATA_OVERWRITE, 0x20, "other.txt"),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c == &["a".to_owned(), "held.txt".to_owned()])
      ),
      "the premise: the eviction covered what it forgot: {out:?}"
    );
    // The evicted session goes on writing — no record — and closes through a
    // link outside the root, so its own routing repairs nothing.
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "out.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c.is_empty())
      ),
      "the close pays at the root what the cap can no longer name: {out:?}"
    );
  }

  /// A DIRECTORY renamed TWICE on one open handle, end to end through
  /// admission, driven off the reason words the journal was measured writing.
  ///
  /// This is the cell that used to assert the opposite. The second move was
  /// believed to write no record, so the map kept the first destination and the
  /// close bought a reseed to re-establish the whole tree. The journal writes
  /// both moves, the delta arithmetic already hands each half its fresh bit, and
  /// the pairer already turns them into two `Renamed` events — so the map is
  /// re-parented twice, the consumer is told where the subject went both times,
  /// and the close is silent because there is nothing left to say.
  #[test]
  fn a_directory_renamed_twice_on_one_handle_reports_both_moves() {
    let mut adm = admission();
    let mut out = Vec::new();
    // b -> b2, the departing half then the arriving one.
    adm.admit(record(20, 10, reason::RENAME_OLD_NAME, 0x10, "b"), &mut out);
    adm.admit(
      record(20, 10, reason::RENAME_NEW_NAME, 0x10, "b2"),
      &mut out,
    );
    // b2 -> b3, which the retired class believed the journal never wrote. The
    // departing bit is fresh because writing the arriving half cleared it.
    adm.admit(
      record(20, 10, reason::RENAME_OLD_NAME, 0x10, "b2"),
      &mut out,
    );
    adm.admit(
      record(20, 10, reason::RENAME_NEW_NAME, 0x10, "b3"),
      &mut out,
    );
    let moves: Vec<&UsnAdmitted> = out
      .iter()
      .filter(|e| matches!(e, UsnAdmitted::Renamed { .. }))
      .collect();
    assert_eq!(moves.len(), 2, "both moves are reported as pairs: {out:?}");
    assert!(
      matches!(moves[1], UsnAdmitted::Renamed { old, new, .. }
        if matches!(old, UsnTarget::Resolved(c) if c == &["a".to_owned(), "b2".to_owned()])
          && matches!(new, UsnTarget::Resolved(c) if c == &["a".to_owned(), "b3".to_owned()])),
      "and the SECOND one names both of its ends: {out:?}"
    );
    // The close summary re-asserts RENAME_NEW_NAME, exactly as the measured
    // stream's 0x80002100 does.
    out.clear();
    adm.admit(
      record(20, 10, reason::RENAME_NEW_NAME | reason::CLOSE, 0x10, "b3"),
      &mut out,
    );
    assert!(
      out.is_empty(),
      "and it buys no reseed and no cover: everything it summarizes was already \
       delivered: {out:?}"
    );
    // The map followed both moves, which is what the reseed used to be paid to
    // repair: a record under the twice-renamed directory still resolves.
    adm.admit(
      record(50, 20, reason::FILE_CREATE, 0x20, "leaf.txt"),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
          if c == &["a".to_owned(), "b3".to_owned(), "leaf.txt".to_owned()])
      ),
      "the map is at the SECOND destination, with no walk having rebuilt it: \
       {out:?}"
    );
  }

  /// The same question about a FILE, which used to take one root cover instead
  /// of the reseed. It takes neither: two moves, two `Renamed` pairs, and a
  /// close that says nothing.
  #[test]
  fn a_file_renamed_twice_on_one_handle_reports_both_moves() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::RENAME_OLD_NAME, 0x20, "one.txt"),
      &mut out,
    );
    adm.admit(
      record(50, 20, reason::RENAME_NEW_NAME, 0x20, "two.txt"),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(50, 20, reason::RENAME_OLD_NAME, 0x20, "two.txt"),
      &mut out,
    );
    adm.admit(
      record(50, 20, reason::RENAME_NEW_NAME, 0x20, "three.txt"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Renamed { old, new, .. }]
        if matches!(old, UsnTarget::Resolved(c)
          if c == &["a".to_owned(), "b".to_owned(), "two.txt".to_owned()])
          && matches!(new, UsnTarget::Resolved(c)
            if c == &["a".to_owned(), "b".to_owned(), "three.txt".to_owned()])),
      "the second move is an ordinary pair: {out:?}"
    );
    out.clear();
    adm.admit(
      record(
        50,
        20,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "three.txt",
      ),
      &mut out,
    );
    assert!(out.is_empty(), "and the close buys no root cover: {out:?}");
  }

  /// The shape where the journal MERGES the arriving half into the summary that
  /// ends the session, which is the one the retirement improves most.
  ///
  /// The cover used to be the record's last word: a close carrying
  /// `RENAME_NEW_NAME` bought the reseed (or the root cover) and then, because
  /// the cover disowned its own name, refused to lower the arrival at all — so
  /// the consumer was sent back to the filesystem instead of being told where
  /// the subject went. Now BOTH ends are named.
  ///
  /// They are named as two singles rather than as one atomic pair, and that is
  /// the drain guard doing exactly its job: a record that RETIRES the carry's
  /// session widows the half first, because retirement is when the half's
  /// registrations are read out. Widowing costs the pairing, never the
  /// endpoints — each half degrades to its own membership verb carrying its own
  /// move evidence.
  #[test]
  fn a_close_merged_with_its_arriving_half_names_both_ends() {
    for (attrs, kind) in [(0x10u32, "directory"), (0x20, "file")] {
      let mut adm = admission();
      let mut out = Vec::new();
      adm.admit(
        record(20, 10, reason::RENAME_OLD_NAME, attrs, "b"),
        &mut out,
      );
      assert!(
        out.is_empty() && adm.holds_old(),
        "{kind}: the premise: the departing half is parked: {out:?}"
      );
      adm.admit(
        record(20, 10, reason::RENAME_NEW_NAME | reason::CLOSE, attrs, "b2"),
        &mut out,
      );
      assert!(
        out.iter().any(
          |e| matches!(e, UsnAdmitted::Single { delta, target: UsnTarget::Resolved(c), .. }
            if c == &["a".to_owned(), "b".to_owned()]
              && delta & reason::RENAME_OLD_NAME != 0)
        ),
        "{kind}: the departure is named: {out:?}"
      );
      assert!(
        out.iter().any(
          |e| matches!(e, UsnAdmitted::Single { delta, target: UsnTarget::Resolved(c), .. }
            if c == &["a".to_owned(), "b2".to_owned()]
              && delta & reason::RENAME_NEW_NAME != 0)
        ),
        "{kind}: and so is the destination the cover used to refuse to name: \
         {out:?}"
      );
      assert!(
        !out.iter().any(|e| matches!(
          e,
          UsnAdmitted::MapInconsistent
            | UsnAdmitted::Single {
              target: UsnTarget::EscalateAt(_),
              ..
            }
        )),
        "{kind}: and nothing is covered: {out:?}"
      );
    }
  }

  /// The other record that ends a parked half's session: a `CLOSE` for its
  /// subject that completes NOTHING.
  ///
  /// Its damage was worse for being quieter. The close's own delta was empty,
  /// so admission returned before the pairer was even reached and the half
  /// stayed parked BEYOND the record that retired its session — the close
  /// delivered nothing, and the departure surfaced only at whatever later
  /// record or boundary flush finally drained it. That departure is not a
  /// discharge of anything: `RENAME_OLD_NAME` standing at a close whose summary
  /// never carried the arriving half means the destination was never observed
  /// at all, and it may be in-root. Removing a subtree from the consumer's
  /// state on that evidence, with nothing behind it, is the divergence — so the
  /// half is drained while its entry is still there to book against, and it is
  /// the record that ended the session that delivers it.
  #[test]
  fn a_close_that_completes_nothing_still_drains_its_subjects_parked_half() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(20, 10, reason::RENAME_OLD_NAME, 0x10, "b"), &mut out);
    out.clear();
    adm.admit(
      record(20, 10, reason::RENAME_OLD_NAME | reason::CLOSE, 0x10, "b"),
      &mut out,
    );
    assert!(
      !adm.holds_old(),
      "an unbooked obligation may not outlive the record that retires its \
       subject"
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { delta, target: UsnTarget::Resolved(c), .. }
          if c == &["a".to_owned(), "b".to_owned()] && delta & reason::RENAME_OLD_NAME != 0)
      ),
      "the departure is delivered by the record that ended the session, not by \
       some later one: {out:?}"
    );
  }

  /// A cover is paid AT one record and OWED BY the record that could not prove
  /// its own name, and the two must not be the same delivery in the wrong
  /// order.
  ///
  /// The verdict that still reaches it is the [ledger's](OrphanLedger) anonymous
  /// residue: the bound took a debt's NAME, so some session this table stopped
  /// tracking still owes a repair and no close can prove whose it is. It is paid
  /// with the reseed spine, and a reseed says the MAP is untrustworthy — which
  /// is the map the paying record would resolve its own name through. So the
  /// cover is that record's last word: lowering it anyway hands the consumer a
  /// create at a path the source has just said it cannot resolve, and the
  /// consumer re-enumerates at the rescan only to be re-diverged by the record
  /// that bought it.
  #[test]
  fn a_paid_cover_is_the_last_word_of_the_record_that_paid_it() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    // One live session slot, and — the ledger takes the same bound — one named
    // orphan debt.
    let mut adm = UsnAdmission::new(map, 1);
    let mut out = Vec::new();
    // Three writing sessions in turn: each evicts its predecessor, which owes a
    // repair to the link it just delivered at. The second eviction has no name
    // left to record and falls into the residue.
    for (frn, name) in [(50u128, "one.txt"), (60, "two.txt"), (70, "three.txt")] {
      adm.admit(
        record(frn, 10, reason::DATA_OVERWRITE, 0x20, name),
        &mut out,
      );
    }
    assert_eq!(
      adm.sessions.orphans(),
      1,
      "the premise: the named set stopped growing at its bound"
    );
    out.clear();
    // An unrelated subject's close. The residue rides along on it, because the
    // residue names nobody and this close may be the debtor's.
    adm.admit(
      record(
        80,
        10,
        reason::FILE_CREATE | reason::CLOSE,
        0x20,
        "fresh.txt",
      ),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::MapInconsistent]),
      "the reseed is the whole of what this record may say — no create at a \
       name resolved through the map it just disowned: {out:?}"
    );
  }

  /// A parked rename half is a record ALREADY OBSERVED and NOT YET LOWERED, so
  /// the in-root obligations only its lowering can register do not exist while
  /// it sits there. An unrelated record observed in that window took its entry
  /// at its emptiest — no retained link — and the ledger honestly recorded no
  /// debt, because none had been registered yet. The half then widowed into
  /// `note_link` calls with no entry left to reach, and the close found neither
  /// a live session nor a marker: an in-root notice with nothing anywhere left
  /// to repair it.
  ///
  /// The half is therefore drained BEFORE anything else is observed, which is
  /// also the journal's own order: it is the earlier record. The carried half
  /// proves a WRITE besides its move, which is what makes it owe a registration
  /// at all — a repeated write is still silent, and its repair still has to
  /// reach the link the notice went to.
  #[test]
  fn a_parked_half_registers_before_an_unrelated_record_can_take_its_entry() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 1);
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "one.txt",
      ),
      &mut out,
    );
    assert!(
      out.is_empty() && adm.holds_old(),
      "the premise: the half is parked, so nothing about it is registered yet: \
       {out:?}"
    );
    adm.admit(
      record(60, 10, reason::DATA_OVERWRITE, 0x20, "other.txt"),
      &mut out,
    );
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, target: UsnTarget::Resolved(c), .. }
        if c == &["a".to_owned(), "one.txt".to_owned()]
          && delta & reason::RENAME_OLD_NAME != 0),
      "the widow is lowered first, in journal order: {out:?}"
    );
    assert_eq!(
      adm.sessions.orphans(),
      1,
      "and the eviction it triggered found a registration to owe for"
    );
    // A further write records nothing — its class is already in the mask — and
    // the close lands on an out-of-root hard link, whose own routing repairs
    // nothing.
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "elsewhere.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c.is_empty())
      ),
      "the close still covers the repair the cap can no longer name: {out:?}"
    );
  }

  /// The same window, entered by the other record shape that closes it: a NEW
  /// half for a DIFFERENT subject. It cannot pair either — halves pair on the
  /// subject's file reference — so it widows the carry too, and it evicts under
  /// exactly the same pressure.
  #[test]
  fn a_mismatched_new_half_cannot_take_the_carrys_entry_either() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 1);
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "one.txt",
      ),
      &mut out,
    );
    adm.admit(
      record(60, 10, reason::RENAME_NEW_NAME, 0x20, "arrived.txt"),
      &mut out,
    );
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, target: UsnTarget::Resolved(c), .. }
        if c == &["a".to_owned(), "one.txt".to_owned()]
          && delta & reason::RENAME_OLD_NAME != 0),
      "the mismatched half widows the carry ahead of itself: {out:?}"
    );
    assert_eq!(
      adm.sessions.orphans(),
      1,
      "and the eviction it triggered found a registration to owe for"
    );
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "elsewhere.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c.is_empty())
      ),
      "the close still covers the repair the cap can no longer name: {out:?}"
    );
  }

  /// The journal is VOLUME-WIDE: every rename anywhere on the volume reaches the
  /// session table, membership having been decided nowhere yet. A DIRECTORY
  /// renamed out there still costs the watched tree nothing, and the reason is a
  /// proof rather than a preference — NTFS forbids hard links to directories, so
  /// the link its records name is its only one and unreported endpoints are the
  /// whole truth about where it is. Without that proof a rename in an unwatched
  /// directory would answer with a rescan over the watched one, and a busy
  /// volume would keep this source permanently reseeding itself.
  #[test]
  fn a_directory_rename_outside_the_root_raises_no_cover_over_it() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 999, reason::RENAME_OLD_NAME, 0x10, "x"),
      &mut out,
    );
    adm.admit(
      record(
        50,
        999,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        0x10,
        "y",
      ),
      &mut out,
    );
    adm.admit(
      record(
        50,
        999,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME | reason::CLOSE,
        0x10,
        "y",
      ),
      &mut out,
    );
    assert!(
      out.is_empty(),
      "an unwatched DIRECTORY rename costs the watched tree nothing: {out:?}"
    );
  }

  /// THE WATCHED HARD LINK'S RENAME, end to end through admission — the shape
  /// the latent debt existed for, and the witness that the records which
  /// actually arrive already handle it.
  ///
  /// `/r/a/in.txt` and an out-of-root `out.txt` are two links of file 50. The
  /// OUTSIDE link is renamed first: both its endpoints are links this scope does
  /// not report, so nothing is admitted. The WATCHED link is renamed next. That
  /// second move was believed silent — the rename bits already stood for the
  /// reference — so the close on the outside link had to buy a root-scoped cover
  /// against a divergence nobody could name, and every FILE RENAME ON THE VOLUME
  /// bought one with it.
  ///
  /// It is not silent. The rename path clears the opposite half as it sets its
  /// own, so the watched link's departing half is fresh whatever the outside
  /// link did, and the move is reported at both of its in-root ends by its own
  /// two records. Nothing is covered, because nothing is unknown.
  #[test]
  fn a_watched_hard_links_rename_reports_itself_after_an_unwatched_ones() {
    let mut adm = admission();
    let mut out = Vec::new();
    // The consumer learns the watched link the ordinary way.
    adm.admit(
      record(50, 10, reason::FILE_CREATE, 0x20, "in.txt"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }]
        if c == &["a".to_owned(), "in.txt".to_owned()]),
      "the premise: the consumer holds a/in.txt: {out:?}"
    );
    out.clear();

    // The OUTSIDE link is renamed. Neither endpoint is reported.
    adm.admit(
      record(50, 999, reason::RENAME_OLD_NAME, 0x20, "out.txt"),
      &mut out,
    );
    adm.admit(
      record(50, 999, reason::RENAME_NEW_NAME, 0x20, "out2.txt"),
      &mut out,
    );
    assert!(
      out.is_empty(),
      "the premise: the outside rename is not this scope's business and \
       delivers nothing: {out:?}"
    );

    // `/r/a/in.txt` is renamed HERE, and the journal writes both of its halves.
    adm.admit(
      record(50, 10, reason::RENAME_OLD_NAME, 0x20, "in.txt"),
      &mut out,
    );
    adm.admit(
      record(50, 10, reason::RENAME_NEW_NAME, 0x20, "in2.txt"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Renamed { old, new, .. }]
        if matches!(old, UsnTarget::Resolved(c)
          if c == &["a".to_owned(), "in.txt".to_owned()])
          && matches!(new, UsnTarget::Resolved(c)
            if c == &["a".to_owned(), "in2.txt".to_owned()])),
      "the watched link's move names both of its ends: {out:?}"
    );

    // And the close on the outside link has nothing left to repair.
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "out2.txt",
      ),
      &mut out,
    );
    assert!(
      out.is_empty(),
      "so the close covers nothing, and a file rename anywhere on the volume no \
       longer rescans the watched root: {out:?}"
    );
  }

  /// The same volume-wide question asked of a rename that CROSSES the boundary:
  /// one endpoint outside the root, one inside, with the arriving half merged
  /// into the summary that ends the session.
  ///
  /// The close used to answer this with a root cover and then decline to name
  /// the arrival at all, because the cover disowned the record carrying it. Both
  /// halves are still drained on time — the departing one widows ahead of the
  /// close, exactly as the drain guard requires — and what the pair proves is
  /// now DELIVERED: the subject arrived at a name this scope reports, and the
  /// records say so.
  #[test]
  fn a_crossing_into_the_root_reports_its_arrival_at_the_close_that_carries_it() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 999, reason::RENAME_OLD_NAME, 0x20, "outside.txt"),
      &mut out,
    );
    assert!(
      out.is_empty() && adm.holds_old(),
      "the premise: the departing half is parked, and its endpoint is one this \
       scope does not report: {out:?}"
    );
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        0x20,
        "in.txt",
      ),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { delta, target: UsnTarget::Resolved(c), .. }]
        if c == &["a".to_owned(), "in.txt".to_owned()]
          && delta & reason::FILE_CREATE != 0),
      "the crossing's reported end is delivered rather than covered: {out:?}"
    );
  }

  /// The two refusal ledgers agree everywhere except on `OutsideRoot`, which is
  /// the whole reason there are two. At a site that has not resolved its parent
  /// it is the firehose's ordinary membership drop; at a site that HAS — and has
  /// since mutated the map — it is the map disagreeing with itself, and a
  /// refusal read as success there leaves a subtree unmapped and unmentioned.
  ///
  /// A ledger cell, not a witness: the containment check now runs before the
  /// discard that made `OutsideRoot` reachable, so this pins the fallback rather
  /// than the path that reaches it.
  #[test]
  fn the_two_refusal_ledgers_differ_only_where_the_parent_was_proven() {
    use super::{LearnOutcome, learn_refusal, learn_refusal_below_a_resolved_parent};
    assert!(learn_refusal(LearnOutcome::OutsideRoot).is_none());
    assert!(matches!(
      learn_refusal_below_a_resolved_parent(LearnOutcome::OutsideRoot),
      Some(UsnAdmitted::MapInconsistent)
    ));
    for outcome in [
      LearnOutcome::Learned,
      LearnOutcome::OverCapacity,
      LearnOutcome::Inconsistent,
    ] {
      assert_eq!(
        learn_refusal(outcome),
        learn_refusal_below_a_resolved_parent(outcome),
        "{outcome:?}"
      );
    }
  }

  /// Two links in ONE directory are two links. A repair keyed to the parent
  /// alone would call this already-paid and leave the first name stale.
  #[test]
  fn two_links_in_one_directory_are_two_targets() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::DATA_OVERWRITE, 0x20, "one.txt"),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(
        50,
        20,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "two.txt",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c == &["a".to_owned(), "b".to_owned(), "one.txt".to_owned()])
      ),
      "a shared parent is not a shared link: {out:?}"
    );
  }

  /// Past the retention ceiling the enumeration would be silently short, so
  /// the whole root is covered once instead — the bound degrades, it does not
  /// grow and it does not drop.
  #[test]
  fn a_session_past_the_link_ceiling_covers_the_whole_root() {
    let mut adm = admission();
    let mut out = Vec::new();
    // Each open touches a different link AND a different kind of change, so
    // every record carries a fresh bit and is really written.
    let mut mask = 0;
    for (n, bit) in [
      reason::DATA_OVERWRITE,
      reason::DATA_EXTEND,
      reason::DATA_TRUNCATION,
      reason::BASIC_INFO_CHANGE,
      reason::EA_CHANGE,
    ]
    .into_iter()
    .enumerate()
    {
      mask |= bit;
      adm.admit(record(50, 20, mask, 0x20, &format!("l{n}.txt")), &mut out);
    }
    out.clear();
    adm.admit(
      record(50, 999, mask | reason::CLOSE, 0x20, "out.txt"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }]
        if c.is_empty()),
      "a saturated set is paid with the root cover: {out:?}"
    );
  }

  /// A target whose directory has left the watched tree has no in-root
  /// location left to point at. Its departure was itself delivered; the cover
  /// is simply not emitted, rather than being aimed at a path outside the root.
  #[test]
  fn a_target_whose_directory_left_the_root_has_nothing_left_to_cover() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::DATA_OVERWRITE, 0x20, "in.txt"),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(20, 10, reason::FILE_DELETE | reason::CLOSE, 0x10, "b"),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(
        50,
        999,
        reason::DATA_OVERWRITE | reason::CLOSE,
        0x20,
        "out.txt",
      ),
      &mut out,
    );
    assert!(out.is_empty(), "{out:?}");
  }

  /// The session cap is the other way an object-keyed repair can lose its
  /// link. An evicted session's targets are covered in-band, so the bound
  /// degrades to noise rather than to the silence it exists to prevent.
  #[test]
  fn an_evicted_session_is_covered_rather_than_stranded() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 1);
    let mut out = Vec::new();
    adm.admit(
      record(50, 10, reason::DATA_OVERWRITE, 0x20, "first.txt"),
      &mut out,
    );
    out.clear();
    adm.admit(
      record(60, 10, reason::DATA_OVERWRITE, 0x20, "second.txt"),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c == &["a".to_owned(), "first.txt".to_owned()])
      ),
      "the cap must cover what it forgets: {out:?}"
    );
  }

  /// A cover repairs notices that PREDATE its record, so it is emitted ahead
  /// of that record's own events — which keeps it on the trusted side of a
  /// batch stop the very same record raises. Emitted afterwards it would be
  /// truncated away with the untrusted suffix, and the obligation the cap
  /// surrendered would vanish with it.
  #[test]
  fn a_cover_survives_a_stop_its_own_record_raises() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "A".into()), (20, 10, "P".into())]);
    let mut adm = UsnAdmission::new(map, 1);
    let mut out = Vec::new();
    let verdict = adm.admit_batch(
      vec![
        record(50, 20, reason::DATA_OVERWRITE, 0x20, "held.txt"),
        // Evicts the session above AND contradicts the map: "A was created
        // under P", replayed against a map where P already sits inside A.
        record(10, 20, reason::FILE_CREATE, 0x10, "A"),
      ],
      &mut out,
    );
    assert!(
      matches!(verdict, Some(UsnAdmitted::MapInconsistent)),
      "{verdict:?}"
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::EscalateAt(c), .. }
          if c == &["A".to_owned(), "P".to_owned(), "held.txt".to_owned()])
      ),
      "the surrendered target is covered ahead of the stop: {out:?}"
    );
    assert!(
      matches!(out.last(), Some(UsnAdmitted::MapInconsistent)),
      "and the verdict is still the batch's last word: {out:?}"
    );
  }

  /// `INDEXABLE_CHANGE` is a user-visible attribute change
  /// (`FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`), not filesystem bookkeeping: the
  /// RDCW arm reports it through `FILE_NOTIFY_CHANGE_ATTRIBUTES`, so filtering
  /// it here made the two Windows backends disagree about whether the mutation
  /// happened at all.
  #[test]
  fn an_indexable_change_admits_as_metadata() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(50, 20, reason::INDEXABLE_CHANGE, 0x20, "f"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { delta, target, .. }]
        if delta & reason::ATTRIB != 0
          && *target == UsnTarget::Resolved(vec!["a".into(), "b".into(), "f".into()])),
      "{out:?}"
    );
  }
}

#[cfg(test)]
mod r1_regressions {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  const ROOT: u128 = 1;

  fn admission() -> UsnAdmission {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    UsnAdmission::new(map, 64)
  }

  fn record(frn: u128, parent: u128, reason_mask: u32, attrs: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: attrs,
      name: UsnName::Utf8(name.into()),
    }
  }

  /// A cumulative CREATE|DATA_EXTEND after an emitted CREATE reports the
  /// Modified fact — never a second Created that eats it.
  #[test]
  fn cumulative_masks_forward_fresh_bits_only() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(50, 10, reason::FILE_CREATE, 0x20, "f"), &mut out);
    assert!(matches!(&out[0], UsnAdmitted::Single { delta, .. }
      if *delta == reason::FILE_CREATE));

    out.clear();
    adm.admit(
      record(50, 10, reason::FILE_CREATE | reason::DATA_EXTEND, 0x20, "f"),
      &mut out,
    );
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, .. }
      if *delta == reason::DATA_EXTEND),
      "only the fresh content bit forwards: {out:?}"
    );
  }

  /// A widowed half keeps its fresh content bits alongside the synthetic
  /// membership verb.
  #[test]
  fn widows_keep_their_content_bits() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "f",
      ),
      &mut out,
    );
    adm.flush(&mut out);
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, .. }
      if delta & reason::FILE_DELETE != 0 && delta & reason::DATA_OVERWRITE != 0),
      "{out:?}"
    );
  }

  /// A PAIRED rename keeps the same content bits its widowed form does, and
  /// keeps them on the half whose record carried them.
  ///
  /// Pairing is a property of where the read boundary fell, not of what the
  /// filesystem did, so a content change that survives when the partner is
  /// missing must survive when it arrives — otherwise the same write is
  /// reported or lost by the accident of batching.
  #[test]
  fn paired_renames_keep_their_content_bits() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "f",
      ),
      &mut out,
    );
    assert!(out.is_empty(), "the OLD half parks");
    adm.admit(
      record(
        50,
        ROOT,
        reason::RENAME_OLD_NAME
          | reason::DATA_OVERWRITE
          | reason::RENAME_NEW_NAME
          | reason::BASIC_INFO_CHANGE,
        0x20,
        "f2",
      ),
      &mut out,
    );
    // A metadata bit first seen on the ARRIVING record is that record's, and
    // the content already spent on the departing one is not re-reported: the
    // fresh-mask split is what keeps one change from becoming two.
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
      matches!(&out[0], UsnAdmitted::Renamed { old_content, new_content, .. }
        if *old_content == reason::DATA_OVERWRITE && *new_content == reason::BASIC_INFO_CHANGE),
      "{out:?}"
    );
  }

  /// A rename whose other end is outside the root degrades to the in-root
  /// end's membership verb, and that naming choice must not consume the
  /// content evidence the same record proved.
  #[test]
  fn boundary_renames_keep_their_content_bits() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "f",
      ),
      &mut out,
    );
    adm.admit(
      record(
        50,
        999,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE | reason::RENAME_NEW_NAME,
        0x20,
        "gone",
      ),
      &mut out,
    );
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, .. }
        if delta & reason::FILE_DELETE != 0 && delta & reason::DATA_OVERWRITE != 0),
      "{out:?}"
    );
  }

  /// A directory moved IN from outside demands its subtree walk and the
  /// covering located rescan at the target.
  #[test]
  fn a_moved_in_directory_demands_its_walk() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(70, 999, reason::RENAME_OLD_NAME, 0x10, "ext"),
      &mut out,
    );
    adm.admit(
      record(70, 10, reason::RENAME_NEW_NAME, 0x10, "in"),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
        if target == &["a".to_owned(), "in".to_owned()])
      ),
      "{out:?}"
    );
    // The moved-in top is mapped: its children admit immediately.
    out.clear();
    adm.admit(record(80, 70, reason::FILE_CREATE, 0x20, "child"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["a".to_owned(), "in".to_owned(), "child".to_owned()])
    );
  }
}

#[cfg(test)]
mod r2_regressions {
  use super::{
    UsnAdmission, UsnAdmitted,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  const ROOT: u128 = 1;

  fn record(frn: u128, parent: u128, reason_mask: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: 0x20,
      name: UsnName::Utf8(name.into()),
    }
  }

  /// A pre-loss bit whose CLOSE fell inside the gap must re-report after
  /// the reseed boundary resets the session history.
  #[test]
  fn reseed_resets_cumulative_history() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    adm.admit(record(50, 10, reason::DATA_EXTEND, "f"), &mut out);
    assert_eq!(out.len(), 1);

    // The gap: the CLOSE was skipped, the reseed boundary resets.
    adm.reset_sessions();
    out.clear();
    adm.admit(record(50, 10, reason::DATA_EXTEND, "f"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, .. }
        if *delta == reason::DATA_EXTEND),
      "the post-gap session re-reports: {out:?}"
    );
  }

  /// A move-in followed by an in-root rename in the SAME buffer: the map's
  /// resolution (the walk's anchor) tracks the rename, not the stale
  /// move-in target.
  #[test]
  fn same_buffer_move_in_then_rename_tracks_the_map() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    let dir = |frn, parent, mask, name: &str| UsnRecord {
      attributes: 0x10,
      ..record(frn, parent, mask, name)
    };
    adm.admit(dir(70, 999, reason::RENAME_OLD_NAME, "ext"), &mut out);
    adm.admit(dir(70, 10, reason::RENAME_NEW_NAME, "in"), &mut out);
    adm.admit(dir(70, 10, reason::RENAME_OLD_NAME, "in"), &mut out);
    adm.admit(dir(70, ROOT, reason::RENAME_NEW_NAME, "b"), &mut out);

    let stale = out.iter().find_map(|e| match e {
      UsnAdmitted::MovedInSubtree { frn, target } => Some((*frn, target.clone())),
      _ => None,
    });
    assert_eq!(
      stale,
      Some((70, vec!["a".to_owned(), "in".to_owned()])),
      "the EVENT keeps its historical target (the rescan's location)"
    );
    assert_eq!(
      adm.map_mut().resolve_dir(70),
      Some(vec!["b".to_owned()]),
      "the MAP (the walk's anchor) already tracks the rename"
    );
  }
}

#[cfg(test)]
mod r9_regressions {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  /// A directory the seed walk raced past (renamed between its parent's
  /// enumeration and its own): the in-root rename replay learns the absent
  /// FRN AND demands the subtree walk — never a mapped top over a blind
  /// subtree.
  #[test]
  fn an_unmapped_in_root_rename_demands_its_walk() {
    let mut map = FrnMap::new(1, None);
    map.seed([(10, 1, "a".into()), (20, 1, "b".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    let dir = |frn, parent, mask, name: &str| UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: mask,
      source_info: 0,
      attributes: 0x10,
      name: UsnName::Utf8(name.into()),
    };
    // FRN 70 was never seeded (the race), yet both rename ends are in-root.
    adm.admit(dir(70, 10, reason::RENAME_OLD_NAME, "raced"), &mut out);
    adm.admit(dir(70, 20, reason::RENAME_NEW_NAME, "landed"), &mut out);
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
        if target == &["b".to_owned(), "landed".to_owned()])
      ),
      "{out:?}"
    );
    // And its children admit through the learned chain.
    out.clear();
    adm.admit(dir(80, 70, reason::FILE_CREATE, "child"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["b".to_owned(), "landed".to_owned(), "child".to_owned()])
    );
  }
}

#[cfg(test)]
mod r10_regressions {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  /// A reparse boundary REMOVED mid-stream: the now-ordinary directory is
  /// learned and its walk demanded — never a permanently blind subtree.
  #[test]
  fn a_removed_reparse_boundary_demands_its_walk() {
    let mut map = FrnMap::new(1, None);
    map.seed([(10, 1, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    // FRN 70 was a junction under a: excluded from the map. The boundary
    // is removed (no reparse attribute anymore).
    adm.admit(
      UsnRecord {
        frn: 70,
        parent: 10,
        usn: 0,
        reason: reason::REPARSE_POINT_CHANGE | reason::CLOSE,
        source_info: 0,
        attributes: 0x10,
        name: UsnName::Utf8("was-junction".into()),
      },
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
        if target == &["a".to_owned(), "was-junction".to_owned()])
      ),
      "{out:?}"
    );
    out.clear();
    adm.admit(
      UsnRecord {
        frn: 80,
        parent: 70,
        usn: 0,
        reason: reason::FILE_CREATE,
        source_info: 0,
        attributes: 0x20,
        name: UsnName::Utf8("child".into()),
      },
      &mut out,
    );
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["a".to_owned(), "was-junction".to_owned(), "child".to_owned()])
    );
  }
}

#[cfg(test)]
mod r11_regressions {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  fn dir(frn: u128, parent: u128, mask: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: mask,
      source_info: 0,
      attributes: 0x10,
      name: UsnName::Utf8(name.into()),
    }
  }

  fn admission() -> UsnAdmission {
    let mut map = FrnMap::new(1, None);
    map.seed([(10, 1, "a".into())]);
    UsnAdmission::new(map, 64)
  }

  /// A reparse add-then-remove within ONE open session: the cumulative
  /// second bit must still run the boundary-removed learn-and-walk.
  #[test]
  fn a_reparse_toggle_in_one_session_still_walks() {
    let mut adm = admission();
    let mut out = Vec::new();
    // Boundary added (reparse attribute set): the mapped dir drops.
    adm.admit(
      UsnRecord {
        attributes: 0x410,
        ..dir(10, 1, reason::REPARSE_POINT_CHANGE, "a")
      },
      &mut out,
    );
    out.clear();
    // Same session (no CLOSE between): boundary removed again.
    adm.admit(
      dir(10, 1, reason::REPARSE_POINT_CHANGE | reason::CLOSE, "a"),
      &mut out,
    );
    assert!(
      out
        .iter()
        .any(|e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 10, .. })),
      "the cumulative bit must not suppress the removal's walk: {out:?}"
    );
  }

  /// A structural directory whose name has no spelling is map death.
  #[test]
  fn an_unnameable_directory_creation_is_map_death() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      UsnRecord {
        name: UsnName::Escalate,
        ..dir(70, 10, reason::FILE_CREATE, "")
      },
      &mut out,
    );
    assert!(
      out.iter().any(|e| matches!(e, UsnAdmitted::MapOverflow)),
      "{out:?}"
    );
  }

  /// A widowed directory NEW half is a move-in: the anchor learns AND the
  /// subtree walk is demanded (a cursor can start between rename halves).
  #[test]
  fn a_widowed_directory_new_half_demands_its_walk() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(dir(70, 10, reason::RENAME_NEW_NAME, "arrived"), &mut out);
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
        if target == &["a".to_owned(), "arrived".to_owned()])
      ),
      "{out:?}"
    );
    out.clear();
    adm.admit(dir(80, 70, reason::FILE_CREATE, "child"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["a".to_owned(), "arrived".to_owned(), "child".to_owned()])
    );
  }
}

#[cfg(test)]
mod r12_regressions {
  use super::{
    UsnAdmission, UsnAdmitted,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  /// An out-to-in directory move whose NEW name has no spelling is map
  /// death — never a bare parent rescan over a standing unmapped tree.
  #[test]
  fn an_unnameable_move_in_is_map_death() {
    let mut map = FrnMap::new(1, None);
    map.seed([(10, 1, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    let dir = |frn, parent, mask, name| UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: mask,
      source_info: 0,
      attributes: 0x10,
      name,
    };
    adm.admit(
      dir(
        70,
        999,
        reason::RENAME_OLD_NAME,
        UsnName::Utf8("ext".into()),
      ),
      &mut out,
    );
    adm.admit(
      dir(70, 10, reason::RENAME_NEW_NAME, UsnName::Escalate),
      &mut out,
    );
    assert!(
      out.iter().any(|e| matches!(e, UsnAdmitted::MapOverflow)),
      "{out:?}"
    );
  }
}

/// The reported tree's boundary as the USN arm enforces it: the exclusion
/// decision sits ahead of every place the admission map can grow, so excluded
/// churn consumes none of the capped budget the rest of the tree competes for.
#[cfg(test)]
mod exclusion_fence {
  use std::path::PathBuf;

  use super::{
    UsnAdmission, UsnAdmitted, UsnFence, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  const ROOT: u128 = 1;
  const DIR: u32 = 0x10;
  const FILE: u32 = 0x20;

  fn fence(exclusions: &[&str]) -> UsnFence {
    UsnFence::new(
      PathBuf::from("/r"),
      exclusions.iter().map(PathBuf::from).collect(),
    )
  }

  /// `/r` with `keep` mapped under it, a directory cap of `cap`, and the
  /// caller's exclusions in force. `cache` is deliberately NOT mapped: the seed
  /// walk declines an excluded directory, so the live stream meets it exactly as
  /// the walk left it — absent.
  fn admission(cap: Option<usize>, exclusions: &[&str]) -> UsnAdmission {
    let mut map = FrnMap::new(ROOT, cap);
    map.seed([(10, ROOT, "keep".into())]);
    UsnAdmission::new(map, 64).with_fence(fence(exclusions))
  }

  fn record(frn: u128, parent: u128, reason_mask: u32, attrs: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: attrs,
      name: UsnName::Utf8(name.into()),
    }
  }

  /// THE budget property, on the live stream. A build cache's churn under an
  /// excluded name is create/delete of one directory over and over, each
  /// incarnation a fresh file reference — so every create is map GROWTH.
  ///
  /// The common layer's fence drops compiled DELIVERIES, which arrive long after
  /// the map has already learned: with the map growing, the third create reaches
  /// the cap and answers `MapOverflow`, which does not merely drop the excluded
  /// event — it TERMINATES the source, taking every unrelated subscription on the
  /// root with it. The documented guarantee is that excluded churn cannot consume
  /// the admission-map budget, so the decision has to precede the growth.
  #[test]
  fn excluded_churn_consumes_no_admission_map_budget() {
    let mut adm = admission(Some(2), &["/r/cache"]);
    let mut out = Vec::new();
    for round in 0..200u128 {
      let frn = 1000 + round;
      adm.admit(
        record(frn, ROOT, reason::FILE_CREATE, DIR, "cache"),
        &mut out,
      );
      adm.admit(
        record(
          frn,
          ROOT,
          reason::FILE_CREATE | reason::DATA_EXTEND,
          DIR,
          "cache",
        ),
        &mut out,
      );
      adm.admit(
        record(
          frn,
          ROOT,
          reason::FILE_CREATE | reason::DATA_EXTEND | reason::FILE_DELETE,
          DIR,
          "cache",
        ),
        &mut out,
      );
    }
    assert!(
      !out.iter().any(UsnAdmitted::ends_the_batchs_trust),
      "six hundred excluded records never end the source: {out:?}"
    );
    assert!(
      out.is_empty(),
      "and nothing from inside the exclusion is delivered: {out:?}"
    );
    assert_eq!(
      adm.map_mut().directories(),
      1,
      "the map still holds only the reported directory"
    );

    // The rest of the tree still has its whole budget: one more reported
    // directory fits under the cap of two.
    adm.admit(record(30, ROOT, reason::FILE_CREATE, DIR, "also"), &mut out);
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }]
        if c == &["also".to_owned()]),
      "a reported create still admits: {out:?}"
    );
    assert_eq!(adm.map_mut().directories(), 2);
  }

  /// A file's churn inside an excluded subtree delivers nothing either — and the
  /// sibling that is NOT excluded still delivers, so the fence is a boundary and
  /// not a mute button.
  #[test]
  fn nothing_inside_an_exclusion_is_delivered_and_everything_outside_still_is() {
    let mut adm = admission(None, &["/r/cache"]);
    let mut out = Vec::new();
    adm.admit(
      record(50, ROOT, reason::DATA_OVERWRITE, FILE, "cache"),
      &mut out,
    );
    assert!(out.is_empty(), "{out:?}");
    adm.admit(
      record(51, 10, reason::DATA_OVERWRITE, FILE, "f.txt"),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }]
        if c == &["keep".to_owned(), "f.txt".to_owned()]),
      "the reported sibling is untouched: {out:?}"
    );
  }

  /// A directory moved IN onto an excluded path must not be learned and must not
  /// demand a walk: learning it would put a subtree the caller asked not to hear
  /// about into the capped map, and the walk would enumerate it into the map
  /// wholesale.
  #[test]
  fn a_move_in_onto_an_excluded_path_neither_learns_nor_walks() {
    let mut adm = admission(None, &["/r/cache"]);
    let mut out = Vec::new();
    adm.admit(
      record(70, 999, reason::RENAME_OLD_NAME, DIR, "elsewhere"),
      &mut out,
    );
    adm.admit(
      record(
        70,
        ROOT,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        DIR,
        "cache",
      ),
      &mut out,
    );
    assert!(
      out.is_empty(),
      "neither end is in the reported tree, so nothing is reported: {out:?}"
    );
    assert_eq!(adm.map_mut().directories(), 1, "and nothing was learned");
    // And the arrival really is unmapped: a create under it resolves nothing.
    adm.admit(record(80, 70, reason::FILE_CREATE, FILE, "child"), &mut out);
    assert!(out.is_empty(), "{out:?}");
  }

  /// A crossing INTO an exclusion is a departure from the reported tree: the
  /// moved subtree is forgotten, no walk is owed, and the half the caller CAN
  /// see is still reported — that crossing is precisely what tells it the object
  /// is gone.
  #[test]
  fn a_rename_into_an_exclusion_departs_and_owes_no_walk() {
    let mut adm = admission(None, &["/r/cache"]);
    adm.map_mut().seed([(20, 10, "deep".into())]);
    let mut out = Vec::new();
    adm.admit(
      record(10, ROOT, reason::RENAME_OLD_NAME, DIR, "keep"),
      &mut out,
    );
    adm.admit(
      record(
        10,
        ROOT,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        DIR,
        "cache",
      ),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { target: UsnTarget::Resolved(c), delta, .. }]
        if c == &["keep".to_owned()] && delta & reason::FILE_DELETE != 0),
      "the departure is reported at the name the caller was watching: {out:?}"
    );
    assert!(
      !out
        .iter()
        .any(|e| matches!(e, UsnAdmitted::MovedInSubtree { .. })),
      "an excluded destination is owed no walk: {out:?}"
    );
    assert_eq!(
      adm.map_mut().directories(),
      0,
      "the departed subtree left the map with its descendant"
    );
  }

  /// The other direction. A subtree moved OUT of an exclusion was never walked,
  /// so re-parenting it would leave it blind: it is learned as an arrival and its
  /// walk is demanded, exactly like a move in from outside the root.
  #[test]
  fn a_rename_out_of_an_exclusion_arrives_and_demands_its_walk() {
    let mut adm = admission(None, &["/r/cache"]);
    let mut out = Vec::new();
    adm.admit(
      record(70, ROOT, reason::RENAME_OLD_NAME, DIR, "cache"),
      &mut out,
    );
    adm.admit(
      record(
        70,
        ROOT,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        DIR,
        "shown",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
          if target == &["shown".to_owned()])
      ),
      "the newly reportable subtree is walked in: {out:?}"
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::Single { target: UsnTarget::Resolved(c), delta, .. }
          if c == &["shown".to_owned()] && delta & reason::FILE_CREATE != 0)
      ),
      "and the arrival is reported: {out:?}"
    );
  }

  /// Both ends excluded reports nothing and mutates nothing — the only rename
  /// shape the fence suppresses outright.
  #[test]
  fn a_rename_wholly_inside_the_exclusions_reports_nothing() {
    let mut adm = admission(None, &["/r/cache", "/r/tmp"]);
    let mut out = Vec::new();
    adm.admit(
      record(70, ROOT, reason::RENAME_OLD_NAME, DIR, "cache"),
      &mut out,
    );
    adm.admit(
      record(
        70,
        ROOT,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        DIR,
        "tmp",
      ),
      &mut out,
    );
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(adm.map_mut().directories(), 1);
  }

  /// The carve-out: a caller who excluded the very tree it asked to watch must
  /// still be told the watch is over. The root anchor's records are routed by the
  /// anchor rather than by a link, and the fence never reaches them.
  #[test]
  fn the_roots_own_death_is_never_suppressed() {
    let mut adm = admission(None, &["/r"]);
    let mut out = Vec::new();
    adm.admit(record(ROOT, 999, reason::FILE_DELETE, DIR, "r"), &mut out);
    assert!(
      matches!(&out[..], [UsnAdmitted::RootDeath]),
      "the one signal that says the watch ended: {out:?}"
    );
  }

  /// A rename with an exclusion BENEATH one endpoint. Exclusions match on path
  /// prefixes, so a re-parent — which rewrites the subtree's path and carries
  /// every mapped descendant across untouched — can land the map's contents on
  /// the wrong side of the fence and leave them there permanently.
  ///
  /// Here `/r/a/cache` is reportable and mapped; renaming `a` to `b` puts it at
  /// `/r/b/cache`, which the caller excluded. A bare re-parent kept that
  /// directory (and everything the walk mapped below it) in the capped map
  /// forever, holding exactly the budget the exclusion exists to shed.
  #[test]
  fn a_rename_that_moves_the_exclusion_geometry_relearns_and_rewalks() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into()), (20, 10, "cache".into())]);
    let mut adm = UsnAdmission::new(map, 64).with_fence(fence(&["/r/b/cache"]));
    let mut out = Vec::new();
    adm.admit(
      record(10, ROOT, reason::RENAME_OLD_NAME, DIR, "a"),
      &mut out,
    );
    adm.admit(
      record(
        10,
        ROOT,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        DIR,
        "b",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(|e| matches!(e, UsnAdmitted::Renamed { .. })),
      "the move itself is still reported: {out:?}"
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 10, target }
          if target == &["b".to_owned()])
      ),
      "what the map holds for this subtree is no longer what the fence \
       reports, so it is re-walked: {out:?}"
    );
    assert_eq!(
      adm.map_mut().resolve_dir(20),
      None,
      "the descendant that crossed into the exclusion is gone from the map"
    );
    assert_eq!(
      adm.map_mut().resolve_dir(10),
      Some(vec!["b".to_owned()]),
      "and the top is relearned at its new location"
    );
  }

  /// The exclusion-geometry re-walk DISCARDS a subtree, and the discard erases
  /// the very evidence a containment refusal reads to prove itself.
  ///
  /// `/r/a/b` is mapped, an exclusion sits beneath `a`, and a stale rename —
  /// history replayed below the live edge — proposes `a` BENEATH `b`. The
  /// geometry check fires, `forget(a)` takes `b` down with it, and the re-`learn`
  /// then finds no parent at all: `OutsideRoot`, which the refusal ledger reads
  /// as the firehose's ordinary membership drop. What came out was a
  /// `MovedInSubtree` at a path nothing could resolve, a `Renamed` to match, and
  /// a map holding neither directory — the subtree unmapped, permanently, with
  /// no `MapInconsistent`, no loss and no reseed anywhere in the stream.
  ///
  /// The containment question is now asked of the map as it still STANDS, before
  /// anything is discarded.
  #[test]
  fn an_exclusion_geometry_move_onto_its_own_descendant_reseeds_rather_than_vanishing() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into()), (20, 10, "b".into())]);
    let mut adm = UsnAdmission::new(map, 64).with_fence(fence(&["/r/a/cache"]));
    let mut out = Vec::new();
    let verdict = adm.admit_batch(
      vec![
        record(10, ROOT, reason::RENAME_OLD_NAME, DIR, "a"),
        record(
          10,
          20,
          reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
          DIR,
          "a",
        ),
      ],
      &mut out,
    );
    assert!(
      matches!(verdict, Some(UsnAdmitted::MapInconsistent)),
      "the contradiction reaches the reseed spine: {verdict:?}"
    );
    assert!(
      !out.iter().any(|e| matches!(
        e,
        UsnAdmitted::MovedInSubtree { .. } | UsnAdmitted::Renamed { .. }
      )),
      "and nothing resolved against the disowned topology is delivered: {out:?}"
    );
    assert_eq!(
      adm.map_mut().resolve_dir(10),
      Some(vec!["a".to_owned()]),
      "the standing map is left for the reseed to replace, not erased"
    );
    assert_eq!(
      adm.map_mut().resolve_dir(20),
      Some(vec!["a".to_owned(), "b".to_owned()])
    );
  }

  /// The same rewrite the other way: `/r/a/cache` is EXCLUDED, so the seed walk
  /// never mapped it; renaming `a` to `b` makes it reportable, and a bare
  /// re-parent would leave it absent from the map — every record beneath it
  /// resolving nothing, a visible subtree blind forever.
  #[test]
  fn a_rename_that_reveals_an_excluded_subtree_demands_its_walk() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64).with_fence(fence(&["/r/a/cache"]));
    let mut out = Vec::new();
    adm.admit(
      record(10, ROOT, reason::RENAME_OLD_NAME, DIR, "a"),
      &mut out,
    );
    adm.admit(
      record(
        10,
        ROOT,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        DIR,
        "b",
      ),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 10, target }
          if target == &["b".to_owned()])
      ),
      "the newly visible subtree is walked in rather than left blind: {out:?}"
    );
  }

  /// An ordinary rename with no exclusion under either endpoint still takes the
  /// cheap in-place re-parent — the geometry guard must not turn every move into
  /// a subtree walk.
  #[test]
  fn an_ordinary_rename_still_reparents_in_place() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into()), (20, 10, "child".into())]);
    let mut adm = UsnAdmission::new(map, 64).with_fence(fence(&["/r/cache"]));
    let mut out = Vec::new();
    adm.admit(
      record(10, ROOT, reason::RENAME_OLD_NAME, DIR, "a"),
      &mut out,
    );
    adm.admit(
      record(
        10,
        ROOT,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        DIR,
        "b",
      ),
      &mut out,
    );
    assert!(
      !out
        .iter()
        .any(|e| matches!(e, UsnAdmitted::MovedInSubtree { .. })),
      "no walk is owed: {out:?}"
    );
    assert_eq!(
      adm.map_mut().resolve_dir(20),
      Some(vec!["b".to_owned(), "child".to_owned()]),
      "the mapped descendant followed its parent for free"
    );
  }

  /// The COLD half's decision, at the one place it is decidable off a real
  /// volume: the seed and reseed walks learn a directory child only when
  /// [`UsnFence::excludes_path`] declines to fence its joined path, so a
  /// preexisting excluded subtree can never exhaust the directory cap.
  ///
  /// This drives the predicate the walk calls over the shape a listing produces;
  /// the handle-bound enumeration around it needs a live NTFS volume and is
  /// exercised only by the Windows integration suite.
  #[test]
  fn the_seed_walks_decision_declines_an_excluded_subtree_before_the_cap() {
    let fence = fence(&["/r/cache"]);
    let mut map = FrnMap::new(ROOT, Some(2));
    let mut declined = 0usize;
    // One reported directory, then two hundred inside the exclusion, then the
    // second reported one: a cap of two survives only if the excluded ones cost
    // nothing.
    let mut listing: Vec<(u128, u128, String, PathBuf)> =
      vec![(10, ROOT, "keep".into(), PathBuf::from("/r/keep"))];
    for n in 0..200u128 {
      listing.push((
        1000 + n,
        ROOT,
        format!("cache{n}"),
        PathBuf::from("/r/cache").join(format!("d{n}")),
      ));
    }
    listing.push((11, ROOT, "also".into(), PathBuf::from("/r/also")));
    for (frn, parent, name, path) in listing {
      if fence.excludes_path(&path) {
        declined += 1;
        continue;
      }
      assert_eq!(
        map.learn(frn, parent, name),
        super::map::LearnOutcome::Learned,
        "the reported tree fits its cap"
      );
    }
    assert_eq!(declined, 200);
    assert_eq!(map.directories(), 2);
  }

  /// A crossing OUT of an exclusion whose arrival is merged into the summary
  /// that ends the session: a departing endpoint the fence EXCLUDES, an arriving
  /// one it reports.
  ///
  /// An excluded endpoint is not an out-of-root one — its parent resolves — so
  /// the two are distinguishable, and the suppression rule keeps them apart
  /// three ways (reported / excluded / outside). The close used to answer this
  /// shape with a root cover that was then its LAST word, so the arrival it
  /// carried was never named. It is named now: the departing half is fenced off
  /// and reports nothing, and the arriving one is delivered by the record that
  /// carries it.
  #[test]
  fn an_excluded_to_reported_crossing_reports_the_arrival_its_close_carries() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64).with_fence(fence(&["/r/a/cache"]));
    let mut out = Vec::new();
    adm.admit(
      record(50, 10, reason::RENAME_OLD_NAME, FILE, "cache"),
      &mut out,
    );
    assert!(
      out.is_empty() && adm.holds_old(),
      "the premise: the departing endpoint resolves and is FENCED OFF, so its \
       half is parked and reports nothing: {out:?}"
    );
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        FILE,
        "kept.txt",
      ),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { delta, target: UsnTarget::Resolved(c), .. }]
        if c == &["a".to_owned(), "kept.txt".to_owned()]
          && delta & reason::FILE_CREATE != 0),
      "the reported end is delivered rather than covered: {out:?}"
    );
  }

  /// And the crossing still DELIVERS when its halves arrive apart, with the
  /// close that follows adding nothing. The suppression rule drops a rename only
  /// when NO endpoint is reported, and one reported end is one delivery — the
  /// close has nothing left to say about a move its own records already named.
  #[test]
  fn an_excluded_to_reported_crossing_still_reports_its_arriving_half() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64).with_fence(fence(&["/r/a/cache"]));
    let mut out = Vec::new();
    adm.admit(
      record(50, 10, reason::RENAME_OLD_NAME, FILE, "cache"),
      &mut out,
    );
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::RENAME_NEW_NAME,
        FILE,
        "kept.txt",
      ),
      &mut out,
    );
    assert!(
      matches!(&out[..], [UsnAdmitted::Single { delta, target: UsnTarget::Resolved(c), .. }]
        if c == &["a".to_owned(), "kept.txt".to_owned()]
          && delta & reason::FILE_CREATE != 0
          && delta & reason::RENAME_NEW_NAME != 0),
      "the endpoint inside the reported tree is reported, as an arrival: {out:?}"
    );
    out.clear();
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_NEW_NAME | reason::CLOSE,
        FILE,
        "kept.txt",
      ),
      &mut out,
    );
    assert!(
      out.is_empty(),
      "and the close covers nothing: the move it summarizes was reported by the \
       records that wrote it: {out:?}"
    );
  }
}
