//! The decidable form of the premise the repeat-rename retirement rests on:
//! *every move a session makes is reported by two records of its own, each
//! record's rename half is FRESH at the instant the journal writes it, and the
//! source joins the two into ONE ordered move.*
//!
//! # Why this is not a test helper
//!
//! A deletion is only as sound as the evidence that licensed it, and that
//! evidence has to be enforced where the deletion is relied upon. The retirement
//! recorded on [`SessionTable::observe`](super::SessionTable::observe) rests on
//! a measurement taken in CI, and a measurement that cannot FAIL certifies
//! nothing. So the question "do these records satisfy the premise?" lives here,
//! as a pure function over a record stream, and the real-journal cell in
//! `tributary-fs/tests/windows_rdcw.rs` asserts on its verdict rather than on a
//! hand-rolled bit count of its own.
//!
//! # It decides through the production machines, never beside them
//!
//! The premise is a statement about what the SOURCE would do with the records,
//! not about the words the journal wrote. Two separate decisions stand between
//! a record and a reported move, and BOTH are made here by the production type
//! that makes them in the source:
//!
//! - FRESHNESS is [`SessionTable`](super::SessionTable)'s. Production forwards
//!   a record's fresh bits — `reason & !seen`, with `seen` advanced only by a
//!   record that carried something new — and DISCARDS any rename half that is
//!   not fresh. A predicate that counted raw `USN_REASON_RENAME_*` bits would
//!   pass a stream whose second move production drops on the floor, which is
//!   exactly the shape the premise has to exclude.
//! - PAIRING is [`UsnPairer`](super::UsnPairer)'s, and it is a different
//!   question with a different answer. The pairer recognises a DEPARTING half
//!   only when the arriving one is absent from the same delta; a mask carrying
//!   both is read as an ARRIVAL. It carries at most one departing half, and
//!   only across ADJACENT records — anything else widows it. And the admission
//!   drains that carry before it accounts a record that takes the session's
//!   entry, so this subject's own `CLOSE` widows a parked half rather than
//!   completing it.
//!
//! Re-deriving the second one is how the gate came to accept precisely what it
//! exists to reject. A predicate that asked only "is the expected bit present
//! and fresh?" returned `Holds` for
//!
//! ```text
//! [OLD|NEW|CLOSE @ a, NEW @ a2, OLD @ b, NEW|CLOSE @ b2]
//! ```
//!
//! while production emits four WIDOWS and not one ordered pair: the first
//! record's coalesced mask is read as an arrival with nothing parked, and the
//! last record's `CLOSE` drains the half it looks like it completes. That is
//! the accumulating-mask world the measurement was taken to rule out, waved
//! through by the gate that fences it.
//!
//! So this module owns no delta arithmetic and no pairing arithmetic. It feeds
//! the records to a real `SessionTable` and a real `UsnPairer` in journal order,
//! in the order [`UsnAdmission::admit`](super::UsnAdmission::admit) itself
//! sequences them — the drain that runs BEFORE the accounting, the vocabulary's
//! own [`FILTERED`](super::reason::FILTERED) mask, the record a zero delta never
//! hands the pairer, and the disowning verdict that widows a carry — and reads
//! the [`UsnEvent`](super::UsnEvent)s that fall out. None of the three can
//! drift, because there is only one of each.
//!
//! # And it decides over the stream the source actually reads: the WHOLE volume's
//!
//! Reusing the source's machines is worth nothing if they are fed an input the
//! source never receives. The journal is VOLUME-WIDE — `admit` is handed every
//! subject's records, interleaved, in one order — and one of the pairing rules
//! above is a rule ABOUT that interleaving: a parked departing half is drained
//! before any record that takes its session entry, and every record of a
//! DIFFERENT file reference is such a record. Hand this predicate one subject's
//! records only and that rule can never fire, so
//!
//! ```text
//! [OLD @ a, one record of ANOTHER subject, NEW @ a2]
//! ```
//!
//! reaches the pairer as an adjacent pair and returns `Holds`, while production
//! drains on the foreign record and emits `WidowOld` then `WidowNew`. A gate fed
//! a filtered stream removes exactly the records whose presence makes the source
//! widow — which is the outcome the gate exists to certify does not happen — and
//! no amount of reusing the source's types repairs that, because they are being
//! asked the wrong question rather than answering the right one wrongly.
//!
//! So every record carries its own [file reference](PremiseRecord::frn) and the
//! whole ordered stream is replayed. WHICH records the expected sequence is
//! about is a separate question, answered by the `subject` argument: a foreign
//! record is never matched against a move, never names a half, and never walls
//! the sequence with a close of its own — and it still decides plenty, all of it
//! THROUGH the source, by taking the entry a carry is registered against, by
//! breaking an adjacency, by filling the table.
//!
//! # What it deliberately does NOT reuse, and why that cannot hide a defect
//!
//! Two things. The LOWERING, because it resolves through an `FrnMap` and a
//! watched root, and this is a pure function over a record stream with neither;
//! `admit`'s ordering rule around it is carried anyway rather than dropped, at
//! the site that would have dropped it. And the tail classification that tells
//! [`Silent`](PremiseVerdict::Silent) from
//! [`NotFresh`](PremiseVerdict::NotFresh), which reads raw bits on purpose —
//! it runs only once a refusal is already certain and only chooses WHICH
//! refusal to name, so no arithmetic in it can turn a refusal into a `Holds`.
//!
//! Everything else `admit` does either is replayed here or provably cannot
//! reach a freshness or pairing decision. `cover_stranded` reads the outcome and
//! writes covers; it touches neither the table nor the pairer. `admit_batch`'s
//! trust stop needs a MAP verdict, which needs the lowering, so no stop exists
//! to be replayed. The lowering's own flush is the pairer's flush, which is
//! here. And the table is deliberately given a cap the stream cannot reach, so
//! the eviction path — the only route to the orphan ledger, hence the only route
//! to a disowning verdict on a measured volume — stays shut.
//!
//! ONE RESIDUAL, NAMED RATHER THAN PAPERED OVER. The source reads the journal in
//! buffers, and the carry survives a buffer boundary exactly as it survives a
//! record — EXCEPT when a decode came back lossy, where the source widows the
//! carry before raising the loss. This replay is boundary-free, so it matches
//! the source on every non-lossy read and is MORE PERMISSIVE across a lossy one.
//! It cannot be closed from here: a probe's read boundaries are the probe's, not
//! the source's, and a probe that adopted the source's decoder to learn
//! lossiness would be reporting that decoder's beliefs back to itself. What
//! bounds it is that a lossy read is a read that DROPPED records — so the
//! subject's own halves are liable to be missing from the stream the gate then
//! judges, and a missing half is a refusal by every other arm here.
//!
//! # Where it is deliberately STRICTER than production
//!
//! A gate may refuse a stream production would tolerate; it may never accept
//! one production would mishandle. Two refusals are stricter than the source's
//! own behaviour on purpose, and each is named at its verdict:
//! [`Coalesced`](PremiseVerdict::Coalesced) and
//! [`ClosedEarly`](PremiseVerdict::ClosedEarly).
//!
//! And one input is narrowed rather than defaulted: the table is told
//! [`RenameSemantics::Measured`](super::RenameSemantics::Measured) explicitly,
//! because the retirement this gate licenses is scoped to that volume and a
//! constructor default is not a decision anyone made here.

use super::{
  RenameSemantics, SessionTable, UsnEvent, UsnPairer,
  decode::{UsnName, UsnRecord},
  reason,
};

/// One journal record, reduced to the three fields the premise turns on.
///
/// `reason` is the CUMULATIVE word the journal wrote, verbatim — never a delta.
/// Turning it into one is this module's whole job, and doing it at the call site
/// is the drift this type exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PremiseRecord<'a> {
  /// The record's subject, as the journal keyed it (`FileReferenceNumber`).
  ///
  /// The reason the stream may be — and must be — the whole volume's rather
  /// than one subject's. Both the session accounting and the pairing drain are
  /// decided against this field, so a caller that dropped it would be handing
  /// the source a stream it never reads; see the module header.
  pub frn: u128,
  /// The record's cumulative `USN_REASON_*` word.
  pub reason: u32,
  /// The link the record was written under (`Open.Link.Name`).
  pub name: &'a str,
}

/// One move the premise requires the journal to have recorded, under its own
/// two names, in this position of the sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedMove<'a> {
  /// The link name the move departs — the `RENAME_OLD_NAME` half's name.
  pub from: &'a str,
  /// The link name the move arrives at — the `RENAME_NEW_NAME` half's name.
  pub to: &'a str,
}

/// Which half of a move a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameHalf {
  /// `RENAME_OLD_NAME` — the name the move retires.
  Departing,
  /// `RENAME_NEW_NAME` — the name the move installs.
  Arriving,
}

impl RenameHalf {
  /// The reason bit this half is carried by.
  const fn bit(self) -> u32 {
    match self {
      Self::Departing => reason::RENAME_OLD_NAME,
      Self::Arriving => reason::RENAME_NEW_NAME,
    }
  }

  /// A stable tag for a failure message.
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Departing => "RENAME_OLD_NAME",
      Self::Arriving => "RENAME_NEW_NAME",
    }
  }
}

/// What one subject's record stream says about the premise.
///
/// Exactly one variant is an answer the retirement may be built on, and it is
/// the one that names no defect. Every other variant is a refusal, and each
/// names a DIFFERENT way the premise can be false — which matters, because the
/// ones a real volume could produce are not equally surprising and a CI log
/// that says only "failed" would not distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PremiseVerdict {
  /// Every expected move was reported by its own ordered, correctly named,
  /// FRESH pair of halves — a pair the source's own pairer joined — and a
  /// `USN_REASON_CLOSE` record followed the last of them.
  Holds,
  /// A move wrote NO record carrying its half at all — not even a repeated bit
  /// in a later cumulative word. The move is invisible to the journal, so the
  /// retirement's premise is false and the location debt it retired is owed.
  Silent {
    /// Which expected move went unreported.
    move_index: usize,
    /// The half that never arrived.
    half: RenameHalf,
  },
  /// A record CARRIED the half's bit, but only as a repeat of one already
  /// standing in the session's mask — so production's delta drops it and the
  /// move reaches no consumer. This is the accumulating-mask world the
  /// measurement was taken to rule out.
  NotFresh {
    /// Which expected move production would discard.
    move_index: usize,
    /// The half whose bit was stale.
    half: RenameHalf,
    /// The index of the last record that carried the bit and was discarded.
    at: usize,
  },
  /// One record's FRESH delta carried BOTH halves of a move at once.
  ///
  /// The OTHER accumulating-mask world, and the one a freshness test alone
  /// cannot see: the expected bit really is fresh, so a predicate that asked
  /// only "is it there?" would accept it. Production does not read it as the
  /// expected half — the source's pairer recognises a departure only when the
  /// arrival is absent from the same delta, so a coalesced mask becomes an
  /// ARRIVAL and whatever move it was meant to report is lost as a widow.
  ///
  /// REFUSED AHEAD OF THE PAIRER RATHER THAN THROUGH IT, and that is the one
  /// place this predicate is deliberately stronger than the source. Production
  /// pairs a coalesced arrival with a parked departure whenever one is still
  /// held, so the shape is not universally rejected downstream; here the fresh
  /// rename mask must equal EXACTLY the half the sequence is owed, which no
  /// coalesced word can. A stream that reaches this arm is one the measurement
  /// says NTFS does not write, and if a volume writes it anyway the retirement
  /// has no evidence over it.
  Coalesced {
    /// Which expected move the coalesced record fell in.
    move_index: usize,
    /// The index of the record whose delta carried both halves.
    at: usize,
  },
  /// A fresh half arrived where one was expected, but under a name that is not
  /// the move's. The records exist and say nothing about the link in question.
  Unattributed {
    /// Which expected move the stream failed to name.
    move_index: usize,
    /// The half whose name was wrong.
    half: RenameHalf,
    /// The index of the record that carried the misnamed half.
    at: usize,
  },
  /// A fresh ARRIVING half reached the pairer with no departure held — an
  /// arrival before its own departure. The pairing this arm performs is
  /// order-bound, so a stream in this shape is not one the retirement's
  /// reasoning covers.
  OutOfOrder {
    /// Which expected move arrived inverted.
    move_index: usize,
    /// The index of the record the source widowed as an unowned arrival.
    at: usize,
  },
  /// A fresh DEPARTING half was widowed rather than joined to its arrival.
  ///
  /// Both halves may well be in the stream; the source still reported no
  /// ordered move, because the pairer carries a departure only across adjacent
  /// records and the admission drains it ahead of any record that takes the
  /// subject's session entry. Anything with a delta of its own between the two
  /// halves, any arrival merged into this subject's own `CLOSE`, and ANY RECORD
  /// OF ANOTHER SUBJECT between the halves, lands here.
  ///
  /// The last of those is only reachable because the stream is the volume's:
  /// a foreign record can never complete this half and can evict the entry its
  /// registrations are owed against, so the admission drains on it. A predicate
  /// fed one subject's records would report `Holds` over precisely that shape.
  ///
  /// Production tolerates this — a widowed half carries the same mask at the
  /// same location, so only the joint announcement is lost — but the retirement
  /// was licensed by a stream of ORDERED PAIRS, and a gate that accepted
  /// widows would be certifying more than was measured.
  Unpaired {
    /// Which expected move the source failed to join.
    move_index: usize,
    /// The index of the record whose departing half was widowed.
    at: usize,
  },
  /// A `USN_REASON_CLOSE` ended the session while expected moves were still
  /// outstanding, and the stream then went on recording them.
  ///
  /// The premise is about a SESSION — one held handle, moving more than once —
  /// because that is the only shape in which a second move can meet its own
  /// rename bits already standing. A close resets the accumulated word, so
  /// halves recorded after it are fresh on EVERY filesystem, accumulating ones
  /// included: the stream would satisfy a freshness test while proving nothing
  /// whatever about the question. Reading past the close is how a predicate
  /// certifies the retirement off evidence that does not bear on it, so the
  /// close is a wall rather than a reset.
  ///
  /// A close with nothing further in the stream is NOT this: it is a session
  /// that ended with a move unrecorded, and [`Silent`](Self::Silent) or
  /// [`NotFresh`](Self::NotFresh) says which — the more specific answer, so
  /// the wall refuses only once something tries to cross it.
  ClosedEarly {
    /// Which expected move was still outstanding when the session ended.
    move_index: usize,
    /// The index of the `CLOSE` record that ended it.
    at: usize,
  },
  /// The moves were all recorded, but no `USN_REASON_CLOSE` followed the last
  /// of them — so the session the premise is about was never observed to end,
  /// and the stream may simply be incomplete.
  Unclosed,
}

impl PremiseVerdict {
  /// Whether the premise holds and the retirement may rest on this stream.
  #[must_use]
  pub const fn holds(self) -> bool {
    matches!(self, Self::Holds)
  }
}

/// The position in `records` a replayed record came from.
///
/// The replay stamps each record's own index into the `usn` field precisely so
/// that an event the source hands back — a widow the pairer has been carrying
/// for records — can still name the record it came from. The conversion cannot
/// fail: a slice index round-trips through `i64` on every target this crate
/// builds for.
fn source_index(record: &UsnRecord) -> usize {
  usize::try_from(record.usn).unwrap_or_default()
}

/// How far the expected sequence has got, and what the source has told it.
struct Sequence<'a> {
  /// The file reference the expected moves are ABOUT. Every other subject in
  /// the stream is replayed through the source and matched against nothing.
  subject: u128,
  /// The moves the stream must report, in this order.
  moves: &'a [ExpectedMove<'a>],
  /// How many of them the source has already reported as ordered pairs.
  wanted: usize,
  /// Where the search for an unrecorded half begins — just past the last half
  /// this scan accepted, so a bit belonging to an EARLIER move is never read as
  /// evidence about a later one.
  resumed_at: usize,
  /// The record whose departing half the pairer is carrying ON THE SUBJECT'S
  /// BEHALF.
  ///
  /// The pairer's carry slot is volume-wide — one slot for whichever subject
  /// parked last — so "a departure is held" and "THIS subject's departure is
  /// held" stopped being the same question the moment the stream became the
  /// volume's. This is the second one, kept in step with the first by the same
  /// events: set where the subject parks, cleared where the source joins it,
  /// and never left standing over a widow because a widowed subject half is a
  /// refusal that returns.
  departure_at: Option<usize>,
  /// Whether any fresh rename half has entered the pairing yet. Until one has,
  /// a `CLOSE` belongs to an earlier session — the write that created the file,
  /// the call that linked it — and resets the accumulator exactly as the source
  /// would have it.
  started: bool,
  /// The first `CLOSE` of the SUBJECT that ended its session with moves still
  /// outstanding.
  closed_early: Option<usize>,
}

impl<'a> Sequence<'a> {
  /// A sequence about `subject`, owed every move in `moves` and told nothing
  /// yet.
  const fn new(subject: u128, moves: &'a [ExpectedMove<'a>]) -> Self {
    Self {
      subject,
      moves,
      wanted: 0,
      resumed_at: 0,
      departure_at: None,
      started: false,
      closed_early: None,
    }
  }

  /// Whether every expected move has been reported as an ordered pair.
  const fn complete(&self) -> bool {
    self.wanted == self.moves.len()
  }

  /// Advances the sequence by one replayed record — its index, its subject, the
  /// link it was written under, the delta the session table forwarded and what
  /// the pairer made of it — returning the refusal it earned, or `None` if the
  /// sequence is still intact.
  ///
  /// The departing name is checked where the pairer PARKS it and the arriving
  /// one where the pairer JOINS it: each half is judged at the earliest moment
  /// the source has decided what it is, so a stream that ends on a misnamed
  /// departure still names that defect instead of degrading into "the arrival
  /// never came".
  ///
  /// EVERY record is weighed, the subject's and every stranger's, and the two
  /// are separated by exactly one thing: a stranger's own bits are matched
  /// against no move (its rename halves are its business, its name names its own
  /// link, its close ends its own session) while the EVENTS are read whoever
  /// they name — because the event a stranger's arrival produces may be the
  /// widowing of THIS subject's parked half, and that is the whole reason the
  /// stranger is in the stream.
  fn weigh(
    &mut self,
    at: usize,
    frn: u128,
    name: &str,
    fresh: u32,
    events: Vec<UsnEvent>,
  ) -> Option<PremiseVerdict> {
    if frn == self.subject {
      let renaming = fresh & reason::RENAME;
      if renaming == reason::RENAME {
        return Some(PremiseVerdict::Coalesced {
          move_index: self.wanted,
          at,
        });
      }
      if renaming != 0 {
        if let Some(closed) = self.closed_early {
          return Some(PremiseVerdict::ClosedEarly {
            move_index: self.wanted,
            at: closed,
          });
        }
        self.started = true;
        if renaming == reason::RENAME_OLD_NAME {
          if name != self.moves[self.wanted].from {
            return Some(PremiseVerdict::Unattributed {
              move_index: self.wanted,
              half: RenameHalf::Departing,
              at,
            });
          }
          self.departure_at = Some(at);
        }
      }
    }
    for event in events {
      match event {
        // A record the source carried no rename half out of decides nothing
        // here: a session opens, writes and links, and none of that is what is
        // being weighed.
        UsnEvent::Single(_) => {}
        UsnEvent::WidowOld(old) if old.frn == self.subject => {
          return Some(PremiseVerdict::Unpaired {
            move_index: self.wanted,
            at: source_index(&old),
          });
        }
        UsnEvent::WidowNew(new) if new.frn == self.subject => {
          return Some(PremiseVerdict::OutOfOrder {
            move_index: self.wanted,
            at: source_index(&new),
          });
        }
        UsnEvent::Renamed { new, .. } if new.frn == self.subject => {
          // The pairer emits a join at the ARRIVING record, so `new` is this
          // record and its name is the one the move must arrive at. The
          // departing name was checked when this same pairer parked it, and no
          // move can have completed in between to move the goalposts.
          if name != self.moves[self.wanted].to {
            return Some(PremiseVerdict::Unattributed {
              move_index: self.wanted,
              half: RenameHalf::Arriving,
              at: source_index(&new),
            });
          }
          self.departure_at = None;
          self.resumed_at = at + 1;
          self.wanted += 1;
          if self.complete() {
            break;
          }
        }
        // A STRANGER'S OWN PAIRING, joined or widowed. It is the source's
        // verdict about another file reference and says nothing whatever about
        // this one's moves — the only thing a stranger decides here it decides
        // through the arms above, by having taken this subject's carry with it.
        UsnEvent::WidowOld(_) | UsnEvent::WidowNew(_) | UsnEvent::Renamed { .. } => {}
      }
    }
    None
  }

  /// Remembers that the SUBJECT's `CLOSE` ended its session while moves were
  /// outstanding.
  ///
  /// It is a WALL rather than a reset: nothing recorded after it may advance the
  /// sequence. A close clears the accumulated word, so halves written after one
  /// are fresh on every filesystem — accumulating ones included — and reading
  /// them would certify the retirement off evidence that does not bear on it.
  const fn note_close(&mut self, at: usize) {
    if self.started && self.closed_early.is_none() {
      self.closed_early = Some(at);
    }
  }

  /// What the stream still owes, once it has run out with a move outstanding.
  ///
  /// WHICH half is owed is the pairer's own state, narrowed to this subject —
  /// `carrying` says the source is holding a departure and `departure_at` says
  /// it is holding THIS one, and neither answers alone over a volume-wide slot.
  /// WHY the stream ran out is the difference between a journal that wrote
  /// nothing and a journal that wrote a bit production discards. Only the second
  /// impeaches the delta rule, so the tail is asked which happened rather than
  /// guessed at — and asked of the subject's own records, since a stranger's
  /// rename bit is evidence about the stranger.
  fn owed(&self, records: &[PremiseRecord<'_>], carrying: bool) -> PremiseVerdict {
    let (half, resumed_at) = match self.departure_at.filter(|_| carrying) {
      Some(parked) => (RenameHalf::Arriving, parked + 1),
      None => (RenameHalf::Departing, self.resumed_at),
    };
    let stale = records[resumed_at..]
      .iter()
      .rposition(|entry| entry.frn == self.subject && entry.reason & half.bit() != 0);
    match stale {
      Some(offset) => PremiseVerdict::NotFresh {
        move_index: self.wanted,
        half,
        at: resumed_at + offset,
      },
      None => PremiseVerdict::Silent {
        move_index: self.wanted,
        half,
      },
    }
  }
}

/// Whether `records` — a WHOLE VOLUME's journal records, in journal order —
/// report every move in `moves`, made by `subject`, as its own ordered,
/// correctly named pair of FRESH halves that the SOURCE ITSELF joins, followed
/// by a close.
///
/// The records are replayed through a real `SessionTable` and a real
/// `UsnPairer`, in the order the admission sequences them, so "fresh" and
/// "paired" both mean precisely what the source means by them. A record whose
/// delta carries neither rename half is skipped. A record OF THE SUBJECT whose
/// delta DOES carry one must carry EXACTLY the half the sequence is owed, under
/// the name it is owed at, adjacently enough for the source's own pairer to join
/// it — anything else is a refusal.
///
/// PASSING ONE SUBJECT'S RECORDS IS NOT A NARROWER QUESTION, IT IS A DIFFERENT
/// ONE, and the module header says why: the source's drain rule fires on records
/// of OTHER subjects, so a filtered stream is one in which the rule that widows
/// a pair cannot fire at all. Give this the stream as the journal wrote it.
///
/// An empty `moves` asks only that the stream contain a close of the subject's.
#[must_use]
pub fn moves_are_recorded_afresh(
  records: &[PremiseRecord<'_>],
  subject: u128,
  moves: &[ExpectedMove<'_>],
) -> PremiseVerdict {
  // THE TABLE MUST NOT EVICT, and over a volume-wide stream a fixed cap no
  // longer promises that. An eviction drops the evicted subject's accumulated
  // mask, after which a re-asserted half meets an empty mask and is FRESH on
  // every filesystem — the accumulating world waved through by a bound rather
  // than by the journal. It would also be the one path that reaches the orphan
  // ledger, and so the one path that can raise a disowning verdict here. So the
  // cap is sized to the stream: at most one live entry per record, and one more
  // than that holds them all whatever the volume's traffic was. It bounds the
  // REPLAY and states nothing about the source's own cap, which is a different
  // question with a different answer.
  //
  // The rename semantics are STATED rather than inherited from the constructor's
  // default — this gate speaks for the MEASURED volume and for no other, and the
  // retirement it licenses is scoped to exactly that.
  let cap = records.len().saturating_add(1);
  let mut table = SessionTable::new(cap).with_rename_semantics(RenameSemantics::Measured);
  let mut pairer = UsnPairer::new();
  let mut sequence = Sequence::new(subject, moves);
  // Set once every expected move has been consumed; from then on the only
  // question left is whether a close follows. An empty `moves` is already there.
  let mut completed_at = moves.is_empty().then_some(0usize);
  for (at, entry) in records.iter().enumerate() {
    let record = UsnRecord {
      // The journal's own subject key, carried verbatim. It is what the drain
      // rule, the session accounting and the pairer's join condition all turn
      // on, so a replay that flattened it would be replaying a stream the source
      // never reads.
      frn: entry.frn,
      parent: 0,
      // The record's own position, so an event the pairer hands back records
      // later can still be attributed to the record it came from.
      usn: at as i64,
      reason: entry.reason,
      source_info: 0,
      attributes: 0,
      name: UsnName::Utf8(entry.name.to_owned()),
    };
    // `UsnAdmission::admit`'s own order, and every step of it is load-bearing:
    // the carry is drained BEFORE anything is accounted (a STRANGER's record can
    // evict the session entry the carry's registrations are made against, and
    // the carry's own `CLOSE` retires it, so both widow the half rather than
    // waiting on it), the delta is taken second, and a record the delta leaves
    // nothing to forward never reaches the pairer at all — so it neither pairs
    // nor breaks an adjacency.
    let mut events = Vec::new();
    if pairer.holds_old_whose_entry_this_record_takes(&record) {
      pairer.flush(&mut events);
    }
    let outcome = table.observe(&record);
    // The one step of the admission this replay cannot reach is the LOWERING,
    // which resolves through a map no gate has. Its ordering rule is carried
    // anyway rather than quietly dropped: a record whose accounting disowns its
    // own name completes no parked half, so that half widows and the record
    // itself lowers nothing. Unreachable as this table is configured — only an
    // UNMEASURED volume's close, or a debt the cap orphaned, raises such a
    // verdict, and this gate speaks for the measured volume and sizes the cap so
    // that nothing is ever evicted — and replicated exactly because an omission
    // nobody wrote down is how the pairing came to be re-derived.
    let disowned = outcome.unnamed.disowns_its_record();
    if disowned {
      pairer.flush(&mut events);
    }
    let fresh = if disowned {
      0
    } else {
      outcome.mask & !reason::FILTERED
    };
    if fresh != 0 {
      pairer.push(
        UsnRecord {
          reason: fresh,
          ..record
        },
        fresh,
        &mut events,
      );
    }
    if completed_at.is_none() {
      if let Some(verdict) = sequence.weigh(at, entry.frn, entry.name, fresh, events) {
        return verdict;
      }
      if sequence.complete() {
        completed_at = Some(at);
      }
    }
    // Only the SUBJECT's close ends the session the premise is about. A
    // stranger's close ends the stranger's, which neither completes this stream
    // nor walls it — it is one more record that takes the carry's entry, and the
    // drain above has already said so.
    if entry.frn != subject || entry.reason & reason::CLOSE == 0 {
      continue;
    }
    match completed_at {
      // The close may be the very record that completed the last move, so the
      // search for it starts at that record rather than after it.
      Some(done) if at >= done => return PremiseVerdict::Holds,
      _ => sequence.note_close(at),
    }
  }
  if completed_at.is_some() {
    return PremiseVerdict::Unclosed;
  }
  sequence.owed(records, pairer.holds_old())
}

#[cfg(test)]
mod tests {
  use super::{ExpectedMove, PremiseRecord, PremiseVerdict, RenameHalf, moves_are_recorded_afresh};

  /// The file reference the expected moves are about.
  const SUBJECT: u128 = 0x0004_0000_0000_1234;
  /// Any OTHER file reference on the same volume. The journal is volume-wide,
  /// so records of one interleave the subject's for no reason at all — and the
  /// source's drain rule is about exactly that.
  const STRANGER: u128 = 0x0004_0000_0000_5678;

  fn rec(reason: u32, name: &str) -> PremiseRecord<'_> {
    PremiseRecord {
      frn: SUBJECT,
      reason,
      name,
    }
  }

  /// One record of a DIFFERENT subject, as the journal interleaves them.
  fn other(reason: u32, name: &str) -> PremiseRecord<'_> {
    PremiseRecord {
      frn: STRANGER,
      reason,
      name,
    }
  }

  fn mv<'a>(from: &'a str, to: &'a str) -> ExpectedMove<'a> {
    ExpectedMove { from, to }
  }

  fn two_links() -> Vec<ExpectedMove<'static>> {
    vec![
      mv("hardlink-a.txt", "hardlink-a2.txt"),
      mv("hardlink-b.txt", "hardlink-b2.txt"),
    ]
  }

  /// The stream the `windows-2022` and `windows-2025` runners actually printed,
  /// verbatim from the module header — two moves through one held handle. This
  /// is the sequence the retirement was licensed by, so a predicate that
  /// refused it would be refusing the evidence rather than testing it.
  fn measured_ntfs() -> Vec<PremiseRecord<'static>> {
    vec![
      rec(0x0000_0100, "repeat-first.txt"),
      rec(0x0000_1100, "repeat-first.txt"),
      rec(0x0000_2100, "repeat-second.txt"),
      rec(0x0000_1100, "repeat-second.txt"),
      rec(0x0000_2100, "repeat-third.txt"),
      rec(0x8000_2100, "repeat-third.txt"),
    ]
  }

  fn measured_moves() -> Vec<ExpectedMove<'static>> {
    vec![
      mv("repeat-first.txt", "repeat-second.txt"),
      mv("repeat-second.txt", "repeat-third.txt"),
    ]
  }

  #[test]
  fn the_measured_ntfs_stream_holds() {
    assert_eq!(
      moves_are_recorded_afresh(&measured_ntfs(), SUBJECT, &measured_moves()),
      PremiseVerdict::Holds,
      "the stream the retirement was licensed by must satisfy the predicate \
       enforcing it"
    );
  }

  /// The same stream with the close removed proves nothing about a session,
  /// because it has not been shown to be one — the reason the cell that takes
  /// this measurement waits for the close before judging anything.
  #[test]
  fn a_stream_that_never_closes_is_refused() {
    let mut records = measured_ntfs();
    records.pop();
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &measured_moves()),
      PremiseVerdict::Unclosed
    );
  }

  /// The shape the retirement would be WRONG about: the second link's move
  /// writes no record at all, so the subject's location changed with nothing in
  /// the stream to say so.
  #[test]
  fn a_silent_second_move_is_refused() {
    let records = [
      rec(0x0000_0100, "hardlink-a.txt"),
      rec(0x0000_1100, "hardlink-a.txt"),
      rec(0x0000_2100, "hardlink-a2.txt"),
      // link B is renamed here and the journal says nothing.
      rec(0x8000_2100, "hardlink-a2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::Silent {
        move_index: 1,
        half: RenameHalf::Departing,
      }
    );
  }

  /// The shape the finding named: the records EXIST, but the rename bits
  /// accumulated instead of alternating, so production's delta drops both
  /// halves and the move reaches no consumer. A predicate that counted raw bits
  /// would call this a pass.
  #[test]
  fn an_accumulating_mask_is_refused_even_though_records_exist() {
    let records = [
      rec(0x0000_0100, "hardlink-a.txt"),
      rec(0x0000_1100, "hardlink-a.txt"),
      // Both halves now stand at once — the world the measurement ruled out.
      rec(0x0000_3100, "hardlink-a2.txt"),
      rec(0x0000_3100, "hardlink-b.txt"),
      rec(0x0000_3100, "hardlink-b2.txt"),
      rec(0x8000_3100, "hardlink-b2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::NotFresh {
        move_index: 1,
        half: RenameHalf::Departing,
        at: 5,
      },
      "the bit is in the word and production still discards it"
    );
  }

  /// THE ACCUMULATING MASK THE FRESHNESS TEST CANNOT SEE, verbatim as the
  /// review posed it: the expected bit is present AND fresh in every position,
  /// so a predicate that asked only "is the half there and new?" answered
  /// `Holds` — while the source pairs none of it.
  ///
  /// The first record's delta carries both halves at once. Production reads
  /// that as an ARRIVAL with nothing parked and widows it; the departure the
  /// stream meant to report is never reported at all. The predicate refuses it
  /// one step earlier and for the same reason: a fresh rename mask that is not
  /// exactly the owed half is the accumulating world, whatever the source then
  /// does with it.
  #[test]
  fn a_coalesced_first_half_is_refused_even_though_every_expected_bit_is_fresh() {
    let records = [
      rec(0x8000_3000, "hardlink-a.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      rec(0x0000_1000, "hardlink-b.txt"),
      rec(0x8000_2000, "hardlink-b2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::Coalesced {
        move_index: 0,
        at: 0,
      },
      "a delta carrying both halves is the shape the gate exists to fence"
    );
  }

  /// The tail of the same counterexample on its own: an arrival merged into the
  /// subject's own `CLOSE`. The admission drains the parked departure BEFORE it
  /// accounts a record that takes the session entry, so the record that looks
  /// like the move's second half widows the first instead of completing it —
  /// and the source reports two widows where the gate requires one pair.
  #[test]
  fn an_arrival_merged_into_the_close_is_refused() {
    let records = [
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x8000_2000, "hardlink-a2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(
        &records,
        SUBJECT,
        &[mv("hardlink-a.txt", "hardlink-a2.txt")]
      ),
      PremiseVerdict::Unpaired {
        move_index: 0,
        at: 0,
      }
    );
  }

  /// Both halves, correctly named and both fresh — with a record of its own
  /// delta between them. The pairer carries a departure only across ADJACENT
  /// records, so the source widows both ends and announces no move; the gate
  /// certifies ordered pairs, so it declines to certify this.
  #[test]
  fn halves_separated_by_a_record_of_their_own_are_refused() {
    let records = [
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x0000_1002, "hardlink-a.txt"),
      rec(0x0000_3002, "hardlink-a2.txt"),
      rec(0x8000_3002, "hardlink-a2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(
        &records,
        SUBJECT,
        &[mv("hardlink-a.txt", "hardlink-a2.txt")]
      ),
      PremiseVerdict::Unpaired {
        move_index: 0,
        at: 0,
      }
    );
  }

  /// Every half present, correctly named, fresh and adjacently paired — but the
  /// handle closed between the two moves, so the second move's freshness is the
  /// close's doing rather than the rename path's. An accumulating filesystem
  /// would print exactly this, which is why reading past the close would
  /// certify the retirement off evidence that does not bear on it.
  #[test]
  fn a_close_between_the_moves_is_refused() {
    let records = [
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      rec(0x8000_2000, "hardlink-a2.txt"),
      rec(0x0000_1000, "hardlink-b.txt"),
      rec(0x0000_2000, "hardlink-b2.txt"),
      rec(0x8000_2000, "hardlink-b2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::ClosedEarly {
        move_index: 1,
        at: 2,
      }
    );
  }

  /// Two moves' worth of fresh halves, neither naming the second link — the
  /// "recorded but unattributed" outcome the earlier cell classified and then
  /// declined to fail on.
  #[test]
  fn fresh_halves_under_the_wrong_name_are_refused() {
    let records = [
      rec(0x0000_1100, "hardlink-a.txt"),
      rec(0x0000_2100, "hardlink-a2.txt"),
      rec(0x0000_1100, "hardlink-a2.txt"),
      rec(0x0000_2100, "hardlink-a3.txt"),
      rec(0x8000_2100, "hardlink-a3.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::Unattributed {
        move_index: 1,
        half: RenameHalf::Departing,
        at: 2,
      }
    );
  }

  /// The arriving half ahead of its own departing one. The pairing is
  /// order-bound, so this stream is outside what the retirement reasoned about
  /// even though both halves are present and correctly named.
  #[test]
  fn an_inverted_pair_is_refused() {
    let records = [
      rec(0x0000_2000, "hardlink-a2.txt"),
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x8000_1000, "hardlink-a2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(
        &records,
        SUBJECT,
        &[mv("hardlink-a.txt", "hardlink-a2.txt")]
      ),
      PremiseVerdict::OutOfOrder {
        move_index: 0,
        at: 0,
      }
    );
  }

  /// An empty stream is not evidence of anything, and in particular is not
  /// evidence FOR the premise.
  #[test]
  fn an_empty_stream_is_refused() {
    assert_eq!(
      moves_are_recorded_afresh(&[], SUBJECT, &[mv("a", "b")]),
      PremiseVerdict::Silent {
        move_index: 0,
        half: RenameHalf::Departing,
      }
    );
    assert_eq!(
      moves_are_recorded_afresh(&[], SUBJECT, &[]),
      PremiseVerdict::Unclosed
    );
  }

  /// A departure parked with its arrival not yet drained is not a refusal about
  /// the departure — the polling cell simply has not read far enough — so the
  /// half the tail reports owed is the ARRIVING one.
  #[test]
  fn a_parked_departure_owes_its_arrival() {
    let records = [
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      rec(0x0000_1000, "hardlink-b.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::Silent {
        move_index: 1,
        half: RenameHalf::Arriving,
      }
    );
  }

  /// A session that opens, writes and links before it moves anything: the
  /// records that carry no rename half are skipped rather than refused, and a
  /// close from an EARLIER session resets the accumulator exactly as the source
  /// would have it.
  #[test]
  fn unrelated_records_and_an_earlier_session_do_not_disturb_the_verdict() {
    let records = [
      rec(0x0000_0100, "hardlink-a.txt"),
      rec(0x0000_0102, "hardlink-a.txt"),
      rec(0x8000_0102, "hardlink-a.txt"),
      rec(0x0001_0000, "hardlink-b.txt"),
      rec(0x8001_0000, "hardlink-b.txt"),
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      rec(0x0000_1000, "hardlink-b.txt"),
      rec(0x0000_2000, "hardlink-b2.txt"),
      rec(0x8000_2000, "hardlink-b2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::Holds
    );
  }

  /// THE STREAM THE FILTERED GATE COULD NOT SEE, verbatim as the review posed
  /// it: the subject's departing half, ONE RECORD OF ANOTHER SUBJECT, then the
  /// subject's arriving half.
  ///
  /// The journal is volume-wide and this is the ordinary shape of it. Production
  /// drains the parked half before it accounts a record that takes its session
  /// entry, and a stranger's record is such a record, so the source reports
  /// `WidowOld` and `WidowNew` — no ordered move at all. A gate handed only the
  /// subject's records sees the two halves ADJACENT, joins them, and certifies a
  /// pairing the source never performed.
  #[test]
  fn a_strangers_record_between_the_halves_is_refused() {
    let records = [
      rec(0x0000_1000, "hardlink-a.txt"),
      // One write on some unrelated file. That is the entire counterexample.
      other(0x0000_0102, "someone-else.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      rec(0x8000_2000, "hardlink-a2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(
        &records,
        SUBJECT,
        &[mv("hardlink-a.txt", "hardlink-a2.txt")]
      ),
      PremiseVerdict::Unpaired {
        move_index: 0,
        at: 0,
      },
      "a stranger between the halves is what the source widows on"
    );
  }

  /// The same counterexample with the stranger's mask entirely REPEATED, so its
  /// delta is empty and the record reaches neither the pairer nor a consumer.
  ///
  /// It widows the subject's half anyway, and that is the drain's placement
  /// rather than an accident: the carry is drained AHEAD of the accounting that
  /// would have found the delta empty, because the question the drain asks is
  /// whether this record takes the carry's session entry — which is answerable
  /// off the raw record and is `true` for every stranger, silent or not.
  #[test]
  fn even_a_zero_delta_stranger_between_the_halves_is_refused() {
    let records = [
      other(0x0000_0102, "someone-else.txt"),
      rec(0x0000_1000, "hardlink-a.txt"),
      other(0x0000_0102, "someone-else.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      rec(0x8000_2000, "hardlink-a2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(
        &records,
        SUBJECT,
        &[mv("hardlink-a.txt", "hardlink-a2.txt")]
      ),
      PremiseVerdict::Unpaired {
        move_index: 0,
        at: 1,
      }
    );
  }

  /// Strangers everywhere EXCEPT between a pair's two halves, including a
  /// stranger's `CLOSE` sitting exactly where the subject's own close would wall
  /// the sequence. None of them is about this subject: a foreign close ends a
  /// foreign session, and the carry is empty at each of these points, so the
  /// source joins both pairs and the premise holds.
  #[test]
  fn strangers_around_the_pairs_do_not_disturb_the_verdict() {
    let records = [
      other(0x0000_0100, "someone-else.txt"),
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      other(0x8000_0100, "someone-else.txt"),
      rec(0x0000_1000, "hardlink-b.txt"),
      rec(0x0000_2000, "hardlink-b2.txt"),
      other(0x0000_0100, "third-party.txt"),
      rec(0x8000_2000, "hardlink-b2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::Holds
    );
  }

  /// A stranger's own half widowed by the subject's arrival. The source really
  /// does report a widow here — for the STRANGER — and it says nothing whatever
  /// about the moves being weighed, so the subject's pair still holds.
  #[test]
  fn a_strangers_widowed_half_is_not_this_subjects_refusal() {
    let records = [
      other(0x0000_1000, "someone-else.txt"),
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      rec(0x8000_2000, "hardlink-a2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(
        &records,
        SUBJECT,
        &[mv("hardlink-a.txt", "hardlink-a2.txt")]
      ),
      PremiseVerdict::Holds
    );
  }

  /// A stranger moving through the EXPECTED NAMES reports nothing for this
  /// subject. Attribution is the journal's file reference, never the link text:
  /// a volume is free to have another file called `hardlink-b.txt`, and the
  /// subject's second move is still owed after it moves.
  #[test]
  fn a_strangers_move_under_the_expected_names_reports_nothing_for_the_subject() {
    let records = [
      rec(0x0000_1000, "hardlink-a.txt"),
      rec(0x0000_2000, "hardlink-a2.txt"),
      other(0x0000_1000, "hardlink-b.txt"),
      other(0x0000_2000, "hardlink-b2.txt"),
      rec(0x8000_2000, "hardlink-a2.txt"),
    ];
    assert_eq!(
      moves_are_recorded_afresh(&records, SUBJECT, &two_links()),
      PremiseVerdict::Silent {
        move_index: 1,
        half: RenameHalf::Departing,
      },
      "the stranger's pair is the stranger's; link B never moved"
    );
  }
}
