//! The sans-I/O driver core: every decision between a raw OS batch and the
//! Monitor lives here, with all I/O returned as typed [`Effect`]s.
//!
//! `DriverCore` is the proto's Sans-I/O pattern applied one level up. It owns
//! the [`Monitor`] plus the driver state the Monitor cannot hold — path
//! lowering, flag grounding, rename classification, probe parking, overflow
//! clamping, identity minting, and the consumer-lag protocol — and it never
//! spawns, stats, sends, or reads a clock. The async driver task executes the
//! effects it emits and feeds the results (and the time) back in, so every
//! protocol is unit-testable with a hand clock and zero tasks.
//!
//! FSEvents flags are hints, never a log: one event's flag word can carry
//! several operations OR'd together with ordering unrecoverable, so no record
//! verb is minted from an ambiguous word — truth is established by a
//! [`Probe`](Effect::Probe) and anything un-groundable escalates to a located
//! rescan. Loss is never silent.
//!
//! Device trust is fail-closed: every move cookie derives from contemporaneous
//! probe evidence (a live `dev == root_dev` read, or a same-batch partner's
//! probe binding the fileID to the root device), the mount table only ever
//! VETOES trust — its mutations are monotone within a batch (adds early,
//! removals late) — and any loss signal revokes its authority until a fresh
//! read of the live table is installed.
//!
//! # THE CADENCE RULE
//!
//! **A safety predicate may not be derived from a value re-read at a cadence. It
//! must rest on retained evidence of an observation, or on a transition the host
//! itself observed.**
//!
//! This is not a style preference; it is the single shape behind every defect
//! adversarial review has found in the mount subsystem, and it is cheap to audit
//! against. A value re-read at a cadence answers *what is true now*. Almost every
//! predicate here needs *what happened since*, and the two differ exactly when
//! something happened and came back — which is the case that matters and the case a
//! re-read cannot see. The failure is always the same one: a MATCH is taken as
//! CONFIRMATION, so the predicate is loudest precisely when it is wrong.
//!
//! Five shapes it covers, one per site the rule was extracted from:
//!
//! - **A derivation cannot see evidence that was DISCARDED.**
//!   [`generation_stale`](ScopeState::generation_stale) asks whether the coverage
//!   set's exempt partition was verified in a world this scope has left — and it can
//!   only read the records the set HOLDS. A rejected whole-root generation is
//!   precisely the message that would have put the FIRST exempt record there, so
//!   after the rejection the set is empty of exactly the evidence the derivation
//!   looks for. The answer is not one more clearing site but retained evidence
//!   ([`Generation::Lost`]), set by an observation and discharged by ONE event — a
//!   generation actually landing.
//! - **A value the kernel RECYCLES is not a world counter.** Mount ids are
//!   allocated lowest-free, so a root that went A → B → A is back on the id a
//!   refresh still holds and the comparison passes. The frame moves on an
//!   INCARNATION token instead ([`RootIncarnation`](crate::os::RootIncarnation)) —
//!   a non-recycled id where the kernel has one, else a count of mount-namespace
//!   transitions read through a HELD fd. Both are transitions the host observed;
//!   neither is a value this core re-read.
//! - **A counter another concern can occupy is not a verdict.** A boundary
//!   report's transport credit once came out of `os_batch_capacity`, so one event
//!   batch's slot decided whether a walk's evidence could be delivered; then the
//!   deferrable producer's reports shared the counter the undeferrable one's
//!   terminal was read out of. Both are the same mistake as the public
//!   `max_map_directories` once paying for walk declines.
//! - **A PREDICTION about another party's world is a re-read wearing a record's
//!   clothes.** A refused whole-root recovery used to leave its round trip
//!   ([`pending_recovery`](ScopeState::pending_recovery)) standing, suppressing the
//!   retry on the argument that a fresh request would be answered by a walk reading
//!   the same root and refused identically. The core holds no reading of the
//!   source's world at all — only one reply, evidence of where one walk stood at
//!   one moment — so the suppression was a re-read of this core's OWN unchanged
//!   frame taken as confirmation, and a transient same-object self-bind (the walk
//!   fences against a mount that departs before the refresh, leaving the root on
//!   the object it started on, so neither the legacy id nor the never-recycled
//!   incarnation token moves) made it permanent. The answer is not a third state
//!   machine: the record is DISCHARGED by the reply that dominates it, and the
//!   retry is SPENT once, with the refusal that comes back from the request spent
//!   on it as the observation the prediction wanted ([`RefusedWalk`]).
//! - **A backlog is not a death.** A producer that could not claim a boundary-report
//!   slot answered the terminal, on the reading that a full counter proves the
//!   driver has stopped consuming. It proves only that eight reports await
//!   ingestion at this instant, and permits return on another thread — so a driver
//!   merely descheduled killed a healthy source. Separating the deferrable and
//!   undeferrable counters (the shape above) stopped one producer occupying the
//!   other's headroom; it did not turn an instantaneous count into evidence of a
//!   transition. The answer is to reserve the credit BEFORE the events leave the
//!   kernel — where a producer that "cannot defer" still has somewhere to put them
//!   — and to reserve the terminal for a liveness proof (a closed receiver, a
//!   failed read, an ABI verdict, an explicit shutdown).
//!
//! ## THE BOUND/VERDICT RULE
//!
//! The third and fifth shapes above are the same shape, and it is sharper than the
//! cadence rule and decidable by inspection alone, so it is stated on its own:
//!
//! > **A piece of state may express a BOUND or a VERDICT, never both — and every
//! > TERMINAL must name the observation that proves it.**
//!
//! A bound answers *how much*, and it is a residency, a quota, a cap. A verdict
//! answers *what is true*, and the ones that matter here grant trust, retire a
//! record, or end a source. Reading a full bound as a verdict is how a healthy
//! source was killed twice: the boundary-report counters say eight reports await
//! ingestion at this instant and nothing about the driver, so their exhaustion
//! answers a WAIT, and the terminal is reserved for a liveness proof (a closed
//! receiver, a failed read, an ABI verdict, an explicit shutdown).
//!
//! **The one exception, and the test for it:** a shared counter feeding a
//! CONSERVATIVE verdict is sound, because a foreign occupant can only push the
//! answer toward the safe side. A foreign occupant of the Windows drain's
//! `DRAIN_PACKET_BUDGET` — the recorded exception — can only push a teardown toward
//! `Unproven`, and a reserved unit on `teardown_pressure` can only push a `watch`
//! toward a capacity refusal; neither grants trust and neither is terminal. Sharing
//! is a defect exactly when the verdict it feeds is terminal or trust-granting.
//!
//! **A verdict names its observation, and the observation must still be OPEN.** The
//! trap the rule's own sites fell into is naming a fact about a step that has
//! already completed. [`on_root_recovered`](DriverCore::on_root_recovered)'s
//! mismatch arm reads *a reply was refused* — a fact about the read that already
//! happened — and used it to arm the next one; what says a read is still owed is
//! [`owes_whole_root`](ScopeState::owes_whole_root), and while a round trip stands
//! in the world this scope holds, a read can only move the frame out from under it
//! and refuse it too. Retained evidence keyed to a disagreement
//! ([`RefusedWalk`]) bounds the retry only on the leg that HAS a key; the arming
//! must name the need.
//!
//! **And the site is not one site.** Three arms schedule a whole-root recovery —
//! an autonomous generation lost ([`on_walk_boundaries`](DriverCore::on_walk_boundaries)),
//! a requested reply refused ([`on_root_recovered`](DriverCore::on_root_recovered)),
//! a located admission reply from a world this scope has left
//! ([`on_admitted`](DriverCore::on_admitted)) — and each once spelled its own
//! conjunct set over the same question, so a different one of them was found
//! incomplete each round: one armed unconditionally, one overwrote a round trip
//! already out, one derived the need from a set it had just emptied. Naming the
//! need is not enough if three copies name it differently, so all three now read
//! ONE predicate over TWO values whose product is entirely legal
//! ([`Generation`] and [`pending_recovery`](ScopeState::pending_recovery)):
//! `transition; if owes_whole_root() { carrier }`. They differ only in the carrier
//! — a mount refresh for the two that dispute the FRAME (the core may be the stale
//! party, so an immediate re-request would be answered by a walk reading the very
//! same root), and a request on the spot for the one that disputes nothing about
//! it, whose need is witnessed by a parked ticket the arm is about to retire.
//!
//! # Mount-refresh publication
//!
//! [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed) publishes on a strict
//! order. The root-LIVENESS verdict is acted on FIRST and unconditionally — a dead
//! root is terminal regardless of snapshot staleness, so its death evidence is never
//! discarded by a stale flag. Everything the snapshot then carries — the mount TABLE
//! and the root's descent FRAME (`root_mnt_id`) — publishes ONLY when the snapshot is
//! not stale: a stale completion (an INVALIDATING arming — a loss, or a world swap —
//! overlapped its read, so the snapshot may predate the lost window, and the table +
//! frame come from that one read) publishes neither and re-arms one fresh read. The
//! periodic tick is NOT such an arming: it coalesces onto an in-flight read and lets
//! it publish, because a cadence witnesses no transition (see [`RefreshCause`]).
//! So `state.root_mnt_id` is only ever
//! the last AUTHORITATIVE frame, never a stale/pre-window one, and the frame
//! [`crosses_mount_boundary`] consumes for enumerate descent is always authoritative.
//! A non-stale frame CHANGE (a same-object re-mount moved the root to a different
//! mount) then reconciles a DESCENDING scope's coverage — a rescan-and-re-arm
//! re-checks the children the last enumerate classified under the old frame, since
//! adopting the frame alone does not re-read them (a kernel-recursive scope never
//! consumes the frame, so it needs no replay).
//!
//! The mount-TABLE half carries an authority invariant of its own: `mounts_authoritative`
//! is true ONLY immediately after a refresh installs an authoritative table, and ANY
//! refresh that cannot install one closes it — a STALE completion (discarded above) OR
//! a live but NON-authoritative read (the live table could not be read). So the
//! device-trust-by-absence check ([`device_trusted`]) consults the table ONLY while
//! authority is open; a closed authority falls back to the conservative born-closed
//! behavior — no absence-based trust until the next authoritative refresh re-opens it —
//! while probe-read device evidence (`dev == root_dev`) still decides independently
//! throughout.
//!
//! That install REPLACES the table component rather than unioning onto it, and the
//! separation that makes replacement sound is the point: the rows a snapshot lists
//! ([`ScopeState::mount_table`]) are replaceable because reads are serialized and a
//! row absent from an authoritative one is a mount the host says is gone, while every
//! prefix learned from something OTHER than a snapshot — an in-band mount word, a
//! probe's foreign device — lives in [`ScopeState::learned_mounts`], which no read may
//! shrink. The union that stood in their place retained one path per HISTORICAL
//! mountpoint for the life of the scope. And the whole check is gated per backend
//! ([`consumes_absence_trust`]): one predicate decides both whether the table is built
//! and whether it may be read, so a backend that consumes no absence trust maintains
//! nothing and is granted nothing.
//!
//! # Root-death signals per backend
//!
//! Every backend's root death — unmount, delete, or replace — must reach a
//! trigger that runs [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed)'s
//! death mapping or the Monitor's self-event path; the trigger differs by
//! backend, and two backends' unmount is signal-silent, which the periodic tick
//! ([`root_liveness_interval`](DriverCore::new)) exists to cover:
//!
//! | backend | root unmount trigger | in-tree delete/replace trigger |
//! |---|---|---|
//! | inotify (descending) | `IN_UNMOUNT` + `IN_IGNORED` event — **but a LAZY unmount emits neither** (#74) → the **periodic tick** re-stats the root | `IN_DELETE_SELF` / `IN_MOVE_SELF` event |
//! | FSEvents (macOS) | `RootChanged` flag → root-alive probe | `RootChanged` flag → root-alive probe |
//! | fanotify (`FAN_MARK_FILESYSTEM`) | **SILENT** — no event, no hangup (the mark holds the sb alive; L4.1) → the **periodic tick** re-stats the root | `FAN_DELETE_SELF` / `FAN_MOVE_SELF` event |
//! | RDCW (Windows) | any terminal read completion → fatal source error → self-event | same signal; RDCW draws no in-band distinction from unmount |
//! | USN journal (Windows) | a failed journal read → fatal source error → self-event | the root's own FRN named in a delete/rename record → `RootDeath` |
//!
//! So the Linux pair arms the tick and nothing else does (gated by
//! [`liveness_ticked`](DriverCore::liveness_ticked)); every listed in-band
//! signal already lowers a terminal `Removed`/`Rescan` through the existing
//! paths, and the tick's role is solely to make the quiet cases observable
//! within a bounded latency — a loss-triggered refresh already catches them
//! immediately when a loss occurs.
//!
//! # Mount transitions below the root
//!
//! The same silence has a second half that is about COVERAGE rather than death:
//! a mount that departs BELOW the root leaves everything under it uncovered, and
//! a lazy unmount announces that to nobody either. Only FSEvents lowers such a
//! departure in band (an `UNMOUNT` flag word, which `compile::fsevents`'
//! `plan_mount` turns into a located cover AND a table removal); no other
//! backend does, and the table install below is a UNION, so a departed prefix is
//! never removed by a refresh.
//!
//! **The mount table is the OBSERVER for that whole class, not a belt beside
//! one.** A mount created after the watcher settles is seen by nothing else: no
//! enumerate runs (there is no event), the fanotify walk is spawn-only, and no
//! arm fires. So [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed) diffs
//! each authoritative read against the CENSUS the last one left
//! ([`ScopeState::census`]) and feeds one LOCATED COVER per transition:
//!
//! - **departure**, a key gone from the read: cover at the census's location for
//!   it;
//! - **arrival**, a key absent from the census: cover — an appearing mount
//!   shadows ground the consumer may already have enumerated, which is why
//!   `compile::fsevents` covers the arrivals macOS signals;
//! - **move**, the same key rendered somewhere else: cover BOTH, since the ground
//!   it left is revealed and the ground it landed on is shadowed;
//! - **replacement**, the same key at the same location on a different device:
//!   cover.
//!
//! Nothing derived here touches the trust components at all, and that separation
//! is what the two sets exist for: coverage asks what MOVED since the last read,
//! trust asks what is foreign NOW, and their safety directions are opposite. The
//! trust table's own replacement discipline is stated above.
//!
//! ## Identity is the key, the path is a hint
//!
//! The census is keyed by the row's own mount id wherever the host answers one
//! ([`Key`]), and #74 is the reason. `/proc/self/mountinfo` renders each row's
//! path by its own `seq_path_root` call, and the namespace-generation bracket the
//! read is taken inside certifies `(mnt_id, dev)` and nothing about the label —
//! so the table is a coherent source of mount IDENTITY and a best-effort source
//! of mount LOCATION. Keyed by the label instead, the bug reproduces with no torn
//! read at all: a mount at `R/a/x`, then `mv R/a R/b`, then a lazy unmount of
//! `R/b/x` derives the departure against a stale `R/a/x` and never covers the
//! ground revealed at `R/b/x`.
//!
//! Locations survive as COVER-LOCATION HINTS, re-rooted the moment the core
//! learns a directory moved ([`rebase_hints`](DriverCore::rebase_hints)) and
//! lowered through [`mount_cover`], which degrades to the whole root for a hint
//! it cannot spell — over-cover, never silence.
//!
//! ## Condemn on a TRANSITION, never on an ABSENCE
//!
//! Which boundaries may be covered-and-dropped is not a property any of them
//! carries. A btrfs subvolume (device belt, root's own mount id, no table row
//! ever) is in no census, so it transitions in none, so nothing here ever
//! condemns it — the cover storm that a per-record provenance partition once
//! existed to prevent is structurally impossible, with no partition at all. A
//! key's PRESENCE obliges nothing; only a transition between two observations
//! does.
//!
//! What a census cannot speak for is held in the LEDGER
//! ([`ScopeState::ledger`]), and only a seam ever puts anything there. Each entry
//! carries the [`Standing`] its own seam decided from the two ids it read, and
//! that decision is a fact about one instant rather than a predicate re-evaluated
//! against a root frame that moves:
//!
//! - [`Standing::Mount`] — an id that differs from the root's: a vfsmount seen
//!   before any census listed it. It is the departure BELT for exactly the window
//!   between that seam and the next authoritative read, which is where the join
//!   spends it: listed, the census owns every later transition; unlisted, this is
//!   the one place that departure was ever derivable.
//! - [`Standing::SameMount`] — the ROOT's own mount id: a subvolume. No row will
//!   ever list it, so it joins nothing and is condemned by nothing; the event
//!   stream and the generations retire it.
//! - [`Standing::Unknown`] — one id unanswerable, which is EVERY seam observation
//!   on Linux 4.11–5.7 until stage 3 reads ids from `fdinfo`, genuine vfsmounts
//!   included. Nothing can tell those two apart, so the scope pays for the
//!   ambiguity at the coarsest granularity there is:
//!
//! > **While a scope holds ANY `Unknown` entry, every AUTHORITATIVE refresh
//! > covers the WHOLE ROOT** ([`ScopeState::fails_closed`]).
//!
//! Three earlier designs tried to bound this per record — a spent-once `bool`, a
//! generation stamp with a cadence, a saturation latch — and each produced a
//! fresh defect, because on a host that answers no mount ids the storm sequence
//! and the silent-loss sequence are the SAME sequence of observations: absent
//! from every census, re-declined by every crawl. No predicate over a per-entry
//! observation can separate them. The scope-wide rule does not try.
//!
//! **The cost is real and accepted.** On a 4.11–5.7 kernel whose root holds btrfs
//! subvolumes, every seam entry is `Unknown` and only a census row standing at
//! its location clears one — and no row ever stands at a subvolume — so the scope
//! covers its whole root on every authoritative refresh, for as long as it holds
//! one. That is correctness bought
//! at a permanent per-refresh root cover, and it is the deliberate trade; see
//! [`root_liveness_interval`](crate::WatcherOptions::root_liveness_interval).
//!
//! **Who actually pays is narrow.** On Linux ≥ 5.8 the `Unknown` population is
//! provably EMPTY: `root_mnt_id` is read at spawn or the source does not start,
//! and every seam that records a boundary reads the id from the fd it already
//! pinned (a `statx` that FAILS never mints an entry at all). So every entry is
//! decided `Mount` or `SameMount`, and `fails_closed` answers `false` for the life
//! of the scope. The fanotify backend requires `FAN_REPORT_TARGET_FID` (5.17), so
//! it can never run on a host that pays this at all.
//!
//! A refusal at [`MAX_BOUNDARIES`] needs no announcement of its own for the same
//! reason: the bound only refuses when the ledger is full of entries that may yet
//! owe a cover, which on an id-less host is exactly the state that already covers
//! the whole root every refresh.
//!
//! A world swap (spawn, replace, widen) SEEDS the census from its own barrier
//! read rather than emptying it, and empties the ledger with the world it
//! described. The barrier read opens no authority, but the cold crawl that follows
//! the swap declines coverage beneath every mount it finds, and the two are
//! unordered detached jobs — so a prefix that departs in that window leaves an
//! unenumerated subtree that an empty census could never make derivable, at that
//! refresh or any later one.
//!
//! ## Beside the detector: LATENCY seams, and PREVENTION
//!
//! Two roles sit beside the refresh, and neither is a second detector:
//!
//! - **latency seams** — the enumerate decline (`on_enumerated`), the os-layer
//!   WALKS ([`on_walk_boundaries`](DriverCore::on_walk_boundaries)) and a
//!   boundary-bearing probe answer ([`record_probe_boundary`]) record what they
//!   observe into the LEDGER ([`record_boundary`]). For a vfsmount that is
//!   latency ONLY: the next census keys everything they see, so a seam merely
//!   closes the window between an observation and that read. For a boundary no
//!   census will ever list they are the sole observers there will ever be, and
//!   what they record there transitions in no census and is condemned by none.
//! - **prevention** — an arm that would land ACROSS the scope frame is REFUSED
//!   by the executor rather than installed ([`ScopeFrame`] rides every
//!   [`Effect::AddWatch`]). This is the only guard on an arm the enumerate fence
//!   never judged: a directory learned from a `Created` record is armed with no
//!   enumerate in between, and inotify's `Created` carries no identity, so the
//!   arm's own object guard passes whatever it opens.
//!
//! **The WALK seam is not latency on a kernel-recursive profile — it is the only
//! observer there is.** A descending scope re-learns its boundaries on every
//! cover's re-arm crawl; `Monitor::start_rearm` refuses outright when the scope
//! does not descend, so a fanotify scope runs no enumerate at all and its source's
//! own walks are the single place it ever fences a directory. Four walks drive it:
//! the spawn seed walk, whose declines ride `RootMeta::declined` into the same
//! world swap that seeds the baseline; the post-loss whole-map reseed and the
//! moved-in subtree walk and the ADMISSION RESEED, all three of which run on the
//! reader thread and reach
//! [`on_walk_boundaries`](DriverCore::on_walk_boundaries) over the source's one
//! ordered queue. What the walk read is what the set holds — the core
//! re-derives nothing, because a walk's frame comes from a pinned fd no later
//! path resolution could reproduce honestly.
//!
//! ## The admission reseed, and the one cover that WAITS
//!
//! The fourth walk is not only a seam. A fanotify source admits events by
//! directory-handle MEMBERSHIP and its walks stop AT a mount, so the ground a
//! departed mount reveals has no handles in the map: the source is blind to it,
//! and no crawl will ever repair that (`Monitor::start_rearm` refuses a
//! non-descending scope outright). A located cover alone would send the consumer
//! to re-read ground the reader still drops every event on, with no loss signal,
//! since an unknown handle is "provably outside the root".
//!
//! So on that ONE profile a departure's cover is PARKED
//! ([`PendingAdmit`]) on a round trip — [`Effect::AdmitBoundaries`] out,
//! [`on_admitted`](DriverCore::on_admitted) back — and reaches the consumer only
//! once the source can see what it is being sent to look at. Every other backend
//! covers in the same step it condemns; the gate is fanotify, not
//! kernel-recursiveness, because FSEvents, RDCW and the USN journal all mark a
//! tree or a volume rather than a set of handles.
//!
//! **The reseed is scoped to RECORDED boundaries, and that is licensed by one
//! fact about the map.** Ground the watcher knew before a mount arrived is
//! already in the map, and a mount landing over it does not take it out again:
//! the mark's event mask carries no mount verb (`FAN_CREATE`/`DELETE`/`MODIFY`/
//! `ATTRIB`/`RENAME`/`DELETE_SELF`/`MOVE_SELF`/`ONDIR`), so shadowing a directory
//! emits nothing, the map's only removals are `forget` (a real delete or
//! move-out), a whole-map `reseed`, and the orphan eviction that fires when a
//! parent chain breaks — and a shadowed directory's parent chain is intact. So
//! event-learned ground survives a shadow window and resumes on its own; only the
//! ground the walk DECLINED — which is exactly what the ledger records — was
//! never mapped at all. The whole-map reseed is the one removal that can undo
//! this (its walk stops at the live mount and drops what is under it), and that
//! case lands back in the same place: the boundary is recorded, so its departure
//! walks the revealed ground in.
//!
//! **A refusal records nothing, and that is deliberate.** A failed arm reaches
//! the Monitor's `Err` arm, which emits a located `Rescan`, books a
//! level-persistent slot deficit and drops the node — it queues no enumerate and
//! calls no re-arm. For a boundary a census will key the recorder is the next
//! read's ARRIVAL side, whose cover re-arms a crawl that re-runs the decline, and
//! the reconcile heals the deficit. For one no census will ever list there is no
//! row, no arrival and no crawl: the slot stays a deficit re-signalled ahead of
//! every sync cookie — signalled, not silent — and that is the ACCEPTED terminal
//! for that case, not an omission to be repaired later.
//!
//! **The EXEMPT ledger entries have their own lifecycle, because no census can
//! give them one.** Three mechanisms retire them, and each covers a case the
//! others cannot:
//!
//! - [`retire_removed_boundaries`](DriverCore::retire_removed_boundaries) — a
//!   compiled `Removed`/`MovedFrom`/`DeleteSelf`/`MoveSelf` says the location is
//!   gone. Reads the EVENT STREAM, which is exactly what a loss window empties.
//! - [`retire_relisted_boundaries`] — a complete enumerate of a directory is an
//!   authoritative re-observation of its children (the DESCENDING profile's
//!   generation, and the loss recovery's own re-listing runs it).
//! - [`retire_unwalked_boundaries`] — a complete whole-root walk is the same
//!   thing for the KERNEL-RECURSIVE profile, which runs no enumerate at all.
//!
//! **Whatever applies WALK-DERIVED state must know which root the walk ran under**,
//! because a walk's declines are relative to the scope's descent frame and a walk
//! that ran under another one describes a different world. The appliers, and where
//! each stands:
//!
//! - [`on_walk_boundaries`](DriverCore::on_walk_boundaries) and
//!   [`on_root_recovered`](DriverCore::on_root_recovered) — the two messages that
//!   carry a COMPLETE generation, and the two that retire the exempt ledger
//!   entries. Both are checked against the root mount id their walk fenced
//!   against, and the recovery (which answers a request) against the frame epoch it
//!   was issued at as well.
//! - [`on_stream_spawned`](DriverCore::on_stream_spawned),
//!   [`on_root_replaced`](DriverCore::on_root_replaced) and the widen commit —
//!   EXEMPT by construction: each installs `root_dev`/`root_mnt_id`/`frame_epoch`
//!   from the same barrier read whose declines it records, so the generation and
//!   the frame it is relative to cannot disagree.
//! - [`on_admitted`](DriverCore::on_admitted) — already stamped: a reply whose
//!   [`PendingAdmit::epoch`] is not the scope's records nothing.
//! - [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed) — stamped by
//!   construction: `crate::os::mount_sample` takes the table and the root's stat
//!   inside ONE proven-still mount-namespace generation, and a stale or cross-world
//!   snapshot publishes neither.
//! - the DESCENDING profile's enumerate declines ([`retire_relisted_boundaries`])
//!   — unstamped and correctly so: it is a ONE-LEVEL generation on the profile
//!   whose every cover re-arms a crawl that re-runs the very listing, so a frame
//!   that moved under it costs one false condemnation that the next enumerate
//!   repairs. The kernel-recursive profile has no such repair, which is why its
//!   whole-root generation is the one that must be checked.
//! - [`retire_removed_boundaries`](DriverCore::retire_removed_boundaries) and
//!   [`record_probe_boundary`] — frame-FREE: neither carries a captured frame. The
//!   first retires on a location the event stream saw vanish (a mountpoint cannot
//!   be unlinked while a mount is on it), the second evaluates
//!   [`ScopeFrame::crossed_by`] against the live frame at ingest.
//!
//! Above all three retirement mechanisms sits [`MAX_BOUNDARIES`], an
//! unconditional bound that holds when every one of them has failed. Without it a churning subvolume
//! layout whose deletions were repeatedly lost retained one `PathBuf` per missed
//! deletion for the life of the scope, and every linear scan of the ledger paid
//! for it.

use std::{
  collections::{BTreeMap, BTreeSet, VecDeque},
  num::NonZeroU64,
  path::{Path, PathBuf},
  sync::Arc,
  time::Duration,
};

use tributary_proto::{
  ArmAttempt, Capabilities, Change, ChangeKind, DirEntry, EnumerateResult, Evidence, FileKind,
  Identity, Instant, Interest, IoClass, Location, Monitor, MoveCookie, OsRecord, RecordKind, ReqId,
  Scope, ScopeId, Segment, StatEntry, StatResult, SubtreeScope, WatchError, WatchId,
  monitor::{CoverageWorkEpoch, RecordOutcome},
};

use crate::{
  error::WatchRootError,
  os::{
    BackendKind, BatchPayload, FsEventFlags, MountRow, RawOsEvent, RootIdentity, RootMeta,
    ScopeFrame, SourceError, SourceEvent,
    linux::{RawLinuxEvent, WatchOutcome},
    transport::BudgetPermit,
    windows::RawWindowsEvent,
  },
  stamped::Stamped,
};

mod compile;

#[cfg(test)]
mod tests;

/// Correlates a [`Effect::Probe`] request with its
/// [`on_probe_result`](DriverCore::on_probe_result).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProbeId(u64);

/// What an executed probe (one no-follow stat of a path) found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
  /// The path does not exist.
  Missing,
  /// The path exists.
  Present {
    /// The object's kind.
    kind: FileKind,
    /// The object's inode number, if one could be read.
    file_id: Option<NonZeroU64>,
    /// The device the object lives on; identity is minted only on the
    /// root's own device.
    dev: u64,
    /// The object's MOUNT id, or `None` where the host answers none (below
    /// Linux 5.8, the `STATX_MNT_ID` mask bit unset, or a non-Linux/fake
    /// executor).
    ///
    /// Carried for exactly one reason, and it is a correctness one rather than
    /// a convenience: [`record_probe_boundary`] records what a probe answer
    /// reveals about a mount boundary (SEAM 4), and a boundary observation with
    /// no mount id enters the ledger [`Standing::Unknown`] on a host that
    /// answers ids — indistinguishable from a subvolume, and failing the whole
    /// scope closed. A probe that answered a device alone therefore made every
    /// boundary it saw ambiguous on a kernel that could have named it exactly.
    /// Answering the id keeps `None` meaning "the host cannot say", which is
    /// the one reading [`Standing::decide`] is sound under.
    mnt_id: Option<u64>,
  },
  /// The probe failed (permission, I/O); existence is unknowable.
  Failed,
}

/// What the mount refresh's root re-stat found — folded into every refresh so a
/// kernel-recursive backend, which receives no in-tree signal when its root is
/// unmounted or replaced (design §7), still detects the death at the refresh
/// cadence (birth + every loss signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootLiveness {
  /// The root still stats to an object; the core compares its identity against
  /// the barrier's to decide alive-vs-replaced.
  Present(RootIdentity),
  /// The root path no longer exists (lowers to `DeleteSelf`).
  Missing,
  /// The root could not be stat'd (permission, I/O, an unmounted-out mount
  /// point); existence is unknowable, so it lowers to `MoveSelf` exactly like a
  /// `RootChanged` probe that resolves `Failed`.
  Unreadable,
}

/// One mount-table refresh result: the mount rows strictly under the root,
/// whether the read was authoritative, and what the root itself re-stat'd to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountRefresh {
  /// The mount rows observed strictly under the root, at most one per location.
  ///
  /// Identity-bearing where the host can answer it ([`MountRow`]), which is what
  /// makes this refresh the PRIMARY departure detector rather than a belt: a
  /// mount replaced at an unchanged path shows up as an identity change and in
  /// nothing else, and the class of mount created AFTER a watcher settles is
  /// observed by no other seam at all.
  pub(crate) mounts: Vec<MountRow>,
  /// Whether the live mount table could be read (device trust returns only
  /// with an authoritative read).
  pub(crate) authoritative: bool,
  /// The root's liveness at refresh time — the composition-only root-death
  /// check (no new timer, no new effect: the refresh already runs at birth and
  /// on every loss).
  pub(crate) root: RootLiveness,
  /// The root's CURRENT mount id, re-read at the refresh cadence. A same-object
  /// re-mount of the root (unmount + re-bind: identity unchanged, so the death
  /// gate passes) lands the root on a NEW mount, and the descent boundary
  /// [`crosses_mount_boundary`] fences children against the scope's captured
  /// `root_mnt_id` — so without refreshing it, every descendant on the new mount
  /// would read as a boundary and lower non-descendable until the next re-watch.
  /// [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed) adopts a `Some`
  /// value once the root is confirmed alive-and-present AND the refresh is not stale
  /// (a stale snapshot's frame is as suspect as its mount table). `None` (below Linux
  /// 5.8, the mask bit unset, or a non-Linux/fake source that reports no frame)
  /// leaves the captured value intact — a transient read miss never drops a known
  /// frame.
  pub(crate) root_mnt_id: Option<u64>,
  /// WHICH INCARNATION of a mount the root was on when this refresh read it, where
  /// the host can answer that at all ([`RootIncarnation`](crate::os::RootIncarnation)).
  ///
  /// [`root_mnt_id`](Self::root_mnt_id) is a value observed at one instant, and an
  /// unmount plus a remount between two refreshes hands the new mount the id the
  /// old one freed — so an id that MATCHES across the gap is not evidence the root
  /// stayed put. This is the fact that is, and the scope's frame moves on it.
  ///
  /// `None` where nothing could answer: a host with no unique mount id and no
  /// namespace generation, or a window this refresh could not prove quiet (a
  /// token built out of two reads that straddle a transition would read as
  /// continuity on the very next refresh). A `None` compares against nothing and
  /// leaves the scope's last PROVEN token standing — the frame then moves on the
  /// mount-id comparison alone, exactly as it did before this existed.
  pub(crate) root_incarnation: Option<crate::os::RootIncarnation>,
}

/// One row of the CENSUS: what an authoritative mount-table read observed, keyed
/// by the thing two successive reads may be diffed on.
///
/// # Identity is the key, the path is a hint
///
/// `/proc/self/mountinfo` renders every row's path by its own `seq_path_root`
/// call, and the namespace-generation bracket the read is taken inside certifies
/// the row's `(mnt_id, dev)` and nothing about its label — so the table is a
/// coherent source of mount IDENTITY and a best-effort source of mount LOCATION.
/// A set keyed by the label leaves #74 open with no torn read at all: a mount at
/// `R/a/x`, then `mv R/a R/b`, then a lazy unmount of `R/b/x`, derives its
/// departure at the stale `R/a/x` and never covers the ground revealed at
/// `R/b/x`.
///
/// So the key is the identity, and the location is carried as the COVER-LOCATION
/// hint — rebased when the core learns the directory it names was renamed
/// ([`rebase_moved`]) and lowered through [`mount_cover`], which degrades to the
/// whole root for a hint it cannot spell.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CensusRow {
  /// What identifies this row across two reads.
  key: Key,
  /// Where this read rendered it.
  location: PathBuf,
  /// The device mounted here, where the host answers one.
  dev: Option<u64>,
  /// The id of the mount this one hangs off, where the host answers one — the
  /// second half of the same-place REPLACEMENT test, and never a link to walk.
  ///
  /// A legacy mount id is allocated lowest-free, so an unmount and a mount
  /// inside one window hand the new mount the id the old one freed; if it also
  /// landed at the same location on the same device, the device comparison
  /// alone reads continuity. Its PARENT is another vfsmount unless it was
  /// mounted onto the very same one, so comparing both NARROWS that window.
  /// It does not close it — `STATX_MNT_ID_UNIQUE` (6.8) is what closes it — and
  /// narrowing costs at most a redundant cover.
  parent_id: Option<u64>,
}

/// What a census row is diffed ON — the mount's own id wherever the host answers
/// one, and its rendered location where none exists.
///
/// The two are never mixed for one row: a row HAS an id or it does not, so
/// `Location` is the honest degrade for a host whose table answers no ids at all
/// (macOS `getfsstat`, a fake) rather than a fallback within one read. A key
/// CHANGE at one location — `Location(L)` becoming `Id(x)` because a host started
/// answering ids — reads as a departure plus an arrival at the same `L`, which
/// the cover deduplication collapses into the single cover it is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
  /// The mount's own id, unique among live mounts.
  Id(u64),
  /// The rendered location, where the host answers no mount id. A same-path
  /// remount is then observable only through the row's device, and a mount that
  /// MOVES reads as one departure plus one arrival — the honest degrade, and
  /// still two covers.
  Location(PathBuf),
}

/// One boundary a SEAM observed, held only for as long as no census row speaks
/// for it.
///
/// # Why anything is held at all
///
/// [`crosses_mount_boundary`] fires on `device_boundary || mount_boundary`, so a
/// **btrfs subvolume** inside the root trips the DEVICE belt while carrying the
/// root's own mount id: it is not a vfsmount, it has no mountinfo row EVER, and
/// no read of the table will ever list it. A mount, by contrast, is listed by
/// every read — but only from the next one, so a seam that observed one closes
/// the window between the observation and that read.
///
/// Two obligations, one type, and the [`Standing`] decided at the seam is what
/// separates them: the mount half is a departure BELT the census takes over on
/// its first read, and the subvolume half is a boundary the census can never
/// speak for at all.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LedgerEntry {
  /// Where the boundary is — the cover-location hint, rebased on a rename
  /// exactly as a census row's is.
  location: PathBuf,
  /// What the seam's own two ids said this boundary is.
  ///
  /// The device the seam also read is deliberately NOT held. A census row is
  /// diffed on its device (that is the same-place replacement), but an entry is
  /// joined by ID or by the location a row stands at, and neither reads a device
  /// — so storing one would be a field nothing decides anything from.
  standing: Standing,
}

/// What a seam's own reading said a boundary IS — decided once, at the seam,
/// from the two ids it read, and never re-derived from a value some later
/// observation put in this scope's state.
///
/// # Why the seam decides and nothing re-decides
///
/// The predicate this replaced asked `mnt_id == root_mnt_id` on every read, over
/// a `root_mnt_id` that moves under a live scope (a same-object unmount + rebind
/// of the root is supported) — so every subvolume's record started reading
/// mount-backed at once, and a rebase pass existed solely to walk that back. Both
/// ids are read at the seam, against the frame in force there; a comparison of
/// two values from the same instant is a fact, and a fact does not need
/// maintaining.
///
/// The `None` trap the old birth-time verdict fell into was reading `None ==
/// None` as "not mount-backed". Here an unanswerable id is its own standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
  /// The seam read an id that DIFFERS from the root's: a vfsmount, observed
  /// before any census listed it. The census owns it from its next read — either
  /// by listing it (nothing owed) or by not listing it, which is the departure
  /// this entry is the belt for.
  Mount(u64),
  /// The seam read the ROOT's own mount id: a btrfs subvolume, or anything else
  /// on the root's own mount. No mountinfo row will ever list it, so it joins no
  /// census and is condemned by none; it leaves only by the event stream or by a
  /// complete generation.
  SameMount,
  /// One of the two ids was unanswerable — the whole of Linux 4.11–5.7, where
  /// `statx(STATX_MNT_ID)` does not exist, and any host whose frame could not be
  /// read. Nothing here can tell a genuine vfsmount from a same-mount subvolume,
  /// so the scope FAILS CLOSED while one is held
  /// ([`ScopeState::fails_closed`]) rather than guessing in either direction.
  Unknown,
}

impl Standing {
  /// What the seam's two ids decide, and the whole of the decision: two known
  /// ids that agree put the boundary on the root's own mount, two that disagree
  /// name another one, and an unanswerable half is its own answer.
  const fn decide(root_mnt_id: Option<u64>, mnt_id: Option<u64>) -> Self {
    match (root_mnt_id, mnt_id) {
      (Some(root), Some(mnt)) if root == mnt => Self::SameMount,
      (Some(_), Some(mnt)) => Self::Mount(mnt),
      _ => Self::Unknown,
    }
  }

  /// Whether no census will ever speak for this entry — the population only a
  /// complete generation can reconcile, and the one the retirement passes and
  /// [`ScopeState::holds_exempt_record`] are about.
  const fn is_exempt(self) -> bool {
    matches!(self, Self::SameMount | Self::Unknown)
  }
}

/// The census one authoritative read produces: one row per table row, keyed by
/// the row's own mount id where the host answers one and by its rendered location
/// where it does not.
///
/// A repeated KEY is dropped, keeping the FIRST. Ids are unique among live
/// mounts, so a repeated `Id` is a torn or malformed read and never a stacked
/// mount — and keeping it would put one mount in the census twice, where the
/// next diff would derive its arrival twice and its departure twice. Several
/// rows at one LOCATION are ordinary and all stay: a Linux stack lists one row
/// per member, each with its own id, and the id is what keys them apart.
fn census_of(rows: &[MountRow]) -> Vec<CensusRow> {
  let mut seen: BTreeSet<Key> = BTreeSet::new();
  rows
    .iter()
    .filter_map(|row| {
      let key = match row.mnt_id {
        Some(id) => Key::Id(id),
        None => Key::Location(row.location.clone()),
      };
      seen.insert(key.clone()).then(|| CensusRow {
        key,
        location: row.location.clone(),
        dev: row.dev,
        parent_id: row.parent_id,
      })
    })
    .collect()
}

/// Re-roots every location at-or-under `from` onto `to` — the rename repair, run
/// over the census and the ledger together.
///
/// A [`Key::Location`] key IS a location and moves with it; a [`Key::Id`] key is
/// absolute and does not. That asymmetry is the point: an id-keyed row survives a
/// rename as the same row with a new hint, while an id-less host's row is simply
/// a path and follows the path.
fn rebase_moved(location: &mut PathBuf, from: &Path, to: &Path) -> bool {
  let Ok(rest) = location.strip_prefix(from) else {
    return false;
  };
  *location = to.join(rest);
  true
}

/// One departure whose cover is PARKED on an outstanding admission round trip —
/// the fanotify half of the mount design, and the only place a cover this core
/// derived does not reach the Monitor in the same step.
///
/// # Why a cover ever waits
///
/// fanotify admits events by directory-handle membership and its seed walk stops
/// at a mount, so the ground a departed mount reveals has no handles in the map:
/// the source is blind to it, and there is no crawl to fix that
/// (`Monitor::start_rearm` refuses a non-descending scope outright). Emitting the
/// cover first would tell the consumer to re-read ground the source still cannot
/// see, and every mutation between that re-read and the eventual admission would
/// drop silently. So the cover waits for the map, which is why this exists at
/// all: the verdict is made here and the walk runs on the reader thread, so the
/// two are a round trip and the cover has to survive it.
///
/// # It carries a LOCATION, not a record
///
/// The verdict that parks it is a TRANSITION between two censuses, and a
/// transition is spent the moment it is derived: there is no record to hold and
/// nothing to put back. What the round trip still needs is the place the cover
/// must land, and one answer — [`StillCovered`](crate::os::AdmitOutcome::StillCovered)
/// — is a fresh SEAM observation of whatever is standing there, which enters the
/// ledger on its own terms through [`record_boundary`] like any other seam's.
///
/// That is what ended an indefinite storm the put-back it replaced produced. A
/// real mount ON TOP OF a btrfs subvolume departs; the walk re-opens the location
/// and finds the subvolume, whose id is the root's own; restoring the departed
/// mount's row over it made every later refresh find that row absent, condemn it
/// again, park again, and emit one cover per tick for the life of the scope.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingAdmit {
  /// The round trip this cover waits on.
  ticket: crate::os::AdmitTicket,
  /// Where the departure was derived — where the cover lands when the reply
  /// releases it. Rebased on a rename like every other hint
  /// ([`rebase_hints`](DriverCore::rebase_hints)), because the ground can move
  /// while the round trip is out.
  location: PathBuf,
  /// The scope's [`frame_epoch`](ScopeState::frame_epoch) when this was parked.
  /// A reply that comes back against a different one is answered by a whole-root
  /// recovery instead of on its own terms — see
  /// [`on_admitted`](DriverCore::on_admitted).
  epoch: u64,
}

/// The ONE whole-root recovery round trip a scope has out — the root-scope
/// sibling of [`PendingAdmit`], and held to the same rule: opened by the request,
/// discharged by an ANSWER that was applied, and by nothing else.
///
/// It parks no record and no located cover, because a recovery's reply carries the
/// whole root's cover itself. What it holds is what the two questions about an
/// unanswered recovery need: which tickets its reply would discharge, and which
/// world it was asked in. See [`ScopeState::pending_recovery`] for why the second
/// one is both the anti-spin latch and the retry trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingRecovery {
  /// The cutoff the reply must carry to discharge this round trip. Every ticket at
  /// or below it is answered by that one reply.
  ticket: crate::os::AdmitTicket,
  /// The scope's [`frame_epoch`](ScopeState::frame_epoch) when this was issued.
  /// The reply echoes it back, and the core applies nothing from a reply whose
  /// echo is no longer the scope's.
  epoch: u64,
}

/// The DISAGREEMENT one refused whole-root recovery was refused ON: the foreign
/// root its walk fenced against, and the frame this scope held while refusing it.
///
/// Retained for one question and no other — **has this scope already re-asked
/// under this exact disagreement?** — which is the question the suppression it
/// replaces used to answer by PREDICTION. "A fresh request would be answered by a
/// walk that reads the same root and is refused identically" is a claim about the
/// SOURCE's world, and the core holds no reading of that at all: what it holds is
/// one reply, evidence of where a walk stood at the moment it ran. A transient
/// same-object self-bind makes that reply describe a mount that is already gone
/// (the walk saw B; B departed; the root is back on the very mount object A it
/// started on, so both its legacy id and its unique incarnation token are
/// unchanged and no frame move can be observed) — and the prediction is then
/// exactly wrong: the fresh walk reopens the path, reads A, and is ACCEPTED.
///
/// So the retry is not predicted away. It is spent, once, and the refusal that
/// comes back from the request issued AFTERWARDS is the observation the
/// prediction wanted: two walks, the second raised in full knowledge of the first,
/// both fencing against the same foreign root while this scope held the same
/// frame. Only then does [`DriverCore::on_root_recovered`] stop arming its own
/// refresh on THIS leg — the edge that could otherwise turn the retry into a
/// self-driven loop (refusal arms a read, the read re-asks, the re-ask is refused).
/// What survives that is one recovery per REFRESH, which is the cost a
/// [`fails_closed`](ScopeState::fails_closed) scope already pays by design, not
/// one per scheduler round.
///
/// A DIFFERENT foreign root re-opens it, and that is not laxity: the source's
/// world demonstrably moved between the two walks, so the second reply is fresh
/// information rather than a repeat.
///
/// # It is only HALF the brake, and the other half is the need itself
///
/// This keys on a disagreement, so it reaches only the walked-id leg. An EPOCH
/// mismatch has no key at all — the epoch is what moved, so no two refusals can
/// ever share one — and the arming is itself what moves it. The arm is therefore
/// gated on [`owes_whole_root`](ScopeState::owes_whole_root) as well: while a round
/// trip stands in the world this scope still holds, nothing is owed a read, because
/// that reply carries the generation, the cutoff and the cover together. See the
/// module doc's bound/verdict rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RefusedWalk {
  /// The root mount id the refused walk fenced its descent against.
  walked: u64,
  /// The scope's [`frame_epoch`](ScopeState::frame_epoch) at the refusal.
  epoch: u64,
}

/// **What this scope holds about the last COMPLETE whole-root generation** — one
/// value, so no combination of its parts can be illegal.
///
/// It stands beside [`pending_recovery`](ScopeState::pending_recovery), which says
/// whether a round trip is OUTSTANDING and nothing else. The two answer different
/// questions — what the coverage set was last verified by, and whether a request is
/// in flight — so every element of their product is a legal state and neither has
/// to be reconciled against the other at a transition. What is NOT representable is
/// a refusal key held by a scope whose generation is verified, the one combination
/// no site may produce and that prose used to be all that forbade.
///
/// The whole value is written by two transitions
/// ([`generation_applied`](ScopeState::generation_applied),
/// [`generation_lost`](ScopeState::generation_lost)) and read by one predicate
/// ([`generation_stale`](ScopeState::generation_stale)) plus the one arm that asks
/// whether a disagreement has already been re-asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Generation {
  /// The coverage set was verified by a complete generation applied under
  /// `frame_epoch == epoch` — or seeded whole by a world swap's own barrier read,
  /// which is the same kind of evidence taken at the one moment the set is known
  /// to be complete.
  ///
  /// A WATERMARK, not a debt. It advances only where a generation was actually
  /// applied, and no site clears it or moves it forward on anything else. That is
  /// deliberate: a stored `recovery_owed` boolean — set at one site, read at
  /// another, lost by a third — is stranded by whichever transition nobody
  /// enumerated, and the answer is not one more clearing site but a fact no
  /// transition can falsify. The set was verified in world N; the scope is now in
  /// world M.
  ///
  /// What it makes derivable is [`generation_stale`](ScopeState::generation_stale):
  /// a scope holding boundaries the mount table cannot speak for, whose last
  /// complete generation was taken in a world it has since left, is owed another
  /// one — whether the previous one was refused, superseded, or never asked for at
  /// all.
  Verified {
    /// The [`frame_epoch`](ScopeState::frame_epoch) the generation was applied
    /// under.
    epoch: u64,
  },
  /// A complete generation was produced and NOT applied here: retained EVIDENCE,
  /// set where one is discarded and discharged by exactly one event — a generation
  /// landing.
  ///
  /// It is not an obligation flag wearing a new name. An obligation is decided by a
  /// transition and then has to be remembered and cleared, and every path that
  /// forgets either half strands it. This is a record of something that HAPPENED,
  /// held to the discipline [`pending_recovery`](ScopeState::pending_recovery)
  /// holds a round trip with: no site decides the need has passed, and the only way
  /// it clears is that the thing it asks for was done.
  ///
  /// # Why the derived half is not enough on its own
  ///
  /// [`generation_stale`](ScopeState::generation_stale)'s derivation asks whether
  /// the coverage set's EXEMPT partition was verified in a world this scope has
  /// left, and it can only read the records the set HOLDS. A rejected whole-root
  /// generation is precisely the message that could have carried the FIRST exempt
  /// record — a btrfs subvolume no mountinfo row lists — and its declines are
  /// dropped at the rejection, so the set holds none and
  /// [`holds_exempt_record`](ScopeState::holds_exempt_record) reads false. The need
  /// is then invisible to every derivation, and no later mount table can
  /// reconstruct it.
  ///
  /// The production window is a source adoption: the core's frame epoch has already
  /// moved while a freshly spawned reader's mailbox still starts at zero, so that
  /// reader's first autonomous generation is refused on the epoch before the first
  /// [`PublishFrame`](Effect::PublishFrame) reaches it — and the refresh that
  /// refusal arms reads the very same mount id, leaving the frame epoch equal to
  /// the birth watermark. Nothing else in the state says a generation was ever
  /// owed.
  Lost {
    /// The disagreement the last REQUESTED recovery was refused ON, or `None` where
    /// none has been — see [`RefusedWalk`] for why a refusal is SPENT once rather
    /// than predicted away.
    ///
    /// It lives HERE because a refusal always loses the generation and a generation
    /// landing clears both: the two facts have exactly one lifetime between them,
    /// and a key held beside a verified watermark would be a state no site may
    /// produce.
    ///
    /// Only the walked-id leg has a key. An EPOCH mismatch has none — the epoch is
    /// what moved, so no two refusals can ever share one — and the key decides one
    /// thing: whether [`on_root_recovered`](DriverCore::on_root_recovered)'s
    /// mismatch arm arms its own mount refresh. It never decides whether a recovery
    /// is OWED, which stays [`owes_whole_root`](ScopeState::owes_whole_root)'s and
    /// is derived from what this scope holds, so a stale key costs at most one
    /// self-armed table read and never a silence.
    refused: Option<RefusedWalk>,
  },
}

/// Why one mount refresh is being armed.
///
/// The two causes agree completely when nothing is in flight — both arm one
/// read. They differ ONLY in what they say about a refresh that IS in flight,
/// because they carry opposite evidence about its snapshot:
///
/// - an **invalidating** arming happened BECAUSE the world moved (a loss window,
///   a root replace or widen, a birth), so the in-flight read may have sampled
///   the far side of that transition — it is suspect, and
///   [`refresh_stale`](ScopeState::refresh_stale) condemns it.
/// - a **periodic** arming is pure cadence: nothing happened. The in-flight
///   snapshot is exactly as good as the one this tick would take, so the tick
///   coalesces onto it and lets it PUBLISH.
///
/// Conflating the two starves everything that publishes past
/// [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed)'s stale gate — the
/// mount-table install, the frame adoption, and the departure diff. With refresh
/// latency at or past the interval (a backed-up blocking pool, or simply a short
/// interval — any nonzero duration is configurable), a tick that stale-marked
/// would condemn EVERY completion in turn: each is discarded and re-armed, and
/// the next tick condemns the next read. The root-death check survives that only
/// because it is evaluated BEFORE the gate; the departure diff sits behind it,
/// so the silence #74 exists to break would never be broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshCause {
  /// The world moved under the in-flight read: a loss signal, a root replace or
  /// widen, or the birth arming. Condemns an outstanding snapshot.
  Invalidating,
  /// The periodic tick came due. Coalesces onto an outstanding read without
  /// condemning it — and without ever CLEARING a condemnation an invalidating
  /// arming already made.
  Periodic,
}

/// One I/O obligation the driver task must execute for the core.
#[derive(Debug)]
pub(crate) enum Effect {
  /// Start the native source watching `root` for `scope`.
  SpawnStream {
    /// The scope the stream will feed.
    scope: ScopeId,
    /// The root path as the consumer supplied it.
    root: PathBuf,
  },
  /// Quiesce and destroy `scope`'s native source.
  TeardownStream {
    /// The scope whose stream is torn down.
    scope: ScopeId,
  },
  /// `lstat` one path and feed the outcome back under `probe`.
  Probe {
    /// The correlation id the result must echo.
    probe: ProbeId,
    /// The absolute path to stat.
    path: PathBuf,
  },
  /// Deliver one change to the consumer, reporting the delivery outcome back
  /// through [`on_delivery`](DriverCore::on_delivery).
  Emit {
    /// The scope the change belongs to.
    scope: ScopeId,
    /// The canonical root the change's location is relative to. Deliveries
    /// carry their own root so consumer-side assembly never depends on a
    /// registry entry — a dead scope's trailing changes (above all its
    /// terminal `Rescan`) still assemble after the scope is reclaimed.
    root: Arc<PathBuf>,
    /// The change to deliver.
    change: Change,
  },
  /// Install a kernel watch for one directory the Monitor descended into,
  /// reporting the outcome through
  /// [`on_watch_installed`](DriverCore::on_watch_installed).
  AddWatch {
    /// The scope whose live source executes the arm.
    scope: ScopeId,
    /// The Monitor watch being armed.
    watch: WatchId,
    /// The arm ATTEMPT this effect executes, echoed back with its outcome. A
    /// `WatchId` outlives its bindings — a root keeps it across a rebind — so
    /// only the attempt distinguishes this arm's verdict from that of one a
    /// later arm has already superseded.
    attempt: ArmAttempt,
    /// The already-armed parent watch (its anchor roots the open).
    parent: WatchId,
    /// The child's name under the parent.
    name: Segment,
    /// The child's absolute path — the parent's path joined with the name;
    /// executors and fakes address the object by it.
    path: Arc<PathBuf>,
    /// The `(dev, ino)` the enumerate (or the root's barrier) read for this
    /// object, when known. The executor opens the target by path/anchor and must
    /// confirm the opened object matches this before installing the watch — a
    /// rename between the enumerate and the arm would otherwise install the watch
    /// on a different object while the Monitor keeps the stale identity. `None`
    /// leaves the arm unverified (identity was unavailable — a foreign-device or
    /// unrepresentable entry), exactly as the Monitor already reconciles.
    expected: Option<ExpectedObject>,
    /// The scope's descent frame at the moment the arm was issued. The executor
    /// stats the object it opened and REFUSES the arm when the landing sits
    /// across this frame ([`ScopeFrame::crossed_by`]) — the prevention half of
    /// the mount-boundary design, and the only one that runs on an arm the
    /// enumerate fence never saw.
    ///
    /// Not the same guard as [`expected`](Self::AddWatch::expected), and it must
    /// not be folded into it: `expected` is `None` for exactly the arms that
    /// need this most (inotify's `Created` carries no identity), so a frame
    /// check gated on a known object would be gated off precisely where the
    /// boundary gets crossed.
    frame: ScopeFrame,
  },
  /// Remove one per-directory kernel watch the Monitor dropped. Fire-and-
  /// forget: the Monitor's unwatch carries no result contract, and a wd the
  /// removal never reached is reclaimed when the scope's stream closes.
  RemoveWatch {
    /// The scope whose live source executes the disarm.
    scope: ScopeId,
    /// The Monitor watch being disarmed.
    watch: WatchId,
  },
  /// Read one directory (blocking readdir + per-entry stat), reporting the
  /// raw listing through [`on_enumerated`](DriverCore::on_enumerated).
  Enumerate {
    /// The correlation id the result must echo.
    req: ReqId,
    /// The directory's watch.
    watch: WatchId,
    /// The directory's absolute path.
    path: Arc<PathBuf>,
  },
  /// Re-read the live mount table strictly under `root` (blocking) and feed
  /// the result back through
  /// [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed): a loss signal
  /// may have swallowed a mount transition, so the table's authority is
  /// revoked until this fresh read installs.
  RefreshMounts {
    /// The scope whose device-trust table went stale.
    scope: ScopeId,
    /// The canonical root to enumerate mounts under.
    root: Arc<PathBuf>,
  },
  /// Ask `scope`'s live source to ADMIT the ground a departed mount revealed,
  /// reporting the outcome back through
  /// [`on_admitted`](DriverCore::on_admitted).
  ///
  /// The one effect whose whole purpose is to make the consumer WAIT. A departed
  /// mount's cover is parked on each of these round trips and emitted only when the
  /// answer lands, because a membership-admitting source (fanotify) is blind to the
  /// revealed ground until its map learns it: cover first and the consumer's
  /// re-read races ahead of admission, so every mutation in between drops on an
  /// unknown handle with no loss signal at all.
  ///
  /// The driver routes it to the scope's source handle. A scope with no live
  /// handle — or a reader thread already gone — resolves every round trip in it
  /// [`Unreachable`](crate::os::AdmitOutcome::Unreachable) inline, so no parked
  /// cover is left waiting on a reply that cannot come.
  ///
  /// # One BURST, indivisibly
  ///
  /// It carries the whole run of round trips ONE departure verdict opened, not one
  /// of them, and the driver hands that run to the source under a single mailbox
  /// post. A refresh can condemn many boundaries at once, and a source that could
  /// observe a PREFIX of the burst would snapshot that prefix into a whole-root
  /// recovery and take the remainder — arriving while that recovery's walk ran —
  /// as a SECOND obligation, buying a second whole-root walk and a second report.
  /// The boundary budget's supported floor is one permit, held until the driver
  /// consumes the message, so the second report claims nothing and kills a source
  /// that had nothing wrong with it. Publishing the burst whole is what makes the
  /// reader's own fold ("a burst costs one walk") reachable at all.
  AdmitBoundaries {
    /// The scope whose source owns the admission map.
    scope: ScopeId,
    /// Every round trip this burst opens, in ticket order — each with the revealed
    /// location its walk re-opens, the scope's descent frame at the moment the
    /// departure was PARKED, and the scope's
    /// [`frame_epoch`](ScopeState::frame_epoch) at that same moment.
    ///
    /// The walk re-opens the location and refuses the reseed when the object it
    /// pinned sits across the ROOT's frame — a location still covered, or
    /// re-covered since the refresh read the table — reading that root frame live
    /// rather than taking the carried one, and refusing the request outright when
    /// the two disagree (see
    /// [`AdmitRequest::frame`](crate::os::AdmitRequest::frame)). The epoch rides so
    /// a whole-root recovery that COLLAPSES a request can be stamped with it (see
    /// [`AdmitRequest::epoch`](crate::os::AdmitRequest::epoch)).
    requests: Vec<crate::os::AdmitRequest>,
  },
  /// Publish `scope`'s current [`frame_epoch`](ScopeState::frame_epoch) to its
  /// live source.
  ///
  /// The one effect that opens no round trip and expects no answer. It exists so a
  /// source that produces a whole-root generation WITHOUT being asked — fanotify's
  /// post-loss reseed — can stamp that generation with a core-owned, monotone,
  /// never-recycled count of worlds rather than with a mount id the kernel
  /// re-issues lowest-free (see [`WalkReach::WholeRoot`](crate::os::WalkReach)).
  ///
  /// Emitted on every non-stale mount refresh rather than only on a frame CHANGE,
  /// so a source spawned into a scope whose epoch has already moved is seeded by
  /// that scope's next refresh instead of stamping a world it was never told about.
  /// A scope with no live handle simply drops it: a source that is not there
  /// produces no generation to stamp.
  PublishFrame {
    /// The scope whose source is being told.
    scope: ScopeId,
    /// The count of worlds this scope has adopted, as of now.
    epoch: u64,
  },
  /// Ask `scope`'s live source for ONE WHOLE-ROOT recovery: reseed the entire
  /// admission map from the root, report the complete generation the walk
  /// produces, and answer with the cover — reported back through
  /// [`on_root_recovered`](DriverCore::on_root_recovered).
  ///
  /// The root-scope form of [`AdmitBoundaries`](Self::AdmitBoundaries), emitted
  /// where no located answer will do: the scope FAILS CLOSED (it holds a record
  /// whose identity cannot say whether its boundary is still there), a departure
  /// burst past [`MAX_PENDING_ADMITS`] collapsed, or the scope's own state says one
  /// is still owed ([`ScopeState::owes_whole_root`]). It carries no location and no
  /// frame because it addresses the root itself, which is on its own frame by
  /// construction.
  ///
  /// The ticket is what makes it a CUTOFF rather than one more round trip: it is
  /// minted from the same monotone counter, so every admission this scope opened
  /// before it is subsumed and discharged by the one reply.
  ///
  /// A scope with no live handle resolves it inline through
  /// [`on_recovery_unreachable`](DriverCore::on_recovery_unreachable) — the root
  /// cover is emitted on the refresh's verdict alone, with no reseed behind it,
  /// exactly as an unreachable admission degrades.
  RecoverRoot {
    /// The scope whose source owns the admission map.
    scope: ScopeId,
    /// The cutoff this recovery discharges and the frame epoch it is issued at —
    /// the latter echoed back on the reply, which the core applies only while the
    /// epoch is still its own ([`RootRecovery::epoch`](crate::os::RootRecovery)).
    request: crate::os::RecoveryRequest,
  },
}

/// The outcome of one attempted [`Effect::Emit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
  /// The consumer channel accepted the change.
  Accepted,
  /// The consumer channel was full; the change was not delivered.
  Refused,
}

/// Correlates one parked set-cover acknowledgement with its settlement: the
/// driver opens a fence via [`open_cover_fence`](DriverCore::open_cover_fence)
/// when an acked reconcile starts, and
/// [`poll_cover_settlements`](DriverCore::poll_cover_settlements) reports each
/// fence's [`CoverSettle`] once its scope's re-arm work quiesces. Minted from a
/// monotone counter, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FenceId(u64);

/// How [`on_set_cover`](DriverCore::on_set_cover) disposed of one requested
/// cover reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverReconcile {
  /// The prune/grow walk ran. The scope may now hold re-arm work; a caller
  /// that owes an acknowledgement opens a fence
  /// ([`open_cover_fence`](DriverCore::open_cover_fence)) that resolves when
  /// [`Monitor::rearm_settled`] next holds for the scope.
  Reconciling,
  /// No reconcile ran; the reason tells the driver what to answer immediately.
  Noop(CoverNoop),
}

/// Why [`on_set_cover`](DriverCore::on_set_cover) refused to reconcile — each
/// reason maps to an immediate (never-fenced) driver answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverNoop {
  /// The scope is not registered.
  UnknownScope,
  /// The scope is not publicly live: between its spawn and the root-arm grant
  /// (or root-less before spawn) no caller holds a handle, so there is no
  /// coverage CLAIM to reconcile — the registration's own crawl is still
  /// installing the scope's whole coverage, and a reconcile over it would prune
  /// or re-issue ground the grant has not handed anyone. Refused outright; the
  /// caller's cover is re-issued once the grant commits (the umbrella only ever
  /// covers committed watches, so only the re-publicized API can reach this).
  ///
  /// This clause once carried a second, sharper reason: a pre-grant grow would
  /// mark the root's pending COLD arm as a re-arm and so suppress the initial
  /// inventory's `Created`s. That harm did not go away — it became the DESIGN.
  /// A registration births its root re-arm-flavored deliberately, because the
  /// contract reports no inventory for state that merely pre-existed the grant,
  /// and the window is marked so the suppression is never silent. The refusal
  /// therefore rests on the claim argument alone; the retired reason is recorded
  /// rather than dropped, because the clause reads vestigial without it.
  NotLive,
  /// The scope's backend is kernel-recursive: one whole-subtree stream is the
  /// coverage, which never narrowed, so there is nothing to prune or re-arm.
  /// Explicit rather than a silent walk-of-nothing, so the driver can answer
  /// "coverage was never reduced" instead of "applied".
  KernelRecursive,
  /// The retained cover was refused: empty, or entirely outside the live root
  /// (a caller typo / relative / stale path) — acting on either would prune
  /// the whole scope. Prior coverage and `applied_cover` stay untouched.
  RefusedCover,
}

/// How one settled set-cover fence reports its window.
///
/// # What a clean settle certifies, and what it cannot
///
/// [`Applied`](Self::Applied) is an IRREVERSIBLE claim about remote
/// asynchronous state, so its exact reach is worth stating. Three surfaces ride
/// it and are uncorrectable once it is reported: the acknowledgement itself
/// (its oneshot has one constructor and no retraction), the settle-fenced
/// cookie dispatch's pre-write contract ("a covering `Rescan` rides the queue
/// ahead of this cookie"), and the settle-floor promotion the clean verdict
/// performs (`settle_floor := applied_cover`, the claim a later lossy settle
/// rewinds to). What is NOT at stake is the end-to-end sync verdict: a
/// `Delivered` cannot be falsely certified through a settle, because the
/// cookie's own event travels the scope's single ordered lane behind any loss
/// that preceded its write, and the umbrella's two loss clocks (the per-sub
/// serial and the shared generation snapshotted before the install) resolve
/// every such race `Dominated`.
///
/// Certification over remote state always leaves a final
/// [observation, certify] instant, so the guarantee is stated against the
/// window's PROOFS: a fence settles `Applied` only when every counted proof
/// its window rests on postdates every loss the kernel had committed by that
/// proof's execution. A loss committed after those proofs is observed at its
/// own ingest, which marks pending fences lossy, degrades the claim and the
/// floor, and re-proves the scope before any later settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverSettle {
  /// The reconcile's re-arm work quiesced with no loss signal in the window:
  /// every re-armed watch is live, so writes under the retained cover from
  /// this moment are delivered.
  Applied,
  /// The reconcile settled, but the window was lossy — a covering `Rescan`
  /// passed, a grow kickoff coalesced into an in-flight cold read, or an
  /// unanswered classification stat stands the scope's settlement loss.
  /// Coverage may be partial; a covering `Rescan` dominating the gap has been
  /// EMITTED.
  ///
  /// Emitted, and no more than that: this verdict is not a delivery receipt, and
  /// the caller RE-ENUMERATES the retained cover rather than waiting for the
  /// instruction to arrive. A full consumer channel refuses the offer and parks
  /// it (INV-PARK) to be retried behind this answer. A verdict minted on the
  /// CLOSING pass is weaker again — the core is dropped with its effects still
  /// queued, and the one loss source whose cover only a settlement can stand
  /// gets none there at all — which is exactly why the caller re-enumerates
  /// instead. Making the answer wait for the delivery would put a caller's own
  /// reply behind that caller draining its event stream.
  ///
  /// All three sources carry a cover into the verdict. The first IS the
  /// `Rescan`. The second holds the barrier down
  /// ([`Monitor::coverage_settled`](tributary_proto::Monitor::coverage_settled))
  /// until the coalesced read completes, and that completion escalates into one.
  /// The third is the only loss that stands none of its own — the read that
  /// queued the stat reconciled nothing for the slot, and a pure grow stands no
  /// `Rescan` at all — so a LIVE settle observation stands a scope-level one and
  /// holds the tranche for the single flush that offers it, which is the same
  /// best-effort ordering the other two already have (see
  /// [`poll_cover_settlements`](DriverCore::poll_cover_settlements)). The close
  /// pass stands none: no flush follows it.
  Degraded,
  /// The scope died under this fence: the teardown fold resolved it and there
  /// is no stream left to report anything on.
  ///
  /// Minted at the single place death is known SYNCHRONOUSLY — the teardown
  /// fold — so the fact travels with the verdict. A consumer that must not act
  /// on a dead scope reads it here instead of re-deriving it from driver maps
  /// that only a later `TeardownStream` execution clears, which is what let a
  /// parked barrier be answered over a scope that was already gone.
  ///
  /// Weaker than [`Degraded`](Self::Degraded) for any caller that only asks
  /// "was coverage complete" — both answer no — so the public
  /// `set_cover` outcome maps it to `Degraded` and is unchanged by its
  /// introduction.
  Dead,
}

/// Which boundary a [`poll_cover_settlements`](DriverCore::poll_cover_settlements)
/// pass speaks for, and therefore which verdicts it is entitled to mint.
///
/// # The residue rule
///
/// A live pass runs behind a source drain bounded by a per-lane snapshot, and
/// that drain can legitimately end with counted items still resident: the
/// merged fan-in may answer `Pending` while a ready item exists. The scopes
/// whose own lane still holds such items ride here, and for each of them this
/// pass mints NOTHING — not a clean verdict and not a lossy one.
///
/// Withholding the LOSSY verdict too is the part worth stating, because a
/// degraded verdict is not falsifiable by more loss. It is falsifiable by
/// DEATH: an unread terminal `Fatal` sitting in exactly those counted items
/// has not yet folded the scope's fence to [`Dead`](CoverSettle::Dead), so a
/// [`Degraded`](CoverSettle::Degraded) minted over it ANSWERS a caller —
/// dispatching its parked cookie write on a stream that is already gone, the
/// successful-but-unsatisfiable barrier `Dead` exists to refuse. So the rule
/// is by scope, not by verdict: while a scope's own lane holds counted-but-
/// unconsumed items, no settlement that answers a caller may resolve for it.
///
/// The residue set is per SCOPE rather than one global flag because the items
/// are per lane: a busy scope's backlog says nothing about another scope's
/// window, and coupling them would defer an unrelated fence for as long as the
/// neighbour keeps producing.
///
/// # Liveness
///
/// The deferral cannot outlive the residue that caused it. The snapshot is
/// retaken every pass, so a scope whose lane drains spends immediately and
/// resolves on the next one; and if the residue IS the terminal `Fatal`,
/// ingesting it folds the fence to `Dead`, which resolves through the already-
/// settled path this gate never touches. Either way the next pass answers.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SettlePass<'a> {
  /// The driver's live loop top: verdicts are minted against streams that are
  /// still running, so a clean window may certify — except for the scopes in
  /// `unspent`, whose settled fences are all held over to a later pass.
  Live {
    /// Scopes whose current delivery lane still holds items this pass's source
    /// snapshot counted but its drain did not ingest.
    unspent: &'a BTreeSet<ScopeId>,
  },
  /// The driver's close drain: every stream has been torn down, so there is
  /// nothing left to certify a clean window against and the boundary withholds
  /// that verdict. Nothing may be DEFERRED here, though — this is the last
  /// pass there will ever be, and a held-over fence would strand its caller's
  /// reply forever — so a lossy window still reports its honest verdict, and
  /// owes no ordering proof to do it (see [`Self::owes_cut_proof`]).
  Closing,
}

impl SettlePass<'_> {
  /// Whether this pass may mint a clean certificate at all.
  const fn certifies_clean(self) -> bool {
    matches!(self, Self::Live { .. })
  }

  /// Whether a verdict minted here is acted on against a LIVE stream, and so
  /// rests on the ordering proof every live verdict owes (see [`CutProof`]).
  ///
  /// Only the loop-top pass does. By the close drain every stream has already
  /// been torn down: no reader is left to cut a kernel queue and answer the
  /// batch that would mint a proof, and no verdict this pass reports can reach
  /// a stream — the close drain dispatches no cookie and answers a parked one
  /// with its pre-physical terminal. So the proof is both unobtainable and
  /// unnecessary here, and demanding it would do the one thing the last pass may
  /// not: park a caller's reply on a round trip that can never complete.
  const fn owes_cut_proof(self) -> bool {
    matches!(self, Self::Live { .. })
  }

  /// Whether this pass may stand the cover a standing stat loss owes and hold a
  /// licensed tranche for the ONE flush that offers it, so the instruction is
  /// offered before the verdict it covers answers a caller.
  ///
  /// Only the live loop may, and the hold it takes is bounded by the DRIVER: the
  /// driver re-tops on it ([`take_cover_flush_due`](DriverCore::take_cover_flush_due)),
  /// the loop-top flush offers the cover, and the very next observation resolves —
  /// whether that offer was accepted or refused. Nothing here waits on consumer
  /// progress, which a `Degraded` verdict does not promise.
  ///
  /// The close drain neither stands a cover nor holds. It is the last pass there
  /// will ever be, so a held fence would strand its caller's reply forever, and
  /// there is no flush left to carry an instruction anywhere — the drained items'
  /// effects die with the core. It reports the lossy verdict where it stands, and
  /// the caller re-enumerates on it exactly as the contract says.
  const fn orders_stat_cover(self) -> bool {
    matches!(self, Self::Live { .. })
  }

  /// Whether `scope`'s settled fences are held over rather than resolved —
  /// true only for a live pass's unspent scopes, never at close.
  fn withholds(self, scope: ScopeId) -> bool {
    match self {
      Self::Live { unspent } => unspent.contains(&scope),
      Self::Closing => false,
    }
  }
}

/// Whether the covering `Rescan` a standing stat loss owes one tranche has been
/// stood yet.
///
/// A [`Degraded`](CoverSettle::Degraded) verdict reports that such a `Rescan` was
/// EMITTED, never that the consumer has taken it: the loop-top `try_send` refuses
/// it whenever the channel is full, which parks it as the scope's dominating
/// instruction (INV-PARK), and the caller re-enumerates rather than waiting for
/// it. So the latch records the one fact the verdict rests on — the cover was
/// stood — and nothing about the delivery it does not promise.
///
/// What it still buys is ORDERING, best-effort and bounded by the driver alone:
/// the tranche is held for exactly the ONE re-top whose flush offers the cover
/// ([`take_cover_flush_due`](DriverCore::take_cover_flush_due)), so a consumer
/// with room is instructed before the verdict — exactly as it is for every other
/// `Degraded` producer, whose covers are queued by an earlier pass and flushed at
/// this pass's loop top. A consumer without room is not waited for: the cover is
/// parked (or folded into the instruction already parked) and rides the lane's
/// own delivery retry, behind the verdict.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum StatCover {
  /// No cover has been stood for this tranche.
  #[default]
  Unstood,
  /// Stood: the tranche is held for the single flush that follows and resolves
  /// at the next observation, whatever that flush did with it — accepted,
  /// refused and parked, or (where the lane was ALREADY lagging) folded into the
  /// scope's parked dominating `Rescan` and never separately offered at all.
  ///
  /// Preserved across a PROOF INVALIDATION, which defers the tranche with its
  /// entry — and so this state — intact, so a deferred tranche re-instructs
  /// nobody.
  Stood,
}

/// One scope's pending set-cover fence bookkeeping.
///
/// # The lossy-window rule
///
/// `lossy` is the scope's loss memory since its last settle **observation**
/// (the [`poll_cover_settlements`](DriverCore::poll_cover_settlements) call
/// that found the scope settled and cleared this entry). It is set by
///
/// - any public scope `Rescan` passing [`route_event`](DriverCore::route_event)
///   — which ENSURES the entry, creating it when none exists, so the memory is
///   scope-persistent rather than fence-scoped: a loss landing OUT of any
///   reconcile window (after a clean settle, before the next `on_set_cover`)
///   is still remembered until the next settle observation, and the same
///   `Rescan` immediately degrades a narrowed `applied_cover` claim to the
///   empty cover (see [`ScopeState::applied_cover`]); and
/// - any reconcile whose grow observed a [`RearmKickoff::Coalesced`] — the
///   obligation rides an in-flight COLD read the settle counter deliberately
///   does not see, so the scope can read settled while the obligation is
///   latent (lossy **from birth**, per the fence design's F0 amendment).
///
/// A third source is a standing CONDITION rather than an event, so it is read
/// at the settle observation instead of being remembered here: an unanswered
/// classification stat that stands the scope's settlement loss
/// ([`Monitor::stat_loss_outstanding`], read in
/// [`poll_cover_settlements`](DriverCore::poll_cover_settlements)). An event
/// mark would be spent by the first observation to pass while the slot stayed
/// dark, so the condition is re-read every time a verdict is minted.
///
/// It is also the one source that arrives with NO cover of its own — the two
/// events above are (or produce) the `Rescan` that marks them — so the
/// observation that reads it stands one, and holds the tranche for the single
/// flush that offers it ([`stat_cover`](CoverFence::stat_cover)).
///
/// Either event marks every currently-pending fence lossy AND is remembered
/// here until the scope next settles, so a fence opened AFTER the event but
/// BEFORE that settle inherits it — a reply-less reconcile
/// (`request_set_cover`) that coalesced still degrades the fence the driver
/// opens for a later acked reconcile of the same window, and the first
/// reconcile issued after an out-of-window loss degrades honestly (its re-arm
/// work is re-attempted against the degraded claim; a second clean re-issue
/// then applies). The settle observation clears the memory with the fences —
/// a pending-empty entry created by an out-of-window `Rescan` included — so
/// nothing leaks onto a fence opened after it. A corollary: every fence
/// resolving at one settle reports the same verdict — lossiness only accretes
/// between settles, an opening fence inherits the accreted state, and a loss
/// marks all pending — which is the honest shape: covers applied within one
/// unsettled window ride each other's re-arm work, so none of them can claim
/// a cleaner window than the scope's.
///
/// # The tranche rule
///
/// One ordering proof does not necessarily speak for every fence the entry
/// holds: it licenses only those that were already open when it was requested
/// (see [`CutProof`]). Fences therefore carry the ordinal they were opened at,
/// and because they are held in open order the ones a proof licenses are always
/// a PREFIX of the list. A settle observation resolves that prefix and leaves
/// the rest pending, with their accrued lossiness intact, to be offered a
/// successor proof.
///
/// The entry itself — the scope's loss memory, and the applied-cover repair
/// that rides its removal — is spent only when the LAST pending fence goes. A
/// claim is never promoted over a stretch of the window no proof has ordered
/// yet, and the loss memory a straggler may still need is never cleared out
/// from under it.
///
/// [`RearmKickoff::Coalesced`]: tributary_proto::RearmKickoff::Coalesced
#[derive(Debug, Default)]
struct CoverFence {
  /// Pending fences in open (FIFO) order, so their ordinals ascend and the
  /// fences one proof licenses are a prefix.
  pending: Vec<PendingFence>,
  /// The scope's loss memory since the last settle observation (see the
  /// lossy-window rule above).
  lossy: bool,
  /// Whether the covering `Rescan` a standing stat loss owes has been stood for
  /// the tranche this entry is about to resolve
  /// ([`Monitor::cover_stat_loss`](tributary_proto::Monitor::cover_stat_loss)).
  ///
  /// The latch is what makes the one-flush ordering stand exactly ONE cover per
  /// tranche: it leaves [`Unstood`](StatCover::Unstood) when the cover is stood,
  /// is reset when the tranche is drained, and goes with the entry when the last
  /// pending fence does. Without it a scope whose stat never answers would stand
  /// a fresh cover on every pass and never report the degraded verdict the
  /// standing loss exists to produce; with it a later tranche — resolving under
  /// its own successor proof, over a stretch of the window the earlier cover does
  /// not reach — still stands one of its own.
  stat_cover: StatCover,
  /// Open ordinals minted for this entry so far. Per entry, which is the only
  /// scale the tranche rule compares at: a proof's mark lives on this same
  /// entry and dies with it.
  opened: u64,
  /// How far a clean verdict is licensed, and what is out to license the rest —
  /// see [`CutProof`].
  cut: CutProof,
}

/// One fence awaiting its scope's settle.
#[derive(Debug, Clone, Copy)]
struct PendingFence {
  /// The id the driver parked this caller's reply under.
  fence: FenceId,
  /// Whether this fence's window has taken loss — inherited from the entry's
  /// memory at open, then set by every later loss event.
  lossy: bool,
  /// Where this fence sits in its entry's open order, counted from one. An
  /// ordering proof licenses exactly the fences it reaches (see [`CutProof`]).
  opened: u64,
}

impl CoverFence {
  /// Records `fence` as pending: it takes the next open ordinal and inherits
  /// the loss memory the scope has accrued since its last settle observation.
  fn open(&mut self, fence: FenceId) {
    self.opened += 1;
    self.pending.push(PendingFence {
      fence,
      lossy: self.lossy,
      opened: self.opened,
    });
  }

  /// Records one loss event: remembered until the next settle observation and
  /// stamped onto every pending fence.
  fn mark_lossy(&mut self) {
    self.lossy = true;
    for pending in &mut self.pending {
      pending.lossy = true;
    }
  }

  /// The newest pending fence's ordinal — the mark a proof must reach to
  /// license this entry's whole pending set.
  ///
  /// Zero when nothing is pending. Such an entry still owes a proof before its
  /// settle observation may repair the applied-cover claim, but it has no fence
  /// to exclude, so any proof taken under the current epoch reaches it.
  fn high_water(&self) -> u64 {
    self.pending.last().map_or(0, |pending| pending.opened)
  }
}

/// Whether this fence has forced the source to surface what the kernel already
/// holds, which is what a CLEAN verdict rests on.
///
/// The barrier's counted work — arms, re-arms, enumerates — proves the coverage
/// was rebuilt. It does NOT prove the kernel had nothing queued while that
/// happened: an enumerate completes on the blocking pool and never crosses the
/// reader, and a re-issued or pruning cover can settle with no counted work at
/// all. In both cases the settle-edge drain sees only what the reader has
/// ALREADY forwarded, so a record the kernel committed but nobody has read yet
/// sits in no lane and the drain reads trivially spent.
///
/// One empty control batch closes that: the reader cuts its kernel queue onto
/// the lane before answering ANY batch, so the reply is an ordering proof —
/// whatever the kernel held is ingested ahead of it.
///
/// # What one proof licenses
///
/// A proof speaks for the WINDOW AS IT STOOD WHEN THE REQUEST WAS MADE — not
/// for all time and not for the scope at large — so it licenses a clean verdict
/// on one condition, read along both axes that window has:
///
/// **A proof licenses a fence iff the fence was already pending when the proof
/// was requested AND the scope has acquired no coverage work since.**
///
/// The two halves are the same statement about the same instant. The request
/// records the scope's coverage-work epoch ([`Monitor::coverage_work_epoch`])
/// and the open ordinal of the newest fence then pending — one [`CutMark`] —
/// and the reply's proof inherits it whole. Work acquired afterwards moves the
/// epoch and voids the proof outright; a fence opened afterwards takes a higher
/// ordinal and is simply not among those it speaks for — the earlier fences it
/// genuinely ordered keep it. Neither half is a special case of the other: work
/// can be acquired with no fence opening, and a fence can open with no work
/// acquired at all.
///
/// Both are checked against the scope AS IT READS NOW rather than against a
/// list of events that invalidate a proof, which is what makes the rule total:
/// nothing has to hunt down the marks a scope holds when its epoch moves,
/// because a mark stamped under a departed epoch licenses nothing wherever it
/// sits, and an epoch never returns.
///
/// # A request is not a proof
///
/// A request and the proof it will mint are therefore kept apart, and the entry
/// holds both at once: the PROVEN PREFIX — the strongest mark a completed cut
/// has earned, which is the only thing that licenses a verdict — and the
/// SUCCESSOR IN FLIGHT, the request out for the fences that prefix does not
/// reach. Latching a successor records that a request exists and nothing more:
/// authority already earned is not evidence about a window still being ordered,
/// so it can neither be spent by one nor lowered by one. A completed request
/// retires into the prefix and only ever moves it forward — across an epoch its
/// mark replaces the prefix outright, since carrying an older stamp's reach onto
/// a newer one would claim an ordering that cut never took, and within one epoch
/// the further reach wins.
///
/// Holding one slot for both would confuse a claim with an answer, and the
/// driver's loop makes that fatal rather than merely lossy: it latches the
/// successors it is offered ABOVE the settlement it resolves below, so a window
/// taking one new fence per round would have every successor erase the proof
/// that had just landed for its predecessors, and no fence would ever resolve.
///
/// # Why a binding and not a list
///
/// The barrier ([`Monitor::coverage_settled`]) is a conjunction over several
/// kinds of coverage work, each of them "the scope holds none of this". So it
/// can go settled → unsettled → settled again through work the proof knows
/// nothing about: a proven cut forwards a `MovedFrom` whose held-source
/// obligation is created only when the settle-edge drain ingests it, and a
/// paired `MovedTo` then releases the hold. An overflow the kernel committed
/// after the cut can still be sitting unread across that whole round, and a
/// proof kept valid through it would certify exactly the record it existed to
/// surface. Enumerating such edges cannot be made to hold: the enumeration is
/// complete only until the barrier grows another conjunct.
///
/// So the proof carries the scope's coverage-work epoch
/// ([`Monitor::coverage_work_epoch`]) — a counter that advances whenever the
/// scope acquires work ANY conjunct counts — and licenses a clean verdict only
/// while the scope still reads that epoch. Since a conjunct can only turn from
/// settled to unsettled by acquiring work, an unchanged epoch means the window
/// the cut ordered was never re-opened, for every conjunct at once.
///
/// # Convergence
///
/// A scope that keeps acquiring work keeps invalidating proofs, which costs
/// nothing: it is not settled, so it is offered no fence and asked for no
/// proof. The epoch does NOT move on a release, so a scope that settles and
/// then stays settled holds it fixed, and the next proof taken over it survives
/// to certify. Progress therefore needs only quiescence, not quiet.
///
/// The ordinal converges for a reason of its own, and it is why a request
/// already in flight is never displaced by a fence opened behind it: every
/// request licenses every fence pending at the instant it was latched, so each
/// completed proof resolves at least the whole tranche that was waiting when it
/// left, and the fences that joined behind it are offered a successor the
/// moment it lands ([`covers_awaiting_cut`](DriverCore::covers_awaiting_cut)
/// compares the proven prefix's reach against the newest pending ordinal).
/// Arrival rate therefore cannot outrun resolution: a fence waits on the first
/// request latched after it opened, and on no more than one round trip beyond
/// the one already out.
///
/// # What the epoch does not cover
///
/// A reconcile whose prune drops a watch subtree MOVES coverage without
/// acquiring any: a drop only releases work, so no funnel bumps the epoch, yet
/// the window is no longer the one the proof was taken over. That one discards
/// the latch at its own site — proven prefix and request in flight alike, since
/// neither speaks for the window that remains. Without it a proof spent on one
/// cascade would license a second cascade joining the same entry: the whole
/// defect, one level up.
///
/// A reconcile that grows nothing and prunes nothing is NOT one of them, and
/// must not reset. It leaves the window exactly as the standing proof found it,
/// so that proof still orders every record the window can hold. Discarding it
/// there would buy no ordering at all, and would cost far more than a round
/// trip: such re-issues can arrive faster than a cut completes, so every proof
/// that completed would land on a latch some later re-issue had already reset,
/// and the window would never settle clean.
///
/// A newly opened fence is not one of them either, and for a stronger reason: it
/// needs no reset at all. Its ordinal already places it outside every standing
/// request's reach, which is strictly more precise than resetting — the coarser
/// rule threw away a proof that was still perfectly good for the fences it had
/// ordered, so a scope taking acknowledged covers faster than a cut completes
/// lost every proof to the next fence and settled none of them.
///
/// It is deliberately NOT the retired settle-edge observation gate: there is no
/// observation record to hold valid, no serial, no lane generation and no
/// completion flag, and the ordering is bought by a cut the reader already
/// performs rather than by a new mechanism.
///
/// # Why a lossy window owes one too
///
/// The proof is owed for the WINDOW, not for the claim the verdict will make.
/// More loss genuinely cannot falsify a degraded verdict — but the cut is not
/// there to surface loss, it is there to surface whatever the kernel holds
/// unread, and that includes DEATH. A root renamed away while its
/// `IN_MOVE_SELF` sits unread in the kernel queue is a scope that no longer
/// exists, and a `Degraded` is a LIVE verdict: it answers its caller and
/// dispatches the parked cookie write, which then lands in a recreated,
/// unmonitored directory and is reported `Ok` for a record no stream can ever
/// deliver. The scope's death is processed afterwards, and the loss that
/// degraded the window covers nothing that happened after it. The omitted cut is
/// exactly what would have put that record on the lane first, folding the fence
/// to [`CoverSettle::Dead`] and refusing the cookie. So every live fence asks,
/// whatever verdict it is heading for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct CutProof {
  /// The prefix already proven: the strongest mark a completed cut has earned
  /// for this entry, and the only thing here that licenses a verdict. `None`
  /// until one lands.
  proven: Option<CutMark>,
  /// The request out for the fences `proven` does not reach. At most one is ever
  /// out, and what the window does behind it leaves it alone.
  in_flight: Option<CutRequest>,
}

/// The window one cut speaks for, stamped at the instant its request was
/// committed to and inherited unchanged by the proof it mints.
///
/// The stamp is the scope's [`Monitor::coverage_work_epoch`] at that instant, and
/// the value it carries is the open ordinal of the newest fence then pending —
/// the last fence this cut reaches. Keeping the reach [`Stamped`] is what makes
/// the epoch check unskippable rather than merely required: the mark licenses
/// nothing at any other epoch, there is no way to read the reach at all without
/// naming the epoch it is being read under, and the epoch cannot be named
/// without reading it off the Monitor — a [`CoverageWorkEpoch`] is unforgeable
/// here, so no site can satisfy the check with the stamp the mark already
/// carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct CutMark(Stamped<CoverageWorkEpoch, u64>);

/// A cut that has been asked for: the token of the batch carrying the request,
/// and the mark that batch's completion earns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct CutRequest {
  /// Identifies the request, so only the completion of the batch that actually
  /// carried it can close this one.
  token: u64,
  /// What the reply will prove — the window as it stood when the request was
  /// committed to, never as it stands when the reply lands.
  mark: CutMark,
}

impl CutMark {
  /// The mark a cut taken under coverage-work epoch `epoch` earns: it reaches
  /// the fences through open ordinal `covers` and no further.
  const fn new(epoch: CoverageWorkEpoch, covers: u64) -> Self {
    Self(Stamped::new(epoch, covers))
  }

  /// The stronger of two marks: a later epoch wins outright, and within one
  /// epoch the further reach does.
  ///
  /// Reaches never merge across epochs. Only one epoch is ever current, so the
  /// older stamp already licenses nothing, and carrying its reach onto the newer
  /// one would claim an ordering the newer cut never took. The comparison
  /// therefore decides which mark is kept WHOLE and nothing else, and it is made
  /// inside the stamped value so that neither reach has to be read out to make
  /// it: a reach is still only ever read under an epoch the scope currently
  /// holds.
  fn strongest(self, other: Self) -> Self {
    if other.0.supersedes(&self.0) {
      other
    } else {
      self
    }
  }

  /// How far this mark licenses a CLEAN verdict at `epoch` — nothing at all
  /// unless it was stamped under exactly the coverage work the scope still
  /// holds.
  fn reach(self, epoch: CoverageWorkEpoch) -> Option<u64> {
    self.0.current(epoch).copied()
  }
}

impl CutProof {
  /// Whether this latch already speaks for every fence through `high_water` at
  /// `epoch`, and so owes no fresh cut.
  ///
  /// A request stamped under the current epoch does, whatever has opened behind
  /// it: it will license everything that was pending when it left, and asking
  /// again would only orphan it — a scope taking fences steadily would then
  /// cancel every request before its reply could land, and the fences it was
  /// bought for would wait on a reply nothing can close. The proven prefix does
  /// only as far as its reach, so fences opened past it are what provoke a
  /// successor once nothing is out. Anything stamped under an epoch the scope
  /// has since left speaks for nothing, a request included, because its reply
  /// could only ever mint a proof that is stale on arrival.
  fn answers_for(self, epoch: CoverageWorkEpoch, high_water: u64) -> bool {
    match (self.in_flight, self.proven) {
      // A request licenses its whole tranche or nothing, so its reach is not
      // consulted — only whether it still speaks at this epoch at all.
      (Some(request), _) if request.mark.reach(epoch).is_some() => true,
      (_, Some(proven)) => match proven.reach(epoch) {
        Some(covers) => covers >= high_water,
        None => false,
      },
      _ => false,
    }
  }

  /// The open ordinal through which a CLEAN verdict is licensed at `epoch`.
  ///
  /// Only the proven prefix licenses anything, and only as far as the tranche
  /// its request was made behind. A stale prefix and a request still out both
  /// license nothing: the fences beyond withhold, and the window asks again.
  fn licenses_through(self, epoch: CoverageWorkEpoch) -> Option<u64> {
    match self.proven {
      Some(proven) => proven.reach(epoch),
      None => None,
    }
  }

  /// Puts `token`'s request out for `mark`'s window. The proven prefix is left
  /// exactly as it stands: a successor is a claim about a window still being
  /// ordered, never evidence against one already ordered.
  fn latch(&mut self, token: u64, mark: CutMark) {
    self.in_flight = Some(CutRequest { token, mark });
  }

  /// Retires the request in flight into the proven prefix, raising it to that
  /// request's mark — but only for the token actually out, so every other
  /// completion is inert.
  fn prove(&mut self, token: u64) {
    let Some(request) = self.in_flight.take_if(|request| request.token == token) else {
      return;
    };
    self.proven = Some(
      self
        .proven
        .map_or(request.mark, |proven| proven.strongest(request.mark)),
    );
  }

  /// Discards everything the latch holds — proven prefix and request in flight
  /// alike — because the window they were taken over is no longer the one this
  /// entry stands for.
  fn invalidate(&mut self) {
    *self = Self::default();
  }
}

/// The ordering proof one scope's STAGED adoption markers wait on — the same
/// reader-queue cut [`CutProof`] buys, consumed for the one certifying verdict
/// that used to resolve on the op lane instead.
///
/// # What it is bought for
///
/// A widen's adoption marker is discharged by the chain parent's first complete
/// listing, and the confirming direction of that listing is a claim about an
/// INTERVAL — the splice-to-listing window — read off the interval's end state.
/// That is admissible only if every record which could refute it has already
/// been fed to the Monitor, and the listing's own completion does not establish
/// it: the listing runs on the blocking pool, its completion is reported on the
/// op channel, and the driver polls that channel ahead of the source lane. So
/// the record which refutes the window — the adopted object's own `MoveSelf` —
/// can be committed by the kernel BEFORE the listing and still unread when the
/// listing's verdict runs.
///
/// The reader's pre-reply cut is exactly the missing edge. A control batch
/// requested after the listing is answered only behind a drain of everything the
/// kernel had committed to the instance's queue, forwarded onto the source lane
/// AHEAD of the reply. One scope is one instance is one FIFO queue, so a
/// refuting record committed before the listing is on the lane before that
/// reply, and the choke point's drain feeds it before the seal takes any
/// verdict.
///
/// The interval the claim is about is the ADOPTED OBJECT's occupancy of its
/// slot. A cut orders records, and every reading behind the verdict — the
/// marker's survival, the listing's identity match, the occupancy check — is
/// about an inode, its parent link, and its filesystem. A mount stacked over the
/// slot and unmounted again before the listing disturbs none of those and emits
/// no record for a cut to order, so it leaves the end state reading exactly as
/// the widen left it (see [`Monitor::seal_staged_adoptions`]).
///
/// # Why it is not [`CutProof`]
///
/// Same primitive, different window, and two differences that matter.
///
/// A cover fence's proof is stamped with the scope's coverage-work epoch,
/// because what it must not outlive is the barrier re-opening. A seal's window
/// is pinned by the markers themselves — a staged marker holds
/// [`Monitor::coverage_settled`] down, so the fence's own arming predicate
/// (`barrier_settled`) is false for exactly as long as a seal is owed, and the
/// two can never be offered a cut in the same pass. What a seal must not
/// outlive is the TRANSPORT: a cut taken on a queue the scope no longer reads
/// orders nothing about the one it does. So the latch is stamped with the
/// delivery lane instead, and a lane it does not name answers for nothing.
///
/// And a cover fence's in-flight request licenses its whole tranche including
/// fences opened behind it, because a fence is a question about the window the
/// cut already ordered. A staging is not: a marker staged after the request was
/// committed to had its listing ingested after the cut was requested, so the cut
/// says nothing about it. The reach is therefore compared at the VERDICT
/// ([`licenses_through`](AdoptionSeal::licenses_through)), and a later staging
/// waits for its own successor rather than being swept into a proof that never
/// covered it.
///
/// # Why it cannot strand a scope
///
/// A token stops being provable in exactly four ways, and each of them clears
/// this latch by a different edge:
///
/// - the batch carrying it never proves — it unwound, or its reader died under
///   the current generation. Both fail closed to `on_source_fatal`, whose
///   teardown releases every marker of the scope, so the staged set empties and
///   [`resolve_adoption_seals`](DriverCore::resolve_adoption_seals) drops the
///   entry;
/// - the completion arrives under a generation the scope has swapped away from,
///   so the driver's in-flight mark no longer names it and the proof is dropped
///   silently. The lane stamp catches that with no help from anyone: the latch
///   stops answering the moment the scope's lane moves, and the scope is offered
///   a fresh cut. (The swap also rebinds the root, which releases the markers —
///   so the entry is dropped as well. Two independent escapes, deliberately, for
///   the same reason [`CutProof`] has two.)
/// - the scope is torn down. Its markers die with its tree and the entry is
///   dropped with them;
/// - the batch is still QUEUED when a later request for the same scope discards
///   it ([`queue_cut_proof`](crate::driver::queue_cut_proof)'s coalesce rule).
///   Only two things mint a later request here: this latch itself, which does so
///   only after rebuilding on a moved lane and so no longer names the discarded
///   token, and a cover fence, which is offered a cut only once every marker of
///   the scope has been released — the very condition that drops this entry.
///
/// What it CAN do is defer: a scope whose source lane never finishes draining
/// holds its seal over pass after pass. That is the deferral a cover fence
/// already carries, bounded per pass by the drain's own per-lane budget, and the
/// marker keeps every one of its other exits — the spend, the retry cap, the
/// walk, the rebind — throughout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct AdoptionSeal {
  /// The delivery lane everything below was taken on. A latch read under any
  /// other lane answers for nothing and is rebuilt.
  lane: u64,
  /// The staging generation an answered cut has proven through: every marker
  /// staged at or before it may be sealed. `None` until one lands. Kept as a
  /// PREFIX rather than consumed, so a seal the drain defers costs no second
  /// round trip.
  proven: Option<u64>,
  /// The request out, and the newest staging it will license. At most one is
  /// ever out: a staging that opens behind it waits for a successor rather than
  /// displacing it, so a scope widening steadily cannot cancel every request
  /// before its reply lands.
  in_flight: Option<SealRequest>,
}

/// A seal cut that has been asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SealRequest {
  /// Identifies the request, so only the completion of the batch that actually
  /// carried it can close this one.
  token: u64,
  /// The staging generation this request's answer earns — the newest staging at
  /// the instant it was committed to, never the newest when the reply lands.
  reach: u64,
}

impl AdoptionSeal {
  /// A latch on `lane` with nothing proven and nothing out.
  const fn new(lane: u64) -> Self {
    Self {
      lane,
      proven: None,
      in_flight: None,
    }
  }

  /// Whether this latch already owes no fresh cut for a scope on `lane` whose
  /// newest staging is `high_water`.
  ///
  /// A request still out answers whatever has staged behind it — asking again
  /// would only orphan it, and the successor the later staging needs is offered
  /// the moment this one lands. A proven prefix answers only as far as it
  /// reaches. Anything stamped on another lane answers for nothing at all,
  /// request included: its reply can only ever prove an ordering of a queue the
  /// scope has stopped reading.
  const fn answers_for(self, lane: u64, high_water: u64) -> bool {
    if self.lane != lane {
      return false;
    }
    if self.in_flight.is_some() {
      return true;
    }
    match self.proven {
      Some(proven) => proven >= high_water,
      None => false,
    }
  }

  /// The staging generation a CONFIRM is licensed through on `lane`, which the
  /// caller must read off the scope's CURRENT transport rather than off this
  /// latch — a stamp compared against itself proves nothing.
  ///
  /// Only the proven prefix licenses anything: a request still out has ordered
  /// nothing yet, and a prefix earned on another lane orders nothing here.
  const fn licenses_through(self, lane: u64) -> Option<u64> {
    match self.proven {
      Some(proven) if self.lane == lane => Some(proven),
      _ => None,
    }
  }

  /// Puts `token`'s request out for the stagings through `reach`. The proven
  /// prefix is left as it stands — a successor is a claim about stagings this
  /// latch has not ordered yet, never evidence against the ones it has.
  const fn latch(&mut self, token: u64, reach: u64) {
    self.in_flight = Some(SealRequest { token, reach });
  }

  /// Retires the request in flight into the proven prefix — but only for the
  /// token actually out, so every other completion is inert.
  fn prove(&mut self, token: u64) {
    let Some(request) = self.in_flight.take_if(|request| request.token == token) else {
      return;
    };
    self.proven = Some(match self.proven {
      Some(proven) => proven.max(request.reach),
      None => request.reach,
    });
  }
}

/// A planned Monitor input, compiled from one raw event.
#[derive(Debug)]
enum Planned {
  /// Feed a normalized record.
  Rec(OsRecord),
  /// Feed an overflow for a scope slice.
  Over(Scope),
}

/// One raw event's compilation: its planned inputs, possibly gated on a probe.
#[derive(Debug)]
struct Item {
  planned: Vec<Planned>,
  probe: Option<ProbeId>,
  /// A vanished rename half's cookie candidacy `(fileID, source path)`:
  /// granted at settlement iff a same-batch partner's probe evidenced the
  /// fileID on the root device AND the vanished path itself lies under no
  /// foreign prefix of the still-monotone table.
  cookie_candidate: Option<(NonZeroU64, PathBuf)>,
}

/// A batch whose items are being resolved; fed to the Monitor only once every
/// probe has answered, so per-root input order is preserved. `trailing`
/// inputs (a covering rescan for an ambiguous rename group) apply after every
/// item, so whatever the items degraded to is dominated.
///
/// A profile that answers [`feeds_at_classify`] has no probes to wait on and
/// hands its items over during the fence, so what reaches `settle` here is the
/// `trailing` tail alone; the ordering statement above is unchanged, since the
/// items went first either way.
#[derive(Debug)]
struct PendingBatch {
  items: Vec<Item>,
  awaiting: usize,
  trailing: Vec<Planned>,
  /// The batch's transport budget slot, held for as long as the compiled
  /// items are retained: parked memory then counts against the same budget
  /// that bounds the queue, so a stuck probe back-pressures the callback
  /// instead of growing the park unbudgeted. Dropped when the batch settles
  /// or is discarded (loss flush, scope teardown) — RAII, every path.
  permit: Option<BudgetPermit>,
  /// Unmount trust-removals deferred to the batch's settlement: removing a
  /// foreign prefix only ever INCREASES trust, so it must not happen before
  /// every one of the batch's classification and cookie decisions has run
  /// (the monotone-within-batch rule).
  deferred_unmounts: Vec<PathBuf>,
  /// fileIDs a `Present` rename probe bound to the root device in THIS batch,
  /// each with EVERY partner path that carried the proof — the contemporaneous
  /// evidence a vanished partner's cookie grant requires at settlement.
  /// Evidence exists only under the temporal bind: the partner's EVENT word
  /// carried the same fileID its probe observed (a probe-only fileID proves
  /// what occupies the path NOW, not what the batch's events were about).
  /// All partners are kept, not a representative: a grant demands exactly one
  /// (see [`DriverCore::grant_evidenced_cookies`]), and probe completion
  /// order must not decide which partner a cover points at.
  evidenced: BTreeMap<NonZeroU64, Vec<PathBuf>>,
}

/// Per-root batch parking: while a batch has probes in flight, later batches
/// queue behind it rather than overtaking it. Both the active batch and every
/// queued payload keep holding their transport budget slot (see
/// [`BatchPayload`]), so the park's memory is bounded by the same budget as
/// the queue's.
#[derive(Debug, Default)]
struct Park {
  active: Option<PendingBatch>,
  queued: VecDeque<BatchPayload>,
}

/// Why a probe was issued, and how to plan its resolution.
#[derive(Debug)]
enum ProbePurpose {
  /// A multi-verb flag word needed existence to ground a single record.
  Ambiguous {
    item: usize,
    flags: FsEventFlags,
    target: Option<Location>,
    path: PathBuf,
  },
  /// An unpaired rename half needed existence to pick its direction.
  Rename {
    item: usize,
    file_id: Option<NonZeroU64>,
    target: Option<Location>,
    path: PathBuf,
    /// Whether the half may mint a pairing cookie at all — `false` for a
    /// member of an ambiguous same-fileID group, whose shared id must not
    /// pair anything.
    allow_cookie: bool,
    /// The content and metadata facts the word carried alongside the rename.
    /// A surviving object owes them as ONE grounded record beside the move
    /// half, carrying every fact so either subscription admits it; an empty
    /// set owes nothing.
    content: Evidence,
  },
  /// A `RootChanged` needed the root's existence to pick the death signal.
  RootAlive { item: usize },
  /// An [`Action::Stat`](tributary_proto::Action::Stat) — the kind of a slot a
  /// listing could not classify. It belongs to no batch: the Monitor asked for
  /// it directly, and its answer goes straight back through
  /// [`Monitor::on_stat_result`], so it never parks an item or grounds a
  /// record.
  SlotKind {
    req: ReqId,
    /// The path stat'd. Carried solely so a boundary-revealing answer can be
    /// RECORDED (seam 4): `stat_result` discards the probed device by design,
    /// and until this the answer's device had nowhere to go.
    path: PathBuf,
  },
}

#[derive(Debug)]
struct ProbeCtx {
  scope: ScopeId,
  purpose: ProbePurpose,
}

/// How long a refused parked delivery waits before it is offered again. The
/// retry rides the core's own timer: an immediate re-offer would spin the
/// executing loop without yielding (the channel cannot drain meanwhile), so a
/// lagged consumer is polled at this bounded interval instead.
const DELIVERY_RETRY: Duration = Duration::from_millis(25);

/// The consumer-lag state of one scope. Events are only ever dropped while a
/// dominating `Rescan` is parked and undelivered, so the consumer's
/// post-`Rescan` re-enumeration provably covers them.
///
/// INV-PARK: the parked coverage never narrows while the lag stands. Every
/// `Rescan` routed while lagged — including a LOCATED one (a deficit
/// re-signal, an incomplete read, a failed arm) — is folded in by
/// [`DriverCore::covering_merge`]: the location becomes the join of the two
/// subtree coverages (their longest common prefix) and the id + epoch become
/// the newest mint's. So the promised drop set only ever grows, and the one
/// delivered instruction carries an epoch that dominates everything dropped
/// under it.
#[derive(Debug)]
enum LagState {
  /// Deliveries flow.
  Normal,
  /// The consumer channel refused a change: a dominating `Rescan` is parked
  /// (or being minted, while `parked` is `None`) and everything else for the
  /// scope is dropped as dominated.
  Lagged {
    parked: Option<Change>,
    attempt: Attempt,
  },
}

/// The delivery lifecycle of a parked `Rescan`.
#[derive(Debug, Clone, Copy)]
enum Attempt {
  /// Ready to be offered by [`DriverCore::poll_effect`].
  Idle,
  /// Offered and awaiting its [`DriverCore::on_delivery`] outcome; carries
  /// the offered change's epoch so an acceptance of a since-replaced
  /// `Rescan` retries the newer one rather than ending the lag.
  InFlight(tributary_proto::Epoch),
  /// Refused; re-offered once the retry deadline passes.
  Spent {
    /// When the next offer becomes due.
    retry_at: Instant,
  },
}

/// A torn-down scope's terminal `Rescan`, retried until the consumer accepts
/// it. Teardown ends the OS stream immediately, but the one change covering
/// everything the dead scope dropped must survive refusals — a plain queued
/// emit is one-shot, with no scope state left to re-park it on a full channel.
#[derive(Debug)]
struct DyingDelivery {
  change: Change,
  attempt: Attempt,
  /// The dead scope's canonical root, retained so the terminal delivery (and
  /// any straggler routed through the dying entry) still assembles after the
  /// scope state — and the consumer-side registry entry — are gone.
  root: Arc<PathBuf>,
}

/// One watched root's driver-side state.
#[derive(Debug)]
struct ScopeState {
  watch: WatchId,
  /// The [`ArmAttempt`] of the root's BOOTSTRAP arm — the one
  /// `Action::Watch(Root)` a registration ever queues, captured when the
  /// action is consumed because the spawn path answers it out of band (a
  /// kernel-recursive stream inline, a descending root through its own
  /// `AddWatch`). `None` until the action is drained.
  root_attempt: Option<ArmAttempt>,
  /// The backend lowering profile registration intended; the spawned
  /// source's [`RootMeta`] must agree.
  profile: BackendKind,
  requested: PathBuf,
  /// Canonicalized root bytes — known once the stream spawned. Shared so
  /// every delivery can carry it without copying.
  root: Option<Arc<PathBuf>>,
  root_dev: Option<u64>,
  /// The root's MOUNT id — the descent boundary the enumerate lowering fences on.
  /// A child directory on a different mount (even the SAME device, as a
  /// `mount --bind` of a same-superblock directory produces) is lowered
  /// non-descendable, closing the same-device bind breach the `root_dev` check
  /// alone cannot. Captured at the spawn barrier AND re-read on every alive,
  /// NON-STALE mount refresh: a same-object re-mount of the root (unmount + re-bind,
  /// identity unchanged) moves it to a new mount, so a frozen value would fence every
  /// descendant on the new mount as a boundary — the refresh keeps it current
  /// (`on_mounts_refreshed` adopts a fresh `Some`, then reconciles a descending
  /// scope's coverage when the frame changed). Only ever the last AUTHORITATIVE frame
  /// — a stale refresh publishes nothing here (see the module doc's mount-refresh
  /// publication invariant). `None` when neither the barrier nor a refresh could read
  /// it (below Linux 5.8, or a non-Linux/fake source), and then the device check
  /// governs alone — the honest degrade.
  root_mnt_id: Option<u64>,
  /// The last PROVEN incarnation token for the mount
  /// [`root_mnt_id`](Self::root_mnt_id) names — what makes a frame move
  /// observable when the id did not change.
  ///
  /// Overwritten only by a refresh that answered one, so an unprovable window
  /// leaves the last proven token to be compared against, rather than a token
  /// that would silently agree with whatever comes next. `None` until the first
  /// refresh that can answer, and forever on a host that answers none.
  root_incarnation: Option<crate::os::RootIncarnation>,
  /// How many times this scope's descent frame has MOVED — bumped wherever
  /// `root_dev`/`root_mnt_id` are installed, and never read for its value.
  ///
  /// It exists for one comparison: an admission round trip
  /// ([`PendingAdmit`]) is opened against the frame in force at PARK time and
  /// answered arbitrarily later, and everything the reply asks the core to do —
  /// put a condemned record back, release a located cover — is only meaningful in
  /// the world that frame describes. The executor refuses a request whose frame
  /// the live root no longer has (it re-reads the root's frame beside the
  /// location's, which is the only way a mount id comparison means anything), but
  /// it cannot see a frame that moved AFTER its walk. This can, and it turns such
  /// a reply into the whole-root recovery instead of a located answer.
  ///
  /// The two world swaps bump it too, though they also CLEAR the parked set, so
  /// nothing there depends on it: bumping anyway keeps "the frame moved" and "the
  /// epoch moved" the same statement, rather than one that happens to hold.
  frame_epoch: u64,
  /// What this scope holds about its coverage set's last COMPLETE whole-root
  /// generation: the world it was verified in, or the evidence that one was
  /// produced and lost — see [`Generation`], which carries the rationale for both
  /// halves and for the refusal key that rides the second.
  ///
  /// Written only by [`generation_applied`](Self::generation_applied) and
  /// [`generation_lost`](Self::generation_lost), so there is no raw write to
  /// enumerate and no partial update to strand.
  generation: Generation,
  /// The whole-root recovery round trip this scope has OUT and unanswered.
  ///
  /// The root-scope sibling of a [`PendingAdmit`], and held with the same
  /// discipline: it is opened by the request and DISCHARGED by an answer that was
  /// applied — a matching [`RootRecovery`](crate::os::RootRecovery) whose cutoff
  /// dominates it, or an inline `Unreachable` resolution — never by a transition
  /// that merely thought it was no longer needed. A reply whose stamps are not this
  /// scope's leaves it standing, because such a reply applied nothing.
  ///
  /// It carries the epoch it was ISSUED at, and that is what makes it both the
  /// in-flight suppressor and the retry trigger, with no third piece of state
  /// between them:
  ///
  /// - issued in the world this scope still holds — the reply is coming and will
  ///   carry the generation, the cutoff and the cover together, so a second
  ///   request buys a duplicate whole-root walk and nothing else.
  /// - issued in a world this scope has LEFT — its reply can never be applied
  ///   here, so the round trip is owed again, and the frame the refresh just
  ///   published is what the fresh request is stamped with.
  ///
  /// # It means OUTSTANDING, and nothing else
  ///
  /// It used to mean a second thing on top of that — an anti-spin latch, LEFT
  /// STANDING after its one reply arrived and was refused, on the argument that a
  /// fresh request would be answered identically. That argument is a prediction
  /// about the SOURCE's world made from a value this core re-reads (its own frame,
  /// unchanged), and it is the cadence rule's exact failure mode: the match was
  /// read as confirmation. A transient same-object self-bind refutes it — the walk
  /// fenced against a mount that departed before the refresh, the root is back on
  /// the mount OBJECT it started on so neither its legacy id nor its unique
  /// incarnation token moved, and the record then sat at the current epoch
  /// suppressing every later refresh for the life of the scope, with the rejected
  /// generation's evidence and its cutoff-covered recovery stranded behind it.
  ///
  /// So a reply that arrives and applies nothing DISCHARGES the round trip it
  /// dominates: nothing more will ever come for it, and a record of an outstanding
  /// request must not outlive the request. What bounds the retry is retained
  /// evidence about the refusal itself, held on the generation it lost
  /// ([`Generation::Lost`]) — an observation, not a prediction.
  ///
  /// Cleared by both world swaps along with the rest of the old world's state: the
  /// round trip belongs to a root this scope no longer watches, and the swap's own
  /// covering `Rescan` owes the consumer the whole new tree regardless.
  pending_recovery: Option<PendingRecovery>,
  /// The [`frame_epoch`](Self::frame_epoch) this scope has already PUBLISHED to
  /// its live source ([`Effect::PublishFrame`]), or `None` for a source that has
  /// been told nothing yet.
  ///
  /// Bookkeeping, never an obligation, and it fails in the safe direction by
  /// construction: a publication that is somehow not delivered leaves the source
  /// stamping an OLDER epoch, and an older stamp is refused rather than wrongly
  /// applied. That is why it may be a plain "what I have said" record rather than
  /// something that has to survive a transition — the worst it can cost is one
  /// refused generation, which the derived need then asks for again.
  ///
  /// Reset to `None` wherever a FRESH source is adopted (the birth and both world
  /// swaps): a new reader's mailbox starts at zero, so whatever the old one was
  /// told says nothing about what this one knows.
  published_epoch: Option<u64>,
  /// The root object's identity, captured at the spawn barrier. The mount
  /// refresh re-stats the root and compares against this: a `Missing` or
  /// mismatched read is a root death, lowered through the same self-event path
  /// a `RootChanged` probe uses (kernel-recursive backends have no in-tree
  /// unmount signal, so the refresh cadence is their root-liveness check).
  /// `None` for a scope whose barrier read no identity (off-unix fakes).
  identity: Option<RootIdentity>,
  /// The AUTHORITATIVE mount table's locations under the root, as of the last
  /// read that could take one — the REPLACEABLE half of the device-trust veto.
  ///
  /// Every row here came from one snapshot, and the next authoritative snapshot
  /// replaces the whole vector rather than unioning onto it
  /// ([`install_mount_table`]). It used to union, on the argument that absence
  /// from a table must never GRANT trust — but the two components below were
  /// conflated then, and the union was what actually leaked: every mountpoint a
  /// host ever presented stayed here for the life of the scope, so a long-lived
  /// scope on a container host retained one `PathBuf` per HISTORICAL mount and
  /// paid a linear scan against that history on every refresh. Unbounded
  /// residency is not a safe direction, it is a leak wearing one.
  ///
  /// Replacement is sound because the reads are SERIALIZED — [`arm_refresh`] lets
  /// at most one be outstanding, so snapshot N+1 is read after N landed — and a
  /// stale one publishes no table at all. A row absent from an authoritative read
  /// is therefore a mount the host says is gone, which is exactly the fact that
  /// makes the path root-device again. What replacement must NOT touch is a
  /// prefix learned somewhere OTHER than a table snapshot, and that is why those
  /// live in [`learned_mounts`](Self::learned_mounts) instead.
  ///
  /// Empty, always, on a backend that consumes no absence-based trust
  /// ([`consumes_absence_trust`]) — the same predicate [`device_trusted`] gates
  /// its absence leg on, so skipping the maintenance can never grant trust.
  ///
  /// Tiny in practice, so a linear scan beats indexing.
  mount_table: Vec<PathBuf>,
  /// Foreign-device prefixes this scope learned from something OTHER than a mount
  /// table read — the INDEPENDENT half of the veto, and the one no snapshot may
  /// remove.
  ///
  /// Two writers, both FSEvents-only by construction: [`apply_mount_add`] (an
  /// in-band `Mount` flag word) and [`learn_device`] (a probe that read a foreign
  /// device at a path). Neither is a mount-table row: the first can describe a
  /// mount that arrived AFTER the snapshot in flight was read, and the second is a
  /// path that may sit arbitrarily deep inside one. A table install that dropped
  /// either would re-trust a subtree this scope has direct evidence is foreign.
  ///
  /// So the lifecycle is evidence-backed in both directions, and only in both
  /// directions: an entry enters on an observation and leaves ONLY on the in-band
  /// unmount word that proves its mount is gone (`deferred_unmounts`, applied at
  /// [`settle`](DriverCore::settle)) or on a world swap, which retires the whole
  /// world the prefix described. A cadence never removes one.
  learned_mounts: Vec<PathBuf>,
  /// Whether `mounts` is backed by an authoritative read of the live mount
  /// table (the spawn seed, or a post-loss refresh). Without it, a path not
  /// covered by a known mount prefix proves nothing (the table is blind), so
  /// event-side device trust is refused. Revoked by every loss signal — a
  /// dropped window may have carried a mount transition.
  mounts_authoritative: bool,
  /// The CENSUS: the mount rows the last AUTHORITATIVE read observed, keyed by
  /// identity ([`CensusRow`]).
  ///
  /// Two successive censuses diffed BY KEY are the primary mount detector, and
  /// every verdict it produces is a TRANSITION between two observations rather
  /// than anything this scope stored as an obligation:
  ///
  /// - a key here and gone from the read DEPARTED with no signal at all — #74's
  ///   lazy unmount, which emits no `IN_UNMOUNT`, no hangup and no `Rescan`;
  /// - a key in the read and absent here ARRIVED, shadowing ground the consumer
  ///   may already have enumerated (`compile::fsevents`' `plan_mount` covers the
  ///   arrival macOS signals, and the class of mount created after a watcher
  ///   settles is observed by no seam at all);
  /// - the same key at a NEW location MOVED — covered at both, which is also what
  ///   makes cross-read id recycling benign;
  /// - the same key at the same location, on a different device or hanging off
  ///   a different mount, was REPLACED.
  ///
  /// **Condemn on a transition, never on an absence.** A btrfs subvolume has no
  /// row and never will, so it is in no census, so it transitions in none: the
  /// cover storm a provenance partition once existed to prevent is structurally
  /// impossible here, with no partition at all.
  ///
  /// Deliberately SEPARATE from [`mounts`](Self::mounts), and deliberately not a
  /// replacement for it. The table serves DEVICE TRUST, where a stale extra
  /// prefix only ever vetoes (safe) and a missing one grants trust that was never
  /// proven (unsafe) — so its install must stay a union. Coverage wants the
  /// opposite direction: there the stale extra prefix is exactly what HIDES a
  /// departure. Keeping the two apart lets this one be replaced on a table read
  /// while the trust table never shrinks; nothing here ever reaches
  /// [`device_trusted`].
  ///
  /// Replaced whole by every authoritative read and by every world swap's barrier
  /// read — never merely cleared. The old root's table proves nothing about the
  /// new root's, but the new root's barrier read proves plenty: the cold crawl
  /// declines coverage beneath every mount it finds, and crawl and first refresh
  /// are unordered, so a prefix that departs in that window is a departure nobody
  /// would otherwise ever derive (an empty census reads the post-departure table
  /// as an arrival-only frame and stays silent about the ground). Seeding is
  /// conservative in the cover direction and touches no authority:
  /// `mounts_authoritative` is unaffected by what lands here.
  ///
  /// A root FRAME change rebases nothing here. Mount ids are absolute, so the
  /// census survives a same-object remount of the root and the next read diffs
  /// against it — a remount that moved no mount is then quiet, rather than
  /// covering every mount under the root as an arrival.
  census: Vec<CensusRow>,
  /// The LEDGER: the boundaries a SEAM observed that no census row speaks for
  /// ([`LedgerEntry`]).
  ///
  /// It holds exactly what the census cannot. A [`Standing::Mount`] entry is a
  /// vfsmount seen before any census listed it, and the belt for the window
  /// between the two — the census takes it over on its very next read. A
  /// [`Standing::SameMount`] entry is a subvolume the census will never list, and
  /// only the event stream or a complete generation retires it. A
  /// [`Standing::Unknown`] entry is a host that cannot tell those apart, and it
  /// fails the scope closed until a census row stands at its location.
  ///
  /// Bounded by [`MAX_BOUNDARIES`], which holds when every reconciliation has
  /// failed.
  ledger: Vec<LedgerEntry>,
  /// Departure covers PARKED on an outstanding admission round trip — see
  /// [`PendingAdmit`]. Only ever non-empty on a fanotify scope, whose source is
  /// the only one that admits by membership and can therefore be blind to ground
  /// a departed mount revealed.
  ///
  /// Bounded by the transitions actually derivable under the root: the census
  /// row (or ledger entry) whose disappearance parks one is gone from the state
  /// by the same step, so no later refresh can re-derive that departure and park
  /// a second round trip for it. Every entry is retired by exactly one reply, by
  /// a world swap, or by the scope's own death.
  pending_admits: Vec<PendingAdmit>,
  /// An [`Effect::RefreshMounts`] is outstanding; repeated loss signals
  /// coalesce onto it instead of stacking effects.
  refresh_pending: bool,
  /// An INVALIDATING arming ([`RefreshCause::Invalidating`] — a loss signal, or
  /// a world swap's own re-arm) landed while a refresh was in flight: that
  /// snapshot may predate the newly-lost window, so its result is discarded and
  /// one more refresh re-arms.
  ///
  /// The periodic tick pointedly does NOT set it. A tick carries no evidence
  /// against the in-flight snapshot — it is a cadence, not a transition — and a
  /// tick that condemned it would starve every publication behind
  /// [`on_mounts_refreshed`](DriverCore::on_mounts_refreshed)'s stale gate for
  /// as long as refresh latency stayed at or past the interval.
  refresh_stale: bool,
  /// A root REPLACE committed while a refresh was in flight: that snapshot
  /// describes the replaced world, so EVERYTHING it carries — the liveness
  /// verdict included — is about an object this scope no longer watches.
  /// Its result is discarded whole and one refresh re-arms against the live
  /// world. Distinct from [`refresh_stale`](Self::refresh_stale), which
  /// gates only the table/frame: same-world death evidence must survive a
  /// loss, but a cross-world verdict must not survive a replace.
  refresh_world_stale: bool,
  lag: LagState,
  park: Park,
  /// The journal id counter wrapped; any minted resume token is invalid.
  resume_poisoned: bool,
  /// Whether public delivery has begun — the never-live fence's real fact. A
  /// scope is publicly live once its CALLER holds a handle: for a kernel-
  /// recursive backend that is the spawn (the live stream is the coverage, the
  /// grant commits inline), but for a descending backend it is the ROOT ARM
  /// SUCCESS, not the spawn — the source starts with no watches, so `root`
  /// being populated at spawn does NOT yet mean anything is delivered. The
  /// [`DeferredGrant`](crate::driver::DeferredGrant) dates the caller's handle
  /// from the same root arm, so a root arm that FAILS answers the caller `Err`
  /// and leaves this `false`: [`route_event`](DriverCore::route_event) then
  /// drops the Monitor's internal failure `Rescan` instead of emitting a public
  /// event for a registration no one owns.
  publicly_live: bool,
  /// When this scope's mount table is next re-read (and its root re-stat'd),
  /// for a profile [`liveness_ticked`](DriverCore::liveness_ticked) arms — the
  /// Linux pair, inotify and fanotify — under a non-zero interval. `None` for
  /// every other backend, before the root goes live, and while the tick is
  /// disabled; the loss-triggered refresh remains its own path. Seeded once the
  /// birth refresh confirms the root alive and re-armed by
  /// [`on_timeout`](DriverCore::on_timeout) after each tick fires.
  liveness_deadline: Option<Instant>,
  /// The retained cover this scope's per-directory coverage was last reconciled to by
  /// [`on_set_cover`](DriverCore::on_set_cover) — `None` is FULL coverage (the initial,
  /// never-pruned state). The broadening delta a later set-cover must re-arm is computed
  /// against THIS previously-applied cover ([`broadening_delta`]), never against which
  /// watches happen to exist: a narrower cover deliberately keeps the connecting ANCESTORS
  /// of its retained prefixes armed while pruning their other descendants, so an exact-path
  /// "is a watch present at this prefix" test would wrongly read a retained ancestor as
  /// fully covered and skip re-arming the descendants the earlier cover pruned — silent loss
  /// after the bridge Rescan's crawl. Set on every successful `on_set_cover`;
  /// initialized `None`. **Optimistic**: recorded before the grow's re-arm
  /// work completes, so a LOSSY settle rewinds it to `settle_floor` (the
  /// applied-cover-lie fix — see `settle_floor`), and a public scope `Rescan`
  /// degrades a `Some` claim IMMEDIATELY to the EMPTY cover (nothing below
  /// the root is claimed): the loss may have hollowed the claim even with no
  /// reconcile in flight, so the next `on_set_cover` computes a full
  /// broadening delta and re-proves the coverage it requests
  /// ([`route_event`](DriverCore::route_event)'s lossy-window handling).
  applied_cover: Option<Vec<PathBuf>>,
  /// The coverage provably live regardless of grow outcomes: the running
  /// antichain MEET ([`cover_meet`]) of every cover applied since the last
  /// CLEAN settle observation — `None` is FULL coverage, the meet identity.
  /// Retained-and-covered survivors are never re-armed by a reconcile, so
  /// meet-coverage never gapped even when every grow arm failed. Updated on
  /// EVERY `on_set_cover` application (acked or reply-less); at each settle
  /// observation ([`poll_cover_settlements`](DriverCore::poll_cover_settlements)):
  /// a CLEAN settle resets it to the now-truthful `applied_cover`, a LOSSY
  /// settle rewinds `applied_cover` to it (it IS the floor, so it stays).
  /// A public scope `Rescan` degrading a narrowed `applied_cover` folds this
  /// floor down with it (the meet with the empty cover is the empty cover),
  /// so the observation-time rewind cannot resurrect the pre-loss claim.
  /// Without the rewind a re-issue after a failed grow would compute an empty
  /// [`broadening_delta`] and settle clean over a hole; under-claiming only
  /// costs redundant re-reads.
  settle_floor: Option<Vec<PathBuf>>,
  /// A same-transport widen's WITNESSED WINDOW (INV-ROOT), open from the
  /// reservation of the widened root's watch id to the commit gate. The
  /// reserved watch is pre-armed on the LIVE lane under a Monitor-unknown id,
  /// so its kernel records would drop silently at the Monitor's unknown-watch
  /// guard; the inotify lowering (`plan_inotify`) intercepts them HERE
  /// instead — before the guard: a death record taints the window, benign
  /// churn is counted and left to the post-commit cold read. Every scope loss signal ([`on_root_overflow`](DriverCore::on_root_overflow))
  /// taints too — a loss may have carried the death records themselves. The
  /// commit ([`on_root_widened`](DriverCore::on_root_widened)) consumes the
  /// window and refuses a tainted one into the stream-replace fallback, so
  /// the barrier never certifies over a binding whose window was not
  /// provably clean — verification by witness, never by an out-of-band
  /// identity sample (which cannot distinguish a live watch from an IGNORED
  /// one over a same-identity rebind).
  pending_widen: Option<PendingWiden>,
}

/// What one record owes the exclusion geometry, decided from the Monitor's own
/// report of what that record did to the watch tree.
///
/// Read entirely on the far side of the record's hand-off to the Monitor
/// ([`reparent_geometry`](DriverCore::reparent_geometry)): nothing about a rename's
/// consequences is knowable before the Monitor has decided them, so there is no
/// pre-feed half and no verdict a pre-feed half could return.
#[derive(Debug)]
enum Geometry {
  /// The record carries no geometry, or its rename left the geometry unchanged,
  /// or the Monitor relocated nothing.
  Nothing,
  /// A repair to queue directly BEHIND the record: the Monitor's own located
  /// loss signal at the rename's destination, so the re-enumeration is lowered
  /// against the path the subtree actually landed at.
  Repair(Planned),
}

/// The witnessed window of one pending same-transport widen (INV-ROOT): the
/// reserved root's binding is provably live at the commit iff the window saw
/// neither a reserved death record nor a scope loss signal. Created by
/// [`begin_widen_watch`](DriverCore::begin_widen_watch) BEFORE the pre-arm
/// dispatch (so no reserved-attributed record can predate it), consumed by the
/// commit gate, cleared by [`abort_widen_watch`](DriverCore::abort_widen_watch)
/// on a failed pre-arm and by [`on_root_replaced`](DriverCore::on_root_replaced)
/// when the fallback replace commits over it.
#[derive(Debug)]
struct PendingWiden {
  /// The reserved root [`WatchId`] the pre-arm bound on the live lane.
  reserved: WatchId,
  /// The witness verdict: `Some` once the window tainted. First cause wins —
  /// the earliest signal is the one that ended the window's cleanliness.
  tainted: Option<TaintCause>,
  /// Benign (non-death) reserved records the latch consumed — the churn the
  /// post-commit cold read converges. Diagnostic surface for the fallback.
  benign: u32,
}

impl PendingWiden {
  fn taint(&mut self, cause: TaintCause) {
    self.tainted.get_or_insert(cause);
  }
}

/// Why a widen's witnessed window was spent without committing (INV-ROOT) —
/// the diagnostic the fallback carries, mirroring the transport `Fatal`'s
/// carried class. The first two causes are WITNESS verdicts: the window saw
/// something that costs it the proof its own binding is live. The last two are
/// not witnessed at all — they are the commit gate finding the splice
/// unprovable on its face, one because the adopted OBJECT cannot be named and
/// one because the adopted PATH is too deep to prove — but each spends the
/// window and takes the same fallback, so they travel the same channel rather
/// than inventing a parallel one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaintCause {
  /// The reserved root's own death record: `Ignored` (⊇ unmount), `MoveSelf`,
  /// or `DeleteSelf`, attributed to the reserved watch inside the window.
  RootDeath(RecordKind),
  /// A transport loss signal for the scope (overflow, decode loss, budget
  /// refusal) — the window may have lost the death records themselves, so it
  /// can no longer witness their absence.
  Loss,
  /// The OLD root's identity does not fit the Monitor's enumerate-mint space
  /// (a synthesized or unreadable `ino == 0`, or a 128-bit file id past
  /// `u64` — ReFS), so the splice could install no expected object at the
  /// adopted edge and its dark-window tripwire would have nothing to re-prove
  /// against. Not a witness verdict: nothing went wrong in the window, the
  /// commit is simply not provable, and the fallback's fresh spawn barrier
  /// rebuilds the binding without needing the identity at all.
  UnmintableIdentity,
  /// The old root sits more than one segment below the new one, so the splice
  /// would have to mint INTERMEDIATE connectors — unidentified cold nodes whose
  /// own edges no adoption marker names and no read re-proves. A connector could
  /// move out of its slot and back inside the dark window unrecorded, movement
  /// deeper down the chain could go unobserved entirely, and a rename of an
  /// ANCESTOR of the old root emits no `MoveSelf` for the already-watched old
  /// root, so the invalidation that spends a moved adoption's proof never fires;
  /// the single tail marker would confirm regardless.
  /// [`Monitor::widen_root`] therefore serves depth one only. Like
  /// [`UnmintableIdentity`](Self::UnmintableIdentity) this is not a witness
  /// verdict and not a driver bug — the widen was well-formed and the window was
  /// clean, the shape is simply one no proof covers — and the fallback replace
  /// re-establishes the binding over an arbitrarily deep widen without needing a
  /// window proof at all.
  UnprovableChain,
}

/// A tainted window's diagnostics, carried on the commit refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WidenTaint {
  /// What ended the window's cleanliness.
  pub(crate) cause: TaintCause,
  /// How many benign reserved records the latch consumed before the verdict.
  pub(crate) benign: u32,
}

/// How [`on_root_widened`](DriverCore::on_root_widened) disposed of a
/// same-transport widen commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum WidenCommit {
  /// The splice applied; the widen is live on the same transport. Carries the
  /// [`ArmAttempt`] the pre-armed root's replayed outcome must be reported
  /// under — the splice mints it, so an outcome naming any other attempt is a
  /// superseded arm's and is discarded.
  Committed(ArmAttempt),
  /// The commit is not provable, for one of the [`TaintCause`]s: the
  /// witnessed window tainted (a reserved death record or a scope loss signal
  /// landed between the reservation and this commit, so the binding cannot be
  /// proven live), the old root carried no mintable identity for the
  /// adopted edge's re-proof, or it sat more than one segment down so the
  /// splice's intermediate connector edges would have no proof at all. Core
  /// and Monitor are untouched except that the
  /// spent window is consumed; the caller disarms the pre-armed descriptor
  /// and falls back to the general stream replace, whose spawn barrier
  /// re-establishes the binding from scratch. A LEGITIMATE outcome, never a
  /// driver bug — and because the window is consumed HERE, the caller must
  /// not close it again.
  TaintedWindow(WidenTaint),
  /// A violated precondition on a path the driver's gates make unreachable —
  /// core and Monitor bit-identical (the window entry included), the caller
  /// treats it loudly and falls back to the stream replace, whose commit
  /// clears the leftover window.
  Refused,
}

impl ScopeState {
  /// The root every delivery of this scope carries: the canonical root once
  /// the stream spawned, else the consumer-supplied path (the defensive floor
  /// for a scope that dies before its spawn result lands).
  fn delivery_root(&self) -> Arc<PathBuf> {
    self
      .root
      .clone()
      .unwrap_or_else(|| Arc::new(self.requested.clone()))
  }

  /// This scope's descent frame, as every arm carries it.
  ///
  /// Read LIVE at each emission, never captured once: a same-object re-mount
  /// moves `root_mnt_id` and a replace/widen swaps both halves, and an arm must
  /// be judged against the frame of the world that issued it. Both halves are
  /// `None` before the stream spawns, which is the honest degrade — an arm with
  /// nothing to fence against installs, exactly as [`crosses_mount_boundary`]
  /// declines nothing under an unknown frame.
  const fn frame(&self) -> ScopeFrame {
    ScopeFrame {
      root_dev: self.root_dev,
      root_mnt_id: self.root_mnt_id,
    }
  }

  /// Whether any EXEMPT ledger entry sits at a direct child of `dir` — the cheap
  /// precondition [`DriverCore::on_enumerated`] asks before paying anything at
  /// all for [`retire_relisted_boundaries`]'s bookkeeping.
  ///
  /// Exempt is [`Standing::SameMount`] or [`Standing::Unknown`]: the entries a
  /// census never takes over, and therefore the only ones a listing has to
  /// reconcile. A [`Standing::Mount`] entry is dropped by the very next
  /// authoritative refresh's join whatever a listing does, so it is not worth a
  /// per-entry scan of every enumerate to catch one earlier.
  ///
  /// False for every scope holding no seam-observed subvolume, which is every
  /// scope in production today, so an enumerate over a directory with no exempt
  /// entry under it does exactly the work it did before.
  fn holds_exempt_under(&self, dir: &Path) -> bool {
    self
      .ledger
      .iter()
      .any(|entry| entry.standing.is_exempt() && entry.location.parent() == Some(dir))
  }

  /// **The fail-closed trigger.** Whether this scope holds any
  /// [`Standing::Unknown`] entry — a boundary whose seam could not tell a genuine
  /// vfsmount from a same-mount subvolume, because one of the two ids was
  /// unanswerable.
  ///
  /// While it answers `true`, every AUTHORITATIVE refresh covers the WHOLE root
  /// (see [`DriverCore::on_mounts_refreshed`]). Not the entry's own location, not
  /// once per entry, not on a cadence: one root cover per frame that was actually
  /// read, for as long as any such entry is held.
  ///
  /// # Why the trigger is scope-wide and the cover is root-wide
  ///
  /// An `Unknown` entry cannot say whether the boundary it names is still there,
  /// and a census that stands nowhere at its location cannot say either — the mount table
  /// never lists a subvolume, and never lists a vfsmount whose row the host
  /// cannot key by id. Three successive designs tried to pay for that per entry:
  /// covering once (permanent silent loss, once the one cover was spent),
  /// covering on a generation cadence (the stamp was cleared by the re-listing
  /// that the cover's own crawl produced), and latching a refusal (one latch
  /// silenced every later refused boundary). Each failed the same way, because on
  /// an id-less host a re-observation of such a boundary is bit-for-bit identical
  /// whether it is the old mount or a new one. There is no evidence to key a
  /// per-entry decision to, so no per-entry decision is made.
  ///
  /// # The cost, stated plainly
  ///
  /// On a 4.11–5.7 kernel with btrfs subvolumes under the root this is a
  /// PERMANENT per-refresh whole-root cover: every seam entry there is `Unknown`,
  /// and only a census row at the location or a retirement pass clears one. That
  /// is accepted — correctness over cost — and documented on
  /// [`root_liveness_interval`](crate::WatcherOptions::root_liveness_interval),
  /// which is the knob that prices it.
  ///
  /// # Who never pays
  ///
  /// On Linux ≥ 5.8 this is `false` for the life of every scope: `root_mnt_id` is
  /// read at spawn (a failure there is a spawn failure, not a `None`), and every
  /// seam that records reads the boundary's own id from the fd it pinned — a
  /// `statx` that fails yields an incomplete walk or a `Failed` probe and records
  /// nothing. So every entry is decided `Mount` or `SameMount`, and the `Unknown`
  /// population is empty.
  fn fails_closed(&self) -> bool {
    self
      .ledger
      .iter()
      .any(|entry| matches!(entry.standing, Standing::Unknown))
  }

  /// Whether this scope holds ANY boundary the mount table cannot speak for — the
  /// EXEMPT entries ([`Standing::SameMount`] and [`Standing::Unknown`]), which no
  /// mountinfo row ever lists and which therefore only a complete whole-root
  /// generation can reconcile.
  ///
  /// A scope holding none of them needs no generation at all: everything it holds
  /// is either a census row or a [`Standing::Mount`] entry the next join settles,
  /// so the table diff derives arrivals, replacements and departures on its own
  /// and a refused generation costs it nothing.
  fn holds_exempt_record(&self) -> bool {
    self.ledger.iter().any(|entry| entry.standing.is_exempt())
  }

  /// Whether a complete whole-root generation is owed the coverage set — either
  /// because one was LOST, or because the last one that landed was taken in a
  /// world this scope has since left.
  ///
  /// The two arms are not two spellings of one test, and neither covers the other.
  ///
  /// The derived arm fires without anyone remembering the transition that made it
  /// true — a reply superseded before it landed, a frame that moved with no report
  /// in flight at all — but it reads the coverage set, so it can only see
  /// boundaries the set HOLDS. A generation produced and then discarded is the one
  /// thing it is blind to: those declines are exactly what would have PUT the first
  /// exempt record in the set, so after the rejection the set holds none,
  /// [`holds_exempt_record`](Self::holds_exempt_record) reads false, and the frame
  /// epoch a re-mount would have moved sits equal to the birth watermark because
  /// the id never changed. No later mount table can reconstruct an exempt boundary
  /// — no row ever lists one.
  ///
  /// So a lost generation is RETAINED as evidence ([`Generation::Lost`]) rather
  /// than re-derived, and the derived arm stays for the cases no loss ever
  /// witnessed.
  fn generation_stale(&self) -> bool {
    match self.generation {
      Generation::Lost { .. } => true,
      Generation::Verified { epoch } => epoch != self.frame_epoch && self.holds_exempt_record(),
    }
  }

  /// The disagreement this scope's last refused recovery was refused on, or `None`
  /// — for a `Verified` generation there is none by construction, which is the
  /// state [`Generation`] makes unrepresentable rather than merely unwritten.
  fn refused_key(&self) -> Option<RefusedWalk> {
    match self.generation {
      Generation::Lost { refused } => refused,
      Generation::Verified { .. } => None,
    }
  }

  /// **A complete generation was APPLIED to this coverage set under the frame this
  /// scope holds** — the watermark advances, and any evidence a lost one left,
  /// refusal key included, is discharged by the one event that may discharge it.
  ///
  /// Called at exactly the sites that apply one: the two accept paths
  /// ([`on_walk_boundaries`](DriverCore::on_walk_boundaries),
  /// [`on_root_recovered`](DriverCore::on_root_recovered)) and the three world
  /// swaps, whose barrier read seeds a set that is complete the moment it exists.
  /// Nowhere else may write the watermark forward, which is what keeps it evidence
  /// rather than a debt somebody remembered to clear.
  fn generation_applied(&mut self) {
    self.generation = Generation::Verified {
      epoch: self.frame_epoch,
    };
  }

  /// **A complete generation was produced and NOT applied here** — the evidence is
  /// retained, and `disagreement` (where the refusal HAS a key) becomes the key the
  /// next refusal is measured against.
  ///
  /// Returns whether this refusal REPEATS the key already held: same frame, same
  /// foreign root, so the walk that produced it was raised in full knowledge of the
  /// first refusal and a third read changes nothing (see [`RefusedWalk`]). The
  /// comparison is against the key held BEFORE this call, because a key overwritten
  /// first would compare against itself and never report a repeat.
  ///
  /// A refusal with no key — an epoch mismatch, or an autonomous report nobody
  /// requested — keeps whatever key was held rather than clearing it: only a
  /// generation LANDING discharges evidence, and an unrelated refusal is not one.
  #[must_use = "a repeated refusal must not arm a read of its own; the caller decides on this"]
  fn generation_lost(&mut self, disagreement: Option<RefusedWalk>) -> bool {
    let held = self.refused_key();
    let reasked = disagreement.is_some() && held == disagreement;
    self.generation = Generation::Lost {
      refused: disagreement.or(held),
    };
    reasked
  }

  /// Whether any cover is PARKED on a round trip that cannot be answered on its
  /// own terms any more — one opened in a world this scope has left.
  ///
  /// [`on_admitted`](DriverCore::on_admitted) makes the same judgement per reply,
  /// but only for a reply that ARRIVES. A recovery whose cutoff the source has
  /// already consumed answers those requests by cutoff, so if that recovery's own
  /// reply is refused, no per-ticket reply will ever come for them and the covers
  /// sit parked forever. Deriving it from the parked set itself is what makes that
  /// unreachable: the tickets are still there to be seen.
  fn parked_across_worlds(&self) -> bool {
    self
      .pending_admits
      .iter()
      .any(|parked| parked.epoch != self.frame_epoch)
  }

  /// **Whether a whole-root recovery is OWED** — derived from what this scope
  /// holds, never remembered from the transition that made it true.
  ///
  /// Evaluated wherever a recovery could be issued rather than latched at one site
  /// and read at another, which is the whole shape change: there is no debt to
  /// strand, so no state transition can strand one.
  ///
  /// An outstanding round trip is consulted FIRST and answers on its own, in both
  /// directions — see [`pending_recovery`](Self::pending_recovery). While one is
  /// out in the world this scope still holds, its reply will carry the generation,
  /// the cutoff and the cover together, so asking again buys a duplicate
  /// whole-root walk and nothing else; once the world has moved out from under it,
  /// that reply can never be applied here and the round trip is owed again
  /// whatever else is true.
  ///
  /// # Why the retained evidence is not consulted ahead of the round trip
  ///
  /// It looks like it should be: [`Generation::Lost`] is retained evidence and the
  /// pending record is a value compared against a re-read frame, so the cadence
  /// rule seems to order them the other way. It does
  /// not, and the reason is that the two are not answering the same question. The
  /// record answers *is one already out?* — a fact about a message, not a reading
  /// of the world — and consulting the evidence ahead of it would issue a second
  /// whole-root walk for every refresh that lands while the first one's reply is
  /// still in flight, which is a far hotter spin than the one the ordering was
  /// blamed for.
  ///
  /// What made the ordering look wrong was that the record did not mean
  /// "outstanding" any more: a refused reply used to leave it standing. Restore its
  /// one meaning — [`on_root_recovered`](DriverCore::on_root_recovered) discharges
  /// the round trip its reply dominates, refused or applied — and a rejection lands
  /// in the `None` arm, where the retained evidence has always been read. The
  /// ordering needs no change; the field did.
  fn owes_whole_root(&self) -> bool {
    match self.pending_recovery {
      Some(out) if out.epoch == self.frame_epoch => false,
      Some(_) => true,
      None => self.generation_stale() || self.parked_across_worlds(),
    }
  }
}

/// Where a path fell relative to its scope root.
enum Lowered {
  /// The root itself.
  Root,
  /// A descendant, as a root-relative location.
  Target(Location),
  /// Not under the root (above it, unrelated, or unrepresentable) — the
  /// caller escalates, never drops.
  Outside,
}

/// The sans-I/O driver core. See the module docs for the shape.
#[derive(Debug)]
pub(crate) struct DriverCore {
  monitor: Monitor,
  scopes: BTreeMap<ScopeId, ScopeState>,
  watch_scopes: BTreeMap<WatchId, ScopeId>,
  /// Outstanding enumerate requests: the scope whose state mints entry
  /// identities when the raw listing returns, plus the directory the read was
  /// ISSUED against.
  ///
  /// That path is a HISTORICAL fact — where the directory was when this core
  /// asked for its listing — and is deliberately not re-derived on completion.
  /// It is not a second addressing map: nothing arms or opens by it (the
  /// executor lists through the directory's own anchor, which follows the inode
  /// across a rename). Three passes read it, and each is a statement about the
  /// world the read was ISSUED in rather than an address: the cold half of the
  /// exclusion fence, seam 1's own [`record_boundary`], and the ONE-LEVEL
  /// generation [`retire_relisted_boundaries`]. A rename that moves the read
  /// directory across an exclusion boundary is answered by the geometry pass's
  /// located repair ([`reparent_geometry`](Self::reparent_geometry)), whose re-arm
  /// issues a FRESH read against the destination; this in-flight one was compiled
  /// against the pre-move world and is superseded rather than patched. The two
  /// coverage passes cost at most one stale record and one false condemnation on
  /// that path, which the destination's own re-listing repairs — the same bound the
  /// module doc states for the unstamped descending generation.
  enum_reqs: BTreeMap<ReqId, (ScopeId, Arc<PathBuf>)>,
  probes: BTreeMap<ProbeId, ProbeCtx>,
  effects: VecDeque<Effect>,
  /// Terminal `Rescan`s of torn-down scopes, each retried until accepted.
  /// Scope handles are never reused, so a dead scope's key cannot collide
  /// with a live one.
  dying: BTreeMap<ScopeId, DyingDelivery>,
  /// Per-scope set-cover fence bookkeeping (see [`CoverFence`]'s lossy-window
  /// rule). An entry exists exactly while the scope has an unobserved
  /// reconcile OR an unobserved loss signal — created by every `Reconciling`
  /// [`on_set_cover`](Self::on_set_cover) (acked or not, so a reply-less
  /// reconcile's window is still observed and its loss memory still clears)
  /// and by every public scope `Rescan`, whatever the profile (so an
  /// out-of-window loss is remembered, not dropped with the window), removed
  /// by the settle observation or the scope's teardown. No entry may outlive
  /// its scope.
  ///
  /// A kernel-recursive scope takes the mark too: `sync_root` fences any
  /// profile, so exempting it left a real queue overflow invisible to a
  /// pending sync fence.
  cover_fences: BTreeMap<ScopeId, CoverFence>,
  /// Per-scope adoption-seal latch — the ordering proof a STAGED adoption
  /// marker waits on (see [`AdoptionSeal`]). An entry is minted when the scope
  /// is first offered a cut for a staged marker and dropped by
  /// [`resolve_adoption_seals`](Self::resolve_adoption_seals) as soon as the
  /// scope has no staged marker left, so it never outlives the obligation and
  /// never outlives its scope.
  adoption_seals: BTreeMap<ScopeId, AdoptionSeal>,
  /// Fences a scope teardown resolved (always [`CoverSettle::Dead`] — the
  /// terminal `Rescan` covers the caller, and the verdict carries the death
  /// itself because the `TeardownStream` that clears the driver's liveness
  /// maps is only queued at that point), folded into the next
  /// [`poll_cover_settlements`](Self::poll_cover_settlements) so the driver
  /// consumes every resolution at its one loop-top choke point.
  settled_covers: Vec<(FenceId, CoverSettle)>,
  /// Whether a settlement stood a covering `Rescan` and held its tranche for it
  /// (see [`CoverFence::stat_cover`]), so the driver must flush its effects and
  /// resolve again rather than park — the one place a
  /// [`poll_cover_settlements`](Self::poll_cover_settlements) pass leaves work
  /// that no external input will bring it back for. Read and cleared by
  /// [`take_cover_flush_due`](Self::take_cover_flush_due).
  cover_flush_due: bool,
  scope_seq: u64,
  probe_seq: u64,
  fence_seq: u64,
  /// A monotone counter minting [`AdmitTicket`](crate::os::AdmitTicket)s for the
  /// admission round trips a fanotify departure opens. Monotone across the whole
  /// core (not per scope) so a reply from a world this scope has already replaced
  /// can never collide with a ticket parked in the new one.
  admit_seq: u64,
  /// A monotone counter minting move cookies for `FAN_RENAME` pairs. fanotify
  /// reports each rename atomically (both halves in one event), so the cookie
  /// only needs to pair the two records emitted adjacently — a fresh counter
  /// per rename suffices and never clashes across renames.
  cookie_seq: u64,
  /// How often a signal-silent scope (the Linux pair — see
  /// [`liveness_ticked`](DriverCore::liveness_ticked)) re-reads its mount table
  /// and re-stats its root: the composition's one timer (see the per-backend
  /// signal table in the module docs). `Duration::ZERO` disables the tick — only
  /// the loss-triggered refresh then detects a quiet unmount, at the root or
  /// below it. Every scope the gate does not arm ignores it.
  root_liveness_interval: Duration,
  /// The caller's exclusion directories, applied to every scope this core owns
  /// (they are a watcher-wide option, not a per-root one). Empty is the common
  /// case and short-circuits both fences below.
  ///
  /// THE COMMON-LAYER EXCLUSION FENCE, in two halves — the enforcement for every
  /// backend that carries none of its own:
  ///
  /// - [`on_enumerated`](Self::on_enumerated) drops an excluded entry from a cold
  ///   or re-arm listing, so an excluded directory is never staged, never armed
  ///   and never descended;
  /// - [`fence_exclusions`](Self::fence_exclusions) drops a compiled record — or a
  ///   located rescan — whose absolute path is at or under an exclusion, so a
  ///   directory created or moved live under one never enters coverage either,
  ///   and no event from inside one is delivered.
  ///
  /// Placing it HERE rather than in the backends is forced, not stylistic. A
  /// descending backend's only way to decline a directory is to refuse its arm,
  /// and the Monitor reads a refused arm as coverage LOSS: it drops the node and
  /// emits a `Rescan` naming exactly that location. Answering "do not tell me
  /// about this path" with a rescan that names the path is worse than ignoring
  /// the option, so the suppression has to happen BEFORE the Monitor ever learns
  /// the directory exists — which is the enumerate listing and the compiled
  /// record, the two places a directory can enter coverage from. Nothing here
  /// refuses an arm, so nothing here can produce that rescan.
  exclusions: Vec<PathBuf>,
}

impl DriverCore {
  /// Builds a core whose Monitor pairs renames within `move_window` and re-stats
  /// each signal-silent scope's root every `root_liveness_interval`
  /// (`Duration::ZERO` disables that tick).
  pub(crate) fn new(move_window: Duration, root_liveness_interval: Duration) -> Self {
    let mut monitor = Monitor::new(caps_for(BackendKind::FsEvents));
    monitor.set_move_window(move_window);
    Self {
      monitor,
      scopes: BTreeMap::new(),
      watch_scopes: BTreeMap::new(),
      enum_reqs: BTreeMap::new(),
      probes: BTreeMap::new(),
      effects: VecDeque::new(),
      dying: BTreeMap::new(),
      cover_fences: BTreeMap::new(),
      adoption_seals: BTreeMap::new(),
      settled_covers: Vec::new(),
      cover_flush_due: false,
      scope_seq: 0,
      probe_seq: 0,
      fence_seq: 0,
      admit_seq: 0,
      cookie_seq: 0,
      root_liveness_interval,
      exclusions: Vec::new(),
    }
  }

  /// Returns this core enforcing `exclusions` on every scope it registers — the
  /// watcher-wide load-shedding set, applied through the two fences documented on
  /// [`exclusions`](Self::exclusions).
  #[must_use]
  pub(crate) fn with_exclusions(mut self, exclusions: Vec<PathBuf>) -> Self {
    self.exclusions = exclusions;
    self
  }

  /// Whether `path` is at or under one of this core's exclusions — the ONE
  /// matching rule, shared with the sync-cookie birth refusal and with the
  /// fanotify backend's own fence.
  fn excluded(&self, path: &Path) -> bool {
    crate::driver::excluded(&self.exclusions, path)
  }

  /// Where one watch of `state`'s scope IS: the scope root's canonical path
  /// joined with the Monitor's own placement of that watch in its node tree.
  ///
  /// # Derived, never mirrored
  ///
  /// This core keeps no map of watch paths. It kept one once, and the map was a
  /// second description of a tree the Monitor already owns: a rename is answered
  /// by rewriting ONE parent link, which relocates a whole subtree in O(1) and
  /// leaves every absolute path a mirror had stored naming ground the subtree has
  /// left. Repairing that costs a subtree walk per rename, has to be invoked from
  /// wherever renames are noticed, and — being an invocation rather than a
  /// property — is exactly the kind of repair that gets missed on a path nobody
  /// tested. It WAS missed: the repair sat behind the exclusion fence, so the
  /// default configuration (no exclusions) never ran it at all, and every arm and
  /// every enumerate the core dispatched under a moved subtree addressed the old
  /// path while the delivery beside it named the new one.
  ///
  /// Deriving makes the question unaskable. There is one description of where a
  /// watch is, the Monitor's, and reading it cannot be stale because there is
  /// nothing to go stale.
  ///
  /// The cost is real and stated plainly: one parent-chain walk (a map lookup per
  /// level) and one fresh `PathBuf`, against a mirror's single lookup and clone.
  /// It is paid only where a path is actually wanted — dispatching an effect, or
  /// answering the exclusion fence, both of which already allocate a path — and a
  /// scope with no exclusions configured never asks per record at all.
  ///
  /// # Why the root is answered without a walk
  ///
  /// A scope root has no location of its own — it IS the origin — and
  /// [`Monitor::location_of_checked`] correctly answers it with the empty
  /// location. Joining an empty location would yield a trailing separator, and
  /// more importantly the root's path is a fact this core holds directly
  /// (`state.root`, installed by the spawn barrier and by every root swap), so
  /// there is nothing to derive. A watched root never moves inside its own tree.
  ///
  /// # Why the state is passed in
  ///
  /// [`on_batch`](Self::on_batch) DETACHES a scope's [`ScopeState`] from `scopes`
  /// for the duration of one read, so a derivation that looked the scope up
  /// itself would answer `None` for every record of every batch — the fence's
  /// fail-open, silently, on the hot path. Callers that hold a scope id instead
  /// go through [`scoped_path`](Self::scoped_path).
  ///
  /// # Do not store the answer
  ///
  /// See [`Monitor::location_of_checked`]'s own warning. A stored copy is the
  /// mirror this derivation exists to have deleted.
  ///
  /// `None` when the scope has no root yet (registered, not spawned) or when the
  /// Monitor cannot place the watch — a dropped node, a severed ancestry. Never a
  /// SHORT path: `location_of_checked` reports those conditions as `None` rather
  /// than as a truncated location, which is what makes an unresolvable watch
  /// distinguishable from one sitting at the root.
  fn path_of(&self, state: &ScopeState, watch: WatchId) -> Option<PathBuf> {
    let root = state.root.as_deref()?;
    if watch == state.watch {
      return Some(root.clone());
    }
    let mut path = root.clone();
    for segment in self.monitor.location_of_checked(watch)?.segments() {
      path.push(segment.as_str());
    }
    Some(path)
  }

  /// [`path_of`](Self::path_of) for a caller holding a scope ID rather than the
  /// state itself — the drain's route, which looks a scope up per action.
  fn scoped_path(&self, scope: ScopeId, watch: WatchId) -> Option<PathBuf> {
    self.path_of(self.scopes.get(&scope)?, watch)
  }

  /// The absolute path a watch-anchored input addresses: the anchor's own path
  /// joined with the record's root-relative descent.
  ///
  /// One resolution for both lowering profiles, which is what lets ONE fence
  /// cover them: a descending record anchors at the affected directory's own
  /// watch and carries a one-segment name, a kernel-recursive record anchors at
  /// the root watch and carries the whole root-relative location.
  ///
  /// `None` when the anchor cannot be placed ([`path_of`](Self::path_of) — a
  /// superseded or already-dropped watch, or a scope not yet spawned). The fence
  /// then FAILS OPEN — it suppresses nothing. That direction is deliberate:
  /// exclusions are documented as an optimization that correctness never depends
  /// on, so the only cost of not suppressing is a delivery the caller did not
  /// want, whereas suppressing on an unresolved path would drop one it may have
  /// needed.
  fn anchored_path(
    &self,
    state: &ScopeState,
    watch: WatchId,
    descent: Option<&Location>,
  ) -> Option<PathBuf> {
    let mut path = self.path_of(state, watch)?;
    for segment in descent.into_iter().flat_map(Location::segments) {
      path.push(segment.as_str());
    }
    Some(path)
  }

  /// Whether `profile` arms the periodic refresh — the gate for the one timer
  /// this composition adds. TWO silences need it, and a profile arms if it has
  /// either: a root unmount that emits no in-band signal, and a mount DEPARTURE
  /// below the root that emits none.
  ///
  /// The per-backend signal table (design §7; the module docs restate it):
  ///
  /// | backend | root unmount | root delete/replace in-tree | mount departure BELOW the root | tick |
  /// |---|---|---|---|---|
  /// | inotify (descending) | `IN_UNMOUNT` + `IN_IGNORED` — but a LAZY unmount emits NOTHING | `IN_DELETE_SELF`/`IN_MOVE_SELF` | **SILENT** | **yes** |
  /// | FSEvents (macOS) | `RootChanged` | `RootChanged` | the `UNMOUNT` flag word, lowered to `plan_mount`'s located cover | no |
  /// | fanotify (`FAN_MARK_FILESYSTEM`) | **SILENT** (fd goes quiet, mark holds the sb alive — L4.1) | `FAN_DELETE_SELF`/`FAN_MOVE_SELF` | **SILENT** | **yes** |
  /// | RDCW (Windows) | fatal source error on any terminal read completion | same signal | **SILENT** (deferred) | no |
  /// | USN journal (Windows) | fatal source error on a failed journal read | `RootDeath` (the root's own FRN in a delete/rename record) | **SILENT** (deferred) | no |
  ///
  /// This gate used to state *"only fanotify's unmount is signal-silent, so only
  /// fanotify arms the tick"*, which #74 measured false: an inotify watch on a
  /// subdirectory SURVIVED a lazy unmount and remount of its mount with no
  /// delivery, no `Rescan`, and nothing else at all, for 120 s. `umount -l`
  /// detaches the subtree from the namespace while the watch itself keeps the
  /// superblock alive, so the `IN_UNMOUNT` the eager path emits never comes —
  /// neither for the root (this tick's folded-in re-stat catches that) nor for
  /// any mount below it (the mount-departure diff the same refresh runs catches
  /// that; see [`on_mounts_refreshed`](Self::on_mounts_refreshed)).
  ///
  /// The two Windows rows share the below-root hole and are DEFERRED by owner
  /// ruling, not by any property of this composition — everything the tick feeds
  /// is profile-agnostic — so admitting them later is an edit to this `matches!`
  /// plus their own cells. FSEvents is the one profile that genuinely needs
  /// neither half: `RootChanged` covers its root and the `UNMOUNT` word covers
  /// every departure below it.
  const fn liveness_ticked(profile: BackendKind) -> bool {
    matches!(profile, BackendKind::Fanotify | BackendKind::Inotify)
  }

  /// Mints the next `FAN_RENAME` pairing cookie.
  fn next_cookie(&mut self) -> MoveCookie {
    self.cookie_seq += 1;
    MoveCookie::new(NonZeroU64::new(self.cookie_seq).expect("cookie counter starts at one"))
  }

  /// Registers a new watched root, returning its scope handle. Queues the
  /// [`Effect::SpawnStream`] that starts the native source.
  ///
  /// Fallible only because the Monitor refuses a scope that already has a
  /// registered root. The mint below is monotonic and never reuses a value, so
  /// the branch is dead by construction HERE — it is propagated rather than
  /// `expect`ed because the Monitor's guard exists for out-of-tree drivers, and
  /// an assertion in this crate's only caller would answer their mistake with a
  /// panic instead of the refusal. Nothing is registered on the error path.
  pub(crate) fn on_watch(
    &mut self,
    root: PathBuf,
    interest: Interest,
    profile: BackendKind,
  ) -> Result<ScopeId, WatchRootError> {
    self.scope_seq += 1;
    let scope = ScopeId::new(NonZeroU64::new(self.scope_seq).expect("sequence starts at one"));
    let Some(watch) = self
      .monitor
      .register_root_with_profile(scope, interest, caps_for(profile))
    else {
      return Err(WatchRootError::ScopeInUse);
    };
    self.scopes.insert(
      scope,
      ScopeState {
        watch,
        root_attempt: None,
        profile,
        requested: root,
        root: None,
        root_dev: None,
        root_mnt_id: None,
        root_incarnation: None,
        frame_epoch: 0,
        generation: Generation::Verified { epoch: 0 },
        pending_recovery: None,
        published_epoch: None,
        identity: None,
        mount_table: Vec::new(),
        learned_mounts: Vec::new(),
        mounts_authoritative: false,
        census: Vec::new(),
        ledger: Vec::new(),
        pending_admits: Vec::new(),
        refresh_pending: false,
        refresh_stale: false,
        refresh_world_stale: false,
        lag: LagState::Normal,
        park: Park::default(),
        resume_poisoned: false,
        publicly_live: false,
        liveness_deadline: None,
        applied_cover: None,
        settle_floor: None,
        pending_widen: None,
      },
    );
    self.watch_scopes.insert(watch, scope);
    self.drain_monitor();
    Ok(scope)
  }

  /// Unregisters a watched root; its teardown effect follows.
  pub(crate) fn on_unwatch(&mut self, scope: ScopeId) {
    if self.scopes.contains_key(&scope) {
      self.monitor.unregister_root(scope);
      self.drain_monitor();
    }
  }

  /// Reconciles `scope`'s per-directory kernel coverage to the `retained` cover **in place**,
  /// **bidirectionally** (the set-cover reconcile): it BOTH prunes every descended watch
  /// strictly OUTSIDE the cover AND re-arms any retained subtree the scope is not currently
  /// covering — while leaving every retained subtree that is already covered, and the
  /// connecting ancestors from the root down to each, untouched. Neither the retained-and-
  /// covered watches nor the connecting ancestors are ever re-armed, so their events keep
  /// flowing with **no gap and no re-crawl** (the shrink-in-place property); only the
  /// previously-pruned corner is grown back.
  ///
  /// `retained` is the antichain of canonical absolute paths some surviving consumer still
  /// needs. A watch at path `P` is KEPT by the prune iff some retained `R` satisfies
  /// `P.starts_with(R)` (P lies in a retained subtree) OR `R.starts_with(P)` (P is a
  /// connecting ancestor a retained subtree descends from); it is pruned only when strictly
  /// outside **every** retained prefix, so no retained key ever routes through a pruned watch.
  /// A retained prefix with **no live watch at its own path** — one an EARLIER, narrower cover
  /// pruned — is re-armed by re-arming its deepest still-watched ancestor (the root is always
  /// one), whose recursive re-arm re-installs the pruned directory and everything between; the
  /// re-arm emits no `Created` and no `Rescan`, so it silently restores coverage the way the
  /// prune silently reclaims it.
  ///
  /// # Why the grow half exists
  ///
  /// A prune-only set-cover cannot restore coverage: after an applied prune of `/a/c`, a later
  /// consumer watching `/a/c` again (subsumed under the still-armed wide root — `Covered` at
  /// the umbrella, no re-arm) would sit over a hole no per-directory watch backs, silently
  /// missing every deep change. The umbrella now re-issues the FRESH cover (including that
  /// newcomer) on the `Covered` commit, and this grow half is what turns that re-issue into
  /// real coverage again.
  ///
  /// **Best-effort and correctness-neutral.** The caller (the umbrella's set-cover seam)
  /// computes `retained` from the live survivors, so the prune only ever removes coverage no
  /// consumer is subscribed under and the grow only ever re-arms coverage a survivor needs: a
  /// partial or skipped prune merely leaves the root briefly over-broad (self-healing), and a
  /// skipped grow merely leaves the newcomer briefly under-covered until the umbrella's own
  /// bridging `Rescan` and a later re-issue converge — neither loses an event under a retained,
  /// covered key, and neither emits a `Rescan`.
  ///
  /// # Refusals
  ///
  /// A [`Noop`](CoverReconcile::Noop) — no prune, no grow, `applied_cover` and the settle
  /// floor untouched — for:
  ///
  /// - an **unknown scope** ([`UnknownScope`](CoverNoop::UnknownScope));
  /// - a scope that is **not publicly live** ([`NotLive`](CoverNoop::NotLive)) — no caller
  ///   holds a handle between a descending scope's spawn and its root-arm grant, so there is no
  ///   coverage CLAIM to reconcile: the registration's own crawl is installing all of it (see
  ///   [`NotLive`](CoverNoop::NotLive) for the sharper reason this clause used to carry, and
  ///   why it is now the design rather than the harm);
  /// - a **kernel-recursive** scope (fanotify / FSEvents;
  ///   [`KernelRecursive`](CoverNoop::KernelRecursive)): its single whole-subtree stream has no
  ///   per-directory children, so coverage never narrowed and there is nothing to prune or
  ///   re-arm — reported explicitly rather than walked as silence, so the driver can answer
  ///   "recursive" instead of "applied";
  /// - a **refused cover** ([`RefusedCover`](CoverNoop::RefusedCover)): empty `retained`
  ///   (defensive — never prune the whole tree) or a cover ENTIRELY outside the live root (a
  ///   caller error — validated against the scope root and refused before any prune, so a typo /
  ///   relative / stale path can never silently prune the whole scope). A PARTIALLY out-of-root
  ///   cover proceeds with the in-root subset only.
  ///
  /// Otherwise [`Reconciling`](CoverReconcile::Reconciling): the walk ran, and each pruned
  /// watch's [`RemoveWatch`](Effect::RemoveWatch) and each grown watch's
  /// [`AddWatch`](Effect::AddWatch) / [`Enumerate`](Effect::Enumerate) flow through the ordinary
  /// descending paths, keeping the reader's `wd` table and the core's watch-to-scope map
  /// consistent exactly as delete-driven and create-driven transitions do. A `Reconciling` return also
  /// updates the fence bookkeeping: the scope's [`CoverFence`] entry is (re)ensured so the next
  /// settle observation sees this window, any `Coalesced` grow kickoff records the born-lossy
  /// memory (see [`CoverFence`]), and `applied_cover` / `settle_floor` are recorded
  /// (optimistically / as the running meet).
  #[must_use = "the disposition routes the acknowledgement: a Noop is answered immediately, a Reconciling may owe a fence"]
  pub(crate) fn on_set_cover(&mut self, scope: ScopeId, retained: &[PathBuf]) -> CoverReconcile {
    let Some(state) = self.scopes.get(&scope) else {
      return CoverReconcile::Noop(CoverNoop::UnknownScope);
    };
    // The publicly-live gate (see the refusal table above): pre-grant there is no
    // coverage claim to reconcile — the registration's own crawl owns all of it.
    if !state.publicly_live {
      return CoverReconcile::Noop(CoverNoop::NotLive);
    }
    // Kernel-recursive coverage never narrowed: refuse explicitly (the walk below would be
    // a structural no-op, but recording `applied_cover` for it would misstate that the
    // whole-subtree stream was ever reconciled).
    if state.profile.is_kernel_recursive() {
      return CoverReconcile::Noop(CoverNoop::KernelRecursive);
    }
    // An empty cover would mark every node strictly-outside (vacuously) and prune the
    // whole scope; the umbrella never requests it, but never risk collapsing coverage.
    if retained.is_empty() {
      return CoverReconcile::Noop(CoverNoop::RefusedCover);
    }
    // Validate the retained cover against the LIVE scope root before acting on it. A
    // retained path that is not under the root — a caller typo, a relative or stale path — lies
    // strictly OUTSIDE every in-root watch, so an UNVALIDATED cover would mark the whole scope
    // outside and SILENTLY PRUNE ALL coverage. Keep only paths within the root (the root itself
    // allowed). The prefix test is LEXICAL, and `Path::starts_with` does not resolve `..` — so a
    // path like `root/../elsewhere` lexically begins with the root while escaping it (
    // ). A CANONICAL retained path never contains `.`/`..` components (the scope root and
    // every survivor cover the umbrella issues are canonical), so any path carrying one is a
    // caller error: reject it outright rather than guessing what it resolves to. A root not yet
    // known cannot validate anything — unreachable behind the publicly-live gate (a live scope
    // always spawned), kept as the defensive not-live answer.
    let Some(root) = state.root.clone() else {
      return CoverReconcile::Noop(CoverNoop::NotLive);
    };
    let retained: Vec<PathBuf> = retained
      .iter()
      .filter(|path| {
        path.starts_with(root.as_path())
          && !path.components().any(|component| {
            matches!(
              component,
              std::path::Component::ParentDir | std::path::Component::CurDir
            )
          })
      })
      .cloned()
      .collect();
    // An ENTIRELY out-of-root cover is a caller error the core refuses to act on: do NOT prune and
    // do NOT record `applied_cover`, leaving the prior (still-correct) coverage untouched. A
    // PARTIALLY valid cover proceeds with the valid subset ONLY — the invalid prefixes are dropped.
    if retained.is_empty() {
      return CoverReconcile::Noop(CoverNoop::RefusedCover);
    }
    let retained = retained.as_slice();

    let root_watch = state.watch;
    // The cover the previous reconcile settled on: the grow keys its re-arm on the delta
    // against THIS, not on which watches survive.
    let prev_cover = state.applied_cover.clone();

    // --- PRUNE (the shrink half): drop every descended watch strictly OUTSIDE the cover ---
    // This scope's descended (non-root) watches strictly OUTSIDE every retained prefix,
    // shallowest first — so a maximal outside subtree is dropped at its top and its
    // deeper descendants are already gone (skipped by the `is_watched` guard) when
    // reached. The root is never a candidate (it is an ancestor of every retained key).
    let mut outside: Vec<(usize, WatchId)> = self
      .watch_scopes
      .iter()
      .filter(|(watch, watch_scope)| **watch_scope == scope && **watch != root_watch)
      .filter_map(|(watch, _)| {
        let path = self.path_of(state, *watch)?;
        let strictly_outside = retained
          .iter()
          .all(|r| !path.starts_with(r) && !r.starts_with(path.as_path()));
        strictly_outside.then(|| (path.components().count(), *watch))
      })
      .collect();
    outside.sort_unstable_by_key(|(depth, _)| *depth);
    // Whether the shrink half actually dropped coverage — the Monitor's own answer, not an
    // inference from the requested cover, because a cover naming subtrees this scope no longer
    // watches prunes nothing.
    let mut pruned = false;
    for (_, watch) in outside {
      // A node an ancestor's drop already reclaimed is no longer watched — skip it (the
      // shallow-first order guarantees the ancestor was processed first).
      if self.monitor.is_watched(watch) {
        pruned |= self.monitor.drop_watch_subtree(watch);
      }
    }

    // --- GROW (the set-cover dual): re-arm the BROADENING DELTA against the PREVIOUS cover ---
    // A retained prefix is re-armed iff the previously-applied cover did NOT already cover it
    // ([`broadening_delta`]): its subtree was pruned under that cover, so a watch may still sit
    // at its own path merely as a connecting ANCESTOR while its descendants are gone. Keying on
    // the delta rather than on exact-path watch presence is exactly what re-arms those pruned
    // descendants when growing back to a retained ancestor (`/a/b/deep` → `/a/b`) or to the
    // whole root. For each delta prefix, re-arm the DEEPEST still-watched
    // ancestor-OR-SELF: its recursive re-arm re-reads that directory, re-installs every
    // previously-pruned directory beneath it, and cascades down — with no `Created` and no
    // `Rescan`. Dedup by target watch, so sibling delta prefixes sharing one ancestor re-arm
    // it once.
    let mut to_rearm: BTreeSet<WatchId> = BTreeSet::new();
    for r in broadening_delta(prev_cover.as_deref(), retained) {
      // The deepest still-watched ancestor-or-self of `r` in this scope. The root is always an
      // ancestor of every retained prefix, so a prefix under the root always finds one; a `None`
      // (a prefix somehow above/outside the root) simply grows nothing.
      let deepest = self
        .watch_scopes
        .iter()
        .filter(|(_, watch_scope)| **watch_scope == scope)
        .filter_map(|(watch, _)| {
          let path = self.path_of(state, *watch)?;
          r.starts_with(&path)
            .then(|| (path.components().count(), *watch))
        })
        .max_by_key(|(depth, _)| *depth);
      if let Some((_, watch)) = deepest {
        to_rearm.insert(watch);
      }
    }
    // Kick off the ANTICHAIN of the targets only: a target inside another target's
    // subtree is dropped, because the shallower target's recursive re-arm already
    // re-reads it — and kicking both would land the ancestor's cascade on the
    // descendant's own in-flight re-arm read, dirtying it into an escalation
    // `Rescan` (an honest `Degraded`, but for a collision this reconcile itself
    // manufactured). Ancestor+descendant targets arise whenever the delta holds a
    // pruned prefix (re-armed at a shallow surviving ancestor) alongside a
    // still-watched one (re-armed at itself) — the degraded-claim full delta after
    // a loss being the canonical case.
    let targets: Vec<WatchId> = to_rearm
      .iter()
      .filter(|watch| {
        !to_rearm.iter().any(|other| {
          other != *watch
            && matches!(
              (self.path_of(state, **watch), self.path_of(state, *other)),
              (Some(path), Some(ancestor)) if path.starts_with(&ancestor)
            )
        })
      })
      .copied()
      .collect();
    // A `Coalesced` kickoff folded its obligation into an in-flight COLD read the settle
    // counter deliberately does not see: the scope can read settled while the obligation is
    // latent, so the fence window is lossy FROM BIRTH (the F0 amendment).
    let mut coalesced = false;
    // Whether the grow half actually recorded a re-arm obligation — again the Monitor's answer:
    // a `Refused` kickoff (a target the tree no longer holds) grows nothing.
    let mut grew = false;
    for watch in targets {
      let kickoff = self.monitor.rearm_watch_subtree(watch);
      coalesced |= kickoff.is_coalesced();
      grew |= !kickoff.is_refused();
    }

    // Fence bookkeeping BEFORE the drain, so an entry exists when any change this reconcile
    // provokes routes: ensure the scope's entry (the next settle observation must see this
    // window even when the reconcile is reply-less — that observation resets the floor on a
    // clean settle and clears the loss memory), and record the born-lossy memory, which marks
    // every already-pending fence and is inherited by any fence opened before the scope next
    // settles (see [`CoverFence`]).
    let fence = self.cover_fences.entry(scope).or_default();
    // A reconcile that MOVED coverage extended the window past whatever a standing
    // ordering proof was taken over, so that proof licenses nothing about what it
    // now holds. Reset it: the proof is asked for again at the next quiescence, and
    // a reply still in flight for the spent request finds `Unproven` and correctly
    // no-ops. The epoch binding does not subsume this — a prune only RELEASES work,
    // so no funnel bumps the epoch even though the coverage under the proof changed.
    //
    // A reconcile that grew nothing and pruned nothing extended nothing, and its
    // window is exactly the one the standing proof already orders. Invalidating
    // there would be worse than a wasted round trip: reply-less re-issues of a
    // settled cover can arrive faster than a cut completes, so every completed
    // proof would land on a latch a later re-issue had already reset, and the
    // window would never settle clean at all (see [`CutProof`]).
    if pruned || grew {
      fence.cut.invalidate();
    }
    if coalesced {
      fence.mark_lossy();
    }

    // Turn the queued `Action::Unwatch`es (prune) into `RemoveWatch` effects and the queued
    // `Action::Watch`/`Enumerate`s (grow) into `AddWatch`/`Enumerate` effects, and reconcile
    // the watch-to-scope map, exactly as Monitor-driven drops and descents do. A no-op when
    // both halves queued nothing.
    self.drain_monitor();

    // Record the cover just applied: the NEXT set-cover computes its broadening delta against it
    //. Stored verbatim; `broadening_delta` treats the init `None` as full, and a
    // full-root cover (retained = the root's own path) yields an empty delta for any later shrink
    // exactly as `None` would. The record is OPTIMISTIC (the grow's re-arm work has not
    // completed), so the settle floor keeps the running meet the lossy-settle rewind falls back
    // to (see `ScopeState::settle_floor`).
    if let Some(state) = self.scopes.get_mut(&scope) {
      state.settle_floor = Some(cover_meet(state.settle_floor.as_deref(), retained));
      state.applied_cover = Some(retained.to_vec());
    }
    CoverReconcile::Reconciling
  }

  /// Opens one settlement fence for `scope`: the driver parks an acked
  /// `set_cover`'s reply under the returned id and resolves it with the
  /// [`CoverSettle`] the next [`poll_cover_settlements`](Self::poll_cover_settlements)
  /// reports for it. Call it immediately after the
  /// [`Reconciling`](CoverReconcile::Reconciling) `on_set_cover` it acknowledges
  /// (before any other core input), so the fence cannot miss its own
  /// reconcile's window: it inherits the scope's loss memory accrued since the
  /// last settle observation — including a born-lossy `Coalesced` grow — per
  /// [`CoverFence`]'s rule.
  ///
  /// The fence takes the entry's next open ordinal, and that is what keeps it
  /// from inheriting an ordering proof older than itself: a proof licenses only
  /// the fences that were already pending when it was requested, and this one
  /// was not (see [`CutProof`]). Standing proofs and requests in flight are
  /// left untouched — they still order the fences they were bought for, and the
  /// successor this fence needs is asked for once they land.
  pub(crate) fn open_cover_fence(&mut self, scope: ScopeId) -> FenceId {
    self.fence_seq += 1;
    let fence = FenceId(self.fence_seq);
    self.cover_fences.entry(scope).or_default().open(fence);
    fence
  }

  /// How many acknowledged reconciles `scope` currently holds pending on its
  /// coverage fence — the core's half of one admitted `set_cover`, minted by
  /// [`open_cover_fence`](Self::open_cover_fence) together with the driver's
  /// parked reply sender and released together with it. The driver reads this as
  /// the admission bound for awaited reconciles, so neither half can grow past
  /// the cap while a scope's proof round trip is stalled.
  pub(crate) fn pending_cover_fences(&self, scope: ScopeId) -> usize {
    self
      .cover_fences
      .get(&scope)
      .map_or(0, |entry| entry.pending.len())
  }

  /// Whether `scope` still carries a coverage-fence ENTRY at all — the memory a
  /// fence opened right now would inherit.
  ///
  /// [`pending_cover_fences`](Self::pending_cover_fences) cannot answer this: an
  /// entry holding no pending fence reads zero there while still carrying the
  /// scope's accrued `lossy` memory, and that is exactly the state a routed
  /// `Rescan` leaves behind until a settle observation spends it (see
  /// [`CoverFence`]). A registration window's closing `Rescan` therefore stands
  /// across the gap between its routing and the ordering-proof round trip that
  /// lets the observation clear the entry, and a fence opened inside that gap
  /// inherits the loss and settles `Degraded` — honestly for the product, and
  /// fatally for a cell staging a clean baseline. Staging that means "this scope
  /// has nothing accrued" waits on the ENTRY going, not on the pending count.
  ///
  /// Test-only, gated to the driver suite that consumes it.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn holds_cover_fence_entry(&self, scope: ScopeId) -> bool {
    self.cover_fences.contains_key(&scope)
  }

  /// Drops the pending records of `abandoned` fences — callers that cancelled their
  /// `set_cover` await before the settle. Only the per-fence records go: the scope's
  /// loss memory, its settle-floor bookkeeping, and every still-awaited fence stay
  /// untouched, so the settle observation's cover repair is unaffected. Without this,
  /// a caller repeatedly issuing-and-cancelling against a scope whose re-arm work is
  /// stalled would accumulate one pending record per processed request indefinitely —
  /// the bounded command mailbox limits only instantaneous traffic, never the total.
  pub(crate) fn abandon_cover_fences(&mut self, abandoned: &std::collections::BTreeSet<FenceId>) {
    if abandoned.is_empty() {
      return;
    }
    for entry in self.cover_fences.values_mut() {
      entry
        .pending
        .retain(|pending| !abandoned.contains(&pending.fence));
    }
  }

  /// Reports every set-cover fence that has settled since the last poll: each
  /// scope with an unobserved reconcile whose coverage work quiesced
  /// ([`Monitor::coverage_settled`] — the counted re-arm work of
  /// [`Monitor::rearm_settled`], plus the held-move and latent-cold-read
  /// windows a sync cookie must not dispatch inside) resolves ALL its pending
  /// fences at this one settle instant — in FIFO open order, each with its
  /// recorded lossiness ([`Applied`](CoverSettle::Applied) /
  /// [`Degraded`](CoverSettle::Degraded)) — plus every fence a scope teardown
  /// already resolved [`Dead`](CoverSettle::Dead). The driver polls this at
  /// its loop top, after feeding results back.
  ///
  /// A settled scope resolves the fences its ordering proof licenses — the
  /// prefix of its pending list the proof was requested behind (see
  /// [`CutProof`]) — and holds any that opened past it, which are offered a
  /// successor proof and resolve at a later pass. A lossy window owes that proof
  /// exactly as a clean one does: what the cut surfaces is an unread death, and
  /// a `Degraded` dispatches its caller's cookie onto a stream just as an
  /// `Applied` does. Only a scope that can obtain no proof is exempt — a
  /// kernel-recursive one, whose control batches never reach a reader — and it
  /// resolves whole.
  ///
  /// The settle observation is also where the applied-cover lie is repaired:
  /// a LOSSY window rewinds `applied_cover` to the settle floor (the provable
  /// under-claim, so a re-issue recomputes a real broadening delta); a CLEAN
  /// window resets the floor to the now-truthful `applied_cover`. That repair
  /// rides the entry's removal, so it waits for the LAST pending fence: a claim
  /// is never promoted over a stretch of the window no proof has ordered yet.
  /// Once the entry goes, no fence state outlives it — pending fences and loss
  /// memory alike.
  /// The settle-fence gate: exactly the Monitor's barrier predicate
  /// ([`Monitor::coverage_settled`]), with no core-side conjunct. The widen
  /// window needs none: pre-commit, fences certify the OLD world, whose
  /// coverage is genuinely live and unchanged (the zero-gap half); the commit
  /// itself is gated on the witnessed window (INV-ROOT —
  /// [`on_root_widened`](Self::on_root_widened)), so by the time a fence can
  /// consult this gate over the widened world the binding was proven live at
  /// the commit or the widen fell back to a fresh spawn barrier. A scope with
  /// no state resolves through the teardown fold below, never through this
  /// gate.
  fn barrier_settled(&self, scope: ScopeId) -> bool {
    self.monitor.coverage_settled(scope)
  }

  /// Whether the next [`poll_cover_settlements`](Self::poll_cover_settlements)
  /// would OBSERVE at least one scope — some scope with fence bookkeeping
  /// whose coverage barrier currently holds. The driver consults this before
  /// resolving so it can first ingest every source message already queued:
  /// loss signals and arm ACKs travel on two unordered channels, and an
  /// observation taken while a loss for the scope is queued-but-unseen would
  /// certify a clean window the loss already voided (and reset the settle
  /// floor to a cover the loss is about to invalidate). Teardown-folded
  /// settles need no such fence — their verdict is already `Dead`, which more
  /// loss cannot falsify — so they do not arm this probe. They are still
  /// delivered promptly: the driver's loop-top resolve is unconditional.
  pub(crate) fn cover_settlement_due(&self) -> bool {
    self
      .cover_fences
      .keys()
      .any(|scope| self.barrier_settled(*scope))
  }

  /// The scopes whose barrier has quiesced but which have not yet forced the
  /// source to surface what the kernel holds — see [`CutProof`].
  ///
  /// Reporting does NOT latch: the caller may decline a scope — a stream that is
  /// already gone has nothing to ask — and a request spent on a batch nobody
  /// sends could only ever be closed by a reply that never comes, parking the
  /// fence until its scope dies. So the caller latches with
  /// [`mark_cut_inflight`](Self::mark_cut_inflight) once it has committed to
  /// sending, and a declined scope simply reappears here next pass.
  ///
  /// A LOSSY fence is returned like any other, and the offer is the half of that
  /// rule that keeps it live: the settle gate below requires a proof of every
  /// live fence, so a fence that is never OFFERED one would wait for it forever.
  /// The two sides carry the same exemption and no other, which is what makes
  /// "asked for iff required" hold rather than merely be intended.
  ///
  /// A scope whose latch does not speak for its whole pending set IS returned,
  /// for either of the two reasons a latch can fall short: the coverage work it
  /// was stamped against has moved on, so it licenses nothing at all; or a
  /// fence has opened past the tranche the proven prefix reaches, so it licenses
  /// nothing for THAT fence. Either way a fence would otherwise wait on a reply
  /// that cannot certify it. A request still in flight under the current epoch
  /// is not re-asked for — see [`CutProof`]'s convergence rule, which is what
  /// bounds a fence's wait however fast fences arrive.
  ///
  /// Those two cases leave no gap between them, which is the property a fence's
  /// liveness rests on: a settled clean window holding a fence its prefix does
  /// not reach is offered a cut unless one is already out under the current
  /// epoch, and both ways that request can end — its own completion, which
  /// raises the prefix, and the epoch moving out from under it, which retires
  /// it where it stands — put the window straight back here.
  ///
  /// The offer and the latch below share one predicate, so the caller can
  /// always latch what it was offered.
  pub(crate) fn covers_awaiting_cut(&self) -> Vec<ScopeId> {
    self
      .cover_fences
      .iter()
      .filter(|(scope, entry)| {
        self.cut_proof_required(**scope)
          && self.barrier_settled(**scope)
          && !entry
            .cut
            .answers_for(self.coverage_epoch(**scope), entry.high_water())
      })
      .map(|(scope, _)| *scope)
      .collect()
  }

  /// The coverage-work epoch a cut proof for `scope` is stamped with and
  /// checked against — see [`CutProof`].
  fn coverage_epoch(&self, scope: ScopeId) -> CoverageWorkEpoch {
    self.monitor.coverage_work_epoch(scope)
  }

  /// Whether `scope`'s live verdicts need an ordering proof at all.
  ///
  /// Only a per-directory-watch scope can hold an unread kernel queue a fence
  /// would resolve over, and only such a scope has a control port whose batch a
  /// reader answers — so a kernel-recursive scope can neither need the proof nor
  /// obtain one, and asking would strand its settles rather than protect them. A
  /// scope whose state is gone needs nothing: its fences resolve at the teardown
  /// fold.
  fn cut_proof_required(&self, scope: ScopeId) -> bool {
    self
      .scopes
      .get(&scope)
      .is_some_and(|state| !state.profile.is_kernel_recursive())
  }

  /// Latches `scope`'s fence as having the ordering-proof request `token` in
  /// flight, so it is asked for exactly one however many passes the reply takes.
  /// Called only once the caller has committed to sending that batch.
  ///
  /// The request is stamped with the scope's CURRENT coverage-work epoch and
  /// with the newest ordinal currently pending — the tranche this proof will be
  /// able to license — both of which its proof inherits and is checked against
  /// at the settle, so the caller needs no bookkeeping of its own. Latching is
  /// refused only when the latch already speaks for that pair, which is exactly
  /// when [`covers_awaiting_cut`](Self::covers_awaiting_cut) would not have
  /// offered the scope: what it offers, this always latches. Latching displaces
  /// whatever request was out, so the batch that carried it can no longer prove
  /// anything — which is why an in-flight request under the current epoch is
  /// never displaced merely because a fence opened behind it. The proven prefix
  /// is untouched either way: a successor asks about the fences beyond it and
  /// says nothing about the ones it already reaches.
  pub(crate) fn mark_cut_inflight(&mut self, scope: ScopeId, token: u64) {
    let epoch = self.coverage_epoch(scope);
    if let Some(entry) = self.cover_fences.get_mut(&scope) {
      let covers = entry.high_water();
      if !entry.cut.answers_for(epoch, covers) {
        entry.cut.latch(token, CutMark::new(epoch, covers));
      }
    }
  }

  /// Records that `scope`'s source answered a control batch, whose reply the
  /// reader's pre-reply cut precedes — so anything the kernel held is now on
  /// the lane, ahead of this.
  ///
  /// Only the request actually in flight is closed, and only by its OWN token —
  /// which is what makes every stale completion inert. A window extended by a
  /// reconcile discards the latch, so a reply for the request that predated it
  /// matches nothing; and a PREDECESSOR batch of the same scope, whose cut was
  /// taken before this request existed, carries a different token and cannot
  /// close it either. The caller supplies the token only for a batch that ran to
  /// completion, so an unwinding batch proves nothing.
  ///
  /// The proof inherits the REQUEST's epoch and mark, not the scope's now: the
  /// cut ordered the window as it stood when the request was committed to, so
  /// work the scope acquired while the batch was out is outside it and must
  /// leave the proof stale rather than be absorbed into it, and a fence opened
  /// while the batch was out is outside it and must wait for a successor rather
  /// than be swept into this one. It RAISES the proven prefix (see
  /// [`CutProof`]), so a completion can only ever extend what the entry has
  /// earned.
  pub(crate) fn prove_cut(&mut self, scope: ScopeId, token: u64) {
    if let Some(entry) = self.cover_fences.get_mut(&scope) {
      entry.cut.prove(token);
    }
  }

  /// The scopes whose staged adoption markers have not yet forced the source to
  /// surface what the kernel holds — see [`AdoptionSeal`].
  ///
  /// `lane_of` reports a scope's CURRENT delivery lane, which the latch is
  /// stamped with: a latch naming any other lane speaks for a queue the scope
  /// has stopped reading, and is re-offered rather than waited on. The driver
  /// owns that number, so it is asked for it here rather than mirroring it.
  ///
  /// Reporting does NOT latch, for the same reason
  /// [`covers_awaiting_cut`](Self::covers_awaiting_cut) does not: the caller may
  /// decline a scope whose stream is already gone, and a request spent on a
  /// batch nobody sends could only ever be closed by a reply that never comes.
  /// A declined scope simply reappears next pass.
  ///
  /// The offer and [`mark_adoption_cut_inflight`](Self::mark_adoption_cut_inflight)
  /// share one predicate, so the caller can always latch what it was offered.
  pub(crate) fn adoptions_awaiting_cut(&self, lane_of: &impl Fn(ScopeId) -> u64) -> Vec<ScopeId> {
    self
      .monitor
      .staged_adoption_scopes()
      .into_iter()
      .filter(|(scope, high_water)| {
        self.cut_proof_required(*scope)
          && !self
            .adoption_seals
            .get(scope)
            .is_some_and(|seal| seal.answers_for(lane_of(*scope), *high_water))
      })
      .map(|(scope, _)| scope)
      .collect()
  }

  /// Latches `scope`'s seal as having the ordering-proof request `token` in
  /// flight on `lane`, so it is asked for exactly one however many passes the
  /// reply takes. Called only once the caller has committed to sending that
  /// batch.
  ///
  /// The request is stamped with the newest staging the scope currently holds —
  /// the stagings this proof will be able to license — which its proof inherits
  /// and the seal is checked against, so the caller needs no bookkeeping of its
  /// own. A latch on a lane the scope has left is rebuilt from nothing rather
  /// than extended: neither its prefix nor its request orders the queue the
  /// scope now reads.
  pub(crate) fn mark_adoption_cut_inflight(&mut self, scope: ScopeId, lane: u64, token: u64) {
    let Some(high_water) = self.monitor.adoption_staging_high_water(scope) else {
      return;
    };
    let seal = self
      .adoption_seals
      .entry(scope)
      .or_insert_with(|| AdoptionSeal::new(lane));
    if seal.lane != lane {
      *seal = AdoptionSeal::new(lane);
    }
    if !seal.answers_for(lane, high_water) {
      seal.latch(token, high_water);
    }
  }

  /// Records that `scope`'s source answered, on `lane`, a control batch carrying
  /// the seal request `token` — whose reply the reader's pre-reply cut precedes,
  /// so anything the kernel held is now on the lane, ahead of this.
  ///
  /// Only the request actually in flight is closed, and only by its OWN token
  /// and its OWN lane, which is what makes every stale completion inert: a
  /// predecessor batch's cut was taken before this request existed, and a batch
  /// answered on a retired transport cut a queue this scope no longer reads.
  pub(crate) fn prove_adoption_cut(&mut self, scope: ScopeId, lane: u64, token: u64) {
    if let Some(seal) = self.adoption_seals.get_mut(&scope)
      && seal.lane == lane
    {
      seal.prove(token);
    }
  }

  /// Whether the next [`resolve_adoption_seals`](Self::resolve_adoption_seals)
  /// would release at least one staged marker — some scope holding a proven
  /// prefix that reaches a marker still staged.
  ///
  /// The driver consults this to arm the same source drain a cover settlement
  /// arms, and for the same reason: the verdict may only be taken over a lane
  /// nobody is still reading. Free for a scope that owes no seal — the latch map
  /// is empty outside a widen's confirm window.
  pub(crate) fn adoption_seal_due(&self, lane_of: &impl Fn(ScopeId) -> u64) -> bool {
    self.adoption_seals.iter().any(|(scope, seal)| {
      seal
        .licenses_through(lane_of(*scope))
        .is_some_and(|through| self.monitor.adoption_staged_through(*scope, through))
    })
  }

  /// Releases every staged adoption marker an answered cut has ordered, at the
  /// driver's one choke point — after the drain that fed the lane to spent, and
  /// never for a scope the drain did not finish.
  ///
  /// The withholding is the same rule a cover settlement takes and it is owed
  /// for a stronger reason: the whole point of the cut is to put a refuting
  /// record on the lane, so a verdict taken while that lane still holds unread
  /// items would resolve over exactly the record the round trip was bought to
  /// surface.
  ///
  /// Sweeping first is the seal latch's clear-on-empty edge: a scope with no
  /// staged marker owes no seal, so its latch — proven prefix and request in
  /// flight alike — is dropped where it stands rather than left to answer for an
  /// obligation that no longer exists. That is what keeps a request whose reply
  /// can never arrive from being mistaken for one that still might.
  pub(crate) fn resolve_adoption_seals(
    &mut self,
    lane_of: &impl Fn(ScopeId) -> u64,
    unspent: &std::collections::BTreeSet<ScopeId>,
  ) {
    let monitor = &self.monitor;
    self
      .adoption_seals
      .retain(|scope, _| monitor.adoption_staging_high_water(*scope).is_some());
    let due: Vec<(ScopeId, u64)> = self
      .adoption_seals
      .iter()
      .filter(|(scope, _)| !unspent.contains(*scope))
      .filter_map(|(scope, seal)| {
        seal
          .licenses_through(lane_of(*scope))
          .filter(|through| monitor.adoption_staged_through(*scope, *through))
          .map(|through| (*scope, through))
      })
      .collect();
    if due.is_empty() {
      return;
    }
    for (scope, through) in due {
      self.monitor.seal_staged_adoptions(scope, through);
    }
    self.drain_monitor();
  }

  /// Resolves every settled fence the [`SettlePass`] entitles this boundary to
  /// mint, and holds the rest over WITH THEIR ENTRIES INTACT — a deferred
  /// window is retried, never degraded and never lost.
  ///
  /// Deaths are not gated by any of it: a teardown fold and the seam-bug path
  /// both resolve [`Dead`](CoverSettle::Dead) through the already-settled list
  /// this function drains unconditionally, so a scope held over below still
  /// reports its death at the very pass that reads it.
  ///
  /// - a live pass whose drain SPENT the scope's counted items resolves
  ///   everything, subject to the window's own ordering proof — owed by a lossy
  ///   window as much as by a clean one, since both dispatch a caller's cookie;
  /// - a live pass with counted items still resident on that scope's lane
  ///   resolves NOTHING for it — including a lossy window, whose `Degraded`
  ///   would answer a caller over a death that may be sitting in exactly those
  ///   items (see [`SettlePass`]);
  /// - the close pass refuses the clean verdict — no stream is left to certify
  ///   against — while still reporting a lossy window honestly, because a
  ///   deferral at close would strand its caller's reply forever.
  pub(crate) fn poll_cover_settlements(
    &mut self,
    pass: SettlePass<'_>,
  ) -> Vec<(FenceId, CoverSettle)> {
    let mut settled = std::mem::take(&mut self.settled_covers);
    let scopes: Vec<ScopeId> = self.cover_fences.keys().copied().collect();
    for scope in scopes {
      if !self.barrier_settled(scope) {
        continue;
      }
      // An unanswered classification stat over a slot this scope covers with
      // nothing is a LOSS this settlement must carry, and it is read here — at
      // the observation — rather than at an edge, because it is a STANDING
      // condition and not an event. A scope's loss memory is spent by every
      // settle observation, so a mark laid when the stat was queued would be
      // cleared by the first observation to pass and the next fence would
      // certify the same uncovered window anyway.
      //
      // The slot may be a directory the scope has no watch on: the read that
      // listed it as `FileKind::Unknown` reconciled nothing for it, and the stat
      // is uncounted, so the barrier above quiesces with the slot dark. Nor need
      // that read have stood a `Rescan` — a pure grow and a record-driven cold
      // read stand none — so this is the only thing between the fence and a
      // certified window. The verdict degrades and the settle floor keeps its
      // under-claim, which sends the consumer back to enumerate — never
      // `Applied` over ground writes go unrecorded beneath.
      //
      // Deliberately NOT a conjunct of the barrier
      // ([`Monitor::stat_loss_outstanding`]): a driver that never answers must
      // cost a degraded verdict, not a wedged scope. Everything below still runs
      // — the residue and certification deferrals, the ordering proof, the
      // resolution — as for any other lossy window, plus the ONE further pass
      // this loss owes on its own account: it is the only one that arrives with
      // no `Rescan`, so the verdict's cover is stood and ordered below.
      let stat_loss = self.monitor.stat_loss_outstanding(scope);
      if stat_loss && let Some(entry) = self.cover_fences.get_mut(&scope) {
        entry.mark_lossy();
      }
      // The residue deferral: this scope's lane still holds items the pass
      // counted and did not read, and an unread terminal `Fatal` among them
      // makes a live verdict of EITHER kind a claim about a stream that is
      // already gone. Both deferrals here keep the entry INTACT, so a window
      // they catch is retried rather than decided.
      if pass.withholds(scope) {
        continue;
      }
      // The certification deferral, which IS clean-only: the close pass has no
      // stream left to certify a clean window against, so it holds that verdict
      // over rather than minting it. A lossy window is not withheld here — it
      // has nothing to certify, its floor move is the rewind, and this is the
      // last pass its caller will ever be answered by.
      if !pass.certifies_clean()
        && self
          .cover_fences
          .get(&scope)
          .is_some_and(|entry| !entry.lossy)
      {
        continue;
      }
      // The counted work quiescing proves the coverage was rebuilt; it does not
      // prove the kernel had nothing queued while that happened. Until a fence
      // has an ordering proof, any live verdict would rest on the drain having
      // seen a lane the reader may not have filled yet.
      //
      // How far the proof reaches decides how much of the entry may resolve.
      // Both of its bounds are checked against the scope as it reads NOW: it
      // must have been taken over the coverage work the scope currently holds —
      // a proof stamped before the scope acquired and released more of it
      // ordered an earlier window, and the record it would certify over may
      // still be kernel-resident — and it reaches only the fences that were
      // already pending when it was requested. A stale proof is therefore no
      // proof at all, and an unreached fence withholds; both reappear in
      // `covers_awaiting_cut`.
      //
      // A LOSSY window owes the same proof. More loss cannot falsify its
      // degraded verdict, but the cut does not surface loss — it surfaces
      // whatever the kernel still holds, death included, and a `Degraded` is a
      // live verdict that dispatches its caller's parked cookie exactly as an
      // `Applied` does. A root renamed away and its pathname recreated while
      // `IN_MOVE_SELF` sits unread would otherwise take that write into an
      // unmonitored directory and answer `Ok` for a record no stream can report,
      // with the scope's death processed only afterwards and the earlier loss
      // covering nothing that happened after it.
      //
      // Two cases are exempt, and neither is about the verdict. A
      // KERNEL-RECURSIVE scope can obtain no proof at all: its control batches
      // carry no inotify port, so the source refuses them without ever reaching
      // a reader, and requiring one would defer its settles forever. The
      // consequence is recorded honestly: the kernel-resident leg of this defect
      // stays open on such a backend, where it is currently unreachable because
      // the scope records no coverage claim and takes no `set_cover` fence —
      // only a `sync_root` opens one, and a sync's own ordering rests on the
      // single ordered lane instead. The CLOSE pass is exempt for the mirror
      // reason (see [`SettlePass::owes_cut_proof`]): every stream is already
      // torn down, so no reader can answer and no verdict can dispatch. Both
      // exempt cases reach every fence they hold, so they always resolve whole.
      let Some(entry) = self.cover_fences.get(&scope) else {
        continue;
      };
      let through = if self.cut_proof_required(scope) && pass.owes_cut_proof() {
        let Some(reach) = entry.cut.licenses_through(self.coverage_epoch(scope)) else {
          continue;
        };
        reach
      } else {
        entry.high_water()
      };
      let Some(entry) = self.cover_fences.get_mut(&scope) else {
        continue;
      };
      // Ordinals ascend with open order, so the licensed fences are exactly a
      // prefix; the rest stay pending, keeping the lossiness they have accrued,
      // and are decided by their own successor proof.
      let split = entry
        .pending
        .partition_point(|pending| pending.opened <= through);
      // THE COVER THE STANDING STAT LOSS OWES. The mark above degrades this
      // tranche's verdict; a degraded verdict reports a covering `Rescan`
      // EMITTED for the gap, and this condition is the one loss source that
      // stands none of its own — the read that queued the stat reconciled
      // nothing for the slot, and a pure grow or a record-driven cold read
      // stands no `Rescan` at all. So it is stood HERE, scope-level, where the
      // verdict is minted: the darkness cannot be covered at the slot (that is
      // what the outstanding request means), and the root-covering `Rescan` is
      // the re-enumerate instruction the degraded verdict names.
      //
      // The tranche is then held for exactly ONE pass — entry intact, exactly
      // like the deferrals above — so the driver's re-top
      // ([`take_cover_flush_due`](Self::take_cover_flush_due)) flushes the
      // instruction to the consumer's channel before the next observation
      // answers the caller. That is the same ordering every OTHER `Degraded`
      // producer gets for free: its cover is queued by an earlier pass and
      // offered by this pass's loop-top flush.
      //
      // The hold ends there and is never extended by the offer's OUTCOME. A
      // refused cover is parked as the scope's dominating instruction and rides
      // the lane's own delivery retry, BEHIND the verdict — because `Degraded`
      // promises emission, not delivery, and a hold that waited for an
      // acceptance would make a caller's own `set_cover` reply depend on that
      // caller reading its event stream. Nothing here reads the lane, the
      // channel, or the consumer.
      //
      // Only where a verdict is actually minted (`split > 0`): an observation
      // that resolves no fence — a bare loss-memory entry, or a tranche no proof
      // has reached — instructs nobody and so owes nobody a cover.
      //
      // Asked as a VALUE the match produces, so a state added to [`StatCover`]
      // does not compile until it has said whether a tranche may resolve over it.
      let stood = entry.stat_cover;
      let (stat_cover, held) = if pass.orders_stat_cover() {
        match stood {
          // Nothing stood yet, and this pass mints a verdict over the standing
          // loss: stand the cover and hold the tranche for the flush that offers
          // it.
          StatCover::Unstood if stat_loss && split > 0 => match self.stand_stat_cover(scope) {
            StatCover::Stood => (StatCover::Stood, true),
            // Nothing was stood, so nothing is owed and nothing is ordered: a
            // kernel-recursive scope stats no slot, and a torn-down one has no
            // consumer left to instruct.
            StatCover::Unstood => (StatCover::Unstood, false),
          },
          // No verdict over a standing loss here: nobody is instructed, so nobody
          // is owed a cover.
          StatCover::Unstood => (StatCover::Unstood, false),
          // Stood on an earlier pass, so its flush has already run — or a proof
          // invalidation deferred this tranche past it, which is a longer wait
          // still. Either way the instruction is out and the verdict may follow;
          // the latch is preserved so no second cover is stood.
          StatCover::Stood => (StatCover::Stood, false),
        }
      } else {
        (stood, false)
      };
      // Re-taken because standing the cover routes its own `Rescan` through the
      // loss-memory entry (which is where a `Rescan` degrades the scope's
      // recorded claim, exactly as any other loss does).
      let Some(entry) = self.cover_fences.get_mut(&scope) else {
        continue;
      };
      entry.stat_cover = stat_cover;
      if held {
        continue;
      }
      let resolving: Vec<PendingFence> = entry.pending.drain(..split).collect();
      // The hold is spent with the tranche it ordered: a successor tranche
      // covers its own stretch of the window.
      entry.stat_cover = StatCover::Unstood;
      let lossy = entry.lossy;
      let spent = entry.pending.is_empty();
      // Teardown removes the entry with its scope, so a live entry always has scope
      // state; a scope-less entry is a seam bug — resolve its fences `Dead` rather
      // than report `Applied` for coverage nobody backs. Such an entry is exempt
      // above (a scope with no state can obtain no proof), so it always resolves
      // whole and reaches the repair below rather than lingering half-settled.
      let mut dead = false;
      if spent {
        self.cover_fences.remove(&scope);
        if let Some(state) = self.scopes.get_mut(&scope) {
          if lossy {
            state.applied_cover = state.settle_floor.clone();
          } else {
            state.settle_floor = state.applied_cover.clone();
          }
        } else {
          debug_assert!(false, "a fence entry never outlives its scope");
          dead = true;
        }
      }
      for pending in resolving {
        // A scope-less entry means exactly what the teardown fold means — no scope
        // backs this fence — so it mints the same verdict rather than a weaker one
        // that a consumer would have to disambiguate.
        let settle = if dead {
          CoverSettle::Dead
        } else if pending.lossy {
          CoverSettle::Degraded
        } else {
          CoverSettle::Applied
        };
        settled.push((pending.fence, settle));
      }
    }
    settled
  }

  /// Whether the last [`poll_cover_settlements`](Self::poll_cover_settlements)
  /// stood a covering `Rescan` and held its tranche for the flush that offers
  /// it, clearing the flag as it reports.
  ///
  /// The driver re-tops on `true`: the loop-top effect flush OFFERS that
  /// `Rescan` to the consumer's stream, and the next pass — the one that answers
  /// the caller with the degraded verdict naming it — runs behind that offer. It
  /// is the ONE settlement outcome no external input would bring the loop back
  /// for.
  ///
  /// Raised by the pass that STANDS a cover and by no other — one re-top per
  /// held tranche, so the re-top run stays a single pass and the driver's
  /// bounded-service invariant is untouched. What the flush then makes of the
  /// cover changes nothing here: a refused one is parked, and a lane already
  /// lagging absorbed it into its parked instruction before the flush ran. Both
  /// ride the scope's delivery retry, behind a verdict that has already
  /// answered.
  pub(crate) fn take_cover_flush_due(&mut self) -> bool {
    std::mem::take(&mut self.cover_flush_due)
  }

  /// Stands the covering `Rescan` a standing stat loss owes the tranche about to
  /// resolve, and reports whether one was stood.
  ///
  /// [`StatCover::Stood`] asks the driver for the single re-top whose flush
  /// offers it. [`StatCover::Unstood`] where nothing was stood: a
  /// kernel-recursive scope stats no slot, and a torn-down one has no consumer
  /// left to instruct — so nothing is ordered and the tranche resolves where it
  /// stands.
  fn stand_stat_cover(&mut self, scope: ScopeId) -> StatCover {
    if !self.monitor.cover_stat_loss(scope) {
      return StatCover::Unstood;
    }
    self.drain_monitor();
    self.cover_flush_due = true;
    StatCover::Stood
  }

  /// The cookie dispatch's deficit seam: re-signals `scope`'s standing
  /// terminal coverage deficits through the Monitor (one fresh epoch-bumped
  /// covering `Rescan` per site plus a bounded heal kick —
  /// [`Monitor::resignal_coverage_deficits`]), then drains, so the `Rescan`
  /// effects are queued BEFORE the caller dispatches the parked cookie write.
  /// Returns whether anything was re-signaled; a no-op for a scope with no
  /// deficit or a kernel-recursive one.
  pub(crate) fn resignal_coverage_deficits(&mut self, scope: ScopeId) -> bool {
    let signaled = self.monitor.resignal_coverage_deficits(scope);
    if signaled {
      self.drain_monitor();
    }
    signaled
  }

  /// Feeds the blocking spawn's outcome for `scope`'s stream.
  pub(crate) fn on_stream_spawned(&mut self, scope: ScopeId, res: Result<RootMeta, SourceError>) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    let watch = state.watch;
    match res {
      Ok(meta) => {
        // `Backend::Auto` decides the backend only once the source has spawned,
        // so the registered profile is provisional: adopt the probed backend's
        // profile before the root's watch-result is fed. The root node is still
        // bootstrapping (no children, no record ingested), so re-profiling only
        // governs decisions still to come — the post-arm enumerate and every
        // later descent gate. A forced backend resolves to the profile it was
        // registered with, so the reprofile is a no-op there.
        let backend = meta.backend;
        if backend != state.profile {
          state.profile = backend;
          self.monitor.reprofile_root(scope, caps_for(backend));
        }
        let root = Arc::new(meta.root);
        state.root = Some(Arc::clone(&root));
        state.root_dev = Some(meta.root_dev);
        state.root_mnt_id = meta.root_mnt_id;
        // The barrier reads no incarnation token (only a refresh does), so this
        // world starts with none and the first refresh that answers one installs
        // it. Nothing compares against a `None`.
        state.root_incarnation = None;
        state.frame_epoch = state.frame_epoch.wrapping_add(1);
        // This world's set is COMPLETE the moment it is seeded — the barrier read
        // below and this world's own seed walk are exactly the evidence a
        // generation carries — and a fresh source has been told nothing yet. That
        // seeding is itself an applied generation, so it discharges any evidence a
        // rejected one left behind in the world being replaced.
        state.generation_applied();
        state.published_epoch = None;
        state.identity = Some(meta.identity);
        // The coverage baseline is SEEDED from the same barrier read, not left
        // empty. Seeding it opens no authority — `mounts_authoritative` stays
        // false until the birth refresh installs a real table read, and nothing
        // derived from the baseline ever reaches [`device_trusted`] — but the
        // seed IS evidence that a prefix was mounted, and the COLD CRAWL consumes
        // that same fact independently: it reads the mount's foreign device and
        // [`crosses_mount_boundary`] DECLINES to descend beneath it.
        //
        // Crawl and birth refresh are separate detached jobs with no start order
        // between them, so a lazy unmount in the gap leaves the crawl's declined
        // subtree unenumerated while the first authoritative read shows the
        // prefix gone. With an EMPTY baseline that read derives nothing and
        // installs the same empty frame, and so does every later one — coverage
        // under the now-exposed directory stays dead indefinitely. Seeded, the
        // read derives one conservative departure cover instead. Somebody WAS
        // covered-for: coverage was DECLINED on the strength of that mount, which
        // is exactly what makes its departure matter, and over-covering a region
        // the crawl may have declined is the safe direction — a cover is only
        // ever a cost.
        //
        // The seed IS a table read (the same `mounts_under` the refresh runs), so
        // the first refresh diffs against it cleanly: a still-mounted row's key is
        // in both censuses and covers nothing, while a departed one is a
        // transition on the strength of the row this seed saw. The LEDGER is
        // emptied with the old world rather than seeded — nothing a seam observed
        // under the previous root describes this one — and this world's own seed
        // walk refills it below. A probe-learned foreign-device prefix
        // ([`learn_device`]) still never gets in.
        state.census = census_of(&meta.mounts);
        state.ledger.clear();
        install_mount_table(state, meta.mounts.into_iter().map(|row| row.location));
        // The old world's learned prefixes describe a root this scope no longer
        // watches (a birth has none), so they go with the rest of that world. Nothing
        // else may empty this set: see [`ScopeState::learned_mounts`].
        state.learned_mounts.clear();
        // SEAM 2: the boundaries this world's OWN seed walk declined, recorded in
        // the same step that seeds the baseline from the barrier read — so the set
        // is whole before the scope is live, never completed by a later message.
        // These are the ONLY boundaries a kernel-recursive scope ever learns
        // without a mount table: the walk is its only fence, and it runs once, at
        // spawn. Empty on every backend that walks nothing.
        record_declined(state, &meta.declined);
        // Born closed: the seed was read before the stream started, so a
        // mount appearing in that gap is in neither the seed nor the event
        // stream — the seed can only REDUCE trust. Authority arrives with
        // this birth refresh, whose post-live read the stream orders against
        // every later mount transition; until it installs, event-side
        // identity and cookies fail closed (the non-authoritative default).
        Self::arm_refresh(&mut self.effects, scope, state, RefreshCause::Invalidating);
        match backend {
          // Kernel-recursive: the live stream IS the root's coverage, so the
          // spawn doubles as the root's watch-result AND the moment the caller's
          // grant commits inline — public delivery begins here. fanotify's one
          // superblock mark and the Windows primitives' subtree streams cover
          // the whole root exactly like FSEvents.
          BackendKind::FsEvents
          | BackendKind::Fanotify
          | BackendKind::Rdcw
          | BackendKind::UsnJournal => {
            state.publicly_live = true;
            let attempt = state.root_attempt;
            if let Some(attempt) = attempt {
              self.monitor.on_watch_result(
                watch,
                attempt,
                Ok(tributary_proto::WatchAck::Installed),
              );
            } else {
              debug_assert!(false, "a spawned scope drained its root's bootstrap arm");
            }
          }
          // Descending: the source starts with NO watches (nothing may be
          // delivered before the Monitor's own watch flow runs), so the
          // root's kernel watch is armed through the same effect path as
          // every descendant — its watch-result arrives via
          // [`on_watch_installed`](Self::on_watch_installed).
          BackendKind::Inotify => {
            let name = root
              .file_name()
              .and_then(|name| name.to_str())
              .unwrap_or("/");
            // The root's barrier read its identity; the arm confirms the object
            // did not get replaced between that read and the (absolute-path) open.
            // The spawn barrier already brackets identity around start, but the
            // root arm happens after — so the same confirmation applies here.
            let expected = u64::try_from(meta.identity.ino())
              .ok()
              .and_then(NonZeroU64::new)
              .map(|ino| ExpectedObject {
                dev: meta.identity.dev(),
                ino,
              });
            let Some(attempt) = state.root_attempt else {
              debug_assert!(false, "a spawned scope drained its root's bootstrap arm");
              return;
            };
            self.effects.push_back(Effect::AddWatch {
              scope,
              watch,
              attempt,
              parent: watch,
              name: Segment::new(name),
              path: root,
              expected,
              // The ROOT is where the frame comes FROM, so it can never be
              // across it: the check compares the landing to the meta this same
              // spawn just installed. Carried anyway rather than special-cased,
              // so exactly one rule governs every arm.
              frame: state.frame(),
            });
          }
        }
      }
      Err(err) => {
        if let Some(attempt) = state.root_attempt {
          self
            .monitor
            .on_watch_result(watch, attempt, Err(watch_error(&err)));
        }
      }
    }
    self.drain_monitor();
  }

  /// The driver refused the spawned stream before it went live: its FINAL
  /// canonical root overlapped a root this watcher already covers (the
  /// backend re-canonicalizes, so a spawn can resolve somewhere the
  /// reservation did not). The scope ends exactly like a failed spawn.
  pub(crate) fn on_spawn_rejected(&mut self, scope: ScopeId) {
    let Some(state) = self.scopes.get(&scope) else {
      return;
    };
    let watch = state.watch;
    if let Some(attempt) = state.root_attempt {
      self
        .monitor
        .on_watch_result(watch, attempt, Err(WatchError::Gone));
    }
    self.drain_monitor();
  }

  /// Feeds one descending arm's outcome. An [`Aliased`](WatchOutcome::Aliased)
  /// anchor maps to a successful watch-result exactly like a fresh install:
  /// the wd table fans the shared kernel watch's events out to every anchor,
  /// so the anchor's coverage is real — the Monitor proceeds to the post-arm
  /// read the node's own flavor selects (a registration's is re-arm-flavored and
  /// announces nothing; a live discovery's is cold) and the coverage it takes is
  /// correct either way.
  /// The scope a watch belongs to, while the watch is tracked. The driver
  /// uses this to route a root arm's outcome to its deferred registration
  /// grant.
  pub(crate) fn scope_of_watch(&self, watch: WatchId) -> Option<ScopeId> {
    self.watch_scopes.get(&watch).copied()
  }

  /// The attempt `watch`'s current arm carries — what the driver captures off
  /// the [`Effect::AddWatch`] it dispatches. Recovered here for tests that are
  /// not about supersession; one that IS captures the token from the effect and
  /// replays it after a later arm has taken over.
  #[cfg(test)]
  pub(crate) fn arm_attempt(&self, watch: WatchId) -> ArmAttempt {
    self
      .monitor
      .arm_attempt(watch)
      .unwrap_or_else(|| ArmAttempt::new(NonZeroU64::MIN))
  }

  pub(crate) fn on_watch_installed(
    &mut self,
    watch: WatchId,
    attempt: ArmAttempt,
    outcome: WatchOutcome,
  ) {
    // The fresh-vs-aliased bit is carried through, not collapsed: a binding
    // re-proof keys its dark-window verdict on it (`Installed` = the old
    // binding was dead or rebound, so the settle edge owes the closing
    // `Rescan`; `Aliased` = live all along, no window).
    let res = match outcome {
      WatchOutcome::Installed(_) => Ok(tributary_proto::WatchAck::Installed),
      WatchOutcome::Aliased(_) => Ok(tributary_proto::WatchAck::Aliased),
      WatchOutcome::Failed(err) => Err(err),
    };
    // A descending scope's ROOT arm succeeding is the moment its coverage — and
    // its caller's handle (the deferred grant commits on this same result) —
    // become real: public delivery begins here, exactly like the KR spawn does
    // inline. `watch == state.watch` is precisely the root's own watch (the root
    // arms with `parent == watch == the scope's root watch`), so a CHILD arm
    // never flips this. A FAILED root arm leaves `publicly_live` false, so the
    // Monitor's ensuing failure `Rescan` is fenced out of the effect queue — the
    // caller got `Err`, never a handle, so there is no public view to cover.
    if res.is_ok()
      && let Some(&scope) = self.watch_scopes.get(&watch)
      && let Some(state) = self.scopes.get_mut(&scope)
      && state.watch == watch
    {
      state.publicly_live = true;
    }
    self.monitor.on_watch_result(watch, attempt, res);
    self.drain_monitor();
  }

  /// Feeds one raw directory listing back for the enumerate that requested
  /// it, minting each entry's identity through the SAME policy the probe path
  /// uses (enumerate-side identity is the authority; a foreign-device entry
  /// mints `None`). A DIRECTORY across the scope's MOUNT boundary — a differing
  /// mount id, or (as a belt, and when the mount id is unavailable) a differing
  /// device — is lowered as [`FileKind::Other`]: the mount boundary is the scope
  /// boundary, so the Monitor must not descend it — the entry still delivers, the
  /// subtree beyond the boundary is deliberately outside coverage. The mount-id
  /// fence catches a `mount --bind` of a same-DEVICE directory the device check
  /// alone would descend across (the same breach the fanotify walk closes with the
  /// same fence); the device belt still governs when either mount id is unknown
  /// (the honest below-5.8 degrade).
  ///
  /// An entry the caller EXCLUDED is dropped from the listing outright — the cold
  /// half of the common-layer fence (see [`exclusions`](Self::exclusions)). An
  /// excluded directory is therefore never staged, so the Monitor never emits its
  /// `Created`, never reconciles a slot for it, never arms it and never descends
  /// it. The drop deliberately does NOT set `lossy`: a `Partial` listing means the
  /// read could not report everything, which forces a covering `Rescan` and a
  /// bounded retry, whereas this omission is exactly what the caller asked for and
  /// has nothing to recover. This fence needs no backend gate — an enumerate only
  /// ever happens on a descending profile, and a descending backend by
  /// construction has no admission-time enforcement of its own.
  ///
  /// # Seam 1 — the decline is also an OBSERVATION
  ///
  /// The lowering below is the single site where a boundary-crossing dir entry is
  /// declined, and it holds everything the ledger wants: the location, the
  /// entry's device, and its mount id. So each decline is RECORDED
  /// ([`record_boundary`]), and this is the first place a [`Standing::SameMount`]
  /// entry is ever produced — a btrfs subvolume trips the belt with the root's
  /// own mount id and has no mountinfo row, so no census will ever list it and
  /// none can ever condemn it.
  ///
  /// The dir GATE is deliberate and stays. A file-target bind — the
  /// `resolv.conf` class, ubiquitous in containers — is never declined here and
  /// so is never recorded here; the mount refresh sees it regardless, and that is
  /// the stated answer for non-directory targets rather than an accident.
  pub(crate) fn on_enumerated(&mut self, req: ReqId, raw: RawEnumerate) {
    let Some((scope, dir)) = self.enum_reqs.remove(&req) else {
      return;
    };
    let res = match raw {
      RawEnumerate::Failed(class) => EnumerateResult::Failed(class),
      RawEnumerate::Listed { entries, complete } => {
        let Some(state) = self.scopes.get(&scope) else {
          return;
        };
        let mut listed = Vec::with_capacity(entries.len());
        let mut lossy = false;
        // Collected while the scope is borrowed SHARED (the exclusion fence and
        // the identity mint both read `self`), then recorded once the walk is
        // over. Order is preserved, so the containment rule inside
        // `record_boundary` sees the same set it would have seen entry by entry.
        let mut declined: Vec<(PathBuf, Option<u64>)> = Vec::new();
        // SEAM 1's RETIRING half. A complete listing re-observes every child of
        // this directory, which makes it the descending profile's generation for
        // the EXEMPT ledger entries — the ones no census can ever retire.
        // `reconcile` is empty unless this scope actually holds such an entry at a
        // child of `dir`, which is every scope in production today, so the
        // per-entry work below costs nothing at all in the common case. An
        // INCOMPLETE listing reconciles nothing: an absent name proves nothing
        // about a read that was cut short.
        let collect_kept = complete && state.holds_exempt_under(&dir);
        let mut kept: Vec<PathBuf> = Vec::new();
        for entry in entries {
          let Ok(name) = core::str::from_utf8(&entry.name) else {
            // A non-UTF-8 name cannot become a `Segment` (the documented v1
            // limitation): degrade the listing to Partial so the Monitor's
            // bounded retry + standing Rescan cover the unrepresentable
            // entry rather than silently omitting it.
            lossy = true;
            continue;
          };
          let path = dir.join(name);
          if self.excluded(&path) {
            // Skipped BEFORE the fence, so this listing cannot say whether a
            // boundary is there; an excluded child is never a candidate for
            // retirement.
            if collect_kept {
              kept.push(path);
            }
            continue;
          }
          let node = mint(state, &path, NonZeroU64::new(entry.ino), Some(entry.dev));
          let kind = if entry.kind.is_dir() && crosses_mount_boundary(state, &entry) {
            if collect_kept {
              kept.push(path.clone());
            }
            declined.push((path, entry.mnt_id));
            FileKind::Other
          } else {
            entry.kind
          };
          let mut dir_entry = DirEntry::new(Segment::new(name), kind);
          if let Some(node) = node {
            dir_entry = dir_entry.with_node(node);
          }
          listed.push(dir_entry);
        }
        // A lossy listing dropped a name it could not represent, so it is no
        // more authoritative about absence than an incomplete one.
        let reconcile = collect_kept && !lossy;
        if (reconcile || !declined.is_empty())
          && let Some(state) = self.scopes.get_mut(&scope)
        {
          // Retire BEFORE recording, so a boundary this very listing declined
          // survives and a stale record cannot block the containment rule for a
          // live boundary recorded under it.
          if reconcile {
            retire_relisted_boundaries(state, &dir, &kept);
          }
          // Recording owes the seam nothing back — see [`record_boundary`]. The
          // seam that once stood a located cover for a refused observation needed
          // a saturation latch to keep it from storming, and that latch silenced
          // every refusal after the first.
          for (location, mnt_id) in declined {
            record_boundary(state, &location, mnt_id);
          }
        }
        if complete && !lossy {
          EnumerateResult::Ok(listed)
        } else {
          EnumerateResult::Partial(listed)
        }
      }
    };
    self.monitor.on_enumerate(req, res);
    self.drain_monitor();
  }

  /// Feeds one decoded callback batch for `scope`, taking the whole payload:
  /// the budget slot rides with the events for as long as the core retains
  /// them (parked active or queued), so parked memory stays inside the
  /// transport budget and a stuck probe back-pressures the callback.
  pub(crate) fn on_batch(&mut self, scope: ScopeId, payload: BatchPayload, now: Instant) {
    let Some(mut state) = self.scopes.remove(&scope) else {
      return;
    };
    if state.park.active.is_some() {
      state.park.queued.push_back(payload);
      self.scopes.insert(scope, state);
      return;
    }
    let BatchPayload { events, permit, .. } = payload;
    let mut batch = self.compile(&mut state, scope, events, now);
    batch.permit = Some(permit);
    let fed = Self::settle_if_ready(&mut self.monitor, &mut state, scope, batch, now);
    self.scopes.insert(scope, state);
    if fed {
      self.pump_queued(scope, now);
    }
    self.drain_monitor();
  }

  /// Test entry taking bare FSEvents records under a detached budget slot.
  #[cfg(test)]
  pub(crate) fn on_batch_events(&mut self, scope: ScopeId, events: Vec<RawOsEvent>, now: Instant) {
    let events = events.into_iter().map(SourceEvent::FsEvents).collect();
    self.on_batch(scope, BatchPayload::detached(events), now);
  }

  /// Test entry taking bare attributed inotify records.
  #[cfg(test)]
  pub(crate) fn on_inotify_events(
    &mut self,
    scope: ScopeId,
    events: Vec<crate::os::linux::RawLinuxEvent>,
    now: Instant,
  ) {
    let events = events.into_iter().map(SourceEvent::Linux).collect();
    self.on_batch(scope, BatchPayload::detached(events), now);
  }

  /// Feeds one probe's outcome; a completed batch (and any batches queued
  /// behind it) is then fed to the Monitor in order.
  pub(crate) fn on_probe_result(&mut self, probe: ProbeId, outcome: ProbeOutcome, now: Instant) {
    let Some(ctx) = self.probes.remove(&probe) else {
      return;
    };
    // A slot stat answers the Monitor directly: it grounds no batch item, so it
    // resolves ahead of the park machinery and never touches a scope's park.
    if let ProbePurpose::SlotKind { req, path } = ctx.purpose {
      // SEAM 4, ahead of the answer: the probe just read a device for a path
      // under the root, and `stat_result` is about to throw it away. A device
      // the scope's frame calls foreign is a boundary observed at the only
      // moment anything looked, so it is recorded before the answer lowers.
      // Recording owes nothing back — see [`record_boundary`].
      if let Some(state) = self.scopes.get_mut(&ctx.scope) {
        record_probe_boundary(state, &path, outcome);
      }
      self.monitor.on_stat_result(req, stat_result(outcome));
      self.drain_monitor();
      return;
    }
    let Some(mut state) = self.scopes.remove(&ctx.scope) else {
      return;
    };
    let scope = ctx.scope;
    let resolved = Self::resolve(&mut state, ctx.purpose, outcome);
    let mut fed = false;
    if let Some(batch) = state.park.active.as_mut() {
      if let Some((fid, partner)) = resolved.evidences {
        batch.evidenced.entry(fid).or_default().push(partner);
      }
      if let Some(slot) = batch.items.get_mut(resolved.item) {
        slot.planned = resolved.planned;
        slot.probe = None;
        slot.cookie_candidate = resolved.candidate;
        batch.awaiting = batch.awaiting.saturating_sub(1);
      }
      if batch.awaiting == 0 {
        let batch = state.park.active.take().expect("just observed Some");
        Self::settle(&mut self.monitor, &mut state, scope, batch, now);
        fed = true;
      }
    }
    self.scopes.insert(scope, state);
    if fed {
      self.pump_queued(scope, now);
    }
    self.drain_monitor();
  }

  /// Commits a root replacement on a live scope: the new stream's
  /// [`RootMeta`] replaces the scope's world (root bytes, device, mount
  /// frame, identity, mount seed), and everything the OLD world still owed
  /// is resolved by domination — the loss-path cut. Parked work and
  /// in-flight probes were compiled against the old root's bytes, so they
  /// are dropped, not re-addressed; the epoch-bumped full-root `Rescan` the
  /// cut emits instructs the consumer to re-read the (widened) world, which
  /// covers the old subtree's swap window and the newly covered delta alike.
  ///
  /// The scope's LOWERING must be preserved (the driver refuses a
  /// descending↔KR flip as `BackendDiverged` before this input is reached);
  /// a KR→KR backend change (a replace landing on another volume under the
  /// windows Auto ladder) re-profiles exactly like `on_stream_spawned`. On a
  /// descending scope the per-directory book rebinds
  /// ([`Monitor::rebind_root`]): the driver has ALREADY armed the new root
  /// on the new transport and replays that outcome via
  /// [`on_watch_installed`](Self::on_watch_installed) immediately after this
  /// input — the re-arm-flavored rebuild it kicks off restores coverage
  /// without re-announcing content the commit `Rescan` already covers.
  ///
  /// Returns the [`ArmAttempt`] that replay must be reported under (`None` for
  /// a kernel-recursive scope, which replays nothing): the rebind supersedes
  /// every arm the retired transport still owes, so an outcome from one of
  /// those names an older attempt and is discarded rather than judging the
  /// binding that replaced it.
  pub(crate) fn on_root_replaced(
    &mut self,
    scope: ScopeId,
    meta: RootMeta,
    now: Instant,
  ) -> Option<ArmAttempt> {
    let state = self.scopes.get_mut(&scope)?;
    debug_assert_eq!(
      state.profile.is_kernel_recursive(),
      meta.backend.is_kernel_recursive(),
      "replace never crosses lowering profiles; the driver refuses BackendDiverged"
    );
    let backend = meta.backend;
    if backend != state.profile {
      state.profile = backend;
      self.monitor.reprofile_root(scope, caps_for(backend));
    }

    // The world swap — the on_stream_spawned adoption, on a live scope.
    let root = Arc::new(meta.root);
    state.root = Some(root);
    state.root_dev = Some(meta.root_dev);
    state.root_mnt_id = meta.root_mnt_id;
    // A different root on a barrier read that answers no token: the old world's
    // proven incarnation belongs to a mount this scope no longer watches, so it is
    // dropped rather than compared against the new world's first refresh.
    state.root_incarnation = None;
    state.frame_epoch = state.frame_epoch.wrapping_add(1);
    state.identity = Some(meta.identity);
    // The old world's departure baseline describes a table under a root this
    // scope no longer watches, so it is REPLACED — not cleared — by this
    // world's own barrier read, exactly as `on_stream_spawned` seeds a birth's
    // (see the reasoning there). The replace's covering Rescan does not make the
    // seed redundant: the re-enumeration that cover obliges IS the crawl that
    // reads a mount's foreign device and declines beneath it, so it loses the
    // same race to a lazy unmount that a birth crawl does. Nothing of the old
    // world survives the swap, so no prefix that never belonged to this tree can
    // be diffed against the new root's first read.
    // The new world's set is COMPLETE the moment it is seeded — this barrier read
    // and this world's own seed walk are exactly the evidence a generation carries
    // — so the watermark is the world it was taken in, and the old world's
    // outstanding round trip goes with the rest of that world's state: it addresses
    // a root this scope no longer watches, and the swap's own covering `Rescan`
    // owes the consumer the whole new tree regardless.
    state.generation_applied();
    state.pending_recovery = None;
    state.published_epoch = None;
    state.census = census_of(&meta.mounts);
    state.ledger.clear();
    install_mount_table(state, meta.mounts.into_iter().map(|row| row.location));
    // The old world's learned prefixes describe a root this scope no longer
    // watches (a birth has none), so they go with the rest of that world. Nothing
    // else may empty this set: see [`ScopeState::learned_mounts`].
    state.learned_mounts.clear();
    // SEAM 2: the boundaries this world's OWN seed walk declined, recorded in
    // the same step that seeds the baseline from the barrier read — so the set
    // is whole before the scope is live, never completed by a later message.
    // These are the ONLY boundaries a kernel-recursive scope ever learns
    // without a mount table: the walk is its only fence, and it runs once, at
    // spawn. Empty on every backend that walks nothing.
    record_declined(state, &meta.declined);
    // The old world's authority cannot vouch for the new root's mounts:
    // trust fails closed until the refresh this commit arms completes. A
    // refresh already in flight was addressed to the REPLACED root — mark it
    // cross-world so its completion (liveness verdict included) is discarded
    // rather than judging the new identity by the old object.
    state.refresh_world_stale = state.refresh_pending;
    // Every cover PARKED on an outstanding admission round trip dies with the
    // old world, `refresh_world_stale` style: the location it addresses is a
    // path under a root this scope no longer watches, the reader that was going
    // to answer it is being retired, and the swap's own covering `Rescan` owes
    // the consumer the whole new tree regardless. Leaving one parked would hold a
    // cover for a reply that can never arrive.
    state.pending_admits.clear();
    // A replace commit ends any witnessed widen window outright: the fallback
    // route lands here with the tainted (or refused) window still recorded,
    // and the replacement's own spawn barrier re-established the binding from
    // scratch — leaking the dead window would poison a FUTURE widen's
    // reservation (INV-ROOT leg (i)).
    state.pending_widen = None;
    state.mounts_authoritative = false;
    Self::arm_refresh(&mut self.effects, scope, state, RefreshCause::Invalidating);

    // The cut: old-world parked work and probes are dominated, and the
    // Monitor turns the swap into the epoch-bumped covering Rescan.
    state.park.active = None;
    state.park.queued.clear();
    // The geometry pass needs no cut of its own here. It holds no state across
    // records: a rename's source end is read from the Monitor's own reparent
    // report at the instant the destination is fed, so the halves the rebind
    // below purges ([`Monitor::rebind_root`]) take every geometry consequence
    // with them. A destination arriving in the NEW world under a wrapped kernel
    // cookie finds no half, is reported as the fresh directory it is, and
    // repairs nothing.
    Self::trust_lost(&mut self.effects, scope, state);
    self.probes.retain(|_, ctx| ctx.scope != scope);
    // Old-world enumerate contexts are dominated too: a descending replace's
    // in-flight reads will never return (their Monitor slots are dropped by
    // `rebind_root` below), and a late result would otherwise lower against
    // the NEW world before the Monitor rejects its now-unknown request.
    // Reclaim them exactly as teardown does; the rebuild's fresh reads are
    // recorded below in `drain_monitor`.
    self.enum_reqs.retain(|_, (s, _)| *s != scope);
    // Descending: the per-directory book was built on the retired
    // transport — rebind it (children dropped, root reset to a counted
    // re-arm) BEFORE the overflow cut, whose re-arm kickoff then folds into
    // the reset root instead of re-reading the old tree.
    let replay = if backend.is_kernel_recursive() {
      None
    } else {
      self.monitor.rebind_root(scope).map(|(_, attempt)| attempt)
    };
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
    replay
  }

  /// The root `WatchId` of a live scope — the anchor the driver pre-arms on
  /// the replacement transport before committing a descending replace.
  pub(crate) fn root_watch(&self, scope: ScopeId) -> Option<WatchId> {
    self.scopes.get(&scope).map(|state| state.watch)
  }

  /// A live scope's canonical root — the commit-time authority the driver's
  /// widen predicate (old ⊂ new) compares against.
  pub(crate) fn root_path(&self, scope: ScopeId) -> Option<Arc<PathBuf>> {
    self.scopes.get(&scope).and_then(|state| state.root.clone())
  }

  /// A live scope's mount frame `(root_dev, root_mnt_id)` — the same-frame
  /// conjunct of the widen predicate: the enumerate lowering marks any entry
  /// across the scope's frame [`FileKind::Other`] and the reconcile drops the
  /// watch in such a slot, so widening over a differing frame would actively
  /// tear the adopted coverage down. `None` for a scope with no live stream.
  pub(crate) fn root_frame(&self, scope: ScopeId) -> Option<(u64, Option<u64>)> {
    self
      .scopes
      .get(&scope)
      .and_then(|state| state.root_dev.map(|dev| (dev, state.root_mnt_id)))
  }

  /// Mints the watch id a same-transport widen pre-arms on the LIVE port
  /// before its commit — see [`Monitor::reserve_watch_id`].
  pub(crate) fn reserve_watch_id(&mut self) -> WatchId {
    self.monitor.reserve_watch_id()
  }

  /// Opens the witnessed window for a same-transport widen (INV-ROOT): from
  /// this instant every record the transport attributes to `reserved` is
  /// intercepted by the inotify lowering (a death record taints, benign churn
  /// is counted) and every scope loss signal taints — so the commit gate can
  /// prove, not sample, that the reserved binding is still live. MUST be
  /// called before the pre-arm is dispatched: the reader registers the kernel
  /// wd against `reserved` at arm execution, and no attributed record may
  /// predate the window that witnesses it. Single-flight per scope (the
  /// driver's `replace_states` already serializes replaces).
  pub(crate) fn begin_widen_watch(&mut self, scope: ScopeId, reserved: WatchId) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    debug_assert!(
      state.pending_widen.is_none(),
      "replaces are single-flight per scope; a stale window may not leak into a fresh widen"
    );
    state.pending_widen = Some(PendingWiden {
      reserved,
      tainted: None,
      benign: 0,
    });
  }

  /// Closes a witnessed window whose widen will not commit — a failed or
  /// retired pre-arm, or the loud impossible-path fallback. Idempotent; a
  /// scope torn down meanwhile has no state and nothing to clear (the window
  /// died with it).
  pub(crate) fn abort_widen_watch(&mut self, scope: ScopeId) {
    if let Some(state) = self.scopes.get_mut(&scope) {
      state.pending_widen = None;
    }
  }

  /// Commits a same-transport WIDEN on a live descending scope: the world meta
  /// swaps to the new (containing) root and the Monitor splices the new root
  /// ABOVE the old one ([`Monitor::widen_root`]) — the old subtree's watches,
  /// states, reads, move halves, and deficits all ride across untouched on the
  /// unchanged stream, which is the zero-gap guarantee. Deliberately absent,
  /// each a loss signal the D1 replace commit
  /// ([`on_root_replaced`](Self::on_root_replaced)) must produce and this
  /// commit must NOT: no park/probe/enumerate cut (the inotify lowering parks
  /// nothing and its watch-anchored records are immune to the root flip), no
  /// covering `Rescan`, no epoch bump, no cover-claim reset (`applied_cover`
  /// keeps the old claim — resetting to `None` would claim full coverage over
  /// regions a prior `set_cover` pruned, and the next reconcile's broadening
  /// delta against `None` would grow nothing over the hole; keeping it merely
  /// under-claims the freshly-armed slice, the safe direction).
  ///
  /// The caller (the driver's widen commit) has ALREADY armed `reserved` on
  /// the live transport and replays that outcome via
  /// [`on_watch_installed`](Self::on_watch_installed) immediately after this
  /// input; the replay's cold enumerate discovers the newly covered ground as
  /// `Created`s — a birth-equivalent window, dominated by nothing.
  ///
  /// Returns how the commit was disposed of ([`WidenCommit`]).
  /// [`TaintedWindow`](WidenCommit::TaintedWindow) collects the three
  /// unprovable-commit gates. The witnessed-window one (INV-ROOT): a reserved
  /// death record or a scope loss signal landed between the reservation and
  /// this commit, so the reserved binding cannot be proven live. The
  /// adopted-object one: the OLD root's identity does not fit the Monitor's
  /// enumerate-mint space, so the widen's dark-window tripwire would have no
  /// expected object to re-prove the adopted edge against. The adopted-path
  /// one: the old root sits more than one segment down, so the splice's
  /// intermediate connectors would carry edges no marker proves and no
  /// `MoveSelf` invalidates. `Monitor::widen_root` refuses both of the latter
  /// two shapes outright — screened HERE so neither refusal reaches the
  /// driver-bug channel below. Any of the three refuses the
  /// splice with the core and Monitor untouched except for the
  /// spent window, and the caller (which owes no loudness — this is a
  /// legitimate outcome, and it must NOT close the window again) disarms the
  /// pre-armed descriptor and falls back to the general stream replace,
  /// re-establishing the binding through a fresh spawn barrier. Only the widen's
  /// zero-gap SHORTCUT is depth-capped: the stream replace re-roots to an
  /// arbitrarily distant ancestor, so no reachable root becomes unwatchable.
  /// [`Refused`](WidenCommit::Refused) — a violated precondition on a path
  /// the driver's gates make unreachable — leaves the core and the Monitor
  /// bit-identical, the window entry included (every refusal is decided
  /// before the first mutation), and the caller MUST treat it loudly: the
  /// widen falls back to the general stream replace (the driver clears the
  /// leftover window and keeps the registry on the OLD root — the widened
  /// entry publishes only after a `Committed`). A silent `Ok` over a refused
  /// splice would be a registry/core root divergence on the barrier-honesty
  /// path.
  pub(crate) fn on_root_widened(
    &mut self,
    scope: ScopeId,
    meta: RootMeta,
    reserved: WatchId,
    now: Instant,
  ) -> WidenCommit {
    let liveness = self.root_liveness_interval;
    let Some(state) = self.scopes.get_mut(&scope) else {
      return WidenCommit::Refused;
    };
    // The witnessed-window gate (INV-ROOT), FIRST: the window verdict is
    // prior to the splice's shape — a tainted window refuses regardless of
    // how well-formed the commit is, because the thing being committed (the
    // reserved binding) can no longer be proven live. Only the taint verdict
    // consumes the window (its defined semantics: the window is spent, the
    // fallback re-establishes); every later refusal leaves it intact for the
    // fallback commit to clear, preserving the bit-identical contract.
    match &state.pending_widen {
      Some(pending) if pending.reserved != reserved => {
        debug_assert!(false, "the committed reservation is the window's own");
        return WidenCommit::Refused;
      }
      Some(pending) => {
        if pending.tainted.is_some() {
          let spent = state.pending_widen.take().expect("just observed Some");
          return WidenCommit::TaintedWindow(WidenTaint {
            cause: spent.tainted.expect("just observed tainted"),
            benign: spent.benign,
          });
        }
      }
      None => {
        debug_assert!(false, "a widen commit follows its begin_widen_watch");
        return WidenCommit::Refused;
      }
    }
    debug_assert!(
      !state.profile.is_kernel_recursive() && state.profile == meta.backend,
      "a widen never crosses profiles or backends"
    );
    // The inotify lowering settles every batch inline (no probes, no park), so
    // there is no compiled old-root-relative state to cut or re-base. A future
    // probing/parking descending backend must revisit this keep-list.
    debug_assert!(
      state.park.active.is_none() && state.park.queued.is_empty(),
      "the descending profile parks nothing"
    );

    // The adopted chain: the old root's location relative to the new root. The
    // driver validated strict containment and UTF-8 before dispatching the
    // pre-arm; re-derive defensively and refuse untouched on any violation —
    // the driver falls back to the stream replace, whose commit publishes
    // spawn-minted truth (the registry still names the old root: the widened
    // entry publishes only after this commit succeeds).
    let Some(old_root) = state.root.clone() else {
      return WidenCommit::Refused;
    };
    let Ok(rel) = old_root.strip_prefix(meta.root.as_path()) else {
      debug_assert!(false, "the driver routes only strict widens here");
      return WidenCommit::Refused;
    };
    let mut chain = Vec::new();
    for component in rel.components() {
      let std::path::Component::Normal(os) = component else {
        debug_assert!(
          false,
          "a canonical strict suffix has only normal components"
        );
        return WidenCommit::Refused;
      };
      let Some(name) = os.to_str() else {
        debug_assert!(false, "the driver refuses a non-UTF-8 chain");
        return WidenCommit::Refused;
      };
      chain.push(Segment::new(name));
    }
    if chain.is_empty() {
      debug_assert!(false, "the driver refuses an equal-root widen");
      return WidenCommit::Refused;
    }
    // DEPTH ONE only. Past one segment the splice would mint intermediate
    // connectors whose edges nothing proves and nothing invalidates
    // ([`TaintCause::UnprovableChain`]), and `Monitor::widen_root` refuses that
    // shape outright — screened HERE, in the Monitor's own order (chain shape
    // before identity), so that refusal never reaches the driver-bug channel
    // below, exactly as the unmintable-identity screen does. A well-formed,
    // clean-window widen of a deep root is a LEGITIMATE fallback: the stream
    // replace re-roots to an arbitrary ancestor through a fresh spawn barrier,
    // paying a covering `Rescan` and a re-crawl instead of a window proof, so
    // the capability survives the refusal and only its zero-gap shortcut does
    // not. Spending the window is part of the disposal — the caller's
    // `TaintedWindow` arm deliberately does not close it, and a leaked entry
    // would poison a future widen's reservation on this scope if the fallback's
    // spawn then failed.
    if chain.len() > 1 {
      let spent = state
        .pending_widen
        .take()
        .expect("the taint gate above proved the window live");
      return WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::UnprovableChain,
        benign: spent.benign,
      });
    }
    // The adopted node's identity, in the enumerate-mint space (the bare inode
    // — see `mint`): the old root sits on the scope's own device by the widen
    // predicate, so the device-trust gate is satisfied by construction.
    let old_identity = state
      .identity
      .and_then(|id| u64::try_from(id.ino()).ok())
      .and_then(NonZeroU64::new)
      .map(Identity::new);
    // No mintable identity, no adoption. `widen_root` requires one — it is the
    // only thing the tail's first read can re-prove the adopted edge against,
    // and confirming that edge on ignorance would certify a dark-window swap.
    // Screen it here so the Monitor's refusal stays what the assert below says
    // it is (a driver bug), and dispose it as the window's own legitimate
    // spend: the fallback replace rebuilds the binding from a fresh spawn
    // barrier, which needs no identity to be correct. Consuming the window is
    // part of that disposal — the caller's `TaintedWindow` arm deliberately
    // does not close it, and a leaked entry would poison a future widen's
    // reservation on this scope if the fallback's spawn then failed.
    let Some(old_identity) = old_identity else {
      let spent = state
        .pending_widen
        .take()
        .expect("the taint gate above proved the window live");
      return WidenCommit::TaintedWindow(WidenTaint {
        cause: TaintCause::UnmintableIdentity,
        benign: spent.benign,
      });
    };
    let Some((_, attempt)) = self
      .monitor
      .widen_root(scope, reserved, chain, Some(old_identity))
    else {
      debug_assert!(false, "a live descending scope accepts its widen splice");
      return WidenCommit::Refused;
    };

    // Watch bookkeeping: the new root joins the scope map, and the old
    // subtree's addressing needs no rewrite — paths are DERIVED, and the splice
    // above already re-rooted the old root under the adopted chain, so every
    // watch beneath it composes the same absolute path off the new origin.
    let root = Arc::new(meta.root);
    self.watch_scopes.insert(reserved, scope);
    state.watch = reserved;

    // The world swap — the same adoption `on_root_replaced` performs, minus
    // every cut: the new root is a different object, so mount trust fails
    // closed until the refresh this arms completes, and an in-flight refresh
    // was addressed to the OLD root and must be discarded on completion.
    state.root = Some(root);
    state.root_dev = Some(meta.root_dev);
    state.root_mnt_id = meta.root_mnt_id;
    // A different root on a barrier read that answers no token: the old world's
    // proven incarnation belongs to a mount this scope no longer watches, so it is
    // dropped rather than compared against the new world's first refresh.
    state.root_incarnation = None;
    state.frame_epoch = state.frame_epoch.wrapping_add(1);
    state.identity = Some(meta.identity);
    // The widened world's baseline, seeded from its own barrier read — the same
    // swap `on_root_replaced` performs, and for the same reason: the ADDED
    // ground is enumerated by the chain arm's cold read, which declines beneath
    // any mount it finds there, so a lazy unmount racing that read is invisible
    // to a baseline that starts empty. The old root's rows go with the old
    // world; only this read's rows are diffed.
    // The new world's set is COMPLETE the moment it is seeded — this barrier read
    // and this world's own seed walk are exactly the evidence a generation carries
    // — so the watermark is the world it was taken in, and the old world's
    // outstanding round trip goes with the rest of that world's state: it addresses
    // a root this scope no longer watches, and the swap's own covering `Rescan`
    // owes the consumer the whole new tree regardless.
    state.generation_applied();
    state.pending_recovery = None;
    state.published_epoch = None;
    state.census = census_of(&meta.mounts);
    state.ledger.clear();
    install_mount_table(state, meta.mounts.into_iter().map(|row| row.location));
    // The old world's learned prefixes describe a root this scope no longer
    // watches (a birth has none), so they go with the rest of that world. Nothing
    // else may empty this set: see [`ScopeState::learned_mounts`].
    state.learned_mounts.clear();
    // SEAM 2: the boundaries this world's OWN seed walk declined, recorded in
    // the same step that seeds the baseline from the barrier read — so the set
    // is whole before the scope is live, never completed by a later message.
    // These are the ONLY boundaries a kernel-recursive scope ever learns
    // without a mount table: the walk is its only fence, and it runs once, at
    // spawn. Empty on every backend that walks nothing.
    record_declined(state, &meta.declined);
    state.refresh_world_stale = state.refresh_pending;
    // Every cover PARKED on an outstanding admission round trip dies with the
    // old world, `refresh_world_stale` style: the location it addresses is a
    // path under a root this scope no longer watches, the reader that was going
    // to answer it is being retired, and the swap's own covering `Rescan` owes
    // the consumer the whole new tree regardless. Leaving one parked would hold a
    // cover for a reply that can never arrive.
    state.pending_admits.clear();
    // The witnessed window is CONSUMED by the commit (INV-ROOT): it was clean
    // through the taint gate above, the splice landed, and from here the
    // reserved id is a KNOWN root — its death records run the ordinary
    // in-band funnel, so the commit is a regime boundary, never a flush (a
    // death record still queued at this instant invalidates the widened root
    // honestly when it drains). The proof the window discharges: the pre-arm
    // bound the right object (open-verify-install + the post-arm bracket), a
    // binding bound right that later dies or moves emits a death record or
    // its loss is signalled, and neither happened — so the binding is live
    // and correctly placed NOW, with no out-of-band sample consulted.
    state.pending_widen = None;
    Self::trust_lost(&mut self.effects, scope, state);
    Self::arm_liveness(state, liveness, now);

    // A lag-parked Rescan crosses the commit as the WIDENED scope's drop
    // license: while the lag stands, route_event keeps dropping scope-wide —
    // from here that includes the added ground and its cold-read discoveries
    // — so the parked instruction is re-parked at the NEW root (empty
    // location, id + epoch kept), never merely re-based under the adopted
    // prefix: a prefix-joined location would cover only the old subtree
    // while licensing widened-scope drops (INV-PARK). An over-wide
    // re-enumeration is the honest direction. (D1 needs neither — its commit
    // parks a fresh dominating ROOT Rescan through the overflow cut.)
    if let LagState::Lagged {
      parked: Some(change),
      ..
    } = &mut state.lag
    {
      debug_assert!(change.kind().is_rescan(), "only Rescans park under lag");
      *change = Change::new(
        change.id(),
        scope,
        Location::new(),
        change.kind().clone(),
        change.epoch(),
      );
    }

    // The chain arms and the replayed root arm's cold read lower through the
    // ordinary drain — the live port is the attached port, so no transport
    // work exists here at all.
    self.drain_monitor();
    WidenCommit::Committed(attempt)
  }

  /// SEAM 2, live half: records the boundaries a source's own WALK declined —
  /// the post-loss whole-map reseed, the moved-in subtree walk and the admission
  /// reseed, all of which run on the reader thread and reach the core on the
  /// source's one ordered queue.
  ///
  /// The SPAWN walk's declines do not come through here. They are pre-live facts
  /// and ride [`RootMeta::declined`](crate::os::RootMeta) into the same world
  /// swap that seeds the baseline from the barrier read, so a scope is never live
  /// with a half-built set.
  ///
  /// # Why this exists at all, and only on a kernel-recursive profile
  ///
  /// A descending profile learns its boundaries from its own enumerates (seam 1):
  /// every cover re-arms a crawl, and the crawl re-runs the decline. A
  /// kernel-recursive mark runs no enumerate — `Monitor::start_rearm` refuses
  /// outright on a non-descending scope — so the walk is the ONLY place fanotify
  /// ever fences a directory, and a decline it dropped is a boundary nothing in
  /// the system would see again.
  ///
  /// The core takes what the walk decided rather than deriving anything of its
  /// own: the walk holds pinned fds and reads each child's frame from the object
  /// it actually opened, which is evidence no later path-based re-derivation
  /// could reproduce honestly.
  ///
  /// The [`Standing`] is [`record_boundary`]'s to settle from the ids the walk
  /// read, exactly as it is for seam 1 and seam 4.
  ///
  /// # A WHOLE-ROOT report also RETIRES
  ///
  /// A complete walk from the root is not just a list of additions: it is a
  /// generation, and the only one a kernel-recursive profile ever gets. The
  /// mount table cannot retire an exempt ledger entry — a subvolume is absent
  /// from every census by construction — and the compiled-removal pass
  /// ([`retire_removed_boundaries`](Self::retire_removed_boundaries)) reads the
  /// event stream, which a loss window empties. So without this, one lost
  /// deletion kept its record for the scope's life.
  ///
  /// The sweep runs BEFORE the recording, so a boundary this very walk declined
  /// survives it and a stale record cannot block the containment rule for a live
  /// boundary recorded under it.
  ///
  /// # A generation from a root this scope does not hold publishes NOTHING
  ///
  /// This is [`on_root_recovered`](Self::on_root_recovered)'s check on the OTHER
  /// message that carries a whole-root generation, and it is the same defect: "what
  /// this walk did not decline is not there any more" is a claim about a particular
  /// ROOT MOUNT, and applied under a different one it retires records for
  /// boundaries the walk never looked at. The partition it retires from is the one
  /// the mount table cannot see, so nothing puts those records back and the
  /// departure they would have witnessed becomes underivable — the revealed ground
  /// is never admitted and its events drop with no signal at all.
  ///
  /// So a complete report is checked against the root mount id its walk fenced
  /// against ([`WalkReach::WholeRoot`](crate::os::WalkReach)) and applies NEITHER
  /// half on a mismatch. `None` on either side passes, as every unknown frame leg
  /// does.
  ///
  /// **TWO stamps, not one.** The walked id alone was sufficient only against a
  /// root that moved and stayed moved. Mount ids are allocated lowest-free, so a
  /// root that went A → B → A is back on the id the core still holds while this
  /// walk ran against the FIRST A — a mount that has since died — and the
  /// comparison passes. So the report also carries the core's own frame EPOCH as
  /// the source last heard it, sampled before the walk began
  /// ([`WalkReach::WholeRoot`](crate::os::WalkReach)): a count of worlds, minted
  /// core-side, that no reading of a recycled id can forge.
  ///
  /// # What a mismatch owes, and what it does not
  ///
  /// It does NOT owe a cover, and that is the one place this differs from
  /// `on_root_recovered`: a whole-root report is produced only behind a loss, and
  /// the `Overflow` sitting immediately behind it on the source's one ordered queue
  /// covers the entire root whether or not the generation lands (the invariant
  /// [`retire_unwalked_boundaries`] already states and relies on).
  ///
  /// It does owe a GENERATION, and the one thing it records is that the generation
  /// EXISTED. Dropping this report is safe (the coverage set is left exactly as it
  /// was, which is the state the core already trusted) but not complete: an exempt
  /// boundary that appeared since the last generation is recorded nowhere, and the
  /// declines that would have recorded it went out with the report. That is why the
  /// need cannot be derived here from the set alone — the set is empty of exactly
  /// the evidence the derivation looks for — and why the rejection retains it
  /// ([`Generation::Lost`]), discharged only by a generation that actually lands.
  ///
  /// What IS done here is arming a refresh, and the reason is exactly the hole the
  /// previous version left. It used to arm none, on the argument that the
  /// `Overflow` immediately behind this report runs
  /// [`trust_lost`](Self::trust_lost) and arms one a message later. But boundary
  /// reports deliberately do not advance the loss dedup position, so a later loss
  /// can ride an OLDER `Overflow` already queued ahead of this report — whose
  /// refresh can complete before this report is even ingested. With liveness
  /// polling disabled there is then no later refresh at all, and the owed
  /// generation is never asked for. Arming here costs at most one extra table read
  /// (a following `Overflow` coalesces onto it), and buys the read that moves the
  /// frame this report says is wrong.
  ///
  /// # Nothing is owed back at the bound
  ///
  /// A decline the bound REFUSES is a boundary this scope cannot derive a
  /// departure for — but the bound only refuses when the ledger is full of
  /// entries that may yet owe a cover, and on a host that cannot key them such a
  /// scope already covers its whole root on every authoritative refresh
  /// ([`ScopeState::fails_closed`]). The
  /// per-refusal `Overflow` this seam used to stand needed a saturation latch to
  /// keep it from storming (it re-observes the same boundaries on every later
  /// walk), and that latch silenced every refusal after the first.
  pub(crate) fn on_walk_boundaries(
    &mut self,
    scope: ScopeId,
    boundaries: crate::os::WalkBoundaries,
    _now: Instant,
  ) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    if let Some((walked, stamped)) = boundaries.reach.whole_root_stamp() {
      // An unknown id on EITHER side passes, exactly as `on_root_recovered`'s own
      // leg does; the epoch carries the check there. The epoch is compared for
      // equality unconditionally — it is core-owned, so every host has one.
      let walked_elsewhere = matches!(
        (walked, state.root_mnt_id),
        (Some(walked), Some(current)) if walked != current
      );
      if stamped != state.frame_epoch || walked_elsewhere {
        // Neither half — see the section above. The DECLINES are dropped, and that
        // is what has to be recorded: a complete generation existed and this scope
        // did not get it, so whatever exempt boundary it was carrying is now in no
        // set any derivation can read. Retaining the fact costs one bit and is
        // discharged by exactly one event (a generation landing); deriving it
        // instead reads a coverage set that this very rejection kept empty.
        //
        // No key is spent, and none is cleared: an autonomous report is
        // UNREQUESTED, so no arming of this core's can produce another and there is
        // no loop to bound, while a key held from an earlier refused REQUEST still
        // describes a disagreement only a landing generation answers. That is also
        // why the answer is DISCARDED here and nowhere else: with nothing this core
        // did able to produce a repeat, there is no cycle for `reasked` to bound.
        let _ = state.generation_lost(None);
        // And the read is a VERDICT, so it names the observation that proves it.
        // This report proves a generation was lost; what says a READ is owed is
        // `owes_whole_root`. A fanotify reader that sampled epoch N, took a
        // current-epoch recovery request while its autonomous loss reseed was still
        // running, and reported stamped N leaves `pending_recovery` already
        // covering the missing generation at N+1 — and on a host whose incarnation
        // token is the namespace counter (5.17–6.7: any mount anywhere reads as a
        // frame move) the read this used to arm unconditionally moves the epoch
        // before that open recovery replies, refusing it and buying a SECOND
        // whole-root walk to replace the one already in flight.
        //
        // Nothing is silenced by declining: the evidence just retained keeps the
        // need derivable, so whichever site next finds it unserved buys the read.
        if state.owes_whole_root() {
          Self::arm_refresh(&mut self.effects, scope, state, RefreshCause::Invalidating);
        }
        return;
      }
      retire_unwalked_boundaries(state, &boundaries.declined);
      // The set is now COMPLETE under the frame this scope holds, which is the one
      // fact `generation_stale` reads. One of only two message sites that apply a
      // generation, and therefore one of only two that may discharge the evidence a
      // loss left — the refusal key with it.
      state.generation_applied();
    }
    record_declined(state, &boundaries.declined);
  }

  /// Parks EVERY departed boundary's cover on a fresh admission round trip and
  /// emits the ONE request that carries the whole burst.
  ///
  /// Takes `effects` and `admit_seq` beside `state` (like
  /// [`arm_refresh`](Self::arm_refresh) takes `effects`) so it composes with a
  /// `&mut ScopeState` borrowed out of `self.scopes`.
  ///
  /// Each location travels as the absolute path the transition was derived at,
  /// not as anything re-derived from the root: it came off a census row (or a
  /// ledger entry) under this very root, rebased onto any rename the core saw,
  /// and the walk addresses it directly.
  ///
  /// # Why the burst is ONE effect
  ///
  /// One refresh condemns a whole run of records at once, and the requests must
  /// reach the source INDIVISIBLY: a source that can observe a prefix of the burst
  /// snapshots that prefix into a whole-root recovery and takes the remainder as a
  /// second obligation, buying a second whole-root walk and a second report — and
  /// at the supported boundary budget of one, the second report kills a source that
  /// had nothing wrong with it. Emitting one effect is what lets the driver hand
  /// the run over under a single mailbox post (see
  /// [`Effect::AdmitBoundaries`]).
  ///
  /// Empty in, nothing out: a verdict that condemned nothing emits no request.
  fn park_admissions(
    effects: &mut VecDeque<Effect>,
    admit_seq: &mut u64,
    scope: ScopeId,
    state: &mut ScopeState,
    departed: Vec<PathBuf>,
  ) {
    if departed.is_empty() {
      return;
    }
    let requests = departed
      .into_iter()
      .map(|location| {
        *admit_seq += 1;
        let ticket = crate::os::AdmitTicket::new(*admit_seq);
        state.pending_admits.push(PendingAdmit {
          ticket,
          location: location.clone(),
          epoch: state.frame_epoch,
        });
        crate::os::AdmitRequest {
          ticket,
          location,
          // The frame this request is ISSUED against. Read off the scope's
          // CURRENT state, which the refresh above has just re-adopted, so a root
          // that re-mounted is compared against the mount it lives on now. The
          // walk does not fence on it — it re-reads the root's own frame at
          // execution time, beside the location's — but it refuses the request
          // when the two disagree, which is what keeps a frame that moved during
          // the round trip from being substituted for the one this scope's
          // coverage set is relative to.
          frame: ScopeFrame {
            root_dev: state.root_dev,
            root_mnt_id: state.root_mnt_id,
          },
          // The same epoch the park above recorded, on the wire this time: a
          // recovery that collapses this request stamps its reply with it.
          epoch: state.frame_epoch,
        }
      })
      .collect();
    effects.push_back(Effect::AdmitBoundaries { scope, requests });
  }

  /// Asks a fanotify scope's source for ONE whole-root recovery: reseed the
  /// entire admission map from the root, report the complete generation that
  /// walk produces, cover the whole root, and discharge every admission ticket at
  /// or below the one this mints.
  ///
  /// # Why the root cover cannot simply be emitted here
  ///
  /// It is the same reason a located departure cover parks: fanotify admits by
  /// directory-handle MEMBERSHIP, so ground the map has never seen is ground the
  /// source cannot report on. A bare `Scope::Root` cover would send the consumer
  /// to re-read a tree the source is partly blind to, and every mutation between
  /// that re-read and some later reseed would drop on an unknown handle with no
  /// loss signal at all. So the cover travels WITH the reseed, on the reply —
  /// admission-before-cover, at root scope.
  ///
  /// # Ticket, not fire-and-forget
  ///
  /// The ticket is minted from the same monotone counter
  /// [`park_admissions`](Self::park_admissions) uses, and that is what makes the
  /// cutoff meaningful: every round trip this scope opened BEFORE this one has a
  /// lower ticket, and the recovery subsumes all of them (a whole-map reseed
  /// admits strictly more than any located walk, and its complete generation
  /// re-records every boundary that is still live). Nothing is parked for it —
  /// the reply carries the root cover itself.
  ///
  /// A scope with no live source resolves the round trip inline through
  /// [`on_recovery_unreachable`](Self::on_recovery_unreachable), exactly as an
  /// unreachable admission resolves.
  ///
  /// # Stamped with the frame it is issued against
  ///
  /// `epoch` is the scope's [`frame_epoch`](ScopeState::frame_epoch) NOW, and it
  /// rides the round trip exactly as [`park_admissions`](Self::park_admissions)'
  /// does. The reply echoes it back, and
  /// [`on_root_recovered`](Self::on_root_recovered) applies nothing from a
  /// recovery whose stamp is no longer the scope's — a reseed walked in a world
  /// this scope has left describes a coverage set that is not the one it holds.
  ///
  /// # The round trip is RECORDED, and that is what replaces the debt
  ///
  /// [`pending_recovery`](ScopeState::pending_recovery) holds it until an answer
  /// ARRIVES. While it stands with this scope's current epoch, no second recovery
  /// is asked for — the reply that is coming carries the generation, the cutoff and
  /// the cover together, so a duplicate walk is all a second request could buy. The
  /// moment the frame moves out from under it, the same record says the reply can
  /// never be applied and the round trip is owed again. One piece of state, both
  /// directions, and nothing to clear.
  ///
  /// It is discharged by an answer, applied or refused, and not by one that was
  /// merely useful: a refusal applies nothing but ends the round trip just as
  /// surely, and a record kept past its own reply is a suppression resting on a
  /// prediction rather than on anything outstanding — see
  /// [`on_root_recovered`](Self::on_root_recovered).
  ///
  /// A recovery ALWAYS supersedes an older outstanding one: tickets are monotone,
  /// so the newer cutoff discharges everything the older one would have.
  fn request_root_recovery(
    effects: &mut VecDeque<Effect>,
    admit_seq: &mut u64,
    scope: ScopeId,
    state: &mut ScopeState,
    epoch: u64,
  ) {
    *admit_seq += 1;
    let ticket = crate::os::AdmitTicket::new(*admit_seq);
    state.pending_recovery = Some(PendingRecovery { ticket, epoch });
    effects.push_back(Effect::RecoverRoot {
      scope,
      request: crate::os::RecoveryRequest { ticket, epoch },
    });
  }

  /// Feeds ONE whole-root recovery back from a source: the complete generation
  /// its reseed walk produced, the tickets it discharges, and the root cover it
  /// owes — in that order, which is the same order every other walk driver
  /// follows and for the same reason.
  ///
  /// 1. **the generation first.** The declines are recorded (and the records the
  ///    walk did NOT decline retired) before anything makes the consumer re-read
  ///    the ground, so a boundary is in the coverage set ahead of its own cover.
  ///    This is also what restores the records the collapse dropped: a boundary
  ///    the reseed re-declined is still live, and re-enters here.
  /// 2. **the cutoff next.** Every parked cover at or below the cutoff is
  ///    discharged in ONE retain — linear in the parked set, not one search per
  ///    ticket. The located covers they held are dominated by the root cover
  ///    below, so none is emitted.
  /// 3. **the cover last** — a root-scope cover, and NOTHING ELSE.
  ///
  /// # Why this is not routed through the loss path
  ///
  /// It was, and that was a spin loop rather than a cost. A transport loss
  /// re-arms the mount refresh ([`trust_lost`](Self::trust_lost)); a scope that
  /// FAILS CLOSED answers every authoritative refresh with a recovery; so
  /// recovery → loss → refresh → recovery turns over as fast as the driver can
  /// run it, with a whole-map reseed and a root rescan on every iteration. The
  /// accepted cost is ONE of those per liveness tick, not one per scheduler
  /// round.
  ///
  /// Nothing is lost by leaving the loss semantics out. A reseed runs BETWEEN
  /// two reads on the reader's own thread, so no event is dropped for it: the
  /// kernel queue holds what arrives meanwhile, parked batches stay valid, and
  /// the mount table this refresh just read is exactly as authoritative as it
  /// was a statement ago. What the reseed does change is which ground the map
  /// can see — and the root cover is the whole answer to that.
  ///
  /// # A recovery from a SUPERSEDED frame publishes NOTHING
  ///
  /// All three of the things above are relative to the frame the walk ran on. The
  /// generation is a claim about where coverage ENDS under a particular root
  /// mount; the cutoff drops parked round trips on the strength of that claim
  /// dominating them; the cover tells the consumer the ground behind it is
  /// admitted. A reseed that walked frame A while this scope has since adopted
  /// frame B is none of those things for B — and the failure is silent both ways:
  /// a nested mount B reveals is absent from A's map, so the cover promises ground
  /// the source cannot see, while B's own boundaries are retired by a generation
  /// that never looked at them.
  ///
  /// The race is ordinary. A recovery is a queued message behind a reader thread's
  /// whole-tree walk; a mount refresh runs on the blocking pool and is ingested
  /// the moment it lands. Nothing orders the two, and with a zero root-liveness
  /// interval there may be no later refresh to correct the map at all.
  ///
  /// So the reply is checked against BOTH stamps before anything is applied — the
  /// epoch it was ISSUED at ([`RootRecovery::epoch`](crate::os::RootRecovery)) and
  /// the root mount id the walk actually fenced against
  /// ([`root_mnt_id`](crate::os::RootRecovery::root_mnt_id)) — and a mismatch in
  /// either applies NEITHER the generation NOR the cutoff. The two legs cover each
  /// other: the epoch counts worlds core-side, so a re-mount that recycled its own
  /// mount id cannot forge it, while the walked id speaks for the SOURCE, catching
  /// a root that moved before this core ever ran the refresh that would bump an
  /// epoch. Every parked round trip is left parked and answered on its own terms
  /// ([`on_admitted`](Self::on_admitted) makes the same epoch judgement for each).
  ///
  /// What a mismatch OWES is a fresh recovery — the cover this reply was carrying
  /// is still owed, and only a walk on the current frame may carry it — but it is
  /// NOT asked for here. The generation is recorded LOST
  /// ([`Generation::Lost`]), because this reply's declines were the only record of
  /// any exempt boundary that appeared since the last one landed. The round trip this reply DOMINATES is discharged
  /// ([`pending_recovery`](ScopeState::pending_recovery)): its one answer has come,
  /// nothing further will ever be sent for that ticket, and a record whose whole
  /// meaning is "a request is out" may not outlive the request — while a NEWER
  /// request, minted after this reply was produced, sits above the cutoff and is
  /// preserved. A mount refresh is armed IF the need is still unserved after that
  /// discharge — a round trip still standing in this scope's own world already
  /// carries everything the read would ask for again — and that refresh publishes a
  /// frame and re-derives the need in the same disjunction the fail-closed rule and
  /// the collapse use, so the fresh request is stamped with a frame just read
  /// rather than the one being disputed.
  ///
  /// # The retry is spent, not predicted away
  ///
  /// The round trip used to be LEFT STANDING here, as an anti-spin latch: while
  /// this scope held the same world, the argument ran, a fresh request would be
  /// answered by a walk that reads the same root and is refused identically. That
  /// is a claim about the SOURCE's world derived from a value this core re-reads
  /// (its own frame, unchanged), and it is loudest exactly where it is wrong. On
  /// Linux 6.8+ a transient same-object self-bind puts a mount B over the root, the
  /// walk fences against B, and B departs before the refresh: the root is back on
  /// the mount OBJECT it started on, so the legacy id AND the never-recycled
  /// incarnation token both read unchanged, the epoch cannot move, and a record
  /// standing at the current epoch suppressed every later refresh for the life of
  /// the scope — the rejected generation's evidence and its cutoff-covered recovery
  /// stranded with it. Nothing about the observations distinguishes that from a
  /// source and a core that genuinely disagree; only a second walk does.
  ///
  /// So one retry is SPENT, and the refusal of the request spent on it is the
  /// observation. This arm is the only edge that could turn that into a self-driven
  /// loop — a refusal arms a read, the read re-derives the need and re-asks, the
  /// re-ask is refused — and it is closed on BOTH legs. A disagreement this scope
  /// has already re-asked under ([`RefusedWalk`] — same frame, same foreign root)
  /// arms no read of its own; and no refusal at all arms one while a round trip
  /// stands in the world this scope still holds
  /// ([`owes_whole_root`](ScopeState::owes_whole_root)'s first arm), because that
  /// reply carries the generation, the cutoff and the cover together and a read can
  /// only move the frame out from under it and refuse it too. The second gate is
  /// what the first cannot be: an EPOCH mismatch has no disagreement to key on — the
  /// epoch is what moved — so `reasked` is false by construction there, and on a
  /// pre-6.8 host, where any mount anywhere reads as a frame move, the cycle turned
  /// over at whole-root-walk speed for as long as the namespace churned.
  /// What is left is one recovery per REFRESH, which is precisely the cost a
  /// [`fails_closed`](ScopeState::fails_closed) scope pays on every authoritative
  /// refresh by design, and never one per scheduler round.
  ///
  /// Asking on the spot is still the spin, and that is why the refresh is the
  /// carrier: when it is the walked id that disagrees the CORE may be the stale
  /// party, so an immediate re-request would be answered by a walk that reads the
  /// same id — one whole-root reseed per turn with no read of the live table
  /// between them. Waiting for the refresh costs one round trip and puts a freshly
  /// published frame under the retry.
  ///
  /// The arming is [`arm_refresh`](Self::arm_refresh) and deliberately not
  /// [`trust_lost`](Self::trust_lost): a root that re-mounted invalidates this
  /// scope's FRAME, not the locations its last table read listed, and routing a
  /// recovery through the loss path is the spin the section above rejects.
  pub(crate) fn on_root_recovered(
    &mut self,
    scope: ScopeId,
    recovery: crate::os::RootRecovery,
    now: Instant,
  ) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    // An unknown id on EITHER side passes, exactly as every unknown leg of
    // `ScopeFrame::crossed_by` does: below Linux 5.8 nothing reports a mount id,
    // and reading unknown as "different" would reject every recovery such a host
    // can produce. The epoch carries the check there.
    let walked_elsewhere = match (recovery.root_mnt_id, state.root_mnt_id) {
      (Some(walked), Some(current)) if walked != current => Some(walked),
      _ => None,
    };
    if recovery.epoch != state.frame_epoch || walked_elsewhere.is_some() {
      // So the retry is not predicted away — it is SPENT, and the refusal of the
      // request spent on it is the observation the prediction wanted. This arm is
      // the one edge that could make that a self-driven loop: a refusal arms a
      // read, the read re-derives the need and re-asks, the re-ask is refused. It
      // is broken by evidence rather than by a cadence — a disagreement this scope
      // has ALREADY re-asked under (same frame, same foreign root, so the second
      // walk was raised in full knowledge of the first) arms no further read of its
      // own, and the retry falls back to the refresh cadence, which is the one
      // recovery per refresh a `fails_closed` scope already pays.
      //
      // A DIFFERENT foreign root arms again: the source's world moved between the
      // two walks, so the second reply is fresh information, not a repeat.
      let disagreement = walked_elsewhere.map(|walked| RefusedWalk {
        walked,
        epoch: state.frame_epoch,
      });
      // Applied NOTHING, so the generation this reply carried is gone — the same
      // evidence an autonomous report's rejection leaves, and for the same reason:
      // its declines were the only record of an exempt boundary that appeared since
      // the last one landed. The disagreement rides it, keyed against the one held
      // BEFORE this refusal, which is what makes `reasked` a comparison of two
      // walks rather than of a key with itself.
      let reasked = state.generation_lost(disagreement);
      // The round trip is OVER. Its one reply has arrived; a refusal applies
      // nothing, but nothing more will ever be sent for this ticket either, so a
      // record that says "a request is out" must not survive it. Retired on the
      // same cutoff test the accepted path uses — the reply answers the ticket it
      // dominates and every ticket below — which is exactly what PRESERVES a newer
      // request: one issued after this reply was produced sits above the cutoff and
      // is still genuinely outstanding.
      //
      // Leaving it standing was a second meaning on one field, and a prediction
      // besides: that a fresh request would be refused identically. A transient
      // same-object self-bind makes that prediction wrong in the one direction that
      // costs — the walk fenced against a mount that is already gone, the root is
      // back on the mount OBJECT it started on so neither its legacy id nor its
      // unique incarnation token moved, and the standing record then suppressed
      // every later refresh for the life of the scope.
      if state
        .pending_recovery
        .is_some_and(|out| out.ticket <= recovery.cutoff)
      {
        state.pending_recovery = None;
      }
      // And the arm NAMES the observation that proves it. `reasked` keys on a
      // DISAGREEMENT, which covers only the walked-id leg: an EPOCH mismatch has no
      // such key (the epoch is what moved, so no two refusals can ever share one),
      // and the arming is itself what moves it — a refusal arms a read, the read
      // finds the frame moved and bumps the epoch, the bump refuses the reply
      // already in flight, and that refusal arms the next read. A pre-6.8 host
      // reads any mount anywhere as a frame move
      // ([`RootIncarnation::Namespace`](crate::os::RootIncarnation)), so a busy
      // namespace turns that cycle over at whole-root-walk speed, with the reader
      // walking instead of reading and `FAN_Q_OVERFLOW` behind it.
      //
      // "A reply was refused" is a fact about the read that ALREADY happened. What
      // says a read is still OWED is [`ScopeState::owes_whole_root`], whose first
      // arm is precisely this case: while a round trip stands in the world this
      // scope still holds, its reply will carry the generation, the cutoff and the
      // cover together, so the only thing a read could do is move the frame out
      // from under it and refuse it too. Nothing is silenced by waiting — the
      // rejection this arm just retained keeps the need derivable, so the moment
      // that standing round trip is itself answered, this same site finds the need
      // unserved and buys the read.
      //
      if !reasked && state.owes_whole_root() {
        Self::arm_refresh(&mut self.effects, scope, state, RefreshCause::Invalidating);
      }
      return;
    }
    retire_unwalked_boundaries(state, &recovery.declined);
    record_declined(state, &recovery.declined);
    // The set is COMPLETE under the frame this scope holds. One of only two message
    // sites that apply a generation, and therefore one of only two that discharge
    // the evidence a loss left — the refusal key with it.
    state.generation_applied();
    state
      .pending_admits
      .retain(|parked| parked.ticket > recovery.cutoff);
    // The outstanding round trip is discharged by a reply whose cutoff DOMINATES
    // it — which is also what makes a superseded request self-resolving: an older
    // reply that this one overtook was never applied, and this cutoff answers the
    // ticket that older request minted along with everything below it. A reply
    // whose cutoff falls short belongs to a request this scope has since replaced,
    // so the newer one stays out.
    if state
      .pending_recovery
      .is_some_and(|out| out.ticket <= recovery.cutoff)
    {
      state.pending_recovery = None;
    }
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
  }

  /// Resolves a whole-root recovery no source could take: there is no live
  /// stream, so nothing will reseed and nothing will answer.
  ///
  /// The cover is still owed and is emitted on the refresh's own verdict alone —
  /// exactly what [`AdmitOutcome::Unreachable`](crate::os::AdmitOutcome::Unreachable)
  /// does for a located cover. What is NOT done here is retiring parked tickets:
  /// a request that never reached a source discharges nothing, and each parked
  /// round trip is resolved on its own terms (its own `Unreachable`, a world
  /// swap, or the scope's death).
  pub(crate) fn on_recovery_unreachable(&mut self, scope: ScopeId, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    // RESOLVED, not applied: no generation landed, so the coverage set's own
    // watermark is untouched and a scope that still needs one will ask again on
    // its next refresh. What ends here is the ROUND TRIP — nothing will ever
    // answer a request no source took — and leaving it standing would suppress
    // every later request for as long as the frame held still.
    state.pending_recovery = None;
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
  }

  /// Feeds one admission round trip's answer: retires the parked cover and does
  /// whatever the answer still owes.
  ///
  /// This is the release half of admission-before-cover. The reply rides the
  /// source's ONE ordered queue behind the map mutation that produced it, so a
  /// cover emitted from here is a cover whose ground the source can already see.
  ///
  /// An unknown ticket is inert, and deliberately so — it is the shape every
  /// stale reply takes. A world swap clears the parked set (the location belongs
  /// to a root this scope no longer watches, and the swap's own covering `Rescan`
  /// owns the whole new tree), so a reply from the retired world arrives against
  /// no ticket; tickets are minted from a core-wide monotone counter, so it can
  /// never collide with one the new world parked.
  ///
  /// The three answers and what each still owes are
  /// [`AdmitOutcome`](crate::os::AdmitOutcome)'s. Two of them cover.
  /// [`StillCovered`](crate::os::AdmitOutcome::StillCovered) does not: the ground
  /// is still hidden, so there is nothing revealed to re-read, and what the walk
  /// found is a fresh SEAM observation that enters the ledger through
  /// [`record_boundary`] on its own terms — its own identity, its own
  /// [`Standing`], nothing inherited from the transition that parked the trip. A
  /// boundary that is standing and unrecorded has no derivable departure ever
  /// again, which is the whole reason the answer carries what the walk read.
  ///
  /// A ticket the source discharged through a whole-root recovery never arrives
  /// here at all: that recovery answers by CUTOFF
  /// ([`on_root_recovered`](Self::on_root_recovered)), in one linear pass over
  /// the parked set rather than one search per ticket.
  ///
  /// # A reply from a SUPERSEDED frame is not answered on its own terms
  ///
  /// The verdict that parked this round trip was taken against a descent frame,
  /// and both things the reply can still ask for are relative to it: what a
  /// `StillCovered` answer's ids MEAN (a [`Standing`] is the walk's id read
  /// against the root's, and a root that re-mounted between the park and the
  /// reply moved the root's half) and whether a located cover may be released
  /// against a world this scope still holds.
  ///
  /// So a reply whose [`epoch`](PendingAdmit::epoch) is not the scope's current
  /// one discharges into the whole-root recovery instead — and asks for one only if
  /// [`owes_whole_root`](ScopeState::owes_whole_root) still says so, because the
  /// recovery it discharges into may ALREADY BE OUT. The refresh that moved the frame saw this
  /// very ticket parked across worlds
  /// ([`parked_across_worlds`](ScopeState::parked_across_worlds)) and asked for a
  /// current-world recovery on the strength of it, with a cutoff that subsumes the
  /// ticket; this reply can arrive after that. Overwriting
  /// [`pending_recovery`](ScopeState::pending_recovery) unconditionally there made
  /// the source owe a SECOND whole-root walk once it had begun the first — and at
  /// the supported boundary budget of one, the second report kills a source that
  /// had nothing wrong with it. The judgement is therefore taken while the ticket
  /// is STILL PARKED, which is what keeps the derivation honest in the other
  /// direction too: the parked ticket is the only witness that the need exists at
  /// all, and retiring it first would leave the arm deriving `false` from a set it
  /// had just emptied.
  ///
  /// Retiring it after is safe in every branch. If the standing recovery is
  /// APPLIED, its root cover dominates the located one this reply was holding; if
  /// it is REFUSED, the refusal retains [`Generation::Lost`] and the need is
  /// re-derived from that; if no source ever answers it,
  /// [`on_recovery_unreachable`](Self::on_recovery_unreachable) emits the root
  /// cover itself.
  ///
  /// The parked ticket is dropped and no located cover is emitted, exactly as the
  /// departure COLLAPSE does, and for the same reason — the recovery's reseed
  /// walks from the root on
  /// the frame it reads there, its complete generation re-records every boundary
  /// still live, and its root cover dominates every located one it stands in for.
  ///
  /// This is the half for a request that ALREADY RAN. A request still queued when
  /// the frame moves is refused by the executor instead, which re-reads the root's
  /// frame beside the location's and escalates a superseded one into the very same
  /// recovery — so that one never reaches here at all, being discharged by the
  /// recovery's cutoff.
  pub(crate) fn on_admitted(
    &mut self,
    scope: ScopeId,
    report: crate::os::AdmitReport,
    now: Instant,
  ) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    let Some(index) = state
      .pending_admits
      .iter()
      .position(|parked| parked.ticket == report.ticket)
    else {
      return;
    };
    if state.pending_admits[index].epoch != state.frame_epoch {
      // BEFORE the retire, so `owes_whole_root` can still see the ticket that is
      // this need's only witness — and so it can see the recovery that may already
      // serve it. No generation was lost here (this reply carried none) and no key
      // is spent: the dispute is an epoch move, which no two refusals can ever
      // share.
      //
      // Asked on the spot rather than through a refresh: this arm disputes nothing
      // about the frame — the core's OWN refresh is what moved the epoch — so it
      // holds a frame a read has already published, and routing through another
      // read would re-derive the need from the very witness this arm is about to
      // retire.
      if state.owes_whole_root() {
        let epoch = state.frame_epoch;
        Self::request_root_recovery(&mut self.effects, &mut self.admit_seq, scope, state, epoch);
      }
      state.pending_admits.remove(index);
      return;
    }
    let parked = state.pending_admits.remove(index);
    if let crate::os::AdmitOutcome::StillCovered { mnt_id, .. } = report.outcome {
      // Nothing was revealed and nothing is covered: the walk found the location
      // still hidden, so the consumer has no new ground to read. What the walk DID
      // find is a seam observation like any other — it goes through
      // [`record_boundary`], which decides its [`Standing`] from the ids the walk
      // read, refuses it if the census already owns that id, and contains it
      // beneath anything already recorded.
      record_boundary(state, &parked.location, mnt_id);
      return;
    }
    let cover = mount_cover(state, scope, &parked.location);
    self.monitor.on_overflow(cover, now);
    self.drain_monitor();
  }

  /// Feeds a transport-level loss signal for `scope` (a dropped batch, the
  /// handle's overflow latch): parked work is dominated and dropped, and the
  /// Monitor turns the loss into an epoch-bumped `Rescan`.
  pub(crate) fn on_root_overflow(&mut self, scope: ScopeId, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    // The witnessed window's loss leg (INV-ROOT): a loss inside the widen
    // window may have carried the reserved root's own death records, so the
    // window can no longer witness their absence — taint it (coarse by
    // design: attribution of a loss is unknowable, so any scope loss taints).
    // The tainted commit falls back to the stream replace, whose covering
    // Rescan + fresh spawn barrier own the lost window anyway.
    if let Some(pending) = state.pending_widen.as_mut() {
      pending.taint(TaintCause::Loss);
    }
    state.park.active = None;
    state.park.queued.clear();
    Self::trust_lost(&mut self.effects, scope, state);
    self.probes.retain(|_, ctx| ctx.scope != scope);
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
  }

  /// Fails device trust closed after a loss signal: the dropped window may
  /// have carried a mount transition, so the table can no longer prove a path
  /// is root-device. Authority returns only with a fresh read of the live
  /// mount table; repeated losses coalesce onto one outstanding refresh.
  fn trust_lost(effects: &mut VecDeque<Effect>, scope: ScopeId, state: &mut ScopeState) {
    state.mounts_authoritative = false;
    Self::arm_refresh(effects, scope, state, RefreshCause::Invalidating);
  }

  /// Arms one mount-table refresh for `scope`, coalescing onto an outstanding
  /// one instead of stacking effects. Serves the birth refresh (authority is
  /// never presumed at spawn), every post-loss re-read, and the periodic tick.
  ///
  /// What the coalescing DOES to the outstanding read is `cause`'s business (see
  /// [`RefreshCause`]): an invalidating arming condemns it (`refresh_stale`, so
  /// its completion is discarded and one fresh read re-runs), a periodic one
  /// merely rides on it. Only the invalidating branch ever writes the flag, so a
  /// tick can neither condemn a sound snapshot nor absolve a condemned one.
  fn arm_refresh(
    effects: &mut VecDeque<Effect>,
    scope: ScopeId,
    state: &mut ScopeState,
    cause: RefreshCause,
  ) {
    if state.refresh_pending {
      if matches!(cause, RefreshCause::Invalidating) {
        state.refresh_stale = true;
      }
      return;
    }
    // No canonical root means no live stream: nothing to read yet, and the
    // spawn arm re-arms once the root installs.
    let Some(root) = state.root.clone() else {
      return;
    };
    state.refresh_pending = true;
    effects.push_back(Effect::RefreshMounts { scope, root });
  }

  /// (Re)arms the periodic refresh deadline for a signal-silent scope whose root
  /// is live, or clears it when the tick does not apply (a profile
  /// [`liveness_ticked`](Self::liveness_ticked) does not arm, `Duration::ZERO`,
  /// or a root not yet live). Called on every alive mount-refresh completion so
  /// birth seeds it and each refresh re-seeds it, and after
  /// [`on_timeout`](Self::on_timeout) fires a tick. Takes
  /// `interval` explicitly (like [`arm_refresh`](Self::arm_refresh) takes
  /// `effects`) so it composes with a `&mut ScopeState` borrowed out of
  /// `self.scopes`.
  fn arm_liveness(state: &mut ScopeState, interval: Duration, now: Instant) {
    state.liveness_deadline =
      (Self::liveness_ticked(state.profile) && !interval.is_zero() && state.root.is_some())
        .then(|| now + interval);
  }

  /// Feeds one mount-table refresh result: updates device trust AND checks the
  /// root's liveness (folded into the same refresh — a kernel-recursive backend
  /// gets no in-tree unmount signal, so this cadence is its root-death check).
  ///
  /// Publication is ordered: the root-liveness verdict acts FIRST and
  /// unconditionally (a dead root is terminal regardless of snapshot staleness);
  /// the mount table AND the descent frame (`root_mnt_id`) publish only on a
  /// non-stale snapshot; and a non-stale frame CHANGE reconciles a descending
  /// scope's coverage (see the module doc's publication invariant).
  pub(crate) fn on_mounts_refreshed(
    &mut self,
    scope: ScopeId,
    refresh: MountRefresh,
    now: Instant,
  ) {
    let interval = self.root_liveness_interval;
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    // The cross-world gate precedes even the death gate: this completion was
    // addressed to a root this scope REPLACED, so its liveness verdict is
    // about the old object — evidence for a world that ended at the commit,
    // not death evidence for the new one. Discard it whole and re-read the
    // live world (trust is already closed since the commit).
    if state.refresh_world_stale {
      state.refresh_world_stale = false;
      state.refresh_pending = false;
      state.refresh_stale = false;
      Self::trust_lost(&mut self.effects, scope, state);
      return;
    }
    state.refresh_pending = false;

    // Root-liveness FIRST, unconditionally — BEFORE the stale gate. A dead root
    // is terminal: mount-set staleness is irrelevant to it (a root that vanished
    // at the read's snapshot vanished, full stop), so the death evidence must
    // never be discarded by a stale flag. A loss arriving faster than refresh
    // latency stale-marks EVERY completion in turn, so gating the death check on
    // `!stale` would let a quiet unmount stay live for as long as the losses keep
    // coming — the exact hole the tick exists to close. (The tick itself does not
    // contribute to that: it coalesces without condemning, so the diff BELOW the
    // gate is not starved either — see [`RefreshCause`].) The death lowers through
    // the SAME self-event path a `RootChanged` probe uses (terminal
    // Removed/Rescan, then registry reclamation). Only a barrier-known identity
    // can be compared (an off-unix fake has none).
    let death = state.identity.and_then(|expected| match refresh.root {
      // Present and unchanged: alive, continue to the mount table below.
      RootLiveness::Present(live) if live == expected => None,
      // Present but a different object, or unreadable: the path no longer names
      // the watched object — MoveSelf, exactly as a `RootChanged` probe
      // resolving `Present`/`Failed`.
      RootLiveness::Present(_) | RootLiveness::Unreadable => Some(RecordKind::MoveSelf),
      RootLiveness::Missing => Some(RecordKind::DeleteSelf),
    });
    if let Some(kind) = death {
      let watch = state.watch;
      self.monitor.on_os_record(OsRecord::new(watch, kind), now);
      self.drain_monitor();
      return;
    }
    // Alive past the death gate. Deliberately NOT a barrier release edge: a
    // single-sample identity match proves the PATH still names the same
    // object, never that OUR watch is still its live binding (a same-identity
    // unmount+rebind passes it with the watch IGNORED), so no settle fence
    // may read anything from this positive. The widen's binding is proven at
    // its commit by the witnessed window instead (INV-ROOT); this gate's sole
    // job is the negative verdict above — a mismatch runs the death funnel.
    //
    // The stale gate governs EVERYTHING this snapshot carries — the mount-TABLE
    // install below AND the descent FRAME adopted after it. A newer loss overlapped
    // this read, so its snapshot may predate the lost window; `refresh_mounts` takes
    // the table and the root's stat inside ONE proven-still mount-namespace
    // generation (`crate::os::mount_sample` — the pair is rejected outright when the
    // namespace moved across it), so a stale table means an equally stale frame:
    // publish neither. The table is discarded, one fresh refresh re-arms, and device
    // trust stays closed. Liveness is already settled above (terminal regardless of
    // stale), so a stale-but-alive completion only re-arms: the frame block and the
    // table install below are BOTH the authoritative path.
    if state.refresh_stale {
      state.refresh_stale = false;
      Self::trust_lost(&mut self.effects, scope, state);
      return;
    }

    // Non-stale: adopt the freshly re-read mount frame. A same-object re-mount
    // (unmount + re-bind at the same path) keeps the root's `(dev, ino)`, so the
    // death gate above passed, yet the root now lives on a DIFFERENT mount — and
    // `crosses_mount_boundary` fences enumerate descent against this `root_mnt_id`,
    // so a frozen frame would lower every descendant on the new mount
    // non-descendable. Only a `Some` read is adopted: a transient mnt-id miss
    // (`None`) must not drop a known frame to the device belt. Gated behind the stale
    // check above, so `state.root_mnt_id` is only ever the last AUTHORITATIVE frame —
    // the value `crosses_mount_boundary` consumes is never a stale/pre-window one.
    //
    // TWO legs, and the second is what makes the first honest. An id comparison
    // observes a VALUE, and mount ids are allocated lowest-free: a root that went
    // A -> B -> new-A between two refreshes is back on the id this scope still
    // holds, the comparison passes, and the epoch — which every round trip is
    // stamped with — never moves. A walk that ran against the FIRST A then arrives
    // with both the legacy id and the epoch matching, its generation retiring
    // exempt records the live root never presented while its reseeded map
    // describes the dead incarnation. So the frame also moves on the INCARNATION
    // token, which is a transition the host observed rather than a value this
    // scope re-read (see [`RootIncarnation`](crate::os::RootIncarnation)).
    //
    // The token only ever ADDS a move. A refresh that answers none, or a host that
    // has none, compares nothing and leaves this exactly the id check it has always
    // been — which is what keeps every host without a mount namespace (and every
    // fake) on the behaviour it had.
    let incarnation_moved = matches!(
      (state.root_incarnation, refresh.root_incarnation),
      (Some(held), Some(read)) if held != read
    );
    if refresh.root_incarnation.is_some() {
      state.root_incarnation = refresh.root_incarnation;
    }
    let frame_changed = if let Some(mnt_id) = refresh.root_mnt_id {
      let changed = state.root_mnt_id != Some(mnt_id);
      state.root_mnt_id = Some(mnt_id);
      changed || incarnation_moved
    } else {
      incarnation_moved
    };
    // The one site where the frame can move under a LIVE parked round trip: the
    // swaps clear the parked set, this does not. See [`ScopeState::frame_epoch`].
    if frame_changed {
      state.frame_epoch = state.frame_epoch.wrapping_add(1);
    }
    // A frame change rebases NOTHING. Mount ids are absolute — a census row's key
    // and a ledger entry's [`Standing`] were both decided against the ids read at
    // one instant, and a root that moved to another mount changes neither. So the
    // census survives the change and the read below diffs against it: a same-object
    // remount that moved no mount under the root is quiet, where dropping the
    // census would have covered every one of them as an arrival.

    // Alive and current: (re)arm the liveness tick — the birth refresh seeds it
    // and every later refresh re-seeds it, regardless of whether the mount table
    // itself could be read below.
    Self::arm_liveness(state, interval, now);

    let fanotify = state.profile == BackendKind::Fanotify;
    // PUBLISH THE FRAME EPOCH. The source stamps its own unrequested whole-root
    // generation with this, and a mount id cannot stand in for it (ids are
    // allocated lowest-free, so a root that moved and came back carries the id the
    // core still holds). Only fanotify produces such a generation, so only fanotify
    // is told.
    //
    // Sent on the first non-stale refresh after a source is adopted and on every
    // one that finds the epoch moved since — never repeatedly for a value already
    // published. The first is what SEEDS a reader whose mailbox starts at zero into
    // a scope whose epoch has already moved (the birth adoption, or a world swap);
    // the rest is what keeps it current.
    if fanotify && state.published_epoch != Some(state.frame_epoch) {
      state.published_epoch = Some(state.frame_epoch);
      self.effects.push_back(Effect::PublishFrame {
        scope,
        epoch: state.frame_epoch,
      });
    }

    let mut covers: Vec<Scope> = Vec::new();
    // Whether this refresh ends by asking the source for a whole-root recovery.
    // Decided on BOTH branches below — the need is a question about what this scope
    // holds and which world it holds it in, and the mount table answers neither.
    let mut recover_root = false;
    if refresh.authoritative {
      let frame = refresh.mounts;
      // The mount diff, in BOTH directions, taken against the coverage set
      // BEFORE this frame installs. The two sets answer different questions and
      // must not be merged: coverage asks what MOVED since the last read (so a
      // stale extra prefix is precisely what hides a departed mount), trust asks
      // what is foreign NOW (so a missing prefix grants trust never proven). The
      // trust component this frame replaces below is one snapshot's rows; the
      // prefixes that could not survive replacement are learned elsewhere and
      // live elsewhere ([`ScopeState::learned_mounts`]), which is what lets the
      // rows be replaced without buying coverage at trust's expense.
      let mut covered: Vec<PathBuf> = Vec::new();
      // THE CENSUS DIFF, by KEY, old against new. The refresh's whole output is
      // a pure function of two observations: nothing was stored as an obligation
      // between them, and nothing is condemned on an ABSENCE — only on a
      // transition. A btrfs subvolume has no row in either census, so it
      // transitions in neither and is silent here forever, with no partition and
      // no per-record provenance to keep it that way.
      //
      // Planned against an index built ONCE, then applied. The obvious shape — a
      // `find` per row — is O(rows x rows) key comparisons on every refresh of
      // every watched root, and a large mount namespace (containers, systemd
      // private mounts, a snap-heavy desktop) has thousands of rows: the driver is
      // single-threaded, so that stalls every scope it owns and the stall itself
      // induces the queue loss this whole file exists to avoid.
      let census = census_of(&frame);
      // Departures travel separately from the located covers to the disposal
      // below: on a fanotify scope each one owes an admission round trip BEFORE
      // its cover, and no `retain`/`for` here can emit an effect.
      let mut departed: Vec<PathBuf> = Vec::new();
      {
        let held: BTreeMap<&Key, &CensusRow> =
          state.census.iter().map(|row| (&row.key, row)).collect();
        for row in &census {
          match held.get(&row.key) {
            // ARRIVAL. A mount that appears SHADOWS ground the consumer may
            // already have enumerated, so it owes the same cover a departure does
            // — this is what `compile::fsevents`' `plan_mount` plans for the
            // arrival macOS signals in band, reached here from the table for the
            // backends that signal nothing. Bounded per transition, never per
            // tick: this census is what makes the next read quiet.
            None => covered.push(row.location.clone()),
            // MOVE — the same mount, rendered somewhere else. BOTH locations are
            // covered: the ground it left is revealed and the ground it landed on
            // is shadowed. This is also what makes cross-read id recycling benign,
            // since a recycled id that landed elsewhere reads as a move and covers
            // the old location exactly as the departure it really was.
            Some(was) if was.location != row.location => {
              covered.push(was.location.clone());
              covered.push(row.location.clone());
            }
            // REPLACEMENT — the same key at the same place, and something about
            // the mount itself differs: its DEVICE, or the MOUNT IT HANGS OFF.
            // Two KNOWN values that disagree on either half, never a half this
            // read could not answer: see [`identity_changed`].
            //
            // The parent half is what the legacy mount id alone cannot say. Ids
            // are allocated lowest-free, so a mount that departs and one that
            // arrives inside one window hand the newcomer the freed id; if it
            // also landed at the same location on the same device, the device
            // comparison reads continuity and the ground it shadows is never
            // covered. Its parent is a different vfsmount unless it was mounted
            // onto the very same one, so reading BOTH turns that silent match
            // into a cover.
            Some(was)
              if identity_changed(was.dev, row.dev)
                || identity_changed(was.parent_id, row.parent_id) =>
            {
              covered.push(row.location.clone());
            }
            Some(_) => {}
          }
        }
        // DEPARTURE — a key this read did not list. #74's lazy unmount, which
        // emits no `IN_UNMOUNT`, no hangup and no `Rescan`. Covered at the OLD
        // row's location, which is the rebased hint rather than the label this
        // read rendered: a mount whose directory was renamed between the two reads
        // is covered where it actually stands ([`rebase_moved`]).
        let read: BTreeSet<&Key> = census.iter().map(|row| &row.key).collect();
        departed.extend(
          state
            .census
            .iter()
            .filter(|was| !read.contains(&was.key))
            .map(|was| was.location.clone()),
        );
      }
      state.census = census;
      // THE LEDGER JOIN, re-derived from the census this read just installed and
      // retained across nothing. Each entry answers one question — does the census
      // speak for me now? — and the answer is a fact about two observations rather
      // than a state some earlier step wrote down.
      //
      // A `Mount` entry leaves either way, and that is the belt working rather
      // than the belt being thrown away: it existed for exactly the window between
      // the seam that saw the mount and the first census that could, and this is
      // that census. Listed, the census owns the departure from here on; unlisted,
      // the mount went in that very window and this is the only place its
      // departure will ever be derivable.
      {
        let mut ids: BTreeSet<u64> = BTreeSet::new();
        let mut located: BTreeSet<&Path> = BTreeSet::new();
        for row in &state.census {
          if let Key::Id(id) = row.key {
            ids.insert(id);
          }
          located.insert(row.location.as_path());
        }
        state.ledger.retain(|entry| match entry.standing {
          Standing::Mount(id) => {
            if !ids.contains(&id) {
              departed.push(entry.location.clone());
            }
            false
          }
          // An `Unknown` entry is OCCUPIED once any census row stands at its
          // location, whatever keys that row. The entry's whole job is to be the
          // only witness a departure there could have, and a row at the location
          // ends that: from here on the census derives that place's departure,
          // its move and its replacement, and if what the seam saw was something
          // else UNDER the row, the row's own departure cover re-reveals it and
          // the crawl re-declines it.
          //
          // Matching only an id-less row would leave the floor kernel — 4.11-5.7,
          // where `/proc/self/mountinfo` has always carried mount ids and
          // `statx(STATX_MNT_ID)` does not exist — with every seam entry
          // `Unknown`, every census row `Id`-keyed, and nothing that could ever
          // clear one: a whole-root cover per refresh for the life of the scope,
          // on a kernel range that pays none today.
          Standing::Unknown => !located.contains(entry.location.as_path()),
          // A `SameMount` entry joins nothing, ever. No mountinfo read will list
          // a subvolume, so its absence from a census is evidence of nothing and
          // its presence in the ledger obliges nothing.
          Standing::SameMount => true,
        });
      }
      // One cover per PLACE. Two transitions can name one location — a key change
      // at a single `L` is a departure and an arrival there, a move can land where
      // something else left — and the consumer owes one re-read either way. Bounded
      // by the transitions rather than by the rows, which is what makes the clone
      // per entry free in every frame that moved nothing.
      dedup_locations(&mut covered);
      dedup_locations(&mut departed);
      // FAIL CLOSED, COLLAPSE, or an OWED recovery — the three states that answer
      // with one whole-root recovery instead of anything located. One request
      // between them, whichever combination holds: the recovery each wants is the
      // same work.
      //
      // Fail-closed is read AFTER the join, so this census has already settled
      // which entries are still `Unknown`: a row that stands where the last id-less
      // entry sat clears the state on the very refresh that read it, and a seam
      // observation that added one arms it on the very next.
      //
      // The collapse is the producer side of the admission bound. One refresh can
      // condemn every mount under the root at once, and handing the source a run
      // that long makes it allocate, queue and individually answer a request per
      // departure — the burst the bound exists to absorb, absorbed nowhere. It is
      // collapsed HERE, where the burst is produced, into the same single request.
      //
      // The owed recovery is DERIVED, not remembered
      // ([`ScopeState::owes_whole_root`]): a coverage set last verified in a world
      // this scope has left, or a cover parked on a round trip that world took
      // with it. It is asked for against the frame THIS read just published, which
      // is the whole reason it waits for one.
      let recover = state.fails_closed()
        || (fanotify
          && (state.owes_whole_root()
            || state.pending_admits.len() + departed.len() > MAX_PENDING_ADMITS));
      if recover {
        // The whole-root cover DOMINATES every located cover this census computed
        // — arrivals, moves, replacements and departures alike — so those are
        // dropped rather than emitted alongside it. On fanotify it also subsumes
        // every admission round trip they would have opened: the recovery reseeds
        // the whole map, which admits strictly more ground than one located walk
        // per departure, and the recovery's own whole-root generation re-records
        // every boundary that is still live.
        covered.clear();
        departed.clear();
        if fanotify {
          recover_root = true;
        } else {
          covers.push(Scope::Root(scope));
        }
      } else if fanotify {
        // Where a departure's cover goes. Every backend but fanotify covers here
        // and now: its source sees the revealed ground the instant the mount
        // leaves, so the cover is the whole obligation. FANOTIFY admits by
        // directory-handle MEMBERSHIP and its seed walk stopped at the mount, so
        // the revealed ground has no handles at all — covering now would send the
        // consumer to re-read a subtree the source is still blind to, and every
        // mutation until the next whole-map reseed would drop with no loss signal.
        // There, the cover PARKS on an admission round trip and the reply releases
        // it (see [`PendingAdmit`] and [`Effect::AdmitBoundaries`]).
        Self::park_admissions(
          &mut self.effects,
          &mut self.admit_seq,
          scope,
          state,
          departed,
        );
      } else {
        covered.extend(departed);
        dedup_locations(&mut covered);
      }
      // Lowered AFTER the census and the ledger are settled: `lower` reads only
      // the scope root, which this refresh does not touch, so the order is free
      // and taking it here keeps the borrow of the sets and the borrow of the
      // state apart.
      covers.extend(covered.iter().map(|path| mount_cover(state, scope, path)));
      // REPLACEMENT, and it is the whole table component. The union that stood
      // here kept every location the host ever presented, for the life of the
      // scope: on a container host cycling mount namespaces that is one `PathBuf`
      // per historical mountpoint plus a linear scan of that history per current
      // row per refresh, and "a stale prefix only vetoes" does not bound it.
      //
      // What the union was protecting is real, and it now lives in
      // [`ScopeState::learned_mounts`] where no snapshot can reach it: an in-band
      // mount word (a mount that may postdate the read in flight) and a probed
      // foreign device (a path no row will ever name). What is left here is one
      // snapshot's rows, and a row absent from an AUTHORITATIVE read is a mount the
      // host says is gone — the very fact that makes the path root-device again.
      // The reads are serialized (at most one outstanding, and a stale one
      // publishes no table at all), so this read is strictly newer than the one it
      // replaces; and on a backend with no absence-trust consumer the component
      // stays empty, which [`device_trusted`] reads as no trust rather than as
      // total trust.
      //
      // The enriched rows change nothing here: trust reads LOCATIONS.
      install_mount_table(state, frame.iter().map(|row| row.location.clone()));
      state.mounts_authoritative = true;
    } else {
      // The live table could not be read, so this refresh installs no table — and a
      // prior authoritative install may have left authority OPEN. Leaving it open
      // would keep proving paths root-device by their ABSENCE from a table we just
      // failed to re-read across the very mount change this refresh was meant to
      // reconcile. Close it: absence from an unreadable table is not evidence of
      // in-root-device. Both veto components are KEPT — this read witnessed no
      // departure, and a table it could not see condemns nothing — so the last
      // authoritative rows stand for the next authoritative read to replace, and
      // the learned prefixes stand until their own evidence retires them. The
      // coverage set is kept for the same
      // reason and diffed by the next authoritative read: a read that could not
      // see the table has not witnessed anything arrive or depart, and treating
      // its empty result as a diff would report the whole table gone on one bad
      // read.
      state.mounts_authoritative = false;
      // The owed recovery is judged HERE TOO, and that is not symmetry for its own
      // sake. Confining the discharge to the authoritative branch is what left a
      // rejected cutoff with no retry at all: with `root_liveness_interval` zero —
      // a supported setting — or a persistently unreadable mountinfo, the one
      // refresh a mismatch arms comes back here, closes trust, schedules nothing,
      // and the collapsed admissions stay parked forever with neither their
      // generation nor a root cover ever published.
      //
      // Nothing about the need depends on the table. The frame was adopted above
      // this branch (out of the root's own `statx`, which a failed table read does
      // not touch), so the request this issues is stamped with a frame just read —
      // exactly what waiting for a refresh was ever for.
      recover_root = fanotify && state.owes_whole_root();
    }

    // ONE request, whichever branch decided it, and stamped with the frame this
    // refresh has just published: the request names the world its reply will be
    // judged against.
    if recover_root {
      let epoch = state.frame_epoch;
      Self::request_root_recovery(&mut self.effects, &mut self.admit_seq, scope, state, epoch);
    }

    let kernel_recursive = state.profile.is_kernel_recursive();

    // One COVER per mount transition — never a delivery. A bind mount, or a
    // mount in another namespace, can make the same directory appear and
    // disappear with the watched object itself unchanged, so a synthesized
    // record would fabricate an event that did not happen; a cover only obliges
    // re-enumeration, and over-sending one is a cost rather than a bug. This is
    // the same shape (and the same reasoning) as `compile::fsevents`'
    // `plan_mount`, which plans `Planned::Over(located(..))` for the volume
    // change macOS does signal — in BOTH directions, as this does.
    //
    // Sent for a KERNEL-RECURSIVE profile too, unlike the frame replay below:
    // that replay is skipped there because only a descending scope consumes
    // `root_mnt_id` at all, whereas a mount transition changes what the tree
    // CONTAINS — the directory a departed mount was covering is visible again
    // and its contents were never enumerated; the ground an arriving mount
    // shadows was enumerated and is now something else — which one recursive
    // mark leaves just as unread as per-directory watches do.
    if !covers.is_empty() {
      for cover in covers {
        self.monitor.on_overflow(cover, now);
      }
      self.drain_monitor();
    }

    // A CHANGED frame means a same-object re-mount moved the root to a different
    // mount: every child the last enumerate already classified carries the OLD
    // verdict — those now on the root's mount were fenced as boundaries, those left
    // behind are boundaries now — and adopting the frame does not re-read them. Only
    // a descending scope consumes the frame (a kernel-recursive mark covers the whole
    // subtree, so its frame is inert), so only it needs the replay: rescan and re-arm
    // the root under the now-authoritative frame. The loss that drove this refresh
    // also rescans, but that rescan races AHEAD of this completion and reads the
    // pre-adoption frame; this replay reruns it once the frame is current.
    if frame_changed && !kernel_recursive {
      self.monitor.on_overflow(Scope::Root(scope), now);
      self.drain_monitor();
    }
  }

  /// Feeds a dead-stream signal: the scope's coverage ended with no parent
  /// watch left to report it.
  pub(crate) fn on_source_fatal(&mut self, scope: ScopeId, now: Instant) {
    let Some(state) = self.scopes.get(&scope) else {
      return;
    };
    let watch = state.watch;
    self
      .monitor
      .on_os_record(OsRecord::new(watch, RecordKind::Ignored), now);
    self.drain_monitor();
  }

  /// Feeds the outcome of one attempted [`Effect::Emit`].
  pub(crate) fn on_delivery(&mut self, scope: ScopeId, delivery: Delivery, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      // A dead scope: the outcome belongs to its retryable terminal `Rescan`
      // iff that offer is the one in flight — the driver reports each emit
      // synchronously, so an ordinary post-teardown emit and the dying offer
      // are never in flight together. An ordinary emit's refusal is covered
      // by the dying `Rescan` itself and needs no bookkeeping.
      if let Some(entry) = self.dying.get_mut(&scope)
        && matches!(entry.attempt, Attempt::InFlight(_))
      {
        match delivery {
          Delivery::Accepted => {
            self.dying.remove(&scope);
          }
          Delivery::Refused => {
            entry.attempt = Attempt::Spent {
              retry_at: now + DELIVERY_RETRY,
            };
          }
        }
      }
      return;
    };
    match (delivery, &mut state.lag) {
      (Delivery::Accepted, LagState::Lagged { parked, attempt }) => {
        let delivered_current = match (parked.as_ref(), &attempt) {
          (Some(change), Attempt::InFlight(epoch)) => change.epoch() == *epoch,
          _ => false,
        };
        if delivered_current {
          state.lag = LagState::Normal;
        } else {
          // A since-replaced Rescan was accepted: the newer one still owes
          // delivery, so it becomes offerable immediately.
          *attempt = Attempt::Idle;
        }
      }
      (Delivery::Accepted, LagState::Normal) => {}
      (Delivery::Refused, LagState::Normal) => {
        state.lag = LagState::Lagged {
          parked: None,
          attempt: Attempt::Idle,
        };
        // Everything this scope already queued is dominated by the Rescan
        // being minted below; delivering any of it after the refusal would
        // put an ordinary event ahead of the Rescan that covers the drop.
        Self::purge_scope_emits(&mut self.effects, scope);
        self.monitor.on_overflow(Scope::Root(scope), now);
        self.drain_monitor();
      }
      (Delivery::Refused, LagState::Lagged { attempt, .. }) => {
        // Never re-offer synchronously — the refusing channel cannot have
        // drained yet; the retry rides the core's timer.
        *attempt = Attempt::Spent {
          retry_at: now + DELIVERY_RETRY,
        };
      }
    }
  }

  /// Advances time: resolves rename halves whose pairing window elapsed,
  /// re-arms refused parked deliveries whose retry deadline passed, and fires
  /// the periodic mount refresh for every signal-silent scope whose tick came
  /// due (the ONE timer this composition adds — a quiet unmount produces neither
  /// a birth nor a loss refresh, so without this neither the root's death nor a
  /// departed mount below it would ever be observed).
  pub(crate) fn on_timeout(&mut self, now: Instant) {
    self.monitor.handle_timeout(now);
    for state in self.scopes.values_mut() {
      if let LagState::Lagged { attempt, .. } = &mut state.lag
        && let Attempt::Spent { retry_at } = attempt
        && now.reached(*retry_at)
      {
        *attempt = Attempt::Idle;
      }
    }
    for entry in self.dying.values_mut() {
      if let Attempt::Spent { retry_at } = entry.attempt
        && now.reached(retry_at)
      {
        entry.attempt = Attempt::Idle;
      }
    }
    // Fire due liveness ticks: each arms the existing `RefreshMounts` (whose
    // completion runs the root-death mapping AND the departure diff) and re-arms
    // the deadline for the next interval. Collected first so `arm_refresh` can
    // take `&mut effects` while each scope is mutated in turn.
    //
    // A refresh already in flight coalesces — `RefreshCause::Periodic`, so the
    // tick rides that read rather than condemning it. The deadline still
    // advances here, so a coalesced tick loses no obligation: the read it rode
    // publishes (installing the table, adopting the frame, deriving departures)
    // and re-seeds the deadline itself on its alive completion, so the cadence
    // simply re-bases off whichever of the two lands later. Condemning it
    // instead is what starves the whole publication path once refresh latency
    // reaches the interval (see [`RefreshCause`]).
    let interval = self.root_liveness_interval;
    let due: Vec<ScopeId> = self
      .scopes
      .iter()
      .filter_map(|(scope, state)| {
        state
          .liveness_deadline
          .filter(|deadline| now.reached(*deadline))
          .map(|_| *scope)
      })
      .collect();
    for scope in due {
      if let Some(state) = self.scopes.get_mut(&scope) {
        Self::arm_refresh(&mut self.effects, scope, state, RefreshCause::Periodic);
        Self::arm_liveness(state, interval, now);
      }
    }
    self.drain_monitor();
  }

  /// Dequeues the next I/O obligation, if any. A scope lagging with a parked
  /// `Rescan` — or a torn-down scope whose terminal `Rescan` is still owed —
  /// offers that delivery here once per attempt; a refusal re-arms through
  /// the retry timer, never synchronously.
  pub(crate) fn poll_effect(&mut self) -> Option<Effect> {
    if let Some(effect) = self.effects.pop_front() {
      return Some(effect);
    }
    for (scope, state) in self.scopes.iter_mut() {
      let root = match &state.lag {
        LagState::Lagged {
          parked: Some(_),
          attempt: Attempt::Idle,
        } => state.delivery_root(),
        _ => continue,
      };
      if let LagState::Lagged {
        parked: Some(change),
        attempt: attempt @ Attempt::Idle,
      } = &mut state.lag
      {
        *attempt = Attempt::InFlight(change.epoch());
        return Some(Effect::Emit {
          scope: *scope,
          root,
          change: change.clone(),
        });
      }
    }
    for (scope, entry) in self.dying.iter_mut() {
      if matches!(entry.attempt, Attempt::Idle) {
        entry.attempt = Attempt::InFlight(entry.change.epoch());
        return Some(Effect::Emit {
          scope: *scope,
          root: Arc::clone(&entry.root),
          change: entry.change.clone(),
        });
      }
    }
    None
  }

  /// The earliest instant [`on_timeout`](Self::on_timeout) has work to do: the
  /// Monitor's pairing deadline, a parked delivery's retry, or a scope's next
  /// root-liveness re-stat, whichever comes first.
  ///
  /// # Every table with its own lifetime is represented here
  ///
  /// The rule worth stating as one: a per-scope table whose entries expire on
  /// their own schedule must be REPRESENTED in the scheduler, or swept where it
  /// is consulted, or both. Retiring it as a side effect of some other timer
  /// happening to be armed is not a rule, it is a coincidence, and it survives
  /// only until the mechanism supplying the coincidence changes.
  ///
  /// The corollary is the cheaper defence, and the one the rename geometry now
  /// takes: a derived table with its own lifetime is a lifetime to schedule, so
  /// deriving nothing — reading the fact off the store that already owns it —
  /// removes the obligation rather than discharging it. The geometry's source end
  /// comes from the Monitor's own reparent report, which expires with the
  /// Monitor's own half, so there is no second expiry for this census to carry.
  ///
  /// The rule is checkable because the census is small. Every deadline stored
  /// anywhere under the run loop is one of three, and all three reach the loop's
  /// single `min_instant(core.poll_timeout(), cookies.min_retry_at())`:
  ///
  /// - the Monitor's pending-move deadline, via [`Monitor::poll_timeout`];
  /// - [`Attempt::Spent`]'s retry, for a scope's parked delivery and for a dying
  ///   scope's terminal `Rescan`;
  /// - [`liveness_deadline`](ScopeState::liveness_deadline), the signal-silent
  ///   root re-stat.
  ///
  /// (The driver's own sync-cookie remove-retry is the other term of that
  /// `min_instant`, outside this core.) A fourth stored deadline introduced
  /// anywhere without a leg here reopens the same class of wedge.
  pub(crate) fn poll_timeout(&self) -> Option<Instant> {
    let retry = self
      .scopes
      .values()
      .filter_map(|state| match &state.lag {
        LagState::Lagged {
          attempt: Attempt::Spent { retry_at },
          ..
        } => Some(*retry_at),
        _ => None,
      })
      .chain(self.dying.values().filter_map(|entry| match entry.attempt {
        Attempt::Spent { retry_at } => Some(retry_at),
        _ => None,
      }))
      .chain(
        self
          .scopes
          .values()
          .filter_map(|state| state.liveness_deadline),
      )
      .min();
    match (self.monitor.poll_timeout(), retry) {
      (Some(monitor), Some(retry)) => Some(if monitor.reached(retry) {
        retry
      } else {
        monitor
      }),
      (monitor, retry) => monitor.or(retry),
    }
  }

  /// Whether `scope`'s journal ids wrapped, invalidating any resume token.
  #[cfg(test)]
  pub(crate) fn resume_poisoned(&self, scope: ScopeId) -> bool {
    self
      .scopes
      .get(&scope)
      .is_some_and(|state| state.resume_poisoned)
  }

  /// Whether `scope` has a pending terminal `Rescan` in the dying set — a
  /// never-live scope must never appear here.
  #[cfg(test)]
  pub(crate) fn dying_contains(&self, scope: ScopeId) -> bool {
    self.dying.contains_key(&scope)
  }

  /// Every path this core currently holds — or is trying to hold — a kernel
  /// watch for, sorted: the descending COVERAGE set itself, as opposed to what
  /// happened to be delivered.
  ///
  /// An entry appears the moment the arm is queued and disappears when the node
  /// drops, so a directory that entered coverage shows up here even if its arm
  /// never completed and even if nothing was ever emitted for it. That is the
  /// distinction a delivery-only assertion cannot make, and exclusions are
  /// precisely a coverage question.
  ///
  /// Each entry names where its watch IS, not where it was armed: the set is
  /// derived per call ([`path_of`](Self::path_of)), so a rename the Monitor
  /// answered by re-parenting a subtree is reflected here with no repair pass and
  /// no exclusion configured. A watch the Monitor can no longer place is absent
  /// rather than reported at a stale path — this is a coverage statement, and a
  /// watch nothing can address covers nothing.
  #[cfg(test)]
  pub(crate) fn covered_paths(&self) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = self
      .watch_scopes
      .iter()
      .filter_map(|(watch, scope)| self.scoped_path(*scope, *watch))
      .collect();
    paths.sort();
    paths
  }

  /// Lowers one raw batch per the scope's backend profile. The FSEvents path
  /// probe-grounds ambiguity; the inotify path is direct. A payload variant
  /// that disagrees with the profile is a seam bug — its events degrade to a
  /// root rescan rather than a wrong lowering.
  fn compile(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<SourceEvent>,
    now: Instant,
  ) -> PendingBatch {
    let mut batch = match state.profile {
      BackendKind::FsEvents => {
        let mut fsevents = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::FsEvents(ev) => fsevents.push(ev),
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_fsevents(state, scope, fsevents);
        if mismatched {
          debug_assert!(false, "a foreign event reached an FSEvents scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
      BackendKind::Inotify => {
        let mut linux = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::Linux(RawLinuxEvent::Inotify { anchors, event }) => {
              linux.push(RawLinuxEvent::Inotify { anchors, event });
            }
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_inotify(state, scope, linux);
        if mismatched {
          debug_assert!(false, "a non-inotify event reached an inotify scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
      BackendKind::Fanotify => {
        let mut fanotify = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::Linux(RawLinuxEvent::Fanotify(admitted)) => fanotify.push(admitted),
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_fanotify(state, scope, fanotify);
        if mismatched {
          debug_assert!(false, "a non-fanotify event reached a fanotify scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
      BackendKind::Rdcw => {
        let mut rdcw = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::Windows(RawWindowsEvent::Rdcw(event)) => rdcw.push(event),
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_rdcw(state, scope, rdcw);
        if mismatched {
          debug_assert!(false, "a non-RDCW event reached an RDCW scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
      BackendKind::UsnJournal => {
        let mut usn = Vec::with_capacity(events.len());
        let mut mismatched = false;
        for ev in events {
          match ev {
            SourceEvent::Windows(RawWindowsEvent::Usn(event)) => usn.push(event),
            _ => mismatched = true,
          }
        }
        let mut batch = self.compile_usn(state, scope, usn);
        if mismatched {
          debug_assert!(false, "a non-USN event reached a USN scope");
          batch.trailing.push(Planned::Over(Scope::Root(scope)));
        }
        batch
      }
    };
    // BEFORE the fence, and before anything is fed: a record naming a vanished
    // object must be addressed against the tree as it stood when the record was
    // produced, and the fence is free to drop records whose truth about the
    // filesystem this pass still wants.
    self.retire_removed_boundaries(state, &batch);
    self.fence_exclusions(state, scope, &mut batch, now);
    batch
  }

  /// Drops every LEDGER entry whose location this read says is gone — the
  /// lifecycle no census can give them, made real.
  ///
  /// # The debt this pays, and the part it CANNOT pay
  ///
  /// No census can remove an exempt ledger entry: a btrfs subvolume is absent
  /// from every one by construction, so condemning it there is a cover storm.
  /// The design's answer —
  /// *"its lifecycle is the ordinary event flow, since deleting a subvolume emits
  /// real delete events on the parent"* — was true about the filesystem and false
  /// about the code until this pass existed: the events arrived and no one
  /// consumed them.
  ///
  /// This pass reads the EVENT STREAM, which is exactly what a loss window
  /// empties. A deletion dropped by an overflow is a deletion this pass never
  /// sees, and before the generations existed that record stood for the scope's
  /// life. Two other mechanisms cover that gap — [`retire_relisted_boundaries`]
  /// on a descending profile and [`retire_unwalked_boundaries`] on a
  /// kernel-recursive one, both driven by the re-observation the loss recovery
  /// already runs — and [`MAX_BOUNDARIES`] bounds the ledger unconditionally when
  /// every one of them has failed. The remaining removal path,
  /// [`settle`](Self::settle)'s signalled-unmount `retain`, serves the FSEvents
  /// `UNMOUNT` word and reaches nothing else.
  ///
  /// # Which entries, and which kinds
  ///
  /// The LEDGER only, and all of it. A census row's removal is the next
  /// authoritative read's job and it does it with a cover; short-circuiting that
  /// here would silence a departure cover the primary detector owes — so this
  /// pass does not touch the census at all. That also makes it provably inert
  /// over the state a refresh alone produces, whose ledger is empty.
  ///
  /// Four kinds say an object left a location: `Removed` and `MovedFrom` for a
  /// named child, `DeleteSelf` and `MoveSelf` for a watched directory itself.
  /// `Ignored` is deliberately NOT among them — it is watch lifecycle, not object
  /// lifecycle, and fires on the driver's OWN prune, where nothing on disk moved
  /// at all.
  ///
  /// A drop is at-or-under the vanished path: a boundary inside a directory that
  /// went away went away with it.
  ///
  /// # No cover is owed
  ///
  /// The record that drives the drop IS the coverage — a delete or a move-out is
  /// delivered to the consumer on its own account. The reasoning deliberately
  /// does NOT lean on "a ledger entry obliges nothing": a genuine vfsmount is
  /// recorded in exactly the same shape on a host that answers no mount ids
  /// ([`Standing::Unknown`]). It leans on what the driving record proves instead
  /// — a mountpoint cannot be unlinked or renamed while a mount is on it, so a
  /// location this pass hears vanish is a location whose boundary was already
  /// detached, and the ground the detach revealed left with the directory. Should
  /// a boundary somehow survive at the location, the enumerate that re-reads the
  /// parent re-declines it and seam 1 records it again.
  ///
  /// It runs over the LEDGER only, and over all of it. The census is the mount
  /// table's, and a row this pass could reach is one whose departure the next
  /// authoritative read will derive and cover — removing it here would replace
  /// that cover with silence.
  fn retire_removed_boundaries(&self, state: &mut ScopeState, batch: &PendingBatch) {
    // Nothing recorded: the pass is a pure no-op, so it never walks a read for it.
    if state.ledger.is_empty() {
      return;
    }
    let mut gone: Vec<PathBuf> = Vec::new();
    for planned in batch
      .items
      .iter()
      .flat_map(|item| item.planned.iter())
      .chain(batch.trailing.iter())
    {
      let Planned::Rec(rec) = planned else {
        continue;
      };
      if !matches!(
        rec.kind(),
        RecordKind::Removed | RecordKind::MovedFrom | RecordKind::DeleteSelf | RecordKind::MoveSelf
      ) {
        continue;
      }
      if let Some(path) = self.anchored_path(state, rec.watch(), rec.target()) {
        gone.push(path);
      }
    }
    if gone.is_empty() {
      return;
    }
    // This pass runs on EVERY compiled batch, so the containment test is the one
    // place a per-event cost can compound: a delete-heavy batch and a scope at
    // the ledger bound make the naive scan `entries x vanished` per batch.
    let gone: BTreeSet<&Path> = gone.iter().map(PathBuf::as_path).collect();
    state
      .ledger
      .retain(|entry| !under_any_prefix(&gone, &entry.location));
  }

  /// Drops every compiled input the caller's exclusions cover — the live half of
  /// the common-layer fence (see [`exclusions`](Self::exclusions)).
  ///
  /// This is where a descending backend's coverage is actually declined: the
  /// Monitor arms a directory it learns about from a `Created`/`MovedTo` record,
  /// so a record the fence removes is a directory the Monitor never learns about,
  /// never arms and never descends. It is also where the two kernel-recursive
  /// Windows backends get their enforcement, off exactly the same rule — one
  /// fence, three backends, and a future descending backend inherits it by
  /// existing.
  ///
  /// Three things are never suppressed, and each is load-bearing:
  ///
  /// - a SELF-EVENT (`Ignored`/`MoveSelf`/`DeleteSelf`). Its watch's own death is
  ///   the one record that says the coverage is over, and a caller who excluded
  ///   the very tree it asked to watch must still be told the watch ended — the
  ///   same carve-out the fanotify fence makes for the root's death;
  /// - a ROOT-scoped or backend-wide overflow. Those cover the reported tree as
  ///   well as the exclusion, so dropping one would be silent loss over ground
  ///   the caller IS watching. The scope-wide cover in located clothing (the root
  ///   watch, no descent) is the same signal and is spared with them;
  /// - anything whose anchor path cannot be resolved ([`anchored_path`] is `None`)
  ///   — the fence fails OPEN, never closed.
  ///
  /// A located rescan strictly INSIDE an exclusion is dropped, and that is not
  /// silent loss: nothing under an exclusion is covered, so there is no coverage
  /// for it to be lost from — while keeping it would hand the caller a rescan
  /// naming the very path it asked never to hear about, which is the failure mode
  /// this whole fence exists to avoid.
  ///
  /// Runs in STREAM ORDER, and each record's classification and its hand-off to
  /// the Monitor are ONE step — the record is judged, then fed, before the NEXT
  /// record is judged. Two passes over the buffer cannot express that, and the
  /// split is not a tidiness question but the hole itself: one read can carry a
  /// directory's rename into an exclusion followed by a record from a descendant
  /// watch that rode across with it. Classify-then-feed judges that suffix against
  /// a Monitor that has not yet performed the re-parent — so the descendant still
  /// resolves outside the exclusion, is kept, and the re-parent then delivers it
  /// under the excluded destination. A record already retained is past recall: the
  /// located repair queued after the pair covers what comes next, it does not
  /// unsay what was kept ahead of it. Feeding first moves the Monitor's tree,
  /// which IS this core's addressing ([`path_of`]), so the suffix resolves where
  /// the rename actually put it and the ordinary fence suppresses it as ordinary
  /// excluded ground.
  ///
  /// `trailing` is fenced after every item for the same reason it is FED after
  /// every item: it is later in the stream, so it must be judged against the
  /// addressing the items left behind.
  ///
  /// # Feeding
  ///
  /// A profile that answers [`feeds_at_classify`] hands each kept record to the
  /// Monitor HERE, as it is judged, rather than leaving the read for
  /// [`settle`](Self::settle) to replay. That closes the phase lag the stream-order
  /// walk above is otherwise blind to: this core derives every watch path from the
  /// Monitor's tree, so a read that judges all of its records before telling the
  /// Monitor about any of them judges the whole read against the world as it stood
  /// before the read began.
  ///
  /// It is also what lets the geometry decision be driven by the Monitor's own
  /// [`RecordOutcome`] rather than by a prediction: the hand-off happens between
  /// this record and the next one to be judged, so the report of what it did to the
  /// tree is available in time. The geometry pass therefore sits wholly on the FAR
  /// side of the hand-off ([`reparent_geometry`](Self::reparent_geometry)) — it
  /// acts on the re-parent that happened, and nothing precedes the feed to predict
  /// one.
  ///
  /// The discipline is chosen by the PROFILE, above both of this function's
  /// early-outs. A scope that configured no exclusions still feeds record by
  /// record, so the suppressing path and the default path are one path — the
  /// alternative is a default configuration whose feeding no exclusion cell ever
  /// covers.
  ///
  /// Order is unchanged either way: items in stream order, then `trailing`, which
  /// under feed-at-classify is simply the part `settle` still has to feed.
  ///
  /// # The geometry pass has no bound of its own, and must not grow one back
  ///
  /// This pass once mirrored each parked rename SOURCE in a per-scope table so a
  /// later destination could look one up. A mirror is retained state, retention
  /// wants a ceiling, and the ceiling was a refusal: at a full table a rename
  /// source was not parked, classification stopped at that record, and its whole
  /// read suffix was dropped behind one scope-wide `Rescan`. Reading the source off
  /// the Monitor's own reparent report retains nothing here, so the ceiling and its
  /// refusal are gone with the table.
  ///
  /// A reader who notices that a burst of unpaired renames is now retained without
  /// any limit visible from here will be tempted to put the ceiling back. It was
  /// never a ceiling on the burst. Every source this pass could park is a source the
  /// Monitor parks too — the same record, one step later in the same walk, keyed by
  /// `(scope, cookie)` against the mirror's `cookie` — so the mirror's population
  /// was a per-scope subset of `Monitor::pending_moves`, retired on the same
  /// deadline. That store is UNCAPPED: `park_pending_move` is its single insert
  /// funnel and inserts unconditionally, and each `PendingMove` carries a
  /// `Location`, an `Evidence` and six further fields against the mirror's one
  /// optional path. So the adversarial stream that filled the mirror already grows
  /// the primary store past any number the mirror would have refused at, and always
  /// did. Capping the shadow moved no memory ceiling; it only bought a dropped read
  /// suffix and a scope-wide re-read per over-cap read.
  ///
  /// A bound on rename retention is therefore a question for `pending_moves`, where
  /// the retention actually is, and it has to be answered there — with the Monitor's
  /// own pairing semantics in hand — rather than re-imposed on a derived table whose
  /// refusal costs coverage and defends nothing.
  ///
  /// [`anchored_path`]: Self::anchored_path
  /// [`path_of`]: Self::path_of
  fn fence_exclusions(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    batch: &mut PendingBatch,
    now: Instant,
  ) {
    // INV-FEED. The feeding discipline is read off the PROFILE, before either
    // early-out, so a scope with no exclusions configured reaches the Monitor by
    // exactly the same route as one with them (see [`feeds_at_classify`]).
    let at_classify = feeds_at_classify(state.profile);
    debug_assert!(
      !runs_rename_geometry(state.profile) || at_classify,
      "INV-FEED: geometry => feed-at-classify — a profile that resolves paths \
       mid-read must not classify its records over the phase lag"
    );
    debug_assert!(
      !at_classify || batch.awaiting == 0,
      "INV-FEED: feed-at-classify => awaiting == 0 — a probe-parked batch's items \
       are placeholders and must not reach the Monitor before their probes answer"
    );
    // The fence itself stands down where the backend decides exclusions at
    // admission, and where the caller configured none.
    let fence = !self.exclusions.is_empty() && !backend_enforces_exclusions(state.profile);
    // The geometry half additionally stands down for a kernel-recursive profile
    // (see [`reparent_geometry`](Self::reparent_geometry)); the fence itself does
    // not.
    let geometry = fence && runs_rename_geometry(state.profile);
    if !fence && !at_classify {
      return;
    }
    for item in &mut batch.items {
      let planned = core::mem::take(&mut item.planned);
      // Nothing is retained under feed-at-classify — each kept record leaves for
      // the Monitor as it is judged — so the buffer that would hold them is not
      // allocated.
      let mut kept = if at_classify {
        Vec::new()
      } else {
        Vec::with_capacity(planned.len())
      };
      for planned in planned {
        if fence && self.fenced(state, &planned) {
          continue;
        }
        // Only a KEPT record carries geometry: a rename half the fence just
        // suppressed has an unreported endpoint, which means no watched subtree
        // to carry across — the destination reconciles a fresh directory and
        // cold-walks it, and that walk is fenced entry by entry.
        //
        // The destination slot a repair would name, taken while the record is
        // still in hand: the feed consumes it, and the verdict that decides
        // whether a repair is owed does not exist until the feed has happened.
        let landing = if geometry {
          Self::landing(&planned)
        } else {
          None
        };
        let outcome = Self::accept(&mut self.monitor, state, &mut kept, planned, now);
        // The repair is by construction anchored at a reported destination, so
        // it needs no fencing of its own. It follows the record it repairs, in
        // this order, on both disciplines.
        if let Some((watch, target)) = landing
          && let Geometry::Repair(repair) =
            self.reparent_geometry(state, scope, watch, target.as_ref(), &outcome)
        {
          Self::accept(&mut self.monitor, state, &mut kept, repair, now);
        }
      }
      item.planned = kept;
    }
    if fence {
      batch
        .trailing
        .retain(|planned| !self.fenced(state, planned));
    }
  }

  /// Takes one record the fence kept: handed to the Monitor AT ONCE under a
  /// feed-at-classify profile, buffered into `kept` for
  /// [`settle`](Self::settle) otherwise.
  ///
  /// The two disciplines differ only in WHEN a record leaves, never in which
  /// records leave or in what order: the fence walks one read in stream order and
  /// `settle` replays the buffer in that same order, so the sequence the Monitor
  /// observes is identical. `trailing` is not accepted here — it is judged and fed
  /// after every item on both disciplines, which under feed-at-classify means it
  /// is simply left for `settle` to feed once the items are already gone.
  ///
  /// Returns what the hand-off did to the watch tree's shape. A BUFFERED record has
  /// not reached the Monitor, so it truthfully reports [`RecordOutcome::Nothing`]:
  /// nothing has been done to the tree yet. That cannot mislead the one caller that
  /// reads the value, because [`runs_rename_geometry`] implies
  /// [`feeds_at_classify`] (INV-FEED's first leg, asserted at compile time) — a
  /// profile whose geometry consumes the outcome never takes the buffering branch
  /// at all.
  fn accept(
    monitor: &mut Monitor,
    state: &ScopeState,
    kept: &mut Vec<Planned>,
    planned: Planned,
    now: Instant,
  ) -> RecordOutcome {
    if !feeds_at_classify(state.profile) {
      kept.push(planned);
      return RecordOutcome::Nothing;
    }
    Self::feed(monitor, planned, now)
  }

  /// Whether an exclusion lies AT OR UNDER `path` — the fence's own containment
  /// predicate run the other way round, with `path` as the exclusion set and each
  /// exclusion as the candidate.
  ///
  /// [`excluded`](Self::excluded) answers "is this path inside an exclusion", which
  /// is what suppression needs. Re-parenting needs the mirror question — "does this
  /// subtree CONTAIN an exclusion" — because that is what decides whether rewriting
  /// the subtree's path changes which of its descendants are reported.
  ///
  /// Deliberately expressed through [`crate::driver::excluded`] rather than a fresh
  /// prefix walk: that is the ONE matching rule the cold fence, the live fence, the
  /// sync-cookie birth refusal and the fanotify backend all share, and a second rule
  /// here could drift out of step with it and re-open the hole from the other side.
  fn exclusion_under(&self, path: &Path) -> bool {
    let containing = [path.to_path_buf()];
    self
      .exclusions
      .iter()
      .any(|exclusion| crate::driver::excluded(&containing, exclusion))
  }

  /// The destination slot a rename's repair would be lowered against, taken from a
  /// record BEFORE it is fed.
  ///
  /// The two inputs of the post-feed decision sit on opposite sides of the hand-off:
  /// the feed consumes the record, and the outcome that decides whether a repair is
  /// owed at all does not exist until the feed has happened. So the record's own
  /// half is captured here, and joined with the Monitor's report afterwards.
  ///
  /// Gated on the KIND alone. Only a `MovedTo` can report a reparent, and gating any
  /// tighter — on a directory flag the destination half is free to omit — would let
  /// a real reparent go unrepaired because its record under-described itself.
  fn landing(planned: &Planned) -> Option<(WatchId, Option<Location>)> {
    match planned {
      Planned::Rec(rec) if matches!(rec.kind(), RecordKind::MovedTo) => {
        Some((rec.watch(), rec.target().cloned()))
      }
      _ => None,
    }
  }

  /// Re-enumerates a moved directory subtree whose RENAME changed the exclusion
  /// geometry over it — the one thing the record-by-record fence structurally
  /// cannot see.
  ///
  /// [`fenced`](Self::fenced) judges each record by its own anchored endpoint, so a
  /// rename whose two endpoints are BOTH reported is preserved whole, as it must be.
  /// But the Monitor answers such a rename by re-parenting the already-known watch
  /// subtree in place — an O(1) carry-over that rewrites the subtree's path while
  /// carrying every descendant across untouched. Exclusions match on path prefixes,
  /// so which descendants are reported is a function of that very path, and a move
  /// whose endpoints sit on different sides of an exclusion leaves the coverage
  /// describing a tree the fence no longer agrees with — in BOTH directions, and
  /// permanently, because nothing else ever re-walks it:
  ///
  /// - **out of an exclusion.** With root `/r` and `/r/a/cache` excluded, the cold
  ///   walk of `/r/a` skipped `cache` and armed nothing there. Renaming `/r/a` to
  ///   `/r/b` makes `cache` reportable, yet the bare re-parent adds nothing: no watch
  ///   exists at `/r/b/cache`, no record can be attributed to it, and a newly visible
  ///   subtree is blind forever. This is silent, permanent loss.
  /// - **into an exclusion.** With `/r/a/cache` excluded, `/r/b/cache` IS covered.
  ///   Renaming `/r/b` to `/r/a` leaves those watches installed, so the scope keeps
  ///   spending kernel watches — and delivering — on ground the caller excluded to
  ///   shed exactly that cost.
  ///
  /// The rule is [`exclusion_under`](Self::exclusion_under) at EITHER endpoint, which
  /// is how the fanotify admission map and the USN journal decide the same question:
  /// one predicate, asked of both ends, never a second matching rule. Deliberately
  /// CONSERVATIVE in the same way — an exclusion sitting under both endpoints at the
  /// same relative offset leaves the geometry genuinely unchanged yet answers `true`,
  /// costing one re-enumeration on a path this rare.
  ///
  /// Where it DIFFERS is the repair, because inotify's coverage is not a private
  /// admission map it can forget and relearn locally: it is the Monitor's node tree
  /// plus real kernel watches. So the repair is stated as the Monitor's own located
  /// loss signal at the destination, queued immediately AFTER the pairing record so
  /// the re-parent has already landed. The Monitor answers that signal by emitting a
  /// covering `Rescan` there and re-arming from the destination's parent — a complete
  /// re-arm read prunes vanished names, arms new ones and cascades into survivors, so
  /// it descends into the just-reparented directory and reconciles it against a fresh
  /// listing. That listing is produced by [`on_enumerated`](Self::on_enumerated),
  /// which applies the SAME exclusion rule: a newly reportable child is listed and
  /// armed, a newly excluded one is absent and pruned. Both directions, one existing
  /// mechanism, no parallel bookkeeping.
  ///
  /// Runs only where the common fence runs AND coverage is per-directory. A backend
  /// that enforces exclusions itself already handles its own geometry, and a
  /// kernel-recursive one has no per-directory watches to re-arm — its single stream
  /// covers the destination the moment the re-parent lands — so escalating there
  /// would be a bare `Rescan` repairing nothing.
  ///
  /// Loss is never silent: when the escalation cannot be placed (the destination
  /// anchor resolves no path) it degrades to the scope-wide cover, whose recovery
  /// re-arms everything. That cover replaces a REPAIR, never an ordering — it
  /// re-reads what comes next and cannot unsay a record the same read already
  /// retained under the pre-move addressing.
  ///
  /// Called per RECORD from the fence's own stream-ordered walk rather than as a
  /// second pass, and the ORDER of the repair is the reason: it must be queued
  /// directly behind the record that provoked it, so the Monitor answers it with
  /// the re-parent already landed and the located `Rescan` names the destination.
  ///
  /// # What this pass is NOT
  ///
  /// It does not re-address anything. Watch paths are DERIVED from the Monitor's
  /// own tree ([`path_of`](Self::path_of)), so the O(1) re-parent that carried the
  /// subtree across has already moved every path under it — for every scope,
  /// whether or not exclusions are configured, and with no walk. This pass owes
  /// only the question derivation cannot answer: a moved subtree's watches are
  /// correctly NAMED at their new home, but which directories under that home
  /// should be watched AT ALL is a function of the exclusion set, and that
  /// membership did not move with them. A subtree carried out of an exclusion has
  /// correct names for the watches it holds and no watches at all for the children
  /// the cold walk skipped; a subtree carried into one keeps watches on ground the
  /// caller excluded. Only a re-enumeration settles membership, and only a scope
  /// with exclusions can have any membership to settle — which is why the pass is
  /// gated on the fence, while addressing is not gated on anything.
  ///
  /// # It acts on the reparent that HAPPENED
  ///
  /// The trigger is the Monitor's own [`RecordOutcome`] for the record just fed,
  /// not a source this pass parked and predicted a pairing for. A prediction and a
  /// performance are two implementations of one rule, and two implementations skew:
  /// the Monitor pairs only inside the window, only over a held subtree, and only
  /// when the O(1) reparent it then attempts actually succeeds. Every case that
  /// fails one of those tests reports [`RecordOutcome::Nothing`] and is answered
  /// here by repairing nothing — which is correct by construction, because a
  /// subtree nothing relocated has crossed no exclusion boundary.
  ///
  /// # Composing the source
  ///
  /// [`RecordOutcome::Reparented`] reports a `(from_parent, from)` SLOT rather than
  /// an absolute path, and `from` is the SCOPE-relative location the Monitor
  /// reconstructed from its live tree at report time — `from_parent`'s own location
  /// already joined with the half's name. So the absolute source is the scope
  /// ROOT's path joined with it, and `from_parent` names the anchor the
  /// reconstruction ran against rather than a second anchor to join onto (joining
  /// against `from_parent`'s own path would count that parent's location twice).
  ///
  /// The root is also the one anchor a post-feed composition cannot get wrong: a
  /// watched root never moves inside its own tree, so it is the fixed point every
  /// other path is derived from. The source is then the Monitor's live description
  /// of where the subtree was, plus that fixed point — which is exactly what an
  /// absolute path pinned at `MovedFrom` could not be, since an ancestor renamed
  /// mid-window moves the ground under it and leaves the pin naming nothing.
  ///
  /// Composed AFTER the record has been fed, which is safe for the same reason: the
  /// reparent this outcome reports rewrote a child edge inside the tree, and the
  /// root path it is joined onto is not something any reparent can touch.
  fn reparent_geometry(
    &self,
    state: &ScopeState,
    scope: ScopeId,
    watch: WatchId,
    target: Option<&Location>,
    outcome: &RecordOutcome,
  ) -> Geometry {
    let Some((_, from)) = outcome.reparented() else {
      return Geometry::Nothing;
    };
    let from = self.anchored_path(state, state.watch, Some(from));
    let to = self.anchored_path(state, watch, target);
    // One predicate, asked of both ends. An endpoint that resolved no
    // path answers "changed" for the same reason the fanotify map does
    // for a moved node whose ancestry no longer reaches the root: with
    // no path to compare, the safe direction is the one that costs a
    // re-enumeration, not the one that costs coverage.
    let changed = |end: Option<&Path>| end.is_none_or(|path| self.exclusion_under(path));
    if !changed(from.as_deref()) && !changed(to.as_deref()) {
      return Geometry::Nothing;
    }
    // The located repair needs a destination to name. Without one the
    // scope-wide cover is the honest degrade — never a quiet drop, and
    // never a `Rescan` naming a path that could not be resolved.
    Geometry::Repair(match (to, target) {
      (Some(_), Some(target)) => Planned::Over(located(watch, Some(target.clone()))),
      _ => Planned::Over(Scope::Root(scope)),
    })
  }

  /// Whether one planned Monitor input addresses only excluded ground.
  fn fenced(&self, state: &ScopeState, planned: &Planned) -> bool {
    match planned {
      Planned::Rec(rec) => {
        !rec.kind().is_self_event()
          && self
            .anchored_path(state, rec.watch(), rec.target())
            .is_some_and(|path| self.excluded(&path))
      }
      Planned::Over(Scope::Subtree(sub)) => {
        let scope_wide = sub.watch() == state.watch && sub.descent().is_empty();
        !scope_wide
          && self
            .anchored_path(state, sub.watch(), Some(sub.descent()))
            .is_some_and(|path| self.excluded(&path))
      }
      Planned::Over(_) => false,
    }
  }

  fn settle_if_ready(
    monitor: &mut Monitor,
    state: &mut ScopeState,
    scope: ScopeId,
    batch: PendingBatch,
    now: Instant,
  ) -> bool {
    if batch.awaiting == 0 {
      Self::settle(monitor, state, scope, batch, now);
      true
    } else {
      state.park.active = Some(batch);
      false
    }
  }

  /// Settles a fully-resolved batch: grants evidenced vanished-half cookies,
  /// feeds the Monitor in item order, then applies the deferred unmount
  /// trust-removals (the monotone rule's late edge).
  ///
  /// A feed-at-classify profile ([`feeds_at_classify`]) arrives here with its
  /// items already emptied by the fence, so what it settles is `trailing` alone —
  /// which is where `trailing` belongs on both disciplines, after every item. The
  /// other two duties are the reason the split is safe to make per profile: a
  /// cookie grant needs a `cookie_candidate` and `evidenced` partners, and a
  /// deferred unmount needs `deferred_unmounts`, and all three are filled only by
  /// the FSEvents path — which does not feed at classify time.
  fn settle(
    monitor: &mut Monitor,
    state: &mut ScopeState,
    scope: ScopeId,
    mut batch: PendingBatch,
    now: Instant,
  ) {
    Self::grant_evidenced_cookies(state, scope, &mut batch);
    let deferred = std::mem::take(&mut batch.deferred_unmounts);
    for item in batch.items {
      for planned in item.planned {
        Self::feed(monitor, planned, now);
      }
    }
    for planned in batch.trailing {
      Self::feed(monitor, planned, now);
    }
    for path in deferred {
      // BOTH halves. The word is evidence the mount is gone, which is the one
      // thing that may retire a learned prefix — and leaving the matching table
      // row standing until the next snapshot would keep vetoing on a mount the
      // source has already announced departed.
      state.learned_mounts.retain(|m| m != &path);
      state.mount_table.retain(|m| m != &path);
      // The census and the ledger follow the SIGNALLED removal too. Every path
      // deferred here came from an unmount word whose `plan_mount` already
      // planned the located cover for it, so leaving it recorded would make the
      // next authoritative read derive a departure that was covered in band —
      // one duplicate cover per signalled unmount. Dropping it can only ever
      // shrink the diff, and only for departures a backend announced.
      state.census.retain(|row| row.location != path);
      state.ledger.retain(|entry| entry.location != path);
    }
  }

  /// Grants a vanished rename half its pairing cookie at settlement, under
  /// ALL the proofs the fabrication class demands: a same-batch partner's
  /// probe bound the fileID to the root device AND that partner's event word
  /// carried the same fileID (the temporal bind — see
  /// [`PendingBatch::evidenced`]), and the vanished path lies under no
  /// foreign prefix of the still-monotone, still-authoritative table (a
  /// collision from a just-mounted or just-unmounted volume fails here).
  /// Cross-batch vanished sources never cookie — the Monitor degrades them
  /// to a removal, the documented pairing cost.
  ///
  /// The residual is inode reuse INSIDE one batch: FSEvents supplies no
  /// rename token, so an object deleted and an unrelated object recycling
  /// its inode within the same batch can satisfy every proof above and
  /// mis-pair. That cannot be distinguished from a real rename event-side,
  /// so every granted pair also queues one covering located rescan at the
  /// pair's deepest common ancestor — a mis-pair is then recoverable, never
  /// silent.
  fn grant_evidenced_cookies(state: &ScopeState, scope: ScopeId, batch: &mut PendingBatch) {
    let evidenced = std::mem::take(&mut batch.evidenced);
    let mut covers: Vec<Planned> = Vec::new();
    for item in &mut batch.items {
      let Some((fid, path)) = item.cookie_candidate.take() else {
        continue;
      };
      let Some(partners) = evidenced.get(&fid) else {
        continue;
      };
      // The unambiguous-partner rule: a grant demands EXACTLY ONE evidenced
      // partner. With two or more, the Monitor would pair the granted cookie
      // with whichever destination feeds first while a one-partner cover
      // could point at another — the recovery the cover exists to guarantee
      // would miss the real destination. Ambiguity is a degrade, not an
      // error: no cookie (the vanished half resolves as its removal, the
      // present halves as creations) under one cover spanning the source and
      // every evidenced partner.
      if partners.len() != 1 {
        covers.push(Self::covering_rescan(
          state,
          scope,
          core::iter::once(&path).chain(partners.iter()),
        ));
        continue;
      }
      if !device_trusted(state, &path, None) {
        continue;
      }
      let partner = &partners[0];
      let mut granted = false;
      for planned in &mut item.planned {
        if let Planned::Rec(rec) = planned
          && rec.kind().is_moved_from()
          && rec.cookie().is_none()
        {
          *rec = rec.clone().with_cookie(MoveCookie::new(fid));
          granted = true;
        }
      }
      if granted {
        covers.push(Self::covering_rescan(
          state,
          scope,
          [&path, partner].into_iter(),
        ));
      }
    }
    batch.trailing.extend(covers);
  }

  /// Hands one planned input to the Monitor and reports what it did to the watch
  /// tree's SHAPE.
  ///
  /// The [`RecordOutcome`] is the Monitor's own account of the reparent it just
  /// performed — never a prediction re-derived from the same record by a second
  /// implementation of the same rule. That is what the geometry pass decides on
  /// ([`reparent_geometry`](Self::reparent_geometry)).
  ///
  /// An overflow instruction moves no subtree, so it reports nothing.
  fn feed(monitor: &mut Monitor, planned: Planned, now: Instant) -> RecordOutcome {
    match planned {
      Planned::Rec(rec) => monitor.on_os_record(rec, now),
      Planned::Over(scope) => {
        monitor.on_overflow(scope, now);
        RecordOutcome::Nothing
      }
    }
  }

  /// Compiles and feeds queued batches until one parks or the queue drains.
  fn pump_queued(&mut self, scope: ScopeId, now: Instant) {
    loop {
      let Some(mut state) = self.scopes.remove(&scope) else {
        return;
      };
      let Some(BatchPayload { events, permit, .. }) = state.park.queued.pop_front() else {
        self.scopes.insert(scope, state);
        return;
      };
      let mut batch = self.compile(&mut state, scope, events, now);
      batch.permit = Some(permit);
      let fed = Self::settle_if_ready(&mut self.monitor, &mut state, scope, batch, now);
      self.scopes.insert(scope, state);
      if !fed {
        return;
      }
    }
  }

  /// One rescan covering an ambiguous same-fileID rename group: the deepest
  /// common ancestor of the members' parents, clamped to the whole root when
  /// any member falls outside it.
  fn covering_rescan<P: AsRef<Path>>(
    state: &ScopeState,
    scope: ScopeId,
    paths: impl Iterator<Item = P>,
  ) -> Planned {
    let mut prefix: Option<Vec<Segment>> = None;
    for path in paths {
      let parent = match lower(state, path.as_ref()) {
        Lowered::Target(location) => {
          let mut segments = location.segments().to_vec();
          segments.pop();
          segments
        }
        Lowered::Root => Vec::new(),
        Lowered::Outside => return Planned::Over(Scope::Root(scope)),
      };
      prefix = Some(match prefix {
        None => parent,
        Some(acc) => acc
          .iter()
          .zip(parent.iter())
          .take_while(|(a, b)| a == b)
          .map(|(a, _)| a.clone())
          .collect(),
      });
    }
    let descent = prefix.unwrap_or_default();
    let target = if descent.is_empty() {
      None
    } else {
      Some(Location::from_segments(descent))
    };
    Planned::Over(located(state.watch, target))
  }

  /// Resolves one probe's plan.
  fn resolve(state: &mut ScopeState, purpose: ProbePurpose, outcome: ProbeOutcome) -> Resolved {
    match purpose {
      // A slot stat grounds no batch item; `on_probe_result` answers it before
      // this table is ever reached.
      ProbePurpose::SlotKind { .. } => {
        debug_assert!(false, "a slot stat is answered ahead of the batch table");
        Resolved::plain(usize::MAX, Vec::new())
      }
      ProbePurpose::RootAlive { item } => {
        let kind = match outcome {
          ProbeOutcome::Missing => RecordKind::DeleteSelf,
          // Present elsewhere or unknowable both end the scope's coverage:
          // the registered path no longer names the watched object.
          ProbeOutcome::Present { .. } | ProbeOutcome::Failed => RecordKind::MoveSelf,
        };
        Resolved::plain(item, vec![Planned::Rec(OsRecord::new(state.watch, kind))])
      }
      ProbePurpose::Ambiguous {
        item,
        flags,
        target,
        path,
      } => {
        // The word's content and metadata bits are facts existence cannot judge:
        // an lstat says what is THERE, never whether the bytes or the mode moved
        // while it was. They therefore ride through both arms below, and only the
        // STRUCTURAL half is grounded — which is exactly what the probe is for.
        let content = Evidence::new()
          .maybe_modified(flags.item_modified())
          .maybe_attrib(
            flags.item_inode_meta_mod()
              || flags.item_change_owner()
              || flags.item_xattr_mod()
              || flags.item_finder_info_mod(),
          );
        let planned = match outcome {
          ProbeOutcome::Missing => {
            let proven = content.with_removed();
            match record_proved(state, proven, target.clone(), dir_hint(flags), None) {
              Some(rec) => vec![Planned::Rec(rec)],
              None => vec![Planned::Over(located(state.watch, target))],
            }
          }
          ProbeOutcome::Present {
            kind, file_id, dev, ..
          } => {
            learn_device(state, &path, dev);
            let proven = content.maybe_created(flags.item_created());
            let node = mint(state, &path, file_id, Some(dev));
            match record_proved(state, proven, target.clone(), Some(kind.is_dir()), node) {
              Some(rec) => vec![Planned::Rec(rec)],
              // The word's ONLY grounded verb was a removal existence just
              // disproved: nothing is left to name, so the located rescan grounds
              // whatever occupies the path now.
              None => vec![Planned::Over(located(state.watch, target))],
            }
          }
          ProbeOutcome::Failed => vec![Planned::Over(located(state.watch, target))],
        };
        Resolved::plain(item, planned)
      }
      ProbePurpose::Rename {
        item,
        file_id,
        target,
        path,
        allow_cookie,
        content,
      } => {
        match outcome {
          // Gone: the source half of a move out of (or within) the tree. A
          // vanished path has NO contemporaneous device evidence — the mount
          // table cannot prove which device it WAS on — so no cookie is
          // minted here. Settlement grants one iff a same-batch partner's
          // probe binds this fileID to the root device; otherwise the
          // Monitor degrades the half to an immediate removal (cross-batch
          // vanished sources never pair — the documented cost).
          ProbeOutcome::Missing => {
            let candidate = allow_cookie
              .then_some(file_id)
              .flatten()
              .map(|fid| (fid, path.clone()));
            let rec = record_with(state, RecordKind::MovedFrom, target, None, None);
            Resolved {
              item,
              planned: vec![Planned::Rec(rec)],
              evidences: None,
              candidate,
            }
          }
          // Exists: the destination half. An appeared DIRECTORY delivers no
          // events for the children it arrived with, so the record is paired
          // with a located rescan — unless the Monitor pairs it with a held
          // source, where the extra rescan is merely redundant, never wrong.
          ProbeOutcome::Present {
            kind,
            file_id: probed,
            dev,
            ..
          } => {
            learn_device(state, &path, dev);
            // Identity binding: the cookie and its published evidence derive
            // from the PROBED inode exclusively — the probe is what carries
            // the device proof. An event id that disagrees with the probe
            // means the path was replaced between the callback and the
            // lstat: the batch's view of this path is stale, so no cookie
            // may bridge the two objects, and the located rescan below
            // re-grounds whatever occupies the path now.
            let stale = matches!((file_id, probed), (Some(event), Some(live)) if event != live);
            let cookie = (allow_cookie && !stale)
              .then(|| cookie_for(state, probed, dev))
              .flatten();
            let node = mint(state, &path, probed, Some(dev));
            let mut rec = record_with(
              state,
              RecordKind::MovedTo,
              target.clone(),
              Some(kind.is_dir()),
              node,
            );
            if let Some(cookie) = cookie {
              rec = rec.with_cookie(cookie);
            }
            let mut planned = vec![Planned::Rec(rec)];
            // The word coalesced content/metadata changes with the rename: a
            // change existence cannot judge, so it rides the probe and is owed
            // alongside the move. ONE record carries the WHOLE set, so a
            // metadata-only subscription admits a chmod-with-rename that a
            // `Modified` verb alone would have hidden from it. The set holds
            // those two facts and no others: existence subsumes any coalesced
            // create/remove bits at this probed site, and the `moved` fact
            // already rides the `MovedTo` above.
            //
            // `None` is the empty set — most pure renames — and pushes
            // NOTHING, exactly as the bool guard this replaced did. It must
            // NOT fall back to the sibling arms' covering rescan, which would
            // staple one onto every rename.
            if let Some(rec) =
              record_proved(state, content, target.clone(), Some(kind.is_dir()), node)
            {
              planned.push(Planned::Rec(rec));
            }
            if kind.is_dir() || stale {
              planned.push(Planned::Over(located(state.watch, target)));
            }
            Resolved {
              item,
              planned,
              // Evidence needs the TEMPORAL BIND on top of the cookie's own
              // rules: the event word must have carried the same fileID the
              // probe observed. A probe-only fileID proves what occupies the
              // path now — not which object the batch's events were about —
              // so it may cookie this present half but never vouch for a
              // vanished partner (that pair degrades to Removed + Created).
              evidences: (cookie.is_some() && file_id == probed)
                .then(|| probed.map(|fid| (fid, path.clone())))
                .flatten(),
              candidate: None,
            }
          }
          ProbeOutcome::Failed => {
            Resolved::plain(item, vec![Planned::Over(located(state.watch, target))])
          }
        }
      }
    }
  }

  /// Drops every queued [`Effect::Emit`] belonging to `scope`. Called exactly
  /// when the scope's queued deliveries become dominated (lag entry): the
  /// non-emit effects (spawns, teardowns, probes) are obligations, never
  /// dominated, and always survive.
  fn purge_scope_emits(effects: &mut VecDeque<Effect>, scope: ScopeId) {
    effects.retain(|effect| !matches!(effect, Effect::Emit { scope: s, .. } if *s == scope));
  }

  /// Removes and returns the LAST queued `Rescan` emit for `scope` (with the
  /// root it was queued to deliver under), if any — the terminal covering
  /// change a teardown keeps retryable.
  fn extract_last_rescan(
    effects: &mut VecDeque<Effect>,
    scope: ScopeId,
  ) -> Option<(Arc<PathBuf>, Change)> {
    let idx = effects.iter().rposition(|effect| {
      matches!(effect, Effect::Emit { scope: s, change, .. } if *s == scope && change.kind().is_rescan())
    })?;
    match effects.remove(idx) {
      Some(Effect::Emit { root, change, .. }) => Some((root, change)),
      _ => None,
    }
  }

  /// The covering merge of two same-scope `Rescan`s (INV-PARK): the location
  /// becomes their longest common prefix — the join of the two subtree
  /// coverages, since a shorter location covers MORE — and the id + epoch
  /// become the newer change's, so the merged instruction still licenses
  /// every drop either input licensed while its epoch dominates everything
  /// dropped. Never narrows either input. Callers pass the later-minted
  /// change as `newer`: route order is mint order, and every routed `Rescan`
  /// carries a freshly bumped epoch, so `newer`'s epoch is the greater one.
  fn covering_merge(prev: &Change, newer: Change) -> Change {
    debug_assert!(
      prev.kind().is_rescan() && newer.kind().is_rescan(),
      "only Rescans carry a drop license to merge"
    );
    let shared = prev
      .location()
      .segments()
      .iter()
      .zip(newer.location().segments())
      .take_while(|(a, b)| a == b)
      .count();
    if shared == newer.location().len() {
      // Newer's location is a prefix of prev's (or equal): it already covers
      // everything prev promised.
      return newer;
    }
    let location = Location::from_segments(newer.location().segments()[..shared].iter().cloned());
    Change::new(
      newer.id(),
      newer.scope(),
      location,
      ChangeKind::Rescan,
      newer.epoch(),
    )
  }

  fn mint_probe(&mut self, scope: ScopeId, purpose: ProbePurpose) -> ProbeId {
    self.probe_seq += 1;
    let probe = ProbeId(self.probe_seq);
    self.probes.insert(probe, ProbeCtx { scope, purpose });
    probe
  }

  /// Clamps an overflow path to the scope: strictly-under-root rescans the
  /// located subtree; the root, an ancestor ("/" on drops), or anything
  /// unrepresentable rescans the whole root.
  fn clamp(state: &ScopeState, scope: ScopeId, path: &Path) -> Scope {
    match lower(state, path) {
      Lowered::Target(location) => {
        Scope::Subtree(SubtreeScope::new(state.watch).with_descent(location))
      }
      Lowered::Root | Lowered::Outside => Scope::Root(scope),
    }
  }

  /// Re-roots every cover-location hint at-or-under `from` onto `to` — the census
  /// rows and the ledger entries together.
  ///
  /// Both ends are absolute paths built the way every other hint is: the scope
  /// root joined with the change's own root-relative [`Location`]. A move whose
  /// source or destination is the ROOT itself is not this pass's business — the
  /// root's own identity is the death gate's — and is skipped rather than
  /// re-rooting everything the scope holds onto one of its own descendants.
  ///
  /// An id-keyed census row's KEY is absolute and does not move; a
  /// [`Key::Location`] one IS the location and moves with it, or the next read on
  /// an id-less host would diff the same mount against itself under two names and
  /// derive a departure plus an arrival where nothing was mounted or unmounted.
  ///
  /// Three sets carry hints and all three move: the census, the ledger, and the
  /// admissions parked on a round trip.
  fn rebase_hints(state: &mut ScopeState, from: &Location, to: &Location) {
    if from.is_empty() || to.is_empty() {
      return;
    }
    let Some(root) = state.root.as_deref() else {
      return;
    };
    let absolute = |location: &Location| {
      let mut path = root.to_path_buf();
      for segment in location.segments() {
        path.push(segment.as_str());
      }
      path
    };
    let (from, to) = (absolute(from), absolute(to));
    if from == to {
      return;
    }
    for row in &mut state.census {
      if rebase_moved(&mut row.location, &from, &to)
        && let Key::Location(key) = &mut row.key
      {
        *key = row.location.clone();
      }
    }
    for entry in &mut state.ledger {
      rebase_moved(&mut entry.location, &from, &to);
    }
    // A PARKED location is a cover hint like any other: it is where the released
    // cover lands, and a rename that moves the ground while the round trip is out
    // would otherwise land it on a directory that no longer exists. Nothing else
    // reads it — the reply is matched by TICKET — so moving it is the whole
    // repair.
    for parked in &mut state.pending_admits {
      rebase_moved(&mut parked.location, &from, &to);
    }
  }

  /// Drains the Monitor to a fixpoint: actions become effects, changes route
  /// through the per-scope lag protocol. Events drain first — a root-death
  /// `Rescan` must route while its scope's lag state still exists.
  fn drain_monitor(&mut self) {
    while let Some(change) = self.monitor.poll_event() {
      self.route_event(change);
    }
    while let Some(action) = self.monitor.poll_action() {
      match action {
        tributary_proto::Action::Watch(cmd) => {
          if let Some(scope) = cmd.target().root() {
            // The bootstrap arm is answered out of band — by the spawn itself on a
            // kernel-recursive backend, by the root's own `AddWatch` on a descending
            // one — so its attempt is captured HERE, where the action is consumed,
            // and echoed at whichever of those answers it.
            let root = match self.scopes.get_mut(&scope) {
              Some(state) => {
                state.root_attempt = Some(cmd.attempt());
                state.requested.clone()
              }
              None => PathBuf::new(),
            };
            self.effects.push_back(Effect::SpawnStream { scope, root });
          } else if let Some(scope) = cmd.target().rearm_root() {
            // A root binding re-proof: re-add the EXISTING root's kernel watch
            // on the LIVE source — the self-parented root-arm shape the spawn
            // path uses, never a stream (re)spawn. `expected` is the barrier
            // identity, so a different-object rebind at the same path fails
            // the arm's open-verify as `Gone` into the root-invalidation
            // funnel — the death the identity-sampling liveness gate cannot
            // see.
            let Some(state) = self.scopes.get(&scope) else {
              debug_assert!(false, "a root re-add names a live scope");
              continue;
            };
            debug_assert_eq!(
              state.watch,
              cmd.id(),
              "a root re-add names the current root"
            );
            let Some(root) = state.root.clone() else {
              debug_assert!(false, "a root re-add follows a committed spawn");
              continue;
            };
            let name = root
              .file_name()
              .and_then(|name| name.to_str())
              .unwrap_or("/");
            let expected = state.identity.and_then(|identity| {
              u64::try_from(identity.ino())
                .ok()
                .and_then(NonZeroU64::new)
                .map(|ino| ExpectedObject {
                  dev: identity.dev(),
                  ino,
                })
            });
            self.effects.push_back(Effect::AddWatch {
              scope,
              watch: cmd.id(),
              attempt: cmd.attempt(),
              parent: cmd.id(),
              name: Segment::new(name),
              path: root,
              expected,
              frame: state.frame(),
            });
          } else if let Some(child) = cmd.target().as_child() {
            let parent = child.parent();
            let Some(&scope) = self.watch_scopes.get(&parent) else {
              debug_assert!(false, "a child watch descends from a known parent");
              continue;
            };
            // Addressed off the parent's CURRENT placement, so a child armed
            // under a subtree an earlier record in this same read relocated
            // opens at the path the delivery beside it names.
            let Some(parent_path) = self.scoped_path(scope, parent) else {
              debug_assert!(false, "a child watch descends from a placeable parent");
              continue;
            };
            let name = child.name().clone();
            let path = Arc::new(parent_path.join(name.as_str()));
            self.watch_scopes.insert(cmd.id(), scope);
            // The object the enumerate discovered, so the arm can confirm the
            // open lands on it: the Monitor node carries the entry's identity
            // (its inode), and single-device descent means a descended child is
            // always on the scope's root device — a foreign-device entry mints no
            // identity and is never descended. An identity-less node leaves the
            // arm unverified, exactly as the Monitor already reconciles.
            let expected = self.monitor.node_identity(cmd.id()).and_then(|id| {
              self
                .scopes
                .get(&scope)
                .and_then(|state| state.root_dev)
                .map(|dev| ExpectedObject { dev, ino: id.get() })
            });
            // THE arm this design exists to refuse. A child learned from a
            // `Created` record was never enumerated, so `crosses_mount_boundary`
            // never judged it and `expected` above is `None` (inotify's
            // `Created` carries no identity) — leaving the executor's own object
            // guard vacuous. The frame is what the executor judges it on.
            let frame = self
              .scopes
              .get(&scope)
              .map(ScopeState::frame)
              .unwrap_or_default();
            self.effects.push_back(Effect::AddWatch {
              scope,
              watch: cmd.id(),
              attempt: cmd.attempt(),
              parent,
              name,
              path,
              expected,
              frame,
            });
          }
        }
        tributary_proto::Action::Unwatch(watch) => {
          let is_root = self
            .watch_scopes
            .get(&watch)
            .and_then(|scope| self.scopes.get(scope))
            .is_some_and(|state| state.watch == watch);
          if !is_root {
            // A per-directory child watch the Monitor dropped: disarm it and
            // forget which scope owned it. Fire-and-forget — the unwatch carries
            // no result contract, and an unreached wd dies with the stream.
            let scope = self.watch_scopes.remove(&watch);
            if let Some(scope) = scope {
              self.effects.push_back(Effect::RemoveWatch { scope, watch });
            }
            continue;
          }
          if let Some(scope) = self.watch_scopes.remove(&watch) {
            // The scope's terminal `Rescan` — parked by lag, or still queued
            // as a plain effect — is the only signal covering whatever the
            // dead scope dropped, and it must survive refusals: a queued
            // emit is one-shot (a refusal finds no scope state to re-park
            // it), so the newest terminal `Rescan` moves into the dying set
            // and retries until the consumer accepts it. Ordinary queued
            // emits stay best-effort — each is dominated by that `Rescan`.
            //
            // A NEVER-LIVE scope promotes nothing: its caller got Err, not a
            // handle, so there is no consumer view to cover (the route_event
            // fence already kept its changes out of the effect queue). The fact
            // is `publicly_live` — a descending scope whose root arm failed
            // populated `root` at spawn yet is not publicly live, so it must not
            // promote a terminal `Rescan` for a registration no one owns.
            let removed = self.scopes.remove(&scope);
            let live = removed.as_ref().is_some_and(|state| state.publicly_live);
            let parked = removed.and_then(|state| {
              let root = state.delivery_root();
              match state.lag {
                LagState::Lagged { parked, .. } => parked.map(|change| (root, change)),
                LagState::Normal => None,
              }
            });
            let queued = Self::extract_last_rescan(&mut self.effects, scope);
            debug_assert!(
              live || (parked.is_none() && queued.is_none()),
              "a never-live scope emits nothing to promote"
            );
            // Both present is structurally dead today — a Lagged scope
            // queues no emits and a Normal one parks nothing — but if both
            // ever exist the terminal promise must not narrow to whichever
            // carries the newer epoch: the coverages merge (INV-PARK) and
            // the promotion rides the newer mint's root.
            let terminal = match (parked, queued) {
              (Some(a), Some(b)) => {
                let ((_, older), (root, newer)) = if b.1.epoch() > a.1.epoch() {
                  (a, b)
                } else {
                  (b, a)
                };
                Some((root, Self::covering_merge(&older, newer)))
              }
              (a, b) => a.or(b),
            };
            if live && let Some((root, change)) = terminal {
              self.dying.insert(
                scope,
                DyingDelivery {
                  change,
                  attempt: Attempt::Idle,
                  root,
                },
              );
            }
            // Scope teardown mid-fence (unwatch, root death — every teardown funnels
            // through this arm): the reconcile's work dies with the scope, so every
            // pending fence resolves `Dead` — the terminal `Rescan` above covers the
            // caller — folded into the next settlement poll so the driver keeps its
            // one choke point. The entry is removed with the scope: no fence state
            // outlives it.
            //
            // `Dead` rather than `Degraded` because this is the one place the death
            // is known synchronously, while the `TeardownStream` that clears the
            // driver's liveness maps is merely QUEUED. A consumer polling this
            // settlement therefore cannot re-derive the fact from those maps — they
            // still read live — so it has to travel in the verdict.
            if let Some(entry) = self.cover_fences.remove(&scope) {
              for pending in entry.pending {
                self.settled_covers.push((pending.fence, CoverSettle::Dead));
              }
            }
            self.probes.retain(|_, ctx| ctx.scope != scope);
            let dead: Vec<WatchId> = self
              .watch_scopes
              .iter()
              .filter(|(_, s)| **s == scope)
              .map(|(w, _)| *w)
              .collect();
            for watch in dead {
              self.watch_scopes.remove(&watch);
            }
            self.enum_reqs.retain(|_, (s, _)| *s != scope);
            self.effects.push_back(Effect::TeardownStream { scope });
          }
        }
        tributary_proto::Action::Enumerate(cmd) => {
          let watch = cmd.dir();
          let Some(&scope) = self.watch_scopes.get(&watch) else {
            debug_assert!(false, "an enumerate reads a known directory");
            continue;
          };
          let Some(path) = self.scoped_path(scope, watch) else {
            debug_assert!(false, "an enumerate reads a placeable directory");
            continue;
          };
          let path = Arc::new(path);
          self.enum_reqs.insert(cmd.req(), (scope, Arc::clone(&path)));
          self.effects.push_back(Effect::Enumerate {
            req: cmd.req(),
            watch,
            path,
          });
        }
        tributary_proto::Action::Stat(cmd) => {
          // The Monitor asks only for a slot a listing left unclassifiable. This
          // driver's own listing lowers every `FileType` it can name and falls back
          // to `Other`, so the request is unreachable through it — but a stat is a
          // protocol obligation, and dropping one would leave the Monitor's slot
          // dark forever rather than merely until the answer lands. It is served on
          // the blocking pool by the same `lstat` the FSEvents grounding uses.
          let Some(child) = cmd.of().as_child() else {
            debug_assert!(false, "the Monitor stats a named child slot");
            continue;
          };
          let Some(&scope) = self.watch_scopes.get(&child.parent()) else {
            debug_assert!(false, "a stat names a slot under a known directory");
            continue;
          };
          let Some(parent_path) = self.scoped_path(scope, child.parent()) else {
            debug_assert!(false, "a stat names a slot under a placeable directory");
            continue;
          };
          let path = parent_path.join(child.name().as_str());
          let probe = self.mint_probe(
            scope,
            ProbePurpose::SlotKind {
              req: cmd.req(),
              path: path.clone(),
            },
          );
          self.effects.push_back(Effect::Probe { probe, path });
        }
        other => {
          debug_assert!(false, "the Monitor requests no other work: {other:?}");
        }
      }
    }
  }

  fn route_event(&mut self, change: Change) {
    let scope = change.scope();
    let Some(state) = self.scopes.get_mut(&scope) else {
      // A change for a scope torn down in the same drain still delivers when
      // its root is still nameable (the dying entry keeps it) — over-delivery
      // is the safe direction. Without a dying entry the dead scope owes no
      // coverage, and a straggler with no assignable root is dropped rather
      // than misattributed.
      if let Some(entry) = self.dying.get(&scope) {
        self.effects.push_back(Effect::Emit {
          scope,
          root: Arc::clone(&entry.root),
          change,
        });
      }
      return;
    };
    // THE RENAME REPAIR, and it is the reason #74 reproduces with no torn read at
    // all. A mount's identity does not change when the directory it is under is
    // renamed, and the mount table is never told: `rename(2)` bumps no namespace
    // generation, so a census taken after the `mv` still renders the row under its
    // NEW label while everything this scope holds names the old one. Left
    // unrepaired, a mount at `R/a/x` under an `R/a -> R/b` rename departs into a
    // cover at `R/a/x`, and the ground revealed at `R/b/x` is never covered at
    // all.
    //
    // So a paired move re-roots every hint at-or-under it, in the same step the
    // core learns of it and BEFORE the change leaves. It runs for a scope that is
    // not publicly live and for one that is lagged, because the rename happened
    // either way and the hints are internal state, not delivery.
    //
    // `learned_mounts` is deliberately NOT rebased here: a stale learned prefix
    // only ever VETOES trust, which is the safe direction.
    if let Some(from) = change.kind().moved_from() {
      Self::rebase_hints(state, from, change.location());
    }
    // NEVER-LIVE FENCE: a scope whose public delivery never began owes the
    // consumer nothing — its watch() resolved Err (a spawn failure, a final-root
    // rejection, or a descending ROOT-ARM failure) and the caller never received
    // the handle these changes would carry. The Monitor's own failure Rescan for
    // such a root is internal bookkeeping, not public coverage; delivering it
    // would tell a consumer to rescan a root that was never watched. The fact is
    // `publicly_live`, NOT `root.is_some()`: a descending scope populates `root`
    // at spawn but is not publicly live until its root arm succeeds, so a failed
    // root arm (whose `Err` the deferred grant already delivered) is fenced here.
    if !state.publicly_live {
      return;
    }
    // THE LOSSY WINDOW: a public scope `Rescan` signals the scope may have lost
    // coverage work (a failed grow arm, an unreadable re-arm read, an overflow) —
    // whether or not a reconcile is currently unobserved. For a descending scope:
    //
    // - The `Rescan` ENSURES the scope's loss-memory entry (creating it when none
    //   exists) and marks it: every pending fence degrades, and a fence opened later
    //   — before the next settle observation clears the memory — inherits the loss
    //   (see [`CoverFence`]). Without the entry creation an out-of-window loss (after
    //   a clean settle, before the next reconcile) would be dropped with the window.
    //   The entry-creating mark cannot leak: the next settle observation removes a
    //   pending-empty entry exactly like any other.
    // - A NARROWED claim (`applied_cover` is `Some`) degrades IMMEDIATELY to the
    //   empty cover — the standing `Rescan` means the claim may span a hole, and the
    //   empty cover claims nothing below the root. The settle floor folds with it
    //   (the meet with the empty cover IS the empty cover), so an observation-time
    //   rewind cannot resurrect the stale claim. The next `on_set_cover` then
    //   computes its broadening delta against the degraded claim — a full re-arm of
    //   the requested retained set, genuinely re-proving coverage. Redundant
    //   re-reads on surviving watches are the bounded cost (a re-arm never MOVES a
    //   survivor). A never-narrowed scope (`applied_cover == None`) has no stale
    //   claim to degrade; its coverage self-heals through the Monitor's own re-arm.
    //
    // A kernel-recursive scope's whole-subtree stream never narrows
    // (`on_set_cover` refuses it before recording anything, so its `applied_cover`
    // is never `Some`), but that buys it no exemption here: `sync_root` opens a
    // cover fence for ANY scope without consulting the profile, so a KR scope can
    // hold a pending fence, and skipping its loss memory let a real
    // `FAN_Q_OVERFLOW` resolve that fence `Applied` over a window the kernel had
    // already dropped events from. The cost is at most ONE entry per scope,
    // cleared at the next settle observation — and a kernel-recursive scope's
    // `Rescan` sources are all genuine loss windows rather than churn: a real
    // queue overflow, a root death, and a root replace's cut. Conservative by
    // design for descending scopes: an unrelated churn `Rescan` degrades too (the
    // caller self-heals by re-issuing). Both routes below deliver the `Rescan`
    // (emitted, or parked as the lag's dominating change), so a marked window is
    // never a signal the consumer didn't also get.
    if change.kind().is_rescan() {
      self.cover_fences.entry(scope).or_default().mark_lossy();
      if state.applied_cover.is_some() {
        state.applied_cover = Some(Vec::new());
        state.settle_floor = Some(Vec::new());
      }
    }
    match &mut state.lag {
      LagState::Normal => {
        let root = state.delivery_root();
        self.effects.push_back(Effect::Emit {
          scope,
          root,
          change,
        });
      }
      LagState::Lagged { parked, .. } => {
        if change.kind().is_rescan() {
          // Fold the new Rescan into the parked one (INV-PARK): a located
          // mint (a deficit re-signal, an incomplete read, a failed arm)
          // must not shrink the drop set the parked instruction promised, so
          // the coverages join while the id + epoch advance to the newest
          // mint. Everything non-Rescan the scope produces while lagged
          // stays covered by the never-narrowing parked instruction and is
          // dropped.
          *parked = Some(match parked.take() {
            None => change,
            Some(prev) => Self::covering_merge(&prev, change),
          });
        }
      }
    }
  }
}

/// The plan for one compiled event.
enum ItemPlan {
  Immediate(Vec<Planned>),
  Await { probe: ProbeId, path: PathBuf },
}

/// One probe's resolution: the item it grounds, its planned inputs, and its
/// contribution to the batch's cookie-evidence exchange.
struct Resolved {
  item: usize,
  planned: Vec<Planned>,
  /// A fileID this probe bound to the root device (a cookied `Present`
  /// rename half whose EVENT word carried the same fileID the probe
  /// observed), with the partner path that carried the proof — settlement
  /// evidence for a vanished partner.
  evidences: Option<(NonZeroU64, PathBuf)>,
  /// A vanished half's grant candidacy (see [`Item::cookie_candidate`]).
  candidate: Option<(NonZeroU64, PathBuf)>,
}

impl Resolved {
  fn plain(item: usize, planned: Vec<Planned>) -> Self {
    Self {
      item,
      planned,
      evidences: None,
      candidate: None,
    }
  }
}

/// Lowers one executed `lstat` into the Monitor's stat vocabulary. A vanished
/// path is the benign race the Monitor settles as an empty slot; an unreadable
/// one settles nothing and leaves the slot's deficit standing.
fn stat_result(outcome: ProbeOutcome) -> StatResult {
  match outcome {
    // Identity is minted as the enumerate mints it — the bare inode, for an object
    // the probe could name. The probed DEVICE is deliberately not consulted: this
    // answer settles a kind, and the mount/device descent gate the enumerate applies
    // still governs whether the Monitor may go below the slot at all.
    ProbeOutcome::Present { kind, file_id, .. } => {
      let entry = StatEntry::new(kind);
      StatResult::Ok(match file_id.map(Identity::new) {
        Some(node) => entry.with_node(node),
        None => entry,
      })
    }
    ProbeOutcome::Missing => StatResult::Failed(IoClass::NotFound),
    ProbeOutcome::Failed => StatResult::Failed(IoClass::Io),
  }
}

/// Builds a record with identity minted from the event-side fileID.
fn record_from_event(
  state: &ScopeState,
  kind: RecordKind,
  target: Option<Location>,
  is_dir: Option<bool>,
  file_id: Option<NonZeroU64>,
  path: &Path,
) -> OsRecord {
  let node = mint(state, path, file_id, None);
  record_with(state, kind, target, is_dir, node)
}

/// Builds a record addressing `target` under the scope's root watch.
fn record_with(
  state: &ScopeState,
  kind: RecordKind,
  target: Option<Location>,
  is_dir: Option<bool>,
  node: Option<Identity>,
) -> OsRecord {
  let mut rec = OsRecord::new(state.watch, kind);
  if let Some(target) = target {
    rec = rec.with_target(target);
  }
  if let Some(is_dir) = is_dir {
    rec = rec.with_is_dir(is_dir);
  }
  if let Some(node) = node {
    rec = rec.with_node(node);
  }
  rec
}

/// Builds a record for the whole fact set `proven`, addressing `target` under the
/// scope's root watch. `None` when the set names no dirent verb — the caller then
/// owes a located rescan rather than a fabricated record.
fn record_proved(
  state: &ScopeState,
  proven: Evidence,
  target: Option<Location>,
  is_dir: Option<bool>,
  node: Option<Identity>,
) -> Option<OsRecord> {
  let mut rec = OsRecord::proved(state.watch, proven)?;
  if let Some(target) = target {
    rec = rec.with_target(target);
  }
  if let Some(is_dir) = is_dir {
    rec = rec.with_is_dir(is_dir);
  }
  if let Some(node) = node {
    rec = rec.with_node(node);
  }
  Some(rec)
}

/// The cover ONE mount transition at `path` lowers to — the single mapping the
/// mount design's covers use, so the refresh's own arrival/departure/replacement
/// covers and the admission round trip's parked one can never lower differently.
///
/// [`Lowered::Root`] and [`Lowered::Outside`] name the two cases that address no
/// location: the root itself (whose own mount changes are the death gate's
/// business and the frame replay's, not this diff's) and a path that will not
/// lower — a mount point under the root with a non-UTF-8 component. Both
/// over-cover the whole root, exactly as `compile::fsevents`' `plan_mount` does
/// for its own un-lowerable volume change.
///
/// **This site is where representability is ALLOWED to matter, and the only one.**
/// Every internal table screens on RAW containment ([`strictly_under_root`]), so
/// an unrepresentable boundary is recorded like any other and its departure is
/// derived like any other; it is here — where a location has to be spelled for a
/// consumer — that the answer degrades. Moving that decision back to the record
/// makes `Outside` silence, where `Outside` here is a whole-root `Rescan`.
fn mount_cover(state: &ScopeState, scope: ScopeId, path: &Path) -> Scope {
  match lower(state, path) {
    // The ordinary case: a mount BELOW the root moved, so everything under that
    // location needs re-enumeration.
    Lowered::Target(location) => located(state.watch, Some(location)),
    Lowered::Root | Lowered::Outside => Scope::Root(scope),
  }
}

/// A located subtree overflow at `target` under `watch` (the watch itself
/// when `target` is `None`).
fn located(watch: WatchId, target: Option<Location>) -> Scope {
  let sub = SubtreeScope::new(watch);
  Scope::Subtree(match target {
    Some(location) => sub.with_descent(location),
    None => sub,
  })
}

/// The directory-ness hint a flag word carries, if any.
fn dir_hint(flags: FsEventFlags) -> Option<bool> {
  if flags.item_is_dir() {
    Some(true)
  } else if flags.item_is_file() || flags.item_is_symlink() {
    Some(false)
  } else {
    None
  }
}

/// Mints the record identity for an object at `path`.
///
/// One function serves the event path (no device known — trusted iff no
/// foreign-mount prefix covers the path) and the probe path (`dev` known —
/// authoritative). Two minting schemes would make the Monitor's identity
/// comparisons fire on the same object forever.
fn mint(
  state: &ScopeState,
  path: &Path,
  file_id: Option<NonZeroU64>,
  dev: Option<u64>,
) -> Option<Identity> {
  let fid = file_id?;
  device_trusted(state, path, dev).then(|| Identity::new(fid))
}

/// Whether an enumerated directory `entry` sits across the scope's MOUNT
/// boundary and so must not be descended (lowered to [`FileKind::Other`]).
///
/// Two independent fences, either one a boundary:
///
/// - **the device belt** — `entry.dev != root_dev`. A different device is a
///   different superblock, always a boundary, and needs no mount id. Kept even
///   when mount ids are known (a different device cannot share the root's mount, so
///   this only ever agrees with the mount fence, but it costs nothing and is the
///   sole fence when a mount id is unavailable).
/// - **the mount fence** — the child's mount id differs from the root's, when BOTH
///   are known. This is the fence the device belt CANNOT provide: a `mount --bind`
///   of a same-superblock directory shares the root's device, so only a differing
///   mount id marks it a boundary.
///
/// When either mount id is unknown (the executor could not read one — below Linux
/// 5.8, the `stx_mask` bit unset, or a non-Linux/fake source), the device belt
/// alone governs — the honest degrade to the settled single-device policy, never
/// over-fencing a genuine in-root directory on a mount-id read miss. An unknown
/// ROOT device (`None`, an off-unix fake) leaves the belt inert; with no mount id
/// either, nothing crosses — the fake tree is one scope.
///
/// A `None` mount id reaching this belt is ALWAYS a legitimate mask-absent read (a
/// SUCCESSFUL statx below 5.8, or a fake), NEVER a swallowed statx failure: on Linux
/// the spawn barrier fails closed on any statx error (`os::linux::require_statx`) and
/// the mount-id captures turn a statx syscall failure into a spawn/walk failure, so a
/// statx-denied environment never goes live to feed a `None` frame here. The belt is
/// thus only ever the honest pre-5.8 degrade, not a silently disabled fence.
fn crosses_mount_boundary(state: &ScopeState, entry: &RawDirEntry) -> bool {
  let device_boundary = matches!(state.root_dev, Some(root_dev) if entry.dev != root_dev);
  let mount_boundary = matches!(
    (state.root_mnt_id, entry.mnt_id),
    (Some(root_mnt), Some(entry_mnt)) if root_mnt != entry_mnt
  );
  device_boundary || mount_boundary
}

/// Whether one half of a recorded mount's identity CHANGED between what was
/// recorded and what a table read now reports.
///
/// A change is two KNOWN values that disagree. `None` is unknown, never
/// different: a record and a row can carry different halves of the truth simply
/// because different observers answered them (a probe reads a device but no
/// mount id; a `getfsstat` row reads neither; a mountinfo line reads both), and
/// reading that as a replacement would cover a mount nothing did to. The same
/// `(Some, Some)` discipline [`crosses_mount_boundary`] fences on and
/// `root_mnt_id`'s adoption follows — on a host that answers no ids at all, the
/// same-path remount is simply not observable, which is the honest degrade
/// rather than a silently disabled check.
const fn identity_changed(recorded: Option<u64>, observed: Option<u64>) -> bool {
  matches!((recorded, observed), (Some(was), Some(now)) if was != now)
}

/// Records one boundary a SEAM observed into the LEDGER — the latency half of
/// the mount design, and for the boundaries a census never lists the only half.
///
/// The seams (a declined dir entry, an os-layer walk's decline, a
/// boundary-bearing probe answer, an admission that found the location still
/// covered) see a boundary at the moment the watcher's own machinery touched it,
/// ahead of the next table read. What that buys differs by [`Standing`], and on a
/// kernel-recursive profile by seam: the WALK is not latency there but the sole
/// observer of every boundary, since that profile runs no enumerate whose fence
/// could learn one.
///
/// - for a [`Standing::Mount`] it is LATENCY only. The next census sees every
///   mount this sees, so without a seam entry a boundary observed now merely
///   waits for the next tick to be keyed — and only a departure INSIDE that
///   window is missed. With one, that window closes, and the entry is spent on
///   the very census that closes it.
/// - for a [`Standing::SameMount`] boundary — a btrfs subvolume, which trips the
///   device belt carrying the root's OWN mount id — a seam is the only observer
///   there will ever be. `/proc/self/mountinfo` has no row for it and never will.
/// - a [`Standing::Unknown`] entry is either of those on a host that cannot say
///   which, and it fails the whole scope closed until a census row stands where
///   it does.
///
/// # Four rules, each of which a naive version gets wrong
///
/// **Strictly under the root — tested on the RAW path.** An entry AT the root
/// could never be matched by a census (`parse_mountinfo` filters the root's own
/// row out), so it would fail the scope closed forever on a host with no ids.
/// [`strictly_under_root`] is the whole test, and it is `Path`-component-wise
/// rather than protocol-representable ON PURPOSE.
///
/// This set is INTERNAL and keyed by `PathBuf`. Nothing here addresses a
/// consumer, so nothing here needs a location the protocol can spell — and
/// requiring one dropped observations that were fully identified. A Linux
/// pathname is arbitrary bytes, so a mount can perfectly well sit at a location
/// with a non-UTF-8 component; a [`Lowered::Target`] guard classified every such
/// observation [`Lowered::Outside`] and returned, which meant a fanotify walk
/// that DECLINED that boundary — reporting its raw path and its mount identity,
/// the only witness there will ever be for a mount that arrived after the spawn
/// census — recorded nothing at all. A lazy departure below it then produced
/// neither an admission nor a cover, and the revealed subtree stayed absent from
/// the FID map with its events silently rejected.
///
/// Lowering belongs at COVER EMISSION, where it already has a safe degrade:
/// [`mount_cover`] answers `Scope::Root` for a location it cannot spell, so an
/// unrepresentable boundary costs a WHOLE-ROOT cover rather than silence. That is
/// strictly the over-covering direction, which is the one this design takes
/// everywhere else too.
///
/// **Nothing the CENSUS already owns** — a row STANDING at this location, or one
/// already keyed by this observation's own id. Either way the census derives that
/// place's departure, its move and its replacement on its own, and a ledger entry
/// beside it would derive the same departure a second time or fail the scope
/// closed over ground a row already speaks for. This is the rule that keeps the
/// two structures disjoint, and it is what lets every retirement pass run over
/// the whole ledger with no partition test at all.
///
/// **Nothing beneath a boundary already recorded.** Ground under a live recorded
/// boundary is already declined, so a second entry there addresses coverage
/// nobody has, and when that boundary departs its cover dominates the whole
/// subtree. It is the containment [`learn_device`] applies to the trust table,
/// and it hides no real mount — a census row is keyed DIRECTLY, never through
/// here. It is also what makes a re-observation at an existing entry's location
/// inert: a `Path` prefix is inclusive, so the entry standing there keeps the
/// [`Standing`] its own seam decided rather than adopting a later reading. That
/// direction is the safe one — an entry demoted from `Mount` to `SameMount` by a
/// second observation would lose the departure belt it is held for, and one
/// promoted out of `Unknown` would clear a fail-closed on a reading that cannot
/// prove the boundary is the same one.
///
/// This rule was once documented as the set's GROWTH BOUND, and it never was
/// one. It refuses an entry BENEATH an existing one and says nothing about one
/// ABOVE it or BESIDE it: `/r/a` still enters a ledger already holding `/r/a/b`,
/// and a flat run of siblings — `/r/a`, `/r/b`, `/r/c`, one per subvolume ever
/// created and deleted — is contained by nothing at all. The real bound is
/// [`MAX_BOUNDARIES`], enforced below; the reconciliation that keeps the ledger
/// ACCURATE rather than merely bounded is the census join plus
/// [`retire_unwalked_boundaries`] (kernel-recursive) and
/// [`retire_relisted_boundaries`] (descending).
///
/// # Nothing is owed back to the caller
///
/// This returns nothing, and that is a claim rather than an omission. Every
/// outcome — recorded, owned by the census, contained, re-observed, or refused at
/// the bound — leaves the caller nothing to do. The refusal in particular:
/// [`make_room_in_ledger`] only ever refuses when the ledger is FULL of witnesses
/// that may still owe a cover, which on any host that answers ids means a
/// thousand live subvolume observations and on one that does not means the scope
/// is already covering its whole root on every authoritative refresh.
fn record_boundary(state: &mut ScopeState, location: &Path, mnt_id: Option<u64>) {
  if !strictly_under_root(state, location) {
    return;
  }
  let standing = Standing::decide(state.root_mnt_id, mnt_id);
  // OCCUPIED, on either of the two facts a census can offer: a row STANDING at
  // this location, or a row already keyed by this observation's own id.
  //
  // The location leg is not a convenience. On Linux 4.11-5.7 every census row is
  // `Id`-keyed (mountinfo has always carried mount ids) and every seam answers
  // none (`statx(STATX_MNT_ID)` does not exist), so the id leg never fires there
  // — and without the location leg every enumerate that re-declines a mount the
  // census already lists would push an `Unknown` entry and fail the whole scope
  // closed until the next refresh's join dropped it again. One whole-root cover
  // per refresh, for as long as anything under the root is being listed. It is
  // the same rule the join applies, one step earlier, and it is what keeps the
  // ledger to what the census cannot speak for.
  //
  // The id leg still earns its place: an observation whose id the census keys
  // ELSEWHERE is a mount the next read will derive a move for, and recording it
  // here would derive that move's departure a second time.
  if state.census.iter().any(|row| {
    row.location == location
      || matches!((&row.key, standing), (Key::Id(a), Standing::Mount(b)) if *a == b)
  }) {
    return;
  }
  if state
    .ledger
    .iter()
    .any(|entry| location.starts_with(&entry.location))
  {
    return;
  }
  // The HARD BOUND, applied BEFORE the push so the ledger can never exceed it
  // even for an instant. Room is made by evicting a proven `SameMount` entry —
  // one nothing can ever promote into a departure witness — and never a `Mount`
  // or `Unknown` one. When there is nothing but witnesses to evict, THIS
  // observation is refused instead: the direction that over-covers rather than
  // the one that loses a cover. See [`make_room_in_ledger`].
  if !make_room_in_ledger(state, MAX_BOUNDARIES) {
    // Refused, and refused SILENTLY on purpose. The fence that declined this
    // boundary reads the scope's FRAME, never the ledger, so descent is still
    // stopped there; and on a host that cannot key its witnesses the scope is
    // already failing closed, which covers the whole root on every authoritative
    // refresh and dominates anything a per-refusal announcement could stand. The
    // announcement this replaced was latched per saturation episode precisely
    // because it would otherwise storm, and that latch was itself a finding: one
    // refusal silenced every later one for the life of the episode.
    return;
  }
  state.ledger.push(LedgerEntry {
    location: location.to_path_buf(),
    standing,
  });
}

/// The most boundary entries one scope's ledger may hold at once.
///
/// This is the ledger's real growth bound, and it holds UNCONDITIONALLY — when
/// every reconciliation path has failed, when the event stream that carries
/// deletions is lost, when the walk that would establish a generation never runs.
/// The census join and the retirement passes keep the ledger accurate; this keeps
/// it finite.
///
/// Sized so it binds only pathology: a real btrfs/snapper/docker layout under one
/// watched root holds tens of subvolumes, not thousands, and every genuine
/// vfsmount on an id-answering host is taken over by the first authoritative
/// census and so is not held here at all. A scope that reaches the bound is one
/// where distinct boundary locations churned past every reconciliation, and
/// holding 1024 of them is strictly better than holding all of them forever.
///
/// WHICH 1024 is [`make_room_in_ledger`]'s decision, and it is not simply "the
/// most recent": an entry that could still be the witness for a departure cover
/// is kept and the new observation refused instead, because an extra arrival
/// cover is a cost and a lost departure cover is a hole.
const MAX_BOUNDARIES: usize = 1024;

/// The most departure covers one fanotify scope may hold PARKED on admission
/// round trips at once. A refresh that would push past it collapses its whole
/// departure set into one [`Effect::RecoverRoot`] instead.
///
/// The burst this bounds is real and it is the namespace's: one refresh can
/// condemn every mount under the root at once (a container teardown, a
/// `umount -R`, an automounter expiring a tree). Each parked entry is a
/// `PathBuf` plus a request the source must queue, walk and answer individually
/// — and the answering side searches the parked vector per reply, so an
/// unbounded burst is quadratic on top of unbounded.
///
/// The collapse is not a weaker answer. A whole-map reseed walks strictly more
/// ground than the located walks it replaces, its complete generation re-records
/// every boundary that is still live (which is what a `StillCovered` would have
/// done, one at a time), and the root cover behind it dominates every located
/// cover it stands in for.
///
/// Sized so it binds only the burst: a handful of simultaneous departures is
/// ordinary and each deserves its own located walk and its own precise cover,
/// while sixty-four at once is a namespace-scale event whose one recovery is both
/// cheaper and stronger. Deliberately the same number the source's own backlog
/// cap uses, so the producer collapses before the consumer ever has to.
const MAX_PENDING_ADMITS: usize = 64;

/// Frees a slot in the ledger for one more entry, or answers `false` when it
/// could not without dropping one that may yet owe a cover — the eviction half of
/// [`MAX_BOUNDARIES`].
///
/// # What may be evicted, and what may NOT
///
/// An earlier version of this evicted the oldest entry outright, on the reasoning
/// that a boundary the mount table cannot condemn "obliges no cover, so dropping
/// one costs at most an extra arrival cover". That reads "the census will not
/// speak for it" as "it is not a mount", and it is not:
///
/// - a [`Standing::SameMount`] entry — both ids known and EQUAL — describes
///   something no mountinfo read will ever list. Nothing can promote it, so it
///   can never become the witness for a cover, and it leaves silently.
/// - a [`Standing::Unknown`] entry is the exact shape a GENUINE post-census
///   vfsmount takes on a host that answers no mount ids. Dropping it discards the
///   only witness a departure there will ever have.
/// - a [`Standing::Mount`] entry is a witness by construction: it is the belt for
///   the window between the seam that saw the mount and the census that will take
///   it over.
///
/// So only `SameMount` is evicted. The ledger is bounded at the INTAKE side
/// instead: when it holds nothing but entries that might yet owe a cover, the new
/// observation is refused (`false`) rather than a witness discarded.
///
/// # Why refusing the new observation loses nothing
///
/// A refused observation is not a missed boundary. The fence that declined it
/// reads the scope's FRAME, never this ledger, so descent is still stopped there;
/// and the ledger's only jobs for an entry are to hold a departure witness the
/// census cannot, to block a redundant entry beneath it, and to fail the scope
/// closed. Refusing therefore only ever causes MORE covering — a mount refused
/// here is keyed by the next census as an ARRIVAL, covered, and its departure
/// covered like any other from then on. That is the same over-signal direction
/// the design accepts for arrival covers generally.
///
/// # The bound still binds on a host that answers no mount ids
///
/// There, EVERY entry is `Unknown`, so nothing is ever evicted — and the ledger
/// is still hard-bounded, because the refusal above caps intake at
/// [`MAX_BOUNDARIES`]. "Never evict a witness" and "hold a finite set" are only in
/// tension if eviction is the only bound; making the intake the bound resolves it
/// without ever paying for a fresh observation with a witness. The stale contents
/// are reclaimed by the passes that exist for exactly that
/// ([`retire_unwalked_boundaries`], [`retire_relisted_boundaries`],
/// [`DriverCore::retire_removed_boundaries`]) and by the census join — this is
/// the floor under them, not a substitute for them.
///
/// Oldest-first among the `SameMount` entries because the ledger is in insertion
/// order, so the ones most likely to be stale are at the front.
fn make_room_in_ledger(state: &mut ScopeState, cap: usize) -> bool {
  // One slot must be free for the caller's push, so the ledger has to end BELOW
  // the cap, not at it.
  let mut excess = state.ledger.len().saturating_sub(cap.saturating_sub(1));
  if excess == 0 {
    return true;
  }
  state.ledger.retain(|entry| {
    if excess > 0 && matches!(entry.standing, Standing::SameMount) {
      excess -= 1;
      return false;
    }
    true
  });
  excess == 0
}

/// Collapses repeated locations to their FIRST occurrence, in place, preserving
/// order — the cover set and the parked set are sets of PLACES.
///
/// Two transitions can name one location: a key change at a single `L` is a
/// departure and an arrival there, and a move can land where something else left.
/// The consumer owes one re-read either way, and on fanotify one round trip.
///
/// The clone per surviving entry is bounded by the TRANSITIONS rather than by the
/// rows, so a frame in which nothing moved — every frame, on a settled host —
/// allocates nothing at all.
fn dedup_locations(locations: &mut Vec<PathBuf>) {
  if locations.len() < 2 {
    return;
  }
  let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
  locations.retain(|location| seen.insert(location.clone()));
}

/// Whether `path` is AT or UNDER any member of `prefixes` — the containment test
/// every retire pass makes, against a set built once for the whole pass.
///
/// The obvious spelling is `prefixes.iter().any(|p| path.starts_with(p))`, which
/// is linear in the set for EVERY record and turns each pass into
/// O(records x prefixes). Two of these passes run at event rate (one per compiled
/// batch, one per directory listing), so that product is the shape that stalls a
/// single-threaded driver. Probing `path`'s own ancestors against an ordered set
/// is O(depth log prefixes) instead, and it is the same predicate:
/// `a.starts_with(b)` holds exactly when some ancestor-or-self of `a` equals `b`.
fn under_any_prefix(prefixes: &BTreeSet<&Path>, path: &Path) -> bool {
  path.ancestors().any(|ancestor| prefixes.contains(ancestor))
}

/// Retires every LEDGER entry a COMPLETE whole-root walk did not decline — the
/// generation half of the ledger's lifecycle, on the profile that has no other.
///
/// A kernel-recursive scope runs no enumerate, so
/// [`retire_relisted_boundaries`]'s re-listing never happens there; and no census
/// can retire an entry the mount table will never list. That left the
/// compiled-removal pass ([`DriverCore::retire_removed_boundaries`]) as the sole
/// removal path, and a loss window that swallowed a deletion left its entry
/// standing for the scope's life. A complete walk from the root is the answer
/// already available: it declines every boundary that is still there, so anything
/// the ledger holds that it did NOT decline is not there any more.
///
/// It runs over the WHOLE ledger, with no standing test: the ledger holds nothing
/// the census owns ([`record_boundary`] refuses that at intake and the join drops
/// it), so there is no partition here whose removal could silence a cover the
/// census is responsible for.
///
/// One exclusion, and it is load-bearing: **nothing UNDER a decline is retired.**
/// A walk stops at a boundary, so it observed nothing below one and may not speak
/// for it. Reachable through the containment rule's one gap — an entry ABOVE an
/// existing one is accepted — so it is guarded rather than argued away.
///
/// # Why no cover is owed — and it is NOT "these entries oblige nothing"
///
/// On a host that answers no mount ids a genuine vfsmount is recorded in exactly
/// the same shape as a subvolume ([`Standing::Unknown`]), and if one of THOSE
/// departs, the ground it revealed does owe a cover. What discharges it here is
/// the CALLER. There are exactly two, and each carries its own root-wide cover:
///
/// - the reader's POST-LOSS reseed, which enqueues a root-wide `Overflow`
///   immediately BEHIND its [`WalkReach::WholeRoot`](crate::os::WalkReach) report
///   on the source's one ordered queue;
/// - the whole-root RECOVERY, whose generation and root cover are the same
///   indivisible message ([`DriverCore::on_root_recovered`]).
///
/// So every retirement this pass makes is followed, in order, by a cover over the
/// entire root — which dominates any located cover a departed boundary could have
/// owed. A future caller that reports a complete generation WITHOUT a covering
/// loss behind it breaks that and must supply its own cover.
///
/// Neither caller's generation reaches this pass unchecked: both are judged
/// against the root mount id their walk fenced against before anything is retired,
/// because "everything still standing under the root" names a particular root
/// mount and this pass deletes what nothing else can restore.
fn retire_unwalked_boundaries(state: &mut ScopeState, declined: &[crate::os::DeclinedBoundary]) {
  if state.ledger.is_empty() {
    return;
  }
  let observed: BTreeSet<&Path> = declined
    .iter()
    .map(|boundary| boundary.location.as_path())
    .collect();
  state
    .ledger
    .retain(|entry| under_any_prefix(&observed, &entry.location));
}

/// Retires every LEDGER entry at a DIRECT CHILD of `dir` that a complete,
/// non-lossy listing of `dir` did not decline — the generation half of the
/// ledger's lifecycle on a DESCENDING profile.
///
/// A listing is authoritative about exactly one level: it names every child of
/// `dir` that exists. So an entry at a child the listing did not name is a
/// boundary whose directory is gone, and one at a child the listing named
/// WITHOUT declining is a location that is no longer a boundary at all (the
/// subvolume was deleted and an ordinary directory took its place). Either way
/// nothing else would ever drop it once a loss window ate the deletion record
/// the compiled-removal pass reads.
///
/// It runs over the whole ledger, with no standing test, for the reason
/// [`retire_unwalked_boundaries`] states: the ledger holds nothing the census
/// owns.
///
/// `kept` is every child path this listing DECLINED or EXCLUDED. An exclusion is
/// there for honesty rather than necessity: an excluded child is never recorded
/// through any seam, so it should never be a candidate — but the listing skips
/// it before the fence, so it cannot be read as "seen and not a boundary".
///
/// Callers must skip an INCOMPLETE or lossy listing entirely: an absent name
/// proves nothing when the read was cut short.
///
/// # Why no cover is owed
///
/// NOT because a ledger entry obliges nothing — it may be a genuine vfsmount
/// recorded on a host that answers no mount ids ([`Standing::Unknown`]) — but
/// because the LISTING that retires it is itself the re-observation. A child that stopped being a boundary comes back
/// from this very read as an ordinary directory, so the Monitor's own
/// reconciliation arms it and enumerates it (a listed directory with no child
/// watch is armed additively), and the ground the departure revealed is read on
/// that crawl. A child the read did not name at all is gone, and there is no
/// ground under it to re-read. Should a boundary somehow still be there, the very
/// next enumerate re-declines it and seam 1 records it again.
fn retire_relisted_boundaries(state: &mut ScopeState, dir: &Path, kept: &[PathBuf]) {
  // The listing's names as a SET: a directory with many children and a scope at
  // the ledger bound would otherwise pay `children x entries` comparisons per
  // enumerate. Exact membership, not containment — a listing speaks for its own
  // level only.
  let kept: BTreeSet<&Path> = kept.iter().map(PathBuf::as_path).collect();
  state.ledger.retain(|entry| {
    if entry.location.parent() != Some(dir) {
      return true;
    }
    kept.contains(entry.location.as_path())
  });
}

/// Records every boundary an os-layer WALK declined — SEAM 2's landing site, and
/// the ONE body both halves of the seam use, so the spawn walk and the live walks
/// can never record on different terms.
///
/// Each decline goes through [`record_boundary`] like every other seam
/// observation: strictly under the root, nothing the census already owns, and
/// nothing beneath a boundary already recorded. Nothing here keys a census row —
/// a walk's fence is not a mountinfo row — so what it creates is a ledger entry
/// whose [`Standing`] the walk's own two ids decide.
///
/// A walk never produces a decline BENEATH one of its own: a declined directory is
/// not descended, so nothing under it is ever reached to be declined again. The
/// containment rule therefore only ever fires here against a boundary some other
/// observer recorded first, and one walk's declines are always mutually
/// incomparable.
fn record_declined(state: &mut ScopeState, declined: &[crate::os::DeclinedBoundary]) {
  for boundary in declined {
    record_boundary(state, &boundary.location, boundary.mnt_id);
  }
}

/// The retained prefixes in `new` the PREVIOUS applied cover `prev` did not already cover —
/// the broadening delta a set-cover must re-arm. `prev == None` is the FULL
/// (never-pruned) cover: it covers everything, so nothing is broadening and the delta is empty.
/// Otherwise a retained prefix `r` is broadening iff NO member of `prev` is a prefix of it: its
/// subtree was pruned under `prev` (only its connecting ancestors were kept armed), so it must
/// be re-armed regardless of whether a watch survives at its own path. A prefix INSIDE some
/// previously-retained subtree (`r.starts_with(p)`) was never pruned and is skipped.
///
/// A pure function of the two covers — the coverage-restore decision in isolation, unit-tested
/// cross-platform. The caller resolves each broadening prefix to the deepest still-watched
/// ancestor-or-self and re-arms it.
fn broadening_delta<'a>(prev: Option<&[PathBuf]>, new: &'a [PathBuf]) -> Vec<&'a Path> {
  let Some(prev) = prev else {
    return Vec::new();
  };
  new
    .iter()
    .filter(|r| !prev.iter().any(|p| r.starts_with(p)))
    .map(PathBuf::as_path)
    .collect()
}

/// The antichain MEET of two retained covers — the coverage guaranteed by BOTH.
///
/// A cover retains everything under its prefixes, so the meet is their
/// intersection: a path is covered by the meet iff it is covered by `prev` AND
/// by `applied`. For antichain covers that is the pairwise rule — for each
/// nested pair, keep the DEEPER prefix (`meet({/x}, {/x/y}) = {/x/y}`); prefixes
/// nested in no member of the other cover contribute nothing
/// (`meet({/x}, {/z}) = {}` — an EMPTY meet is meaningful: nothing is
/// guaranteed by both). `prev == None` is FULL coverage, the meet identity
/// (`meet(FULL, A) = A`), mirroring `applied_cover`'s never-pruned initial
/// state. The pairwise result is deduped and normalized to cover form (a
/// member inside another member's subtree is redundant — with antichain
/// inputs the pairwise set already is one, so the pruning is defensive).
///
/// The settle floor is folded with this on every applied cover; a pure
/// function of the two covers, unit-tested cross-platform like
/// [`broadening_delta`].
fn cover_meet(prev: Option<&[PathBuf]>, applied: &[PathBuf]) -> Vec<PathBuf> {
  let Some(prev) = prev else {
    return applied.to_vec();
  };
  let mut deeper: Vec<&Path> = Vec::new();
  for p in prev {
    for a in applied {
      let kept = if a.starts_with(p) {
        a.as_path()
      } else if p.starts_with(a) {
        p.as_path()
      } else {
        continue;
      };
      if !deeper.contains(&kept) {
        deeper.push(kept);
      }
    }
  }
  let mut meet: Vec<PathBuf> = Vec::new();
  for kept in &deeper {
    // Cover normal form: a member strictly inside another member's subtree is
    // redundant — the shallower member already covers it. (`deeper` is deduped,
    // so value inequality means a different member.)
    let redundant = deeper
      .iter()
      .any(|other| *kept != *other && kept.starts_with(other));
    if !redundant {
      meet.push(kept.to_path_buf());
    }
  }
  meet
}

/// The move cookie for a rename half, minted ONLY from contemporaneous probe
/// evidence: `dev` is the device a probe just read for the object. fileIDs
/// are device-scoped, so any cookie without live root-device proof could pair
/// two different objects into a fabricated move — corruption with no covering
/// rescan. The mount table never grants a cookie; it can only veto one (the
/// vanished-half grant in [`DriverCore::grant_evidenced_cookies`] requires a
/// partner's probe evidence AND a clean table).
fn cookie_for(state: &ScopeState, file_id: Option<NonZeroU64>, dev: u64) -> Option<MoveCookie> {
  let fid = file_id?;
  (state.root_dev == Some(dev)).then(|| MoveCookie::new(fid))
}

/// Whether `path`'s objects provably live on the scope's root device.
///
/// A probe-side caller passes the stat-read device — direct evidence that
/// decides alone. An event-side caller passes `dev: None`, and unknown is
/// UNTRUSTED by default: absence from the mount table only proves anything
/// when the table was seeded authoritatively at spawn (an unseeded table is
/// merely blind to already-mounted volumes, which is exactly how a foreign
/// fileID gets promoted into a fabricated move).
///
/// The prefix comparison here is byte-based, and on a case-insensitive volume
/// a spelling-aliased path could MISS a stored mount prefix — the trust-
/// increasing direction. That miss is contained by what the table's answer
/// may still reach: cookies never come from the table (`cookie_for` requires
/// probe-read device evidence, and every probe carries the real device
/// regardless of spelling); the vanished-half grant uses the table only as a
/// VETO on top of partner probe evidence, and every grant that fires queues a
/// covering located `Rescan`, so an evaded veto degrades to a covered
/// mis-pair, never a silent one; event-side `mint` identity is consumed by
/// the Monitor only through descent machinery, which a kernel-recursive
/// backend never engages. The spellings themselves also share one origin —
/// mount prefixes (`getfsstat`) and event paths both carry the kernel's VFS
/// form through the same filesystem-representation transform — so an aliased
/// miss requires the kernel reporting two spellings for one mount point.
fn device_trusted(state: &ScopeState, path: &Path, dev: Option<u64>) -> bool {
  match (dev, state.root_dev) {
    (Some(dev), Some(root_dev)) => return dev == root_dev,
    (Some(_), None) => return false,
    (None, _) => {}
  }
  consumes_absence_trust(state.profile)
    && state.mounts_authoritative
    && !state.mount_table.iter().any(|m| path.starts_with(m))
    && !state.learned_mounts.iter().any(|m| path.starts_with(m))
}

/// **Whether `backend` has any consumer of ABSENCE-based device trust** — the
/// `dev: None` leg of [`device_trusted`], where a path is proven root-device by
/// no mount prefix covering it.
///
/// Stated as a predicate rather than left as prose because it decides two things
/// that must never disagree: whether the mount table is MAINTAINED
/// ([`install_mount_table`]) and whether it may be READ. Gating the read on the
/// same answer is what makes skipping the maintenance safe — a backend that stops
/// building the table cannot then be granted trust by its emptiness, and one that
/// grows a consumer without flipping this fails CLOSED (no absence trust) rather
/// than open.
///
/// The four-way argument, which is the whole content of the answer:
///
/// - **FSEvents** — the one `true`. Its lowering mints records straight from a
///   flag word's fileID with no device read anywhere in the path
///   ([`record_from_event`] -> [`mint`] with `dev: None`), and its settlement
///   grants a vanished rename half its pairing cookie under a table VETO
///   ([`DriverCore::grant_evidenced_cookies`]). It is also the only backend that
///   FEEDS the table anything but a snapshot: mount and unmount arrive in band as
///   flag words. Consumer, writer and evidence source are all the same backend.
/// - **inotify** — descending, and its boundary question is answered by the
///   enumerate fence, which reads a real `dev` (and where the host has one, a
///   mount id) off the fd it pinned. Every identity it mints comes from that read
///   or from a probe, so `dev` is `Some` and [`device_trusted`] returns on the
///   direct-evidence arm before the table is consulted at all.
/// - **fanotify** — kernel-recursive with membership-only admission: it holds no
///   node identity to mint, and its map admits by directory-handle membership,
///   which the seed and reseed walks establish by walking. Absence from a table
///   grants it nothing it could use.
/// - **RDCW and USN (Windows)** — a watch is scoped to one VOLUME by
///   construction: RDCW's handle and the USN journal cursor are both per-volume,
///   so nothing under the root can be on a foreign device and the question the
///   table answers does not arise. There is no `/proc/self/mountinfo` equivalent
///   feeding one either.
///
/// Written as an exhaustive match so a new backend cannot be added without
/// answering it — the same discipline [`feeds_at_classify`] carries.
const fn consumes_absence_trust(backend: BackendKind) -> bool {
  match backend {
    BackendKind::FsEvents => true,
    BackendKind::Inotify | BackendKind::Fanotify | BackendKind::Rdcw | BackendKind::UsnJournal => {
      false
    }
  }
}

/// Installs one authoritative mount table's locations, REPLACING the last one.
///
/// The single write path for [`mount_table`](ScopeState::mount_table) — the
/// spawn barrier's seed, both world swaps' and the authoritative refresh's — so
/// the replacement discipline and the per-backend gate are stated once and
/// cannot drift between the four.
///
/// The gate CLEARS as well as skips: a scope whose profile resolved to a
/// non-consuming backend after registering under a provisional one
/// ([`DriverCore::on_stream_spawned`]'s reprofile) must not keep rows a
/// provisional profile installed.
fn install_mount_table(state: &mut ScopeState, rows: impl IntoIterator<Item = PathBuf>) {
  state.mount_table.clear();
  if consumes_absence_trust(state.profile) {
    state.mount_table.extend(rows);
  }
}

/// Applies one MOUNT event's trust-reducing prefix add. Runs in `compile`'s
/// pre-scan — strictly before any of the batch's items are classified — so a
/// same-batch rename under the just-mounted volume already sees the foreign
/// prefix. The trust-increasing dual (an unmount's removal) is deferred to
/// settlement instead: see the monotone-within-batch rule in `compile`.
///
/// Contained on the RAW path ([`strictly_under_root`]), like [`record_boundary`]
/// and like [`learn_device`] just below — this table is a set of `PathBuf`
/// prefixes that only ever REDUCES trust, so refusing an entry it cannot spell
/// as a protocol location would grant trust the observation just denied. The
/// representability gate that stood here was the same one [`record_boundary`]
/// carried, and it failed in the same direction.
fn apply_mount_add(state: &mut ScopeState, ev: &RawOsEvent) {
  if !strictly_under_root(state, &ev.path) {
    return;
  }
  // Into the LEARNED half, and deduped only against that half. A word describes a
  // mount that may have arrived after the snapshot currently in flight was read,
  // so pairing it with a table row would let that install drop it; kept
  // independent, it is removed by exactly one thing — the unmount word for the
  // same path, deferred to settlement — which is what bounds this set to the
  // mounts that are actually live.
  if !state.learned_mounts.iter().any(|m| m == &ev.path) {
    state.learned_mounts.push(ev.path.clone());
  }
}

/// Records a probed foreign-device path as a mount prefix, so later
/// event-side identities under it degrade to `None` instead of colliding.
///
/// Into the LEARNED half: this is a path the probe read a device at, not a
/// mountpoint, so no table row need ever name it and an install that replaced it
/// away would re-trust a subtree a stat proved foreign. Deduped against BOTH
/// halves — a path already covered by a live table row or an existing learned
/// prefix adds no veto — which is also what bounds the set: the first prefix
/// learned under a volume absorbs every deeper path on it.
fn learn_device(state: &mut ScopeState, path: &Path, dev: u64) {
  if let Some(root_dev) = state.root_dev
    && dev != root_dev
    && !state.mount_table.iter().any(|m| path.starts_with(m))
    && !state.learned_mounts.iter().any(|m| path.starts_with(m))
  {
    state.learned_mounts.push(path.to_path_buf());
  }
}

/// SEAM 4: records the boundary a probe answer revealed, if it revealed one.
///
/// A probe answers BOTH halves the fence reads — the device and, where the host
/// can say, the mount id ([`ProbeOutcome::Present`]) — so the boundary question
/// it puts to [`ScopeFrame::crossed_by`] is the same two-fence truth table
/// [`crosses_mount_boundary`] applies to a dir entry, and the record it mints
/// carries the same identity a listing's decline would.
///
/// **That the id is asked for at all is the correctness point, not a detail.** A
/// probe that answered a device alone recorded every boundary with
/// `mnt_id: None`, which [`Standing::decide`] can only read as
/// [`Standing::Unknown`] — a boundary that fails the whole scope closed on a
/// kernel able to name it exactly, and that no census join can ever clear except
/// by a row standing at its location. Recording an ambiguity from an observation
/// that COULD tell a vfsmount from a same-mount subvolume is the defect; asking
/// for the id is the fix, and it leaves `None` meaning only "this host answers no
/// mount ids".
///
/// Only a `Present` answer carries either fact. `Missing` and `Failed` observe
/// nothing about a boundary — a path that is absent or unreadable says nothing
/// about what is mounted there — so they record nothing rather than guessing in
/// either direction.
///
/// # Why the SLOT-STAT answer and not every probe answer
///
/// The slot stat is the probe whose device is genuinely DISCARDED: `stat_result`
/// consumes the kind and the inode and drops the rest. The FSEvents grounding
/// probes (`ProbePurpose::Ambiguous`, `ProbePurpose::Rename`) already consume
/// theirs — [`learn_device`] for trust, [`mint`] and [`cookie_for`] for identity
/// — and recording them here would buy nothing and cost two things it should
/// not:
///
/// - **retirement.** An exempt ledger entry is retired by a compiled removal
///   ([`DriverCore::retire_removed_boundaries`]), by a complete re-listing of its
///   parent ([`retire_relisted_boundaries`]) or by a complete whole-root walk
///   ([`retire_unwalked_boundaries`]). An FSEvents removal reaches none of them:
///   it is not compiled — it is GROUNDED by the very probe that would have
///   recorded the boundary, one stage later — and that profile runs neither
///   enumerates nor walks. Entries from that path would have no seam that ever
///   drops them, leaving only the hard bound.
/// - **growth.** Those probes fire per event, so a long-lived watcher over a
///   mounted volume would accrete one record per distinct path ever probed.
///
/// Neither costs coverage on the platform that issues them: macOS signals its
/// volume changes IN BAND (`compile::fsevents`' `plan_mount` covers arrival and
/// departure alike), so the latency a seam buys there is already bought. The
/// slot stat, by contrast, only ever fires on a descending profile — the Monitor
/// stats a slot a LISTING left unclassifiable — which is exactly the profile
/// whose enumerates re-observe the location and whose removals compile.
fn record_probe_boundary(state: &mut ScopeState, path: &Path, outcome: ProbeOutcome) {
  let ProbeOutcome::Present { dev, mnt_id, .. } = outcome else {
    return;
  };
  if !state.frame().crossed_by(Some(dev), mnt_id) {
    return;
  }
  record_boundary(state, path, mnt_id);
}

/// Whether one byte separates path COMPONENTS on this platform.
///
/// `/` everywhere, and `\\` in addition on Windows, where it is the primary
/// separator and the one `Path::join` writes. Reading only `/` there made this
/// whole lowering answer [`Lowered::Outside`] for every path any `join` had
/// built — the containment tests below all use `Path`'s own component-wise
/// comparison and were correct already, so this byte scan was the one place that
/// disagreed with the platform about what a path is. `\\` is a legal FILENAME
/// byte on Unix, so the extra separator is strictly `cfg`-gated rather than
/// accepted everywhere.
const fn is_separator_byte(byte: u8) -> bool {
  byte == b'/' || (cfg!(windows) && byte == b'\\')
}

/// Whether `path` is a STRICT descendant of the scope root — the containment
/// every internal `PathBuf`-keyed table screens on.
///
/// `Path::starts_with` compares COMPONENTS, so `/r/bc` is not under `/r/b` and a
/// platform's own separators are the platform's business; the raw byte scan
/// [`lower`] performs exists only because a protocol [`Location`] has to be built
/// out of `str` segments, and it is not needed to answer containment.
///
/// **It deliberately says nothing about representability.** [`lower`] answers
/// [`Lowered::Outside`] for a path with any non-UTF-8 component, and the tables
/// that screened on `Lowered::Target` therefore DROPPED observations about real
/// ground — silently, and in the direction that loses coverage. A location the
/// protocol cannot spell is a problem for whatever ADDRESSES the consumer, and
/// that is the cover ([`mount_cover`], which degrades to the whole root), never
/// the record.
fn strictly_under_root(state: &ScopeState, path: &Path) -> bool {
  let Some(root) = state.root.as_deref() else {
    return false;
  };
  path != root && path.starts_with(root)
}

/// Lowers an absolute event path to its place under the scope root.
///
/// Canonical roots never carry a trailing separator except the filesystem
/// root `/` itself (both `fs::canonicalize` and the spawn-side transform
/// guarantee it), so `/` is the one root whose descendants strip to a bare
/// remainder.
fn lower(state: &ScopeState, path: &Path) -> Lowered {
  let Some(root) = state.root.as_deref() else {
    return Lowered::Outside;
  };
  let root_bytes = path_bytes(root);
  let bytes = path_bytes(path);
  let Some(rest) = bytes.strip_prefix(root_bytes) else {
    return Lowered::Outside;
  };
  let rest = match rest {
    [] => return Lowered::Root,
    [byte, tail @ ..] if is_separator_byte(*byte) => tail,
    // The root "/" already ends with the separator, so its descendants
    // arrive without a leading one ("/tmp/a" strips to "tmp/a").
    tail if root_bytes == b"/" => tail,
    // The prefix matched mid-component (root "/a/b" vs path "/a/bc").
    _ => return Lowered::Outside,
  };
  let mut segments = Vec::new();
  for part in rest.split(|&byte| is_separator_byte(byte)) {
    if part.is_empty() {
      continue;
    }
    // macOS filenames are valid Unicode by filesystem contract; anything
    // else is unaddressable and escalates at the caller.
    let Ok(part) = std::str::from_utf8(part) else {
      return Lowered::Outside;
    };
    segments.push(Segment::new(part));
  }
  if segments.is_empty() {
    Lowered::Root
  } else {
    Lowered::Target(Location::from_segments(segments))
  }
}

fn path_bytes(path: &Path) -> &[u8] {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes()
  }
  #[cfg(not(unix))]
  {
    path.as_os_str().to_str().map_or(&[][..], str::as_bytes)
  }
}

/// The Monitor capability profile a backend registers with.
const fn caps_for(backend: BackendKind) -> Capabilities {
  let caps = Capabilities::new().with_supports_push().with_native_move();
  match backend {
    // Every kernel-recursive backend registers the KR profile: one native
    // stream covers the whole root, so the Monitor never descends.
    BackendKind::FsEvents | BackendKind::Fanotify | BackendKind::Rdcw | BackendKind::UsnJournal => {
      caps.with_kernel_recursive()
    }
    // inotify's per-watch teardown records (`IN_IGNORED`, unmount included)
    // ride the same queue an `IN_Q_OVERFLOW` empties, so a loss can leave
    // retained watches kernel-dead with no record of it: a scope-level loss
    // must re-prove every retained binding by an acknowledged re-add.
    BackendKind::Inotify => caps.with_lossy_watch_teardown(),
  }
}

/// Whether `backend` decides exclusions ITSELF, at admission, before an event
/// ever reaches the common layer — the composition gate for the live half of the
/// common-layer fence ([`DriverCore::fence_exclusions`]).
///
/// The fence supplies enforcement exactly where a backend has none. Where a
/// backend already has one, re-deciding here could only DIFFER from it, because
/// the backend decides with strictly more context:
///
/// - **FSEvents** hands the set to the OS, which drops the events before the
///   process sees them (a rejected set fails the spawn outright, so enforcement
///   is proven, never partial). Its records are also minted at probe resolution,
///   AFTER compile, so a fence here would cover only some of them — partial
///   suppression is worse than none.
/// - **fanotify** fences at admission, where it holds the atomic rename pair. It
///   deliberately forwards a rename that CROSSES the boundary — the crossing is
///   what tells the consumer the object left the reported tree — and suppresses
///   only a rename with NO end in the reported tree (an end fails to be
///   reported either because it is excluded or because it lies outside the
///   watched root — the two are not the same test). A second, half-by-half
///   decision here would silently rewrite that pair into a bare removal.
///
/// Every other backend answers `false` and is enforced by the fence, INCLUDING a
/// future descending one: a descending backend cannot enforce at admission (its
/// only refusal is an arm, which the Monitor reads as loss), so the default is
/// the correct answer for the whole class rather than a per-backend opinion.
const fn backend_enforces_exclusions(backend: BackendKind) -> bool {
  matches!(backend, BackendKind::FsEvents | BackendKind::Fanotify)
}

/// Whether `backend` runs the GEOMETRY half of the common-layer fence — the half
/// that re-enumerates a moved subtree whose rename crossed an exclusion boundary
/// ([`DriverCore::reparent_geometry`]), read off the Monitor's own report on the
/// far side of each record's hand-off.
///
/// A pure function of the profile, deliberately: the caller's exclusion set
/// decides whether the geometry pass has anything to do on a given read, but not
/// whether the profile is one that resolves per-directory paths mid-read at all.
/// That distinction is what [`feeds_at_classify`] is coupled to — a discipline
/// that flipped with the configuration would make the exclusion path a different
/// code path from the default one.
const fn runs_rename_geometry(backend: BackendKind) -> bool {
  !backend_enforces_exclusions(backend) && !caps_for(backend).kernel_recursive()
}

/// Whether `backend` hands each kept record to the Monitor AS THE FENCE
/// CLASSIFIES IT, instead of buffering the whole read for
/// [`settle`](DriverCore::settle).
///
/// # Why the discipline exists
///
/// Batch-then-settle puts a PHASE LAG between the two halves of one read: the
/// fence classifies every record before the Monitor is told about any of them.
/// This core derives every watch path from the Monitor's own tree
/// ([`DriverCore::path_of`]), so under the lag a descending profile's addressing
/// question — "where does this record's watch live NOW" — is answered by a
/// Monitor that has not yet heard a single record of the read it is being asked
/// about, and one rename early in the read makes every later answer wrong. The
/// geometry decision has the same shape: it reads the Monitor's report of a
/// reparent that, under the lag, has not happened. Feeding at classify time
/// closes both: by the time a record is judged, every record ahead of it in the
/// same read has already landed, and the report of what each one did to the tree
/// exists.
///
/// # Why it is per-PROFILE and not per-configuration
///
/// The answer is read off the backend alone, so a scope with no exclusions
/// configured feeds exactly the way a scope with them does. The fence's
/// early-outs (no exclusions, or a backend that enforces its own) decide whether
/// there is anything to SUPPRESS; they must not decide how records reach the
/// Monitor, or the default configuration would exercise a feeding path the
/// exclusion tests never cover.
///
/// # Why only inotify
///
/// [`settle`](DriverCore::settle) has three duties, and inotify is the profile
/// for which the other two are vacuous:
///
/// - **granting evidenced cookies.** A `cookie_candidate` is minted only at probe
///   resolution and `evidenced` is filled only there, so both are empty for every
///   lowering that mints no probe — which is every lowering but FSEvents.
/// - **applying deferred unmount trust-removals.** `deferred_unmounts` is filled
///   only by the FSEvents lowering; every other lowering builds it empty.
///
/// What remains is feeding, and feeding early is safe only where the batch is
/// complete when the fence runs: FSEvents is the one profile that compiles a
/// batch with `awaiting > 0`, parking it until its probes answer, and a parked
/// batch's items are still placeholders. It also stands the fence down entirely
/// ([`backend_enforces_exclusions`]), so it neither needs nor may have this.
/// fanotify likewise stands the fence down. RDCW and USN are fence-active but
/// kernel-recursive, so they run no geometry, and every record of theirs anchors
/// at the scope ROOT — the one watch no rename inside the tree can move — so
/// their addressing is a fixed point and batch-then-settle costs them nothing.
///
/// The batch's transport permit is unaffected: a feed-at-classify profile never
/// parks, so its permit is attached and dropped inside the same call either way.
///
/// Written as an exhaustive match so a new backend cannot be added without
/// answering this question, and checked against [`runs_rename_geometry`] below.
const fn feeds_at_classify(backend: BackendKind) -> bool {
  match backend {
    // Descending and fence-active: the only profile whose fence resolves
    // per-directory paths mid-read, and the only one that compiles no
    // probe-parked batch AND runs the geometry pass.
    BackendKind::Inotify => true,
    // Parks for probes (`awaiting > 0`), so a batch is not complete when the
    // fence runs — and stands the fence down anyway.
    BackendKind::FsEvents => false,
    // Enforces exclusions at admission; the fence stands down.
    BackendKind::Fanotify => false,
    // Fence-active but kernel-recursive: no per-directory watches, so no
    // geometry and no mid-read addressing dependency.
    BackendKind::Rdcw | BackendKind::UsnJournal => false,
  }
}

/// INV-FEED, first leg: geometry ⇒ feed-at-classify.
///
/// Both sides are pure functions of the profile, so the implication is settled at
/// COMPILE time rather than left to agree by coincidence — a future descending
/// backend that answered [`feeds_at_classify`] with `false` would run the
/// geometry pass over the phase lag, classifying each record against addressing
/// its own read is still rewriting, and would fail to build here instead.
///
/// The second leg (feed-at-classify ⇒ `awaiting == 0`) is a property of the
/// compiled batch rather than of the profile, so it is asserted where the batch
/// exists, in [`DriverCore::fence_exclusions`]. That assertion is stated over the
/// profile in hand rather than variant by variant, so it reaches every backend
/// including one added after this list.
const _: () = {
  assert!(!runs_rename_geometry(BackendKind::Inotify) || feeds_at_classify(BackendKind::Inotify));
  assert!(!runs_rename_geometry(BackendKind::FsEvents) || feeds_at_classify(BackendKind::FsEvents));
  assert!(!runs_rename_geometry(BackendKind::Fanotify) || feeds_at_classify(BackendKind::Fanotify));
  assert!(!runs_rename_geometry(BackendKind::Rdcw) || feeds_at_classify(BackendKind::Rdcw));
  assert!(
    !runs_rename_geometry(BackendKind::UsnJournal) || feeds_at_classify(BackendKind::UsnJournal)
  );
};

/// The `(dev, ino)` an arm must confirm the opened object still has before
/// installing its kernel watch — the object-correctness check that closes the
/// enumerate→arm rename window (a descended child, or the root itself). Carried
/// on [`Effect::AddWatch`] and plumbed to the executor's open+fstat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedObject {
  /// The device the object was read on.
  pub(crate) dev: u64,
  /// The object's inode.
  pub(crate) ino: NonZeroU64,
}

/// One raw directory entry as the executor read it — name bytes and stat
/// facts only; the CORE mints the proto `DirEntry` (identity policy needs the
/// scope's device-trust state, which an executor never holds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawDirEntry {
  /// The entry's name, as raw bytes (non-UTF-8 degrades the listing).
  pub(crate) name: Vec<u8>,
  /// The entry's kind.
  pub(crate) kind: FileKind,
  /// The device the entry lives on.
  pub(crate) dev: u64,
  /// The entry's inode number (0 = unknown).
  pub(crate) ino: u64,
  /// The entry's MOUNT id (from `statx(STATX_MNT_ID)`), or `None` when the
  /// executor could not read it (a pre-5.8 kernel, the mask bit unset, or a
  /// non-Linux/fake executor). The core fences descent on a differing mount id —
  /// a `mount --bind` of a same-device directory shares [`dev`](Self::dev), so
  /// the device alone cannot mark it a boundary. `None` falls back to the device
  /// check (the honest below-5.8 degrade).
  pub(crate) mnt_id: Option<u64>,
}

/// One raw enumerate outcome from the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RawEnumerate {
  /// The directory was read; `complete` is false when the read was cut short.
  Listed {
    /// The entries read.
    entries: Vec<RawDirEntry>,
    /// Whether the listing covered the whole directory.
    complete: bool,
  },
  /// The directory could not be read.
  Failed(IoClass),
}

/// Maps a spawn failure to the Monitor's watch-error vocabulary.
fn watch_error(err: &SourceError) -> WatchError {
  match err {
    SourceError::RootUnavailable { source, .. } => match source.kind() {
      std::io::ErrorKind::NotFound => WatchError::NotFound,
      std::io::ErrorKind::PermissionDenied => WatchError::Permission,
      _ => WatchError::Io,
    },
    _ => WatchError::Io,
  }
}
