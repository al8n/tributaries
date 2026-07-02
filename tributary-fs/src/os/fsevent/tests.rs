use super::*;

#[test]
fn flag_predicates_match_their_bits() {
  let f = FsEventFlags::new(FsEventFlags::ITEM_CREATED.bits() | FsEventFlags::ITEM_IS_DIR.bits());
  assert!(f.item_created());
  assert!(f.item_is_dir());
  assert!(!f.item_removed());
  assert!(!f.item_renamed());
  assert!(f.contains(FsEventFlags::ITEM_CREATED));
  assert!(!f.contains(FsEventFlags::ITEM_REMOVED));
}

#[test]
fn coalesced_flag_words_report_every_operation() {
  let f = FsEventFlags::new(
    FsEventFlags::ITEM_CREATED.bits()
      | FsEventFlags::ITEM_MODIFIED.bits()
      | FsEventFlags::ITEM_REMOVED.bits()
      | FsEventFlags::ITEM_RENAMED.bits(),
  );
  assert!(f.item_created() && f.item_modified() && f.item_removed() && f.item_renamed());
}

#[test]
fn lost_sync_covers_both_drop_sides() {
  assert!(FsEventFlags::USER_DROPPED.lost_sync());
  assert!(FsEventFlags::KERNEL_DROPPED.lost_sync());
  assert!(!FsEventFlags::MUST_SCAN_SUBDIRS.lost_sync());
  assert!(!FsEventFlags::new(0).lost_sync());
}

#[test]
fn file_id_policy_is_total() {
  assert_eq!(file_id_from_extended(0), None);
  assert_eq!(file_id_from_extended(5).map(|n| n.get()), Some(5));
  assert_eq!(
    file_id_from_extended(-1).map(|n| n.get()),
    Some(u64::MAX),
    "the bit-cast is the lossless inverse of signed journal storage"
  );
}

#[test]
fn path_from_fs_repr_stops_at_the_first_nul() {
  assert_eq!(
    path_from_fs_repr(b"/tmp/a.txt\0slack"),
    Some(PathBuf::from("/tmp/a.txt"))
  );
  assert_eq!(path_from_fs_repr(b"/tmp/x"), Some(PathBuf::from("/tmp/x")));
  assert_eq!(path_from_fs_repr(b""), None);
  assert_eq!(path_from_fs_repr(b"\0"), None);
}

#[cfg(unix)]
#[test]
fn path_from_fs_repr_preserves_non_utf8_bytes() {
  use std::os::unix::ffi::OsStrExt;
  let bytes = b"/tmp/\xC3\x28\0";
  let path = path_from_fs_repr(bytes).expect("non-UTF-8 bytes are still a path");
  assert_eq!(path.as_os_str().as_bytes(), b"/tmp/\xC3\x28");
}

mod forward {
  use std::sync::atomic::{AtomicBool, Ordering};

  use super::*;

  fn raw(path: &str) -> RawOsEvent {
    RawOsEvent {
      path: PathBuf::from(path),
      flags: FsEventFlags::new(0),
      event_id: 1,
      file_id: None,
    }
  }

  /// Runs `forward_batch` against scripted channels, returning what each
  /// channel accepted and the dedup flag's final state.
  fn run(
    pending: bool,
    events: Vec<RawOsEvent>,
    lossy: bool,
    data_outcomes: &[SendOutcome],
    control_open: bool,
  ) -> (Vec<&'static str>, Vec<&'static str>, bool) {
    let overflow_pending = AtomicBool::new(pending);
    let mut data_sent = Vec::new();
    let mut control_sent = Vec::new();
    let mut script = data_outcomes.iter().copied();
    forward_batch(
      &overflow_pending,
      events,
      lossy,
      |msg| {
        let outcome = script.next().expect("the script covers every data send");
        if outcome == SendOutcome::Sent {
          data_sent.push(label(&msg));
        }
        outcome
      },
      |msg| {
        if control_open {
          control_sent.push(label(&msg));
        }
        control_open
      },
    );
    (
      data_sent,
      control_sent,
      overflow_pending.load(Ordering::Acquire),
    )
  }

  fn label(msg: &SourceMessage) -> &'static str {
    match msg {
      SourceMessage::Batch(_) => "batch",
      SourceMessage::Overflow => "overflow",
      SourceMessage::Fatal(_) => "fatal",
    }
  }

  #[test]
  fn all_undecodable_callback_signals_one_overflow() {
    let (data, control, pending) = run(false, Vec::new(), true, &[], true);
    assert!(data.is_empty());
    assert_eq!(control, ["overflow"], "loss rides the control channel");
    assert!(pending, "the signal stays pending until acknowledged");
  }

  #[test]
  fn lossy_batch_sends_data_and_one_overflow() {
    let (data, control, pending) = run(false, vec![raw("/r/a")], true, &[SendOutcome::Sent], true);
    assert_eq!(data, ["batch"]);
    assert_eq!(control, ["overflow"]);
    assert!(pending);
  }

  #[test]
  fn dropped_batch_signals_one_overflow() {
    let (data, control, pending) = run(false, vec![raw("/r/a")], false, &[SendOutcome::Full], true);
    assert!(data.is_empty());
    assert_eq!(control, ["overflow"]);
    assert!(pending);
  }

  #[test]
  fn pending_signal_dedups_further_losses() {
    let (data, control, pending) = run(true, Vec::new(), true, &[], true);
    assert!(data.is_empty());
    assert!(
      control.is_empty(),
      "an unacknowledged Overflow already covers this loss"
    );
    assert!(pending);
  }

  #[test]
  fn acknowledged_signal_rearms() {
    let overflow_pending = AtomicBool::new(false);
    let mut sent = 0usize;
    signal_loss(&overflow_pending, |_| {
      sent += 1;
      true
    });
    // The driver acknowledges (resets) — the next loss signals afresh.
    overflow_pending.store(false, Ordering::Release);
    signal_loss(&overflow_pending, |_| {
      sent += 1;
      true
    });
    assert_eq!(sent, 2);
  }

  #[test]
  fn closed_data_channel_signals_nothing() {
    let (data, control, pending) =
      run(false, vec![raw("/r/a")], true, &[SendOutcome::Closed], true);
    assert!(data.is_empty());
    assert!(control.is_empty(), "no receiver is left to signal");
    assert!(!pending);
  }

  #[test]
  fn closed_control_channel_restores_the_dedup() {
    let (data, control, pending) = run(false, Vec::new(), true, &[], false);
    assert!(data.is_empty());
    assert!(control.is_empty());
    assert!(
      !pending,
      "a dead control receiver must not mute a future generation"
    );
  }

  #[test]
  fn fatal_signals_at_most_once() {
    let fatal_sent = AtomicBool::new(false);
    let mut sent = 0usize;
    signal_fatal_once(&fatal_sent, SourceError::CallbackPanic, |_| {
      sent += 1;
      true
    });
    signal_fatal_once(&fatal_sent, SourceError::CallbackPanic, |_| {
      sent += 1;
      true
    });
    assert_eq!(sent, 1, "the terminal Fatal is once-ever");
  }
}

mod pure_rename {
  use super::*;

  #[test]
  fn type_hints_keep_a_rename_pure() {
    for extra in [
      0,
      FsEventFlags::ITEM_IS_FILE.bits(),
      FsEventFlags::ITEM_IS_DIR.bits(),
      FsEventFlags::ITEM_IS_SYMLINK.bits(),
      FsEventFlags::ITEM_IS_HARDLINK.bits(),
      FsEventFlags::ITEM_IS_LAST_HARDLINK.bits(),
    ] {
      let word = FsEventFlags::new(FsEventFlags::ITEM_RENAMED.bits() | extra);
      assert!(word.is_pure_rename(), "{word:?}");
    }
  }

  #[test]
  fn any_extra_operation_makes_a_rename_impure() {
    for extra in [
      FsEventFlags::ITEM_CREATED.bits(),
      FsEventFlags::ITEM_REMOVED.bits(),
      FsEventFlags::ITEM_MODIFIED.bits(),
      FsEventFlags::ITEM_INODE_META_MOD.bits(),
      FsEventFlags::ITEM_XATTR_MOD.bits(),
      FsEventFlags::ITEM_CHANGE_OWNER.bits(),
      FsEventFlags::ITEM_FINDER_INFO_MOD.bits(),
      FsEventFlags::ITEM_CLONED.bits(),
      FsEventFlags::OWN_EVENT.bits(),
      FsEventFlags::MUST_SCAN_SUBDIRS.bits(),
      FsEventFlags::ROOT_CHANGED.bits(),
    ] {
      let word = FsEventFlags::new(FsEventFlags::ITEM_RENAMED.bits() | extra);
      assert!(!word.is_pure_rename(), "{word:?}");
    }
    assert!(
      !FsEventFlags::ITEM_MODIFIED.is_pure_rename(),
      "a non-rename word is never a pure rename"
    );
  }
}
