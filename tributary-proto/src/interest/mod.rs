//! The per-watch subscription mask.

/// What kinds of change a watch subscribes to.
///
/// The core hands an `Interest` to the driver in an
/// [`Action::Watch`](crate::Action::Watch); the driver lowers it to the
/// backend's native flags (`IN_*` for inotify, `FAN_*` for fanotify, the
/// FSEvents stream flags). A field set to `false` means "do not subscribe", but
/// note that some backends cannot mask individual kinds — the driver may deliver
/// a superset, which the core's delivery filter then narrows.
///
/// # Configuration faces
///
/// With the `serde` feature the mask is a plain object of its own field names,
/// every key optional and defaulted from [`Interest::new`] (the EMPTY mask), so a
/// document names only what it subscribes to. Unknown keys are ignored — a
/// document written for a later version still loads.
///
/// ```json
/// { "created": true, "removed": true, "moved": true }
/// ```
///
/// It is deliberately NOT a list of kind names: [`ondir`](Self::ondir) is a
/// target-class modifier rather than an event subscription (see
/// [`is_empty`](Self::is_empty)), so a flat set of names would misrepresent it as a
/// kind.
///
/// With the `clap` feature it is a `clap::Args` group of one `--<field>` flag per
/// bit. Every bit defaults to `false`, so a bare flag SETS it and the flagless
/// command line is [`Interest::new`]:
///
/// ```text
/// $ app --created --removed --moved
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct Interest {
  #[cfg_attr(feature = "clap", arg(long))]
  created: bool,
  #[cfg_attr(feature = "clap", arg(long))]
  removed: bool,
  #[cfg_attr(feature = "clap", arg(long))]
  modified: bool,
  #[cfg_attr(feature = "clap", arg(long))]
  moved: bool,
  #[cfg_attr(feature = "clap", arg(long))]
  attrib: bool,
  #[cfg_attr(feature = "clap", arg(long))]
  ondir: bool,
}

impl Interest {
  /// An empty interest: subscribed to nothing.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new() -> Self {
    Self {
      created: false,
      removed: false,
      modified: false,
      moved: false,
      attrib: false,
      ondir: false,
    }
  }

  /// An interest subscribed to every change kind, including directory targets.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn all() -> Self {
    Self {
      created: true,
      removed: true,
      modified: true,
      moved: true,
      attrib: true,
      ondir: true,
    }
  }

  /// Whether create events are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn created(&self) -> bool {
    self.created
  }

  /// Whether remove events are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn removed(&self) -> bool {
    self.removed
  }

  /// Whether modify (content / data) events are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn modified(&self) -> bool {
    self.modified
  }

  /// Whether move / rename events are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn moved(&self) -> bool {
    self.moved
  }

  /// Whether attribute / metadata events are wanted.
  ///
  /// Maps to inotify `IN_ATTRIB`; without it chmod / chown / utime / xattr /
  /// link-count changes are silently dropped.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn attrib(&self) -> bool {
    self.attrib
  }

  /// Whether events whose target is a directory are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn ondir(&self) -> bool {
    self.ondir
  }

  /// Whether this interest subscribes to no events.
  ///
  /// [`ondir`](Self::ondir) is deliberately excluded: it is a target-class
  /// modifier (directory-vs-file routing), not an event subscription, so an
  /// interest with only `ondir` set still subscribes to nothing and is empty.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_empty(&self) -> bool {
    !(self.created || self.removed || self.modified || self.moved || self.attrib)
  }
}

macro_rules! interest_flag {
  ($field:ident, $set:ident, $with:ident, $update:ident, $maybe:ident, $clear:ident) => {
    #[doc = concat!("Subscribes to `", stringify!($field), "` events (sets it true).")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $set(&mut self) -> &mut Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Returns this interest subscribed to `", stringify!($field), "` events.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[must_use]
    pub const fn $with(mut self) -> Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Sets the `", stringify!($field), "` subscription to `value`.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $update(&mut self, value: bool) -> &mut Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Returns this interest with the `", stringify!($field), "` subscription set to `value`.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[must_use]
    pub const fn $maybe(mut self, value: bool) -> Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Clears the `", stringify!($field), "` subscription (sets it false).")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $clear(&mut self) -> &mut Self {
      self.$field = false;
      self
    }
  };
}

impl Interest {
  interest_flag!(
    created,
    set_created,
    with_created,
    update_created,
    maybe_created,
    clear_created
  );
  interest_flag!(
    removed,
    set_removed,
    with_removed,
    update_removed,
    maybe_removed,
    clear_removed
  );
  interest_flag!(
    modified,
    set_modified,
    with_modified,
    update_modified,
    maybe_modified,
    clear_modified
  );
  interest_flag!(
    moved,
    set_moved,
    with_moved,
    update_moved,
    maybe_moved,
    clear_moved
  );
  interest_flag!(
    attrib,
    set_attrib,
    with_attrib,
    update_attrib,
    maybe_attrib,
    clear_attrib
  );
  interest_flag!(
    ondir,
    set_ondir,
    with_ondir,
    update_ondir,
    maybe_ondir,
    clear_ondir
  );
}

impl Default for Interest {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests;
