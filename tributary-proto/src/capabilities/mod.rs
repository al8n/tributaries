//! Static, source-wide capabilities of a backend.

/// The static capability profile of a notification backend.
///
/// These are **source-wide and constant** for the lifetime of a source — they
/// describe what the backend can do, not its current runtime health (per-scope
/// degradation, e.g. an `ENOSPC` fallback to polling, is tracked elsewhere as
/// runtime state, never by flipping a capability). The most load-bearing flag is
/// [`kernel_recursive`](Self::kernel_recursive): it selects whether the core
/// descends per-directory (inotify, fanotify-inode) or leans on one
/// kernel-recursive watch per root (fanotify-FILESYSTEM, FSEvents, RDCW).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capabilities {
  supports_push: bool,
  atomic_create: bool,
  native_move: bool,
  versioned: bool,
  needs_poll: bool,
  kernel_recursive: bool,
  lossy_watch_teardown: bool,
}

impl Capabilities {
  /// A profile with every capability cleared.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new() -> Self {
    Self {
      supports_push: false,
      atomic_create: false,
      native_move: false,
      versioned: false,
      needs_poll: false,
      kernel_recursive: false,
      lossy_watch_teardown: false,
    }
  }

  /// Whether the backend pushes change notifications (vs. requiring polling).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn supports_push(&self) -> bool {
    self.supports_push
  }

  /// Whether a newly-created object is observed atomically (create is not split
  /// into a partial-then-final sequence the core must reconcile).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn atomic_create(&self) -> bool {
    self.atomic_create
  }

  /// Whether the backend reports renames as first-class move events rather than
  /// an unpaired remove + create.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn native_move(&self) -> bool {
    self.native_move
  }

  /// Whether the backend exposes object versions / generations.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn versioned(&self) -> bool {
    self.versioned
  }

  /// Whether the backend fundamentally needs polling to observe changes.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn needs_poll(&self) -> bool {
    self.needs_poll
  }

  /// Whether one watch per root observes the whole subtree (the kernel handles
  /// recursion), so the core does **not** descend per-directory.
  ///
  /// `true` for fanotify-FILESYSTEM, FSEvents, and RDCW; `false` for inotify and
  /// fanotify-inode, where the core installs a watch per directory and
  /// enumerates to descend.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn kernel_recursive(&self) -> bool {
    self.kernel_recursive
  }

  /// Whether a kernel watch's terminal record can be dropped together with the
  /// notification queue, so a queue loss may leave the backend's per-watch
  /// bindings dead with no record of their death.
  ///
  /// On such a backend (inotify: an unmount's `IN_IGNORED`s ride the same
  /// queue an `IN_Q_OVERFLOW` empties) a retained watch that survives a loss
  /// recovery by identity match may be kernel-dead, so a loss-triggered re-arm
  /// must re-prove every retained binding by an acknowledged re-add rather
  /// than keep it on the identity evidence alone. `false` for backends whose
  /// watch teardown is signalled out of band of the losable queue
  /// (kernel-recursive streams die loudly as a whole).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn lossy_watch_teardown(&self) -> bool {
    self.lossy_watch_teardown
  }
}

macro_rules! capability_flag {
  ($field:ident, $set:ident, $with:ident, $update:ident, $maybe:ident, $clear:ident) => {
    #[doc = concat!("Sets the `", stringify!($field), "` capability true.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $set(&mut self) -> &mut Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Returns this profile with the `", stringify!($field), "` capability set.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[must_use]
    pub const fn $with(mut self) -> Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Sets the `", stringify!($field), "` capability to `value`.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $update(&mut self, value: bool) -> &mut Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Returns this profile with the `", stringify!($field), "` capability set to `value`.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[must_use]
    pub const fn $maybe(mut self, value: bool) -> Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Clears the `", stringify!($field), "` capability (sets it false).")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $clear(&mut self) -> &mut Self {
      self.$field = false;
      self
    }
  };
}

impl Capabilities {
  capability_flag!(
    supports_push,
    set_supports_push,
    with_supports_push,
    update_supports_push,
    maybe_supports_push,
    clear_supports_push
  );
  capability_flag!(
    atomic_create,
    set_atomic_create,
    with_atomic_create,
    update_atomic_create,
    maybe_atomic_create,
    clear_atomic_create
  );
  capability_flag!(
    native_move,
    set_native_move,
    with_native_move,
    update_native_move,
    maybe_native_move,
    clear_native_move
  );
  capability_flag!(
    versioned,
    set_versioned,
    with_versioned,
    update_versioned,
    maybe_versioned,
    clear_versioned
  );
  capability_flag!(
    needs_poll,
    set_needs_poll,
    with_needs_poll,
    update_needs_poll,
    maybe_needs_poll,
    clear_needs_poll
  );
  capability_flag!(
    kernel_recursive,
    set_kernel_recursive,
    with_kernel_recursive,
    update_kernel_recursive,
    maybe_kernel_recursive,
    clear_kernel_recursive
  );
  capability_flag!(
    lossy_watch_teardown,
    set_lossy_watch_teardown,
    with_lossy_watch_teardown,
    update_lossy_watch_teardown,
    maybe_lossy_watch_teardown,
    clear_lossy_watch_teardown
  );
}

impl Default for Capabilities {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests;
