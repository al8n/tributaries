//! The per-primitive sub-machine seam.

use crate::capabilities::Capabilities;

/// A per-primitive sub-machine: the thin, pure backend-specific half beneath the
/// primitive-agnostic [`Monitor`](crate::Monitor).
///
/// The [`Monitor`](crate::Monitor) owns the engine that the design says must be
/// written once — the watch tree, recursion, dedup, move normalization, overflow
/// handling. A `PrimitiveMachine` supplies only what genuinely differs between
/// backends: the static [`Capabilities`] (above all
/// [`kernel_recursive`](Capabilities::kernel_recursive), which selects the
/// recursion strategy) and the identity quirks of one primitive.
///
/// The kernel-recursive split is the load-bearing distinction:
///
/// - **`kernel_recursive == false`** (inotify, fanotify-inode): one watch per
///   directory; the core descends, installing a child watch and enumerating each
///   new directory.
/// - **`kernel_recursive == true`** (fanotify-FILESYSTEM, FSEvents, RDCW): one
///   watch per root observes the whole subtree; the core does not descend.
///
/// # Stability
///
/// This is the foundation contract. The concrete sub-machines
/// ([`inotify`](crate::inotify), [`fanotify`](crate::fanotify),
/// [`fsevents`](crate::fsevents)) will extend it with the per-primitive identity
/// hooks the core consults — inode aliasing (`wd → Set<anchor>`), `wd`-reuse /
/// ABA detection, and the backend's move-cookie format. Those hooks are added
/// alongside each concrete implementation; the stable part today is the
/// capability profile and the derived recursion strategy.
pub trait PrimitiveMachine {
  /// The backend's static, source-wide capability profile.
  fn capabilities(&self) -> Capabilities;

  /// Whether the core should descend per-directory for this backend.
  ///
  /// Defaults to the inverse of
  /// [`kernel_recursive`](Capabilities::kernel_recursive): a kernel-recursive
  /// backend needs no descent, while a per-directory backend does. A sub-machine
  /// only overrides this if its descent strategy diverges from what the
  /// capability flag implies.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn descends(&self) -> bool {
    !self.capabilities().kernel_recursive()
  }
}

#[cfg(test)]
mod tests;
