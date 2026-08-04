//! Retiring a **caught panic payload** without ever letting it start a second unwind.
//!
//! Everything in this crate's consumers that runs foreign code — a caller's filter predicate, a
//! caller's [`Source`] method, a backend's `shutdown`, an FFI callback the OS invokes — contains
//! that code's unwind with [`catch_unwind`](std::panic::catch_unwind). Catching is only half the
//! boundary. `catch_unwind` hands back the value the panic carried, and **disposing of that box
//! runs the value's own destructor**: a [`panic_any`](std::panic::panic_any) payload is any
//! `Send + 'static` value the panicking code chose, so its `Drop` is arbitrary foreign code too,
//! and the standard library warns explicitly that dropping a caught payload may itself panic.
//!
//! Dropped in ordinary control flow one line past the boundary, such a payload starts a **second**
//! unwind through the very frame the containment was protecting — an unwind nothing is guarding
//! any more. The consequences at the sites this crate's consumers care about are not equal but
//! they are all fatal to some invariant: a panic out of an `extern "C-unwind"` callback unwinds
//! into the OS framework that invoked it, a panic out of a destructor that is *itself* running
//! during an unwind aborts the process, and a panic out of a worker loop kills a thread that some
//! counter still believes exists.
//!
//! [`Source`]: https://docs.rs/tributaries

use std::{any::Any, boxed::Box};

/// What became of a caught panic payload handed to [`dispose_panic_payload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadDisposal {
  /// The payload's destructor ran and returned: nothing leaked.
  ///
  /// The ordinary outcome. An ordinary panic carries a `&'static str` or a `String`, whose
  /// disposal is infallible.
  Dropped,
  /// The payload's destructor **panicked**, so the payload was forgotten rather than dropped.
  ///
  /// Its allocation and everything it owns are unreachable for the rest of the process. Callers
  /// that can be driven to this outcome repeatedly by foreign code must bound how many times they
  /// allow it — see the type-level note on [`dispose_panic_payload`].
  Forgotten,
}

impl PayloadDisposal {
  /// Whether the payload had to be forgotten because its own destructor unwound.
  #[inline]
  #[must_use]
  pub const fn is_forgotten(self) -> bool {
    matches!(self, Self::Forgotten)
  }
}

/// Retires `payload` — a payload caught by [`catch_unwind`](std::panic::catch_unwind) — and
/// reports how.
///
/// **This function cannot panic, at any payload nesting depth.** It performs exactly two
/// operations. The payload's `Drop` runs inside its own containment boundary, so a destructor that
/// unwinds is caught rather than propagated; and the payload *that* unwind carries is
/// [`forget`](core::mem::forget)ten, which runs no destructor at all. There is therefore no depth
/// two: the recursion is cut by an operation that executes no foreign code, not by trusting an
/// adversarial `Drop` chain to bottom out. Contain-and-recurse would only move the same problem
/// one frame down while handing the adversary another turn.
///
/// # The cost, and who must bound it
///
/// [`Forgotten`](PayloadDisposal::Forgotten) leaks one payload. That is strictly better than the
/// alternatives at every call site — an escaped unwind loses a thread, a process, or memory the
/// kernel still owns — but it is unbounded if foreign code can be made to produce such a payload
/// over and over. **The bound belongs to the caller**, because only the caller knows what to
/// refuse: this function keeps no global state and imposes no policy, so a subsystem driven by
/// caller churn counts its own forgotten payloads and stops feeding this path (see the
/// per-subscription filter gate in `tributaries`, which enters no predicate again once its owner
/// has forgotten one), while a subsystem whose payloads can only come from a bug in this
/// workspace's own code simply records the outcome.
#[inline]
pub fn dispose_panic_payload(payload: Box<dyn Any + Send>) -> PayloadDisposal {
  match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(payload))) {
    Ok(()) => PayloadDisposal::Dropped,
    Err(second) => {
      core::mem::forget(second);
      PayloadDisposal::Forgotten
    }
  }
}

/// Runs `body` with its unwind contained, retiring any payload through
/// [`dispose_panic_payload`], and reports whether it unwound.
///
/// The shape every call site that has nothing to do with the payload itself wants: a boundary that
/// is total — it neither propagates the caught unwind nor lets the payload's disposal start a new
/// one — reduced to the one bit the site acts on.
#[inline]
pub fn contain<R>(body: impl FnOnce() -> R) -> Result<R, PayloadDisposal> {
  match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
    Ok(value) => Ok(value),
    Err(payload) => Err(dispose_panic_payload(payload)),
  }
}

#[cfg(test)]
mod tests;
