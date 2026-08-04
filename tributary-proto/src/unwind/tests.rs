use super::*;

/// A legal [`panic_any`](std::panic::panic_any) payload whose own disposal unwinds.
struct PanicsOnDrop;

impl Drop for PanicsOnDrop {
  fn drop(&mut self) {
    panic!("a payload whose destructor unwinds");
  }
}

/// A payload that panics as it is dropped, carrying ANOTHER such payload — so a disposal that
/// answered a recursive `Drop` by recursing would never bottom out.
struct PanicsOnDropWithPayload;

impl Drop for PanicsOnDropWithPayload {
  fn drop(&mut self) {
    std::panic::panic_any(PanicsOnDropWithPayload);
  }
}

/// An ordinary payload disposes normally and leaks nothing.
#[test]
fn an_ordinary_payload_is_dropped() {
  let payload = std::panic::catch_unwind(|| panic!("an ordinary message payload"))
    .expect_err("the body unwound");
  assert_eq!(dispose_panic_payload(payload), PayloadDisposal::Dropped);
}

/// The whole point: disposal is TOTAL. Reaching the assertion at all is the proof — a
/// destructor that unwinds is caught here rather than propagated into the caller's frame,
/// which at the real call sites is an FFI callback, a destructor already unwinding, or a
/// worker loop whose thread is still counted.
///
/// FAIL-ON-REVERT: `drop(payload)` in place of the contained disposal and this cell unwinds
/// at the call, never reaching an assertion.
///
/// not(miri): [`Forgotten`](PayloadDisposal::Forgotten) IS a leak — the documented price of
/// cutting the recursion with an operation that runs no destructor — and the second panic
/// here carries a heap payload, so Miri's whole-process leak check reports it. The check
/// has no way to say "this allocation is deliberately unreachable", and silencing it for
/// the shard would hide every unintended leak beside it. The disposal path itself stays
/// under Miri through the recursive cell below, whose payload is a ZST and so leaks nothing.
#[test]
#[cfg_attr(miri, ignore = "asserts a deliberate leak Miri cannot whitelist")]
fn a_payload_whose_drop_panics_is_forgotten_rather_than_propagated() {
  let payload =
    std::panic::catch_unwind(|| std::panic::panic_any(PanicsOnDrop)).expect_err("the body unwound");
  assert_eq!(dispose_panic_payload(payload), PayloadDisposal::Forgotten);
}

/// Depth is not a defence, so the disposal does not rely on one. This payload's destructor
/// panics with another payload of the same type, so every level of a
/// contain-and-recurse disposal would find one more — only an operation that runs NO
/// destructor terminates it.
///
/// FAIL-ON-REVERT: replace the `forget` with a recursive `dispose_panic_payload(second)` and
/// this cell recurses until the stack is gone.
#[test]
fn an_endlessly_recursive_payload_still_terminates_at_depth_one() {
  let payload = std::panic::catch_unwind(|| std::panic::panic_any(PanicsOnDropWithPayload))
    .expect_err("the body unwound");
  assert_eq!(dispose_panic_payload(payload), PayloadDisposal::Forgotten);
}

/// [`contain`] is the same boundary reduced to the bit a call site acts on: a returned value,
/// or a report that the body unwound and its payload has already been retired.
///
/// not(miri): reaches [`Forgotten`](PayloadDisposal::Forgotten) over a heap payload, which is
/// the deliberate leak Miri's whole-process check reports — see the cell above.
#[test]
#[cfg_attr(miri, ignore = "asserts a deliberate leak Miri cannot whitelist")]
fn contain_reports_both_outcomes_without_unwinding() {
  assert_eq!(contain(|| 7), Ok(7));
  assert_eq!(
    contain(|| -> i32 { std::panic::panic_any(PanicsOnDrop) }),
    Err(PayloadDisposal::Forgotten)
  );
  assert_eq!(
    contain(|| -> i32 { panic!("an ordinary message payload") }),
    Err(PayloadDisposal::Dropped)
  );
}
