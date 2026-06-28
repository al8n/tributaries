//! Canonical path segments and reconstructed locations.
//!
//! Path identity is settled at the **driver** boundary: each segment is
//! canonicalized for its volume's case semantics (case-fold + Unicode NFC)
//! before it ever reaches the core, so the pure core compares already-canonical
//! [`Segment`]s with plain equality and never has to know a volume's
//! case-sensitivity. A [`Location`] is the sequence of canonical segments from a
//! watched root down to a target — the core reconstructs it by walking the
//! parent-relative watch tree to a root.

use core::{borrow::Borrow, cmp::Ordering};
use std::{string::String, vec::Vec};

/// One canonical path component (a single name between separators).
///
/// Already case-folded and Unicode-normalized by the driver for its volume, so
/// the core compares segments by plain byte equality. Segments are never empty
/// and never contain a path separator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Segment(String);

impl Segment {
  /// Builds a segment from an already-canonical component.
  ///
  /// The caller (the driver) is responsible for canonicalization; this type
  /// performs none.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(name: impl Into<String>) -> Self {
    Self(name.into())
  }

  /// The canonical component as a string slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }

  /// Whether the component is empty (it never should be; useful in assertions).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl From<&str> for Segment {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn from(value: &str) -> Self {
    Self::new(value)
  }
}

impl From<String> for Segment {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn from(value: String) -> Self {
    Self(value)
  }
}

impl Borrow<str> for Segment {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn borrow(&self) -> &str {
    self.0.as_str()
  }
}

impl AsRef<str> for Segment {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn as_ref(&self) -> &str {
    self.0.as_str()
  }
}

impl core::fmt::Display for Segment {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.0.as_str())
  }
}

/// A canonical location: the sequence of [`Segment`]s from a watched root to a
/// target.
///
/// An empty location denotes the watched root itself. The core reconstructs a
/// location by walking the parent-relative watch tree, so a location is always
/// rooted at a disjoint scope root rather than at the filesystem root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Location(Vec<Segment>);

impl Location {
  /// An empty location (the watched root itself).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new() -> Self {
    Self(Vec::new())
  }

  /// Builds a location from a sequence of canonical segments.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn from_segments(segments: impl IntoIterator<Item = Segment>) -> Self {
    Self(segments.into_iter().collect())
  }

  /// The segments as a slice, root-first.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn segments(&self) -> &[Segment] {
    self.0.as_slice()
  }

  /// The number of segments (the depth below the watched root).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn len(&self) -> usize {
    self.0.len()
  }

  /// Whether this is the watched root itself (no segments).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  /// The final segment (the target's own name), or `None` for the root.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn name(&self) -> Option<&Segment> {
    self.0.last()
  }

  /// Appends a child segment, descending one level.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn push(&mut self, segment: Segment) {
    self.0.push(segment);
  }

  /// Returns this location with `segment` appended (builder form).
  #[cfg_attr(not(tarpaulin), inline)]
  #[must_use]
  pub fn child(mut self, segment: Segment) -> Self {
    self.0.push(segment);
    self
  }
}

impl Default for Location {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn default() -> Self {
    Self::new()
  }
}

impl FromIterator<Segment> for Location {
  #[cfg_attr(not(tarpaulin), inline)]
  fn from_iter<T: IntoIterator<Item = Segment>>(iter: T) -> Self {
    Self(iter.into_iter().collect())
  }
}

impl PartialOrd for Location {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for Location {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn cmp(&self, other: &Self) -> Ordering {
    self.0.cmp(&other.0)
  }
}

#[cfg(test)]
mod tests;
