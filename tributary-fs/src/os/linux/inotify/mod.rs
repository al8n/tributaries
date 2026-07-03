//! The inotify backend: pure wire decode and `wd` attribution (run on every
//! host and under miri), plus the reader thread that owns the per-root fd
//! (Linux, non-miri only).

pub(crate) mod decode;
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) mod reader;
pub(crate) mod table;

#[cfg(test)]
mod tests;
