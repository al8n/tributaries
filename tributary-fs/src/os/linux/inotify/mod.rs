//! The inotify backend's pure half: wire decode and `wd` attribution.
//!
//! Everything here runs on every host and under miri — the fd, the reader
//! thread, and the syscalls arrive with the Source layer, which consumes
//! these tables.

pub(crate) mod decode;
pub(crate) mod table;

#[cfg(test)]
mod tests;
