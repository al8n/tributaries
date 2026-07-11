//! The `ReadDirectoryChangesW` source: the pure decode and rename-pairing
//! machinery now; the OVERLAPPED handle/pump layer follows behind the same
//! seam.

pub(crate) mod decode;
pub(crate) mod pairing;
