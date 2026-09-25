//! skyblock wire protocol: keys, packet sealing, frames, handshake, replay
//! and dedup windows, fragmentation, IPv4 rewriting. Pure logic, no I/O;
//! see SPEC.md §3.

pub mod dedup;
mod error;
pub mod frag;
pub mod frame;
pub mod handshake;
pub mod ip;
pub mod keys;
pub mod packet;
pub mod replay;
pub mod session;
pub mod timing;

pub use error::Error;

/// Monotonic time in microseconds, supplied by the caller.
pub type Micros = u64;
