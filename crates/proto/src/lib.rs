//! skyblock wire protocol: keys, packet sealing, frames, handshake, replay
//! and dedup windows, fragmentation, IPv4 rewriting. Pure logic, no I/O;
//! see SPEC.md §3.

pub mod dedup;
pub mod dns;
mod error;
pub mod flow;
pub mod frag;
pub mod frame;
pub mod handshake;
pub mod ip;
pub mod ipfrag;
pub mod keys;
pub mod packet;
pub mod path;
pub mod replay;
pub mod sched;
pub mod session;
pub mod timing;

pub use error::Error;

/// Monotonic time in microseconds, supplied by the caller.
pub type Micros = u64;
