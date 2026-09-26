//! Packet capture backends. A backend hands outbound
//! packets that belong in the tunnel to a sink, already addressed from the
//! VIP, and injects packets coming back from the tunnel.

#[cfg(target_os = "linux")]
pub mod linux_tun;
#[cfg(windows)]
pub mod windivert;
#[cfg(windows)]
pub mod wintun;

use std::sync::Arc;

use anyhow::Result;

/// Receives outbound IP packets for the tunnel. May be called from several
/// backend threads.
pub type Sink = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

pub trait Capture: Send + Sync {
    /// Starts the backend's capture threads.
    fn start(self: Arc<Self>, sink: Sink) -> Result<()>;
    /// Injects an inner packet received from the node (addressed to the
    /// VIP); the backend may rewrite it in place.
    fn inject(&self, pkt: &mut [u8]);
    /// Undoes system changes (routes) before the process exits.
    fn stop(&self) {}
}
