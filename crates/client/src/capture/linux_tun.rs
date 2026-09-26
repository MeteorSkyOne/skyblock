//! Linux TUN backend, used by the netns testbed: destinations in `routes`
//! go through the TUN device, whose address is the VIP, and so does the
//! node's DNS resolver address.

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use skyblock_sys::cmd;
use skyblock_sys::tun::Tun;
use tracing::{debug, error, info};

use super::{Capture, Sink};

pub struct TunCapture {
    tun: Tun,
}

impl TunCapture {
    pub fn open(
        name: &str,
        vip: Ipv4Addr,
        mtu: u16,
        routes: &[Ipv4Net],
        resolver: Ipv4Addr,
    ) -> Result<Self> {
        let tun = Tun::open(name, false).context("creating TUN device (are you root?)")?;
        tun.configure(vip, 32, mtu)?;
        let resolver = Ipv4Net::from(resolver);
        for r in routes.iter().chain([&resolver]) {
            cmd::run(
                "ip",
                &["route", "replace", &r.to_string(), "dev", tun.name()],
            )?;
        }
        info!(dev = tun.name(), %vip, ?routes, %resolver, "TUN capture ready");
        Ok(Self { tun })
    }
}

impl Capture for TunCapture {
    fn start(self: Arc<Self>, sink: Sink) -> Result<()> {
        std::thread::Builder::new()
            .name("tun-rx".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65536];
                loop {
                    match self.tun.recv(&mut buf) {
                        Ok(n) => sink(&mut buf[..n]),
                        Err(e) => {
                            error!("tun read: {e}");
                            return;
                        }
                    }
                }
            })?;
        Ok(())
    }

    fn inject(&self, pkt: &mut [u8]) {
        if let Err(e) = self.tun.send(pkt) {
            debug!("tun write: {e}");
        }
    }
}
