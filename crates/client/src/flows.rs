//! Address rewriting for packets captured on the host (SPEC §6.4). The
//! game's packets leave with its LAN address as the source; the tunnel
//! carries them with the VIP instead and restores the LAN address on the
//! way back, keyed by `(protocol, local port)`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use skyblock_proto::ip::{Ipv4Packet, PROTO_TCP, PROTO_UDP};

#[derive(Clone, Copy)]
struct Flow<I> {
    lan_ip: Ipv4Addr,
    iface: I,
}

/// `I` is whatever the capture backend needs to re-inject on the right
/// interface (WinDivert: interface and sub-interface index).
pub struct FlowTable<I> {
    vip: Ipv4Addr,
    mss: u16,
    flows: Mutex<HashMap<(u8, u16), Flow<I>>>,
}

impl<I: Copy> FlowTable<I> {
    pub fn new(vip: Ipv4Addr, mtu: u16) -> Self {
        Self {
            vip,
            mss: mtu - 40,
            flows: Mutex::new(HashMap::new()),
        }
    }

    /// Prepares a captured outbound packet for the tunnel: source → VIP,
    /// MSS clamp, fresh checksums (the originals may be left to NIC
    /// offload). Returns `false` for anything but first-fragment TCP/UDP.
    pub fn outbound(&self, pkt: &mut [u8], iface: I) -> bool {
        let Ok(mut p) = Ipv4Packet::parse(pkt) else {
            return false;
        };
        let proto = p.protocol();
        let Some((sport, _)) = p.ports().filter(|_| matches!(proto, PROTO_TCP | PROTO_UDP)) else {
            return false;
        };
        let lan_ip = p.src();
        self.flows
            .lock()
            .expect("flow table lock")
            .insert((proto, sport), Flow { lan_ip, iface });
        p.set_src(self.vip);
        p.clamp_mss(self.mss);
        p.recompute_checksums();
        true
    }

    /// Restores an inbound packet from the tunnel: destination VIP → LAN
    /// address, MSS clamp. Returns the interface to inject on, or `None` if
    /// the packet belongs to no known flow.
    pub fn inbound(&self, pkt: &mut [u8]) -> Option<I> {
        let mut p = Ipv4Packet::parse(pkt).ok()?;
        if p.dst() != self.vip {
            return None;
        }
        let (_, dport) = p.ports()?;
        let flow = *self
            .flows
            .lock()
            .expect("flow table lock")
            .get(&(p.protocol(), dport))?;
        p.set_dst(flow.lan_ip);
        p.clamp_mss(self.mss);
        Some(flow.iface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::ip::{build_udp, checksum_valid, transport_checksum_valid};
    use std::net::SocketAddrV4;

    const LAN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 23);
    const VIP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const GAME: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    fn udp(src: SocketAddrV4, dst: SocketAddrV4) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        let n = build_udp(&mut b, src, dst, 1, b"payload").unwrap();
        b.truncate(n);
        b
    }

    fn valid(p: &[u8]) -> bool {
        let pkt = Ipv4Packet::parse(p).unwrap();
        checksum_valid(&p[..20])
            && transport_checksum_valid(pkt.src(), pkt.dst(), pkt.protocol(), pkt.payload())
    }

    #[test]
    fn roundtrip_restores_lan_address() {
        let t = FlowTable::new(VIP, 1400);
        let mut out = udp(SocketAddrV4::new(LAN, 5000), SocketAddrV4::new(GAME, 27015));
        out[26..28].copy_from_slice(&[0xde, 0xad]); // offloaded checksum
        assert!(t.outbound(&mut out, 7u32));
        let p = Ipv4Packet::parse(&out[..]).unwrap();
        assert_eq!(p.src(), VIP);
        assert!(valid(&out));

        let mut back = udp(SocketAddrV4::new(GAME, 27015), SocketAddrV4::new(VIP, 5000));
        assert_eq!(t.inbound(&mut back), Some(7));
        assert_eq!(Ipv4Packet::parse(&back[..]).unwrap().dst(), LAN);
        assert!(valid(&back));
    }

    #[test]
    fn unknown_flow_or_wrong_destination() {
        let t = FlowTable::<u32>::new(VIP, 1400);
        let mut back = udp(SocketAddrV4::new(GAME, 27015), SocketAddrV4::new(VIP, 5000));
        assert_eq!(t.inbound(&mut back), None);

        let mut out = udp(SocketAddrV4::new(LAN, 5000), SocketAddrV4::new(GAME, 27015));
        t.outbound(&mut out, 1);
        let mut other = udp(SocketAddrV4::new(GAME, 27015), SocketAddrV4::new(LAN, 5000));
        assert_eq!(t.inbound(&mut other), None, "not addressed to the VIP");
    }

    #[test]
    fn non_transport_is_refused() {
        let t = FlowTable::<u32>::new(VIP, 1400);
        let mut p = udp(SocketAddrV4::new(LAN, 5000), SocketAddrV4::new(GAME, 27015));
        p[9] = 1; // ICMP
        assert!(!t.outbound(&mut p, 1));
    }
}
