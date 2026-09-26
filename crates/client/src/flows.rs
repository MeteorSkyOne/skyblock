//! Address rewriting for packets captured on the host (SPEC §6.4). The
//! game's packets leave with its LAN address as the source; the tunnel
//! carries them with the VIP instead and restores the LAN address on the
//! way back, keyed by `(protocol, local port)`. IP fragments after the
//! first carry no ports: outbound they only need the new source address;
//! inbound they follow the first fragment of their datagram.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use skyblock_proto::ip::{Ipv4Packet, PROTO_TCP, PROTO_UDP};

/// Inbound fragment groups are forgotten after this long.
const FRAG_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
struct Flow<I> {
    lan_ip: Ipv4Addr,
    iface: I,
}

struct State<I> {
    flows: HashMap<(u8, u16), Flow<I>>,
    /// `(protocol, source, identification)` of inbound datagrams whose
    /// first fragment was seen.
    frags: HashMap<(u8, Ipv4Addr, u16), (Flow<I>, Instant)>,
}

/// `I` is whatever the capture backend needs to re-inject on the right
/// interface (WinDivert: interface and sub-interface index).
pub struct FlowTable<I> {
    vip: Ipv4Addr,
    mss: u16,
    state: Mutex<State<I>>,
}

impl<I: Copy> FlowTable<I> {
    pub fn new(vip: Ipv4Addr, mtu: u16) -> Self {
        Self {
            vip,
            mss: mtu - 40,
            state: Mutex::new(State {
                flows: HashMap::new(),
                frags: HashMap::new(),
            }),
        }
    }

    /// Prepares a captured outbound packet for the tunnel: source → VIP,
    /// MSS clamp, fresh checksums (the originals may be left to NIC
    /// offload). Returns `false` for anything but TCP/UDP.
    pub fn outbound(&self, pkt: &mut [u8], iface: I) -> bool {
        let Ok(mut p) = Ipv4Packet::parse(pkt) else {
            return false;
        };
        let proto = p.protocol();
        if !matches!(proto, PROTO_TCP | PROTO_UDP) {
            return false;
        }
        match p.ports() {
            Some((sport, _)) => {
                let lan_ip = p.src();
                self.state
                    .lock()
                    .expect("flow table lock")
                    .flows
                    .insert((proto, sport), Flow { lan_ip, iface });
            }
            // A later fragment: its first one registered the flow.
            None if p.frag_offset() > 0 => {}
            None => return false,
        }
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
        let frag_key = (p.protocol(), p.src(), p.ident());
        let flow = {
            let mut st = self.state.lock().expect("flow table lock");
            match p.ports() {
                Some((_, dport)) => {
                    let flow = *st.flows.get(&(p.protocol(), dport))?;
                    if p.more_fragments() {
                        if st.frags.len() >= 64 {
                            st.frags.retain(|_, (_, at)| at.elapsed() < FRAG_TTL);
                        }
                        st.frags.insert(frag_key, (flow, Instant::now()));
                    }
                    flow
                }
                None if p.frag_offset() > 0 => st.frags.get(&frag_key)?.0,
                None => return None,
            }
        };
        p.set_dst(flow.lan_ip);
        p.clamp_mss(self.mss);
        Some(flow.iface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::ip::{build_udp, checksum_valid, transport_checksum_valid};
    use skyblock_proto::ipfrag::fragment;
    use std::net::SocketAddrV4;

    const LAN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 23);
    const VIP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const GAME: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    fn udp(src: SocketAddrV4, dst: SocketAddrV4) -> Vec<u8> {
        udp_len(src, dst, 7)
    }

    fn udp_len(src: SocketAddrV4, dst: SocketAddrV4, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len + 28];
        let n = build_udp(&mut b, src, dst, 1, &vec![0x61; len]).unwrap();
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

    #[test]
    fn fragments_both_ways() {
        let t = FlowTable::new(VIP, 1400);
        // A 3000-byte datagram the host fragmented at MTU 1500.
        let big = udp_len(
            SocketAddrV4::new(LAN, 5000),
            SocketAddrV4::new(GAME, 27015),
            3000,
        );
        let frags = fragment(&big, 1500).unwrap();
        let mut rewritten = vec![];
        for f in &frags {
            let mut f = f.clone();
            assert!(t.outbound(&mut f, 3u32));
            let p = Ipv4Packet::parse(&f[..]).unwrap();
            assert_eq!(p.src(), VIP);
            assert!(checksum_valid(&f[..20]));
            rewritten.push(f);
        }
        // Reassembled, the datagram checks out under the VIP.
        let mut r = skyblock_proto::ipfrag::Ipv4Reassembler::new(1);
        let whole = rewritten
            .iter()
            .find_map(|f| r.push(0, f).unwrap().map(<[u8]>::to_vec))
            .unwrap();
        assert!(valid(&whole));

        // Inbound: later fragments follow the first one.
        let back = udp_len(
            SocketAddrV4::new(GAME, 27015),
            SocketAddrV4::new(VIP, 5000),
            3000,
        );
        let frags = fragment(&back, 1400).unwrap();
        let mut late = frags[2].clone();
        assert_eq!(t.inbound(&mut late), None, "before its first fragment");
        for f in &frags {
            let mut f = f.clone();
            assert_eq!(t.inbound(&mut f), Some(3));
            assert_eq!(Ipv4Packet::parse(&f[..]).unwrap().dst(), LAN);
            assert!(checksum_valid(&f[..20]));
        }
    }
}
