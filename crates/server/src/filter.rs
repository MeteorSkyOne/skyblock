//! Checks on inner packets sent by clients (SPEC §7.7): no spoofed sources,
//! no reaching private, link-local (cloud metadata) or multicast ranges, nor
//! the node itself except for UDP (which the NAT treats as hairpin).

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use skyblock_proto::ip::{Ipv4Packet, PROTO_ICMP, PROTO_TCP, PROTO_UDP};

const DEFAULT_DENY: [&str; 9] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Spoofed,
    Protocol,
    Destination,
}

pub struct InnerFilter {
    deny: Vec<Ipv4Net>,
    allow: Vec<Ipv4Net>,
    node_ip: Option<Ipv4Addr>,
}

impl InnerFilter {
    /// `subnet` (the VIP range) is always denied; `allow` punches holes in
    /// the deny list. `node_ip` is the node's own public address.
    pub fn new(subnet: Ipv4Net, allow: Vec<Ipv4Net>, node_ip: Option<Ipv4Addr>) -> Self {
        let mut deny: Vec<Ipv4Net> = DEFAULT_DENY
            .iter()
            .map(|s| s.parse().expect("valid default range"))
            .collect();
        deny.push(subnet);
        Self {
            deny,
            allow,
            node_ip,
        }
    }

    pub fn check<B: AsRef<[u8]>>(&self, vip: Ipv4Addr, pkt: &Ipv4Packet<B>) -> Result<(), Reject> {
        if pkt.src() != vip {
            return Err(Reject::Spoofed);
        }
        if !matches!(pkt.protocol(), PROTO_TCP | PROTO_UDP | PROTO_ICMP) {
            return Err(Reject::Protocol);
        }
        let dst = pkt.dst();
        if Some(dst) == self.node_ip && pkt.protocol() != PROTO_UDP {
            return Err(Reject::Destination);
        }
        if self.allow.iter().any(|n| n.contains(&dst)) {
            return Ok(());
        }
        if self.deny.iter().any(|n| n.contains(&dst)) {
            return Err(Reject::Destination);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::ip::build_udp;
    use std::net::SocketAddrV4;

    const VIP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const NODE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

    fn udp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        let n = build_udp(
            &mut b,
            SocketAddrV4::new(src, 1000),
            SocketAddrV4::new(dst, 2000),
            0,
            b"x",
        )
        .unwrap();
        b.truncate(n);
        b
    }

    fn filter() -> InnerFilter {
        InnerFilter::new("10.77.0.0/16".parse().unwrap(), vec![], Some(NODE))
    }

    fn check(f: &InnerFilter, src: Ipv4Addr, dst: Ipv4Addr) -> Result<(), Reject> {
        let p = udp(src, dst);
        f.check(VIP, &Ipv4Packet::parse(&p[..]).unwrap())
    }

    #[test]
    fn public_destination_allowed() {
        assert_eq!(check(&filter(), VIP, Ipv4Addr::new(203, 0, 113, 7)), Ok(()));
    }

    #[test]
    fn spoofed_source_rejected() {
        let other = Ipv4Addr::new(10, 77, 0, 3);
        assert_eq!(
            check(&filter(), other, Ipv4Addr::new(8, 8, 8, 8)),
            Err(Reject::Spoofed)
        );
    }

    #[test]
    fn private_and_metadata_rejected() {
        let f = filter();
        for dst in [
            "169.254.169.254",
            "127.0.0.1",
            "192.168.1.1",
            "10.77.0.3",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert_eq!(
                check(&f, VIP, dst.parse().unwrap()),
                Err(Reject::Destination),
                "{dst}"
            );
        }
    }

    #[test]
    fn allow_list_overrides() {
        let f = InnerFilter::new(
            "10.77.0.0/16".parse().unwrap(),
            vec!["192.168.50.0/24".parse().unwrap()],
            None,
        );
        assert_eq!(check(&f, VIP, "192.168.50.9".parse().unwrap()), Ok(()));
        assert_eq!(
            check(&f, VIP, "192.168.51.9".parse().unwrap()),
            Err(Reject::Destination)
        );
    }

    #[test]
    fn node_itself_only_over_udp() {
        let f = filter();
        assert_eq!(check(&f, VIP, NODE), Ok(()), "UDP: NAT hairpin");
        let mut p = udp(VIP, NODE);
        p[9] = PROTO_TCP;
        assert_eq!(
            f.check(VIP, &Ipv4Packet::parse(&p[..]).unwrap()),
            Err(Reject::Destination)
        );
    }

    #[test]
    fn other_protocols_rejected() {
        let mut p = udp(VIP, Ipv4Addr::new(8, 8, 8, 8));
        p[9] = 47; // GRE
        assert_eq!(
            filter().check(VIP, &Ipv4Packet::parse(&p[..]).unwrap()),
            Err(Reject::Protocol)
        );
    }
}
