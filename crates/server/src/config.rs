//! Server configuration.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use ipnet::Ipv4Net;
use serde::Deserialize;
use skyblock_proto::Micros;
use skyblock_proto::keys::{PrivateKey, Psk, PublicKey};
use skyblock_proto::timing::SECOND;

pub const DEFAULT_SUBNET: &str = "10.77.0.0/16";
pub const DEFAULT_MTU: u16 = 1400;
pub const DEFAULT_TUN: &str = "sb0";
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/skyblock-server.sock";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    private_key: String,
    #[serde(default = "default_listen_ip")]
    listen_ip: IpAddr,
    ports: Vec<u16>,
    egress: Option<String>,
    egress_ip: Option<Ipv4Addr>,
    #[serde(default = "default_subnet")]
    subnet: Ipv4Net,
    #[serde(default = "default_tun")]
    tun: String,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default = "default_nat_range")]
    nat_port_range: [u16; 2],
    #[serde(default = "default_nat_timeout")]
    udp_nat_timeout_s: u64,
    /// DNS servers the resolver VIP forwards to; empty = /etc/resolv.conf.
    #[serde(default)]
    dns_upstream: Vec<DnsServer>,
    #[serde(default = "default_control_socket")]
    control_socket: PathBuf,
    /// Extra destinations clients may reach despite the default deny list.
    #[serde(default)]
    allow_destinations: Vec<Ipv4Net>,
    /// Pin the process to this CPU.
    #[serde(default)]
    cpu: Option<usize>,
    /// Poll without sleeping: one core busy, lower wake-up latency.
    #[serde(default)]
    busy_poll: bool,
    #[serde(default)]
    user: Vec<RawUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUser {
    name: String,
    public_key: String,
    psk: Option<String>,
    vip: Ipv4Addr,
}

/// `"1.1.1.1"` or `"1.1.1.1:5353"`.
#[derive(Deserialize)]
#[serde(untagged)]
enum DnsServer {
    Addr(SocketAddr),
    Ip(IpAddr),
}

impl DnsServer {
    fn addr(&self) -> SocketAddr {
        match *self {
            DnsServer::Addr(a) => a,
            DnsServer::Ip(ip) => SocketAddr::new(ip, 53),
        }
    }
}

fn default_control_socket() -> PathBuf {
    PathBuf::from(DEFAULT_CONTROL_SOCKET)
}

fn default_listen_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

fn default_subnet() -> Ipv4Net {
    DEFAULT_SUBNET.parse().expect("valid default subnet")
}

fn default_tun() -> String {
    DEFAULT_TUN.to_owned()
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_nat_range() -> [u16; 2] {
    [20000, 60000]
}

fn default_nat_timeout() -> u64 {
    300
}

pub struct UserConfig {
    pub name: String,
    pub public_key: PublicKey,
    pub psk: Psk,
    pub vip: Ipv4Addr,
}

pub struct Config {
    pub private_key: PrivateKey,
    pub listen_ip: IpAddr,
    pub ports: Vec<u16>,
    pub egress: Option<String>,
    pub egress_ip: Option<Ipv4Addr>,
    pub subnet: Ipv4Net,
    pub tun: String,
    pub mtu: u16,
    pub nat_port_range: RangeInclusive<u16>,
    pub udp_nat_timeout: Micros,
    pub dns_upstream: Vec<SocketAddr>,
    /// Unix socket `skyblock-server status` talks to.
    pub control_socket: PathBuf,
    pub allow_destinations: Vec<Ipv4Net>,
    pub cpu: Option<usize>,
    pub busy_poll: bool,
    pub users: Vec<UserConfig>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config> {
        let raw: RawConfig = toml::from_str(text)?;
        ensure!(!raw.ports.is_empty(), "`ports` must list at least one port");
        ensure!(
            (576..=1432).contains(&raw.mtu),
            "`mtu` must be within 576..=1432"
        );
        let [lo, hi] = raw.nat_port_range;
        ensure!(lo >= 1024 && lo <= hi, "bad `nat_port_range`");
        let dns_upstream: Vec<SocketAddr> = raw.dns_upstream.iter().map(DnsServer::addr).collect();
        ensure!(
            dns_upstream.iter().all(SocketAddr::is_ipv4),
            "`dns_upstream` must be IPv4 addresses"
        );

        let subnet = raw.subnet.trunc();
        let gateway = gateway_addr(subnet);
        let mut users = Vec::with_capacity(raw.user.len());
        let (mut names, mut keys, mut vips) = (HashSet::new(), HashSet::new(), HashSet::new());
        for u in raw.user {
            let public_key: PublicKey = u
                .public_key
                .parse()
                .with_context(|| format!("user {}: bad public_key", u.name))?;
            let psk = match u.psk {
                Some(s) => s
                    .parse()
                    .with_context(|| format!("user {}: bad psk", u.name))?,
                None => Psk::ZERO,
            };
            ensure!(
                subnet.contains(&u.vip)
                    && u.vip != subnet.network()
                    && u.vip != subnet.broadcast()
                    && u.vip != gateway,
                "user {}: vip {} is not a usable address in {subnet}",
                u.name,
                u.vip
            );
            if !names.insert(u.name.clone()) {
                bail!("duplicate user name {}", u.name);
            }
            if !keys.insert(public_key) {
                bail!("user {}: duplicate public_key", u.name);
            }
            if !vips.insert(u.vip) {
                bail!("user {}: duplicate vip {}", u.name, u.vip);
            }
            users.push(UserConfig {
                name: u.name,
                public_key,
                psk,
                vip: u.vip,
            });
        }

        Ok(Config {
            private_key: raw.private_key.parse().context("bad private_key")?,
            listen_ip: raw.listen_ip,
            ports: raw.ports,
            egress: raw.egress,
            egress_ip: raw.egress_ip,
            subnet,
            tun: raw.tun,
            mtu: raw.mtu,
            nat_port_range: lo..=hi,
            udp_nat_timeout: raw.udp_nat_timeout_s * SECOND,
            dns_upstream,
            control_socket: raw.control_socket,
            allow_destinations: raw.allow_destinations,
            cpu: raw.cpu,
            busy_poll: raw.busy_poll,
            users,
        })
    }

    /// Address of the server end of the TUN device (also the DNS resolver).
    pub fn gateway(&self) -> Ipv4Addr {
        gateway_addr(self.subnet)
    }

    /// First usable VIP not yet assigned.
    pub fn next_free_vip(&self) -> Option<Ipv4Addr> {
        let used: HashSet<Ipv4Addr> = self.users.iter().map(|u| u.vip).collect();
        self.subnet
            .hosts()
            .find(|ip| *ip != self.gateway() && !used.contains(ip))
    }
}

/// IPv4 `nameserver` entries of a resolv.conf, as port-53 addresses.
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "nameserver").then_some(())?;
            let ip: Ipv4Addr = w.next()?.parse().ok()?;
            Some(SocketAddr::from((ip, 53)))
        })
        .collect()
}

fn gateway_addr(subnet: Ipv4Net) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(subnet.network()) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        PrivateKey::generate().to_base64()
    }

    fn user(name: &str, vip: &str) -> String {
        format!(
            "[[user]]\nname = \"{name}\"\npublic_key = \"{}\"\nvip = \"{vip}\"\n",
            PrivateKey::generate().public_key()
        )
    }

    #[test]
    fn minimal_config_defaults() {
        let c = Config::parse(&format!("private_key = \"{}\"\nports = [40001]\n", key())).unwrap();
        assert_eq!(c.subnet.to_string(), "10.77.0.0/16");
        assert_eq!(c.gateway(), Ipv4Addr::new(10, 77, 0, 1));
        assert_eq!(c.mtu, 1400);
        assert_eq!(c.nat_port_range, 20000..=60000);
        assert_eq!(c.next_free_vip(), Some(Ipv4Addr::new(10, 77, 0, 2)));
        assert!(c.dns_upstream.is_empty());
        assert_eq!(c.control_socket, Path::new(DEFAULT_CONTROL_SOCKET));
    }

    #[test]
    fn dns_upstreams() {
        let c = Config::parse(&format!(
            "private_key = \"{}\"
ports = [1]
dns_upstream = [\"1.1.1.1\", \"127.0.0.1:5353\"]
",
            key()
        ))
        .unwrap();
        assert_eq!(
            c.dns_upstream,
            vec![
                SocketAddr::from(([1, 1, 1, 1], 53)),
                SocketAddr::from(([127, 0, 0, 1], 5353))
            ]
        );
        let bad = format!(
            "private_key = \"{}\"
ports = [1]
dns_upstream = [\"::1\"]
",
            key()
        );
        assert!(Config::parse(&bad).is_err());

        let resolv = "# generated
search example
nameserver 192.0.2.53
nameserver ::1
options edns0
nameserver 198.51.100.1 # second
";
        assert_eq!(
            parse_resolv_conf(resolv),
            vec![
                SocketAddr::from(([192, 0, 2, 53], 53)),
                SocketAddr::from(([198, 51, 100, 1], 53))
            ]
        );
    }

    #[test]
    fn users_are_validated() {
        let base = format!("private_key = \"{}\"\nports = [1]\n", key());
        let ok = format!("{base}{}{}", user("a", "10.77.0.2"), user("b", "10.77.0.3"));
        let c = Config::parse(&ok).unwrap();
        assert_eq!(c.users.len(), 2);
        assert_eq!(c.next_free_vip(), Some(Ipv4Addr::new(10, 77, 0, 4)));

        for bad in [
            format!("{base}{}{}", user("a", "10.77.0.2"), user("a", "10.77.0.3")),
            format!("{base}{}{}", user("a", "10.77.0.2"), user("b", "10.77.0.2")),
            format!("{base}{}", user("a", "10.77.0.1")),
            format!("{base}{}", user("a", "10.78.0.2")),
        ] {
            assert!(Config::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        let k = key();
        assert!(Config::parse(&format!("private_key = \"{k}\"\nports = []\n")).is_err());
        assert!(
            Config::parse(&format!("private_key = \"{k}\"\nports = [1]\nbogus = 1\n")).is_err()
        );
        assert!(
            Config::parse(&format!("private_key = \"{k}\"\nports = [1]\nmtu = 9000\n")).is_err()
        );
        assert!(Config::parse("private_key = \"xx\"\nports = [1]\n").is_err());
    }
}
