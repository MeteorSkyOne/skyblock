//! Client configuration (SPEC §6.8).

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use ipnet::Ipv4Net;
use serde::Deserialize;
use skyblock_proto::Micros;
use skyblock_proto::dns::normalize_domain;
use skyblock_proto::frame::MAX_PATHS;
use skyblock_proto::keys::{PrivateKey, Psk, PublicKey};
use skyblock_proto::sched::{MAX_COPIES, MAX_COPY_DELAY, Policy};
use skyblock_proto::timing::SECOND;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Per-process capture with WinDivert (Windows).
    Windivert,
    /// Route-based capture through a TUN device (Linux testbed for now).
    Tun,
}

impl Mode {
    pub fn platform_default() -> Mode {
        if cfg!(windows) {
            Mode::Windivert
        } else {
            Mode::Tun
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    private_key: String,
    mode: Option<Mode>,
    default_node: Option<String>,
    #[serde(default)]
    node: Vec<RawNode>,
    #[serde(default)]
    tunnel: TunnelConfig,
    #[serde(default)]
    dns: DnsConfig,
    #[serde(default)]
    game: Vec<GameConfig>,
    #[serde(default)]
    tun: TunConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    name: String,
    addr: Ipv4Addr,
    ports: Vec<u16>,
    public_key: String,
    psk: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TunnelConfig {
    /// UDP sockets (paths) to the node; socket `i` uses `ports[i % len]`.
    pub paths: usize,
    /// Copies of each game packet, both directions (1 = no redundancy).
    pub copies: u8,
    /// Delay between successive copies.
    pub copy_delay_ms: f64,
    /// Upper bound on the inner MTU; the node's value wins if lower.
    pub mtu: u16,
    pub pad_max: usize,
    /// Flow classification thresholds (SPEC §4.1).
    pub bulk_enter_kbps: u32,
    pub bulk_exit_kbps: u32,
    /// In-channel rekey interval (SPEC §3.9); 0 turns rekeying off.
    pub rekey_interval_s: u64,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            paths: 2,
            copies: 2,
            copy_delay_ms: 2.0,
            mtu: 1400,
            pad_max: skyblock_proto::packet::DATA_PAD_MAX,
            bulk_enter_kbps: 2000,
            bulk_exit_kbps: 1000,
            rekey_interval_s: 600,
        }
    }
}

impl TunnelConfig {
    pub fn policy(&self) -> Policy {
        Policy {
            copies: self.copies,
            paths: 0,
            copy_delay: (self.copy_delay_ms * 1000.0).round() as Micros,
            bulk_enter_kbps: self.bulk_enter_kbps,
            bulk_exit_kbps: self.bulk_exit_kbps,
        }
    }

    /// `None` when rekeying is off.
    pub fn rekey_interval(&self) -> Option<Micros> {
        (self.rekey_interval_s > 0).then(|| self.rekey_interval_s * SECOND)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            (576..=1432).contains(&self.mtu),
            "`tunnel.mtu` must be within 576..=1432"
        );
        ensure!(
            self.rekey_interval_s <= 86_400,
            "`tunnel.rekey_interval_s` must be at most 86400"
        );
        ensure!(
            (1..=MAX_PATHS).contains(&self.paths),
            "`tunnel.paths` must be within 1..={MAX_PATHS}"
        );
        ensure!(
            (1..=MAX_COPIES).contains(&self.copies),
            "`tunnel.copies` must be within 1..={MAX_COPIES}"
        );
        let max_delay = MAX_COPY_DELAY as f64 / 1000.0;
        ensure!(
            (0.0..=max_delay).contains(&self.copy_delay_ms),
            "`tunnel.copy_delay_ms` must be within 0..={max_delay}"
        );
        ensure!(
            self.bulk_exit_kbps <= self.bulk_enter_kbps && self.bulk_enter_kbps > 0,
            "need 0 < `bulk_exit_kbps` <= `bulk_enter_kbps`"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GameConfig {
    pub name: String,
    /// Executable file names, matched case-insensitively (WinDivert mode).
    #[serde(default)]
    #[cfg_attr(not(windows), allow(dead_code))]
    pub process: Vec<String>,
    /// Destinations routed into the tunnel (TUN mode).
    #[serde(default)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub ip_ranges: Vec<Ipv4Net>,
    /// Domains (and their subdomains) resolved through the node when
    /// `[dns] mode = "rules"` (SPEC §6.5).
    #[serde(default)]
    #[cfg_attr(not(windows), allow(dead_code))]
    pub domains: Vec<String>,
}

/// Which DNS queries go through the node (SPEC §6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    /// Queries for the games' `domains`.
    #[default]
    Rules,
    /// Every query (not recommended: domestic sites resolve abroad).
    All,
    Off,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct DnsConfig {
    pub mode: DnsMode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TunConfig {
    pub name: String,
    /// Extra routes into the tunnel, on top of the games' `ip_ranges`.
    pub routes: Vec<Ipv4Net>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "sbc0".to_owned(),
            routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub addr: Ipv4Addr,
    pub ports: Vec<u16>,
    pub public_key: PublicKey,
    pub psk: Psk,
}

pub struct Config {
    pub private_key: PrivateKey,
    pub mode: Mode,
    pub default_node: Option<String>,
    pub nodes: Vec<Node>,
    pub tunnel: TunnelConfig,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub dns: DnsConfig,
    pub games: Vec<GameConfig>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub tun: TunConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config> {
        let raw: RawConfig = toml::from_str(text)?;
        raw.tunnel.validate()?;
        let mut names = HashSet::new();
        let mut nodes = Vec::with_capacity(raw.node.len());
        for n in raw.node {
            ensure!(!n.ports.is_empty(), "node {}: `ports` is empty", n.name);
            if !names.insert(n.name.clone()) {
                bail!("duplicate node name {}", n.name);
            }
            nodes.push(Node {
                public_key: n
                    .public_key
                    .parse()
                    .with_context(|| format!("node {}: bad public_key", n.name))?,
                psk: match n.psk {
                    Some(s) => s
                        .parse()
                        .with_context(|| format!("node {}: bad psk", n.name))?,
                    None => Psk::ZERO,
                },
                name: n.name,
                addr: n.addr,
                ports: n.ports,
            });
        }
        let mut games = HashSet::new();
        for g in &raw.game {
            if !games.insert(g.name.as_str()) {
                bail!("duplicate game name {}", g.name);
            }
            for d in &g.domains {
                ensure!(
                    normalize_domain(d).is_some(),
                    "game {}: empty domain {d:?}",
                    g.name
                );
            }
        }
        Ok(Config {
            private_key: raw.private_key.parse().context("bad private_key")?,
            mode: raw.mode.unwrap_or_else(Mode::platform_default),
            default_node: raw.default_node,
            nodes,
            tunnel: raw.tunnel,
            dns: raw.dns,
            games: raw.game,
            tun: raw.tun,
        })
    }

    /// The node named `name`, else `default_node`, else the only node.
    pub fn node(&self, name: Option<&str>) -> Result<&Node> {
        let wanted = name.or(self.default_node.as_deref());
        match wanted {
            Some(w) => self
                .nodes
                .iter()
                .find(|n| n.name == w)
                .with_context(|| format!("no node named {w}")),
            None => match self.nodes.as_slice() {
                [only] => Ok(only),
                [] => bail!("no [[node]] configured"),
                _ => bail!("several nodes configured: pick one with --node or default_node"),
            },
        }
    }

    /// The named games, or all of them when `names` is empty.
    pub fn games(&self, names: &[String]) -> Result<Vec<&GameConfig>> {
        if names.is_empty() {
            return Ok(self.games.iter().collect());
        }
        names
            .iter()
            .map(|n| {
                self.games
                    .iter()
                    .find(|g| &g.name == n)
                    .with_context(|| format!("no game named {n}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> String {
        format!("private_key = \"{}\"\n", PrivateKey::generate().to_base64())
    }

    fn node(name: &str) -> String {
        format!(
            "[[node]]\nname = \"{name}\"\naddr = \"192.0.2.1\"\nports = [40001]\npublic_key = \"{}\"\n",
            PrivateKey::generate().public_key()
        )
    }

    #[test]
    fn node_selection() {
        let one = Config::parse(&format!("{}{}", base(), node("tokyo"))).unwrap();
        assert_eq!(one.node(None).unwrap().name, "tokyo");
        assert!(one.node(Some("la")).is_err());

        let two = Config::parse(&format!("{}{}{}", base(), node("tokyo"), node("la"))).unwrap();
        assert!(two.node(None).is_err());
        assert_eq!(two.node(Some("la")).unwrap().name, "la");

        let dflt = format!(
            "default_node = \"la\"\n{}{}{}",
            base(),
            node("tokyo"),
            node("la")
        );
        assert_eq!(Config::parse(&dflt).unwrap().node(None).unwrap().name, "la");

        assert!(Config::parse(&format!("{}{}{}", base(), node("a"), node("a"))).is_err());
    }

    #[test]
    fn games_and_defaults() {
        let text = format!(
            "{}mode = \"tun\"\n[[game]]\nname = \"valorant\"\nprocess = [\"VALORANT-Win64-Shipping.exe\"]\n[[game]]\nname = \"cs2\"\nip_ranges = [\"198.19.0.0/24\"]\n",
            base()
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.mode, Mode::Tun);
        assert_eq!(c.tunnel.mtu, 1400);
        assert_eq!(c.tun.name, "sbc0");
        assert_eq!(c.games(&[]).unwrap().len(), 2);
        assert_eq!(c.games(&["cs2".into()]).unwrap()[0].ip_ranges.len(), 1);
        assert!(c.games(&["apex".into()]).is_err());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Config::parse(&format!("{}bogus = 1\n", base())).is_err());
        assert!(Config::parse(&format!("{}[tunnel]\nmtu = 100\n", base())).is_err());
        assert!(Config::parse(&format!("{}mode = \"magic\"\n", base())).is_err());
        for bad in [
            "paths = 0",
            "paths = 9",
            "copies = 0",
            "copies = 5",
            "copy_delay_ms = -1.0",
            "copy_delay_ms = 51.0",
            "bulk_enter_kbps = 100\nbulk_exit_kbps = 200",
        ] {
            let text = format!("{}[tunnel]\n{bad}\n", base());
            assert!(Config::parse(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn tunnel_policy() {
        let text = format!(
            "{}[tunnel]\npaths = 3\ncopies = 3\ncopy_delay_ms = 1.5\n",
            base()
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.tunnel.paths, 3);
        let p = c.tunnel.policy();
        assert_eq!((p.copies, p.copy_delay, p.paths), (3, 1500, 0));
        let d = Config::parse(&base()).unwrap().tunnel;
        assert_eq!((d.paths, d.copies, d.copy_delay_ms), (2, 2, 2.0));
        assert_eq!(d.rekey_interval(), Some(600 * SECOND));
        let off = Config::parse(&format!(
            "{}[tunnel]
rekey_interval_s = 0
",
            base()
        ))
        .unwrap();
        assert_eq!(off.tunnel.rekey_interval(), None);
    }

    #[test]
    fn dns_settings() {
        let c = Config::parse(&base()).unwrap();
        assert_eq!(c.dns.mode, DnsMode::Rules);
        let text = format!(
            "{}[dns]
mode = \"all\"
[[game]]
name = \"lol\"
domains = [\"riotgames.com\", \".leagueoflegends.com\"]
",
            base()
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.dns.mode, DnsMode::All);
        assert_eq!(c.games[0].domains.len(), 2);
        assert!(
            Config::parse(&format!(
                "{}[dns]
mode = \"some\"
",
                base()
            ))
            .is_err()
        );
        let empty = format!(
            "{}[[game]]
name = \"x\"
domains = [\".\"]
",
            base()
        );
        assert!(Config::parse(&empty).is_err());
    }
}
