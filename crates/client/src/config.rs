//! Client configuration (SPEC §6.8).

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use ipnet::Ipv4Net;
use serde::Deserialize;
use skyblock_proto::keys::{PrivateKey, Psk, PublicKey};

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
    /// Upper bound on the inner MTU; the node's value wins if lower.
    pub mtu: u16,
    pub pad_max: usize,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            mtu: 1400,
            pad_max: skyblock_proto::packet::DATA_PAD_MAX,
        }
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
    /// Domain suffixes resolved through the node (M3).
    #[serde(default)]
    #[allow(dead_code)]
    pub domains: Vec<String>,
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
        ensure!(
            (576..=1432).contains(&raw.tunnel.mtu),
            "`tunnel.mtu` must be within 576..=1432"
        );
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
        }
        Ok(Config {
            private_key: raw.private_key.parse().context("bad private_key")?,
            mode: raw.mode.unwrap_or_else(Mode::platform_default),
            default_node: raw.default_node,
            nodes,
            tunnel: raw.tunnel,
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
    }
}
