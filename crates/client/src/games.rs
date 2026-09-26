//! Built-in game templates (SPEC §6.8): process names, domains and the
//! networks (ASNs) that host a game's servers, so that a `[[game]]` entry,
//! or `--game`, can just name the game.
//!
//! Only data we are sure of is listed. Server addresses are not: they
//! change, so `skyblock games --ranges NAME` looks up the prefixes the
//! game's ASNs announce right now (RIPEstat) and prints `ip_ranges` for
//! the config (needed by Wintun rules mode only).

use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;

pub struct Template {
    pub name: &'static str,
    pub title: &'static str,
    pub process: &'static [&'static str],
    pub domains: &'static [&'static str],
    /// Networks the game's servers live in (empty: public clouds, no
    /// useful ranges).
    pub asns: &'static [u32],
}

const RIOT: u32 = 6507;
const VALVE: u32 = 32590;
const BLIZZARD: u32 = 57976;

pub const TEMPLATES: &[Template] = &[
    Template {
        name: "valorant",
        title: "VALORANT",
        process: &["VALORANT-Win64-Shipping.exe"],
        domains: &["riotgames.com", "pvp.net"],
        asns: &[RIOT],
    },
    Template {
        name: "lol",
        title: "League of Legends",
        process: &["League of Legends.exe"],
        domains: &["riotgames.com", "leagueoflegends.com", "pvp.net"],
        asns: &[RIOT],
    },
    Template {
        name: "cs2",
        title: "Counter-Strike 2",
        process: &["cs2.exe"],
        domains: &[],
        asns: &[VALVE],
    },
    Template {
        name: "dota2",
        title: "Dota 2",
        process: &["dota2.exe"],
        domains: &[],
        asns: &[VALVE],
    },
    Template {
        name: "overwatch",
        title: "Overwatch 2",
        process: &["Overwatch.exe"],
        domains: &["battle.net", "blizzard.com"],
        asns: &[BLIZZARD],
    },
    Template {
        name: "apex",
        title: "Apex Legends",
        process: &["r5apex.exe", "r5apex_dx12.exe"],
        domains: &[],
        asns: &[],
    },
    Template {
        name: "pubg",
        title: "PUBG: Battlegrounds",
        process: &["TslGame.exe"],
        domains: &[],
        asns: &[],
    },
    Template {
        name: "fortnite",
        title: "Fortnite",
        process: &["FortniteClient-Win64-Shipping.exe"],
        domains: &[],
        asns: &[],
    },
    Template {
        name: "r6",
        title: "Rainbow Six Siege",
        process: &["RainbowSix.exe", "RainbowSix_Vulkan.exe"],
        domains: &[],
        asns: &[],
    },
    Template {
        name: "tarkov",
        title: "Escape from Tarkov",
        process: &["EscapeFromTarkov.exe"],
        domains: &[],
        asns: &[],
    },
    Template {
        name: "thefinals",
        title: "THE FINALS",
        process: &["Discovery.exe"],
        domains: &[],
        asns: &[],
    },
    Template {
        name: "naraka",
        title: "NARAKA: BLADEPOINT",
        process: &["NarakaBladepoint.exe"],
        domains: &[],
        asns: &[],
    },
    Template {
        name: "rust",
        title: "Rust",
        process: &["RustClient.exe"],
        domains: &[],
        asns: &[],
    },
];

pub fn find(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name.eq_ignore_ascii_case(name))
}

/// The table `skyblock games` prints.
pub fn list() -> String {
    let mut out = format!(
        "{:<11} {:<22} {:<48} {}\n",
        "name", "game", "processes", "asns"
    );
    for t in TEMPLATES {
        let asns: Vec<String> = t.asns.iter().map(|a| format!("AS{a}")).collect();
        out.push_str(&format!(
            "{:<11} {:<22} {:<48} {}\n",
            t.name,
            t.title,
            t.process.join(", "),
            if asns.is_empty() {
                "-".into()
            } else {
                asns.join(" ")
            }
        ));
    }
    out
}

/// IPv4 prefixes in a RIPEstat `announced-prefixes` answer: every
/// `"prefix": "a.b.c.d/n"` value (IPv6 ones are skipped).
pub fn parse_announced(json: &str) -> Vec<Ipv4Net> {
    let mut out = Vec::new();
    let mut rest = json;
    while let Some(i) = rest.find("\"prefix\"") {
        rest = &rest[i + "\"prefix\"".len()..];
        let Some(v) = rest
            .trim_start()
            .strip_prefix(':')
            .map(str::trim_start)
            .and_then(|s| s.strip_prefix('"'))
        else {
            continue;
        };
        if let Some(end) = v.find('"')
            && let Ok(net) = v[..end].parse::<Ipv4Net>()
        {
            out.push(net);
        }
    }
    Ipv4Net::aggregate(&out)
}

/// Looks up the prefixes `asns` announce (RIPEstat, via Windows' own
/// `curl.exe` or any `curl` on the path).
pub fn announced(asns: &[u32]) -> Result<Vec<Ipv4Net>> {
    let mut all = Vec::new();
    for a in asns {
        let url = format!("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{a}");
        let json = skyblock_sys::cmd::output("curl", &["-fsSL", "--max-time", "20", &url])
            .with_context(|| format!("fetching the prefixes of AS{a} ({url})"))?;
        let nets = parse_announced(&json);
        if nets.is_empty() {
            bail!("RIPEstat listed no IPv4 prefixes for AS{a}");
        }
        all.extend(nets);
    }
    Ok(Ipv4Net::aggregate(&all))
}

/// `ip_ranges = [...]` as a config line, wrapped.
pub fn ranges_toml(nets: &[Ipv4Net]) -> String {
    let mut out = String::from("ip_ranges = [\n");
    for chunk in nets.chunks(4) {
        let items: Vec<String> = chunk.iter().map(|n| format!("\"{n}\"")).collect();
        out.push_str(&format!("    {},\n", items.join(", ")));
    }
    out.push(']');
    out
}

/// A prefix covering `ip`, for checks in tests and messages.
#[allow(dead_code)]
pub fn covers(nets: &[Ipv4Net], ip: Ipv4Addr) -> bool {
    nets.iter().any(|n| n.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_lowercase() {
        for (i, t) in TEMPLATES.iter().enumerate() {
            assert_eq!(t.name, t.name.to_ascii_lowercase());
            assert!(!t.process.is_empty(), "{}", t.name);
            assert!(TEMPLATES[i + 1..].iter().all(|u| u.name != t.name));
        }
        assert_eq!(find("VALORANT").unwrap().asns, &[RIOT]);
        assert!(find("nope").is_none());
        assert!(list().contains("cs2         Counter-Strike 2"));
    }

    #[test]
    fn parses_ripestat_answers() {
        let json = r#"{"data":{"prefixes":[
            {"prefix": "104.160.128.0/20", "timelines": []},
            {"prefix":"104.160.144.0/20","timelines":[]},
            {"prefix": "2620:10d:c090::/44", "timelines": []},
            {"prefix": "not a prefix"}],
            "resource": "6507"}}"#;
        let nets = parse_announced(json);
        assert_eq!(nets, vec!["104.160.128.0/19".parse::<Ipv4Net>().unwrap()]);
        assert!(covers(&nets, Ipv4Addr::new(104, 160, 131, 1)));
        let toml = ranges_toml(&nets);
        assert_eq!(toml, "ip_ranges = [\n    \"104.160.128.0/19\",\n]");
    }
}
