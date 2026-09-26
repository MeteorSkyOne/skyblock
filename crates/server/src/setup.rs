//! System integration: egress detection, nftables and
//! sysctl, `init` and `adduser`.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;
use skyblock_proto::keys::{PrivateKey, Psk, PublicKey};
use skyblock_sys::cmd;

use crate::config::Config;

const NFT_TABLE: &str = "skyblock";

/// Default-route interface and its IPv4 address, via `ip`.
pub fn detect_egress() -> Option<(String, Ipv4Addr)> {
    let routes = cmd::output("ip", &["-4", "route", "show", "default"]).ok()?;
    let dev = word_after(&routes, "dev")?.to_owned();
    let addrs = cmd::output("ip", &["-4", "-o", "addr", "show", "dev", &dev]).ok()?;
    let ip = word_after(&addrs, "inet")?
        .split('/')
        .next()?
        .parse()
        .ok()?;
    Some((dev, ip))
}

fn word_after<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut words = text.split_whitespace();
    words.find(|w| *w == key)?;
    words.next()
}

/// Egress interface and address: from the config, else auto-detected.
pub fn egress(cfg: &Config) -> Result<(String, Ipv4Addr)> {
    let detected = || detect_egress().context("cannot detect the default-route interface");
    match (&cfg.egress, cfg.egress_ip) {
        (Some(dev), Some(ip)) => Ok((dev.clone(), ip)),
        (Some(dev), None) => {
            let out = cmd::output("ip", &["-4", "-o", "addr", "show", "dev", dev])?;
            let ip = word_after(&out, "inet")
                .and_then(|w| w.split('/').next())
                .and_then(|s| s.parse().ok())
                .with_context(|| format!("no IPv4 address on {dev}"))?;
            Ok((dev.clone(), ip))
        }
        (None, Some(ip)) => Ok((detected()?.0, ip)),
        (None, None) => detected(),
    }
}

/// nftables ruleset: masquerade the VIP subnet and clamp forwarded TCP MSS.
/// Replaces any previous copy of the table atomically.
pub fn nft_rules(tun: &str, subnet: Ipv4Net, egress: &str) -> String {
    format!(
        "add table ip {NFT_TABLE}
delete table ip {NFT_TABLE}
table ip {NFT_TABLE} {{
  chain forward {{
    type filter hook forward priority 0; policy accept;
    iifname \"{tun}\" tcp flags syn tcp option maxseg size set rt mtu
    oifname \"{tun}\" tcp flags syn tcp option maxseg size set rt mtu
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {subnet} oifname \"{egress}\" masquerade
  }}
}}
"
    )
}

pub fn prepare_system(cfg: &Config, egress: &str) -> Result<()> {
    cmd::run("sysctl", &["-qw", "net.ipv4.ip_forward=1"])?;
    let rp = format!("net.ipv4.conf.{}.rp_filter=0", cfg.tun);
    cmd::run("sysctl", &["-qw", &rp])?;
    cmd::run_with_stdin(
        "nft",
        &["-f", "-"],
        &nft_rules(&cfg.tun, cfg.subnet, egress),
    )
    .context("installing nftables rules (is nftables installed?)")
}

pub fn init(dir: &Path, ports: &[u16], egress_dev: Option<String>) -> Result<()> {
    let path = dir.join("server.toml");
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let detected = detect_egress();
    let (dev, ip) = match (egress_dev, detected) {
        (Some(dev), d) => (Some(dev), d.map(|d| d.1)),
        (None, Some((dev, ip))) => (Some(dev), Some(ip)),
        (None, None) => (None, None),
    };
    let key = PrivateKey::generate();
    let text = config_template(&key, ports, dev.as_deref(), ip)?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    println!("wrote {}", path.display());
    println!("node public key: {}", key.public_key());

    let exe = std::env::current_exe()?;
    let unit = format!(
        "[Unit]
Description=skyblock relay node
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={} run -c {}
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
",
        exe.display(),
        path.display()
    );
    let unit_dir = Path::new("/etc/systemd/system");
    if unit_dir.is_dir() {
        let unit_path = unit_dir.join("skyblock-server.service");
        std::fs::write(&unit_path, unit)
            .with_context(|| format!("writing {}", unit_path.display()))?;
        println!("wrote {}", unit_path.display());
        println!("next: skyblock-server adduser <name> <client public key>");
        println!("      systemctl daemon-reload && systemctl enable --now skyblock-server");
        println!("      skyblock-server status");
    }
    Ok(())
}

/// The `server.toml` that `init` writes, with the optional keys commented.
fn config_template(
    key: &PrivateKey,
    ports: &[u16],
    dev: Option<&str>,
    ip: Option<Ipv4Addr>,
) -> Result<String> {
    let ports = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut text = String::new();
    writeln!(text, "# skyblock-server configuration")?;
    writeln!(text, "private_key = \"{}\"", key.to_base64())?;
    writeln!(text, "# public_key = \"{}\"", key.public_key())?;
    writeln!(text, "ports = [{ports}]")?;
    match dev {
        Some(d) => writeln!(text, "egress = \"{d}\"")?,
        None => writeln!(text, "# egress = \"eth0\"   # could not auto-detect")?,
    }
    if let Some(ip) = ip {
        writeln!(text, "egress_ip = \"{ip}\"")?;
    }
    text.push_str(
        "# subnet = \"10.77.0.0/16\"
# mtu = 1400
# nat_port_range = [20000, 60000]
# udp_nat_timeout_s = 300
# dns_upstream = []   # e.g. [\"1.1.1.1\"]; empty: /etc/resolv.conf
# control_socket = \"/run/skyblock-server.sock\"   # for `skyblock-server status`
# cpu = 1             # pin the node to this CPU
# busy_poll = false   # true: never sleep (one core busy, lower wake-up latency)

# Users are appended by `skyblock-server adduser`.
",
    );
    Ok(text)
}

pub fn adduser(config: &Path, name: &str, key: PublicKey, with_psk: bool) -> Result<()> {
    let cfg = Config::load(config)?;
    if cfg.users.iter().any(|u| u.name == name) {
        bail!("user {name} already exists");
    }
    if cfg.users.iter().any(|u| u.public_key == key) {
        bail!("that public key is already registered");
    }
    let vip = cfg
        .next_free_vip()
        .with_context(|| format!("no free address left in {}", cfg.subnet))?;
    let psk = with_psk.then(Psk::generate);

    let original = std::fs::read_to_string(config)?;
    let mut block =
        format!("\n[[user]]\nname = \"{name}\"\npublic_key = \"{key}\"\nvip = \"{vip}\"\n");
    if let Some(p) = &psk {
        writeln!(block, "psk = \"{}\"", p.to_base64())?;
    }
    let mut updated = original.clone();
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&block);
    Config::parse(&updated).context("config would become invalid")?;
    std::fs::write(config, updated)?;
    eprintln!("added {name} with vip {vip}; restart skyblock-server to apply");

    let host = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_owned())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "node".to_owned());
    let addr = cfg
        .egress_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "<node public IP>".to_owned());
    let ports = cfg
        .ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    println!("# paste into the client config:");
    println!("[[node]]");
    println!("name = \"{host}\"");
    println!("addr = \"{addr}\"");
    println!("ports = [{ports}]");
    println!("public_key = \"{}\"", cfg.private_key.public_key());
    if let Some(p) = &psk {
        println!("psk = \"{}\"", p.to_base64());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_rules_mention_everything() {
        let r = nft_rules("sb0", "10.77.0.0/16".parse().unwrap(), "eth0");
        assert!(r.contains("ip saddr 10.77.0.0/16 oifname \"eth0\" masquerade"));
        assert!(r.contains("iifname \"sb0\" tcp flags syn"));
        assert!(r.starts_with("add table ip skyblock\ndelete table ip skyblock\n"));
    }

    #[test]
    fn parses_ip_output() {
        let route = "default via 192.0.2.1 dev ens3 proto dhcp src 192.0.2.10 metric 100\n";
        assert_eq!(word_after(route, "dev"), Some("ens3"));
        let addr = "2: ens3    inet 192.0.2.10/24 brd 192.0.2.255 scope global dynamic ens3\n";
        assert_eq!(word_after(addr, "inet"), Some("192.0.2.10/24"));
        assert_eq!(word_after("", "dev"), None);
    }

    #[test]
    fn init_template_loads_even_uncommented() {
        let key = PrivateKey::generate();
        let text = config_template(
            &key,
            &[40001, 40002],
            Some("eth0"),
            Some(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .unwrap();
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.ports, vec![40001, 40002]);
        assert_eq!(c.egress_ip, Some(Ipv4Addr::new(192, 0, 2, 1)));
        // Every commented default is valid as written.
        let uncommented: String = text
            .lines()
            .map(|l| match l.strip_prefix("# ") {
                Some(rest) if rest.contains(" = ") && !rest.starts_with("public_key") => rest,
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let c = Config::parse(&uncommented).unwrap();
        assert!(c.dns_upstream.is_empty());
        assert!(Config::parse(&config_template(&key, &[1], None, None).unwrap()).is_ok());
    }

    #[test]
    fn adduser_appends_valid_block() {
        let dir = std::env::temp_dir().join(format!("sb-adduser-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.toml");
        std::fs::write(
            &path,
            format!(
                "private_key = \"{}\"\nports = [40001]\n",
                PrivateKey::generate().to_base64()
            ),
        )
        .unwrap();
        let k1 = PrivateKey::generate().public_key();
        adduser(&path, "alice", k1, false).unwrap();
        adduser(&path, "bob", PrivateKey::generate().public_key(), true).unwrap();
        assert!(adduser(&path, "alice", PrivateKey::generate().public_key(), false).is_err());
        assert!(adduser(&path, "carol", k1, false).is_err());
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.users.len(), 2);
        assert_eq!(cfg.users[0].vip, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(cfg.users[1].vip, Ipv4Addr::new(10, 77, 0, 3));
        assert_ne!(cfg.users[1].psk, Psk::ZERO);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
