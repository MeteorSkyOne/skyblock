mod bench;
mod capture;
mod config;
mod core;
// Only the WinDivert backend rewrites addresses and redirects DNS; built
// everywhere for tests.
#[cfg_attr(not(windows), allow(dead_code))]
mod dns;
#[cfg_attr(not(windows), allow(dead_code))]
mod flows;
mod ping;
#[cfg(windows)]
mod procmap;
mod report;
mod tunnel;
#[cfg(windows)]
mod windivert;

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use skyblock_proto::frame::ProbeKind;
use skyblock_proto::keys::PrivateKey;
use tracing::{Level, info};

use crate::bench::BenchArgs;
use crate::capture::Capture;
use crate::config::{Config, GameConfig, Mode};
use crate::core::{ClientCore, Snapshot};
use crate::ping::PingArgs;
use crate::report::{Interval, pct};
use crate::tunnel::Tunnel;

/// skyblock game accelerator client.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Log level: error, warn, info, debug, trace.
    #[arg(long, global = true, default_value = "info")]
    log_level: Level,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a user key pair (paste into the client config; give the
    /// public key to each node's `adduser`).
    Keygen,
    /// Connect to a node and start accelerating.
    Up {
        #[arg(short, long, default_value = "skyblock.toml")]
        config: PathBuf,
        /// Node to use (default: `default_node`, or the only node).
        #[arg(long)]
        node: Option<String>,
        /// Games to accelerate (default: all configured games).
        #[arg(long = "game")]
        games: Vec<String>,
        /// Capture mode (default: from the config / platform).
        #[arg(long, value_parser = parse_mode)]
        mode: Option<Mode>,
    },
    /// Handshake with every node, measure the latency to each, and
    /// optionally have each node measure its latency to a game server;
    /// ranks the nodes by the total. Replaces a running `up` session with
    /// the same key on each node, so run it before `up`.
    Ping {
        #[arg(short, long, default_value = "skyblock.toml")]
        config: PathBuf,
        /// Nodes to test (default: all).
        #[arg(long = "node")]
        nodes: Vec<String>,
        /// Have each node measure its latency to this address.
        #[arg(long)]
        target: Option<Ipv4Addr>,
        /// How nodes probe the target: icmp, or tcp:PORT (a reply is the
        /// SYN-ACK or the RST).
        #[arg(long, default_value = "icmp", value_parser = parse_probe)]
        probe: (ProbeKind, u16),
        /// PINGs per path, and probe pings per node (1-20).
        #[arg(long, default_value_t = 10)]
        count: u8,
    },
    /// Measure loss and latency through a node for several redundancy
    /// settings. Replaces a running `up` session with the same key.
    Bench {
        #[arg(short, long, default_value = "skyblock.toml")]
        config: PathBuf,
        #[arg(long)]
        node: Option<String>,
        /// Measured time per setting, e.g. 30s, 2m.
        #[arg(long, default_value = "30s", value_parser = parse_duration)]
        duration: Duration,
        /// Unmeasured traffic before each setting.
        #[arg(long, default_value = "2s", value_parser = parse_duration)]
        warmup: Duration,
        /// Echo requests per second.
        #[arg(long, default_value_t = 128)]
        pps: u32,
        /// Payload size or range in bytes, e.g. 200 or 100-300.
        #[arg(long, default_value = "100-300", value_parser = parse_size)]
        size: (usize, usize),
        /// Copy counts to try.
        #[arg(long, value_delimiter = ',', default_value = "1,2")]
        copies: Vec<u8>,
        /// Path counts to try (copies spread over this many best paths).
        #[arg(long, value_delimiter = ',', default_value = "2")]
        paths: Vec<u8>,
        /// Copy delays to try, in ms (default: from the config).
        #[arg(long = "delay-ms", value_delimiter = ',')]
        delays_ms: Vec<f64>,
    },
}

fn parse_mode(s: &str) -> Result<Mode, String> {
    match s {
        "windivert" => Ok(Mode::Windivert),
        "tun" => Ok(Mode::Tun),
        _ => Err("expected `windivert` or `tun`".into()),
    }
}

fn parse_probe(s: &str) -> Result<(ProbeKind, u16), String> {
    match s.split_once(':') {
        None if s == "icmp" => Ok((ProbeKind::Icmp, 0)),
        Some(("tcp", port)) => match port.parse() {
            Ok(p) if p > 0 => Ok((ProbeKind::Tcp, p)),
            _ => Err(format!("bad port in `{s}`")),
        },
        _ => Err("expected `icmp` or `tcp:PORT`".into()),
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, unit) = s
        .find(|c: char| c.is_ascii_alphabetic())
        .map_or((s, "s"), |i| (&s[..i], &s[i..]));
    let v: f64 = num.parse().map_err(|_| format!("bad duration `{s}`"))?;
    let secs = match unit {
        "ms" => v / 1000.0,
        "s" => v,
        "m" => v * 60.0,
        _ => return Err(format!("bad duration unit in `{s}` (ms, s, m)")),
    };
    if !(secs > 0.0 && secs < 86_400.0) {
        return Err(format!("duration `{s}` out of range"));
    }
    Ok(Duration::from_secs_f64(secs))
}

fn parse_size(s: &str) -> Result<(usize, usize), String> {
    let bad = || format!("bad size `{s}` (e.g. 200 or 100-300)");
    let (lo, hi) = match s.split_once('-') {
        Some((a, b)) => (a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?),
        None => {
            let v = s.parse().map_err(|_| bad())?;
            (v, v)
        }
    };
    if lo > hi || hi > 1200 {
        return Err(format!("size `{s}` must be ascending and at most 1200"));
    }
    Ok((lo, hi))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(cli.log_level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    match cli.command {
        Command::Keygen => {
            let sk = PrivateKey::generate();
            println!("private_key = \"{}\"", sk.to_base64());
            println!("# public_key = \"{}\"", sk.public_key());
            Ok(())
        }
        Command::Up {
            config,
            node,
            games,
            mode,
        } => up(&config, node.as_deref(), &games, mode),
        Command::Ping {
            config,
            nodes,
            target,
            probe,
            count,
        } => {
            if !(1..=20).contains(&count) {
                bail!("--count must be within 1..=20");
            }
            let cfg = Config::load(&config)?;
            let args = PingArgs {
                nodes,
                target,
                kind: probe.0,
                port: probe.1,
                count,
            };
            ping::run(&cfg, &args)
        }
        Command::Bench {
            config,
            node,
            duration,
            warmup,
            pps,
            size,
            copies,
            paths,
            delays_ms,
        } => {
            let cfg = Config::load(&config)?;
            let node = cfg.node(node.as_deref())?.clone();
            if pps == 0 || pps > 5000 {
                bail!("--pps must be within 1..=5000");
            }
            if copies.iter().any(|&c| c == 0 || c > 4) || paths.iter().any(|&p| p == 0 || p > 8) {
                bail!("--copies must be within 1..=4 and --paths within 1..=8");
            }
            let delays_ms = if delays_ms.is_empty() {
                vec![cfg.tunnel.copy_delay_ms]
            } else {
                delays_ms
            };
            let args = BenchArgs {
                duration,
                warmup,
                pps,
                size,
                copies,
                paths,
                delays_ms,
            };
            bench::run(&cfg, &node, &args)
        }
    }
}

fn up(
    path: &std::path::Path,
    node: Option<&str>,
    games: &[String],
    mode: Option<Mode>,
) -> Result<()> {
    let cfg = Config::load(path)?;
    let node = cfg.node(node)?.clone();
    let games = cfg.games(games)?;
    let mode = mode.unwrap_or(cfg.mode);

    let core = ClientCore::new(
        cfg.private_key.clone(),
        node.public_key,
        node.psk,
        cfg.tunnel.pad_max,
        cfg.tunnel.paths,
        cfg.tunnel.policy(),
    )
    .with_rekey_interval(cfg.tunnel.rekey_interval());
    info!(
        node = %node.name,
        addr = %node.addr,
        ports = ?node.ports,
        paths = cfg.tunnel.paths,
        copies = cfg.tunnel.copies,
        copy_delay_ms = cfg.tunnel.copy_delay_ms,
        "connecting"
    );
    let tunnel = Tunnel::start(core, &node, cfg.tunnel.paths)?;
    let hello = tunnel.wait_connected();
    let mtu = hello.mtu.min(cfg.tunnel.mtu);

    let nodes: Vec<Ipv4Addr> = cfg.nodes.iter().map(|n| n.addr).collect();
    let capture = open_capture(mode, &cfg, &games, &nodes, &hello, mtu)?;
    tunnel.set_capture(Arc::clone(&capture));
    let t = Arc::clone(&tunnel);
    capture.start(Arc::new(move |pkt: &mut [u8]| t.send_ip(pkt)))?;

    let t = Arc::clone(&tunnel);
    ctrlc::set_handler(move || {
        t.close();
        std::process::exit(0);
    })?;
    status_loop(&tunnel, &node.name)
}

#[allow(unused_variables)]
fn open_capture(
    mode: Mode,
    cfg: &Config,
    games: &[&GameConfig],
    nodes: &[Ipv4Addr],
    hello: &skyblock_proto::handshake::ServerHello,
    mtu: u16,
) -> Result<Arc<dyn Capture>> {
    let vip = hello.vip;
    match mode {
        #[cfg(windows)]
        Mode::Windivert => {
            let processes: Vec<String> = games.iter().flat_map(|g| g.process.clone()).collect();
            if processes.is_empty() {
                bail!("no game processes configured ([[game]] process = [...])");
            }
            let domains: Vec<String> = games.iter().flat_map(|g| g.domains.clone()).collect();
            let dns = dns::DnsRedirect::new(cfg.dns.mode, &domains, hello.resolver, vip);
            Ok(Arc::new(capture::windivert::WinDivertCapture::open(
                &processes, nodes, vip, mtu, dns,
            )?))
        }
        #[cfg(target_os = "linux")]
        Mode::Tun => {
            let routes: Vec<_> = games
                .iter()
                .flat_map(|g| g.ip_ranges.iter().copied())
                .chain(cfg.tun.routes.iter().copied())
                .collect();
            if routes.is_empty() {
                bail!("TUN mode needs routes ([[game]] ip_ranges or [tun] routes)");
            }
            Ok(Arc::new(capture::linux_tun::TunCapture::open(
                &cfg.tun.name,
                vip,
                mtu,
                &routes,
                hello.resolver,
            )?))
        }
        #[allow(unreachable_patterns)]
        other => bail!("{other:?} mode is not available on this platform yet"),
    }
}

/// Loss figures carried over between STATS exchanges.
#[derive(Default)]
struct EffLoss {
    up: Option<f64>,
    down: Option<f64>,
    up_rescued: u64,
    down_rescued: u64,
}

fn status_loop(tunnel: &Tunnel, node: &str) -> Result<()> {
    let mut prev = tunnel.snapshot();
    let mut eff = EffLoss::default();
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let cur = tunnel.snapshot();
        if let (Some(a), Some(b)) = (&prev.exchange, &cur.exchange) {
            if b.at != a.at {
                let i = Interval { a, b };
                eff = EffLoss {
                    up: i.up_eff(),
                    down: i.down_eff(),
                    up_rescued: i.up_rescued(),
                    down_rescued: i.down_rescued(),
                };
            }
        }
        println!("{}", status_line(node, &prev, &cur, &eff));
        prev = cur;
    }
}

/// e.g. `[tokyo-1] up | rtt 42.1ms ±0.3 | loss up 0.8%/0.00% down 0.5%/0.00% rescued 3/2
/// | up 128pps 0.2Mbps down 128pps 0.3Mbps | paths 2/2 [42.1 43.0] | flows 3 bulk 1`
fn status_line(node: &str, prev: &Snapshot, cur: &Snapshot, eff: &EffLoss) -> String {
    if !cur.connected {
        return format!("[{node}] connecting");
    }
    let ms = |us: u64| us as f64 / 1000.0;
    let up: Vec<_> = cur.paths.iter().filter(|p| p.up).collect();
    let avg = |f: fn(&&crate::core::PathView) -> f32| -> Option<f64> {
        (!up.is_empty()).then(|| up.iter().map(f).sum::<f32>() as f64 / up.len() as f64)
    };
    let (rtt, var) = cur
        .best
        .and_then(|b| cur.paths.get(b))
        .map_or((0, 0), |p| (p.rtt.srtt, p.rtt.rttvar));
    let (s, p) = (&cur.stats, &prev.stats);
    let mbps = |bytes: u64| bytes as f64 * 8.0 / 1e6;
    let rtts: Vec<String> = cur
        .paths
        .iter()
        .map(|p| format!("{:.1}", ms(p.rtt.srtt)))
        .collect();
    format!(
        "[{node}] up | rtt {:.1}ms ±{:.1} | loss up {}/{} down {}/{} rescued {}/{} | up {}pps {:.1}Mbps down {}pps {:.1}Mbps | paths {}/{} [{}] | flows {} bulk {}",
        ms(rtt),
        ms(var),
        pct(avg(|p| p.loss_out)),
        pct(eff.up),
        pct(avg(|p| p.loss_in)),
        pct(eff.down),
        eff.up_rescued,
        eff.down_rescued,
        s.tx_ip.saturating_sub(p.tx_ip),
        mbps(s.tx_bytes.saturating_sub(p.tx_bytes)),
        s.rx_ip.saturating_sub(p.rx_ip),
        mbps(s.rx_bytes.saturating_sub(p.rx_bytes)),
        up.len(),
        cur.paths.len(),
        rtts.join(" "),
        cur.flows,
        cur.bulk_flows,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_sizes() {
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("10"), Ok(Duration::from_secs(10)));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("5h").is_err());
        assert_eq!(parse_size("100-300"), Ok((100, 300)));
        assert_eq!(parse_size("200"), Ok((200, 200)));
        assert!(parse_size("300-100").is_err());
        assert!(parse_size("2000").is_err());
        assert_eq!(parse_probe("icmp"), Ok((ProbeKind::Icmp, 0)));
        assert_eq!(parse_probe("tcp:443"), Ok((ProbeKind::Tcp, 443)));
        assert!(parse_probe("tcp:0").is_err());
        assert!(parse_probe("udp:53").is_err());
    }
}
