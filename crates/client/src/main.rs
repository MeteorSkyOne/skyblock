mod capture;
mod config;
mod core;
// Only the WinDivert backend rewrites addresses; built everywhere for tests.
#[cfg_attr(not(windows), allow(dead_code))]
mod flows;
#[cfg(windows)]
mod procmap;
mod tunnel;
#[cfg(windows)]
mod windivert;

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use skyblock_proto::keys::PrivateKey;
use tracing::{Level, info};

use crate::capture::Capture;
use crate::config::{Config, GameConfig, Mode};
use crate::core::ClientCore;
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
}

fn parse_mode(s: &str) -> Result<Mode, String> {
    match s {
        "windivert" => Ok(Mode::Windivert),
        "tun" => Ok(Mode::Tun),
        _ => Err("expected `windivert` or `tun`".into()),
    }
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
    );
    info!(node = %node.name, addr = %node.addr, port = node.ports[0], "connecting");
    let tunnel = Tunnel::start(core, &node)?;
    let hello = tunnel.wait_connected();
    let mtu = hello.mtu.min(cfg.tunnel.mtu);

    let nodes: Vec<Ipv4Addr> = cfg.nodes.iter().map(|n| n.addr).collect();
    let capture = open_capture(mode, &cfg, &games, &nodes, hello.vip, mtu)?;
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
    vip: Ipv4Addr,
    mtu: u16,
) -> Result<Arc<dyn Capture>> {
    match mode {
        #[cfg(windows)]
        Mode::Windivert => {
            let processes: Vec<String> = games.iter().flat_map(|g| g.process.clone()).collect();
            if processes.is_empty() {
                bail!("no game processes configured ([[game]] process = [...])");
            }
            Ok(Arc::new(capture::windivert::WinDivertCapture::open(
                &processes, nodes, vip, mtu,
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
            )?))
        }
        #[allow(unreachable_patterns)]
        other => bail!("{other:?} mode is not available on this platform yet"),
    }
}

fn status_loop(tunnel: &Tunnel, node: &str) -> Result<()> {
    let ms = |us: u64| us as f64 / 1000.0;
    let mut prev = tunnel.stats().0;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let (s, hello) = tunnel.stats();
        let state = if hello.is_some() { "up" } else { "connecting" };
        println!(
            "[{node}] {state} | rtt {:.1}ms min {:.1}ms | up {} pkt/s down {} pkt/s | sessions {}",
            ms(s.rtt.srtt),
            ms(s.rtt.min),
            s.tx_data - prev.tx_data,
            s.rx_data - prev.rx_data,
            s.handshakes,
        );
        prev = s;
    }
}
