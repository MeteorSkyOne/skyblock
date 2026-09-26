// The event loop, and so most of the crate, is Linux-only; elsewhere only
// `init`, `adduser` and the unit tests are built.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod config;
mod core;
mod dns;
#[cfg(target_os = "linux")]
mod event_loop;
mod filter;
mod limit;
mod nat;
#[cfg(target_os = "linux")]
mod probe;
mod setup;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use skyblock_proto::keys::PublicKey;
use tracing::Level;

const DEFAULT_DIR: &str = "/etc/skyblock";
const DEFAULT_CONFIG: &str = "/etc/skyblock/server.toml";

/// skyblock relay node.
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
    /// Generate a node key and config file, and install a systemd unit.
    Init {
        #[arg(long, default_value = DEFAULT_DIR)]
        dir: PathBuf,
        /// UDP ports to listen on.
        #[arg(long, value_delimiter = ',', default_value = "40001,40002")]
        ports: Vec<u16>,
        /// Egress interface (default: the default-route interface).
        #[arg(long)]
        egress: Option<String>,
    },
    /// Run the node.
    Run {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Show sessions, paths, NAT mappings and counters of the running node.
    Status {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Control socket (default: `control_socket` from the config).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Authorize a client key, assign it a VIP and print its [[node]] block.
    Adduser {
        name: String,
        public_key: PublicKey,
        /// Also generate a pre-shared key for this user.
        #[arg(long)]
        psk: bool,
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let log = tracing_subscriber::fmt()
        .with_max_level(cli.log_level)
        .with_target(false);
    // Under systemd the journal stamps every line itself.
    if std::env::var_os("JOURNAL_STREAM").is_some() {
        log.without_time().with_ansi(false).init();
    } else {
        log.init();
    }
    match cli.command {
        Command::Init { dir, ports, egress } => setup::init(&dir, &ports, egress),
        Command::Run { config } => run(config),
        Command::Status { config, socket } => status(config, socket),
        Command::Adduser {
            name,
            public_key,
            psk,
            config,
        } => setup::adduser(&config, &name, public_key, psk),
    }
}

#[cfg(target_os = "linux")]
fn run(config: PathBuf) -> Result<()> {
    event_loop::run(config::Config::load(&config)?)
}

#[cfg(not(target_os = "linux"))]
fn run(_config: PathBuf) -> Result<()> {
    anyhow::bail!("skyblock-server runs on Linux only")
}

/// Prints the report the running node writes to its control socket.
#[cfg(unix)]
fn status(config: PathBuf, socket: Option<PathBuf>) -> Result<()> {
    use anyhow::Context;
    use std::io::Read;

    let path = match socket {
        Some(p) => p,
        None => config::Config::load(&config)?.control_socket,
    };
    let mut s = std::os::unix::net::UnixStream::connect(&path).with_context(|| {
        format!(
            "connecting to {} (is skyblock-server running?)",
            path.display()
        )
    })?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut report = String::new();
    s.read_to_string(&mut report)?;
    print!("{report}");
    Ok(())
}

#[cfg(not(unix))]
fn status(_config: PathBuf, _socket: Option<PathBuf>) -> Result<()> {
    anyhow::bail!("skyblock-server runs on Linux only")
}
