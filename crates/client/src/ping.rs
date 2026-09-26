//! `skyblock ping`: handshakes with every node at once,
//! PINGs each path a few times and, given a target, has each node probe it
//! (PROBE_REQ). Nodes are ranked by client→node plus node→target latency.
//!
//! Each node gets its own session, which replaces a running `up` with the
//! same key on that node.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use skyblock_proto::Micros;
use skyblock_proto::frame::{ProbeKind, ProbeReq, ProbeResp};

use crate::config::{Config, Node};
use crate::core::ClientCore;
use crate::tunnel::{Event, Tunnel};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PING_GAP: Duration = Duration::from_millis(100);
/// Probe interval asked of the nodes, in ms.
const PROBE_INTERVAL_MS: u16 = 100;
/// The node gives up on one probe ping after 2s.
const PROBE_SLACK: Duration = Duration::from_secs(3);

pub struct PingArgs {
    /// Nodes to test; empty = all.
    pub nodes: Vec<String>,
    pub target: Option<Ipv4Addr>,
    pub kind: ProbeKind,
    pub port: u16,
    pub count: u8,
}

#[derive(Default)]
struct Collected {
    /// RTT samples per path.
    rtts: Vec<Vec<Micros>>,
    probe: Option<ProbeResp>,
}

/// What one node measured.
struct Report {
    node: Node,
    error: Option<String>,
    connect: Duration,
    /// Per path: (avg, min, answered, sent).
    paths: Vec<(Micros, Micros, usize, usize)>,
    probe: Option<ProbeResp>,
}

impl Report {
    /// Best path by average RTT.
    fn best(&self) -> Option<(usize, Micros, Micros)> {
        self.paths
            .iter()
            .enumerate()
            .filter(|(_, p)| p.2 > 0)
            .min_by_key(|(_, p)| p.0)
            .map(|(i, p)| (i, p.0, p.1))
    }

    fn target(&self) -> Option<Micros> {
        self.probe
            .filter(|p| p.recv > 0)
            .map(|p| Micros::from(p.avg_us))
    }

    /// Sort key: measured totals first, by total; then nodes without a
    /// target result; unreachable ones last.
    fn rank(&self, want_target: bool) -> (u8, Micros) {
        match (self.best(), self.target()) {
            (Some((_, node, _)), Some(t)) => (0, node + t),
            (Some((_, node, _)), None) if !want_target => (0, node),
            (Some((_, node, _)), None) => (1, node),
            (None, _) => (2, 0),
        }
    }
}

pub fn run(cfg: &Config, args: &PingArgs) -> Result<()> {
    let nodes: Vec<Node> = if args.nodes.is_empty() {
        cfg.nodes.clone()
    } else {
        args.nodes
            .iter()
            .map(|n| cfg.node(Some(n)).cloned())
            .collect::<Result<_>>()?
    };
    if nodes.is_empty() {
        bail!("no [[node]] configured");
    }
    match args.target {
        Some(t) => println!(
            "pinging {} node(s), {} per path; target {t} over {}",
            nodes.len(),
            args.count,
            probe_name(args.kind, args.port)
        ),
        None => println!("pinging {} node(s), {} per path", nodes.len(), args.count),
    }
    let workers: Vec<_> = nodes
        .into_iter()
        .map(|node| {
            let key = cfg.private_key.clone();
            let (paths, pad_max) = (cfg.tunnel.paths, cfg.tunnel.pad_max);
            let policy = cfg.tunnel.policy();
            let a = PingArgs {
                nodes: vec![],
                target: args.target,
                kind: args.kind,
                port: args.port,
                count: args.count,
            };
            std::thread::spawn(move || {
                let core = ClientCore::new(key, node.public_key, node.psk, pad_max, paths, policy)
                    .with_rekey_interval(None);
                measure(core, node, paths, &a)
            })
        })
        .collect();
    let mut reports: Vec<Report> = workers
        .into_iter()
        .map(|w| w.join().expect("ping worker panicked"))
        .collect();
    reports.sort_by_key(|r| r.rank(args.target.is_some()));

    println!();
    println!(
        "{:<3} {:<14} {:<16} {:>10}  {:<26} {:>10}  {:<18} {:>9}",
        "#",
        "node",
        "address",
        "node rtt",
        "(best path, min, answered)",
        "target",
        "(min, answered)",
        "total"
    );
    for (i, r) in reports.iter().enumerate() {
        println!("{}", row(i + 1, r, args.target.is_some()));
    }
    Ok(())
}

fn measure(core: ClientCore, node: Node, n_paths: usize, args: &PingArgs) -> Report {
    let mut report = Report {
        node: node.clone(),
        error: None,
        connect: Duration::ZERO,
        paths: vec![],
        probe: None,
    };
    match try_measure(core, &node, n_paths, args, &mut report) {
        Ok(()) => {}
        Err(e) => report.error = Some(format!("{e:#}")),
    }
    report
}

fn try_measure(
    core: ClientCore,
    node: &Node,
    n_paths: usize,
    args: &PingArgs,
    report: &mut Report,
) -> Result<()> {
    let start = Instant::now();
    let tunnel = Tunnel::start(core, node, n_paths)?;
    let got = Arc::new(Mutex::new(Collected {
        rtts: vec![vec![]; n_paths],
        probe: None,
    }));
    let sink = Arc::clone(&got);
    tunnel.set_event_sink(Box::new(move |e| {
        let mut c = sink.lock().expect("ping lock");
        match e {
            Event::Pong { path, rtt } => {
                if let Some(v) = c.rtts.get_mut(path) {
                    v.push(rtt);
                }
            }
            Event::Probe(p) if p.id == 1 => c.probe = Some(p),
            _ => {}
        }
    }));
    tunnel
        .wait_connected_for(CONNECT_TIMEOUT)
        .context("no handshake response")?;
    report.connect = start.elapsed();
    // Connecting PINGs every path once; count those too.
    let sent = 1 + usize::from(args.count);

    let probe_deadline = args.target.map(|ip| {
        tunnel.send_probe(ProbeReq {
            id: 1,
            kind: args.kind,
            ip,
            port: args.port,
            count: args.count,
            interval_ms: PROBE_INTERVAL_MS,
        });
        Instant::now()
            + Duration::from_millis(u64::from(PROBE_INTERVAL_MS) * u64::from(args.count))
            + PROBE_SLACK
    });
    for _ in 0..args.count {
        std::thread::sleep(PING_GAP);
        tunnel.ping_all();
    }
    // Wait for the last PONGs (a few RTTs) and the probe result.
    let rtt = tunnel
        .snapshot()
        .paths
        .iter()
        .map(|p| p.rtt.srtt)
        .max()
        .unwrap_or(0);
    let pongs_by = Instant::now() + Duration::from_micros(3 * rtt) + Duration::from_millis(300);
    loop {
        let done_pongs = Instant::now() >= pongs_by;
        let probe_pending = probe_deadline
            .is_some_and(|d| Instant::now() < d && got.lock().expect("ping lock").probe.is_none());
        if done_pongs && !probe_pending {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    tunnel.close();

    let c = got.lock().expect("ping lock");
    report.paths = c
        .rtts
        .iter()
        .map(|v| {
            let n = v.len().min(sent);
            let avg = if n > 0 {
                v.iter().sum::<Micros>() / n as Micros
            } else {
                0
            };
            (avg, v.iter().copied().min().unwrap_or(0), n, sent)
        })
        .collect();
    report.probe = c.probe;
    if args.target.is_some() && c.probe.is_none() {
        report.error = Some("no probe result".into());
    }
    Ok(())
}

fn probe_name(kind: ProbeKind, port: u16) -> String {
    match kind {
        ProbeKind::Icmp => "icmp".into(),
        ProbeKind::Tcp => format!("tcp:{port}"),
    }
}

fn ms(us: Micros) -> String {
    format!("{:.1}ms", us as f64 / 1000.0)
}

fn row(rank: usize, r: &Report, want_target: bool) -> String {
    let head = format!(
        "{rank:<3} {:<14} {:<16}",
        r.node.name,
        r.node.addr.to_string()
    );
    let Some((best, avg, min)) = r.best() else {
        let why = r.error.as_deref().unwrap_or("no PONG");
        return format!("{head} unreachable: {why}");
    };
    let (answered, sent) = r.paths.iter().fold((0, 0), |(a, s), p| (a + p.2, s + p.3));
    let node = format!("(#{best}, {:.1}, {answered}/{sent})", min as f64 / 1000.0);
    let (target, detail, total) = match (r.probe, want_target) {
        (_, false) => (String::new(), String::new(), ms(avg)),
        (Some(p), true) if p.recv > 0 => (
            ms(Micros::from(p.avg_us)),
            format!(
                "({:.1}, {}/{})",
                f64::from(p.min_us) / 1000.0,
                p.recv,
                p.sent
            ),
            ms(avg + Micros::from(p.avg_us)),
        ),
        (Some(p), true) => ("-".into(), format!("(-, 0/{})", p.sent), "-".into()),
        (None, true) => ("-".into(), "(no result)".into(), "-".into()),
    };
    format!(
        "{head} {:>10}  {node:<26} {target:>10}  {detail:<18} {total:>9}   connect {}",
        ms(avg),
        ms(r.connect.as_micros() as Micros)
    )
}
