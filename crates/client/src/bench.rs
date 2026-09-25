//! `skyblock bench` (SPEC §6.7): sends echo requests at a game-like rate
//! through the node for each combination of copies, paths and copy delay,
//! and reports loss (raw per path and after redundancy), rescues and RTT.
//! The raw loss per path shows whether redundancy itself draws ISP QoS:
//! it would rise with the copy count.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rand::RngExt;
use skyblock_proto::Micros;
use skyblock_proto::sched::Policy;
use skyblock_sys::prio::boost_current_thread;
use skyblock_sys::timer::Waiter;
use tracing::info;

use crate::config::{Config, Node};
use crate::core::{ClientCore, Exchange};
use crate::report::{Interval, pct};
use crate::tunnel::Tunnel;

pub struct BenchArgs {
    pub duration: Duration,
    pub warmup: Duration,
    pub pps: u32,
    pub size: (usize, usize),
    pub copies: Vec<u8>,
    pub paths: Vec<u8>,
    pub delays_ms: Vec<f64>,
}

#[derive(Default)]
struct Received {
    first_id: u32,
    /// RTT per id since `first_id`, in microseconds.
    rtts: Vec<Option<Micros>>,
    /// RTTs in arrival order, for jitter.
    arrivals: Vec<Micros>,
}

impl Received {
    fn reset(&mut self, first_id: u32, count: usize) {
        self.first_id = first_id;
        self.rtts = vec![None; count];
        self.arrivals.clear();
    }

    fn record(&mut self, id: u32, rtt: Micros) {
        let i = id.wrapping_sub(self.first_id) as usize;
        if let Some(slot @ None) = self.rtts.get_mut(i) {
            *slot = Some(rtt);
            self.arrivals.push(rtt);
        }
    }
}

struct Combo {
    copies: u8,
    paths: u8,
    delay_ms: f64,
}

struct Outcome {
    combo: Combo,
    sent: usize,
    lost: usize,
    max_run: usize,
    bursts: usize,
    p50: Micros,
    p99: Micros,
    max: Micros,
    jitter: f64,
    up_eff: Option<f64>,
    down_eff: Option<f64>,
    up_rescued: u64,
    down_rescued: u64,
    up_raw: Vec<Option<f64>>,
    down_raw: Vec<Option<f64>>,
}

pub fn run(cfg: &Config, node: &Node, args: &BenchArgs) -> Result<()> {
    let n_paths = usize::from(args.paths.iter().copied().max().unwrap_or(1)).max(1);
    let core = ClientCore::new(
        cfg.private_key.clone(),
        node.public_key,
        node.psk,
        cfg.tunnel.pad_max,
        n_paths,
        cfg.tunnel.policy(),
    );
    info!(node = %node.name, addr = %node.addr, paths = n_paths, "bench: connecting");
    let tunnel = Tunnel::start(core, node, n_paths)?;
    // This thread sends copy 0 of every request, as the capture thread does
    // in `up`. Unboosted, Windows sometimes stalls it past the copy delay,
    // so copy 1 overtakes copy 0 and the node counts a false rescue.
    boost_current_thread();
    let received = Arc::new(Mutex::new(Received::default()));
    let sink = Arc::clone(&received);
    tunnel.set_echo_sink(Box::new(move |now, id, ts| {
        let rtt = now.saturating_sub(ts);
        sink.lock().expect("bench lock").record(id, rtt);
    }));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !tunnel.snapshot().connected {
        if Instant::now() > deadline {
            bail!("no session with {} after 10s", node.name);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Let every path collect a few RTT samples.
    std::thread::sleep(Duration::from_millis(1500));
    let snap = tunnel.snapshot();
    let rtts: Vec<String> = snap
        .paths
        .iter()
        .enumerate()
        .map(|(i, p)| format!("#{i} {:.1}ms", p.rtt.srtt as f64 / 1000.0))
        .collect();
    println!(
        "bench {} ({}): {} pps, {}-{} B, {}s per run; path rtt {}",
        node.name,
        node.addr,
        args.pps,
        args.size.0,
        args.size.1,
        args.duration.as_secs_f64(),
        rtts.join(", ")
    );

    let mut next_id = 1u32;
    let mut outcomes = vec![];
    for &delay_ms in &args.delays_ms {
        for &copies in &args.copies {
            for &paths in &args.paths {
                let combo = Combo {
                    copies,
                    paths,
                    delay_ms,
                };
                let o = run_one(&tunnel, &received, cfg, combo, args, &mut next_id)?;
                println!("{}", line(&o));
                outcomes.push(o);
            }
        }
    }
    tunnel.close();

    println!();
    println!(
        "copies paths delay |   sent  lost%  maxrun | up eff  rescued | down eff  rescued |  p50ms  p99ms  maxms jitter | raw up / down per path"
    );
    for o in &outcomes {
        println!("{}", row(o));
    }
    Ok(())
}

fn run_one(
    tunnel: &Tunnel,
    received: &Mutex<Received>,
    cfg: &Config,
    combo: Combo,
    args: &BenchArgs,
    next_id: &mut u32,
) -> Result<Outcome> {
    let policy = Policy {
        copies: combo.copies,
        paths: combo.paths,
        copy_delay: (combo.delay_ms * 1000.0).round() as Micros,
        ..cfg.tunnel.policy()
    };
    tunnel.set_policy(policy);
    // Warm up (and make the session active, so STATS come every second).
    send_for(tunnel, args, args.warmup, next_id);
    let settle = settle_time(tunnel);
    let a = wait_exchange(tunnel, tunnel.now() + settle)?;

    let count = (args.duration.as_secs_f64() * f64::from(args.pps)).round() as usize;
    received.lock().expect("bench lock").reset(*next_id, count);
    let sent = send_for(tunnel, args, args.duration, next_id);
    let b = wait_exchange(tunnel, tunnel.now() + settle)?;

    let r = received.lock().expect("bench lock");
    let rtts = &r.rtts[..sent.min(r.rtts.len())];
    let mut sorted: Vec<Micros> = rtts.iter().flatten().copied().collect();
    sorted.sort_unstable();
    let q = |f: f64| -> Micros {
        if sorted.is_empty() {
            0
        } else {
            sorted[((sorted.len() - 1) as f64 * f).round() as usize]
        }
    };
    let jitter = if r.arrivals.len() > 1 {
        let sum: u64 = r.arrivals.windows(2).map(|w| w[0].abs_diff(w[1])).sum();
        sum as f64 / (r.arrivals.len() - 1) as f64
    } else {
        0.0
    };
    let (mut streak, mut max_run, mut bursts) = (0usize, 0usize, 0usize);
    for got in rtts.iter().map(Option::is_some).chain([true]) {
        if got {
            if streak >= 2 {
                bursts += 1;
            }
            streak = 0;
        } else {
            streak += 1;
            max_run = max_run.max(streak);
        }
    }
    let n_paths = tunnel.snapshot().paths.len();
    let i = Interval { a: &a, b: &b };
    Ok(Outcome {
        sent: rtts.len(),
        lost: rtts.len() - sorted.len(),
        max_run,
        bursts,
        p50: q(0.5),
        p99: q(0.99),
        max: sorted.last().copied().unwrap_or(0),
        jitter,
        up_eff: i.up_eff(),
        down_eff: i.down_eff(),
        up_rescued: i.up_rescued(),
        down_rescued: i.down_rescued(),
        up_raw: (0..n_paths).map(|p| i.up_raw(p)).collect(),
        down_raw: (0..n_paths).map(|p| i.down_raw(p)).collect(),
        combo,
    })
}

/// Paces echo requests at `args.pps` for `dur`; returns how many were sent.
fn send_for(tunnel: &Tunnel, args: &BenchArgs, dur: Duration, next_id: &mut u32) -> usize {
    let count = (dur.as_secs_f64() * f64::from(args.pps)).round() as usize;
    let interval = Duration::from_secs_f64(1.0 / f64::from(args.pps));
    let waiter = Waiter::new().expect("timer");
    let mut rng = rand::rng();
    let payload: Vec<u8> = (0..args.size.1).map(|_| rng.random()).collect();
    let start = Instant::now();
    for k in 0..count {
        waiter.wait_until(start + interval * k as u32);
        let len = rng.random_range(args.size.0..=args.size.1);
        tunnel.send_echo(*next_id, &payload[..len]);
        *next_id = next_id.wrapping_add(1);
    }
    count
}

/// Long enough for everything in flight to land: the slowest path's RTT
/// plus a margin.
fn settle_time(tunnel: &Tunnel) -> Micros {
    let worst = tunnel
        .snapshot()
        .paths
        .iter()
        .map(|p| p.rtt.srtt + 4 * p.rtt.rttvar)
        .max()
        .unwrap_or(0);
    worst + 200_000
}

/// Waits for a node `STATS` that arrived after `after`.
fn wait_exchange(tunnel: &Tunnel, after: Micros) -> Result<Exchange> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(e) = tunnel.snapshot().exchange {
            if e.at >= after {
                return Ok(e);
            }
        }
        if Instant::now() > deadline {
            bail!("no STATS from the node for 5s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn ms(us: Micros) -> f64 {
    us as f64 / 1000.0
}

fn raw_list(v: &[Option<f64>]) -> String {
    v.iter().map(|l| pct(*l)).collect::<Vec<_>>().join(" ")
}

fn line(o: &Outcome) -> String {
    let c = &o.combo;
    format!(
        "copies {} paths {} delay {:.1}ms: sent {} lost {} ({:.3}%), max run {}, bursts {} | up eff {} rescued {} raw [{}] | down eff {} rescued {} raw [{}] | rtt p50 {:.1} p99 {:.1} max {:.1} jitter {:.2}ms",
        c.copies,
        c.paths,
        c.delay_ms,
        o.sent,
        o.lost,
        o.lost as f64 * 100.0 / o.sent.max(1) as f64,
        o.max_run,
        o.bursts,
        pct(o.up_eff),
        o.up_rescued,
        raw_list(&o.up_raw),
        pct(o.down_eff),
        o.down_rescued,
        raw_list(&o.down_raw),
        ms(o.p50),
        ms(o.p99),
        ms(o.max),
        o.jitter / 1000.0,
    )
}

fn row(o: &Outcome) -> String {
    let c = &o.combo;
    let mut s = String::new();
    let _ = write!(
        s,
        "{:>6} {:>5} {:>5.1} | {:>6} {:>6.3} {:>6} | {:>6} {:>8} | {:>8} {:>8} | {:>6.1} {:>6.1} {:>6.1} {:>6.2} | [{}] / [{}]",
        c.copies,
        c.paths,
        c.delay_ms,
        o.sent,
        o.lost as f64 * 100.0 / o.sent.max(1) as f64,
        o.max_run,
        pct(o.up_eff),
        o.up_rescued,
        pct(o.down_eff),
        o.down_rescued,
        ms(o.p50),
        ms(o.p99),
        ms(o.max),
        o.jitter / 1000.0,
        raw_list(&o.up_raw),
        raw_list(&o.down_raw),
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_ignores_duplicates_and_strangers() {
        let mut r = Received::default();
        r.reset(u32::MAX - 1, 4);
        r.record(u32::MAX, 10);
        r.record(u32::MAX, 20);
        r.record(1, 30);
        r.record(7, 40);
        r.record(u32::MAX - 5, 50);
        assert_eq!(r.rtts, vec![None, Some(10), None, Some(30)]);
        assert_eq!(r.arrivals, vec![10, 30]);
    }
}
