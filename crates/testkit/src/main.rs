//! `sbtest`: traffic tools for the netns testbed (SPEC §10.3). Output is
//! `key=value` so scripts can parse it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use rand::{Rng, RngExt};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// UDP and TCP echo server on the same port.
    Echo {
        #[arg(long, default_value = "0.0.0.0:9000")]
        bind: SocketAddr,
    },
    /// Round-trip latency over UDP against an echo server.
    UdpPing {
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 500)]
        count: u32,
        #[arg(long, default_value_t = 10)]
        interval_ms: u64,
        #[arg(long, default_value_t = 200)]
        size: usize,
    },
    /// Round-trip latency over one TCP connection against an echo server.
    TcpPing {
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 200)]
        count: u32,
        #[arg(long, default_value_t = 10)]
        interval_ms: u64,
        #[arg(long, default_value_t = 200)]
        size: usize,
    },
    /// Sends one datagram to `prime` (creating NAT state), then reports
    /// datagrams from any other source. Exits 0 if at least one arrived.
    UdpListen {
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long)]
        prime: SocketAddr,
        #[arg(long, default_value_t = 3000)]
        wait_ms: u64,
    },
    /// Sends datagrams to an address.
    UdpSend {
        #[arg(long)]
        to: SocketAddr,
        #[arg(long, default_value_t = 3)]
        count: u32,
    },
    /// Sends random junk to a node and exits 0 only if nothing answers.
    Probe {
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 200)]
        count: u32,
        #[arg(long, default_value_t = 2000)]
        wait_ms: u64,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Echo { bind } => echo(bind),
        Command::UdpPing {
            target,
            count,
            interval_ms,
            size,
        } => udp_ping(target, count, interval_ms, size),
        Command::TcpPing {
            target,
            count,
            interval_ms,
            size,
        } => tcp_ping(target, count, interval_ms, size),
        Command::UdpListen {
            bind,
            prime,
            wait_ms,
        } => udp_listen(bind, prime, wait_ms),
        Command::UdpSend { to, count } => udp_send(to, count),
        Command::Probe {
            target,
            count,
            wait_ms,
        } => probe(target, count, wait_ms),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("sbtest: {e}");
            ExitCode::from(2)
        }
    }
}

type Res = std::io::Result<bool>;

fn echo(bind: SocketAddr) -> Res {
    let udp = UdpSocket::bind(bind)?;
    let tcp = TcpListener::bind(bind)?;
    std::thread::spawn(move || {
        for stream in tcp.incoming().flatten() {
            std::thread::spawn(move || {
                let _ = stream.set_nodelay(true);
                let mut s = stream;
                let mut buf = [0u8; 65536];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    eprintln!("echo listening on {bind} (udp+tcp)");
    let mut buf = [0u8; 65536];
    loop {
        let (n, from) = udp.recv_from(&mut buf)?;
        udp.send_to(&buf[..n], from)?;
    }
}

fn report(prefix: &str, sent: u32, mut rtts: Vec<Duration>) {
    rtts.sort();
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    let pct = |p: f64| {
        if rtts.is_empty() {
            0.0
        } else {
            us(rtts[((rtts.len() - 1) as f64 * p).round() as usize])
        }
    };
    let recv = rtts.len() as u32;
    let mean = if rtts.is_empty() {
        0.0
    } else {
        rtts.iter().map(|d| us(*d)).sum::<f64>() / rtts.len() as f64
    };
    println!(
        "{prefix} sent={sent} recv={recv} loss_pct={:.2} min_us={:.0} p50_us={:.0} p99_us={:.0} max_us={:.0} mean_us={:.0}",
        100.0 * f64::from(sent - recv.min(sent)) / f64::from(sent.max(1)),
        pct(0.0),
        pct(0.5),
        pct(0.99),
        pct(1.0),
        mean
    );
}

fn udp_ping(target: SocketAddr, count: u32, interval_ms: u64, size: usize) -> Res {
    let sock = Arc::new(UdpSocket::bind(("0.0.0.0", 0))?);
    sock.connect(target)?;
    println!("udp local_port={}", sock.local_addr()?.port());
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let start = Instant::now();
    let size = size.max(12);
    let rtts = Arc::new(Mutex::new(vec![None::<Duration>; count as usize]));

    let (rx_sock, rx_rtts) = (Arc::clone(&sock), Arc::clone(&rtts));
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rx_done = Arc::clone(&done);
    let receiver = std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        while !rx_done.load(std::sync::atomic::Ordering::Relaxed) {
            let Ok(n) = rx_sock.recv(&mut buf) else {
                continue;
            };
            if n < 12 {
                continue;
            }
            let seq = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
            let sent_us = u64::from_be_bytes(buf[4..12].try_into().unwrap());
            let rtt = start.elapsed() - Duration::from_micros(sent_us);
            if let Some(slot) = rx_rtts.lock().unwrap().get_mut(seq) {
                slot.get_or_insert(rtt);
            }
        }
    });

    let mut pkt = vec![0u8; size];
    for seq in 0..count {
        pkt[0..4].copy_from_slice(&seq.to_be_bytes());
        pkt[4..12].copy_from_slice(&(start.elapsed().as_micros() as u64).to_be_bytes());
        sock.send(&pkt)?;
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
    std::thread::sleep(Duration::from_secs(1));
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    receiver.join().ok();
    let rtts: Vec<Duration> = rtts.lock().unwrap().iter().flatten().copied().collect();
    let ok = !rtts.is_empty();
    report("udp", count, rtts);
    Ok(ok)
}

fn tcp_ping(target: SocketAddr, count: u32, interval_ms: u64, size: usize) -> Res {
    let t0 = Instant::now();
    let mut s = TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
    let connect = t0.elapsed();
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let msg = vec![0x5a; size.max(1)];
    let mut back = vec![0u8; msg.len()];
    let mut rtts = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let t = Instant::now();
        s.write_all(&msg)?;
        s.read_exact(&mut back)?;
        rtts.push(t.elapsed());
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
    println!("tcp connect_us={:.0}", connect.as_secs_f64() * 1e6);
    let ok = back == msg;
    report("tcp", count, rtts);
    Ok(ok)
}

fn udp_listen(bind: SocketAddr, prime: SocketAddr, wait_ms: u64) -> Res {
    let sock = UdpSocket::bind(bind)?;
    sock.send_to(b"prime", prime)?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let deadline = Instant::now() + Duration::from_millis(wait_ms);
    let mut buf = [0u8; 2048];
    let mut others = 0;
    while Instant::now() < deadline {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            println!("recv from={from} bytes={n}");
            if from != prime {
                others += 1;
            }
        }
    }
    println!("listen from_other={others}");
    Ok(others > 0)
}

fn udp_send(to: SocketAddr, count: u32) -> Res {
    let sock = UdpSocket::bind(("0.0.0.0", 0))?;
    for i in 0..count {
        sock.send_to(format!("hello {i}").as_bytes(), to)?;
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(true)
}

fn probe(target: SocketAddr, count: u32, wait_ms: u64) -> Res {
    let sock = UdpSocket::bind(("0.0.0.0", 0))?;
    sock.connect(target)?;
    let mut rng = rand::rng();
    let mut junk = vec![0u8; 1400];
    for _ in 0..count {
        let len = rng.random_range(1..=junk.len());
        rng.fill_bytes(&mut junk[..len]);
        sock.send(&junk[..len])?;
    }
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let deadline = Instant::now() + Duration::from_millis(wait_ms);
    let mut responses = 0;
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        if sock.recv(&mut buf).is_ok() {
            responses += 1;
        }
    }
    println!("probe sent={count} responses={responses}");
    Ok(responses == 0)
}
