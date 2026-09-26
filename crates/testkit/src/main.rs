//! `sbtest`: traffic tools for the netns testbed (SPEC §10.3). Output is
//! `key=value` so scripts can parse it.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
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
    /// Accepts TCP connections and sends zeros as fast as possible.
    TcpSource {
        #[arg(long)]
        bind: SocketAddr,
    },
    /// Downloads from a `tcp-source` for a while and reports throughput.
    TcpSink {
        #[arg(long)]
        target: SocketAddr,
        #[arg(long, default_value_t = 10)]
        secs: u64,
    },
    /// DNS server answering every A query with `answer`; logs each query
    /// with its source.
    DnsServer {
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long)]
        answer: Ipv4Addr,
    },
    /// Resolves `name` (type A) against `server`; exits 0 on an answer.
    DnsQuery {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
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
        Command::TcpSource { bind } => tcp_source(bind),
        Command::TcpSink { target, secs } => tcp_sink(target, secs),
        Command::DnsServer { bind, answer } => dns_server(bind, answer),
        Command::DnsQuery {
            server,
            name,
            timeout_ms,
        } => dns_query(server, &name, timeout_ms),
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

fn report(prefix: &str, sent: u32, mut rtts: Vec<Duration>, extra: &str) {
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
        "{prefix} sent={sent} recv={recv} loss_pct={:.2} min_us={:.0} p50_us={:.0} p99_us={:.0} max_us={:.0} mean_us={:.0}{extra}",
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
    let dups = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let (rx_sock, rx_rtts, rx_dups) = (Arc::clone(&sock), Arc::clone(&rtts), Arc::clone(&dups));
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
                if slot.is_some() {
                    rx_dups.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
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
    let slots = rtts.lock().unwrap().clone();
    // Longest run of consecutive lost pings (outages).
    let (mut run, mut max_run) = (0u32, 0u32);
    for got in slots.iter().map(Option::is_some) {
        run = if got { 0 } else { run + 1 };
        max_run = max_run.max(run);
    }
    let rtts: Vec<Duration> = slots.into_iter().flatten().collect();
    let ok = !rtts.is_empty();
    let extra = format!(
        " dup={} max_run={max_run}",
        dups.load(std::sync::atomic::Ordering::Relaxed)
    );
    report("udp", count, rtts, &extra);
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
    report("tcp", count, rtts, "");
    Ok(ok)
}

fn tcp_source(bind: SocketAddr) -> Res {
    let listener = TcpListener::bind(bind)?;
    eprintln!("tcp source on {bind}");
    for stream in listener.incoming().flatten() {
        std::thread::spawn(move || {
            let mut s = stream;
            let chunk = [0u8; 65536];
            while s.write_all(&chunk).is_ok() {}
        });
    }
    Ok(true)
}

fn tcp_sink(target: SocketAddr, secs: u64) -> Res {
    let mut s = TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    let start = Instant::now();
    let mut buf = vec![0u8; 65536];
    let mut total = 0u64;
    while start.elapsed() < Duration::from_secs(secs) {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n as u64,
        }
    }
    let el = start.elapsed().as_secs_f64();
    println!(
        "tcp_sink bytes={total} secs={el:.1} mbps={:.1}",
        total as f64 * 8.0 / el / 1e6
    );
    Ok(total > 0)
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

/// End of the first question (after QTYPE/QCLASS), if well formed.
fn question_end(msg: &[u8]) -> Option<usize> {
    let mut pos = 12;
    loop {
        let len = usize::from(*msg.get(pos)?);
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        pos += len;
    }
    (pos + 4 <= msg.len()).then_some(pos + 4)
}

fn question_name(msg: &[u8]) -> String {
    let mut labels = vec![];
    let mut pos = 12;
    while let Some(&len) = msg.get(pos) {
        if len == 0 || len > 63 {
            break;
        }
        let l = msg.get(pos + 1..pos + 1 + usize::from(len)).unwrap_or(&[]);
        labels.push(String::from_utf8_lossy(l).into_owned());
        pos += 1 + usize::from(len);
    }
    labels.join(".")
}

fn dns_server(bind: SocketAddr, answer: Ipv4Addr) -> Res {
    let sock = UdpSocket::bind(bind)?;
    eprintln!("dns server on {bind}, answering {answer}");
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        let q = &buf[..n];
        let Some(end) = question_end(q).filter(|_| n >= 12 && q[2] & 0x80 == 0) else {
            continue;
        };
        println!("dns-server query from={from} name={}", question_name(q));
        let mut r = q[..end].to_vec();
        r[2] = 0x81; // QR, RD
        r[3] = 0x80; // RA
        r[4..12].copy_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&answer.octets());
        sock.send_to(&r, from)?;
    }
}

fn dns_query(server: SocketAddr, name: &str, timeout_ms: u64) -> Res {
    let sock = UdpSocket::bind(("0.0.0.0", 0))?;
    sock.connect(server)?;
    let id: u16 = rand::rng().random();
    let mut q = vec![0u8; 12];
    q[..2].copy_from_slice(&id.to_be_bytes());
    q[2] = 0x01;
    q[5] = 1;
    for l in name.split('.').filter(|l| !l.is_empty()) {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let start = Instant::now();
    sock.send(&q)?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut buf = [0u8; 1500];
    while start.elapsed() < Duration::from_millis(timeout_ms) {
        let Ok(n) = sock.recv(&mut buf) else { continue };
        let r = &buf[..n];
        if n < 12 || r[..2] != id.to_be_bytes() || r[2] & 0x80 == 0 {
            continue;
        }
        let rtt = start.elapsed();
        // First A record after the question.
        let Some(mut pos) = question_end(r) else {
            continue;
        };
        let ancount = u16::from_be_bytes([r[6], r[7]]);
        for _ in 0..ancount {
            // Name: a pointer or labels.
            while pos < n && r[pos] != 0 && r[pos] & 0xc0 != 0xc0 {
                pos += 1 + usize::from(r[pos]);
            }
            pos += if r.get(pos).is_some_and(|b| b & 0xc0 == 0xc0) {
                2
            } else {
                1
            };
            let Some(h) = r.get(pos..pos + 10) else { break };
            let (ty, len) = (
                u16::from_be_bytes([h[0], h[1]]),
                usize::from(u16::from_be_bytes([h[8], h[9]])),
            );
            pos += 10;
            if ty == 1 && len == 4 {
                if let Some(a) = r.get(pos..pos + 4) {
                    println!(
                        "dns answer={} rtt_us={}",
                        Ipv4Addr::new(a[0], a[1], a[2], a[3]),
                        rtt.as_micros()
                    );
                    return Ok(true);
                }
            }
            pos += len;
        }
        println!("dns answer=none rtt_us={}", rtt.as_micros());
        return Ok(false);
    }
    println!("dns timeout");
    Ok(false)
}
