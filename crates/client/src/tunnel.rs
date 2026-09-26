//! The client's threads: one receive thread per path socket, a
//! timer thread driving the core's timers and delayed copies, and the
//! capture backend's threads feeding outbound packets. All share one
//! [`ClientCore`] behind a mutex; I/O happens after the lock is released,
//! via per-thread [`Outbox`]es.
//!
//! A path's socket can be replaced (rebound) while the tunnel runs: when
//! the core finds the path silent, when the session died, or at once when
//! sending on it fails the way a vanished local address does. The new
//! socket gets a new receive thread; the old thread notices within
//! `RECV_TIMEOUT` and exits.

use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use skyblock_proto::Micros;
use skyblock_proto::frame::{ProbeReq, ProbeResp};
use skyblock_proto::handshake::ServerHello;
use skyblock_proto::ip::Ipv4Packet;
use skyblock_proto::sched::Policy;
use skyblock_sys::prio::boost_current_thread;
use skyblock_sys::timer::Waiter;
use tracing::{debug, info, warn};

use crate::capture::Capture;
use crate::config::Node;
use crate::core::{ClientCore, ClientIo, Snapshot};

/// How often receive threads check whether their socket was replaced.
const RECV_TIMEOUT: Duration = Duration::from_millis(250);
/// Send errors rebind a path at most this often.
const ERROR_REBIND_EVERY: Duration = Duration::from_secs(1);

/// Things the core reports that `bench` and `ping` collect.
#[derive(Debug, Clone, Copy)]
pub enum Event {
    /// An echo response: arrival time, id, send timestamp.
    Echo {
        now: Micros,
        id: u32,
        ts: u64,
    },
    /// A PONG on `path` after `rtt`.
    Pong {
        path: usize,
        rtt: Micros,
    },
    Probe(ProbeResp),
}

pub type EventSink = Box<dyn Fn(Event) + Send + Sync>;

/// Packets produced under the core lock, sent/injected after it is dropped.
#[derive(Default)]
pub struct Outbox {
    buf: Vec<u8>,
    sends: Vec<(usize, Range<usize>)>,
    delivers: Vec<Range<usize>>,
    events: Vec<Event>,
    /// Paths to rebind, each with the number of sends queued before the
    /// request (those still use the old socket).
    rebinds: Vec<(usize, usize)>,
}

impl Outbox {
    fn push(&mut self, data: &[u8]) -> Range<usize> {
        let start = self.buf.len();
        self.buf.extend_from_slice(data);
        start..self.buf.len()
    }
}

impl ClientIo for Outbox {
    fn send(&mut self, path: usize, pkt: &[u8]) {
        let r = self.push(pkt);
        self.sends.push((path, r));
    }

    fn deliver(&mut self, ip: &[u8]) {
        let r = self.push(ip);
        self.delivers.push(r);
    }

    fn echo(&mut self, now: Micros, id: u32, ts: u64) {
        self.events.push(Event::Echo { now, id, ts });
    }

    fn pong(&mut self, path: usize, rtt: Micros) {
        self.events.push(Event::Pong { path, rtt });
    }

    fn probe(&mut self, resp: ProbeResp) {
        self.events.push(Event::Probe(resp));
    }

    fn rebind(&mut self, path: usize) {
        self.rebinds.push((path, self.sends.len()));
    }
}

thread_local! {
    static OUTBOX: RefCell<Outbox> = RefCell::new(Outbox::default());
}

/// One path's socket, replaceable while the tunnel runs.
struct PathSock {
    peer: SocketAddr,
    sock: RwLock<Arc<UdpSocket>>,
    /// Bumped on every rebind; a receive thread serving an older one exits.
    generation: AtomicU64,
    last_error_rebind: Mutex<Option<Instant>>,
}

pub struct Tunnel {
    /// For spawning receive threads for rebound sockets.
    me: Weak<Tunnel>,
    core: Mutex<ClientCore>,
    paths: Vec<PathSock>,
    start: Instant,
    capture: OnceLock<Arc<dyn Capture>>,
    events: OnceLock<EventSink>,
    waiter: Waiter,
    /// When the timer thread plans to wake next; senders that schedule
    /// something earlier wake it.
    wake_at: AtomicU64,
}

/// A UDP socket connected to `peer` from an ephemeral local port.
fn open_socket(peer: SocketAddr) -> Result<UdpSocket> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).context("binding UDP socket")?;
    sock.connect(peer)
        .with_context(|| format!("connecting to {peer}"))?;
    #[cfg(windows)]
    disable_udp_connreset(&sock)?;
    sock.set_read_timeout(Some(RECV_TIMEOUT))?;
    Ok(sock)
}

impl Tunnel {
    /// Opens one connected UDP socket per path and starts the receive and
    /// timer threads.
    pub fn start(core: ClientCore, node: &Node, n_paths: usize) -> Result<Arc<Tunnel>> {
        let mut paths = Vec::with_capacity(n_paths);
        for i in 0..n_paths {
            let peer = SocketAddr::from((node.addr, node.ports[i % node.ports.len()]));
            paths.push(PathSock {
                peer,
                sock: RwLock::new(Arc::new(open_socket(peer)?)),
                generation: AtomicU64::new(0),
                last_error_rebind: Mutex::new(None),
            });
        }
        let waiter = Waiter::new().context("creating timer")?;
        let t = Arc::new_cyclic(|me| Tunnel {
            me: me.clone(),
            core: Mutex::new(core),
            paths,
            start: Instant::now(),
            capture: OnceLock::new(),
            events: OnceLock::new(),
            waiter,
            wake_at: AtomicU64::new(0),
        });
        for path in 0..n_paths {
            let sock = Arc::clone(&t.paths[path].sock.read().expect("socket lock"));
            t.spawn_rx(path, sock, 0)?;
        }
        let timer = Arc::clone(&t);
        std::thread::Builder::new()
            .name("timer".into())
            .spawn(move || timer.timer_loop())?;
        Ok(t)
    }

    pub fn now(&self) -> Micros {
        self.start.elapsed().as_micros() as Micros
    }

    fn core(&self) -> MutexGuard<'_, ClientCore> {
        self.core.lock().expect("core lock poisoned")
    }

    /// Blocks until a session is up and returns the node's hello.
    pub fn wait_connected(&self) -> ServerHello {
        loop {
            if let Some(h) = self.core().hello() {
                return h;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Like [`wait_connected`](Self::wait_connected), giving up after
    /// `timeout`.
    pub fn wait_connected_for(&self, timeout: Duration) -> Option<ServerHello> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(h) = self.core().hello() {
                return Some(h);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    pub fn set_capture(&self, capture: Arc<dyn Capture>) {
        let _ = self.capture.set(capture);
    }

    pub fn set_event_sink(&self, sink: EventSink) {
        let _ = self.events.set(sink);
    }

    pub fn snapshot(&self) -> Snapshot {
        let now = self.now();
        self.core().snapshot(now)
    }

    pub fn set_policy(&self, policy: Policy) {
        let now = self.now();
        let mut out = Outbox::default();
        self.core().set_policy(now, policy, &mut out);
        self.flush(&mut out);
    }

    /// PINGs every path now.
    pub fn ping_all(&self) {
        let now = self.now();
        let mut out = Outbox::default();
        self.core().ping_all(now, &mut out);
        self.flush(&mut out);
    }

    /// Asks the node to probe a target; `false` without a session.
    pub fn send_probe(&self, req: ProbeReq) -> bool {
        let mut out = Outbox::default();
        let sent = self.core().send_probe(req, &mut out);
        self.flush(&mut out);
        sent
    }

    /// Sends an outbound IPv4 packet from the capture backend.
    pub fn send_ip(&self, pkt: &[u8]) {
        if Ipv4Packet::parse(pkt).is_err() {
            return;
        }
        let now = self.now();
        OUTBOX.with_borrow_mut(|out| {
            {
                let mut core = self.core();
                core.send_ip(now, pkt, out);
                self.wake_if_needed(&core);
            }
            self.flush(out);
        });
    }

    /// Sends an echo request (`bench`).
    pub fn send_echo(&self, id: u32, payload: &[u8]) -> bool {
        let now = self.now();
        OUTBOX.with_borrow_mut(|out| {
            let sent = {
                let mut core = self.core();
                let sent = core.send_echo(now, id, payload, out);
                self.wake_if_needed(&core);
                sent
            };
            self.flush(out);
            sent
        })
    }

    /// Sends CLOSE so the node can drop the session right away.
    pub fn close(&self) {
        let mut out = Outbox::default();
        self.core().close(&mut out);
        self.flush(&mut out);
    }

    /// Wakes the timer thread if the core now has something due before
    /// the thread's planned wake-up (a delayed copy, or PINGs after idle).
    fn wake_if_needed(&self, core: &ClientCore) {
        if core
            .next_due()
            .is_some_and(|due| due < self.wake_at.load(Ordering::Relaxed))
        {
            self.waiter.wake();
        }
    }

    fn spawn_rx(&self, path: usize, sock: Arc<UdpSocket>, generation: u64) -> io::Result<()> {
        let me = self.me.upgrade().expect("tunnel alive");
        std::thread::Builder::new()
            .name(format!("path-{path}"))
            .spawn(move || me.rx_loop(path, &sock, generation))
            .map(drop)
    }

    /// Receives on `sock` until the path moves to a newer socket.
    fn rx_loop(&self, path: usize, sock: &UdpSocket, generation: u64) {
        let boost = boost_current_thread();
        debug!(path, generation, ?boost, "receive thread");
        let p = &self.paths[path];
        let mut buf = vec![0u8; 65536];
        let mut out = Outbox::default();
        loop {
            if p.generation.load(Ordering::Acquire) != generation {
                return;
            }
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    // Timeouts let us notice a new socket; ICMP errors and
                    // interrupted calls are transient.
                    if !matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::Interrupted
                    ) {
                        warn!(path, "node socket: {e}");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    continue;
                }
            };
            let now = self.now();
            {
                let mut core = self.core();
                core.handle_datagram(now, path, &mut buf[..n], &mut out);
                self.wake_if_needed(&core);
            }
            self.flush(&mut out);
        }
    }

    fn timer_loop(&self) {
        let boost = boost_current_thread();
        debug!(
            ?boost,
            high_res = self.waiter.is_high_resolution(),
            "timer thread"
        );
        let mut out = Outbox::default();
        loop {
            let now = self.now();
            let deadline = {
                let mut core = self.core();
                let d = core.poll(now, &mut out);
                self.wake_at.store(d, Ordering::Relaxed);
                d
            };
            self.flush(&mut out);
            self.waiter
                .wait_until(self.start + Duration::from_micros(deadline));
        }
    }

    /// Replaces `path`'s socket with a fresh one (new local port) and
    /// starts receiving on it.
    fn rebind(&self, path: usize) {
        let p = &self.paths[path];
        let s = match open_socket(p.peer) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                warn!(path, "cannot open a new socket: {e:#}");
                return;
            }
        };
        let local = s.local_addr().ok();
        let generation = {
            let mut cur = p.sock.write().expect("socket lock");
            *cur = Arc::clone(&s);
            p.generation.fetch_add(1, Ordering::AcqRel) + 1
        };
        if let Err(e) = self.spawn_rx(path, s, generation) {
            warn!(path, "cannot start a receive thread: {e}");
        }
        info!(path, ?local, "path moved to a new socket");
    }

    fn flush(&self, out: &mut Outbox) {
        let mut rebinds = std::mem::take(&mut out.rebinds).into_iter().peekable();
        let mut failed = Vec::new();
        for (i, (path, r)) in out.sends.drain(..).enumerate() {
            while let Some((p, _)) = rebinds.next_if(|&(_, before)| before <= i) {
                self.rebind(p);
            }
            let sent = self.paths[path]
                .sock
                .read()
                .expect("socket lock")
                .send(&out.buf[r]);
            if let Err(e) = sent {
                debug!(path, "node send: {e}");
                if needs_new_socket(&e) && !failed.contains(&path) {
                    failed.push(path);
                }
            }
        }
        for (p, _) in rebinds {
            self.rebind(p);
        }
        if let Some(c) = self.capture.get() {
            for r in out.delivers.drain(..) {
                c.inject(&mut out.buf[r]);
            }
        }
        out.delivers.clear();
        if let Some(sink) = self.events.get() {
            for e in out.events.drain(..) {
                sink(e);
            }
        }
        out.events.clear();
        out.buf.clear();
        for path in failed {
            self.rebind_after_error(path);
        }
    }

    /// Sending failed as it does when the local address went away (network
    /// change): move the path to a new socket now and PING through it, so
    /// the node learns the new address without waiting for the path to be
    /// declared down.
    fn rebind_after_error(&self, path: usize) {
        {
            let mut last = self.paths[path]
                .last_error_rebind
                .lock()
                .expect("rebind lock");
            if last.is_some_and(|t| t.elapsed() < ERROR_REBIND_EVERY) {
                return;
            }
            *last = Some(Instant::now());
        }
        self.rebind(path);
        let mut out = Outbox::default();
        self.core().path_rebound(self.now(), path, &mut out);
        self.flush(&mut out);
    }
}

/// Send errors that a fresh socket may cure: the socket's local address is
/// gone or unusable. ICMP-induced resets and full buffers are not.
fn needs_new_socket(e: &io::Error) -> bool {
    !matches!(
        e.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
    )
}

/// Stops ICMP port-unreachable from turning into `WSAECONNRESET` on
/// later receives.
#[cfg(windows)]
fn disable_udp_connreset(sock: &UdpSocket) -> Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, SOCKET, WSAIoctl};

    let enable: u32 = 0;
    let mut returned = 0u32;
    // SAFETY: valid socket handle and in/out buffers for the ioctl.
    let r = unsafe {
        WSAIoctl(
            sock.as_raw_socket() as SOCKET,
            SIO_UDP_CONNRESET,
            (&enable as *const u32).cast(),
            4,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error()).context("SIO_UDP_CONNRESET");
    }
    Ok(())
}
