//! The client's threads (SPEC §6.1): one receive thread per path socket, a
//! timer thread driving the core's timers and delayed copies, and the
//! capture backend's threads feeding outbound packets. All share one
//! [`ClientCore`] behind a mutex; I/O happens after the lock is released,
//! via per-thread [`Outbox`]es.

use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use skyblock_proto::Micros;
use skyblock_proto::handshake::ServerHello;
use skyblock_proto::ip::Ipv4Packet;
use skyblock_proto::sched::Policy;
use skyblock_sys::prio::boost_current_thread;
use skyblock_sys::timer::Waiter;
use tracing::{debug, warn};

use crate::capture::Capture;
use crate::config::Node;
use crate::core::{ClientCore, ClientIo, Snapshot};

/// Receives echo responses (`bench`): arrival time, id, send timestamp.
pub type EchoSink = Box<dyn Fn(Micros, u32, u64) + Send + Sync>;

/// Packets produced under the core lock, sent/injected after it is dropped.
#[derive(Default)]
pub struct Outbox {
    buf: Vec<u8>,
    sends: Vec<(usize, Range<usize>)>,
    delivers: Vec<Range<usize>>,
    echoes: Vec<(Micros, u32, u64)>,
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
        self.echoes.push((now, id, ts));
    }
}

thread_local! {
    static OUTBOX: RefCell<Outbox> = RefCell::new(Outbox::default());
}

pub struct Tunnel {
    core: Mutex<ClientCore>,
    socks: Vec<UdpSocket>,
    start: Instant,
    capture: OnceLock<Arc<dyn Capture>>,
    echo: OnceLock<EchoSink>,
    waiter: Waiter,
    /// When the timer thread plans to wake next; senders that schedule
    /// something earlier wake it.
    wake_at: AtomicU64,
}

impl Tunnel {
    /// Opens one connected UDP socket per path and starts the receive and
    /// timer threads.
    pub fn start(core: ClientCore, node: &Node, n_paths: usize) -> Result<Arc<Tunnel>> {
        let mut socks = Vec::with_capacity(n_paths);
        for i in 0..n_paths {
            let peer = SocketAddr::from((node.addr, node.ports[i % node.ports.len()]));
            let sock = UdpSocket::bind(("0.0.0.0", 0)).context("binding UDP socket")?;
            sock.connect(peer)
                .with_context(|| format!("connecting to {peer}"))?;
            #[cfg(windows)]
            disable_udp_connreset(&sock)?;
            socks.push(sock);
        }
        let t = Arc::new(Tunnel {
            core: Mutex::new(core),
            socks,
            start: Instant::now(),
            capture: OnceLock::new(),
            echo: OnceLock::new(),
            waiter: Waiter::new().context("creating timer")?,
            wake_at: AtomicU64::new(0),
        });
        for path in 0..n_paths {
            let rx = Arc::clone(&t);
            std::thread::Builder::new()
                .name(format!("path-{path}"))
                .spawn(move || rx.rx_loop(path))?;
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

    pub fn set_capture(&self, capture: Arc<dyn Capture>) {
        let _ = self.capture.set(capture);
    }

    pub fn set_echo_sink(&self, sink: EchoSink) {
        let _ = self.echo.set(sink);
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

    fn rx_loop(&self, path: usize) {
        let boost = boost_current_thread();
        debug!(path, ?boost, "receive thread");
        let sock = &self.socks[path];
        let mut buf = vec![0u8; 65536];
        let mut out = Outbox::default();
        loop {
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    // ICMP errors and interrupted calls are transient.
                    if !matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset
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

    fn flush(&self, out: &mut Outbox) {
        for (path, r) in out.sends.drain(..) {
            if let Err(e) = self.socks[path].send(&out.buf[r]) {
                debug!(path, "node send: {e}");
            }
        }
        if let Some(c) = self.capture.get() {
            for r in out.delivers.drain(..) {
                c.inject(&mut out.buf[r]);
            }
        }
        out.delivers.clear();
        if let Some(sink) = self.echo.get() {
            for (now, id, ts) in out.echoes.drain(..) {
                sink(now, id, ts);
            }
        }
        out.echoes.clear();
        out.buf.clear();
    }
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
