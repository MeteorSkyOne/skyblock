//! The client's threads (SPEC §6.1): a receive thread for the node socket,
//! a control thread driving timers, and the capture backend's threads
//! feeding outbound packets. All share one [`ClientCore`] behind a mutex;
//! I/O happens after the lock is released, via per-thread [`Outbox`]es.

use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use skyblock_proto::Micros;
use skyblock_proto::handshake::ServerHello;
use skyblock_proto::ip::Ipv4Packet;
use tracing::{debug, warn};

use crate::capture::Capture;
use crate::config::Node;
use crate::core::{ClientCore, ClientIo, ClientStats};

/// Longest the control thread sleeps, so shutdown and status stay prompt.
const CONTROL_MAX_SLEEP: Duration = Duration::from_millis(50);

/// Packets produced under the core lock, sent/injected after it is dropped.
#[derive(Default)]
pub struct Outbox {
    buf: Vec<u8>,
    sends: Vec<Range<usize>>,
    delivers: Vec<Range<usize>>,
}

impl Outbox {
    fn push(&mut self, data: &[u8]) -> Range<usize> {
        let start = self.buf.len();
        self.buf.extend_from_slice(data);
        start..self.buf.len()
    }
}

impl ClientIo for Outbox {
    fn send(&mut self, pkt: &[u8]) {
        let r = self.push(pkt);
        self.sends.push(r);
    }

    fn deliver(&mut self, ip: &[u8]) {
        let r = self.push(ip);
        self.delivers.push(r);
    }
}

thread_local! {
    static OUTBOX: RefCell<Outbox> = RefCell::new(Outbox::default());
}

pub struct Tunnel {
    core: Mutex<ClientCore>,
    sock: UdpSocket,
    start: Instant,
    capture: OnceLock<Arc<dyn Capture>>,
}

impl Tunnel {
    /// Connects the node socket and starts the receive and control threads.
    pub fn start(core: ClientCore, node: &Node) -> Result<Arc<Tunnel>> {
        let peer = SocketAddr::from((node.addr, node.ports[0]));
        let sock = UdpSocket::bind(("0.0.0.0", 0)).context("binding UDP socket")?;
        sock.connect(peer)
            .with_context(|| format!("connecting to {peer}"))?;
        #[cfg(windows)]
        disable_udp_connreset(&sock)?;

        let t = Arc::new(Tunnel {
            core: Mutex::new(core),
            sock,
            start: Instant::now(),
            capture: OnceLock::new(),
        });
        let rx = Arc::clone(&t);
        std::thread::Builder::new()
            .name("node-rx".into())
            .spawn(move || rx.rx_loop())?;
        let ctl = Arc::clone(&t);
        std::thread::Builder::new()
            .name("control".into())
            .spawn(move || ctl.control_loop())?;
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

    pub fn stats(&self) -> (ClientStats, Option<ServerHello>) {
        let c = self.core();
        (c.stats, c.hello())
    }

    /// Sends an outbound IPv4 packet from the capture backend.
    pub fn send_ip(&self, pkt: &[u8]) {
        if Ipv4Packet::parse(pkt).is_err() {
            return;
        }
        let now = self.now();
        OUTBOX.with_borrow_mut(|out| {
            self.core().send_ip(now, pkt, out);
            self.flush(out);
        });
    }

    /// Sends CLOSE so the node can drop the session right away.
    pub fn close(&self) {
        let mut out = Outbox::default();
        self.core().close(&mut out);
        self.flush(&mut out);
    }

    fn rx_loop(&self) {
        let mut buf = vec![0u8; 65536];
        let mut out = Outbox::default();
        loop {
            let n = match self.sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    // ICMP errors and interrupted calls are transient.
                    if !matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::Interrupted
                    ) {
                        warn!("node socket: {e}");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    continue;
                }
            };
            let now = self.now();
            self.core().handle_datagram(now, &mut buf[..n], &mut out);
            self.flush(&mut out);
        }
    }

    fn control_loop(&self) {
        let mut out = Outbox::default();
        loop {
            let now = self.now();
            let deadline = self.core().poll(now, &mut out);
            self.flush(&mut out);
            let wait = Duration::from_micros(deadline.saturating_sub(self.now()));
            std::thread::sleep(wait.min(CONTROL_MAX_SLEEP));
        }
    }

    fn flush(&self, out: &mut Outbox) {
        for r in out.sends.drain(..) {
            if let Err(e) = self.sock.send(&out.buf[r]) {
                debug!("node send: {e}");
            }
        }
        if let Some(c) = self.capture.get() {
            for r in out.delivers.drain(..) {
                c.inject(&mut out.buf[r]);
            }
        }
        out.delivers.clear();
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
