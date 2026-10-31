//! TCP inside the tunnel: smoltcp's interface, with the device's addresses,
//! over the queues of [`crate::phy`], driven by one task of this process.
//! The tunnel gives IP packets and takes them; TCP's segments, its windows
//! and its retransmissions are smoltcp's. Cloudflare says that smoltcp
//! "does not support modern TCP features" (T-352's Premise): no SACK, a
//! simple congestion control; the link under it is HTTP/2 over TCP, which
//! loses nothing, so the inner TCP mostly never sends again.
//!
//! The same stack is the far end of the stand-in ([`crate::stand_in`]),
//! which takes connections inside its tunnel (`crate::inside`, compiled
//! with the stand-in alone): sockets of smoltcp in this process, never one
//! of the system.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rustls::crypto::SecureRandom as _;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{mpsc, Notify};
use tokio::task::AbortHandle;

use crate::phy::Queue;
use crate::stream::Stream;

/// Each direction's buffer of one TCP connection: the window that one
/// connection may have in flight.
pub const BUFFER: usize = 256 * 1024;
/// A keep-alive on a silent connection, so that a dead far end is found,
/// and how long an unanswered segment waits before the connection ends.
const KEEP_ALIVE: u64 = 25;
const TIMEOUT: u64 = 120;
/// The longest the driver sleeps with nothing to do.
const IDLE: Duration = Duration::from_secs(60);
/// The ports of this end of a connection: the dynamic range (RFC 6335).
const PORTS: std::ops::RangeInclusive<u16> = 49_152..=65_535;

/// Why the tunnel ended: the first part that saw the end says it, and each
/// part that waits on the tunnel's end ([`Why::ended`]) stops.
#[derive(Debug, Clone)]
pub struct Why(Arc<Said>);

#[derive(Debug)]
struct Said {
    slot: Mutex<Option<String>>,
    ended: tokio::sync::watch::Sender<bool>,
}

impl Default for Why {
    fn default() -> Why {
        Why(Arc::new(Said { slot: Mutex::new(None), ended: tokio::sync::watch::Sender::new(false) }))
    }
}

impl Why {
    pub fn set(&self, why: impl Into<String>) {
        let mut slot = self.0.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(why.into());
        }
        drop(slot);
        self.0.ended.send_replace(true);
    }

    pub fn get(&self) -> Option<String> {
        self.0.slot.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Wait until a part has said the end.
    pub async fn ended(&self) {
        let mut said = self.0.ended.subscribe();
        let _ = said.wait_for(|ended| *ended).await;
    }
}

/// A tunnel, as the stack takes it: the packets that go out, those that
/// come in (the channel ends with the tunnel), why it ended, and its tasks,
/// which end with the stack.
pub struct Link {
    pub out: mpsc::Sender<Vec<u8>>,
    pub inbound: mpsc::Receiver<Vec<u8>>,
    pub why: Why,
    pub tasks: Vec<AbortHandle>,
}

pub(crate) struct Inner {
    iface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) phy: Queue,
    next_port: u16,
    pub(crate) live: Vec<SocketHandle>,
    pub(crate) closing: Vec<SocketHandle>,
    pub(crate) ended: Option<String>,
    born: tokio::time::Instant,
}

impl Inner {
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.born.elapsed().as_micros() as i64)
    }

    /// A port of this end that no connection holds.
    fn port(&mut self) -> u16 {
        let used: Vec<u16> = self
            .live
            .iter()
            .chain(&self.closing)
            .filter_map(|h| self.sockets.get::<tcp::Socket>(*h).local_endpoint().map(|e| e.port))
            .collect();
        for _ in PORTS {
            let port = self.next_port;
            self.next_port = if port == *PORTS.end() { *PORTS.start() } else { port + 1 };
            if !used.contains(&port) {
                return port;
            }
        }
        self.next_port
    }

    /// The sockets of closed connections, removed once their FIN is done.
    fn reap(&mut self) {
        let sockets = &mut self.sockets;
        self.closing.retain(|h| {
            let gone = matches!(sockets.get::<tcp::Socket>(*h).state(), tcp::State::Closed | tcp::State::TimeWait);
            if gone {
                sockets.remove(*h);
            }
            !gone
        });
    }
}

pub(crate) struct Shared {
    inner: Mutex<Inner>,
    pub(crate) wake: Notify,
}

impl Shared {
    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The end of the tunnel: each connection is aborted, which wakes each
    /// read and write that waits, and says `why`.
    fn end(&self, why: String) {
        let mut inner = self.lock();
        if inner.ended.is_none() {
            inner.ended = Some(why);
        }
        let handles: Vec<SocketHandle> = inner.live.iter().chain(&inner.closing).copied().collect();
        for handle in handles {
            inner.sockets.get_mut::<tcp::Socket>(handle).abort();
        }
    }
}

/// What the stack's streams share; its tasks end when the last one goes.
pub(crate) struct Core {
    pub(crate) shared: Arc<Shared>,
    tasks: Vec<AbortHandle>,
    addresses: Vec<IpAddr>,
    why: Why,
}

impl Drop for Core {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The stack over one tunnel.
#[derive(Clone)]
pub struct Stack {
    core: Arc<Core>,
}

impl std::fmt::Debug for Stack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stack").field("addresses", &self.core.addresses).finish_non_exhaustive()
    }
}

/// A TCP socket of smoltcp with podssh's settings: no Nagle, as a
/// keystroke must not wait; a keep-alive, and an end to a silent far end.
pub(crate) fn socket() -> tcp::Socket<'static> {
    let (rx, tx) = (tcp::SocketBuffer::new(vec![0u8; BUFFER]), tcp::SocketBuffer::new(vec![0u8; BUFFER]));
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_nagle_enabled(false);
    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(KEEP_ALIVE)));
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(TIMEOUT)));
    socket
}

/// Eight random bytes of this host.
fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    let _ = podssh_ws::crypto::random::OsRandom.fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

impl Stack {
    /// The stack of a device with `addresses` (one of each family at most,
    /// as smoltcp keeps two), over `link`; its driver starts at once.
    pub fn start(addresses: &[IpAddr], link: Link) -> Result<Stack, String> {
        if addresses.is_empty() || addresses.len() > 2 {
            return Err(format!("{} addresses inside the tunnel, where the stack takes one or two", addresses.len()));
        }
        let mut phy = Queue::new(crate::MTU);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random_u64();
        let mut iface = Interface::new(config, &mut phy, smoltcp::time::Instant::from_micros(0));
        iface.update_ip_addrs(|ips| {
            for address in addresses {
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                let _ = ips.push(IpCidr::new(IpAddress::from(*address), prefix));
            }
        });
        // Each destination is off the device's own /32 or /128: each goes
        // to the tunnel, the only link, as a default route via itself says.
        for address in addresses {
            let _ = match address {
                IpAddr::V4(v4) => iface.routes_mut().add_default_ipv4_route(*v4).map(|_| ()),
                IpAddr::V6(v6) => iface.routes_mut().add_default_ipv6_route(*v6).map(|_| ()),
            };
        }
        let span = u64::from(*PORTS.end() - *PORTS.start()) + 1;
        let first = *PORTS.start() + (random_u64() % span) as u16;
        let inner = Inner {
            iface,
            sockets: SocketSet::new(vec![]),
            phy,
            next_port: first,
            live: Vec::new(),
            closing: Vec::new(),
            ended: None,
            born: tokio::time::Instant::now(),
        };
        let shared = Arc::new(Shared { inner: Mutex::new(inner), wake: Notify::new() });
        let Link { out, inbound, why, mut tasks } = link;
        let driver = tokio::spawn(drive(shared.clone(), inbound, out, why.clone()));
        tasks.push(driver.abort_handle());
        Ok(Stack { core: Arc::new(Core { shared, tasks, addresses: addresses.to_vec(), why }) })
    }

    /// Wait until the tunnel has ended.
    pub async fn closed(&self) {
        self.core.why.ended().await;
    }

    /// The device's addresses inside the tunnel.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.core.addresses
    }

    /// Why the tunnel ended, once it has.
    pub fn ended(&self) -> Option<String> {
        self.core.shared.lock().ended.clone()
    }

    /// A TCP connection to `to` inside the tunnel, open within `limit`.
    pub async fn connect(&self, to: SocketAddr, limit: Duration) -> Result<Stream, String> {
        if !self.core.addresses.iter().any(|a| a.is_ipv4() == to.is_ipv4()) {
            let family = if to.is_ipv4() { 4 } else { 6 };
            return Err(format!("{to}: the tunnel gave this device no IPv{family} address"));
        }
        let handle = {
            let mut inner = self.core.shared.lock();
            if let Some(why) = &inner.ended {
                return Err(format!("{to}: the tunnel has ended: {why}"));
            }
            let port = inner.port();
            let mut socket = socket();
            socket.connect(inner.iface.context(), to, port).map_err(|e| format!("{to}: {e}"))?;
            let handle = inner.sockets.add(socket);
            inner.live.push(handle);
            handle
        };
        self.core.shared.wake.notify_one();
        // On an error, the stream's drop closes its socket.
        let stream = Stream::new(self.core.clone(), handle);
        match tokio::time::timeout(limit, stream.established()).await {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(why)) => Err(format!("{to}: {why}")),
            Err(_) => Err(format!("{to}: no answer inside the tunnel within {} s", limit.as_secs())),
        }
    }

    /// What the stack's streams share, for a listener of the stand-in.
    #[cfg(any(test, feature = "stand-in"))]
    pub(crate) fn core(&self) -> &Arc<Core> {
        &self.core
    }
}

/// The driver: smoltcp polled, its packets out to the tunnel, the tunnel's
/// packets in, and a sleep until the next timer of TCP, a packet, or a
/// stream's word; until the tunnel ends.
async fn drive(shared: Arc<Shared>, mut inbound: mpsc::Receiver<Vec<u8>>, out: mpsc::Sender<Vec<u8>>, why: Why) {
    loop {
        let (sent, wait) = {
            let mut guard = shared.lock();
            let now = guard.now();
            let inner = &mut *guard;
            inner.iface.poll(now, &mut inner.phy, &mut inner.sockets);
            let wait = inner.iface.poll_delay(now, &inner.sockets).map(Duration::from).unwrap_or(IDLE);
            inner.reap();
            (std::mem::take(&mut inner.phy.outbound), wait)
        };
        for packet in sent {
            if out.send(packet).await.is_err() {
                why.set("the tunnel stopped taking packets");
                shared.end(why.get().unwrap_or_default());
                return;
            }
        }
        tokio::select! {
            packet = inbound.recv() => match packet {
                Some(packet) => {
                    let mut inner = shared.lock();
                    inner.phy.arrive(packet);
                    while let Ok(more) = inbound.try_recv() {
                        inner.phy.arrive(more);
                    }
                }
                None => {
                    why.set("the tunnel ended");
                    shared.end(why.get().unwrap_or_default());
                    return;
                }
            },
            () = shared.wake.notified() => {}
            () = tokio::time::sleep(wait) => {}
        }
    }
}
