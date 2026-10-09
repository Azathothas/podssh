//! A stand-in relay on the loopback, with blocking sockets, for the tests of
//! the blocking facade: it answers each upgrade with the 101 of
//! `scripts/fake-relay.py`, and then writes frames as the live relay did
//! (`scripts/capture-reverse.py`). The tokens are test strings of the
//! measured shape.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::pair::{self, Pair};
use podssh_relay::relay::Relay;
use podssh_ws::frame::{self, Frame, Role};

pub const NAME: &str = "podssh-test-pair-0123456789abcdef0";
pub const NODE: &str = "testonlynode0000000000000000000000000000000000000000000000000000";
pub const CONNECT: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
const STOP: &str = "testonlystop0000000000000000000000000000000000000000000000000000";
pub const ID1: &str = "4914e9e009a64fcb88d47bb8bd1a8417";
pub const ID2: &str = "0123456789abcdef0123456789abcdef";
pub const LIMIT: Duration = Duration::from_secs(10);

/// A pair on `relay` named `name`, made `made_ms_ago` ago, for 72 hours.
pub fn test_pair(relay: &Relay, name: &str, made_ms_ago: i64) -> Pair {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let made = now - made_ms_ago;
    let body = format!(
        r#"{{"name":"{name}","node_token":"{NODE}","connect_token":"{CONNECT}","stop_token":"{STOP}","expires":{}}}"#,
        made + 72 * 3600 * 1000
    );
    pair::parse(relay, body.as_bytes(), made).expect("a test pair")
}

pub fn open(id: &str) -> String {
    format!(r#"{{"type":"open","id":"{id}"}}"#)
}

pub fn ready(id: &str) -> String {
    format!(r#"{{"type":"ready","id":"{id}"}}"#)
}

/// A node frame: the id, then the payload.
pub fn data(id: &str, payload: &[u8]) -> Vec<u8> {
    [id.as_bytes(), payload].concat()
}

/// A pipe in memory: what goes into the writer comes out of the reader,
/// which ends when the writer is dropped.
pub fn pipe() -> (PipeReader, PipeWriter) {
    let (tx, rx) = mpsc::channel();
    (PipeReader { rx, pending: Vec::new(), at: 0 }, PipeWriter(tx))
}

pub struct PipeReader {
    rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    at: usize,
}

impl Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.at == self.pending.len() {
            match self.rx.recv() {
                Ok(bytes) => (self.pending, self.at) = (bytes, 0),
                Err(_) => return Ok(0),
            }
        }
        let n = (self.pending.len() - self.at).min(buf.len());
        buf[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

pub struct PipeWriter(mpsc::Sender<Vec<u8>>);

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf.to_vec()).map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A writer whose bytes the test reads afterwards.
#[derive(Clone, Default)]
pub struct Shared(Arc<Mutex<Vec<u8>>>);

impl Shared {
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct StandIn {
    listener: TcpListener,
}

impl StandIn {
    pub fn new() -> (StandIn, Relay) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port on the loopback");
        let port = listener.local_addr().unwrap().port();
        (StandIn { listener }, Relay { host: "127.0.0.1".into(), port })
    }

    /// The next connection's request head, and the connection.
    fn head(&self) -> (String, TcpStream) {
        let (mut tcp, _) = self.listener.accept().expect("a connection");
        tcp.set_read_timeout(Some(LIMIT)).unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).expect("a request head");
            head.push(byte[0]);
        }
        (String::from_utf8(head).expect("a text head"), tcp)
    }

    /// Answer the next upgrade with 101: its head, and the session.
    pub fn accept(&self) -> (String, Peer) {
        let (head, mut tcp) = self.head();
        let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).expect("a key").trim().to_string();
        let accept = podssh_ws::handshake::accept_key(&key);
        write!(
            tcp,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .unwrap();
        (head, Peer { tcp, buf: Vec::new() })
    }

    /// Answer the next upgrade with `status` and `body`, as the relay refuses.
    pub fn refuse(&self, status: u16, body: &str) {
        let (_, mut tcp) = self.head();
        write!(tcp, "HTTP/1.1 {status} Refused\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
            .unwrap();
    }
}

/// The relay's end of one session.
pub struct Peer {
    tcp: TcpStream,
    buf: Vec<u8>,
}

impl Peer {
    pub fn send(&mut self, opcode: u8, payload: &[u8]) {
        let bytes = frame::encode(&Frame { fin: true, opcode, payload: payload.to_vec() }, Role::Server, [0; 4]);
        self.tcp.write_all(&bytes).unwrap();
    }

    pub fn text(&mut self, text: &str) {
        self.send(frame::OPCODE_TEXT, text.as_bytes());
    }

    pub fn close(&mut self, code: u16, reason: &str) {
        let payload = [&code.to_be_bytes()[..], reason.as_bytes()].concat();
        self.send(frame::OPCODE_CLOSE, &payload);
    }

    /// The client's next frame other than a Ping, which is answered; `None`
    /// after `wait`, or at the end of the connection.
    pub fn next(&mut self, wait: Duration) -> Option<Frame> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some((f, used)) = frame::decode(&self.buf, Role::Client).expect("a valid client frame") {
                self.buf.drain(..used);
                if f.opcode == frame::OPCODE_PING {
                    self.send(frame::OPCODE_PONG, &f.payload);
                    continue;
                }
                return Some(f);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            self.tcp.set_read_timeout(Some(left.max(Duration::from_millis(1)))).unwrap();
            let mut chunk = [0u8; 16 * 1024];
            match self.tcp.read(&mut chunk) {
                Ok(0) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return None,
                Err(e) => panic!("the stand-in could not read: {e}"),
            }
        }
    }

    /// The client's next frame, which must be text.
    pub fn next_text(&mut self) -> String {
        let f = self.next(LIMIT).expect("a text frame");
        assert_eq!(f.opcode, frame::OPCODE_TEXT, "{f:?}");
        String::from_utf8(f.payload).expect("UTF-8")
    }

    /// A node's data frames, by id, until they hold `total` bytes.
    pub fn node_bytes(&mut self, total: usize) -> Vec<(String, Vec<u8>)> {
        let mut by_id: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        while by_id.values().map(Vec::len).sum::<usize>() < total {
            let f = self.next(LIMIT).expect("a data frame");
            assert_eq!(f.opcode, frame::OPCODE_BINARY, "{f:?}");
            let (id, payload) = f.payload.split_at(32);
            by_id.entry(String::from_utf8(id.to_vec()).unwrap()).or_default().extend_from_slice(payload);
        }
        by_id.into_iter().collect()
    }
}
