//! A file between two clients through a real IRC server (T-097): the
//! sender's chunks and the receiver's acknowledgements cross the server,
//! which relays each line with its sender's prefix, and the file arrives
//! whole, with the same SHA-256. Each side paces its lines (T-275), so a
//! server that closes a fast client lets this one through. Ignored unless
//! `PODSSH_IRC_SERVER` names a server, as HOST:PORT;
//! `PODSSH_IRC_TRANSFER_BYTES` sets the size (2000 by default, as a server's
//! flood control slows a client that sends fast).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use podssh_core::irc::reap::ReapPolicy;
use podssh_core::irc::session::{Registered, Server, Session};
use podssh_core::irc::transfer::{chunk_bytes, Line, Pace, Receiver, Sender};
use podssh_core::irc::{Event, Message, TransferLimits};

const LIMIT: Duration = Duration::from_secs(120);

/// The pace of each side: the default, or `PODSSH_IRC_TRANSFER_PACE` lines a
/// second with as many at once, as for the planted run with none.
fn pace() -> Pace {
    match std::env::var("PODSSH_IRC_TRANSFER_PACE").ok().and_then(|v| v.parse().ok()) {
        Some(rate) => Pace::new(rate, rate),
        None => Pace::default(),
    }
}

/// One client: its socket, its session, and the pace of its transfer's
/// lines (T-275).
struct Client {
    stream: TcpStream,
    session: Session,
    pace: Pace,
}

impl Client {
    fn connect(address: &str, nick: &str) -> Client {
        let (host, port) = address.rsplit_once(':').expect("HOST:PORT");
        let server = Server {
            host: host.into(),
            port: port.parse().expect("a port"),
            nick: nick.into(),
            username: nick.into(),
            realname: "podssh test".into(),
        };
        let stream = TcpStream::connect(address).expect("the server answers");
        stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut client = Client { stream, session: Session::new(server, ReapPolicy::default()), pace: pace() };
        let burst = client.session.initial_burst();
        client.send(&burst);
        client
    }

    /// A transfer's line, when its turn comes.
    fn send_paced(&mut self, message: Message) {
        std::thread::sleep(self.pace.wait(Instant::now()));
        self.pace.sent(Instant::now());
        self.send(&[message]);
    }

    fn send(&mut self, messages: &[Message]) {
        for message in messages {
            let wire = message.to_wire().expect("a line that is safe to write");
            self.stream.write_all(wire.as_bytes()).expect("the server takes the line");
        }
    }

    /// Read what has come, answer what the session must, and give the events.
    fn pump(&mut self) -> Vec<Event> {
        let mut buf = [0u8; 16384];
        match self.stream.read(&mut buf) {
            Ok(0) => panic!("{}: the server closed the connection", self.session.nick()),
            Ok(n) => {
                let (out, events) = self.session.on_bytes(&buf[..n]);
                self.send(&out);
                events
            }
            Err(_) => Vec::new(),
        }
    }

    /// Pump until `want` gives a value, within the limit.
    fn until<T>(&mut self, what: &str, mut want: impl FnMut(&mut Client, &Event) -> Option<T>) -> T {
        let started = Instant::now();
        loop {
            assert!(started.elapsed() < LIMIT, "{}: no {what} within {LIMIT:?}", self.session.nick());
            for event in self.pump() {
                if let Some(value) = want(self, &event) {
                    return value;
                }
            }
        }
    }
}

#[test]
#[ignore = "a real IRC server: PODSSH_IRC_SERVER=HOST:PORT"]
fn a_file_crosses_the_server_between_two_clients() {
    let Ok(address) = std::env::var("PODSSH_IRC_SERVER") else {
        eprintln!("skipped: PODSSH_IRC_SERVER names no server");
        return;
    };
    let total: usize = std::env::var("PODSSH_IRC_TRANSFER_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
    let id = std::process::id() % 1_000_000;
    let channel = format!("#pt{id}");
    let mut a = Client::connect(&address, &format!("pa{id}"));
    let mut b = Client::connect(&address, &format!("pb{id}"));
    for client in [&mut a, &mut b] {
        client.until("welcome", |c, _| (c.session.registered() == Registered::Yes).then_some(()));
        let join = client.session.send_join(&channel, None).expect("a channel that is safe");
        client.send(&join);
        client.until("join", |_, e| matches!(e, Event::Joined { .. }).then_some(()));
    }
    // a sees b in the channel, so the offer reaches b.
    a.until("b's join", |_, e| matches!(e, Event::PeerJoined { .. }).then_some(()));

    let data: Vec<u8> = (0..total).map(|i| (i * 7 % 251) as u8).collect();
    let size = chunk_bytes(a.session.isupport(), &channel, "t1", total as u64).expect("room for a chunk");
    let limits = TransferLimits { chunk_bytes: size, ..TransferLimits::default() };
    let mut sender = Sender::new("t1", "f.bin", total as u64, limits).expect("a safe id and name");
    let offer = sender.offer(&channel);
    a.send(&[offer]);
    let mut receiver = b.until("offer", |_, e| match e {
        Event::Transfer { line: Line::Offer(o), .. } => Some(Receiver::from_offer(o).expect("the offer is accepted")),
        _ => None,
    });
    let mut written = Vec::new();
    while let Some((offset, len)) = sender.next_range() {
        let chunk = sender.next_chunk_message(&channel, &data[offset as usize..offset as usize + len]).unwrap();
        a.send_paced(chunk);
        let bytes = b.until("chunk", |_, e| match e {
            Event::Transfer { line: Line::Chunk(c), .. } => Some(c.clone()),
            _ => None,
        });
        written.extend(receiver.accept(&bytes).expect("the chunk, whole and in order"));
        let ack = receiver.ack(&channel);
        b.send_paced(ack);
        let index = a.until("ack", |_, e| match e {
            Event::Transfer { line: Line::Ack(k), .. } => Some(k.index),
            _ => None,
        });
        assert!(sender.acknowledge(index), "the ack named {index}");
    }
    assert!(sender.is_complete() && receiver.is_complete());
    assert_eq!(written, data, "the file arrived as it was sent");
    use sha2::Digest as _;
    assert!(receiver.verify(&hex::encode(sha2::Sha256::digest(&data))));
    eprintln!("{total} bytes in {} chunks of {size} through {address}", sender.chunks());
    for client in [&mut a, &mut b] {
        let _ = client.stream.write_all(b"QUIT :done\r\n");
    }
}
