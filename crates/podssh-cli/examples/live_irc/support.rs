//! Shared pieces of the `live_irc` probe: the attempt record, the single
//! receive-feed-respond pump, the burst builders, and the CLI small helpers.
//! One read path lives here (`pump_once`); the target flow lives in
//! `live_irc.rs` and calls in.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use podssh_core::irc::{Event, ReapPolicy, Server, Session};
use podssh_ws::client::RelaySession;
use podssh_ws::frame;
use podssh_ws::session::close_code_and_reason;

/// A forward session as bytes in and bytes out, as `podssh proxy` carries
/// it: the relay's empty keepalive frames skipped, a Close as the end.
pub struct LiveRunner {
    session: RelaySession,
    sent: usize,
}

impl LiveRunner {
    pub fn new(session: RelaySession) -> Self {
        LiveRunner { session, sent: 0 }
    }

    /// The next bytes of the target; an error at a Close, with its code and
    /// its reason.
    pub async fn recv_bytes(&mut self) -> Result<Vec<u8>, String> {
        loop {
            let f = self.session.read_frame().await.map_err(|e| e.to_string())?;
            match f.opcode {
                frame::OPCODE_BINARY if f.payload.is_empty() => {}
                frame::OPCODE_BINARY => return Ok(f.payload),
                frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    return Err(format!("relay close {} {reason}", code.unwrap_or(1005)));
                }
                _ => {}
            }
        }
    }

    /// Send `bytes` in frames of at most 32 KiB, as `podssh proxy` does.
    pub async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        for chunk in bytes.chunks(32 * 1024) {
            self.session.send_binary(chunk).await.map_err(|e| e.to_string())?;
            self.sent += 1;
        }
        Ok(())
    }

    pub fn sent_frames(&self) -> usize {
        self.sent
    }
}

/// What one target attempt established. Best-wins across targets.
#[derive(Default)]
pub struct Attempt {
    pub target: String,
    pub connected: bool,
    pub registered: bool,
    pub caps_offered: Vec<String>,
    pub caps_enabled: Vec<String>,
    pub nicklen: String,
    pub split_seen: bool,
    pub payloads: usize,
    pub echo_short: bool,
    pub echo_long: bool,
    pub echo_chan_short: bool,
    pub echo_chan_long: bool,
    pub frames_sent: usize,
}

impl Attempt {
    pub fn is_full(&self) -> bool {
        self.registered && (self.echo_short || self.echo_chan_short) && (self.echo_long || self.echo_chan_long)
    }

    /// ⛔ Registration outranks echo: closer to the proof wins.
    pub fn score(&self) -> u8 {
        (self.registered as u8) * 4 + ((self.echo_short || self.echo_chan_short) as u8) * 2 + (self.connected as u8)
    }

    /// ⛔ Counts, codes, capability names, our probe id. The token never appears.
    pub fn report(&self) {
        print!(
            "target={}\nregistered={}\ncaps_offered={}\ncaps_enabled={}\nisupport_nicklen={}\npayloads={} split_seen={}\necho_self={}/{} echo_chan={}/{}\nframes_sent={}\n",
            self.target,
            self.registered,
            self.caps_offered.join(","),
            self.caps_enabled.join(","),
            self.nicklen,
            self.payloads,
            self.split_seen,
            self.echo_short,
            self.echo_long,
            self.echo_chan_short,
            self.echo_chan_long,
            self.frames_sent
        );
    }
}

/// One receive-feed-respond step shared by every loop in the flow.
/// Closed names the failed half: relay abort and session error differ.
pub enum PumpOut {
    Events(Vec<Event>),
    Timeout,
    Closed(&'static str, String),
}

pub async fn pump_once(runner: &mut LiveRunner, irc: &mut Session, a: &mut Attempt, step: Instant) -> PumpOut {
    let payload = match tokio::time::timeout_at(step.into(), runner.recv_bytes()).await {
        Ok(Ok(p)) => p,
        // A Close names its code and reason: who ended the session.
        Ok(Err(e)) => return PumpOut::Closed("recv", e),
        Err(_) => return PumpOut::Timeout,
    };
    a.payloads += 1;
    // ⛔ A payload not ending at a line ending is a message across a frame boundary.
    if !payload.ends_with(b"\n") {
        a.split_seen = true;
    }
    let (out, events) = match irc.on_bytes(&payload) {
        Ok(v) => v,
        Err(e) => return PumpOut::Closed("session", format!("{e}")),
    };
    if send_all(runner, &out, a).await.is_err() {
        return PumpOut::Closed("send", "write failed".into());
    }
    PumpOut::Events(events)
}

/// Log numeric codes only (stderr, never bodies): 001/005/421 is the diagnosis.
pub fn log_numerics(host: &str, port: u16, events: &[Event]) {
    for e in events {
        if let Event::Numeric { code, .. } = e {
            eprintln!("podssh: {host}:{port}: numeric {code}");
        }
    }
}

/// The registration burst: CAP LS first, or NICK/USER only under `--no-cap`.
pub fn burst_for(irc: &mut Session, no_cap: bool) -> Vec<podssh_core::irc::Message> {
    if !no_cap {
        return irc.initial_burst();
    }
    let server = irc.server().clone();
    vec![podssh_core::irc::nick_message(&server.nick), podssh_core::irc::user_message(&server)]
}

/// One fresh session: the initial burst and the nick-retry rebuild share it.
pub fn new_session(host: &str, port: u16, nick: String, policy: ReapPolicy) -> Session {
    Session::new(
        Server {
            host: host.to_string(),
            port,
            nick,
            username: "podssh".to_string(),
            realname: "podssh live probe".to_string(),
        },
        policy,
    )
}

/// Write every message's wire bytes, counting frames.
pub async fn send_all(runner: &mut LiveRunner, msgs: &[podssh_core::irc::Message], a: &mut Attempt) -> Result<(), ()> {
    for m in msgs {
        let wire = m.to_wire();
        runner.send_bytes(wire.as_bytes()).await.map_err(|_| ())?;
        a.frames_sent = runner.sent_frames();
    }
    Ok(())
}

pub fn usage() -> ! {
    eprintln!("usage: live_irc [--bundle <ca-pem>] [--target <host>] [--port <n>] [--nick <nick>] [--no-cap]");
    std::process::exit(64);
}

pub fn random_hex6() -> String {
    let mut h = DefaultHasher::new();
    (std::process::id(), std::time::SystemTime::now()).hash(&mut h);
    format!("{:06x}", h.finish() & 0xffffff)
}
