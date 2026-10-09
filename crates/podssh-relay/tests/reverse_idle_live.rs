//! Whether the relay cuts a quiet session of the reverse road (T-061), on
//! request only: `cargo test -p podssh-relay --features pair --test
//! reverse_idle_live -- --ignored --nocapture --test-threads 1`.
//!
//! Each run makes its own pair, opens the node's socket and an operator's,
//! and one session between them. It keeps the session quiet in its own way
//! for 240 s, then sends one byte each way: a socket that the relay put to
//! sleep can stay open and deliver nothing. Then it stops the pair. It prints
//! what each socket saw, and no token.
#![cfg(feature = "pair")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::pair::{self, Pair, PairContext};
use podssh_relay::relay::{node_path, operator_path};
use podssh_relay::reverse::control::{self, NodeInbound, NodeOutbound};
use podssh_relay::reverse::framing::legs::{decode_node_frame, encode_node_frame};
use podssh_relay::reverse::SessionId;
use podssh_relay::{Relay, DEFAULT_RELAY_HOST};
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE, OPCODE_TEXT};
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{connect, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};
use tokio::sync::mpsc;

/// How long a run keeps its session quiet: past the 180 s of payload
/// inactivity that the contract names for an idle session.
const QUIET: Duration = Duration::from_secs(240);
/// A step of the setup, and the wait for a byte to arrive.
const STEP: Duration = Duration::from_secs(15);
/// No run takes longer, so each run ends with a result, never with a hang.
const RUN_LIMIT: Duration = Duration::from_secs(420);

/// What a run does while its session is quiet.
#[derive(Clone, Copy, Debug)]
enum Keep {
    /// No payload, and no Ping from podssh.
    Nothing,
    /// A Ping from the node's end, the operator's end or both, this often.
    Pings { every: Duration, node: bool, operator: bool },
    /// One byte each way, this often: the control.
    Payload(Duration),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Node,
    Operator,
}

/// One thing that a socket's reader saw.
#[derive(Debug)]
enum Seen {
    Data(Vec<u8>),
    Control(String),
    /// The relay's `close` for the session, on the node's socket.
    SessionClosed(String),
    Closed { code: Option<u16>, reason: String },
    Failed(String),
}

type Event = (Side, Duration, Seen);

/// What the readers saw, and how each socket ended.
#[derive(Default)]
struct State {
    to_node: Vec<u8>,
    to_operator: Vec<u8>,
    data_frames: u64,
    controls: u64,
    session_end: Option<(Duration, String)>,
    node_end: Option<(Duration, String)>,
    operator_end: Option<(Duration, String)>,
    log: Vec<String>,
}

impl State {
    fn take(&mut self, (side, at, seen): Event) {
        let when = format!("{:>6.1} s", at.as_secs_f64());
        match seen {
            Seen::Data(bytes) => {
                self.data_frames += 1;
                match side {
                    Side::Node => self.to_node.extend(bytes),
                    Side::Operator => self.to_operator.extend(bytes),
                }
            }
            Seen::Control(text) => {
                self.controls += 1;
                self.log.push(format!("{when} {side:?} got the control {}", short(&text)));
            }
            Seen::SessionClosed(reason) => {
                self.controls += 1;
                let what = format!("the relay's close of the session, reason {:?}", short(&reason));
                self.log.push(format!("{when} {side:?} got {what}"));
                self.session_end = Some((at, what));
            }
            Seen::Closed { code, reason } => {
                let what = format!("a Close, code {code:?}, reason {:?}", short(&reason));
                self.log.push(format!("{when} {side:?} got {what}"));
                *self.end_of(side) = Some((at, what));
            }
            Seen::Failed(why) => {
                let what = format!("a failure: {}", short(&why));
                self.log.push(format!("{when} {side:?} read {what}"));
                *self.end_of(side) = Some((at, what));
            }
        }
    }

    fn end_of(&mut self, side: Side) -> &mut Option<(Duration, String)> {
        match side {
            Side::Node => &mut self.node_end,
            Side::Operator => &mut self.operator_end,
        }
    }

    fn both_ended(&self) -> bool {
        self.node_end.is_some() && self.operator_end.is_some()
    }

    /// A byte may go out: the session and both sockets are still open.
    fn may_send(&self) -> bool {
        self.session_end.is_none() && self.node_end.is_none() && self.operator_end.is_none()
    }
}

/// What a run measured.
struct Outcome {
    label: &'static str,
    state: State,
    /// The periodic bytes that each side sent, before the last byte.
    sent_each_way: usize,
    /// The bytes that the node and the operator had received before the
    /// last byte: the first byte and the periodic ones.
    before: (usize, usize),
    /// The last byte after the quiet, for each direction: `None` when the
    /// session or a socket had ended, so nothing was sent.
    last_to_node: Option<bool>,
    last_to_operator: Option<bool>,
    pongs: (u64, u64),
    heard: (u64, u64),
}

impl Outcome {
    fn print(&self) {
        let open = |end: &Option<(Duration, String)>| match end {
            Some((at, what)) => format!("ended at {:.1} s with {what}", at.as_secs_f64()),
            None => format!("open at {} s", QUIET.as_secs()),
        };
        let byte = |got: Option<bool>| match got {
            Some(true) => "delivered",
            Some(false) => "NOT delivered",
            None => "not sent: the session or a socket had ended",
        };
        eprintln!("T-061 run {}", self.label);
        eprintln!("  the session:       {}", open(&self.state.session_end));
        eprintln!("  node's socket:     {}", open(&self.state.node_end));
        eprintln!("  operator's socket: {}", open(&self.state.operator_end));
        eprintln!("  the last byte to the node: {}", byte(self.last_to_node));
        eprintln!("  the last byte to the operator: {}", byte(self.last_to_operator));
        eprintln!(
            "  periodic bytes sent each way: {}; received: by the node {}, by the operator {}",
            self.sent_each_way,
            self.before.0.saturating_sub(1),
            self.before.1.saturating_sub(1)
        );
        eprintln!("  Pongs received: node {}, operator {}", self.pongs.0, self.pongs.1);
        eprintln!(
            "  frames heard: node {}, operator {} (data {}, controls {})",
            self.heard.0, self.heard.1, self.state.data_frames, self.state.controls
        );
        for line in &self.state.log {
            eprintln!("  {line}");
        }
    }
}

fn short(text: &str) -> String {
    let one: String = text.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
    one.chars().take(200).collect()
}

fn relay() -> Relay {
    Relay { host: DEFAULT_RELAY_HOST.into(), port: 443 }
}

fn socket_config(relay: &Relay, path: String) -> WsClientConfig {
    WsClientConfig {
        endpoint: Endpoint { host: relay.host.clone(), port: relay.port, path },
        trust: Trust::Default,
        server_name: relay.host.clone(),
        timeout: STEP,
        // The relay's cut is measured, not podssh's.
        idle_timeout: None,
        proxy: ProxyChoice::FromEnvironment,
    }
}

/// The next text frame, before the readers run.
async fn next_text(session: &RelaySession, what: &str) -> Result<String, String> {
    let frame = tokio::time::timeout(STEP, session.read_frame())
        .await
        .map_err(|_| format!("no {what} within {} s", STEP.as_secs()))?
        .map_err(|e| format!("waiting for {what}: {e}"))?;
    match frame.opcode {
        OPCODE_TEXT => Ok(String::from_utf8_lossy(&frame.payload).into_owned()),
        OPCODE_CLOSE => {
            let (code, reason) = close_code_and_reason(&frame.payload);
            Err(format!("a Close while waiting for {what}: {code:?} {}", short(&reason)))
        }
        _ => Err(format!("data while waiting for {what}")),
    }
}

/// Read one socket until it ends, and pass on what it saw.
fn reader(side: Side, session: Arc<RelaySession>, id: SessionId, start: Instant, tx: mpsc::UnboundedSender<Event>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let seen = match session.read_frame().await {
                Ok(f) if f.opcode == OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    Seen::Closed { code, reason }
                }
                Ok(f) if f.opcode == OPCODE_TEXT => match (side, control::parse_inbound(&f.payload)) {
                    (Side::Node, Ok(NodeInbound::Close { id: got, reason })) if got == id.as_str() => {
                        Seen::SessionClosed(reason.unwrap_or_default())
                    }
                    _ => Seen::Control(String::from_utf8_lossy(&f.payload).into_owned()),
                },
                Ok(f) if f.opcode == OPCODE_BINARY => match side {
                    Side::Operator => Seen::Data(f.payload),
                    Side::Node => match decode_node_frame(&f.payload) {
                        Ok((got, payload)) if got == id => Seen::Data(payload.to_vec()),
                        Ok(_) => Seen::Control("data for another session".into()),
                        Err(e) => Seen::Failed(format!("a node frame that does not decode: {e}")),
                    },
                },
                Ok(f) => Seen::Failed(format!("a frame of opcode {}", f.opcode)),
                Err(e) => Seen::Failed(e.to_string()),
            };
            let end = matches!(seen, Seen::Closed { .. } | Seen::Failed(_));
            if tx.send((side, start.elapsed(), seen)).is_err() || end {
                return;
            }
        }
    })
}

/// Take events until `done` holds, or `limit` passes.
async fn pump(rx: &mut mpsc::UnboundedReceiver<Event>, state: &mut State, limit: Duration, done: impl Fn(&State) -> bool) {
    let deadline = tokio::time::Instant::now() + limit;
    while !done(state) {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(event)) => state.take(event),
            Ok(None) | Err(_) => return,
        }
    }
}

/// One byte each way, while the session and both sockets are open: a byte
/// for a session that the relay closed would make it close the node's socket.
async fn send_byte(node: &RelaySession, operator: &RelaySession, id: &SessionId, byte: u8, state: &mut State) -> bool {
    if !state.may_send() {
        return false;
    }
    if let Err(e) = operator.send_binary(&[byte]).await {
        state.log.push(format!("the operator could not send a byte: {}", short(&e.to_string())));
    }
    let frame = encode_node_frame(id, &[byte]).expect("one byte fits");
    if let Err(e) = node.send_binary(&frame).await {
        state.log.push(format!("the node could not send a byte: {}", short(&e.to_string())));
    }
    true
}

async fn session(relay: &Relay, made: &Pair, keep: Keep, label: &'static str) -> Result<Outcome, String> {
    let node = connect(&socket_config(relay, node_path(&made.name)?), made.node_token())
        .await
        .map_err(|e| format!("the node's socket: {e}"))?;
    let node = Arc::new(node);
    let hello = next_text(&node, "hello").await?;
    if !matches!(control::parse_inbound(hello.as_bytes()), Ok(NodeInbound::Hello(_))) {
        return Err(format!("the first control was not a hello: {}", short(&hello)));
    }
    let operator = connect(&socket_config(relay, operator_path(&made.name)?), made.connect_token())
        .await
        .map_err(|e| format!("the operator's socket: {e}"))?;
    let operator = Arc::new(operator);
    let open = next_text(&node, "open").await?;
    let id = match control::parse_inbound(open.as_bytes()) {
        Ok(NodeInbound::Open { id }) => SessionId::parse(id.as_bytes()).map_err(|e| e.to_string())?,
        _ => return Err(format!("not an open: {}", short(&open))),
    };
    let ready = control::ready(&id).map_err(|e| e.to_string())?;
    node.send_text(&String::from_utf8_lossy(&ready)).await.map_err(|e| format!("sending ready: {e}"))?;
    let readied = next_text(&operator, "ready").await?;
    if !matches!(control::parse_operator_control(readied.as_bytes()), Ok(NodeOutbound::Ready { .. })) {
        return Err(format!("the operator's first control was not ready: {}", short(&readied)));
    }

    let start = Instant::now();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let readers = [
        reader(Side::Node, node.clone(), id, start, tx.clone()),
        reader(Side::Operator, operator.clone(), id, start, tx),
    ];
    let mut state = State::default();
    // The session carries a byte each way before it is quiet.
    send_byte(&node, &operator, &id, b'0', &mut state).await;
    pump(&mut rx, &mut state, STEP, |s| s.to_node.len() == 1 && s.to_operator.len() == 1).await;
    if state.to_node != b"0" || state.to_operator != b"0" {
        for task in readers {
            task.abort();
        }
        return Err("the session did not carry its first byte each way".into());
    }

    let quiet_from = Instant::now();
    let quiet_end = quiet_from + QUIET;
    let mut sent = 0usize;
    loop {
        let now = Instant::now();
        if now >= quiet_end || !state.may_send() {
            break;
        }
        let next = match keep {
            Keep::Nothing => quiet_end,
            Keep::Pings { every, .. } | Keep::Payload(every) => (now + every).min(quiet_end),
        };
        pump(&mut rx, &mut state, next - now, |s| !s.may_send()).await;
        if Instant::now() >= quiet_end || !state.may_send() {
            break;
        }
        match keep {
            Keep::Nothing => {}
            Keep::Pings { node: from_node, operator: from_operator, .. } => {
                let ends = [(Side::Node, &node, from_node), (Side::Operator, &operator, from_operator)];
                for (side, session, _) in ends.into_iter().filter(|(_, _, on)| *on) {
                    if let Err(e) = session.send_ping(b"t061").await {
                        state.log.push(format!("{side:?} could not send a Ping: {}", short(&e.to_string())));
                    }
                }
            }
            Keep::Payload(_) => {
                if send_byte(&node, &operator, &id, b'a' + (sent % 25) as u8, &mut state).await {
                    sent += 1;
                }
            }
        }
    }
    // An end before the quiet is over: wait out the quiet, so that the other
    // socket's end is seen too.
    let left = quiet_end.saturating_duration_since(Instant::now());
    pump(&mut rx, &mut state, left, State::both_ended).await;
    // Take what is already queued, then the last byte each way.
    pump(&mut rx, &mut state, Duration::from_millis(500), |_| false).await;
    let (node_before, operator_before) = (state.to_node.len(), state.to_operator.len());
    let last_sent = send_byte(&node, &operator, &id, b'z', &mut state).await;
    if last_sent {
        pump(&mut rx, &mut state, STEP, |s| s.to_node.len() > node_before && s.to_operator.len() > operator_before).await;
    }
    let outcome = Outcome {
        label,
        last_to_node: last_sent.then(|| state.to_node.len() > node_before),
        last_to_operator: last_sent.then(|| state.to_operator.len() > operator_before),
        sent_each_way: sent,
        before: (node_before, operator_before),
        pongs: (node.pongs_received(), operator.pongs_received()),
        heard: (node.frames_received(), operator.frames_received()),
        state,
    };
    let _ = operator.send_close(1000, "").await;
    let _ = node.send_close(1000, "").await;
    for task in readers {
        task.abort();
    }
    Ok(outcome)
}

/// Make a pair, measure one run, and stop the pair whatever happened.
async fn measure(keep: Keep, label: &'static str) -> Outcome {
    let relay = relay();
    let ctx = PairContext { relay: &relay, trust: &Trust::Default, proxy: &ProxyChoice::FromEnvironment, timeout: STEP };
    let made = pair::create(&ctx).await.expect("a pair from the live relay");
    let run = tokio::time::timeout(RUN_LIMIT, session(&relay, &made, keep, label)).await;
    let stopped = pair::stop(&ctx, &made).await;
    eprintln!("T-061 run {label}: the pair is stopped: {stopped:?}");
    match run {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(why)) => panic!("run {label}: {why}"),
        Err(_) => panic!("run {label}: no result within {} s", RUN_LIMIT.as_secs()),
    }
}

#[tokio::test]
#[ignore = "live: about 5 min against the relay"]
async fn a_session_with_no_payload_and_no_pings() {
    measure(Keep::Nothing, "(a) no payload and no Pings").await.print();
}

#[tokio::test]
#[ignore = "live: about 5 min against the relay"]
async fn a_session_with_a_ping_from_each_end_every_20_s() {
    let keep = Keep::Pings { every: Duration::from_secs(20), node: true, operator: true };
    measure(keep, "(b) a Ping from each end every 20 s").await.print();
}

#[tokio::test]
#[ignore = "live: about 5 min against the relay"]
async fn a_session_with_a_ping_from_the_node_every_20_s() {
    let keep = Keep::Pings { every: Duration::from_secs(20), node: true, operator: false };
    measure(keep, "(b1) a Ping from the node every 20 s").await.print();
}

#[tokio::test]
#[ignore = "live: about 5 min against the relay"]
async fn a_session_with_a_ping_from_the_operator_every_20_s() {
    let keep = Keep::Pings { every: Duration::from_secs(20), node: false, operator: true };
    measure(keep, "(b2) a Ping from the operator every 20 s").await.print();
}

/// As the node and the operator runners ping (`podssh_ws::LIVENESS_EVERY`).
#[tokio::test]
#[ignore = "live: about 5 min against the relay"]
async fn a_session_with_a_ping_from_each_end_every_10_s_as_the_runners_do() {
    let keep = Keep::Pings { every: podssh_ws::LIVENESS_EVERY, node: true, operator: true };
    measure(keep, "(d) a Ping from each end every 10 s, as the runners do").await.print();
}

/// The control: if a byte each way every 60 s does not keep the session, the
/// setup is wrong, not the relay.
#[tokio::test]
#[ignore = "live: about 5 min against the relay"]
async fn the_control_a_byte_each_way_every_60_s() {
    let outcome = measure(Keep::Payload(Duration::from_secs(60)), "(c) one byte each way every 60 s").await;
    outcome.print();
    assert!(outcome.state.node_end.is_none(), "the node's socket of the control ended");
    assert!(outcome.state.operator_end.is_none(), "the operator's socket of the control ended");
    assert_eq!(outcome.last_to_node, Some(true), "the control's last byte to the node");
    assert_eq!(outcome.last_to_operator, Some(true), "the control's last byte to the operator");
    let periodic = outcome.sent_each_way;
    assert!(periodic >= 3, "the control sent {periodic} bytes each way");
    assert_eq!(outcome.state.to_node.len(), periodic + 2, "each byte reached the node");
    assert_eq!(outcome.state.to_operator.len(), periodic + 2, "each byte reached the operator");
}
