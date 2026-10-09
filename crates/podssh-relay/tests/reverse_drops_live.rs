//! How often the relay's side drops a socket of the reverse road (T-255), on
//! request only: `cargo test -p podssh-relay --features pair --test
//! reverse_drops_live -- --ignored --nocapture`.
//!
//! Four pairs each hold a session, with a Ping from each end every 10 s as
//! the runners ping, and a forward session to GitHub's SSH port is held
//! beside them. A session that ends is opened again. Each end is printed with
//! its UTC time, so that runs from two networks can be compared by time. The
//! run lasts until `PODSSH_DROPS_UNTIL` (Unix seconds, at most an hour ahead)
//! or 15 minutes. It stops its pairs, and prints no token.
#![cfg(feature = "pair")]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podssh_relay::open::Request;
use podssh_relay::pair::{self, Pair, PairContext};
use podssh_relay::relay::{self, forward_path, node_path, operator_path};
use podssh_relay::reverse::control::{self, NodeInbound, NodeOutbound};
use podssh_relay::reverse::framing::legs::encode_node_frame;
use podssh_relay::reverse::SessionId;
use podssh_relay::{Relay, DEFAULT_RELAY_HOST};
use podssh_ws::frame::{OPCODE_CLOSE, OPCODE_TEXT};
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{connect, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};

const PAIRS: usize = 4;
const STEP: Duration = Duration::from_secs(15);
/// How long the other end has to show what the relay did after one end saw
/// the session end.
const AFTERMATH: Duration = Duration::from_secs(5);
const DEFAULT_HOLD: Duration = Duration::from_secs(15 * 60);
const MAX_HOLD: Duration = Duration::from_secs(60 * 60);
/// The least time between two opens of one session, so that a target that
/// ends each session at once is not dialled in a loop.
const REOPEN_GAP: Duration = Duration::from_secs(10);

/// How one end of a session ended.
#[derive(Debug)]
enum End {
    /// A Close frame from the relay, with its code and reason.
    Close(Option<u16>, String),
    /// The relay's `close` of the session, on the node's socket.
    SessionClosed(String),
    /// The connection ended with no Close, or failed: a drop.
    Dropped(String),
    /// The run ended; podssh closed the session.
    RunOver,
}

impl End {
    fn text(&self) -> String {
        match self {
            End::Close(code, reason) => format!("a Close {} {:?}", code.map_or("none".into(), |c| c.to_string()), short(reason)),
            End::SessionClosed(reason) => format!("the relay's close of the session {:?}", short(reason)),
            End::Dropped(why) => format!("a DROP: {}", short(why)),
            End::RunOver => "the end of the run".into(),
        }
    }
}

/// What one holder saw, for the summary.
#[derive(Default)]
struct Tally {
    sessions: u32,
    seconds: f64,
    node_drops: u32,
    operator_drops: u32,
    forward_drops: u32,
    other_ends: u32,
    open_failures: u32,
}

impl Tally {
    fn add(&mut self, other: &Tally) {
        self.sessions += other.sessions;
        self.seconds += other.seconds;
        self.node_drops += other.node_drops;
        self.operator_drops += other.operator_drops;
        self.forward_drops += other.forward_drops;
        self.other_ends += other.other_ends;
        self.open_failures += other.open_failures;
    }
}

fn short(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { '?' } else { c }).take(160).collect()
}

/// The UTC time of day, with milliseconds, from the system clock.
fn utc() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let day = now.as_secs() % 86_400;
    format!("{:02}:{:02}:{:02}.{:03}Z", day / 3600, day / 60 % 60, day % 60, now.subsec_millis())
}

fn say(who: &str, what: &str) {
    eprintln!("{} {who:<9} {what}", utc());
}

/// Until when to hold: `PODSSH_DROPS_UNTIL`, else 15 minutes from now.
fn deadline() -> Instant {
    let Ok(text) = std::env::var("PODSSH_DROPS_UNTIL") else { return Instant::now() + DEFAULT_HOLD };
    let until: u64 = text.trim().parse().expect("PODSSH_DROPS_UNTIL: Unix seconds");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    assert!(until > now, "PODSSH_DROPS_UNTIL is in the past");
    let hold = Duration::from_secs(until - now);
    assert!(hold <= MAX_HOLD, "PODSSH_DROPS_UNTIL is more than an hour ahead");
    Instant::now() + hold
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
        // The relay's ends are measured, not podssh's.
        idle_timeout: None,
        proxy: ProxyChoice::FromEnvironment,
    }
}

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

/// A node's socket and an operator's session on `made`, readied, with a
/// byte each way.
async fn open_session(relay: &Relay, made: &Pair) -> Result<(RelaySession, RelaySession, SessionId), String> {
    let node = connect(&socket_config(relay, node_path(&made.name)?), made.node_token())
        .await
        .map_err(|e| format!("the node's socket: {e}"))?;
    let hello = next_text(&node, "hello").await?;
    if !matches!(control::parse_inbound(hello.as_bytes()), Ok(NodeInbound::Hello(_))) {
        return Err("the first control was not a hello".into());
    }
    let operator = connect(&socket_config(relay, operator_path(&made.name)?), made.connect_token())
        .await
        .map_err(|e| format!("the operator's socket: {e}"))?;
    let open = next_text(&node, "open").await?;
    let id = match control::parse_inbound(open.as_bytes()) {
        Ok(NodeInbound::Open { id }) => SessionId::parse(id.as_bytes()).map_err(|e| e.to_string())?,
        _ => return Err("the node's second control was not an open".into()),
    };
    let ready = control::ready(&id).map_err(|e| e.to_string())?;
    node.send_text(&String::from_utf8_lossy(&ready)).await.map_err(|e| format!("sending ready: {e}"))?;
    let readied = next_text(&operator, "ready").await?;
    if !matches!(control::parse_operator_control(readied.as_bytes()), Ok(NodeOutbound::Ready { .. })) {
        return Err("the operator's first control was not ready".into());
    }
    operator.send_binary(b"0").await.map_err(|e| format!("the operator's first byte: {e}"))?;
    let frame = encode_node_frame(&id, b"0").map_err(|e| e.to_string())?;
    node.send_binary(&frame).await.map_err(|e| format!("the node's first byte: {e}"))?;
    Ok((node, operator, id))
}

/// Read one socket until it ends. Data is not checked: the ends are.
async fn watch(session: Arc<RelaySession>, node_of: Option<SessionId>) -> End {
    loop {
        match session.read_frame().await {
            Ok(f) if f.opcode == OPCODE_CLOSE => {
                let (code, reason) = close_code_and_reason(&f.payload);
                return End::Close(code, reason);
            }
            Ok(f) if f.opcode == OPCODE_TEXT => {
                if let (Some(id), Ok(NodeInbound::Close { id: got, reason })) = (node_of, control::parse_inbound(&f.payload)) {
                    if got == id.as_str() {
                        return End::SessionClosed(reason.unwrap_or_default());
                    }
                }
            }
            Ok(_) => {}
            Err(e) => return End::Dropped(e.to_string()),
        }
    }
}

/// Ping both ends every 10 s until one of them ends or the run is over;
/// then give the other end a moment to show what the relay did. A drop is
/// counted for each end that saw one, whichever end saw its end first.
async fn hold(who: &str, node: Arc<RelaySession>, operator: Arc<RelaySession>, id: SessionId, until: Instant, tally: &mut Tally) {
    let started = Instant::now();
    let lost = || End::Dropped("the reader stopped".into());
    let mut node_end = tokio::spawn(watch(node.clone(), Some(id)));
    let mut operator_end = tokio::spawn(watch(operator.clone(), None));
    let every = podssh_ws::LIVENESS_EVERY;
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    // The end that came first, and whether it was the node's.
    let first = loop {
        tokio::select! {
            end = &mut node_end => break Some((true, end.unwrap_or_else(|_| lost()))),
            end = &mut operator_end => break Some((false, end.unwrap_or_else(|_| lost()))),
            _ = ticker.tick() => {
                let _ = node.send_ping(b"t255").await;
                let _ = operator.send_ping(b"t255").await;
            }
            () = tokio::time::sleep_until(until.into()) => break None,
        }
    };
    let held = started.elapsed().as_secs_f64();
    tally.seconds += held;
    if let Some((node_first, first_end)) = first {
        let other = if node_first { &mut operator_end } else { &mut node_end };
        let other_end = match tokio::time::timeout(AFTERMATH, other).await {
            Ok(Ok(end)) => Some(end),
            Ok(Err(_)) => Some(lost()),
            Err(_) => None,
        };
        let (node_saw, operator_saw) =
            if node_first { (Some(&first_end), other_end.as_ref()) } else { (other_end.as_ref(), Some(&first_end)) };
        let node_dropped = matches!(node_saw, Some(End::Dropped(_)));
        let operator_dropped = matches!(operator_saw, Some(End::Dropped(_)));
        tally.node_drops += u32::from(node_dropped);
        tally.operator_drops += u32::from(operator_dropped);
        tally.other_ends += u32::from(!node_dropped && !operator_dropped);
        let text = |saw: Option<&End>| saw.map_or(format!("nothing within {} s", AFTERMATH.as_secs()), End::text);
        let which = if node_first { "node" } else { "operator" };
        say(who, &format!(
            "ended after {held:.1} s, first on the {which}'s socket: the node saw {}; the operator saw {}",
            text(node_saw),
            text(operator_saw)
        ));
    } else {
        say(who, &format!("held to the end of the run: {held:.1} s"));
    }
    let _ = operator.send_close(1000, "").await;
    let _ = node.send_close(1000, "").await;
    node_end.abort();
    operator_end.abort();
}

/// One pair: hold a session, open it again when it ends, until the run is
/// over; stop the pair. Pair 0 first drops its operator's socket on purpose,
/// and the node must see the relay's close of the session: the check that a
/// drop is seen at all.
async fn pair_holder(index: usize, until: Instant) -> (Tally, Option<bool>) {
    let who = format!("pair {index}");
    let relay = relay();
    let ctx = PairContext { relay: &relay, trust: &Trust::Default, proxy: &ProxyChoice::FromEnvironment, timeout: STEP };
    let mut tally = Tally::default();
    let made = match pair::create(&ctx).await {
        Ok(made) => made,
        Err(e) => {
            say(&who, &format!("no pair: {e}"));
            tally.open_failures += 1;
            return (tally, None);
        }
    };
    let mut planted = None;
    while Instant::now() + REOPEN_GAP < until {
        let opened = Instant::now();
        match open_session(&relay, &made).await {
            Ok((node, operator, id)) => {
                tally.sessions += 1;
                if index == 0 && planted.is_none() {
                    // Dropped with no Close: the stream closes under it.
                    drop(operator);
                    let node = Arc::new(node);
                    let seen = tokio::time::timeout(STEP, watch(node.clone(), Some(id))).await;
                    let ok = matches!(seen, Ok(End::SessionClosed(_)));
                    say(&who, &format!("the planted drop of the operator's socket: the node saw {}", match seen {
                        Ok(end) => end.text(),
                        Err(_) => format!("nothing within {} s", STEP.as_secs()),
                    }));
                    planted = Some(ok);
                    let _ = node.send_close(1000, "").await;
                } else {
                    hold(&who, Arc::new(node), Arc::new(operator), id, until, &mut tally).await;
                }
            }
            Err(why) => {
                tally.open_failures += 1;
                say(&who, &format!("could not open a session: {}", short(&why)));
            }
        }
        let next = opened + REOPEN_GAP;
        if next > Instant::now() {
            tokio::time::sleep_until(next.into()).await;
        }
    }
    let stopped = pair::stop(&ctx, &made).await;
    say(&who, &format!("the pair is stopped: {stopped:?}"));
    (tally, planted)
}

/// A forward session to GitHub's SSH port, held and opened again: the
/// forward path's ends, beside the reverse road's.
async fn forward_holder(until: Instant) -> Tally {
    let who = "forward";
    let mut tally = Tally::default();
    let pool = podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST);
    let relays = relay::select_relays(None, None, &pool).expect("the default relay list");
    let path = forward_path("github.com", 22).expect("a forward path");
    let trust = Trust::Default;
    while Instant::now() + REOPEN_GAP < until {
        let opened_at = Instant::now();
        let request = Request { relays: &relays, path: &path, trust: &trust, target: "github.com:22", rounds: 1 };
        match podssh_relay::open(&request, &mut |_: &str| {}).await {
            Ok(opened) => {
                tally.sessions += 1;
                let session = Arc::new(opened.session);
                // An SSH identification line, then quiet: the server's own
                // limit for a login ends the session in time.
                let _ = session.send_binary(b"SSH-2.0-podssh_t255\r\n").await;
                let mut end = tokio::spawn(watch(session.clone(), None));
                let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + podssh_ws::LIVENESS_EVERY, podssh_ws::LIVENESS_EVERY);
                let seen = loop {
                    tokio::select! {
                        seen = &mut end => break seen.unwrap_or_else(|_| End::Dropped("the reader stopped".into())),
                        _ = ticker.tick() => { let _ = session.send_ping(b"t255").await; }
                        () = tokio::time::sleep_until(until.into()) => break End::RunOver,
                    }
                };
                let held = opened_at.elapsed().as_secs_f64();
                tally.seconds += held;
                match &seen {
                    End::Dropped(_) => tally.forward_drops += 1,
                    End::RunOver => {}
                    _ => tally.other_ends += 1,
                }
                say(who, &format!("the session ended after {held:.1} s with {}", seen.text()));
                end.abort();
                let _ = session.send_close(1000, "").await;
            }
            Err(failure) => {
                tally.open_failures += 1;
                say(who, &format!("could not open a session: {}", failure.lines("github.com:22").join("; ")));
            }
        }
        let next = opened_at + REOPEN_GAP;
        if next > Instant::now() {
            tokio::time::sleep_until(next.into()).await;
        }
    }
    tally
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live: 15 minutes or until PODSSH_DROPS_UNTIL, against the relay"]
async fn the_drops_of_reverse_sockets_and_of_a_forward_session() {
    let until = deadline();
    say("run", &format!("{PAIRS} pairs and a forward session, for {:.0} s", until.saturating_duration_since(Instant::now()).as_secs_f64()));
    let pairs: Vec<_> = (0..PAIRS).map(|i| tokio::spawn(pair_holder(i, until))).collect();
    // On this task: the forward opener's notes are not `Send`.
    let forward = forward_holder(until).await;
    let mut reverse = Tally::default();
    let mut planted = None;
    for task in pairs {
        let (tally, seen) = task.await.expect("a pair's holder");
        reverse.add(&tally);
        planted = planted.or(seen);
    }
    let per_hour = |drops: u32, seconds: f64| if seconds > 0.0 { f64::from(drops) * 3600.0 / seconds } else { 0.0 };
    eprintln!(
        "T-255 reverse: {} sessions, {:.0} session-seconds; node drops {}, operator drops {} ({:.1} an hour of a session); other ends {}; failed opens {}",
        reverse.sessions,
        reverse.seconds,
        reverse.node_drops,
        reverse.operator_drops,
        per_hour(reverse.node_drops + reverse.operator_drops, reverse.seconds),
        reverse.other_ends,
        reverse.open_failures
    );
    eprintln!(
        "T-255 forward: {} sessions, {:.0} session-seconds; drops {} ({:.1} an hour); other ends {}; failed opens {}",
        forward.sessions,
        forward.seconds,
        forward.forward_drops,
        per_hour(forward.forward_drops, forward.seconds),
        forward.other_ends,
        forward.open_failures
    );
    assert_eq!(planted, Some(true), "the planted drop of pair 0's operator was not seen by its node");
    assert!(reverse.sessions >= PAIRS as u32, "each pair holds at least one session");
    assert!(forward.sessions >= 1, "the forward path opened at least once");
}
