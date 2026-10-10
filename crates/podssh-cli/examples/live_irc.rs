//! **IRC live proof: real IRC registration over the real forward path.**
//!
//! Register (CAP LS / NICK / USER → 001), drain trailing numerics, watch for
//! mid-line payload ends (live frame splits), echo two self `PRIVMSG`s
//! byte-exact, then QUIT. The session opens as `podssh ssh` opens one
//! (`podssh_relay::open`): the token comes from the environment, the cache or
//! a mint, and is never printed. Stdout: counts, codes, caps, probe id.
//!
//! **Fallbacks**: seven ircds, `--bundle` or podssh's own trust, one nick retry,
//! throwaway-channel echo when self-messages never reflect (70 partial).
//!
//! Exits: 0 full proof; 70 registered but echo missed; 69 no registration;
//! 64 bad usage.

#[path = "live_irc/support.rs"]
mod support;

use std::time::{Duration, Instant};

use podssh_core::irc::{Event, ReapPolicy, Registered, Session};
use podssh_relay::open::Request;
use podssh_relay::relay::{self, RelayList};
use podssh_ws::Trust;
use support::{Attempt, LiveRunner, PumpOut};

use support::{burst_for, log_numerics, new_session, pump_once, random_hex6, send_all, usage};

const REAPER_MS: u64 = 180_000;

/// Whole-operation wall clock: a bound, not a dial timeout.
const WHOLE_OP: Duration = Duration::from_secs(150);
const PER_TARGET: Duration = Duration::from_secs(60);
const RECV_STEP: Duration = Duration::from_secs(20);
/// One echo gets this long: 401s arrive in seconds; the bound, not the wait,
/// protects a slow network.
const ECHO_WAIT: Duration = Duration::from_secs(10);
/// 005/MOTD arrive WITH 001: drain briefly so CAP/ISUPPORT are complete.
const DRAIN_001: Duration = Duration::from_secs(5);

/// Port 6667, which the relay passes (`docs/irc.md`). First full proof wins. Small networks lead.
const FALLBACK_TARGETS: &[(&str, u16)] = &[
    ("irc.tilde.chat", 6667),
    ("irc.hackint.org", 6667),
    ("irc.snoonet.org", 6667),
    ("irc.libera.chat", 6667),
    ("irc.oftc.net", 6667),
    ("irc.rizon.net", 6667),
    ("irc.undernet.org", 6667),
];

#[tokio::main]
async fn main() {
    let mut bundle_arg: Option<String> = None;
    let mut target_arg: Option<String> = None;
    let mut port_arg: Option<u16> = None;
    let mut nick_arg: Option<String> = None;
    let mut no_cap = false;
    let mut pair_id: Option<String> = None;
    let mut role_arg: Option<String> = None;
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--bundle" => bundle_arg = argv.next(),
            "--target" => target_arg = argv.next(),
            "--port" => {
                port_arg = argv.next().and_then(|p| p.parse().ok());
                if port_arg.is_none() {
                    usage();
                }
            }
            "--nick" => nick_arg = argv.next(),
            // Undernet 421s CAP LS post-001: some ircds stall on CAP from
            // an unregistered client, so the burst without it is the control.
            "--no-cap" => no_cap = true,
            // Pair mode: two instances, one channel. `--pair ID` fixes the
            // probe id both sides share; `--role send|listen` picks the half.
            "--pair" => pair_id = argv.next(),
            "--role" => role_arg = argv.next(),
            _ => usage(),
        }
    }
    if pair_id.is_some() && !matches!(role_arg.as_deref(), Some("send") | Some("listen")) {
        eprintln!("podssh: --pair needs --role send|listen.");
        usage();
    }
    // A named bundle, else podssh's own trust: the system's bundle and the
    // compiled-in roots.
    let trust = match bundle_arg {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    let pool = podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST);
    let relays = relay::select_relays(None, std::env::var(relay::RELAY_ENV).ok(), &pool).unwrap_or_else(|why| {
        eprintln!("podssh: {}: {why}", relay::RELAY_ENV);
        std::process::exit(64);
    });

    let targets: Vec<(String, u16)> = match target_arg {
        Some(h) => vec![(h, port_arg.unwrap_or(6667))],
        None => FALLBACK_TARGETS.iter().map(|(h, p)| (h.to_string(), *p)).collect(),
    };
    let nick_base = nick_arg.unwrap_or_else(|| format!("podssh-{}", random_hex6()));
    // Pair mode shares one id: the listener awaits exactly what the sender sends.
    let probe_id = pair_id.unwrap_or_else(random_hex6);
    let deadline = Instant::now() + WHOLE_OP;

    let mut best = Attempt::default();
    for (host, port) in &targets {
        if Instant::now() >= deadline {
            break;
        }
        let attempt_deadline = std::cmp::min(deadline, Instant::now() + PER_TARGET);
        let a = run_target(
            &relays,
            &trust,
            host,
            *port,
            &nick_base,
            &probe_id,
            attempt_deadline,
            no_cap,
            role_arg.as_deref(),
        )
        .await;
        eprintln!(
            "podssh: {host}:{port}: connected={} registered={} self={}/{} chan={}/{}",
            a.connected, a.registered, a.echo_short, a.echo_long, a.echo_chan_short, a.echo_chan_long
        );
        if a.is_full() {
            a.report();
            println!("LIVE-IRC-OK");
            return;
        }
        if a.score() > best.score() {
            best = a;
        }
    }

    if best.registered {
        best.report();
        eprintln!("podssh: registered but an echo never came back (partial, not a pass).");
        std::process::exit(70);
    }
    if best.connected {
        eprintln!("podssh: connected but no target registered (see per-target lines above).");
    } else {
        eprintln!("podssh: no target connected (see per-target lines above).");
    }
    std::process::exit(69);
}

// Each knob of the live probe is its own argument, as main reads it.
#[allow(clippy::too_many_arguments)]
async fn run_target(
    relays: &RelayList,
    trust: &Trust,
    host: &str,
    port: u16,
    nick_base: &str,
    probe_id: &str,
    deadline: Instant,
    no_cap: bool,
    role: Option<&str>,
) -> Attempt {
    let mut a = Attempt { target: format!("{host}:{port}"), ..Attempt::default() };
    let path = match relay::forward_path(host, port) {
        Ok(path) => path,
        Err(why) => {
            eprintln!("podssh: {host}:{port}: {why}");
            return a;
        }
    };
    let request = Request { relays, path: &path, trust, target: &a.target, rounds: 1 };
    let opened = match podssh_relay::open(&request, &mut |note: &str| eprintln!("podssh: {note}")).await {
        Ok(opened) => opened,
        Err(failure) => {
            for line in failure.lines(&a.target) {
                eprintln!("podssh: {host}:{port}: {line}");
            }
            return a;
        }
    };
    let mut runner = LiveRunner::new(opened.session);
    a.connected = true;

    let policy = match ReapPolicy::from_reaper_ms(REAPER_MS) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("podssh: bad reaper constant: {e}");
            return a;
        }
    };
    let mut irc = new_session(host, port, nick_base.to_string(), policy);

    // `--no-cap` sends NICK/USER only: `initial_burst` always leads with
    // CAP LS, and a ircd that stalls on pre-registration CAP never answers.
    if send_all(&mut runner, &burst_for(&mut irc, no_cap), &mut a).await.is_err() {
        eprintln!("podssh: {host}:{port}: burst write failed.");
        return a;
    }

    // Registration loop. One nick retry; a second 433 abandons the target.
    let mut retried_nick = false;
    loop {
        if Instant::now() >= deadline {
            eprintln!("podssh: {host}:{port}: target bound reached before 001.");
            return a;
        }
        let step = std::cmp::min(deadline, Instant::now() + RECV_STEP);
        match pump_once(&mut runner, &mut irc, &mut a, step).await {
            PumpOut::Timeout => {}
            PumpOut::Closed(why, detail) => {
                eprintln!("podssh: {host}:{port}: {why} failed before 001: {detail}");
                return a;
            }
            PumpOut::Events(events) => log_numerics(host, port, &events),
        }
        match irc.registered() {
            Registered::Yes => break,
            Registered::Refused(podssh_core::irc::RegistrationFailure::NicknameInUse) if !retried_nick => {
                retried_nick = true;
                eprintln!("podssh: {host}:{port}: nick in use, retrying once.");
                irc = new_session(host, port, format!("{nick_base}_"), policy);
                if send_all(&mut runner, &burst_for(&mut irc, no_cap), &mut a).await.is_err() {
                    return a;
                }
            }
            Registered::Refused(f) => {
                eprintln!("podssh: {host}:{port}: registration refused: {f:?}");
                return a;
            }
            Registered::Pending => {}
        }
    }
    a.registered = true;

    // Drain trailing numerics (005, MOTD), then read CAP/ISUPPORT once.
    let drain_end = std::cmp::min(deadline, Instant::now() + DRAIN_001);
    while Instant::now() < drain_end {
        match pump_once(&mut runner, &mut irc, &mut a, drain_end).await {
            PumpOut::Events(events) => log_numerics(host, port, &events),
            PumpOut::Timeout => {}
            PumpOut::Closed(_, _) => break,
        }
    }
    a.caps_offered = irc.negotiation().offered().to_vec();
    a.caps_enabled = irc.negotiation().enabled().to_vec();
    a.nicklen = irc.isupport().get("NICKLEN").unwrap_or("????").to_string();

    // Pair mode skips self-echo: the proof is A→channel→B, not A→A.
    if let Some(r) = role {
        return pair_exchange(&mut runner, &mut irc, &mut a, probe_id, deadline, r, host, port).await;
    }

    // Self-echo: byte-exact equality proves our bytes survived the round trip.
    let me = irc.server().nick.clone();
    let short = format!("podssh live probe {probe_id}");
    let long = format!("podssh live probe {probe_id} {}", "A".repeat(360));
    for (text, slot) in [(&short, 0), (&long, 1)] {
        let msg = match irc.send_privmsg(&me, text) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("podssh: {host}:{port}: send refused: {e}");
                return a;
            }
        };
        if send_all(&mut runner, &[msg], &mut a).await.is_err() {
            return a;
        }
        let echo_end = std::cmp::min(deadline, Instant::now() + ECHO_WAIT);
        let ok = await_echo(&mut runner, &mut irc, &mut a, text, echo_end, &format!("{host}:{port} self")).await;
        if slot == 0 {
            a.echo_short = ok;
        } else {
            a.echo_long = ok;
        }
        if !ok {
            eprintln!("podssh: {host}:{port}: self-echo {slot} never came back.");
        }
    }

    // Channel fallback for networks without self-message reflection.
    if !(a.echo_short && a.echo_long) && Instant::now() < deadline {
        let target = a.target.clone();
        channel_echo(&mut runner, &mut irc, &mut a, probe_id, deadline, &target).await;
    }

    // QUIT deliberately, then a grace beat: a finished probe leaves no
    // ghost nick (an idle reconnect must NOT send QUIT — entry's own rule).
    leave(&mut runner, &mut a).await;
    a
}

/// QUIT + a grace beat so the server processes it before the socket drops.
async fn leave(runner: &mut LiveRunner, a: &mut Attempt) {
    let quit = Session::quit("podssh live probe done");
    let _ = send_all(runner, &[quit], a).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// JOIN + wait for our JOIN echo or 366. False when the join never lands.
async fn join_channel(
    runner: &mut LiveRunner,
    irc: &mut Session,
    a: &mut Attempt,
    channel: &str,
    deadline: Instant,
    target: &str,
) -> bool {
    let joins = match irc.send_join(channel, None) {
        Ok(joins) => joins,
        Err(e) => {
            eprintln!("podssh: channel {channel}: join refused: {e}");
            return false;
        }
    };
    if send_all(runner, &joins, a).await.is_err() {
        return false;
    }
    let mut joined = false;
    while !joined && Instant::now() < deadline {
        let step = std::cmp::min(deadline, Instant::now() + RECV_STEP);
        match pump_once(runner, irc, a, step).await {
            PumpOut::Events(events) => {
                for e in &events {
                    if let Event::Numeric { code, .. } = e {
                        eprintln!("podssh: {target} join: numeric {code}");
                    }
                    match e {
                        Event::Joined { channel: c } if c == channel => joined = true,
                        Event::Numeric { code: 366, .. } => joined = true,
                        _ => {}
                    }
                }
            }
            PumpOut::Timeout => {}
            PumpOut::Closed(_, _) => return false,
        }
    }
    if !joined {
        eprintln!("podssh: channel {channel}: join never echoed.");
    }
    joined
}

/// Pair rendezvous: both sides in one channel; send writes both texts, listen
/// awaits them byte-exact. The sender's flags mean "flushed"; the listener's
/// mean "received" — the listener's report is the proof, read by the caller.
// Each knob of the live probe is its own argument, as main reads it.
#[allow(clippy::too_many_arguments)]
async fn pair_exchange(
    runner: &mut LiveRunner,
    irc: &mut Session,
    a: &mut Attempt,
    probe_id: &str,
    deadline: Instant,
    role: &str,
    host: &str,
    port: u16,
) -> Attempt {
    let target = format!("{host}:{port}");
    let channel = format!("#podssh-{}", &probe_id[..4.min(probe_id.len())]);
    if !join_channel(runner, irc, a, &channel, deadline, &target).await {
        return std::mem::take(a);
    }
    let short = format!("podssh live probe {probe_id}");
    let long = format!("podssh live probe {probe_id} {}", "A".repeat(360));
    for (text, slot) in [(&short, 0), (&long, 1)] {
        if role == "send" {
            let msg = match irc.send_privmsg(&channel, text) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("podssh: pair send refused: {e}");
                    return std::mem::take(a);
                }
            };
            if send_all(runner, &[msg], a).await.is_err() {
                return std::mem::take(a);
            }
            eprintln!("podssh: pair sent {slot}.");
            if slot == 0 {
                a.echo_chan_short = true;
            } else {
                a.echo_chan_long = true;
            }
        } else {
            // Pair-listen waits out the deadline, not one echo budget: the
            // sender registers on its own clock (~20 s) after we start, and a
            // fixed 10 s wait would QUIT before it ever speaks.
            let ok = await_echo(runner, irc, a, text, deadline, &format!("{target} pair")).await;
            if slot == 0 {
                a.echo_chan_short = ok;
            } else {
                a.echo_chan_long = ok;
            }
            if !ok {
                eprintln!("podssh: pair listen {slot} never arrived.");
            }
        }
    }
    leave(runner, a).await;
    std::mem::take(a)
}

/// JOIN a throwaway channel, two echo-waited messages, PART.
async fn channel_echo(
    runner: &mut LiveRunner,
    irc: &mut Session,
    a: &mut Attempt,
    probe_id: &str,
    deadline: Instant,
    target: &str,
) {
    let channel = format!("#podssh-{}", &probe_id[..4.min(probe_id.len())]);
    if !join_channel(runner, irc, a, &channel, deadline, target).await {
        return;
    }
    let short = format!("podssh live probe {probe_id}");
    let long = format!("podssh live probe {probe_id} {}", "B".repeat(360));
    for (text, slot) in [(&short, 0), (&long, 1)] {
        let msg = match irc.send_privmsg(&channel, text) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("podssh: channel {channel}: send refused: {e}");
                return;
            }
        };
        if send_all(runner, &[msg], a).await.is_err() {
            return;
        }
        let echo_end = std::cmp::min(deadline, Instant::now() + ECHO_WAIT);
        let ok = await_echo(runner, irc, a, text, echo_end, &format!("{target} chan")).await;
        if slot == 0 {
            a.echo_chan_short = ok;
        } else {
            a.echo_chan_long = ok;
        }
    }
    if let Ok(parts) = irc.send_part(&channel, Some("podssh live probe done")) {
        let _ = send_all(runner, &parts, a).await;
    }
}

/// Wait for our text back as a PRIVMSG. Numerics log with context: an error
/// sent while waiting (404/442/475) is the diagnosis.
async fn await_echo(
    runner: &mut LiveRunner,
    irc: &mut Session,
    a: &mut Attempt,
    want: &str,
    deadline: Instant,
    ctx: &str,
) -> bool {
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        let step = std::cmp::min(deadline, Instant::now() + RECV_STEP);
        match pump_once(runner, irc, a, step).await {
            PumpOut::Events(events) => {
                for e in &events {
                    if let Event::Numeric { code, .. } = e {
                        eprintln!("podssh: {ctx}: numeric {code}");
                    }
                    if let Event::Privmsg { text, .. } = e {
                        if text == want {
                            return true;
                        }
                    }
                }
            }
            PumpOut::Timeout => {}
            PumpOut::Closed(_, _) => return false,
        }
    }
}
