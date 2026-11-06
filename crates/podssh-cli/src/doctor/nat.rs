//! The line `nat` (T-641, GitHub #139): whether the NAT in front of this
//! host keeps one mapping for a local port whatever the destination, so that
//! a peer that learns it can reach this host with no relay (hole punching),
//! or gives a mapping for each destination, where it cannot. One UDP socket
//! of port 0 asks two STUN servers in turn for the address that each saw
//! (RFC 8489's Binding); one socket for both, as the question is what one
//! local port maps to.
//!
//! The socket is not connected while it asks, so that it can ask two
//! servers: it takes an answer only from the address asked and with the
//! request's id, and skips each other datagram. It lives for the questions
//! alone, a few seconds; at their end it is connected to the first server
//! that answered, which sends nothing and gives this host's own address on
//! that route. UDP goes straight out, as no proxy carries it, whether a proxy
//! is set or not, as the iroh road's probe sends it.
//!
//! The line is never FAIL: either NAT is a fact that podssh works with, its
//! relays carrying each session; with fewer than two mapped addresses it is
//! `????`.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use podssh_ws::{stun, Verdict};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::Report;
use crate::relay_settings::Refusal;

/// The line's name.
const LINE: &str = "nat";
/// The variable that names the servers, or `no`.
pub(crate) const ENV: &str = "PODSSH_STUN";
/// The servers asked by default (the operator's call to confirm, Q86):
/// Cloudflare's, which its Realtime TURN documentation names, then
/// Google's, which WebRTC's samples name. Two operators, so that the two
/// answers come from two destinations: the services of the kind `stun` of
/// `pod-services`, by their rank.
pub(crate) fn defaults() -> Vec<String> {
    let endpoints = pod_services::of_kind("stun").filter_map(|s| s.endpoint("udp"));
    endpoints.map(|e| e.authority()).collect()
}
/// STUN's port when a server names none (RFC 8489, 9).
const PORT: u16 = 3478;
/// The tries of each question, and the wait after each: a request lost on
/// the way goes again with the same id (RFC 8489, 6.2.1).
pub(super) const TRIES: u32 = 3;
pub(super) const TRY_WAIT: Duration = Duration::from_secs(1);
/// The most servers that the variable names, asked in turn until two gave
/// an address: a silent one costs its tries.
const MOST: usize = 4;
/// The bound on the resolving of a server's name.
const RESOLVE_LIMIT: Duration = Duration::from_secs(5);
/// The largest datagram read: a STUN answer is far smaller.
const DATAGRAM: usize = 1500;

/// A STUN server as named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Server {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl std::fmt::Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&podssh_ws::dial::authority(&self.host, self.port))
    }
}

/// What the line does: ask these servers, or none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Setting {
    Servers(Vec<Server>),
    Off,
}

/// The setting of `value`, the variable's: unset or empty, the default;
/// `no`, none; else 2 to [`MOST`] `HOST[:PORT]` by commas. Another value
/// is a setting that cannot be used (78), before any probe.
pub(crate) fn setting_of(value: Option<&str>) -> Result<Setting, Refusal> {
    let text = value.map(str::trim).unwrap_or_default();
    let words = format!("give 2 to {MOST} STUN servers as HOST[:PORT],HOST[:PORT], or no");
    let defaults = defaults();
    let list: Vec<&str> = match text {
        "" => defaults.iter().map(String::as_str).collect(),
        "no" => return Ok(Setting::Off),
        _ => text.split(',').map(str::trim).collect(),
    };
    if !(2..=MOST).contains(&list.len()) {
        // One answer tells nothing: two are the whole signal.
        return Err(Refusal::config(format!("{ENV}: {} named; {words}", list.len())));
    }
    let mut servers = Vec::new();
    for item in list {
        let (host, port) =
            podssh_ws::pt::host_port(item, PORT).map_err(|why| Refusal::config(format!("{ENV}: {why}; {words}")))?;
        servers.push(Server { host, port });
    }
    Ok(Setting::Servers(servers))
}

/// [`setting_of`] the environment's value.
pub(crate) fn setting() -> Result<Setting, Refusal> {
    setting_of(std::env::var(ENV).ok().as_deref())
}

/// The words of a line that `PODSSH_STUN=no` turned off.
fn off_words() -> String {
    format!("{ENV}=no turns it off, so no STUN server was asked")
}

/// The line of a run with `PODSSH_OFFLINE`: nothing was sent.
pub(super) fn offline(report: &mut Report<'_>, setting: &Setting) {
    match setting {
        Setting::Off => report.unknown(LINE, off_words()),
        Setting::Servers(_) => report.unknown(LINE, "not attempted: PODSSH_OFFLINE is set"),
    }
}

/// The line: one socket, the servers in turn, then the verdict.
pub(super) async fn check(report: &mut Report<'_>, setting: &Setting) {
    let servers = match setting {
        Setting::Off => return report.unknown(LINE, off_words()),
        Setting::Servers(servers) => servers,
    };
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => socket,
        Err(e) => {
            let why = format!("no UDP socket binds here ({e}), so no STUN server was asked; the relays need no UDP");
            return report.unknown(LINE, why);
        }
    };
    let asked = ask_each(&socket, servers, TRIES, TRY_WAIT).await;
    let own = own_address(&socket, &asked).await;
    report.line(LINE, verdict(&asked, own));
}

/// What one server gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Answer {
    /// The address that it saw.
    Mapped(SocketAddr),
    /// An answer with no address that can be read: an error, or none named.
    Said(String),
    /// No answer: silent, or not asked, and why.
    Silent(String),
}

/// One server, as asked: how it is named, the address asked, and its answer.
#[derive(Clone, Debug)]
pub(super) struct Asked {
    pub(super) shown: String,
    pub(super) at: Option<SocketAddr>,
    pub(super) answer: Answer,
}

impl Asked {
    /// The server, with the address asked where its name is not one.
    fn named(&self) -> String {
        match self.at {
            Some(at) if at.to_string() != self.shown => format!("{} ({})", self.shown, at.ip()),
            _ => self.shown.clone(),
        }
    }
}

/// Each server in turn from `socket`, until two gave an address.
pub(super) async fn ask_each(socket: &UdpSocket, servers: &[Server], tries: u32, wait: Duration) -> Vec<Asked> {
    let mut asked: Vec<Asked> = Vec::new();
    for server in servers {
        if asked.iter().filter(|a| matches!(a.answer, Answer::Mapped(_))).count() == 2 {
            break;
        }
        let shown = server.to_string();
        let (at, answer) = match address(server).await {
            Ok(at) => {
                let id: stun::TransactionId = rand::random();
                (Some(at), ask(socket, at, &id, tries, wait).await)
            }
            Err(why) => (None, Answer::Silent(why)),
        };
        asked.push(Asked { shown, at, answer });
    }
    asked
}

/// The first IPv4 address of `server`: the socket is of IPv4, where a NAT
/// stands.
async fn address(server: &Server) -> Result<SocketAddr, String> {
    let deadline = Instant::now() + RESOLVE_LIMIT;
    let addrs = podssh_ws::resolve::resolve(&server.host, server.port, deadline)
        .await
        .map_err(|why| format!("its name did not resolve: {why}"))?;
    addrs.into_iter().find(SocketAddr::is_ipv4).ok_or_else(|| "it has no IPv4 address".to_string())
}

/// One question: a Binding Request to `to`, sent again after each `wait`
/// up to `tries`; the answer is the first datagram from `to` that reads as a
/// response with `id`. A datagram from another address, or of another id,
/// answers another question, and is skipped.
pub(super) async fn ask(
    socket: &UdpSocket,
    to: SocketAddr,
    id: &stun::TransactionId,
    tries: u32,
    wait: Duration,
) -> Answer {
    let request = stun::binding_request(id);
    let mut buffer = vec![0u8; DATAGRAM];
    let mut said = String::new();
    for _ in 0..tries {
        if let Err(e) = socket.send_to(&request, to).await {
            return Answer::Silent(format!("could not be sent to: {e}"));
        }
        let until = Instant::now() + wait;
        loop {
            let (n, from) = match tokio::time::timeout_at(until, socket.recv_from(&mut buffer)).await {
                Err(_) => break,
                Ok(Ok(got)) => got,
                // An error of a socket that is not connected can be of
                // another question (Windows reports a closed port so): the
                // try waits out its time, and what came stays queued.
                Ok(Err(e)) => {
                    said = format!("; the system said: {e}");
                    tokio::time::sleep_until(until).await;
                    break;
                }
            };
            if from != to {
                continue;
            }
            let Ok(message) = stun::parse(&buffer[..n]) else { continue };
            if message.id != *id {
                continue;
            }
            match message.kind {
                stun::BINDING_SUCCESS => return mapped_of(&message),
                stun::BINDING_ERROR => return Answer::Said(error_of(&message)),
                _ => continue,
            }
        }
    }
    Answer::Silent(format!("said nothing in {tries} tries of {} ms{said}", wait.as_millis()))
}

/// A success response's address, or why it gives none.
fn mapped_of(message: &stun::Message<'_>) -> Answer {
    match message.mapped() {
        Some(Ok(addr)) => Answer::Mapped(addr),
        Some(Err(why)) => Answer::Said(format!("answered with an address that does not read: {why}")),
        None => Answer::Said("answered with no mapped address".to_string()),
    }
}

/// An error response's words.
fn error_of(message: &stun::Message<'_>) -> String {
    match message.error() {
        Some(Ok((code, reason))) => format!("answered the error {code} {}", podssh_ws::text::one_line(&reason)),
        Some(Err(why)) => format!("answered an error that does not read: {why}"),
        None => "answered an error with no code".to_string(),
    }
}

/// This host's own address toward the first server that gave one: the
/// socket, connected to it once the questions are done, sends nothing and
/// names its local address on that route.
async fn own_address(socket: &UdpSocket, asked: &[Asked]) -> Option<SocketAddr> {
    let to = asked.iter().find(|a| matches!(a.answer, Answer::Mapped(_)))?.at?;
    socket.connect(to).await.ok()?;
    socket.local_addr().ok().filter(|own| !own.ip().is_unspecified())
}

/// The line's verdict: the first two mapped addresses compared with each
/// other and with this host's `own`; fewer than two is `????`.
pub(super) fn verdict(asked: &[Asked], own: Option<SocketAddr>) -> Verdict {
    let mapped: Vec<(&Asked, SocketAddr)> = asked
        .iter()
        .filter_map(|a| match a.answer {
            Answer::Mapped(addr) => Some((a, addr)),
            _ => None,
        })
        .collect();
    let (first, a, second, b) = match mapped.as_slice() {
        [(first, a), (second, b), ..] => (first.named(), *a, second.named(), *b),
        _ => {
            let each: Vec<String> = asked.iter().map(|one| format!("{} {}", one.named(), told(&one.answer))).collect();
            let why = format!(
                "fewer than two STUN servers gave a mapped address, so the NAT's mapping is not known: {}",
                each.join("; ")
            );
            return Verdict::Unknown { why };
        }
    };
    let detail = if a != b {
        let apart = if a.ip() == b.ip() { "its port" } else { "its address" };
        format!(
            "a mapping for each destination: {first} saw {a} and {second} saw {b}, {apart} changed with the \
             destination (hole punching will not work here; the relays carry each session)"
        )
    } else if own == Some(a) {
        format!("no NAT: {first} and {second} each saw this host's own address, {a}")
    } else {
        let from = own.map(|own| format!(" for {own}")).unwrap_or_default();
        format!(
            "one mapping for all destinations: {first} and {second} each saw {a}{from}, so a peer that learns \
             it may reach this host directly (hole punching can work here)"
        )
    };
    Verdict::Ok { detail }
}

/// What one server gave, in a few words.
fn told(answer: &Answer) -> String {
    match answer {
        Answer::Mapped(addr) => format!("saw {addr}"),
        Answer::Said(words) | Answer::Silent(words) => words.clone(),
    }
}

#[cfg(test)]
#[path = "nat_tests.rs"]
mod tests;
