//! What the path does to a stream (T-325, GitHub #54): whether a response
//! passes as it comes or is held until its end, whether a request's body
//! does, the largest body that passes, and how long a quiet stream lives.
//! Which road can work through a proxy depends on these, and the HTTP road
//! of T-319 is to be chosen by them: `--json` gives each probe's numbers.
//!
//! The probes ask a server of podssh's relay role (`/v1/probe/drip` and
//! `/v1/probe/anything`, `podssh_relay::serve::probe`), or go-httpbin's same
//! paths: `--stream URL` alone, after this host's checks; with `--full`, the
//! relay that the user named, and at the default relay, which serves no
//! probe, a quiet socket of its reverse road alone. Each line says where it
//! measured, never "the path" of another name, as a proxy can treat two
//! names apart (#74). One connection at a time, each with its bound.

mod http;
mod judge;
mod prints;
mod quiet;

use std::time::Duration;

use podssh_relay::relay::{Relay, RelayList};
use podssh_ws::{Trust, Verdict};
use serde_json::Value;

use self::http::{Piece, Server, CONNECT_WAIT};
use self::judge::Outcome;
use super::{DoctorArgs, Report};
use crate::relay_settings::Refusal;

/// How long the quiet probe holds a stream by default: past the longest
/// default that the fingerprints name, Cloudflare's 125 s.
pub(super) const HOLD: Duration = Duration::from_secs(130);
/// The longest hold of `--stream-idle`.
const MOST_HOLD: u64 = 600;
/// The probe of a response: so many bytes over so long, the first at once.
const DRIP_OVER: Duration = Duration::from_secs(2);
const DRIP_BYTES: u64 = 5;
/// The probe of a body: so many pieces of so many bytes, so far apart.
const PIECES: usize = 4;
const PIECE_BYTES: usize = 1024;
const PIECE_GAP: Duration = Duration::from_millis(500);
/// Each probe's bound past its own time.
const MARGIN: Duration = Duration::from_secs(10);
/// Bytes a second: a body of the cap's probe slower than this is not waited
/// for, as no cap can be told on such a path.
const SLOWEST: u64 = 256 << 10;
/// The lines after the server's, for a server that was not reached.
const LINES: [&str; 4] = ["response", "request body", "body cap", "quiet stream"];

/// What `--stream`, `--stream-idle` and `--full` ask of the section.
pub(super) enum Asked {
    /// No `--stream`, and no `--full` (or `--full` with `--quick`).
    Nothing,
    /// `--stream URL`: the probes alone, after this host's checks.
    Only(Plan),
    /// `--full`: the section among the others.
    Section(Plan),
}

impl Asked {
    /// The plan of the section that runs among the others.
    pub(super) fn section(&self) -> Option<&Plan> {
        match self {
            Asked::Section(plan) => Some(plan),
            _ => None,
        }
    }
}

/// Where the probes ask, and how long a stream is held quiet.
pub(super) struct Plan {
    at: At,
    hold: Duration,
}

enum At {
    /// A server of the probes: the URL of `--stream`, or the relay that the
    /// user named.
    Server(Server),
    /// The default relay, which serves no probe: a quiet socket of its
    /// reverse road.
    Socket(Relay),
}

/// The plan of the run, or the refusal of a value (64).
pub(super) fn asked(args: &DoctorArgs, relays: &RelayList) -> Result<Asked, Refusal> {
    let hold = match args.stream_idle.as_deref() {
        None => HOLD,
        Some(text) => {
            let secs = text.trim().parse::<u64>().ok().filter(|s| (1..=MOST_HOLD).contains(s));
            let words = format!("--stream-idle {text}: give a number of seconds from 1 to {MOST_HOLD}");
            Duration::from_secs(secs.ok_or_else(|| Refusal::usage(words))?)
        }
    };
    if let Some(url) = &args.stream {
        if args.hop.is_some() {
            return Err(Refusal::usage("--stream and --hop each check one thing alone: give one of them"));
        }
        let server = Server::parse(url).map_err(|why| Refusal::usage(format!("--stream: {why}")))?;
        return Ok(Asked::Only(Plan { at: At::Server(server), hold }));
    }
    if !args.full || args.quick || args.hop.is_some() {
        return match args.stream_idle {
            Some(_) => Err(Refusal::usage("--stream-idle is for --stream URL, or --full without --quick")),
            None => Ok(Asked::Nothing),
        };
    }
    let relay = relays.primary().clone();
    let at = if relays.explicit { At::Server(Server::of_relay(&relay)) } else { At::Socket(relay) };
    Ok(Asked::Section(Plan { at, hold }))
}

/// `--stream URL`: the section alone, after this host's, so that a user who
/// asks about a path waits for no other probe.
pub(super) fn only(mut report: Report<'_>, plan: &Plan, trust: &Trust) -> i32 {
    report.section("stream");
    if podssh_relay::open::offline() {
        report.unknown("stream server", "not attempted: PODSSH_OFFLINE is set");
        return report.finish();
    }
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            runtime.block_on(check(&mut report, plan, trust));
            runtime.shutdown_background();
        }
        Err(e) => report.fail("stream server", format!("could not start the async runtime: {e}")),
    }
    report.finish()
}

/// The section's lines, as the plan asks.
pub(super) async fn check(report: &mut Report<'_>, plan: &Plan, trust: &Trust) {
    match &plan.at {
        At::Socket(relay) => quiet::socket(report, relay, trust, plan.hold).await,
        At::Server(server) => probes(report, server, trust, plan.hold).await,
    }
}

/// The four probes at `server`, one after another, after the line of the
/// server and its own limits.
async fn probes(report: &mut Report<'_>, server: &Server, trust: &Trust, hold: Duration) {
    let at = server.shown();
    // At the root of its host, where podssh's relay role serves it.
    let own = match http::get(server, trust, "/relays.json", CONNECT_WAIT).await {
        Ok(answer) => judge::Own::of(&answer),
        Err(why) => {
            report.fail("stream server", format!("{at}: {why}"));
            for name in LINES {
                report.unknown(name, "not attempted: the server was not reached");
            }
            return;
        }
    };
    report.ok("stream server", judge::server_line(&at, &own));
    // `delay=0` each time: go-httpbin holds its head 2 s by default.
    let drip = server.target(&format!("/drip?duration={}&numbytes={DRIP_BYTES}&delay=0", DRIP_OVER.as_secs()));
    match http::get(server, trust, &drip, DRIP_OVER + MARGIN).await {
        Ok(answer) => {
            let numbers = judge::response_numbers(DRIP_OVER, &answer);
            measured(report, "response", judge::response(&at, DRIP_OVER, DRIP_BYTES, &answer), numbers);
        }
        Err(why) => report.unknown("response", format!("{at}/drip: {why}")),
    }
    let pieces: Vec<Piece> = (0..PIECES).map(|i| Piece { at: PIECE_GAP * i as u32, bytes: PIECE_BYTES }).collect();
    let over = PIECE_GAP * (PIECES as u32 - 1);
    match http::post(server, trust, &server.target("/anything"), &pieces, over + MARGIN).await {
        Ok(answer) => report.line("request body", judge::body(&at, over, PIECES, &answer, &own)),
        Err(why) => report.unknown("request body", format!("{at}/anything: {why}")),
    }
    cap(report, server, trust, &at, &own).await;
    let quiet = server.target(&format!("/drip?duration={}&numbytes=2&delay=0", hold.as_secs()));
    match http::get(server, trust, &quiet, hold + MARGIN).await {
        Ok(answer) => {
            let numbers = judge::quiet_numbers(hold, &answer);
            measured(report, "quiet stream", judge::quiet(&at, hold, &answer, &own), numbers);
        }
        Err(why) => report.unknown("quiet stream", format!("{at}/drip: {why}")),
    }
}

/// The probe of the cap: bodies twice as big each time, from 64 KiB to the
/// server's own cap or the probe's most, until one does not pass.
async fn cap(report: &mut Report<'_>, server: &Server, trust: &Trust, at: &str, own: &judge::Own) {
    let mut steps = Vec::new();
    for size in judge::sizes(own.body_max) {
        let pieces = [Piece { at: Duration::ZERO, bytes: size as usize }];
        let wait = MARGIN * 3 + Duration::from_secs(size / SLOWEST);
        let outcome = match http::post(server, trust, &server.target("/anything"), &pieces, wait).await {
            Ok(answer) => judge::outcome(&answer),
            Err(why) => Outcome::Cut(why),
        };
        let passed = outcome == Outcome::Passed;
        steps.push((size, outcome));
        if !passed {
            break;
        }
    }
    measured(report, "body cap", judge::cap(at, &steps, own), judge::cap_numbers(&steps));
}

/// A line with what its probe measured as numbers, which `--json` gives as
/// its `samples`.
fn measured(report: &mut Report<'_>, name: &str, verdict: Verdict, numbers: Value) {
    report.line(name, verdict);
    if let Some(line) = report.lines.last_mut() {
        line.samples = Some(numbers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relays(explicit: bool) -> RelayList {
        RelayList { hosts: vec![Relay { host: "relay.example".into(), port: 443 }], explicit }
    }

    fn args(stream: Option<&str>, idle: Option<&str>, full: bool) -> DoctorArgs {
        let (stream, stream_idle) = (stream.map(String::from), idle.map(String::from));
        DoctorArgs { stream, stream_idle, full, ..DoctorArgs::default() }
    }

    /// `--stream` alone; `--full` at the relay that the user named, or a
    /// quiet socket at the default one; nothing with neither, or `--quick`.
    #[test]
    fn the_section_runs_alone_with_stream_and_among_the_others_with_full() {
        let only = asked(&args(Some("https://n.example:8443/x/"), Some("6"), false), &relays(false)).unwrap();
        let Asked::Only(plan) = only else { panic!("--stream runs alone") };
        let At::Server(server) = &plan.at else { panic!("a server") };
        assert_eq!((server.shown(), plan.hold), ("https://n.example:8443/x".into(), Duration::from_secs(6)));
        let named = asked(&args(None, None, true), &relays(true)).unwrap();
        let plan = named.section().expect("--full with a named relay");
        assert!(matches!(&plan.at, At::Server(s) if s.shown() == "https://relay.example/v1/probe"));
        assert_eq!(plan.hold, HOLD);
        let default = asked(&args(None, None, true), &relays(false)).unwrap();
        assert!(matches!(&default.section().unwrap().at, At::Socket(r) if r.host == "relay.example"));
        assert!(matches!(asked(&args(None, None, false), &relays(true)).unwrap(), Asked::Nothing));
        let quick = DoctorArgs { quick: true, ..args(None, None, true) };
        assert!(matches!(asked(&quick, &relays(true)).unwrap(), Asked::Nothing));
    }

    /// A value that does not read is 64, before any probe, and so is a flag
    /// that nothing uses.
    #[test]
    fn a_bad_value_or_a_flag_with_no_use_is_refused() {
        let refused = |a: DoctorArgs| asked(&a, &relays(false)).err().map(|r| (r.code, r.message));
        let (code, words) = refused(args(Some("https://n.example"), Some("0"), false)).unwrap();
        assert_eq!((code, words.as_str()), (64, "--stream-idle 0: give a number of seconds from 1 to 600"));
        assert!(refused(args(Some("https://n.example"), Some("601"), false)).is_some());
        let (_, words) = refused(args(None, Some("30"), false)).unwrap();
        assert!(words.starts_with("--stream-idle is for --stream URL"), "{words}");
        let hop = DoctorArgs { hop: Some("git@github.com".into()), ..args(Some("https://n.example"), None, false) };
        assert!(refused(hop).unwrap().1.contains("--stream and --hop"));
        let bads = ["n.example", "ftp://n.example", "https://u:SECRET@n.example", "https://n.example/?q=1"];
        for bad in bads.into_iter().chain(["https://n.example:0", "https://n.example:x"]) {
            let (code, words) = refused(args(Some(bad), None, false)).unwrap_or_else(|| panic!("{bad}"));
            assert_eq!(code, 64, "{bad}");
            assert!(words.starts_with("--stream: ") && !words.contains("SECRET"), "{bad}: {words}");
        }
    }

    #[test]
    fn a_url_gives_its_scheme_host_port_and_prefix() {
        let plain = Server::parse("http://127.0.0.1:8080").unwrap();
        assert_eq!((plain.tls, plain.host.as_str(), plain.port), (false, "127.0.0.1", 8080));
        assert_eq!(plain.prefix, "/v1/probe", "the role's paths when the URL names none");
        assert_eq!(plain.target("/drip?numbytes=2"), "/v1/probe/drip?numbytes=2");
        let v6 = Server::parse("HTTPS://[2001:db8::1]/probe").unwrap();
        assert_eq!((v6.shown(), v6.port), ("https://[2001:db8::1]/probe".into(), 443));
        assert_eq!(Server::parse("https://n.example/").unwrap().prefix, "/v1/probe");
        let relay = Server::of_relay(&Relay { host: "r.example".into(), port: 8443 });
        assert_eq!(relay.shown(), "https://r.example:8443/v1/probe");
    }
}
