//! `podssh doctor`: what this host allows and whether the way out works,
//! measured rather than assumed. One line per check: `ok`, `FAIL` or `????`
//! (the check could not run), what was checked, and what was actually found
//! or opened.
//!
//! A condition podssh is built for (no listener, no pty, no user database
//! entry, no DNS) is a fact, reported `ok` with the fact. `FAIL` is kept for
//! what stops podssh, or one of its fallbacks, from working here. Unknowns are
//! counted apart and never fail the run: the exit is 1 when a check failed
//! and 0 otherwise. Servers are identified by equality (the relay by its
//! certificate and the service name in `/health`, an SSH server by its
//! published host key), never by the shape of a banner. The token is used and
//! never shown, and proxy credentials never appear.
//!
//! The sections that connect run at once, each into a part of its own, and
//! the report keeps their order (`parts.rs`, `sections.rs`; T-511).
//!
//! The bind probes here listen once, accept nothing and close at once (T-358).
//! Each other bind of podssh is a listener that the user asks for, or the UDP
//! socket of a road; the listener scan of `scripts/check-repo.py` holds their
//! files, and `listeners.rs` names the listeners for doctor's lines.

use std::io::Write;

use podssh_relay::relay;
use podssh_ws::{Trust, Verdict};

// Whether the way out takes an address as well as a name (T-366).
mod address;
mod agent;
pub(crate) mod clock;
mod hop;
// The DERP road's servers and its home (T-379).
mod derp;
mod opentunnel;
// How each TLS handshake ended, and what they show together (T-487).
mod diagnosis;
// The forwarders of --forwarder (T-369).
mod forwarder;
mod host;
#[cfg(feature = "iroh")]
mod iroh;
pub mod listeners;
mod names;
mod net;
mod pairs;
// The sections that run at once, each into its own part (T-511).
mod parts;
mod quick;
mod relay_checks;
mod samples;
// Which sections connect, in their order, and how many start together.
mod sections;
// The first server of --shadowsocks (T-373).
mod shadowsocks;
// The sshd of a roost, on this host (T-590).
mod sshd;
#[cfg(feature = "tor")]
mod tor;
#[cfg(unix)]
mod unix;
// The second proxy of --via (T-439).
mod via;
// The servers of --vless (T-440).
mod vless;

// The words of `DoctorJobs`, which the settings file checks as it is read.
pub(crate) use sections::{count as jobs_count, MOST_JOBS};

/// The exit when at least one check failed.
pub const EXIT_FAILED: i32 = 1;

/// What `podssh doctor` was given: the relay settings `ssh` and `proxy` take,
/// so the doctor checks the path they would use.
#[derive(Debug, Clone, Default)]
pub struct DoctorArgs {
    pub relay_host: Option<String>,
    /// `--relay-failover`: how the relay check tries the hosts (T-220).
    pub relay_failover: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    /// `--json`: one JSON object on stdout when every check has run.
    pub json: bool,
    /// `--full`: also log in to GitHub through the relay with a key made
    /// for the check (`login`).
    pub full: bool,
    /// `--hop`: this host and a first hop of `-J` alone (T-371).
    pub hop: Option<String>,
    /// `--forwarder`: forwarders to check after the relay (T-369).
    pub forwarder: Option<String>,
    /// `--shadowsocks`: the file whose first server is checked (T-373).
    pub shadowsocks: Option<String>,
    /// `--via`: the second proxy that is checked (T-439).
    pub via: crate::via::Flags,
    /// `--vless`: the file whose servers are checked (T-440).
    pub vless: Option<String>,
    /// `--quick`: this host, the egress and the relay, with the roads that
    /// the run names, and none of the others (T-511).
    pub quick: bool,
    /// `--jobs N`: at most N sections at once, as typed (T-511).
    pub jobs: Option<String>,
}

/// Run every check; returns the exit code. The report goes to `out`; only a
/// bad setting (64 for a flag, 78 for a variable) goes to `err`.
pub fn run_doctor(args: &DoctorArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    // A hop that does not read is a usage error, before any probe.
    if let Some(Err(why)) = args.hop.as_deref().map(crate::ssh::hop::parse_hop) {
        let _ = writeln!(err, "podssh doctor: --hop {why}");
        return crate::exit_codes::EXIT_USAGE;
    }
    if let Err(refusal) = crate::pins::apply(args.relay_addr.as_deref()) {
        return refusal.report("doctor", err);
    }
    let relays = match crate::relay_settings::relays(args.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok()) {
        Ok(r) => r,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let failover = match crate::relay_settings::failover(
        args.relay_failover.as_deref(),
        std::env::var(podssh_relay::failover::MODE_ENV).ok(),
    ) {
        Ok(mode) => mode,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let forwarders = match crate::forwarder::for_doctor(args.forwarder.as_deref()) {
        Ok(forwarders) => forwarders,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let servers = match crate::shadowsocks::for_doctor(args.shadowsocks.as_deref()) {
        Ok(servers) => servers,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let road = match crate::via::chosen(&args.via, crate::via::trust(args.ca_file.as_deref())) {
        Ok(road) => road,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let links = match crate::vless::for_doctor(args.vless.as_deref()) {
        Ok(links) => links,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let cert_env = std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty());
    let settings = crate::settings::here();
    let jobs = match sections::jobs(args.jobs.as_deref(), settings) {
        Ok(jobs) => jobs,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let (trust, trust_from) = match (&args.ca_file, cert_env, &settings.ca_file) {
        (Some(file), ..) => (Trust::File(file.into()), "--ca-file"),
        (None, Some(file), _) => (Trust::File(file.into()), "SSL_CERT_FILE"),
        (None, None, Some(value)) => (Trust::File(value.text.clone().into()), "CaFile of the settings file"),
        (None, None, None) => (Trust::Default, "the default"),
    };

    let mut report = Report::new(out);
    report.json = args.json;
    if !report.json {
        let _ = writeln!(report.out, "podssh doctor: what this host allows, measured rather than assumed");
        let _ = writeln!(report.out, "{}, {} {}", crate::version::line(), std::env::consts::OS, std::env::consts::ARCH);
    }

    report.section("this host");
    host::check(&mut report);
    if let Some(text) = &args.hop {
        return hop::only(report, text, &trust);
    }
    match &settings.path {
        Some(path) => report.ok("settings", format!("podssh's settings are read from {}", path.display())),
        None => report.ok("settings", "no settings file; the flags, the variables and the defaults hold".to_string()),
    }
    // The relay hosts that a run tries last now (T-059), and first (T-563).
    relay_record(&mut report);
    agent::check(&mut report);
    #[cfg(feature = "iroh")]
    {
        if !args.quick {
            iroh::udp(&mut report);
        }
    }

    report.section("egress");
    net::check_local(&mut report, &relays, &trust, trust_from);
    // The day of cloudflared's roots belongs to the quick tunnel's edge.
    if !args.quick {
        quick::check(&mut report);
    }
    if podssh_relay::open::offline() {
        report.unknown("network", "not attempted: PODSSH_OFFLINE is set");
        if args.full {
            report.unknown("login", "not attempted: PODSSH_OFFLINE is set");
        }
        if !forwarders.is_empty() {
            report.unknown("forwarder", "not attempted: PODSSH_OFFLINE is set");
        }
        if servers.is_some() {
            report.unknown("shadowsocks", "not attempted: PODSSH_OFFLINE is set");
        }
        if road.is_some() {
            report.unknown("via", "not attempted: PODSSH_OFFLINE is set");
        }
        if links.is_some() {
            report.unknown("vless", "not attempted: PODSSH_OFFLINE is set");
        }
        if args.quick {
            sections::left_out_line(&mut report);
            return report.finish();
        }
        report.section("pairs");
        let stored = pairs::stored(&mut report);
        pairs::not_asked(&mut report, &stored, "not asked: PODSSH_OFFLINE is set");
        return report.finish();
    }
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            let checks = sections::Checks {
                relays: &relays,
                trust: &trust,
                failover,
                full: args.full,
                forwarders: &forwarders,
                servers: servers.as_ref(),
                road: road.as_ref(),
                links: links.as_ref(),
                quick: args.quick,
                jobs,
            };
            runtime.block_on(sections::network(&mut report, &checks));
            // A probe may have left a task behind (a relay leg still closing);
            // the report is done, so none is waited for.
            runtime.shutdown_background();
        }
        Err(e) => report.fail("network", format!("could not start the async runtime: {e}")),
    }
    if args.quick {
        sections::left_out_line(&mut report);
    }
    report.finish()
}

/// One check, as the report keeps it for `--json`.
struct Line {
    section: String,
    check: String,
    status: &'static str,
    detail: String,
    /// A probe's tries as numbers (T-324).
    samples: Option<serde_json::Value>,
}

/// The lines so far, and their counts. The text is printed as each check
/// ends; with `json`, the lines are kept and written as one object at the
/// end. One model and two renderers, as for `podssh man`.
pub(crate) struct Report<'a> {
    out: &'a mut dyn Write,
    json: bool,
    section: String,
    lines: Vec<Line>,
    /// Each TLS handshake of a road, and the reference's, for the diagnosis
    /// after the counts (T-487).
    handshakes: Vec<diagnosis::Handshake>,
    ok: usize,
    failed: usize,
    unknown: usize,
}

impl<'a> Report<'a> {
    fn new(out: &'a mut dyn Write) -> Self {
        let (section, lines, handshakes) = (String::new(), Vec::new(), Vec::new());
        Report { out, json: false, section, lines, handshakes, ok: 0, failed: 0, unknown: 0 }
    }

    fn section(&mut self, title: &str) {
        self.section = title.to_string();
        if !self.json {
            let _ = writeln!(self.out, "\n{title}");
        }
    }

    /// One check. The detail is made safe for a terminal here, once, because
    /// it often carries text from a peer or from the environment.
    pub(crate) fn line(&mut self, name: &str, verdict: Verdict) {
        let label = verdict.label();
        let detail = match &verdict {
            Verdict::Ok { detail } => {
                self.ok += 1;
                detail
            }
            Verdict::Failed { detail } => {
                self.failed += 1;
                detail
            }
            Verdict::Unknown { why } => {
                self.unknown += 1;
                why
            }
        };
        let detail = podssh_ws::text::one_line(detail);
        let status = match verdict {
            Verdict::Ok { .. } => "ok",
            Verdict::Failed { .. } => "FAIL",
            Verdict::Unknown { .. } => "unknown",
        };
        if !self.json {
            let _ = writeln!(self.out, "  {label:<4}  {name:<14} {detail}");
            // Network checks take seconds each: show every line as it is known.
            let _ = self.out.flush();
        }
        self.lines.push(Line { section: self.section.clone(), check: name.to_string(), status, detail, samples: None });
    }

    /// [`Report::line`] for a probe that was tried several times; `--json`
    /// gives its times and its losses as numbers too.
    fn sampled(&mut self, name: &str, verdict: Verdict, samples: &samples::Samples) {
        self.line(name, verdict);
        if let Some(line) = self.lines.last_mut() {
            line.samples = Some(samples.json());
        }
    }

    pub(crate) fn ok(&mut self, name: &str, detail: impl Into<String>) {
        self.line(name, Verdict::Ok { detail: detail.into() });
    }

    pub(crate) fn fail(&mut self, name: &str, detail: impl Into<String>) {
        self.line(name, Verdict::Failed { detail: detail.into() });
    }

    pub(crate) fn unknown(&mut self, name: &str, why: impl Into<String>) {
        self.line(name, Verdict::Unknown { why: why.into() });
    }

    /// How a road's TLS handshake with `name` ended, for the diagnosis.
    fn handshake(&mut self, of: diagnosis::Of, name: &str, met: diagnosis::Met) {
        self.handshakes.push(diagnosis::Handshake { of, name: name.to_string(), met, through: None });
    }

    /// A part's lines and counts, once its section has run (T-511).
    fn ended(self) -> parts::Ended {
        let (lines, handshakes) = (self.lines, self.handshakes);
        parts::Ended { lines, handshakes, ok: self.ok, failed: self.failed, unknown: self.unknown }
    }

    /// The lines of a part that ran apart, in their order; its text went
    /// out as the part ran.
    fn absorb(&mut self, part: parts::Ended) {
        self.lines.extend(part.lines);
        self.handshakes.extend(part.handshakes);
        self.ok += part.ok;
        self.failed += part.failed;
        self.unknown += part.unknown;
    }

    fn finish(self) -> i32 {
        let found = diagnosis::diagnose(&self.handshakes);
        if self.json {
            let _ = writeln!(self.out, "{}", self.to_json(&found));
        } else {
            let _ = writeln!(
                self.out,
                "\n{} ok, {} FAIL, {} ???? (could not be checked)",
                self.ok, self.failed, self.unknown
            );
            // After the counts, as a line about them all is known once they
            // are; it counts as nothing (T-487).
            for one in &found {
                let _ = writeln!(self.out, "diagnosis: {}", podssh_ws::text::one_line(&one.detail));
            }
        }
        let _ = self.out.flush();
        if self.failed > 0 {
            EXIT_FAILED
        } else {
            0
        }
    }
}

impl Report<'_> {
    /// The report as one JSON object: the version and the platform, each
    /// check with its section, the counts, and each diagnosis. The details
    /// are the text's, so they hide credentials and tokens in the same way.
    fn to_json(&self, found: &[diagnosis::Diagnosis]) -> String {
        let checks: Vec<serde_json::Value> = self
            .lines
            .iter()
            .map(|l| {
                let mut item = serde_json::json!({
                    "section": l.section, "check": l.check, "status": l.status, "detail": l.detail,
                });
                if let Some(samples) = &l.samples {
                    item["samples"] = samples.clone();
                }
                item
            })
            .collect();
        let findings: Vec<serde_json::Value> = found.iter().map(diagnosis::Diagnosis::json).collect();
        let doc = serde_json::json!({
            "schema": 1,
            "podssh": crate::help::version(),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "checks": checks,
            "counts": { "ok": self.ok, "fail": self.failed, "unknown": self.unknown },
            "diagnosis": findings,
        });
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    }
}

/// The line of the relay hosts that a run tries last now (T-059), for a
/// failure or a rest; and, when there are any, the line of those that it
/// tries first, as they opened lately (T-563). A road other than the
/// WebSocket road is named.
fn relay_record(report: &mut Report<'_>) {
    use podssh_relay::failures::{self, Seen};
    let recent = failures::recent(&failures::Records::load(), crate::pairs::now_ms());
    let window = failures::WINDOW.as_secs() / 60;
    let named = |s: &Seen| match s.road.as_str() {
        failures::WEBSOCKET => s.host.clone(),
        road => format!("{} on {road}", s.host),
    };
    let (mut last, mut opened) = (Vec::new(), Vec::new());
    for s in &recent {
        if let Some((ago, why)) = &s.last {
            last.push(format!("{} ({ago} s ago: {why})", named(s)));
        }
        if let Some((ago, n)) = s.opened {
            opened.push(format!("{} ({ago} s ago, {n} in all)", named(s)));
        }
    }
    match last.is_empty() {
        true => report.ok("failed relays", format!("no relay host failed in the last {window} min")),
        false => report.ok("failed relays", format!("tried last now: {}", last.join(", "))),
    }
    if !opened.is_empty() {
        report.ok("opened relays", format!("tried first while their sessions hold: {}", opened.join(", ")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish(lines: &[Verdict]) -> (i32, String) {
        let mut out = Vec::new();
        let code = {
            let mut report = Report::new(&mut out);
            for v in lines {
                report.line("check", v.clone());
            }
            report.finish()
        };
        (code, String::from_utf8(out).unwrap())
    }

    #[test]
    fn unknowns_are_counted_apart_and_only_a_failure_fails_the_run() {
        let ok = Verdict::Ok { detail: "fine".into() };
        let unknown = Verdict::Unknown { why: "could not run".into() };
        let failed = Verdict::Failed { detail: "broken".into() };
        let (code, text) = finish(&[ok.clone(), unknown.clone(), unknown.clone()]);
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("1 ok, 0 FAIL, 2 ????"), "{text}");
        let (code, text) = finish(&[ok, unknown, failed]);
        assert_eq!(code, EXIT_FAILED, "{text}");
        assert!(text.contains("1 ok, 1 FAIL, 1 ????"), "{text}");
    }

    #[test]
    fn a_line_shows_its_label_and_no_terminal_controls() {
        let (_, text) = finish(&[Verdict::Failed { detail: "evil\u{1b}[2Jtext\r\nmore".into() }]);
        assert!(text.contains("  FAIL  check"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(text.contains("evil[2Jtext more"), "{text:?}");
        let (_, text) = finish(&[Verdict::Unknown { why: "no".into() }]);
        assert!(text.contains("  ????  check"), "{text}");
    }
}
