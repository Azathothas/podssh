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
//! The bind probes here are the only place podssh calls `bind()`: they never
//! listen, and close at once.

use std::io::Write;

use podssh_relay::relay::{self, RelayList};
use podssh_ws::{Trust, Verdict};

use crate::exit_codes::EXIT_USAGE;

mod clock;
mod host;
mod net;
mod relay_checks;
#[cfg(unix)]
mod unix;

/// The exit when at least one check failed.
pub const EXIT_FAILED: i32 = 1;

/// What `podssh doctor` was given: the relay settings `ssh` and `proxy` take,
/// so the doctor checks the path they would use.
#[derive(Debug, Clone, Default)]
pub struct DoctorArgs {
    pub relay_host: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
}

/// Run every check; returns the exit code. The report goes to `out`; only a
/// usage error goes to `err`.
pub fn run_doctor(args: &DoctorArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Err(why) = crate::pins::apply(args.relay_addr.as_deref()) {
        let _ = writeln!(err, "podssh doctor: {why}");
        return EXIT_USAGE;
    }
    let pool = podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST);
    let relays = match relay::select_relays(args.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok(), &pool) {
        Ok(r) => r,
        Err(why) => {
            let _ = writeln!(err, "podssh doctor: {why}");
            return EXIT_USAGE;
        }
    };
    let cert_env = std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty());
    let (trust, trust_from) = match (&args.ca_file, cert_env) {
        (Some(file), _) => (Trust::File(file.into()), "--ca-file"),
        (None, Some(file)) => (Trust::File(file.into()), "SSL_CERT_FILE"),
        (None, None) => (Trust::Default, "the default"),
    };

    let mut report = Report::new(out);
    let _ = writeln!(report.out, "podssh doctor: what this host allows, measured rather than assumed");
    let _ = writeln!(
        report.out,
        "podssh {}, {} {}",
        crate::help::version(),
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    report.section("this host");
    host::check(&mut report);

    report.section("egress");
    net::check_local(&mut report, &relays, &trust, trust_from);
    if podssh_relay::open::offline() {
        report.unknown("network", "not attempted: PODSSH_OFFLINE is set");
        return report.finish();
    }
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            runtime.block_on(network(&mut report, &relays, &trust));
            // A probe may have left a task behind (a relay leg still closing);
            // the report is done, so none is waited for.
            runtime.shutdown_background();
        }
        Err(e) => report.fail("network", format!("could not start the async runtime: {e}")),
    }
    report.finish()
}

async fn network(report: &mut Report<'_>, relays: &RelayList, trust: &Trust) {
    net::check_network(report, relays).await;
    report.section("relay");
    relay_checks::check(report, relays, trust).await;
}

/// The lines printed so far, and their counts.
pub(crate) struct Report<'a> {
    out: &'a mut dyn Write,
    ok: usize,
    failed: usize,
    unknown: usize,
}

impl<'a> Report<'a> {
    fn new(out: &'a mut dyn Write) -> Self {
        Report { out, ok: 0, failed: 0, unknown: 0 }
    }

    fn section(&mut self, title: &str) {
        let _ = writeln!(self.out, "\n{title}");
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
        let _ = writeln!(self.out, "  {label:<4}  {name:<14} {detail}");
        // Network checks take seconds each: show every line as it is known.
        let _ = self.out.flush();
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

    fn finish(self) -> i32 {
        let _ = writeln!(
            self.out,
            "\n{} ok, {} FAIL, {} ???? (could not be checked)",
            self.ok, self.failed, self.unknown
        );
        let _ = self.out.flush();
        if self.failed > 0 {
            EXIT_FAILED
        } else {
            0
        }
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
