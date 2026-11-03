//! Each TLS handshake of a road and how it ended, the reference handshake
//! with github.com, and a diagnosis after the counts where they show a case
//! (T-487, GitHub #99). An egress that resets TLS for each name that it does
//! not list gives a FAIL for each relay host and DERP server, each a reset:
//! one fact, said once, as the reference handshake completes there. A path
//! that drops packets times out instead, and one that resets each handshake
//! resets github.com's too. How each ended is read from the kind of its
//! error (`podssh_ws::Cut`), never from the system's words.

use std::time::Instant;

use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::{ConnectError, Cut, Trust};
use tokio::net::TcpStream;

// The name of the reference handshake: a host that `doctor` asks for
// already, which an allowlist of names often holds.
use super::net::{PROBE, REFERENCE_HOST as REFERENCE};
use super::Report;

/// The check of the reference.
const NAME: &str = "TLS reference";

/// What a handshake met.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Met {
    /// TLS completed, its certificate checked.
    Completed,
    /// The far end reset the connection, or closed it with nothing, before
    /// the handshake ended.
    Reset,
    /// Nothing came within the bound.
    TimedOut,
    /// Anything else: a refused dial, a certificate, a proxy's answer.
    Other,
}

impl Met {
    fn words(self) -> &'static str {
        match self {
            Met::Completed => "a handshake",
            Met::Reset => "a reset",
            Met::TimedOut => "a timeout",
            Met::Other => "another failure",
        }
    }
}

/// The road of a handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Of {
    Relay,
    Derp,
    /// A resolver of DNS over HTTPS, asked straight at its address with no
    /// name (T-604).
    Doh,
    /// A relay of n0's, in a build with the iroh road (T-604).
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    Iroh,
    Reference,
}

/// One handshake, as a check saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Handshake {
    pub(super) of: Of,
    pub(super) name: String,
    pub(super) met: Met,
    /// The proxy that carried it, as the report names it.
    pub(super) through: Option<String>,
}

/// What a cut is: a reset and a close with nothing end the handshake from
/// the far end, before its answer; a timeout is the path's silence.
pub(super) fn met_of(cut: Option<Cut>) -> Met {
    match cut {
        Some(Cut::Reset | Cut::Closed) => Met::Reset,
        Some(Cut::TimedOut) => Met::TimedOut,
        _ => Met::Other,
    }
}

/// What a failed connection met.
pub(super) fn met(e: &ConnectError) -> Met {
    met_of(e.cut())
}

/// How the reference reaches github.com.
pub(super) enum Through {
    /// With no proxy: a dial of its own.
    Direct,
    /// Through the proxy, as the report names it, over the stream of the
    /// CONNECT probe of github.com:443, when the proxy took it.
    Proxy { shown: String, kept: Option<TcpStream> },
}

/// The reference handshake: TLS with github.com on port 443 by its name,
/// its certificate checked; `ok` with what it met, as the reference probes
/// of CONNECT are.
pub(super) async fn reference(report: &mut Report<'_>, trust: &Trust, through: Through) {
    let target = dial::authority(REFERENCE, 443);
    let started = Instant::now();
    let (stream, shown) = match through {
        Through::Direct => match dial::dial(REFERENCE, 443, &ProxyChoice::Direct, PROBE).await {
            Ok(stream) => (stream, None),
            Err(e) => {
                let found = met(&ConnectError::Dial(e.clone()));
                record(report, found, None);
                return report.ok(NAME, format!("{target}: {e}: {}", found.words()));
            }
        },
        Through::Proxy { shown, kept: Some(stream) } => (stream, Some(shown)),
        Through::Proxy { shown, kept: None } => {
            return report.ok(NAME, format!("{target}: not tried, as {shown} took no CONNECT to it"));
        }
    };
    let way = shown.as_ref().map(|proxy| format!(" through {proxy}")).unwrap_or_default();
    let (found, detail) = match podssh_ws::tls_over(stream, REFERENCE, trust, PROBE).await {
        Ok(_) => {
            let ms = started.elapsed().as_millis();
            let done = format!("{target}{way}: TLS completed for {REFERENCE}, its certificate checked, in {ms} ms");
            (Met::Completed, done)
        }
        Err(e) => {
            let found = met(&e);
            (found, format!("{target}{way}: {e}: {}", found.words()))
        }
    };
    record(report, found, shown);
    report.ok(NAME, format!("{detail}; the reference of the roads' handshakes"));
}

fn record(report: &mut Report<'_>, met: Met, through: Option<String>) {
    report.handshakes.push(Handshake { of: Of::Reference, name: REFERENCE.to_string(), met, through });
}

/// A case that the handshakes show, said once after the counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Diagnosis {
    /// `tls-names`, `tls-reset` or `tls-dropped`.
    pub(super) kind: &'static str,
    pub(super) detail: String,
    /// The names that show it: those whose handshake completed, for a list
    /// of names; else those that met the same end.
    pub(super) evidence: Vec<String>,
}

impl Diagnosis {
    /// As `--json` gives it, its detail made safe as the text's is.
    pub(super) fn json(&self) -> serde_json::Value {
        let detail = podssh_ws::text::one_line(&self.detail);
        serde_json::json!({ "kind": self.kind, "detail": detail, "evidence": self.evidence })
    }
}

/// The case of the handshakes, if they show one: each relay host reset
/// while the reference completed (a list of names); each handshake reset,
/// the reference's too; each timed out, the reference's too.
pub(super) fn diagnose(handshakes: &[Handshake]) -> Vec<Diagnosis> {
    let Some(reference) = handshakes.iter().find(|h| h.of == Of::Reference) else { return Vec::new() };
    // A resolver is asked straight at its address: its way is the
    // reference's only when the reference went with no proxy (T-604).
    let shares = |h: &&Handshake| h.of != Of::Doh || reference.through.is_none();
    let roads: Vec<&Handshake> = handshakes.iter().filter(|h| h.of != Of::Reference).filter(shares).collect();
    let relays: Vec<&&Handshake> = roads.iter().filter(|h| h.of == Of::Relay).collect();
    if relays.is_empty() {
        return Vec::new();
    }
    let names = |met: Met| {
        let mut names = vec![REFERENCE.to_string()];
        for h in roads.iter().filter(|h| h.met == met) {
            if !names.contains(&h.name) {
                names.push(h.name.clone());
            }
        }
        names
    };
    let each = |met: Met| roads.iter().all(|h| h.met == met);
    let (reset, total) = (roads.iter().filter(|h| h.met == Met::Reset).count(), roads.len());
    let way = match &reference.through {
        Some(proxy) => format!("the way out through the proxy {proxy}"),
        None => "this host".to_string(),
    };
    // Each relay host reset, and no road by a name timed out: names, not a
    // dropping path. A resolver, asked by its address alone, says nothing of
    // names when it is dropped (T-604).
    let late = roads.iter().any(|h| h.of != Of::Doh && h.met == Met::TimedOut);
    let listed = relays.iter().all(|h| h.met == Met::Reset) && !late;
    let found = match reference.met {
        Met::Completed if listed => Diagnosis {
            kind: "tls-names",
            detail: format!(
                "{way} resets TLS for each name that it does not list: each relay host's handshake was reset \
                 ({reset} of the {total} handshakes of the roads), and {REFERENCE}'s completed. {REFERENCE} is on \
                 the list and the relay's name is not, so each road through the relay's name stays closed until \
                 that name is listed; a road through a listed name serves: --forwarder, --via, or a relay of your \
                 own (--relay-host)"
            ),
            evidence: names(Met::Completed),
        },
        Met::Reset if each(Met::Reset) => Diagnosis {
            kind: "tls-reset",
            detail: format!(
                "{way} resets each TLS handshake on port 443, whatever its name: {REFERENCE}'s and each of the \
                 {total} of the roads were reset, so no road over TLS on port 443 leaves here"
            ),
            evidence: names(Met::Reset),
        },
        Met::TimedOut if each(Met::TimedOut) => Diagnosis {
            kind: "tls-dropped",
            detail: format!(
                "{way} drops each handshake on port 443 and resets none: {REFERENCE}'s and each of the {total} of \
                 the roads got no answer in time, as a firewall that drops does, not one that lists names"
            ),
            evidence: names(Met::TimedOut),
        },
        _ => return Vec::new(),
    };
    vec![found]
}

#[cfg(test)]
#[path = "diagnosis_tests.rs"]
mod tests;
