//! `podssh health --preflight` (T-482, GitHub #92): after the facts, what
//! the far host allows of what a long command needs later, from the same
//! login, in the form of `doctor`'s lines: `ok`, `FAIL` or `????`, the
//! check's name, and what was found. Each probe has a limit of its own
//! ([`LIMIT`]), so a server that never answers fails that probe alone. The
//! server of the issue ended each idle session at a keepalive's reply
//! (#83), refused `tcpip-forward` (#85), opened no `direct-tcpip` (#86) and
//! named no `copy-data` (#87): each was found only when the command that
//! needed it failed, late, in the words of a dead link.
//!
//! The order: the login and the road, from what the login kept; the SFTP
//! subsystem; the remote forward, which the server holds for a moment on its
//! own loopback; the jump; one exec of sh for the tools, tmux among them
//! ([`tools`]); the cgroup, from the facts; and the keepalive last, as a
//! reply that cannot be read ends the connection, after each other probe.
//!
//! The lines are kept and shown at the end, after the facts; `doctor`'s
//! report writes each line as its check ends, and its JSON is doctor's own
//! object, so the preflight keeps its checks in a list of its own, with
//! doctor's labels, widths and keys.

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::preflight as probe;
use podssh_ssh::{Connection, Log};
use podssh_ws::Verdict;
use serde_json::{json, Value};

use super::parse::Facts;
use crate::ssh::resolve::Resolved;
use crate::ssh::transport::Reached;

mod judge;
mod tools;

/// The limit of each probe.
pub const LIMIT: Duration = Duration::from_secs(10);
/// What a run with the preflight has past the run of the facts: the
/// limit of each probe, the forward's cancel and the exec of the tools
/// among them.
pub const MORE: Duration = Duration::from_secs(70);

/// The road that carried the login, as the preflight says it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Road {
    /// `relay`, `direct`, or the word of another road (`forwarder`, `via`).
    pub name: &'static str,
    /// The relay carried the session; else, for a direct one, whether a
    /// proxy did.
    pub relay: bool,
    pub proxy: bool,
    /// The hops of `-J` before the destination, as they were named.
    pub hops: Vec<String>,
}

impl Road {
    /// The road of `resolved` as `reached` went: the relay, or the direct
    /// road after each relay host failed (T-363).
    pub fn of(resolved: &Resolved, reached: &Reached) -> Road {
        let relay = reached.relay.is_some();
        let name = match crate::ssh::road(&resolved.transport) {
            "relay" if !relay => "direct",
            word => word,
        };
        let hops = resolved
            .options
            .jump
            .iter()
            .map(|hop| {
                let user = hop.user.as_ref().map(|u| format!("{u}@")).unwrap_or_default();
                let at =
                    if hop.port == 22 { hop.host.clone() } else { podssh_ws::dial::authority(&hop.host, hop.port) };
                format!("{user}{at}")
            })
            .collect();
        Road { name, relay, proxy: reached.direct_proxy.is_some(), hops }
    }
}

/// One check: its name, and what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
}

/// The checks of a preflight, in their order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Checks(pub Vec<Check>);

impl Checks {
    fn push(&mut self, name: &'static str, verdict: Verdict) {
        self.0.push(Check { name, verdict });
    }

    /// The checks of a run whose login failed: that one, with its words.
    pub fn not_logged_in(why: &str) -> Checks {
        let mut checks = Checks::default();
        checks.push("login", Verdict::Failed { detail: why.to_string() });
        checks
    }

    /// Whether a check failed: the exit is then 1, as `doctor`'s.
    pub fn failed(&self) -> bool {
        self.0.iter().any(|c| matches!(c.verdict, Verdict::Failed { .. }))
    }

    /// The counts of `ok`, `FAIL` and `????`.
    fn counts(&self) -> (usize, usize, usize) {
        let of = |f: fn(&Verdict) -> bool| self.0.iter().filter(|c| f(&c.verdict)).count();
        (
            of(|v| matches!(v, Verdict::Ok { .. })),
            of(|v| matches!(v, Verdict::Failed { .. })),
            of(|v| matches!(v, Verdict::Unknown { .. })),
        )
    }

    /// The section's lines, after a blank one, as `doctor` prints its
    /// lines: each detail made safe for a terminal, as a server's words
    /// come in it.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![String::new(), "preflight".to_string()];
        for c in &self.0 {
            let detail = podssh_ws::text::one_line(detail(&c.verdict));
            out.push(format!("  {:<4}  {:<14} {detail}", c.verdict.label(), c.name));
        }
        let (ok, failed, unknown) = self.counts();
        out.push(String::new());
        out.push(format!("{ok} ok, {failed} FAIL, {unknown} ???? (could not be checked)"));
        out
    }

    /// The checks in the form of `doctor --json`, and their counts.
    pub fn json(&self) -> Value {
        let checks: Vec<Value> = self
            .0
            .iter()
            .map(|c| {
                let status = match c.verdict {
                    Verdict::Ok { .. } => "ok",
                    Verdict::Failed { .. } => "FAIL",
                    Verdict::Unknown { .. } => "unknown",
                };
                let detail = podssh_ws::text::one_line(detail(&c.verdict));
                json!({ "section": "preflight", "check": c.name, "status": status, "detail": detail })
            })
            .collect();
        let (ok, failed, unknown) = self.counts();
        json!({ "checks": checks, "counts": { "ok": ok, "fail": failed, "unknown": unknown } })
    }
}

fn detail(verdict: &Verdict) -> &str {
    match verdict {
        Verdict::Ok { detail } | Verdict::Failed { detail } => detail,
        Verdict::Unknown { why } => why,
    }
}

/// `????` for a probe of the server once the connection had ended: an
/// earlier probe's line says why, and this one asked nothing.
fn ended() -> Verdict {
    Verdict::Unknown { why: "not asked: the connection had ended".into() }
}

/// Each check on `handle`, the destination's connection, after the facts
/// (`facts`, or why none came) of `destination` (`user@host`).
pub async fn run(
    handle: &Connection,
    road: &Road,
    destination: &str,
    facts: Result<&Facts, &str>,
    log: &Arc<Log>,
) -> Checks {
    let mut checks = Checks::default();
    let login = podssh_ssh::outcome::record().facts;
    let (version, method) = (login.server_version.as_deref(), login.method);
    checks.push("login", judge::login(destination, &road.hops, version, method));
    let relay_host = login.relay_host.as_deref().filter(|_| road.relay);
    checks.push("road", judge::road(road, relay_host, &podssh_relay::pool::in_use()));
    log.verbose("preflight: the SFTP subsystem, tcpip-forward, direct-tcpip, the tools, then a keepalive");
    let sftp = match handle.is_closed() {
        true => ended(),
        false => judge::sftp(&probe::sftp(handle, LIMIT).await),
    };
    checks.push("sftp", sftp);
    let forward = match handle.is_closed() {
        true => ended(),
        false => judge::forward(&probe::remote_forward(handle, LIMIT).await),
    };
    checks.push("remote forward", forward);
    let jump = match handle.is_closed() {
        true => ended(),
        false => judge::jump(&probe::jump(handle, LIMIT).await),
    };
    checks.push("jump", jump);
    let found = match handle.is_closed() {
        true => tools::Probed::NotAsked,
        false => tools::probe(handle, LIMIT).await,
    };
    checks.push("exec tools", tools::exec_tools(&found));
    checks.push("tmux", tools::tmux(&found));
    checks.push("cgroup", judge::cgroup(facts));
    let keepalive = match handle.is_closed() {
        true => ended(),
        false => judge::keepalive(&probe::keepalive(handle, LIMIT).await),
    };
    checks.push("keepalive", keepalive);
    checks
}

#[cfg(test)]
mod tests;
