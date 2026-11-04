//! `podssh doctor --exit NAME` (T-458): the exit NAME of the user's net, as
//! `podssh proxy --exit NAME` reaches it, in the three lines of the section
//! `exit`. What the net held says (NAME a member with the role exit, and
//! whether its policy lets this client out); the pair kept under NAME; and
//! one session from the exit to a public target (GitHub's SSH port, unless
//! `--exit-target HOST:PORT`), with the node's verdict, whose refusal it is,
//! and the road that carried it. GitHub's server is identified by its
//! published host key, as the relay's forward check identifies it.

use std::time::{Duration, Instant};

use podssh_ws::{dial, Trust};
use tokio::io::AsyncReadExt;

use super::relay_checks::{github_keys, judge_unlisted, FORWARD_HOST, GITHUB_KEYS, TIMEOUT};
use super::Report;
use crate::exit::open::{Kind, Refused, To};
use crate::relay_settings::Refusal;

/// How long a target other than GitHub's may take to send its first bytes:
/// a server that waits for its client sends none.
const FIRST_BYTES: Duration = Duration::from_secs(5);

/// `--exit NAME`, `--exit-target HOST:PORT` and `--client-key FILE`, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub name: Option<String>,
    pub target: Option<String>,
    pub client_key: Option<String>,
}

/// The exit and the target of its session.
pub(super) struct Plan {
    to: To,
    host: String,
    port: u16,
}

/// The plan of `flags`, `None` with no `--exit`; a flag of the exit without
/// it, or a target that does not read, is a usage error.
pub(super) fn asked(flags: &Flags, ca_file: Option<&str>) -> Result<Option<Plan>, Refusal> {
    let Some(name) = flags.name.as_deref() else {
        for (given, flag) in [(&flags.target, "--exit-target"), (&flags.client_key, "--client-key")] {
            if given.is_some() {
                return Err(Refusal::usage(format!("{flag} is for --exit NAME")));
            }
        }
        return Ok(None);
    };
    let (host, port) = match flags.target.as_deref() {
        None => (FORWARD_HOST.to_string(), 22),
        Some(text) => target(text).map_err(|why| Refusal::usage(format!("--exit-target {text}: {why}")))?,
    };
    // `--exit auto` (T-432): the exit of the target, by the net's routes.
    let name = &crate::exit::auto::name_for(name, &host)?;
    let to = To {
        name: name.to_string(),
        client_key: flags.client_key.clone(),
        ca_file: ca_file.map(str::to_string),
        ..To::default()
    };
    Ok(Some(Plan { to, host, port }))
}

/// `HOST:PORT`, an IPv6 address in brackets.
fn target(text: &str) -> Result<(String, u16), String> {
    let (host, port) = match text.strip_prefix('[') {
        Some(rest) => rest.split_once("]:").ok_or("give HOST:PORT, an IPv6 address in brackets")?,
        None => text.rsplit_once(':').filter(|(host, _)| !host.contains(':')).ok_or("give HOST:PORT")?,
    };
    let port = port.parse::<u16>().ok().filter(|p| *p > 0).ok_or("the port is a number from 1 to 65535")?;
    if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control() || c == '/') {
        return Err("give HOST:PORT".into());
    }
    Ok((host.to_string(), port))
}

/// The section's three lines.
pub(super) async fn check(report: &mut Report<'_>, plan: &Plan, trust: &Trust) {
    net_line(report, plan);
    let name = &plan.to.name;
    let part = match crate::pairs::operator_part(name, None) {
        Ok(part) => part,
        Err(refusal) => {
            report.fail("exit pair", refusal.message);
            return report.unknown("exit", format!("not attempted: no pair is kept under {name}"));
        }
    };
    let relay = dial::authority(&part.relay.host, part.relay.port);
    report.ok("exit pair", format!("the pair {name} at {relay}, until {}", crate::pairs::utc(part.expires_ms)));
    session_line(report, plan, &relay, trust).await;
}

/// What the net held says of the exit and of this client.
fn net_line(report: &mut Report<'_>, plan: &Plan) {
    let name = &plan.to.name;
    let held = match crate::net::held() {
        Ok(held) => held,
        Err(refusal) => {
            return report.unknown("exit net", format!("{}; the exit's own net decides", refusal.message));
        }
    };
    let doc = &held.signed.doc;
    let net = format!("the net {} (serial {})", doc.name, doc.serial);
    if doc.expires <= crate::net::now() {
        return report.fail("exit net", format!("{net} ended at {}", crate::pairs::utc(doc.expires * 1000)));
    }
    match doc.member(name) {
        None => return report.fail("exit net", format!("{net} has no member {name}")),
        Some(exit) if !exit.has_role("exit") => {
            return report.fail("exit net", format!("{net} gives {name} no role exit, so it lets nobody out"));
        }
        Some(_) => {}
    }
    let me = match crate::channel::client_identity(plan.to.client_key.as_deref(), &|_| {}) {
        Ok(identity) => identity.public(),
        Err(why) => return report.fail("exit net", why),
    };
    let Some(member) = doc.member_of_key(&me) else {
        return report
            .fail("exit net", format!("this client's key {me} is no member of {net}, so {name} lets it not out"));
    };
    match crate::net::policy::check(doc, member, crate::net::policy::Want::Exit(name)) {
        Ok(rule) => report.ok("exit net", format!("{name} is an exit of {net}, and lets {} out: {rule}", member.name)),
        Err(why) => report.fail("exit net", why),
    }
}

/// One session from the exit to the plan's target, and what came through it.
async fn session_line(report: &mut Report<'_>, plan: &Plan, relay: &str, trust: &Trust) {
    let target = dial::authority(&plan.host, plan.port);
    let name = &plan.to.name;
    let started = Instant::now();
    let end = match crate::exit::open::open(&plan.to, &plan.host, plan.port).await {
        Ok(end) => end,
        Err(refused) => {
            let whose = whose(&refused);
            return report.fail("exit", format!("{target} from the exit {name}: refused by {whose}: {}", refused.line));
        }
    };
    let ms = started.elapsed().as_millis();
    let reached = format!("{target} from the exit {name}, over the pair's road at {relay}, in {ms} ms");
    let ending = end.ending;
    let mut stream = tokio::io::join(end.read, end.write);
    if plan.host == FORWARD_HOST && plan.port == 22 {
        match podssh_ssh::probe::host_key(stream, TIMEOUT).await {
            Ok(key) => {
                let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
                let line = format!("{reached}; {} host key {fingerprint}", podssh_ssh::known_hosts::key_type(&key));
                match GITHUB_KEYS.contains(&fingerprint.as_str()) {
                    true => report.ok("exit", format!("{line}, one of GitHub's published keys")),
                    false => report.line("exit", judge_unlisted(&line, &fingerprint, github_keys(trust).await)),
                }
            }
            Err(why) => report.fail("exit", format!("{reached}, then {why}")),
        }
    } else {
        let mut first = [0u8; 256];
        match tokio::time::timeout(FIRST_BYTES, stream.read(&mut first)).await {
            Ok(Ok(0)) => report.ok("exit", format!("{reached}; the target closed with nothing")),
            Ok(Ok(n)) => report.ok("exit", format!("{reached}; its first bytes: {}", shown(&first[..n]))),
            Ok(Err(e)) => report.fail("exit", format!("{reached}, then {e}")),
            Err(_) => report.ok("exit", format!("{reached}; it sent nothing in {} s", FIRST_BYTES.as_secs())),
        }
        drop(stream);
    }
    // The session's end, as the run's other sessions end theirs.
    if let Some(ending) = ending {
        let _ = tokio::time::timeout(TIMEOUT, ending.finish()).await;
    }
}

/// A target's first bytes in one short line.
fn shown(bytes: &[u8]) -> String {
    let line = podssh_ws::text::one_line(&String::from_utf8_lossy(bytes));
    match line.char_indices().nth(80) {
        Some((at, _)) => format!("{}...", &line[..at]),
        None => line,
    }
}

/// Whose a refusal is: the road's (the relay, the pair), the channel's (the
/// exit let this client's key not in), the net's policy, or the exit's own
/// check of an address or its dial; by the words that each of them writes
/// (`crate::channel::judged`, `crate::net::policy::check`,
/// `crate::node_exit::checked`).
fn whose(refused: &Refused) -> &'static str {
    let line = refused.line.as_str();
    match refused.kind {
        Kind::Failed => "the road (the relay, or the pair kept under the name)",
        Kind::Unreachable => "the exit's dial, which reached no address of the target",
        Kind::NotAllowed if line.contains("refused this client's key") => "the channel: the exit let this key not in",
        Kind::NotAllowed if line.contains("'s policy") => "the net's policy",
        Kind::NotAllowed if line.contains("not a public address") => "the exit's check of the address",
        Kind::NotAllowed => "the exit",
    }
}

#[cfg(test)]
#[path = "exit_tests.rs"]
mod tests;
