//! `podssh relay spec` (T-060): the relay's published document against the
//! facts that podssh was built with (`crates/podssh-probe/facts/relay-facts.toml`,
//! built into the binary). A host with only the binary can then tell a relay
//! that changed from a defect of podssh. `scripts/check-relay-spec.py` reads
//! the same facts file, and CI asks both for the same verdict.
//!
//! stdout carries the verdict: one `ok` line, or one `FAIL` line for each
//! fact that disagrees. A relay that could not be read is neither: it is a
//! check that did not run, and exits as an unreachable relay does.

use std::io::Write;

use podssh_probe::facts::Facts;
use podssh_probe::relay_facts::{verdict_from, Observed, Verdict};
use podssh_relay::relay;
use podssh_ws::client::https_get;
use podssh_ws::dial::ProxyChoice;

use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::Fault;
use crate::relay_cmd::{block_on, RelayArgs};
use crate::relay_settings::Refusal;

/// The exit when a fact disagrees: the relay changed something that podssh
/// depends on. The same as `doctor`'s when a check fails.
pub const EXIT_DISAGREES: i32 = crate::doctor::EXIT_FAILED;

/// The most of `/llms-full.txt` that is read: the pinned document has
/// 18,359 bytes, and a body far past that is not the relay's document.
const DOCUMENT_LIMIT: usize = 1024 * 1024;

/// Run `podssh relay spec [--document FILE]`; returns the exit code.
pub fn run(args: &RelayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let facts = match Facts::load() {
        Ok(facts) => facts,
        Err(why) => {
            // The facts are built in: this is a defect of the build.
            let _ = writeln!(err, "podssh relay spec: the built-in facts cannot be read: {why}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let observed = match args.document.as_deref() {
        Some(file) => match std::fs::read(file) {
            Ok(bytes) => Observed { version: None, document: Some(String::from_utf8_lossy(&bytes).into_owned()) },
            Err(e) => return Refusal::config(format!("--document {file}: {e}")).report("relay", err),
        },
        None => match live(args, err) {
            Ok(observed) => observed,
            Err(refusal) => return refusal.report("relay", err),
        },
    };
    report(&verdict_from(&observed, &facts), &facts, out, err)
}

/// `/health` and `/llms-full.txt` of the first relay host, through the proxy
/// and the trust of the other relay commands. A request that fails leaves its
/// half `None`, which the verdict reports, and says why on stderr.
fn live(args: &RelayArgs, err: &mut dyn Write) -> Result<Observed, Refusal> {
    crate::pins::apply(args.relay_addr.as_deref())?;
    let relays = crate::relay_settings::relays(args.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok())?;
    let host = relays.primary().clone();
    crate::pairs::online()?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    let proxy = ProxyChoice::FromEnvironment;
    let limit = crate::pairs::REQUEST_LIMIT;
    let (health, document) = block_on(async {
        let health = https_get(&host.host, host.port, "/health", 64 * 1024, &trust, &proxy, limit).await;
        let document = https_get(&host.host, host.port, "/llms-full.txt", DOCUMENT_LIMIT, &trust, &proxy, limit).await;
        (health, document)
    })?;
    let mut said = |what: &str| {
        let _ = writeln!(err, "podssh relay spec: {}: {what}", host.host);
    };
    let version = match health {
        Ok(r) if r.status == 200 => {
            let doc: Option<serde_json::Value> = serde_json::from_slice(&r.body).ok();
            let version = doc.as_ref().and_then(|d| d["version"].as_str()).map(podssh_ws::text::one_line);
            if version.is_none() {
                said("/health carried no version");
            }
            version
        }
        Ok(r) => {
            said(&format!("/health answered HTTP {} {}", r.status, r.body_text(120)));
            None
        }
        Err(e) => {
            said(&format!("/health: {e}"));
            None
        }
    };
    let document = match document {
        Ok(r) if r.status == 200 => Some(String::from_utf8_lossy(&r.body).into_owned()),
        Ok(r) => {
            said(&format!("/llms-full.txt answered HTTP {} {}", r.status, r.body_text(120)));
            None
        }
        Err(e) => {
            said(&format!("/llms-full.txt: {e}"));
            None
        }
    };
    Ok(Observed { version, document })
}

/// The verdict on stdout, and its exit code.
fn report(verdict: &Verdict, facts: &Facts, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let checked = facts.facts.len() + facts.relations.len();
    match verdict {
        Verdict::Ok { version, pinned, sha256, lines } => {
            let served = version.as_deref().unwrap_or("not read (a document from a file)");
            let _ = writeln!(
                out,
                "ok   the relay's document agrees with the {checked} facts of podssh: {lines} lines, sha256 {}; \
                 version {served}, pinned {pinned}",
                &sha256[..16]
            );
            if verdict.version_moved() {
                let _ = writeln!(
                    err,
                    "podssh relay spec: the relay serves version {served}, not the pinned {pinned}; each fact holds, \
                     so the protocol that podssh uses did not move"
                );
            }
            0
        }
        Verdict::Failed { disagreements, .. } => {
            for d in disagreements {
                let _ = writeln!(out, "FAIL {d}");
            }
            let _ = writeln!(
                err,
                "podssh relay spec: {} of the {checked} facts disagree with the relay's document: the relay changed \
                 something that podssh depends on",
                disagreements.len()
            );
            EXIT_DISAGREES
        }
        Verdict::Unknown { why } => {
            let _ = writeln!(err, "podssh relay spec: the check did not run: {why}");
            Fault::RelayUnreachable.code()
        }
    }
}
