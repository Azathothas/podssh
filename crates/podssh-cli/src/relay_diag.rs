//! The relay's own state (T-058), with nothing but the binary: `podssh relay
//! status` with no NAME asks each relay host for its `/health`; `info [HOST
//! PORT]` reads the ranked pool and the limits from `/relays.json`; `trace
//! HOST PORT` asks the relay to dial a target and give its first line
//! (`/trace`, with a forward token in its header and never in the URL).
//! Together they tell a relay problem from a target problem. The caller's
//! address and place, which `/trace` gives too, are never shown.

use std::io::Write;
use std::time::Duration;

use podssh_relay::health;
use podssh_relay::relay::{Relay, RelayList};
use podssh_relay::token::{self, MintContext, Origin};
use podssh_ws::dial::authority;
use podssh_ws::{ConnectError, ProxyChoice, Trust};
use serde_json::{json, Value};

use crate::exitmap::Fault;
use crate::relay_cmd::{block_on, RelayArgs};
use crate::relay_settings::Refusal;

/// The limit on each request, as `doctor` has.
const STEP: Duration = Duration::from_secs(10);
/// The limit on a trace: the relay dials the target, 10 s at most, and
/// waits for its first line.
const TRACE_STEP: Duration = Duration::from_secs(30);
/// The limit on a whole run.
const RUN_LIMIT: Duration = Duration::from_secs(120);
/// The largest body read: `/relays.json` lists each host of the pool.
const MAX_BODY: usize = 512 * 1024;

/// The relay hosts and their trust, with the pins applied; nothing is
/// asked with `PODSSH_OFFLINE`.
fn settings(args: &RelayArgs) -> Result<(RelayList, Trust), Refusal> {
    crate::pins::apply(args.relay_addr.as_deref())?;
    let env = std::env::var(podssh_relay::relay::RELAY_ENV).ok();
    let relays = crate::relay_settings::relays(args.relay_host.as_deref(), env)?;
    crate::pairs::online()?;
    Ok((relays, crate::pairs::trust(args.ca_file.as_deref())))
}

/// The target of `info` and `trace`: `HOST PORT`, or one word `HOST:PORT`,
/// checked so that no text can add a query parameter.
fn target(args: &RelayArgs, sub: &str) -> Result<(String, u16), Refusal> {
    let mut words = args.args.iter().map(String::as_str);
    crate::proxy::parse_target(words.next(), words.next())
        .map_err(|why| Refusal::usage(format!("{sub}: {why}; `podssh relay {sub} HOST PORT`")))
}

fn unavailable(message: String) -> Refusal {
    Refusal { message, code: Fault::RelayUnreachable.code() }
}

/// A failed request: a refusal for a relay's 401 or 403, else no relay.
fn connect_refusal(host: &str, e: ConnectError) -> Refusal {
    match e {
        ConnectError::Refused { status: 401 | 403, .. } => {
            Refusal { message: format!("{host}: {e}"), code: Fault::Auth.code() }
        }
        e => unavailable(format!("{host}: {e}")),
    }
}

/// Run `work` within [`RUN_LIMIT`].
fn bounded<T>(work: impl std::future::Future<Output = Result<T, Refusal>>) -> Result<T, Refusal> {
    match block_on(async { tokio::time::timeout(RUN_LIMIT, work).await })? {
        Ok(done) => done,
        Err(_) => Err(unavailable(format!("the run passed its limit of {} s", RUN_LIMIT.as_secs()))),
    }
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(podssh_ws::text::one_line).filter(|s| !s.is_empty())
}

/// `status` with no NAME: each host's `/health`, a line for each as it
/// comes; 0 when a host answered, 69 when none did.
pub fn status(args: &RelayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (relays, trust) = match settings(args) {
        Ok(settings) => settings,
        Err(refusal) => return refusal.report("relay", err),
    };
    let json = args.json;
    let found = bounded(async {
        let proxy = ProxyChoice::FromEnvironment;
        let mut found: Vec<(Relay, Result<health::Health, health::HealthError>)> = Vec::new();
        for relay in &relays.hosts {
            let result = health::fetch(relay, &trust, &proxy, STEP).await;
            if !json {
                let _ = match &result {
                    Ok(answer) => writeln!(out, "{}", answer.line(&relay.host)),
                    Err(e) => writeln!(out, "{}: {e}", relay.host),
                };
            }
            found.push((relay.clone(), result));
        }
        Ok(found)
    });
    let found = match found {
        Ok(found) => found,
        Err(refusal) => return refusal.report("relay", err),
    };
    let code = if found.iter().any(|(_, r)| r.is_ok()) { 0 } else { Fault::RelayUnreachable.code() };
    if json {
        let hosts: Vec<Value> = found
            .iter()
            .map(|(relay, result)| match result {
                Ok(h) => json!({
                    "host": relay.host, "port": relay.port, "ok": true, "version": h.version, "edge": h.edge,
                    "paused": h.paused, "reverse": h.reverse, "ms": h.took.as_millis() as u64, "tls": h.tls,
                    "opened": h.opened,
                }),
                Err(e) => json!({ "host": relay.host, "port": relay.port, "ok": false, "error": e.to_string() }),
            })
            .collect();
        let doc = json!({ "schema": 1, "podssh": crate::help::version(), "hosts": hosts, "exit": code });
        let _ = writeln!(out, "{doc}");
    } else if code != 0 {
        let _ = writeln!(err, "podssh relay: no relay host answered");
    }
    code
}

/// `info [HOST PORT]`: the first relay host's `/relays.json`, for the target
/// when one is given.
pub fn info(args: &RelayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let target = match args.args.is_empty() {
        true => None,
        false => match target(args, "info") {
            Ok(target) => Some(target),
            Err(refusal) => return refusal.report("relay", err),
        },
    };
    let (relays, trust) = match settings(args) {
        Ok(settings) => settings,
        Err(refusal) => return refusal.report("relay", err),
    };
    let relay = relays.primary().clone();
    let path = match &target {
        Some((host, port)) => format!("/relays.json?host={}&port={port}", query_value(host)),
        None => "/relays.json".to_string(),
    };
    let doc = bounded(async {
        let proxy = ProxyChoice::FromEnvironment;
        let response = podssh_ws::https_get(&relay.host, relay.port, &path, MAX_BODY, &trust, &proxy, STEP)
            .await
            .map_err(|e| connect_refusal(&relay.host, e))?;
        json_of(&relay, "/relays.json", &response)
    });
    let doc = match doc {
        Ok(doc) => doc,
        Err(refusal) => return refusal.report("relay", err),
    };
    if args.json {
        let doc = json!({ "schema": 1, "podssh": crate::help::version(), "relay": relay.host, "info": doc });
        let _ = writeln!(out, "{doc}");
    } else {
        for line in crate::relay_diag_text::info_lines(&relay.host, &doc) {
            let _ = writeln!(out, "{line}");
        }
    }
    0
}

/// `trace HOST PORT`: the first relay host dials the target and gives its
/// first line. 0 when the trace ran, whatever the target said; 69 when the
/// relay could not dial it, or could not be reached.
pub fn trace(args: &RelayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let (host, port) = match target(args, "trace") {
        Ok(target) => target,
        Err(refusal) => return refusal.report("relay", err),
    };
    let (relays, trust) = match settings(args) {
        Ok(settings) => settings,
        Err(refusal) => return refusal.report("relay", err),
    };
    let relay = relays.primary().clone();
    let wanted = authority(&host, port);
    let path = format!("/trace?target={}&banner=1", query_value(&wanted));
    let doc = bounded(async {
        let proxy = ProxyChoice::FromEnvironment;
        let ctx = MintContext { relay: &relay, trust: &trust, proxy: &proxy, timeout: STEP };
        let mut fresh = false;
        loop {
            let token = token::obtain(&ctx, fresh).await.map_err(|e| unavailable(format!("the relay token: {e}")))?;
            let response = podssh_ws::client::https_with_token(
                "GET",
                &relay.host,
                relay.port,
                &path,
                b"",
                token.secret(),
                MAX_BODY,
                &trust,
                &proxy,
                TRACE_STEP,
            )
            .await
            .map_err(|e| connect_refusal(&relay.host, e))?;
            // A cached token that the relay no longer takes: once, a new one.
            if response.status == 403 && token.origin == Origin::Cache && !fresh {
                podssh_relay::cache::remove(&token::token_key(&relay));
                fresh = true;
                continue;
            }
            if response.status == 403 {
                return Err(Refusal {
                    message: format!(
                        "{}: the relay refused the token for /trace: {}",
                        relay.host,
                        response.body_text(120)
                    ),
                    code: Fault::Auth.code(),
                });
            }
            return json_of(&relay, "/trace", &response);
        }
    });
    let doc = match doc {
        Ok(doc) => doc,
        Err(refusal) => return refusal.report("relay", err),
    };
    let found = &doc["target"];
    let code = if text(&found["error"]).is_some() || !found.is_object() { Fault::RelayUnreachable.code() } else { 0 };
    if args.json {
        // The caller's address and place stay out: only the relay and the target.
        let doc = json!({
            "schema": 1, "podssh": crate::help::version(), "relay": relay.host,
            "version": doc["relay"]["version"], "edge": doc["request"]["edge_colo"], "target": found, "exit": code,
        });
        let _ = writeln!(out, "{doc}");
    } else {
        for line in crate::relay_diag_text::trace_lines(&relay.host, &wanted, &doc) {
            let _ = writeln!(out, "{line}");
        }
    }
    code
}

/// The JSON of a 200 answer to `what`; any other answer is no relay.
fn json_of(relay: &Relay, what: &str, response: &podssh_ws::http::Response) -> Result<Value, Refusal> {
    if response.status != 200 {
        return Err(unavailable(format!(
            "{}: {what} answered HTTP {} {}",
            relay.host,
            response.status,
            response.body_text(120)
        )));
    }
    serde_json::from_slice(&response.body)
        .map_err(|_| unavailable(format!("{}: {what} did not answer with JSON", relay.host)))
}

/// A value for the query string: what a URL keeps as it is, else `%XX`.
fn query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_value_cannot_add_a_parameter() {
        assert_eq!(query_value("github.com:22"), "github.com:22");
        assert_eq!(query_value("[2001:db8::1]:22"), "%5B2001:db8::1%5D:22");
        assert_eq!(query_value("a&b=c#d"), "a%26b%3Dc%23d");
    }
}
