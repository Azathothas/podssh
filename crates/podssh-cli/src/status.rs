//! `podssh status`: one line of JSON about the state of this host, for a
//! program to read before anything else: the relay hosts in effect and where
//! they came from, the cached pool, the token (where it is, for which relay,
//! until when; never the token), the proxy (never its credentials), whether
//! podssh has a terminal, and, given a destination, whether its host key is
//! known. It opens no connection, asks no DNS and writes nothing: `podssh
//! doctor` is the report that measures.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use podssh_relay::relay::{self, RelayList};
use podssh_relay::{cache, pool, token};

use crate::pager::Tty;

/// The version of the line's shape: a change that breaks a reader raises it.
pub const SCHEMA: u32 = 1;

/// What `podssh status` was given.
#[derive(Debug, Clone, Default)]
pub struct StatusArgs {
    pub relay_host: Option<String>,
    pub relay_addr: Option<String>,
    /// `[user@]host[:port]`, to say whether its host key is known.
    pub destination: Option<String>,
}

/// The variables that name a proxy, in the order podssh reads them.
const PROXY_VARS: [&str; 4] = ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"];

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Run `podssh status`; returns the exit code: 0, or the code of a bad
/// setting (64 for a flag or the destination, 78 for a variable).
pub fn run_status(args: &StatusArgs, tty: Tty, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Err(refusal) = crate::pins::apply(args.relay_addr.as_deref()) {
        return refusal.report("status", err);
    }
    let env_relay = var(relay::RELAY_ENV);
    let relays = match crate::relay_settings::relays(args.relay_host.as_deref(), env_relay.clone()) {
        Ok(r) => r,
        Err(refusal) => return refusal.report("status", err),
    };
    let host = match args.destination.as_deref().map(destination) {
        None => Value::Null,
        Some(Ok(v)) => v,
        Some(Err(why)) => return crate::relay_settings::Refusal::usage(why).report("status", err),
    };
    let relays_from = match (&args.relay_host, &env_relay) {
        (Some(_), _) => "--relay-host",
        (None, Some(_)) => "PODSSH_RELAY",
        (None, None) => "default and pool",
    };
    let attachment = crate::non_interactive::resolve_tty(tty, false);
    let line = json!({
        "schema": SCHEMA,
        "podssh": crate::help::version(),
        "relays": relays.hosts.iter().map(|r| json!({ "host": r.host, "port": r.port })).collect::<Vec<_>>(),
        "relays_from": relays_from,
        "pool": pool_state(&relays),
        "token": token_state(&relays),
        "proxy": proxy_state(&relays),
        "offline": podssh_relay::open::offline(),
        "attachment": if attachment.is_non_interactive() { "pipe" } else { "terminal" },
        "stdin_tty": tty.stdin,
        "stdout_tty": tty.stdout,
        "host": host,
    });
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
    0
}

/// The pool of the default relay that the cache holds, if any.
fn pool_state(relays: &RelayList) -> Value {
    let primary = &relays.primary().host;
    match pool::cached(primary) {
        Some((fetched_ms, hosts)) => json!({ "cached": true, "fetched_ms": fetched_ms, "hosts": hosts }),
        None => json!({ "cached": false, "fetched_ms": null, "hosts": 0 }),
    }
}

/// Where the token would come from, never the token: the variable, the
/// cache entry of the first relay's deployment, or none.
fn token_state(relays: &RelayList) -> Value {
    let key = token::token_key(relays.primary());
    if var("PODSSH_RELAY_TOKEN").is_some() {
        return json!({ "source": "PODSSH_RELAY_TOKEN", "for": null, "minted_at": null, "expires_ms": null, "usable": true });
    }
    match cache::peek(&key) {
        Some(p) => {
            let fresh = p.expires_ms.saturating_sub(now_ms()) >= cache::MIN_REMAINING_MS;
            json!({
                "source": "cache",
                "for": key,
                "minted_at": p.minted_at,
                "expires_ms": p.expires_ms,
                "usable": fresh && token::usable(&key, p.minted_at.as_deref()),
            })
        }
        None => json!({ "source": "none", "for": key, "minted_at": null, "expires_ms": null, "usable": false }),
    }
}

/// The proxy that podssh would use for the first relay host: the variable
/// and `host:port`, never the credentials. A setting that cannot be used is
/// said, as the doctor says it.
fn proxy_state(relays: &RelayList) -> Value {
    let primary = &relays.primary().host;
    let named = PROXY_VARS.iter().find_map(|n| var(n).map(|v| (*n, v)));
    match (named, podssh_ws::dial::proxy_from_env(primary)) {
        (None, _) => Value::Null,
        (Some((name, _)), Err(why)) => json!({ "variable": name, "proxy": null, "error": why }),
        (Some((name, _)), Ok(None)) => json!({ "variable": name, "proxy": null, "error": null }),
        (Some((name, _)), Ok(Some(proxy))) => json!({ "variable": name, "proxy": proxy.to_string(), "error": null }),
    }
}

/// The destination's name in `known_hosts`, and whether a key is recorded
/// for it, from the files that `podssh ssh` reads by default.
fn destination(text: &str) -> Result<Value, String> {
    let hop = crate::ssh::resolve::parse_hop(text).map_err(|why| format!("{text}: {why}"))?;
    // The rule that `podssh ssh` applies before it connects.
    podssh_relay::relay::check_target(&hop.host).map_err(|why| format!("{text}: {why}"))?;
    let name = podssh_ssh::known_hosts::host_name(&hop.host, hop.port);
    let env = crate::ssh::resolve::Env::from_process();
    let mut files = env.home.as_deref().map(podssh_ssh::options::default_user_known_hosts).unwrap_or_default();
    files.extend(podssh_ssh::options::default_global_known_hosts());
    let algorithms = podssh_ssh::known_hosts::recorded_algorithms(&files, &name);
    let types: Vec<&str> = algorithms.iter().map(|a| a.as_str()).collect();
    Ok(json!({ "name": name, "known": !types.is_empty(), "key_types": types }))
}
