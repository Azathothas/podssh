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
    let settings = crate::settings::here();
    let relays_from = match (&args.relay_host, &env_relay, &settings.relay_host) {
        (Some(_), ..) => "--relay-host",
        (None, Some(_), _) => "PODSSH_RELAY",
        (None, None, Some(_)) => "the settings file",
        (None, None, None) => "default and pool",
    };
    let session_log = match session_log_state() {
        Ok(state) => state,
        Err(refusal) => return refusal.report("status", err),
    };
    let attachment = crate::non_interactive::resolve_tty(tty, false);
    let line = json!({
        "schema": SCHEMA,
        "podssh": crate::help::version(),
        "relays": relays.hosts.iter().map(|r| json!({ "host": r.host, "port": r.port })).collect::<Vec<_>>(),
        "relays_from": relays_from,
        // Each deployment of the list, and whether its list was signed (T-346).
        "deployments": crate::relay_deployments::status_value(&relays),
        "settings": settings.path.as_ref().map(|p| p.display().to_string()),
        "pool": pool_state(&relays),
        "token": token_state(&relays),
        "cache": cache_state(),
        "proxy": proxy_state(&relays),
        "offline": podssh_relay::open::offline(),
        "attachment": if attachment.is_non_interactive() { "pipe" } else { "terminal" },
        "stdin_tty": tty.stdin,
        "stdout_tty": tty.stdout,
        "host": host,
        "session_log": session_log,
        "relay_failures": relay_failures(),
        "relay_opened": relay_opened(),
        "relay_rank": crate::relay_rank::status_value(),
        "relay_order": podssh_relay::rank_list::order_now(podssh_relay::relay::DEFAULT_RELAY_HOST),
        "relay_rank_auto": crate::relay_rank_auto::status_value(),
        "open_files": open_files(),
        "pairs": pairs_state(),
    });
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
    0
}

/// The pairs in the store, by label: when each expires, and whether
/// `podssh relay pair LABEL` makes its next one now, in its last 24 hours
/// (T-395). Never a token.
fn pairs_state() -> Value {
    let now = crate::pairs::now_ms();
    let window = i64::try_from(crate::node_expiry::RENEW_WINDOW.as_millis()).unwrap_or(i64::MAX);
    let each = podssh_relay::pair::labels().into_iter().filter_map(|label| {
        let pair = podssh_relay::pair::load(&label).ok().flatten()?;
        Some(json!({
            "label": label,
            "expires_ms": pair.expires_ms,
            "expired": pair.expires_ms <= now,
            "next_now": pair.expires_ms <= now.saturating_add(window),
        }))
    });
    each.collect()
}

/// The relay hosts that each run tries last now (T-059), with the seconds
/// since each failed or was cut, why, and the road (T-563).
fn relay_failures() -> Value {
    let seen = podssh_relay::failures::recent(&podssh_relay::failures::Records::load(), crate::pairs::now_ms());
    let last = seen.iter().filter_map(|s| s.last.as_ref().map(|(ago_s, why)| (s, ago_s, why)));
    last.map(|(s, ago_s, why)| json!({ "road": s.road, "host": s.host, "ago_s": ago_s, "reason": why })).collect()
}

/// The session log (T-056): its file, and its last line in short form; null
/// when it is off.
fn session_log_state() -> Result<Value, crate::relay_settings::Refusal> {
    let place = crate::session_log::place()?;
    if place == crate::session_log::Place::Off {
        return Ok(Value::Null);
    }
    let file = crate::session_log::file(&place);
    let last = file.as_deref().and_then(crate::session_log::last).map(|l| {
        json!({ "start": l["start"], "verb": l["verb"], "host": l["host"], "port": l["port"], "via": l["via"],
            "end": l["end"], "exit": l["exit"] })
    });
    Ok(json!({ "file": file.map(|p| p.display().to_string()), "last": last }))
}

/// The pool of the default relay that the cache holds, if any.
fn pool_state(relays: &RelayList) -> Value {
    let primary = &relays.primary().host;
    match pool::cached(primary) {
        Some((fetched_ms, hosts)) => json!({ "cached": true, "fetched_ms": fetched_ms, "hosts": hosts }),
        None => json!({ "cached": false, "fetched_ms": null, "hosts": 0 }),
    }
}

/// The cache's directories in the order podssh tries them, and what chose
/// them (T-243): PODSSH_CACHE_DIR, none, or the usual places; and each usual
/// place passed over, as it is in another user's tree, with why (T-593).
fn cache_state() -> Value {
    let from = match cache::chosen() {
        cache::Chosen::Unset => "default".to_string(),
        cache::Chosen::Nothing => "none".to_string(),
        cache::Chosen::Dir(_) => cache::DIR_ENV.to_string(),
        cache::Chosen::Relative(_) => format!("default ({} is relative, and not used)", cache::DIR_ENV),
    };
    let places = cache::places();
    let dirs: Vec<String> = places.dirs.iter().map(|d| d.display().to_string()).collect();
    let passed: Vec<Value> =
        places.passed.iter().map(|p| json!({ "dir": p.dir.display().to_string(), "why": p.why })).collect();
    json!({ "from": from, "dirs": dirs, "passed": passed })
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

/// The proxy that podssh would use for the first relay host: the variable,
/// `host:port` and its kind (`http` or `socks5`), never the credentials. A
/// setting that cannot be used is said, as the doctor says it.
fn proxy_state(relays: &RelayList) -> Value {
    let primary = &relays.primary().host;
    let named = PROXY_VARS.iter().find_map(|n| var(n).map(|v| (*n, v)));
    match (named, podssh_ws::dial::proxy_from_env(primary)) {
        (None, _) => Value::Null,
        (Some((name, _)), Err(why)) => json!({ "variable": name, "proxy": null, "kind": null, "error": why }),
        (Some((name, _)), Ok(None)) => json!({ "variable": name, "proxy": null, "kind": null, "error": null }),
        (Some((name, _)), Ok(Some(proxy))) => {
            json!({ "variable": name, "proxy": proxy.to_string(), "kind": proxy.kind.name(), "error": null })
        }
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

/// The relay hosts that opened lately (T-563), which a run tries first while
/// their last session was not cut: the seconds since, and the opens that
/// the record counts.
fn relay_opened() -> Value {
    let seen = podssh_relay::failures::recent(&podssh_relay::failures::Records::load(), crate::pairs::now_ms());
    let opened = seen.iter().filter_map(|s| s.opened.map(|(ago_s, opens)| (s, ago_s, opens)));
    opened.map(|(s, ago_s, opens)| json!({ "road": s.road, "host": s.host, "ago_s": ago_s, "opens": opens })).collect()
}

/// The limit of open files (T-564), so that a report carries it: the soft
/// limit now and at start, the hard one (null for none), and the host's
/// refusal of a raise; null on Windows, which has no such limit.
fn open_files() -> Value {
    let Some(limits) = crate::nofile::limits() else { return Value::Null };
    let refused = limits.refused.map(|errno| std::io::Error::from_raw_os_error(errno).to_string());
    json!({
        "soft": limits.soft,
        "hard": limits.hard_limit(),
        "at_start": limits.at_start,
        "raised": limits.raised(),
        "refused": refused,
    })
}
