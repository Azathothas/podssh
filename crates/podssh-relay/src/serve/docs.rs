//! The relay role's documents (T-169): `/health`, `/relays.json` and
//! `/trace` in the shapes that podssh reads from the default relay
//! (`docs/relay.md`, "Diagnostics"; the stand-in relay gives the same), and
//! `/llms-full.txt`, podssh's pinned copy of the contract that the role
//! serves, so that `podssh relay spec` checks a role as it checks the
//! default relay.

use std::time::{Duration, Instant};

use podssh_ws::http::request::{self, Request};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

use super::egress::{self, Plan};
use super::policy::shown;
use super::Config;

/// The contract that the role serves, as podssh pinned it.
pub const SPEC: &str = include_str!("../../../podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt");

/// How long `/trace` waits for a target's first bytes.
const BANNER_WAIT: Duration = Duration::from_secs(5);

/// `/health`.
pub fn health(cfg: &Config) -> Value {
    json!({
        "ok": true,
        "service": crate::health::SERVICE,
        "version": cfg.version,
        "contract": super::CONTRACT,
        // Who may mint: `keys` asks a key's signature (T-448).
        "mint": cfg.mint.word(),
        "relay": { "name": "podssh" },
        // The shape of the default relay's, which `podssh relay status` reads.
        "reverse": { "enabled": true },
    })
}

/// `/relays.json`: this host as its one pool host, the target of
/// `?host=&port=` with its URL, and the five limits.
pub fn relays(cfg: &Config, head: &Request) -> Value {
    let authority = head.header("host").unwrap_or("relay.invalid").to_string();
    let name = match authority.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.parse::<u16>().is_ok() => name.to_string(),
        _ => authority.clone(),
    };
    let query = head.target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let get = |key: &str| query.split('&').find_map(|p| p.strip_prefix(key)?.strip_prefix('=').map(str::to_string));
    let (target, connect) = match (get("host"), get("port").and_then(|p| p.parse::<u16>().ok())) {
        (Some(host), Some(port)) => (
            json!({ "host": host, "port": port, "bucket": null, "source": "explicit" }),
            json!(format!("wss://{authority}/connect/{host}/{port}")),
        ),
        _ => (Value::Null, Value::Null),
    };
    let l = &cfg.limits;
    let mut doc = json!({
        "service": crate::health::SERVICE,
        "version": cfg.version,
        "you": { "edge_colo": null, "bucket": null },
        "target": target,
        "connect": connect,
        "policy": { "note": "podssh relay serve: public TCP targets, port 25 refused" },
        // Whether this host routes IPv6 out, as its role knows it (T-253).
        "egress": cfg.policy.ipv6.doc(&cfg.egress),
        // A pair whose connect token takes one upgrade, `POST /v1/pair?once=1`
        // (T-226), tokens of one leg that a node registers and a stop token
        // that it rotates, `POST /v1/rotate/<name>` (T-615), and the owner's
        // halt, `POST /v1/halt/<name>` (T-647), beside the contract.
        "reverse": { "pair_once": true, "leg_tokens": true, "rotate": true, "halt": true },
        // The forward road in the resumable layer, `/v1/layer/HOST/PORT`
        // (T-173), beside the contract: a client asks for it only here, and
        // sends each link to the name of this process, when it has one.
        "forward": cfg.resumes.offer(),
        "pool": [{ "rank": 0, "name": "podssh", "host": name, "bucket": null, "region": null,
                   "client_ms": 0, "target_ms": 0, "score_ms": 0 }],
        "limits": {
            "connect_timeout_ms": l.connect.as_millis() as u64,
            "idle_timeout_ms": l.idle.as_millis() as u64,
            "max_session_ms": l.session.as_millis() as u64,
            "max_session_bytes": l.bytes,
            "max_frame_bytes": podssh_ws::frame::FORWARD_MAX_FRAME,
            "udp": "unsupported",
            // The probes' own limits, beside the contract's (T-325).
            "probe": super::probe::limits(),
        },
    });
    signed_list(&mut doc);
    doc
}

/// The list of deployments that this role signs (T-346), which `podssh
/// relay serve --deployment` gives once; nothing of a request goes into it,
/// so the role signs no text that a client chose.
static LIST: std::sync::OnceLock<crate::pool::signed::Signer> = std::sync::OnceLock::new();

/// Sign the list of `signer` in each `/relays.json` of this process's role;
/// the first call wins, as a process has one role.
pub fn sign_list(signer: crate::pool::signed::Signer) {
    let _ = LIST.set(signer);
}

/// `doc` with the signed list as `signed`, beside the pool, when the role
/// has one: each client that trusts its key takes the list's deployments.
fn signed_list(doc: &mut Value) {
    if let Some(signer) = LIST.get() {
        let now_s = i64::try_from(super::tokens::now_ms() / 1000).unwrap_or(0);
        doc["signed"] = signer.current(now_s);
    }
}

/// `/trace`: public alone; the dial of `?target=HOST:PORT` needs a token in
/// its header, never in the URL, and its target passes the policy.
pub async fn trace(cfg: &Config, head: &Request) -> Vec<u8> {
    let query = head.target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let get = |key: &str| query.split('&').find_map(|p| p.strip_prefix(key)?.strip_prefix('=').map(str::to_string));
    if get("token").is_some() {
        return request::refusal(400, "trace: a token belongs in the X-Relay-Token header", &[]);
    }
    let mut doc = json!({
        "request": { "edge_colo": null, "path": "/trace" },
        "relay": { "name": "podssh", "version": cfg.version },
    });
    let Some(wanted) = get("target") else { return json(&doc) };
    if !head.header("x-relay-token").is_some_and(|t| cfg.tokens.check(t, super::tokens::now_ms())) {
        return request::refusal(403, "trace: missing or wrong token", &[]);
    }
    let Some((host, port)) = wanted.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?))) else {
        return request::refusal(400, "trace: the target is HOST:PORT", &[]);
    };
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    doc["target"] = match cfg.policy.plan(&host, port, None, &cfg.egress).await {
        Err(refused) => {
            if let Some(line) = refused.logged() {
                cfg.event(&line);
            }
            json!({ "error": format!("refused: {}", refused.said()) })
        }
        Ok(plan) => dial_for_trace(&host, port, &plan, cfg).await,
    };
    json(&doc)
}

/// The trace's dial, as a session's goes: through the host's proxy when one
/// is set (T-457), whose leg the answer names as it went.
async fn dial_for_trace(host: &str, port: u16, plan: &Plan, cfg: &Config) -> Value {
    let started = Instant::now();
    let (mut tcp, leg) = match egress::dial(host, plan, &cfg.egress, &cfg.policy.ipv6, cfg.limits.connect).await {
        Ok(reached) => reached,
        Err(missed) => {
            if let Some(line) = missed.line {
                cfg.event(&format!("proxy: {line}"));
            }
            return json!({ "error": format!("refused: cannot reach {}: {}", shown(host, port), missed.said) });
        }
    };
    let connect_ms = started.elapsed().as_millis() as u64;
    let mut buf = vec![0u8; 4096];
    let (first_ms, seen, banner) = match tokio::time::timeout(BANNER_WAIT, tcp.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let line = buf[..n].split(|b| *b == b'\n').next().unwrap_or_default();
            let line = String::from_utf8_lossy(line).trim_end_matches('\r').to_string();
            (json!(started.elapsed().as_millis() as u64), n, json!(line))
        }
        _ => (Value::Null, 0, Value::Null),
    };
    let mut found = json!({
        "host": host, "port": port, "ok": true, "road": "direct", "dialed": leg.dialed,
        "dialed_literal": host.parse::<std::net::IpAddr>().is_ok(),
        // None for a name that the proxy resolved: its family is the proxy's.
        "address_family": leg.family.map(|f| f.to_string()),
        "connect_ms": connect_ms, "first_byte_ms": first_ms, "bytes_seen": seen,
        "verdict": if seen > 0 { "live" } else { "silent-or-unreachable" }, "banner": banner,
    });
    // The proxy's leg by its kind, never where the proxy is.
    if let Some(kind) = leg.proxy {
        found["road"] = json!("proxy");
        found["proxy"] = json!(kind.name());
    }
    found
}

/// A `200` with a JSON body.
pub fn json(doc: &Value) -> Vec<u8> {
    ok("application/json", doc.to_string().as_bytes())
}

/// A `200` with a body of text.
pub fn text(body: &str) -> Vec<u8> {
    ok("text/plain; charset=utf-8", body.as_bytes())
}

fn ok(kind: &str, body: &[u8]) -> Vec<u8> {
    // The Date lets a client check its own clock, as `podssh doctor` does
    // with the default relay's.
    let date = http_date(super::tokens::now_ms() / 1000);
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nDate: {date}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// `secs` after the epoch as an HTTP date (RFC 9110, section 5.6.7):
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // The civil date of a day count, by Howard Hinnant's days_from_civil
    // turned around: years of 400 from 0000-03-01.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            version: "test".into(),
            mint: super::super::Mint::Anyone,
            tokens: super::super::tokens::Tokens::new([3; 32]),
            policy: Default::default(),
            egress: Default::default(),
            limits: Default::default(),
            pairs: Default::default(),
            resumes: Default::default(),
            answered: Default::default(),
            brake: Default::default(),
            events: None,
        }
    }

    fn head(target: &str) -> Request {
        let text = format!("GET {target} HTTP/1.1\r\nHost: relay-a.test:8443\r\n\r\n");
        request::parse_request(text.as_bytes()).unwrap()
    }

    #[test]
    fn relays_json_names_this_host_the_target_and_the_five_limits() {
        let doc = relays(&cfg(), &head("/relays.json?host=github.com&port=22"));
        assert_eq!(doc["pool"][0]["host"], "relay-a.test");
        assert_eq!(doc["connect"], "wss://relay-a.test:8443/connect/github.com/22");
        let l = &doc["limits"];
        assert_eq!(
            (&l["connect_timeout_ms"], &l["idle_timeout_ms"], &l["max_session_ms"]),
            (&json!(10000), &json!(180000), &json!(43200000))
        );
        assert_eq!((&l["max_session_bytes"], &l["max_frame_bytes"]), (&json!(67108864), &json!(262144)));
        assert_eq!(doc["reverse"]["pair_once"], true, "pairs of one upgrade are offered (T-226)");
        assert_eq!((&doc["reverse"]["leg_tokens"], &doc["reverse"]["rotate"]), (&json!(true), &json!(true)), "T-615");
        let body = doc.to_string();
        assert!(crate::forward_layer::offered(body.as_bytes()), "the resumable layer is offered (T-173): {body}");
        assert_eq!(health(&cfg())["service"], "tcp-ssh-relay");
        assert_eq!(health(&cfg())["reverse"]["enabled"], true, "the reverse road is served (T-427)");
        // Whether the host routes IPv6 out, as the role knows it (T-253).
        let mut none = cfg();
        none.policy.ipv6 = super::super::ipv6::Ipv6Out::none();
        assert_eq!(relays(&none, &head("/relays.json"))["egress"]["ipv6"], false);
    }

    #[test]
    fn an_http_date_is_the_rfcs_form() {
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_709_164_800), "Thu, 29 Feb 2024 00:00:00 GMT");
        assert_eq!(http_date(1_793_577_600), "Mon, 02 Nov 2026 00:00:00 GMT");
    }

    #[tokio::test]
    async fn trace_takes_no_token_in_the_url_and_dials_with_one_alone() {
        let reply = |b: Vec<u8>| String::from_utf8(b).unwrap();
        let c = cfg();
        assert!(reply(trace(&c, &head("/trace?token=x")).await).starts_with("HTTP/1.1 400"));
        assert!(reply(trace(&c, &head("/trace?target=github.com:22")).await).starts_with("HTTP/1.1 403"));
        assert!(reply(trace(&c, &head("/trace")).await).contains("\"relay\""));
        assert!(SPEC.contains("2026-10-03-r2"), "the pinned contract is served");
    }
}
