//! The HTTP road (T-319, GitHub #55): a session of the forward road carried
//! by plain requests of HTTP/1.1, for a proxy that ends TLS for the relay's
//! name, refuses the WebSocket upgrade, and still carries requests and their
//! answers (the proxy of a Claude Code cloud container documents such a
//! refusal, T-311). Its split form keeps two connections to the relay host,
//! one for the bytes down and one for the bytes up, which the operator's
//! ruling Q44 allows on this road alone, once the upgrade was refused on the
//! way; the serial form, one request after another on one connection, is its
//! fallback.
//!
//! The wire, which podssh's relay role serves (`crate::serve::http_road`)
//! and [`client`] speaks:
//!
//! - `POST /v1/http/open/HOST/PORT[?family=4|6]`, with the forward token in
//!   `X-Relay-Token`: the role checks the target as `/connect/` does and
//!   dials it, then answers `200` with JSON: the session's id, its key, and
//!   its bounds (`batch_max`, `wait_max_ms`, `down_max`).
//! - Each later request names the session by its id in the path, and proves
//!   it by its key in `X-Session-Key`, never in a URL, as URLs go into logs.
//!   A wrong key and an id that the role does not know get the same `404`.
//! - Up: `POST /v1/http/s/ID/up?seq=N[&fin=1]`, one whole batch, numbered
//!   from 0. `204` once the role stored it. The same number again is the same
//!   batch, answered alike and stored once, so a client sends a batch again,
//!   with the same body, until an answer comes. `X-Ack` is the number of
//!   batches that the target took; past a bounded window the role holds the
//!   answer, then says `503` with `Retry-After`. `fin=1` marks the last
//!   batch, after which the target gets TCP's half-close.
//! - Down: `GET /v1/http/s/ID/down?at=OFFSET&wait=MS`: the target's bytes
//!   from OFFSET, which also says that each byte before it came, so the role
//!   forgets them. The role holds a bounded window of bytes that no request
//!   acknowledged, and reads the target no further until one does. An answer
//!   with bytes is `200` with `X-Offset`, and ends a moment after nothing more
//!   came, or at `down_max` bytes, so that a hop that holds an answer to its
//!   end holds a short one; with nothing for `wait`, a whole `204`. A body
//!   that a hop cut costs nothing: the next request names the offset that
//!   came.
//! - Serial: `POST /v1/http/s/ID/x?[seq=N&]at=OFFSET&wait=MS[&fin=1]`: a
//!   batch up when `seq` is given, as `up` takes it, and the bytes down from
//!   OFFSET in a whole answer, as `down` gives them.
//! - `POST /v1/http/s/ID/close` ends the session at once.
//! - Once the session ended, `410` with `X-Close: CODE REASON`, the close
//!   codes and reasons of the forward road (`docs/relay.md`): `1000 target
//!   closed` once the client has each byte of a target that ended.

pub mod answer;
pub mod client;
pub mod conn;
mod serial;
mod split;

use std::time::Duration;

/// The paths of the road, under the role's `/v1/`.
pub const PREFIX: &str = "/v1/http/";
pub const OPEN: &str = "/v1/http/open/";
pub const SESSION: &str = "/v1/http/s/";
/// The headers of the road.
pub const KEY: &str = "X-Session-Key";
pub const ACK: &str = "X-Ack";
pub const OFFSET: &str = "X-Offset";
pub const CLOSE: &str = "X-Close";

/// The largest batch that the role takes: a POST of the forward road's
/// session, which a hop holds whole.
pub const BATCH_MAX: usize = 256 * 1024;
/// The most bytes of one answer down.
pub const DOWN_MAX: usize = 1 << 20;
/// The longest wait of an answer down with nothing to send: below the 60 s
/// of the idle limits that GitHub #54 names (an AWS load balancer, nginx),
/// and of a quick tunnel's node.
pub const WAIT_MAX: Duration = Duration::from_secs(25);

/// The two forms of the road (Q44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// The bytes down on one connection and the bytes up on another, at once.
    Split,
    /// One exchange after another on one connection.
    Serial,
}

impl Form {
    pub fn name(self) -> &'static str {
        match self {
            Form::Split => "split",
            Form::Serial => "serial",
        }
    }
}

/// What a request of a session asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Up,
    Down,
    Exchange,
    Close,
}

/// Which request of the road a path, with no query, is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Open,
    /// The session's id, and what is asked of it.
    Session(String, Kind),
}

/// The route of `path`; `None` for a path of the road that names nothing.
pub fn route(path: &str) -> Option<Route> {
    if path.starts_with(OPEN) {
        return Some(Route::Open);
    }
    let rest = path.strip_prefix(SESSION)?;
    let (id, what) = rest.split_once('/')?;
    if !is_id(id) {
        return None;
    }
    let kind = match what {
        "up" => Kind::Up,
        "down" => Kind::Down,
        "x" => Kind::Exchange,
        "close" => Kind::Close,
        _ => return None,
    };
    Some(Route::Session(id.to_string(), kind))
}

/// Whether `id` is a session's id: 32 hex digits in lower case.
pub fn is_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `key` is a session's key: 43 characters of base64url, so that it
/// cannot break a header.
pub fn is_key(key: &str) -> bool {
    key.len() == 43 && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The words of a request's query.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    pub seq: Option<u64>,
    pub at: Option<u64>,
    pub wait_ms: Option<u64>,
    pub fin: bool,
}

/// The query of a request-target; a word that does not read is absent.
pub fn query(target: &str) -> Query {
    let mut q = Query::default();
    let Some((_, words)) = target.split_once('?') else { return q };
    for pair in words.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "seq" => q.seq = value.parse().ok(),
            "at" => q.at = value.parse().ok(),
            "wait" => q.wait_ms = value.parse().ok(),
            "fin" => q.fin = value == "1",
            _ => {}
        }
    }
    q
}

/// `X-Close`'s value: the code, then the reason on one line.
pub fn close_value(code: u16, reason: &str) -> String {
    format!("{code} {}", podssh_ws::text::one_line(reason))
}

/// The code and the reason of an `X-Close`.
pub fn parse_close(value: &str) -> Option<(u16, String)> {
    let (code, reason) = value.trim().split_once(' ').unwrap_or((value.trim(), ""));
    Some((code.parse().ok()?, reason.trim().to_string()))
}

/// How a client of the road sizes its requests: from what `podssh doctor
/// --stream` measured of a path (T-325) where a caller has it, never past the
/// role's own bounds, which its open names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// The most bytes of a batch up.
    pub batch: usize,
    /// The wait of an answer down with nothing to send.
    pub wait: Duration,
    /// The longest pause of the serial form between two exchanges that
    /// carried nothing.
    pub poll_max: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning { batch: BATCH_MAX, wait: Duration::from_secs(20), poll_max: Duration::from_secs(1) }
    }
}

impl Tuning {
    /// The default, under a path's cap on a body (half of it, as a hop's
    /// headers count too) and its limit on a quiet answer (two thirds of it).
    pub fn measured(body_cap: Option<u64>, quiet: Option<Duration>) -> Tuning {
        let mut tuning = Tuning::default();
        if let Some(cap) = body_cap {
            tuning.batch = tuning.batch.min((cap / 2) as usize).max(4096);
        }
        if let Some(quiet) = quiet {
            tuning.wait = tuning.wait.min(quiet * 2 / 3).max(Duration::from_secs(1));
        }
        tuning
    }
}

/// What podssh says it is, in each request.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_path_of_the_road_has_its_route_and_another_none() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(route("/v1/http/open/github.com/22"), Some(Route::Open));
        assert_eq!(route(&format!("/v1/http/s/{id}/up")), Some(Route::Session(id.into(), Kind::Up)));
        assert_eq!(route(&format!("/v1/http/s/{id}/down")), Some(Route::Session(id.into(), Kind::Down)));
        assert_eq!(route(&format!("/v1/http/s/{id}/x")), Some(Route::Session(id.into(), Kind::Exchange)));
        assert_eq!(route(&format!("/v1/http/s/{id}/close")), Some(Route::Session(id.into(), Kind::Close)));
        for bad in ["/v1/http/s/abc/up", "/v1/http/s/0123456789ABCDEF0123456789ABCDEF/up", "/v1/http/x", "/v1/http/"] {
            assert_eq!(route(bad), None, "{bad}");
        }
        assert_eq!(route(&format!("/v1/http/s/{id}/other")), None);
    }

    #[test]
    fn a_query_reads_its_numbers_and_leaves_what_does_not_read() {
        let q = query("/v1/http/s/x/x?seq=7&at=1048576&wait=250&fin=1");
        assert_eq!(q, Query { seq: Some(7), at: Some(1 << 20), wait_ms: Some(250), fin: true });
        assert_eq!(query("/p"), Query::default());
        let odd = query("/p?seq=-1&at=x&fin=yes&other=2");
        assert_eq!((odd.seq, odd.at, odd.fin), (None, None, false));
    }

    #[test]
    fn a_close_says_its_code_and_its_reason_on_one_line() {
        assert_eq!(close_value(1001, "idle timeout"), "1001 idle timeout");
        assert_eq!(parse_close("1001 idle timeout"), Some((1001, "idle timeout".into())));
        assert_eq!(parse_close("1000"), Some((1000, String::new())));
        assert_eq!(parse_close("soon"), None);
        assert!(!close_value(1011, "write failed:\r\nX: y").contains('\n'));
    }

    #[test]
    fn a_measured_path_shrinks_the_batch_and_the_wait_and_never_grows_them() {
        let small = Tuning::measured(Some(1 << 20), Some(Duration::from_secs(9)));
        assert_eq!((small.batch, small.wait), (BATCH_MAX, Duration::from_secs(6)));
        let capped = Tuning::measured(Some(64 * 1024), None);
        assert_eq!(capped.batch, 32 * 1024);
        assert_eq!(Tuning::measured(Some(100), Some(Duration::from_millis(10))).batch, 4096);
        assert_eq!(Tuning::measured(None, Some(Duration::from_millis(10))).wait, Duration::from_secs(1));
        assert_eq!(Tuning::measured(None, Some(Duration::from_secs(600))), Tuning::default());
        assert!(is_key("abcdefghijklmnopqrstuvwxyzABCDEFGHIJ-_01234") && !is_key("short"));
    }
}
