//! Where a socket goes, and ⛔ **what podssh refuses to guess**.
//!
//! ⛔ **podssh ships no default relay path.** `01-relay-protocol.md:65-77` records
//! the fact that makes this non-negotiable: **READ**, live spec line 28 reads
//! `- (none configured)`, live line 21 reads `not configured`, and `/health`
//! reports `"relays": []` — **MEASURED** 2026-10-02 from this machine, and
//! re-measured again during this session. ⛔ **The sibling project hardcodes
//! `/connect/railway`** (`dropssh` `src/dropssh.h:42`, consumed at
//! `src/connect.c:143`) ⛔ **and that target no longer exists**, so a stock
//! client of theirs dials a gateway the relay no longer has.
//!
//! ⛔ **A token never enters a URL.** **READ**, spec lines 94-96: *"Send a
//! forward token in `X-Relay-Token`; use `?token=` or `/t/<t>/...` … only when
//! headers are unavailable, since URLs can appear in logs. Send a reverse token
//! only as `X-Relay-Token` or `?token=`."* ⛔ **The `?token=` and `/t/<t>/` forms
//! are read off the live document, and podssh uses neither**, because a header is
//! available on every path it takes and `01-relay-protocol.md:146-149` says
//! plainly: *"podssh must never put a token in a URL when a header is available."*

/// ⛔ **The token header.** Spec lines 94 and 96 both name it.
pub const TOKEN_HEADER: &str = "X-Relay-Token";

/// ⛔ **Which leg a socket belongs to.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegTarget {
    /// ⛔ **READ**, spec line 22: `/connect/<public-host>/<port>`.
    Forward { host: String, port: u16 },
    /// ⛔ **READ**, spec line 23: `/v1/node/<name>`, `node_token`.
    ReverseNode { name: String },
    /// ⛔ **READ**, spec line 24: `/v1/connect/<name>`, `connect_token`.
    ReverseOperator { name: String },
}

impl LegTarget {
    /// ⛔ **The path, and nothing else.** ⛔ **No query string, no token, ever.**
    pub fn path(&self) -> String {
        match self {
            LegTarget::Forward { host, port } => format!("/connect/{host}/{port}"),
            LegTarget::ReverseNode { name } => format!("/v1/node/{name}"),
            LegTarget::ReverseOperator { name } => format!("/v1/connect/{name}"),
        }
    }
}

/// ⛔ **The knobs the relay publishes**, spec lines 199-202. ⛔ **All `None` by
/// default**, because podssh does not enable a knob it has not measured the
/// effect of — spec line 202's `?precheck` is *"clamped to the server cap"* and
/// **that cap is published nowhere**
/// ([`exp-03-precheck-cap.md`](exp-03-precheck-cap.md)).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Knobs {
    pub family: Option<AddressFamily>,
    pub path: Option<EgressRoad>,
    pub lazy: bool,
    pub precheck_ms: Option<u64>,
}

/// ⛔ **READ**, spec line 199: `?family=4` / `?family=6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    fn as_str(self) -> &'static str {
        match self {
            AddressFamily::V4 => "4",
            AddressFamily::V6 => "6",
        }
    }
}

/// ⛔ **READ**, spec line 200: `?path=vpc` / `?path=direct`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRoad {
    Vpc,
    Direct,
}

impl EgressRoad {
    fn as_str(self) -> &'static str {
        match self {
            EgressRoad::Vpc => "vpc",
            EgressRoad::Direct => "direct",
        }
    }
}

/// ⛔ **What is configured.** ⛔ **There is no `Default`, and no constant.** A
/// value of this type can only exist by naming a relay, which is the whole point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    /// ⛔ **The `wss://` origin**, from `/relays.json`'s `connect` field or an
    /// operator's configuration. ⛔ **Never the apex host by default**:
    /// `01-relay-protocol.md:46-54` records that `/relays.json` ranks the pool
    /// and returned `wss://tcp-1.ssh.relay.ajam.dev/connect/github.com/22` —
    /// **MEASURED** 2026-10-01, and re-measured 2026-10-02, still `tcp-1`.
    pub origin: String,
    pub knobs: Knobs,
}

/// ⛔ **The built request: a path, a header map, and ⛔ a guarantee about what is
/// not in either.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub url: String,
    pub headers: Vec<(String, String)>,
}

impl Endpoint {
    /// ⛔ **The check that makes the token rule structural rather than a
    /// convention.** ⛔ It is a method, not a comment, so it runs in a test and
    /// a reviewer's eye cannot be the only defence.
    ///
    /// Returns every position a credential appears in the URL, and an empty
    /// `Vec` means the URL is clean.
    pub fn token_positions_in_url(&self) -> Vec<&'static str> {
        let mut hits = Vec::new();
        for (marker, name) in [
            ("token=", "the ?token= query form"),
            ("/t/", "the /t/<token>/ path form"),
        ] {
            if self.url.contains(marker) {
                hits.push(name);
            }
        }
        hits
    }
}

/// ⛔ **Build the request for a leg.** ⛔ **Takes the token by value and puts it
/// in a header, always.**
pub fn endpoint(config: &RelayConfig, target: &LegTarget, token: &str) -> Endpoint {
    let mut url = format!(
        "{}{}",
        config.origin.trim_end_matches('/'),
        target.path()
    );
    let mut query: Vec<String> = Vec::new();
    if let Some(family) = config.knobs.family {
        query.push(format!("family={}", family.as_str()));
    }
    if let Some(road) = config.knobs.path {
        query.push(format!("path={}", road.as_str()));
    }
    if config.knobs.lazy {
        query.push("dial=lazy".to_string());
    }
    if let Some(precheck) = config.knobs.precheck_ms {
        query.push(format!("precheck={precheck}"));
    }
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query.join("&"));
    }
    // ⛔ **The token goes here and nowhere else.**
    Endpoint {
        url,
        headers: vec![(TOKEN_HEADER.to_string(), token.to_string())],
    }
}

/// ⛔ **The forward frame cap, read from `/relays.json`.** ⛔ **This is a runtime
/// value and never a constant** — there is no `hello` frame on the forward path,
/// so nothing on the wire can tell a client the cap
/// (`01-relay-protocol.md:215-217`).
///
/// ⚠ **The value this module was written against**, carried here as a *record*
/// and not as a default: **MEASURED 2026-10-02, this machine, Git Bash on
/// Windows**, `curl -sSL 'https://tcp.ssh.relay.ajam.dev/relays.json?host=github.com&port=22'`
/// → `"max_frame_bytes": 262144`. ⚠ **This constant is not a fallback**: it is
/// what `Limits::forward` is given when the operator has *not* read `/relays.json`,
/// and it must be replaced by the measured value before a session starts. The
/// test `the_compiled_forward_cap_is_a_record_and_not_a_default` says so.
pub const FORWARD_MAX_FRAME_MEASURED: usize = 262144;