//! E15 — ⛔ **the resolver test doubles, in one place, because they are the same
//! object in every file that needs one.**
//!
//! ⛔ **Why a module and not a copy per file.** `dns_plants.rs` was 525 lines and
//! `dns_props.rs` passed 605 ⛔ — ⛔ **and both were over the limit for the same
//! reason: the same `Counting` stand-in, the same `absent_hosts()`, the same
//! `budgets()`, written out twice.** ⛔ **Two copies of a resolver double are
//! two resolvers**, ⛔ and ⛔ **the second one is free to disagree
//! ⛔ about what a name resolves to** ⛔ — ⛔ so the count
//! ⛔ and the answers live here once.
//!
//! ⛔ **`#[allow(dead_code)]` on the module, and the reason is structural.**
//! `tests/common` is compiled into every test binary that declares `mod common;`
//! ⛔ — ⛔ `framing.rs` and `plants.rs` declare it too ⛔ — ⛔ so ⛔
//! ⛔ **every helper here is unused in four of the six
//! ⛔ binaries**, ⛔ and ⛔ **a warning per helper
//! ⛔ per binary is a warning nobody reads.** ⛔ The
//! alternative ⛔ — ⛔ a `#[cfg]` per file ⛔ — ⛔ makes the
//! ⛔ helpers' availability depend on which file you are in.

// ⛔ Every helper here is used by two of the six test binaries that compile
// `tests/common`; see the module comment for why that is not six warnings.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_transport::dns::{self, Budgets, DohEndpoint, HostsFile, SystemLookup, SystemResult};

/// ⛔ **Short enough for a test suite and long enough that a real
/// `getaddrinfo` beats it** ⛔ — ⛔ **the watchdog's bound is measured against
/// ⛔ this number**, ⛔ so it is named once rather than written
/// ⛔ at each call site where two of them could disagree.
pub const BUDGET: Duration = Duration::from_millis(400);

/// ⛔ **`relay-hostname.md`'s rank-0 pool name, and `INFERRED` from its own
/// measurement table** ⛔ — ⛔ not a name podssh ships (E17: ⛔ **never hardcode a
/// relay NAME**), ⛔ and the tests below only ever pass it *into* podssh.
pub const RELAY: &str = "tcp-1.ssh.relay.ajam.dev";

/// ⛔ **Which plant arm runs.** ⛔ The two-arm pattern is `tests/plants.rs`'s,
/// ⛔ and ⛔ **a plant and its control are separate runs of the same test**, so
/// ⛔ the selector has to be a thing every test can ask.
pub fn planted(name: &str) -> bool {
    std::env::var("PODSSH_PLANT").as_deref() == Ok(name)
}

/// ⛔ **A system resolver whose every call is recorded.** ⛔ **The count is the
/// ⛔ assertion that `Literal` consulted nobody**, ⛔ and ⛔ **an assertion
/// ⛔ on a count rather than on a timing is the only kind that survives a
/// ⛔ fast machine.**
#[derive(Debug)]
pub struct Counting {
    answers: Mutex<Vec<(String, u16)>>,
    pub calls: AtomicUsize,
    fail: bool,
}

impl Counting {
    /// ⛔ **A resolver that answers the two names the tests use**, ⛔ and
    /// ⛔ **errors for every other name** ⛔ — ⛔ **so a test that expects a
    /// ⛔ miss gets one** ⛔ rather than ⛔ a resolver that knows everything.
    pub fn answering() -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(vec![
                (RELAY.to_string(), 443),
                ("example.com".to_string(), 443),
            ]),
            calls: AtomicUsize::new(0),
            fail: false,
        })
    }

    pub fn failing() -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            fail: true,
        })
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SystemLookup for Counting {
    fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, (Option<i32>, String)> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err((Some(-2), "Name or service not known".to_string()));
        }
        self.answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(host))
            .map(|(_h, _)| {
                // ⛔ **A `SocketAddr`, and not a formatted `host:port` string**:
                // ⛔ **MEASURED 2026-10-02** ⛔ a first version of this
                // ⛔ formatted `tcp-1.ssh.relay.ajam.dev:443` and parsed it ⛔ —
                // ⛔ **and `SocketAddr::from_str` rejects a name**, ⛔ so the
                // ⛔ stand-in ⛔ panicked inside the resolver thread ⛔ and ⛔ the
                // ⛔ panic ⛔ **surfaced as `????` on every stage** ⛔ — ⛔ the
                // ⛔ watchdog's own panic path, ⛔ not a DNS fact.
                vec![SocketAddr::new(std::net::IpAddr::from([104, 21, 39, 2]), port)]
            })
            .ok_or((None, format!("no entry for {host}")))
    }
}

/// ⛔ **A `getaddrinfo` that never returns.** ⛔ **This is the shape of the
/// ⛔ real hang** ⛔ — ⛔ a host whose `resolv.conf` names a nameserver the
/// ⛔ egress refuses ⛔ — ⛔ and ⛔ **it is the only honest way to
/// ⛔ test a watchdog on a machine whose resolver works.**
pub struct HangForever;

impl SystemLookup for HangForever {
    fn lookup(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, (Option<i32>, String)> {
        loop {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// ⛔ **A DoH transport that never answers**, for the unreachable-endpoint plant.
pub struct Unreachable;

impl dns::DohTransport for Unreachable {
    fn send(
        &self,
        endpoint: &DohEndpoint,
        _request_line: &str,
        _headers: &[(String, String)],
        _budget: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<dns::DohResponse, String>> + Send + '_>>
    {
        let detail =
            format!("nothing is listening on {}:{}", endpoint.name, endpoint.address.port());
        Box::pin(async move { Err(detail) })
    }
}

pub fn endpoint() -> DohEndpoint {
    DohEndpoint::from_url("https://1.1.1.1/dns-query", 443).expect("an IP-literal endpoint")
}

/// ⛔ **A hosts file that does not exist**, ⛔ **because a test must not
/// ⛔ depend on what the machine running it has in `/etc/hosts`.** ⛔ The path
/// ⛔ carries the caller's tag ⛔ so two test files racing on the same
/// ⛔ nonexistent path cannot be mistaken for each other.
pub fn absent_hosts(tag: &str) -> HostsFile {
    HostsFile::at(format!("/nonexistent/podssh-{tag}-hosts").as_str())
}

pub fn budgets() -> Budgets {
    Budgets { system: BUDGET, doh: BUDGET }
}

/// ⛔ **One `System` stage run at the test budget**, ⛔ **rather than calling
/// ⛔ [`dns::system::run`] at each site** ⛔ so ⛔ the plant and the control
/// ⛔ measure against ⛔ the same number.
pub fn system_stage<L: SystemLookup + 'static>(
    lookup: Arc<L>,
    host: &str,
    port: u16,
) -> SystemResult {
    dns::system::run(lookup, host, port, BUDGET)
}