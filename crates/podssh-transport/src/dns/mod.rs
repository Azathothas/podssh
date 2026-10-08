//! E15 — the resolver chain: ⛔ **`Literal`, `Cache`, `System`, `Hosts`, `Doh`**.
//!
//! ⛔ **A DoH-only resolver lost** (`dns.md` `## Decision`): it makes every
//! startup depend on a third-party endpoint, discards `/etc/hosts` and the
//! system resolver — the two things that work on most hosts — and makes a host
//! with a perfect resolver pay a round trip for names it already cached. ⛔
//! **The chain wins because each stage strictly improves on the next and none
//! can make a working host worse.** So the whole chain is here even though ⛔
//! **E05 — the probe that decides whether the `Doh` stage is *reachable* — has
//! never been run.** The stage is built and bounded; whether it ever answers on
//! the target host is `UNKNOWN` and belongs to E05.
//!
//! ⛔ **`Literal` short-circuits everything, and it short-circuits *first*.**
//! **READ**, `dropssh` `src/dns.c:316-330`: a dotted quad or an IPv6 literal must
//! never reach a resolver. Asking a DoH server to resolve something that is
//! already an address is a round trip that can fail for no reason. ⛔ **`Cache`
//! is second for the sibling's reason** (`src/dns.c:308-312`): *"THE CACHE
//! EXISTS BECAUSE A SESSION RECONNECTS"*, and a reconnect is exactly when the
//! operator is waiting.
//!
//! ⛔ **Every wait is bounded, per-stage, not per-call.** The system resolver is
//! the one that hangs: `getaddrinfo` on a host whose `resolv.conf` names an
//! unreachable nameserver blocks past any timeout set around it. ⛔ **podssh runs
//! the system stage on a blocking thread with a watchdog, not on the async
//! runtime's timeout** — a future cancelled by `tokio::time::timeout` does not
//! stop a thread already inside libc. ⛔ **The sibling calls `getaddrinfo` inline**
//! (`src/dns.c:336-356`) ⛔ **and inherits whatever the platform does.** A watchdog
//! is implemented in [`system::watchdog`], and it is tested against a `getaddrinfo`
//! that never returns.
//!
//! ⛔ **The failure message names every stage it tried**, never "resolution
//! failed". **READ**, `dropssh` `src/dns.c:378-381` is the model:
//! *"cannot resolve %s: getaddrinfo failed, /etc/hosts has no entry, and DoH did
//! not answer (%s)"*, ⛔ **because a bare `cannot resolve` is the message that
//! costs a session** and each source has a different fix.
//!
//! ⛔ **No stage returns an empty `Vec<SocketAddr>` as success.** Every stage
//! returns `Err` or at least one address, and the chain turns an empty answer
//! into the same error a missing stage produces — a caller cannot mistake "the
//! stage ran and found nothing" for "resolved".

mod cache;
mod chain;
mod doh;
mod failure;
mod hosts;
pub mod literal;
mod lookup;
pub mod stages;
pub mod system;

use std::net::SocketAddr;

pub use cache::Cache;
pub use chain::{Budgets, Chain, Sources};
pub use doh::{
    base64url, base64url_decode, decode_question, DohAnswer, DohEndpoint, DohError, DohQuery,
    DohResponse, DohTransport, ScriptedTransport, DEFAULT_PATH as DOH_DEFAULT_PATH,
    SCHEME as DOH_SCHEME, TYPE_A, TYPE_AAAA,
};
pub use hosts::HostsFile;
pub use lookup::lookup as doh_lookup;
pub use literal::{address as literal_address, as_literal, looks_like_an_address};
pub use system::{
    SystemLookup, SystemResolver, SystemResult, Watchdog, SYSTEM_BUDGET,
};


pub use failure::ResolveError;
pub use stages::{not_consulted, How, Stage, StageOutcome, StageReport};

/// ⛔ **A successful resolution, and the stage that produced it.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub host: String,
    pub port: u16,
    pub addrs: Vec<SocketAddr>,
    pub how: How,
}

impl Answer {
    /// ⛔ **The first address, or an error naming the host and the stage.** A
    /// caller that dialled `addrs[0]` on an empty `Vec` would panic, and ⛔ **an
    /// empty `Vec<SocketAddr>` some caller treats as success is exactly the
    /// failure `dns.md`'s `Prove` block forbids.**
    pub fn first(&self) -> Result<SocketAddr, ResolveError> {
        self.addrs.first().copied().ok_or_else(|| {
            ResolveError::Exhausted {
                host: self.host.clone(),
                tried: vec![StageReport {
                    stage: self.how.stage(),
                    // ⛔ `Ok` with an empty list is representable and is refused
                    // here rather than being handed on: the stage claimed success
                    // and produced nothing, and that contradiction is the fault.
                    outcome: StageOutcome::Failed {
                        errno: None,
                        detail: format!(
                            "the {} stage reported ok with zero addresses; an empty answer \
                             is not a resolution",
                            self.how
                        ),
                    },
                    consulted: true,
                }],
            }
        })
    }
}
