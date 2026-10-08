//! E15 — ⛔ **the chain, and the rule that decides what it returns.**
//!
//! ⛔ **The order is fixed and it is the one the entry fixes.** `dns.md`
//! `## Approach`: `Literal` short-circuits everything; `Cache` second for the
//! reason `dropssh` `src/dns.c:27-31` gives ⛔ — *"a reconnect is exactly when
//! the operator is waiting"*; `System` first among the network stages because it
//! is free and it is what everything else on the machine uses
//! (`relay-hostname.md` step 1); `/etc/hosts` second because ⛔ **"a curated
//! entry outranks DoH"** (`relay-hostname.md` step 2); `Doh` third; ⛔ **and an
//! explicitly configured address last, "consulted only after 1-3 fail"**
//! (`relay-hostname.md` step 4).
//!
//! ⛔ **Every wait is bounded, per-stage.** ⛔ No stage here has a timeout set
//! *around* it and no stage runs on the async runtime's timer ⛔ — `System` goes
//! through [`crate::dns::system::watchdog`], and ⛔ **that is the difference
//! between a bounded wait and a future that was cancelled while a thread stays
//! inside libc.**
//!
//! ⛔ **`Literal` consults nothing at all.** ⛔ The chain holds a count of
//! resolvers it asked, and [`Chain::asked`] is public ⛔ **so a test can assert
//! the count is zero** rather than inferring it from a timing measurement.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::cache::{normalise, Cache};
use super::doh::{DohEndpoint, DohTransport};
use super::hosts::HostsFile;
use super::literal as literal_stage;
use super::system::{self, SystemLookup, SystemResolver, SystemResult};
use super::{
    not_consulted, Answer, How, ResolveError, Stage, StageOutcome, StageReport,
};

/// ⛔ **What the chain needs from its caller.** ⛔ **Three separate things, and
/// a `Doh` stage that has no transport is `????` and not `FAIL`** ⛔ — ⛔ **E05
/// has not been run, so no DoH endpoint on the target host has been measured as
/// reachable**, and a stage that was never attempted must say so.
pub struct Sources {
    /// ⛔ The system resolver. ⛔ **`Arc` because it is handed to a thread** that
    /// the watchdog owns, and a borrowed `&L` cannot outlive the call.
    pub system: Arc<dyn SystemLookup>,
    pub hosts: HostsFile,
    /// ⛔ **`None` means the stage is not configured.** ⛔ That is `????`, not
    /// `FAIL`: ⛔ **a stage that did not run must not report a result.**
    pub doh: Option<DohEndpoint>,
    /// ⛔ **The transport, and it may be absent while the endpoint is present**
    /// ⛔ — ⛔ **that combination is `????` too**, because the endpoint is known
    /// and nothing has yet carried a request to it.
    pub doh_transport: Option<Arc<dyn DohTransport>>,
    /// ⛔ **E17's fourth source: an operator-configured `(name, address)` pair.**
    /// ⛔ **There is no default and there is no constant** ⛔ — E06's entry is
    /// about a compiled-in path that no longer exists, and this is the same class
    /// of value.
    pub configured: Vec<(String, std::net::SocketAddr)>,
    pub cache: Cache,
    pub budgets: Budgets,
}

/// ⛔ **Every bound, in one place, so a plant can shorten all of them.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    /// ⛔ The `System` stage's watchdog.
    pub system: Duration,
    /// ⛔ The `Doh` stage, per query.
    pub doh: Duration,
}

impl Default for Budgets {
    /// ⛔ **The DoH budget is longer than the system one, and the reason is that
    /// DoH opens a TLS session.** ⛔ Four seconds is the whole of one round trip
    /// on port 53 ⛔ **and is not enough for a TCP connect, a certificate
    /// verification, an HTTP round trip and a parse** ⛔ — ⛔ a bound chosen as
    /// "a bit more than the system one" would have failed every DoH query on a
    /// slow link and been reported as "DoH did not answer".
    fn default() -> Self {
        Self {
            system: system::SYSTEM_BUDGET,
            doh: Duration::from_secs(10),
        }
    }
}

impl Default for Sources {
    fn default() -> Self {
        Self {
            system: Arc::new(SystemResolver::new()),
            hosts: HostsFile::system(),
            doh: None,
            doh_transport: None,
            configured: Vec::new(),
            cache: Cache::new(),
            budgets: Budgets::default(),
        }
    }
}

/// ⛔ **The resolver.** ⛔ **No `Default`** ⛔ — ⛔ a `Default` would be a resolver
/// with a system stage and no configured DoH endpoint, which is a thing that
/// cannot answer anything on the constrained host and would look configured.
pub struct Chain {
    sources: Sources,
    /// ⛔ **How many resolvers were asked.** ⛔ `Literal` and `Cache` do not
    /// increment it ⛔ **because they are not resolvers** ⛔ — ⛔ **a literal must
    /// never reach one**, and this is the counter a plant asserts on.
    asked: AtomicUsize,
    /// ⛔ The order this chain runs. ⛔ A field ⛔ **because a test needs a chain
    /// that skips a stage**, ⛔ **and a `skip` parameter would be a stage the
    /// production caller could also reach.**
    order: [Stage; 6],
}

impl Chain {
    pub fn new(sources: Sources) -> Self {
        Self { sources, asked: AtomicUsize::new(0), order: Stage::DEFAULT_ORDER }
    }

    /// ⛔ **A chain that never consults one stage.** ⛔ **`Doh` disabled is the
    /// common case here**, ⛔ **not because DoH is refused but because E05 has not
    /// run** ⛔ — ⛔ so a caller with no endpoint gets `???? Doh` ⛔ **and never a
    /// silent skip.**
    pub fn with_order(mut self, order: [Stage; 6]) -> Self {
        self.order = order;
        self
    }

    /// ⛔ **How many resolvers this chain has asked.** ⛔ `0` after a literal.
    pub fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    pub fn sources(&self) -> &Sources {
        &self.sources
    }

    /// ⛔ **Resolve a name.** ⛔ **The port is a parameter and never a part of the
    /// name**, ⛔ because ⛔ **`relay-hostname.md`'s `--relay-address` pair and
    /// E15's host are different things** and a host string carrying `:443` in it
    /// is how a caller accidentally searches `/etc/hosts` for `example.com:443`.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Answer, ResolveError> {
        self.resolve_with_trace(host, port, &mut Vec::new()).await
    }

    /// ⛔ **`resolve`, keeping the per-stage trace.**
    ///
    /// ⛔ **A diagnostic needs the trace on BOTH paths, and that asymmetry is
    /// what made `record` and `doctor` invent reports.** On a failure
    /// `ResolveError` carries the trace ([`ResolveError::tried`]); on a success
    /// the [`Answer`] does not — so a report reconstructed from the outcome
    /// alone said `???? not consulted` about a stage that ran and failed on the
    /// way to a later one answering. ⛔ That is the misreport
    /// `docs/TODO/env/dns.md` forbids, and this is the fix: the caller gets what
    /// [`resolve`](Self::resolve) throws away.
    pub(crate) async fn resolve_traced(
        &self,
        host: &str,
        port: u16,
    ) -> (Result<Answer, ResolveError>, Vec<StageReport>) {
        let mut tried: Vec<StageReport> = Vec::with_capacity(Stage::ALL.len());
        let outcome = self.resolve_with_trace(host, port, &mut tried).await;
        (outcome, tried)
    }

    async fn resolve_with_trace(
        &self,
        host: &str,
        port: u16,
        tried: &mut Vec<StageReport>,
    ) -> Result<Answer, ResolveError> {
        let host = host.trim();
        if host.is_empty() {
            return Err(ResolveError::Empty);
        }

        let mut watchdog_fired: Option<(Stage, Duration)> = None;

        for stage in self.order {
            if tried.iter().any(|r| r.stage == stage) {
                continue;
            }
            match stage {
                Stage::Literal => {
                    match literal_stage::address(host, port) {
                        Some(addr) => {
                            tried.push(StageReport {
                                stage,
                                outcome: StageOutcome::Ok { addresses: vec![addr.clone()] },
                                consulted: true,
                            });
                            return Ok(Answer { host: host.to_string(), port, addrs: vec![addr], how: How::Literal });
                        }
                        None => tried.push(not_consulted(stage, "the host is not an address")),
                    }
                }
                Stage::Cache => {
                    match self.sources.cache.get(host) {
                        Some(addrs) if !addrs.is_empty() => {
                            tried.push(StageReport {
                                stage,
                                outcome: StageOutcome::Ok { addresses: addrs.clone() },
                                consulted: true,
                            });
                            return Ok(Answer { host: host.to_string(), port, addrs, how: How::Cache });
                        }
                        _ => tried.push(not_consulted(stage, "nothing cached for this name")),
                    }
                }
                Stage::System => {
                    self.asked.fetch_add(1, Ordering::SeqCst);
                    let result = system::run(
                        Arc::clone(&self.sources.system) as Arc<dyn SystemLookup>,
                        host,
                        port,
                        self.sources.budgets.system,
                    );
                    let report = result.report();
                    let how = match &result {
                        SystemResult::Answered(addrs) if !addrs.is_empty() => Some((How::System, addrs.clone())),
                        _ => None,
                    };
                    tried.push(report);
                    if let Some((how, addrs)) = how {
                        self.sources.cache.put(host, &addrs);
                        return Ok(Answer { host: host.to_string(), port, addrs, how });
                    }
                    if let SystemResult::Abandoned { budget } = result {
                        // ⛔ **A watchdog is not a failure and it does not stop the
                        // chain.** ⛔ `dns.md`'s second plant requires the chain to
                        // continue to `/etc/hosts` and then DoH, and ⛔ **this is
                        // where it continues from.**
                        watchdog_fired.get_or_insert((Stage::System, budget));
                    }
                }
                Stage::Hosts => {
                    let addrs = normalise(self.sources.hosts.lookup(host, port));
                    if addrs.is_empty() {
                        let why = if self.sources.hosts.exists() {
                            format!("{} has no entry for {host}", self.sources.hosts.path().display())
                        } else {
                            format!("{} does not exist on this host", self.sources.hosts.path().display())
                        };
                        tried.push(not_consulted(stage, &why));
                    } else {
                        tried.push(StageReport {
                            stage,
                            outcome: StageOutcome::Ok { addresses: addrs.clone() },
                            consulted: true,
                        });
                        self.sources.cache.put(host, &addrs);
                        return Ok(Answer { host: host.to_string(), port, addrs, how: How::Hosts });
                    }
                }
                Stage::Doh => {
                    let report = self.stage_doh(host, port).await;
                    let answered = match report.outcome {
                        StageOutcome::Ok { ref addresses } if !addresses.is_empty() => {
                            let addrs = addresses.clone();
                            self.sources.cache.put(host, &addrs);
                            Some((How::Doh, addrs))
                        }
                        _ => None,
                    };
                    tried.push(report);
                    if let Some((how, addrs)) = answered {
                        return Ok(Answer { host: host.to_string(), port, addrs, how });
                    }
                }
                Stage::Configured => {
                    match self.stage_configured(host, port) {
                        Ok(addrs) => {
                            tried.push(StageReport {
                                stage,
                                outcome: StageOutcome::Ok { addresses: addrs.clone() },
                                consulted: true,
                            });
                            return Ok(Answer { host: host.to_string(), port, addrs, how: How::Configured });
                        }
                        Err(detail) => {
                        // ⛔ **A configured-pair miss IS a consulted stage**,
                        // ⛔ and reporting it as `???? not consulted` would hide
                        // the very reason a pin did not apply. ⛔ **`????` is
                        // for a stage that could not be run.** ⛔ **MEASURED
                        // 2026-10-02:** the first version did exactly this and
                        // the test caught it.
                        tried.push(StageReport {
                            stage,
                            outcome: StageOutcome::Failed { errno: None, detail },
                            consulted: true,
                        })
                    }
                    }
                }
            }
        }

        match watchdog_fired {
            // ⛔ **A watchdog that fired with nothing else answering is `Watchdog`,
            // and it names the budget and every stage tried.**
            Some((stage, budget)) => {
                Err(ResolveError::Watchdog { stage, budget, tried: tried.clone() })
            }
            None => {
                Err(ResolveError::Exhausted { host: host.to_string(), tried: tried.clone() })
            }
        }
    }

    /// ⛔ **The `Doh` stage, and the three ways it is not run.**
    ///
    /// | condition | verdict | why |
    /// | --- | --- | --- |
    /// | no endpoint configured | `????` | ⛔ E05 has not run; nothing was attempted |
    /// | endpoint but no transport | `????` | ⛔ the endpoint is known and no request was carried |
    /// | transport refused | `FAIL` | ⛔ it ran, and it did not answer |
    async fn stage_doh(&self, host: &str, port: u16) -> StageReport {
        let Some(endpoint) = self.sources.doh.as_ref() else {
            return not_consulted(Stage::Doh, "no DoH endpoint is configured (E05 has not been run)");
        };
        let Some(transport) = self.sources.doh_transport.as_ref() else {
            return not_consulted(Stage::Doh, "a DoH endpoint is configured but nothing can carry a request to it");
        };
        let budget = self.sources.budgets.doh;
        let outcome = match super::lookup::lookup(transport.as_ref(), endpoint, host, port, budget).await {
            Ok(addrs) if !addrs.is_empty() => StageOutcome::Ok { addresses: normalise(addrs) },
            // ⛔ **An empty answer is `FAIL`, never `Ok` with nothing in it.**
            // ⛔ `dns.md`'s third plant is exactly this case.
            Ok(_) => StageOutcome::Failed { errno: None, detail: "the endpoint answered with no address".into() },
            Err(e) => StageOutcome::Failed { errno: None, detail: e.to_string() },
        };
        StageReport { stage: Stage::Doh, outcome, consulted: true }
    }

    /// ⛔ **E17's fourth source, and it is a pair.** ⛔ **A configured address
    /// for a different name is not an answer**, ⛔ **and there is no single
    /// configured address that applies to everything** ⛔ — ⛔ a bare `--relay-address
    /// 104.21.39.2` with no hostname is refused by [`crate::hostname`] before this
    /// runs, ⛔ **because a pinned address with no name is a TLS failure and
    /// `relay-hostname.md` measured exactly that.**
    fn stage_configured(&self, host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, String> {
        if self.sources.configured.is_empty() {
            return Err("no (name, address) pair is configured".to_string());
        }
        let wanted = host.to_ascii_lowercase();
        let mut hits: Vec<std::net::SocketAddr> = Vec::new();
        let mut names: Vec<&str> = Vec::new();
        for (name, addr) in &self.sources.configured {
            names.push(name);
            if name.to_ascii_lowercase() == wanted {
                hits.push(std::net::SocketAddr::new(addr.ip(), port));
            }
        }
        if hits.is_empty() {
            return Err(format!(
                "no pair names {host}; {} configured: {}. ⛔ A configured address is not a                  wildcard — a pair for one name does not resolve another",
                self.sources.configured.len(),
                names.join(", ")
            ));
        }
        Ok(normalise(hits))
    }

    /// ⛔ **One run, and the full record of what every stage did — whatever the
    /// outcome.**
    ///
    /// ⛔ **The trace is what the run produced and not what its outcome implies.**
    /// ⛔ A report reconstructed from the outcome alone says `???? not consulted`
    /// about a stage that ran and failed, and ⛔ that is the misreport
    /// `docs/TODO/env/dns.md` forbids. ⛔ **MEASURED 2026-10-02:** the first
    /// version of this reported `System: ????` on a host whose `getaddrinfo`
    /// returned `EAI_NONAME`, and the test caught it.
    pub async fn record(&self, host: &str, port: u16) -> Result<Vec<StageReport>, Vec<StageReport>> {
        match self.resolve_traced(host, port).await {
            (Ok(_), tried) => Ok(all_stages(&tried)),
            (Err(e), _) => Err(e.tried().to_vec()),
        }
    }

    /// ⛔ **One line per stage, for `podssh doctor --dns`.**
    ///
    /// ⛔ **It is a second resolve, not a replay of the first.** ⛔ **A report
    /// reconstructed from the first resolve's outcome would say `???? not
    /// consulted` about a stage that ran and failed** ⛔ — and that is the
    /// misreport `docs/TODO/env/dns.md` forbids: ⛔ *"a stage it did not exercise
    /// must not print `ok`"*, ⛔ and **a stage it DID exercise must not print
    /// `????` either.** ⛔ **MEASURED 2026-10-02:** the first version of this
    /// reported `System: ????` on a host where `getaddrinfo` returned
    /// `EAI_NONAME`, and the test caught it.
    ///
    /// ⛔ **Every stage in `Stage::ALL` appears**, ⛔ **and a stage this resolve
    /// did not reach prints `???? not consulted`** ⛔ — ⛔ **never `ok`.**
    pub async fn doctor(&self, host: &str, port: u16) -> Vec<StageReport> {
        // ⛔ **The budget is stretched for a diagnostic run.** ⛔ **A doctor
        // that raced itself and reported a healthy resolver as `????` is wrong
        // in the other direction**, and ⛔ **the fix is not "it is UNKNOWN" — it
        // is a race that lost.** ⛔ **MEASURED 2026-10-02 on this host:** a chain
        // built with the test's 400 ms budget and a real `getaddrinfo` reported
        // `System: ????`.
        let mut budgets = self.sources.budgets;
        budgets.system = budgets.system.max(Duration::from_secs(10));
        budgets.doh = budgets.doh.max(Duration::from_secs(20));
        let relaxed = Chain {
            sources: Sources { budgets, ..sources_with(&self.sources) },
            asked: AtomicUsize::new(self.asked.load(Ordering::SeqCst)),
            order: self.order,
        };
        // ⛔ **The success path carries the trace too.** It used to read
        // `Ok(_) => Vec::new()`, so a run that answered reported **every** stage
        // as `????` — including the one that answered, which is the same
        // fabrication in the other direction.
        let (outcome, tried) = relaxed.resolve_traced(host, port).await;
        match outcome {
            Ok(_) => all_stages(&tried),
            Err(e) => all_stages(e.tried()),
        }
    }
}

/// ⛔ **Every stage in `Stage::ALL`, in order, each with its trace row or a
/// `???? not consulted` row.**
///
/// ⛔ **The length is the doctor's contract**: a report that prints three lines
/// on a host with six stages cannot be read against another host, and a stage
/// missing from it is indistinguishable from a stage that passed.
fn all_stages(tried: &[StageReport]) -> Vec<StageReport> {
    Stage::ALL
        .iter()
        .map(|stage| {
            tried
                .iter()
                .find(|r| r.stage == *stage)
                .cloned()
                .unwrap_or_else(|| not_consulted(*stage, "this lookup did not reach the stage"))
        })
        .collect()
}

/// ⛔ **A copy of a [`Sources`] with one field changed.** ⛔ **`Sources` has
/// no `Clone`** — it holds a `Cache` and `Arc<dyn …>` — and cloning it would
/// clone a cache, ⛔ and a diagnostic that ran against a private cache would
/// report `????` for every name it had just answered.
fn sources_with(sources: &Sources) -> Sources {
    Sources {
        system: Arc::clone(&sources.system),
        hosts: sources.hosts.clone(),
        doh: sources.doh.clone(),
        doh_transport: sources.doh_transport.clone(),
        configured: sources.configured.clone(),
        cache: Cache::new(),
        budgets: sources.budgets,
    }
}
