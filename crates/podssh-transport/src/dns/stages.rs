//! E15 — ⛔ **the six stages, the three-valued verdict, and the record a
//! message is built from.**
//!
//! ⛔ **`ok`, `FAIL <errno>`, `????`** — ⛔ **`????` is not
//! optional.** `AGENTS.md`: ⛔ *⛔ Every stage reports `ok`, `FAIL <errno>`,
//! `????`.⛔* And `dns.md`'s `Prove` block: ⛔ *⛔ A stage it did not exercise
//! must not print `ok`.⛔*
//!
//! ⛔ **`System` will be wrong first**: a `resolv.conf` that exists and a resolver
//! that answers are ⛔ **different facts**, and ⛔ **a `????` that reads as `ok`
//! is the defect four sibling projects shipped.**
//!
//! ⛔ **`StageOutcome::Ok` carries a `Vec<SocketAddr>`, and ⛔ an empty one is
//! NOT a success** — ⛔ `is_ok()` says so, and ⛔ `Answer::first` refuses it.
//! ⛔ That is the shape of ⛔ *⛔an empty `Vec<SocketAddr>` some caller
//! treats as success⛔*.

use std::fmt;
use std::net::SocketAddr;

/// ⛔ **Which stage answered.** `relay-hostname.md` §"Report the route" and
/// `dns.md`'s `Prove` block both need the route **reported, never inferred**:
/// *"Cannot resolve" and "relay down" look identical from the outside, and a
/// doctor that cannot say which it measured is worse than no doctor.*
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum How {
    /// The host was already an address. **READ**, `src/dns.c:321` and `:327`.
    Literal,
    /// A bounded-age answer from a previous resolve. `src/dns.c:310`.
    Cache,
    /// `getaddrinfo`. `src/dns.c:354`.
    System,
    /// A curated `/etc/hosts` line. `src/dns.c:364`.
    Hosts,
    /// DNS over HTTPS. `src/dns.c:371`.
    Doh,
    /// ⛔ **E17's fourth source**: an operator-configured `(name, address)`
    /// pair. It exists in this enum and in `ORDER`, and there is no constant
    /// anywhere that could produce it.
    Configured,
}

impl How {
    /// ⛔ **The word printed by `podssh doctor --dns`.** The control the entry
    /// names is *"must still report `ok` **naming `System`**"*, so the name is a
    /// value with a test rather than prose.
    pub const fn as_str(self) -> &'static str {
        match self {
            How::Literal => "Literal",
            How::Cache => "Cache",
            How::System => "System",
            How::Hosts => "Hosts",
            How::Doh => "Doh",
            How::Configured => "Configured",
        }
    }

    /// ⛔ **The stage this answer came from, and nothing else.** `Cache` is
    /// reported as `Cache`, ⛔ **not as the `System` answer it was copied from**,
    /// because a doctor that says `System` for a cached answer is reporting the
    /// stage it remembers rather than the one that ran.
    pub const fn stage(self) -> Stage {
        match self {
            How::Literal => Stage::Literal,
            How::Cache => Stage::Cache,
            How::System => Stage::System,
            How::Hosts => Stage::Hosts,
            How::Doh => Stage::Doh,
            How::Configured => Stage::Configured,
        }
    }
}

impl fmt::Display for How {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ⛔ **The five network-capable stages plus the two that short-circuit.** The
/// name is used in every failure message, so it is a value and not a string
/// literal at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    Literal,
    Cache,
    System,
    Hosts,
    Doh,
    Configured,
}

impl Stage {
    pub const ALL: [Stage; 6] = [
        Stage::Literal,
        Stage::Cache,
        Stage::System,
        Stage::Hosts,
        Stage::Doh,
        Stage::Configured,
    ];

    /// ⛔ **The order the entry's `## Approach` fixes, and it is a fixed order.**
    /// `dns.md` step 2 lists `System` → `/etc/hosts` → `Doh` and
    /// `relay-hostname.md` step 4 puts the configured address **last**, ⛔
    /// **consulted only after 1-3 fail**. `Literal` and `Cache` are before every
    /// one of them because neither touches a network.
    pub const DEFAULT_ORDER: [Stage; 6] = [
        Stage::Literal,
        Stage::Cache,
        Stage::System,
        Stage::Hosts,
        Stage::Doh,
        Stage::Configured,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Literal => "Literal",
            Stage::Cache => "Cache",
            Stage::System => "System",
            Stage::Hosts => "Hosts",
            Stage::Doh => "Doh",
            Stage::Configured => "Configured",
        }
    }

    /// ⛔ **Whether this stage can block or open a socket.** ⛔ `Literal` and
    /// `Cache` are pure and therefore safe to run before anything is probed —
    /// which is what lets a host with no network at all still resolve a literal.
    pub const fn touches_a_network(self) -> bool {
        matches!(self, Stage::System | Stage::Hosts | Stage::Doh)
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ⛔ **Three-valued, and `Unknown` is not optional.**
///
/// `AGENTS.md`: *"⛔ Every stage reports `ok`, `FAIL <errno>`, `????`."* And
/// `dns.md`'s `Prove` block: ⛔ **"A stage it did not exercise must not print
/// `ok`."** ⛔ **`System` will be wrong first**: a `resolv.conf` that exists and a
/// resolver that answers are **different facts**, and ⛔ **a `????` that reads as
/// `ok` is the defect four sibling projects shipped.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// ⛔ **Only ever set by running the stage.** There is no constructor that
    /// takes a boolean and produces this, so a skipped stage cannot be marked
    /// successful.
    Ok { addresses: Vec<SocketAddr> },
    Failed { errno: Option<i32>, detail: String },
    /// ⛔ **Not attempted, or attempted and abandoned.** A watchdog firing is
    /// `Unknown`: the call is still in libc and podssh cannot say it failed.
    Unknown { why: String },
}

impl StageOutcome {
    /// ⛔ The three labels, spelled as `dns.md` spells them.
    pub const fn label(&self) -> &'static str {
        match self {
            StageOutcome::Ok { .. } => "ok",
            StageOutcome::Failed { .. } => "FAIL",
            StageOutcome::Unknown { .. } => "????",
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, StageOutcome::Ok { addresses } if !addresses.is_empty())
    }

    /// ⛔ **One line, `stage: label detail`.** The `errno` is in the detail when
    /// there is one, because `dns.md` writes `FAIL <errno>` and a `FAIL` without
    /// the number is a `FAIL` nobody can act on.
    pub fn line(&self, stage: Stage) -> String {
        match self {
            StageOutcome::Ok { addresses } => format!(
                "{stage}: ok {} address(es) [{}]",
                addresses.len(),
                addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            StageOutcome::Failed { errno, detail } => match errno {
                Some(e) => format!("{stage}: FAIL errno={e} {detail}"),
                None => format!("{stage}: FAIL {detail}"),
            },
            StageOutcome::Unknown { why } => format!("{stage}: ???? {why}"),
        }
    }
}

/// ⛔ **What one stage did, kept even when it did nothing.** This is the record a
/// failure message is built from, and it is a value rather than a formatted
/// string because `podssh doctor --json` reads the same data the message prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageReport {
    pub stage: Stage,
    pub outcome: StageOutcome,
    /// ⛔ Whether the stage actually ran. A stage that was not in the order is
    /// reported as **not consulted**, and its outcome is `Unknown` — ⛔ **never
    /// `Ok`**, which is the defect this whole three-valued shape exists to stop.
    pub consulted: bool,
}

impl StageReport {
    /// ⛔ **Re-exported as a bare function so the chain's call sites read as
    /// actions rather than as constructors.** ⛔ It is a constructor, and a
    /// constructor on a `StageReport` cannot produce `Ok`, which is the whole
    /// reason it exists.
    pub fn not_consulted(stage: Stage, why: &str) -> Self {
        Self {
            stage,
            outcome: StageOutcome::Unknown { why: why.to_string() },
            consulted: false,
        }
    }

    pub fn line(&self) -> String {
        if self.consulted {
            self.outcome.line(self.stage)
        } else {
            format!("{}: ???? not consulted — {}", self.stage, self.outcome_detail())
        }
    }

    pub(crate) fn outcome_detail(&self) -> &str {
        match &self.outcome {
            StageOutcome::Unknown { why } => why,
            StageOutcome::Failed { detail, .. } => detail,
            StageOutcome::Ok { .. } => "answered",
        }
    }
}

/// ⛔ **The one way a `StageReport` is created as ⛔ *not* consulted.** ⛔ **It is
/// a free function as well as a method** ⛔ — ⛔ **a free function cannot be
/// `StageReport::new`-style borrowed into the call sites that read best with a
/// verb** ⛔ — ⛔ and ⛔ **both forms produce `StageOutcome::Unknown`, so a
/// stage that was skipped is `????` and can never be `ok`.**
pub fn not_consulted(stage: Stage, why: &str) -> StageReport {
    StageReport::not_consulted(stage, why)
}
