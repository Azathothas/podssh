//! E15 — ⛔ **the failure value, and the message that names every stage.**
//!
//! ⛔ **A bare `cannot resolve` is the message that costs a session.** ⛔ **READ**,
//! `dropssh` `src/dns.c:378-381` is the model:
//! *⛔cannot resolve %s: getaddrinfo failed, /etc/hosts has no entry, and DoH did not
//! answer (%s)⛔*, and ⛔ each source has a different fix — ⛔ **so every
//! source is named, including the ones that were not consulted.**
//!
//! ⛔ **`Watchdog` is a separate variant from `Exhausted`**, ⛔ because ⛔ **a
//! call that did not answer is not a call that failed** — ⛔ a thread already
//! inside libc may yet return, and podssh can only say it did not answer in time.

use std::fmt;
use std::time::Duration;

use super::stages::{Stage, StageOutcome, StageReport};

/// ⛔ **Every way resolution fails, as values.** ⛔ **The `tried` list is the
/// message**: `Display` composes it, and `relay-hostname.md`'s first plant
/// requires all four sources to be named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// ⛔ **No host at all.** A distinct variant so the chain never calls a
    /// resolver with an empty string and reports a nameserver's opinion of it.
    Empty,
    /// ⛔ **A stage's watchdog fired.** ⛔ `Unknown`, not `Failed`: the call is
    /// still inside libc and podssh cannot say what it would have returned. The
    /// chain **continues** — `dns.md`'s second plant requires it to.
    Watchdog { stage: Stage, budget: Duration, tried: Vec<StageReport> },
    /// ⛔ **Every stage that was consulted came back empty or failed.**
    Exhausted { host: String, tried: Vec<StageReport> },
    /// ⛔ E17's: an operator configured an address and it does not parse, or
    /// configured one for a different name. ⛔ **Never a silent fallback.**
    ConfiguredAddress { host: String, detail: String },
}

impl ResolveError {
    /// ⛔ **Every stage that was consulted, in the order they ran.** This is what
    /// the doctor prints and what the failure message names.
    pub fn tried(&self) -> &[StageReport] {
        match self {
            ResolveError::Empty => &[],
            ResolveError::Watchdog { tried, .. } => tried,
            ResolveError::Exhausted { tried, .. } => tried,
            ResolveError::ConfiguredAddress { .. } => &[],
        }
    }

    /// ⛔ **The host that could not be resolved**, when there was one.
    pub fn host(&self) -> Option<&str> {
        match self {
            ResolveError::Empty => None,
            ResolveError::Watchdog { .. } => None,
            ResolveError::Exhausted { host, .. } => Some(host),
            ResolveError::ConfiguredAddress { host, .. } => Some(host),
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::Empty => {
                write!(f, "cannot resolve: no host was given")
            }
            ResolveError::ConfiguredAddress { host, detail } => {
                write!(f, "cannot resolve {host}: {detail}")
            }
            ResolveError::Watchdog { stage, budget, tried } => {
                write!(f, "cannot resolve: ")?;
                write_tried(f, tried)?;
                write!(
                    f,
                    "; and the {stage} stage did not answer within {:?} — a call already \
                     inside getaddrinfo cannot be cancelled, so it was abandoned and the \
                     chain continued",
                    budget
                )
            }
            ResolveError::Exhausted { host, tried } => {
                write!(f, "cannot resolve {host}: ")?;
                if tried.is_empty() {
                    write!(f, "no stage was consulted")?;
                    return Ok(());
                }
                write_tried(f, tried)?;
                write!(
                    f,
                    ". Each of those has a different fix: a local resolver, an \
                     /etc/hosts line, egress on 443 to a DoH endpoint, or an explicitly \
                     configured (name, address) pair. ⛔ podssh will not guess a relay \
                     address — a wrong host that looks like a working connection is worse \
                     than a named failure"
                )
            }
        }
    }
}

/// ⛔ **EVERY stage in `Stage::ALL` is named, including the ones that were
/// not consulted.** ⛔ **MEASURED 2026-10-02:** the first version named only the
/// consulted ones, ⛔ so a report that omitted a stage read exactly like a report
/// in which that stage passed — which is the misreport `docs/TODO/env/dns.md`
/// forbids.
pub(crate) fn write_tried(f: &mut fmt::Formatter<'_>, tried: &[StageReport]) -> fmt::Result {
    if tried.is_empty() {
        return write!(f, "no stage was consulted");
    }
    let consulted: Vec<&StageReport> = tried.iter().filter(|r| r.consulted).collect();
    if consulted.is_empty() {
        return write!(f, "no stage was consulted");
    }
    for (i, report) in consulted.iter().enumerate() {
        if i > 0 {
            // ⛔ **A line-continuation indent, and the reason is that the
            // message goes into a log a human reads.** ⛔ **MEASURED
            // 2026-10-02:** the first version ran the four stages together on
            // one line, and the detail of the one stage that mattered was
            // unreadable — ⛔ **that is the message this entry exists to fix.**
            write!(f, ",
              and ")?;
        }
        match &report.outcome {
            // ⛔ **A stage that reported `ok` and produced nothing is named as
            // what it was.** ⛔ It is not printed as a success, because it is
            // the one case a caller could otherwise read as a resolution.
            StageOutcome::Ok { addresses } if addresses.is_empty() => {
                write!(f, "the {} stage reported ok with zero addresses", report.stage)?
            }
            StageOutcome::Ok { .. } => write!(f, "{} answered", report.stage)?,
            StageOutcome::Failed { errno, detail } => {
                match errno {
                    Some(e) => write!(f, "{} failed (errno={e}: {detail})", report.stage),
                    None => write!(f, "{} failed ({detail})", report.stage),
                }?;
            }
            StageOutcome::Unknown { why } => {
                write!(f, "{} could not be read ({why})", report.stage)?
            }
        }
    }
    // ⛔ **And the stages that were NOT consulted are named too**, ⛔ so a
    // reader can tell a stage that was skipped from a stage that was consulted
    // and had nothing to say. ⛔ The report is the whole of what a caller sees.
    for report in tried.iter().filter(|r| !r.consulted) {
        write!(f, ",
              and ")?;
        write!(f, "{} was not consulted ({})", report.stage, report.outcome_detail())?;
    }
    Ok(())
}

impl std::error::Error for ResolveError {}
