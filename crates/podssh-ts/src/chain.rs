//! Mode-chain readiness: which tailnet route to try, and in what order.
//!
//! Three-valued verdicts (`Ok` / `Fail` / `Unknown`), never `ok` for an
//! unrun check. The default order is `tun → socks → tcp → relay` (r2); a
//! forced single mode is a one-element slice — no `--order` in v1. Falling
//! through happens only on pre-dial failures: a dial failing under a ready
//! mode is reported, never retried elsewhere (that rule lives in dispatch).
//! So a mode is ready only when its network check passed before the start
//! (T-102): podssh-cli runs it, and passes its verdict in `reach`.

use std::net::IpAddr;

use crate::config::TsMode;

/// Readiness of one mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The mode is ready to dial.
    Ok,
    /// The mode cannot be used, with the errno-style reason.
    Fail(String),
    /// The probe could not run; never treated as ready.
    Unknown,
}

/// Everything a probe reads, injected so tests use fakes instead of the host.
///
/// `addrs`/`socks_endpoint` have no reader until the Tun/Socks variants
/// land; they are kept (not removed) so the injected-inputs shape is stable
/// and the future rules plug into named fields rather than a redesign.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ChainInputs {
    /// Local interface addresses the probe may see.
    pub addrs: Vec<IpAddr>,
    /// SOCKS endpoint (`host:port`) of an existing userspace daemon, if any.
    pub socks_endpoint: Option<String>,
    /// Auth key material is present (presence only — never the key itself).
    pub has_key: bool,
    /// What the network check of each mode found: a TLS handshake through
    /// the proxy with a stock DERP server for `tcp`, and with the relay host
    /// for `relay`. A mode that is not here was not checked: `Unknown`.
    pub reach: Vec<(TsMode, Verdict)>,
}

impl ChainInputs {
    /// The verdict of `mode`'s network check, `Unknown` when none ran.
    pub fn reached(&self, mode: &TsMode) -> Verdict {
        self.reach.iter().find(|(m, _)| m == mode).map_or(Verdict::Unknown, |(_, v)| v.clone())
    }
}

/// Probe one mode. `Tcp`/`Relay` need key material, then a network check
/// that passed. `Tun`/`Socks` variants do not exist on `TsMode` yet — and
/// the match below is exhaustive on purpose, so adding a variant fails
/// compilation until its probe rule is written. A new mode that silently
/// falls through would be the defect.
pub fn probe(mode: &TsMode, inputs: &ChainInputs) -> Verdict {
    match mode {
        TsMode::Tcp => {
            if inputs.has_key {
                inputs.reached(mode)
            } else {
                Verdict::Fail("no auth key".to_string())
            }
        }
        TsMode::Relay { .. } => {
            if inputs.has_key {
                inputs.reached(mode)
            } else {
                Verdict::Fail("no auth key".to_string())
            }
        }
    }
}

/// First `Ok` in chain order wins. `None` when no mode is ready — the caller
/// prints every verdict and exits 78.
pub fn select_chain(modes: &[TsMode], inputs: &ChainInputs) -> Option<TsMode> {
    modes.iter().find(|m| probe(m, inputs) == Verdict::Ok).cloned()
}

/// The default chain order: `tun → socks → tcp → relay`.
pub fn default_chain(relay: TsMode) -> Vec<TsMode> {
    // Tun/Socks variants do not exist yet; the order is Tcp then the relay
    // mode, and the two front slots are filled when the variants land. The
    // constant below names the intended full order so the gap is visible.
    let _intended = ["tun", "socks", "tcp", "relay"];
    vec![TsMode::Tcp, relay]
}
