//! `podssh operator NAME` (T-084): a byte pipe to the node of the pair under
//! the label NAME. stdin goes to the node's TARGET and its bytes come back on
//! stdout, as `podssh proxy` carries a forward session; so it is the
//! ProxyCommand of OpenSSH for a node. stdout carries those bytes and nothing
//! else; it exits 0 only after the node took the session.

use std::io::Write;

use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome, Wire};
use podssh_ws::client::ConnectError;
use podssh_ws::dial::ProxyChoice;

use crate::exitmap::Fault;
use crate::layered::{Carried, Line};
use crate::pairs;
use crate::relay_settings::Refusal;

/// Each direction of the pipe between the layer and the leg.
const PIPE: usize = 256 * 1024;

/// What `podssh operator` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorArgs {
    /// The label of a stored pair.
    pub name: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    /// A pair, or its operator's part, in a file.
    pub pair_file: Option<String>,
    /// This operator's key file (T-087).
    pub client_key: Option<String>,
    /// The node's key or fingerprint, in place of the pins (T-087).
    pub node_key: Option<String>,
    /// No end-to-end channel (T-088).
    pub no_e2e: bool,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Run the verb; returns the process exit code.
pub fn run_operator(args: &OperatorArgs, err: &mut dyn Write) -> i32 {
    let (label, part, ask) = match prepare(args) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("operator", err),
    };
    // The channel of T-088: this operator's key, and the node's by the pins
    // of the label or by --node-key.
    let say_line = |line: String| eprintln!("podssh operator: {label}: {line}");
    let channel = match ask.operator(crate::channel::Expect::Pinned(label.clone()), &say_line) {
        Ok(channel) => channel,
        Err(why) => return Refusal::config(why).report("operator", err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh operator: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    let trust = pairs::trust(args.ca_file.as_deref());
    let proxy = ProxyChoice::FromEnvironment;
    let config = OperatorConfig {
        relay: &part.relay,
        name: &part.name,
        connect_token: part.connect_token(),
        trust: &trust,
        proxy: &proxy,
        timeout: pairs::REQUEST_LIMIT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    };
    let io = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    // stdout carries the session's bytes alone: each line goes to stderr.
    let say = |line: Line| {
        if let Line::Always(text) = line {
            eprintln!("podssh operator: {label}: {text}");
        }
    };
    // stdin and stdout <-> the resumable layer <-> the operator's leg, a new
    // leg after each lost one when the node offers the layer (T-153).
    let ran = runtime.block_on(async {
        let (link, leg_end) = tokio::io::duplex(PIPE);
        let first = operator::start(&config, leg_end).await?;
        let shown = label.clone();
        let pin_say = move |line: String| eprintln!("podssh operator: {shown}: {line}");
        let carried =
            crate::layered::carry_through(&config, link, first, io, Some(part.expires_ms), &say, channel, pin_say);
        Ok::<_, ConnectError>(carried.await)
    });
    // A read on stdin may still be blocked in a helper thread; the session
    // has ended, so it is not waited for.
    runtime.shutdown_background();
    match ran {
        Ok(carried) => match judged(&label, &carried) {
            None => 0,
            Some((code, why)) => {
                let _ = writeln!(err, "podssh operator: {label}: {why}");
                code
            }
        },
        Err(e) => pairs::connect_refusal(&e, &label).report("operator", err),
    }
}

/// How a session to the node of `label` ended: the exit code and the line
/// that says why, or `None` for a clean end. `podssh pipe node:` judges by
/// it too.
pub(crate) fn judged(label: &str, carried: &Carried) -> Option<(i32, String)> {
    // The channel's verdict first: a refused key is a refusal, whatever the
    // layer and the leg say of the end that followed it.
    if let Some((fault, why)) = &carried.channel {
        return Some((fault.code(), why.clone()));
    }
    match carried {
        Carried { why: Some(why), .. } => Some((Fault::SessionFault.code(), why.clone())),
        Carried { why: None, leg: Some(outcome), .. } => {
            verdict(label, outcome).map(|(fault, why)| (fault.code(), why))
        }
        Carried { why: None, leg: None, .. } => {
            Some((Fault::RelayUnreachable.code(), "the relay did not end the session in time".to_string()))
        }
    }
}

fn prepare(args: &OperatorArgs) -> Result<(String, podssh_relay::pair::OperatorPart, crate::channel::Ask), Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the label of a pair (podssh relay pair NAME)")?;
    pairs::check_label(&label)?;
    let ask = crate::channel::Ask::of(args.client_key.as_deref(), None, args.node_key.as_deref(), args.no_e2e)
        .map_err(Refusal::usage)?;
    if args.no_e2e && args.client_key.is_some() {
        return Err(Refusal::usage(
            "--client-key is this operator's key in the end-to-end channel, which --no-e2e turns off",
        ));
    }
    crate::pins::apply(args.relay_addr.as_deref())?;
    let part = pairs::operator_part(&label, args.pair_file.as_deref())?;
    pairs::online()?;
    Ok((label, part, ask))
}

/// The fault for each end of the session, by the table of `exitmap`; none
/// for a clean end.
fn verdict(label: &str, outcome: &Outcome) -> Option<(Fault, String)> {
    let (fault, why) = match outcome {
        Outcome::LocalEnd | Outcome::Ended { code: 1000, .. } => return None,
        Outcome::NeverReady { code: Some(code), reason } => {
            (Fault::RelayUnreachable, format!("the node did not take the session (relay close {code}): {reason}"))
        }
        Outcome::NeverReady { code: None, reason } => {
            (Fault::RelayUnreachable, format!("the node did not take the session: {reason}"))
        }
        Outcome::Ended { code: 1001, reason } if reason.trim().eq_ignore_ascii_case("pair expired") => (
            Fault::PairExpired,
            format!("the pair expired (relay close 1001); make a new one with `podssh relay pair {label}`"),
        ),
        Outcome::Ended { code: 1001, reason }
            if reason.trim().eq_ignore_ascii_case("operator stopped reverse relay") =>
        {
            (Fault::Revoked, "the pair was stopped (relay close 1001)".to_string())
        }
        Outcome::Ended { code: code @ (1003 | 1008 | 1009), reason } => {
            (Fault::SessionFault, format!("the relay closed the session for a fault (relay close {code}): {reason}"))
        }
        Outcome::Ended { code, reason } => (Fault::RelayUnreachable, pairs::session_end(*code, reason)),
    };
    Some((fault, why))
}
