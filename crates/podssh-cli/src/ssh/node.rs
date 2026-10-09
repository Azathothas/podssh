//! `podssh ssh node://[user@]NAME` (T-084): SSH to the TCP service of a
//! pair's node, through the operator's leg of the reverse road. The
//! destination's host is `node://NAME`, so the messages and the known hosts
//! name the node so: a name that no DNS name can be.

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome, Wire};
use podssh_ssh::{Log, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};

use super::args::SshArgs;
use super::resolve::{Env, Transport};

/// The form of a node's destination.
pub const SCHEME: &str = "node://";

/// Each direction of the pipe between the SSH client and the leg.
const PIPE: usize = 256 * 1024;
/// How long the leg may take to end after the SSH client: its Close and the
/// relay's answer.
const LEG_END: Duration = Duration::from_secs(12);

/// `node://[user@]NAME` as the user and NAME; `None` for each other
/// destination. `node:NAME`, with no slashes, is a host named `node`.
pub fn destination(text: &str) -> Result<Option<(Option<String>, String)>, String> {
    let Some(rest) = text.strip_prefix(SCHEME) else { return Ok(None) };
    let rest = rest.trim_end_matches('/');
    let (user, label) = match rest.rsplit_once('@') {
        Some((user, label)) if !user.is_empty() => (Some(user.to_string()), label),
        Some(_) => return Err(format!("{text:?}: empty user name")),
        None => (None, rest),
    };
    if label.is_empty() {
        return Err(format!("{text:?}: no NAME after {SCHEME}"));
    }
    if label.contains(':') {
        return Err(format!("{text:?}: a node has no port; NAME is the label of a pair"));
    }
    crate::pairs::check_label(label).map_err(|refusal| format!("{text:?}: {}", refusal.message))?;
    Ok(Some((user, label.to_string())))
}

/// What a node can be reached with: the relay, alone, with no `-J`, `-W` or
/// `-p`, which T-084 leaves for later.
pub(super) struct Ask<'a> {
    pub label: &'a str,
    pub args: &'a SshArgs,
    pub host_name: bool,
    pub port: bool,
    pub jumps: usize,
    pub family: Option<u8>,
    pub forward: bool,
}

pub(super) fn transport(r: &Ask<'_>, env: &Env) -> Result<Transport, String> {
    let why = if r.args.direct {
        Some("--direct cannot reach a node: only the relay can")
    } else if r.jumps > 0 {
        Some("a node cannot be reached through a -J hop yet")
    } else if r.forward {
        Some("-W through a node is not implemented yet")
    } else if r.port {
        Some("a node has no port: its TARGET is set where the node runs")
    } else if r.host_name {
        Some("-o HostName cannot apply to a node")
    } else if r.family.is_some() {
        Some("-4 and -6 choose the family that the relay dials; a node dials its own TARGET")
    } else {
        None
    };
    if let Some(why) = why {
        return Err(format!("{SCHEME}{}: {why}", r.label));
    }
    let trust = match r.args.ca_file.clone().or_else(|| env.ssl_cert_file.clone()) {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    Ok(Transport::Node { label: r.label.to_string(), pair_file: r.args.pair_file.clone(), trust })
}

/// SSH over the operator's leg to the node of the pair under `label`.
pub(super) async fn connect(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    opts: &podssh_ssh::options::Options,
    log: Arc<Log>,
) -> i32 {
    let shown = format!("{SCHEME}{label}");
    let part = match crate::pairs::operator_part(label, pair_file).and_then(|part| {
        crate::pairs::online()?;
        Ok(part)
    }) {
        Ok(part) => part,
        Err(refusal) => {
            log.error(&format!("{shown}: {}", refusal.message));
            return EXIT_FAILURE;
        }
    };
    let proxy = ProxyChoice::FromEnvironment;
    let config = OperatorConfig {
        relay: &part.relay,
        name: &part.name,
        connect_token: part.connect_token(),
        trust,
        proxy: &proxy,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    };
    log.verbose(&format!("connecting to {shown} through the relay {}", part.relay.host));
    let (ssh_end, leg_end) = tokio::io::duplex(PIPE);
    let leg = match operator::start(&config, leg_end).await {
        Ok(leg) => leg,
        Err(e) => {
            log.error(&format!("{shown}: {}", crate::pairs::connect_refusal(&e, label).message));
            return EXIT_FAILURE;
        }
    };
    let code = podssh_ssh::run(ssh_end, opts, None, log.clone()).await;
    // The client has closed its end; the leg sends its Close and waits for
    // the answer, so the relay ends the session cleanly.
    let ended = tokio::time::timeout(LEG_END, leg).await;
    if code == EXIT_FAILURE {
        if let Ok(Ok(outcome)) = ended {
            if let Some(why) = explain(&outcome) {
                log.error(&format!("{shown}: {why}"));
            }
        }
    }
    code
}

/// What the leg says of a session that failed; nothing for a normal end.
fn explain(outcome: &Outcome) -> Option<String> {
    match outcome {
        Outcome::NeverReady { code: Some(code), reason } => {
            Some(format!("the node did not take the session (relay close {code}): {reason}"))
        }
        Outcome::NeverReady { code: None, reason } => Some(format!("the node did not take the session: {reason}")),
        Outcome::Ended { code: 1000, .. } | Outcome::LocalEnd => None,
        Outcome::Ended { code, reason } => Some(crate::pairs::session_end(*code, reason)),
    }
}
