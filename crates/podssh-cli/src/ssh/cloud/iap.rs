//! `iap://[user@]PROJECT/ZONE/INSTANCE[:PORT]` (T-351): a port of a VM of
//! GCP, through its Identity-Aware Proxy for TCP (`podssh_ws::iap`), as
//! `gcloud compute start-iap-tunnel` reaches it. Each link takes a token
//! of [`super::google`]; the probe waits 20 s for IAP's connect success, and
//! a failure names its step: the token, the upgrade, or the VM.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::client::{ConnectError, RelayStream};
use podssh_ws::iap::carry::{self, Dial, Dialing, Ended, Line, NotOpen, Say};
use podssh_ws::iap::{self, close, Resume, Target};
use podssh_ws::{ProxyChoice, Trust};

use super::google::{TokenFault, Tokens};
use super::told::Told;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::ssh::transport::{NotReached, Reached};

/// The form of a destination on this road.
pub const SCHEME: &str = "iap://";

/// `iap://[user@]PROJECT/ZONE/INSTANCE[:PORT]` as its user and target.
pub fn destination(text: &str) -> Result<Option<(Option<String>, Target)>, String> {
    let Some(rest) = text.strip_prefix(SCHEME) else { return Ok(None) };
    let (user, rest) = super::user_of(text, rest.trim_end_matches('/'))?;
    let parts: Vec<&str> = rest.split('/').collect();
    let [project, zone, last] = parts[..] else {
        return Err(format!("{text:?}: give it as {SCHEME}PROJECT/ZONE/INSTANCE[:PORT]"));
    };
    let (instance, port) = super::port_of(text, last)?;
    let target = Target::new(project, zone, instance, port).map_err(|why| format!("{text:?}: {why}"))?;
    Ok(Some((user, target)))
}

/// Why a link did not open: its token, or its upgrade.
#[derive(Debug)]
pub enum Fault {
    Token(TokenFault),
    Upgrade(ConnectError),
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Token(TokenFault::Config(why) | TokenFault::Refused(why) | TokenFault::Unreachable(why)) => {
                write!(f, "the token: {why}")
            }
            Fault::Upgrade(e) => write!(f, "the upgrade: {e}"),
        }
    }
}

/// The links of a session to `target`, each with a token of `tokens`,
/// through the environment's proxy.
pub fn dial(target: &Target, tokens: Arc<Tokens>, trust: &Trust) -> Dial<RelayStream, Fault> {
    let (target, trust) = (target.clone(), trust.clone());
    Arc::new(move |resume: Option<Resume>| -> Dialing<RelayStream, Fault> {
        let (target, trust, tokens) = (target.clone(), trust.clone(), tokens.clone());
        Box::pin(async move {
            let token = tokens.token().await.map_err(Fault::Token)?;
            let proxy = ProxyChoice::FromEnvironment;
            let timeout = podssh_relay::open::CONNECT_TIMEOUT;
            iap::connect(&target, resume.as_ref(), &token, &trust, &proxy, timeout).await.map_err(Fault::Upgrade)
        })
    })
}

/// The task's lines, after the VM's name: a lost link for each user, the
/// rest with `-v`.
pub fn say_to(log: &Arc<Log>, shown: &str) -> Say {
    let (log, shown) = (log.clone(), shown.to_string());
    Arc::new(move |line: Line| match line {
        Line::Info(text) => log.info(&format!("{shown}: {text}")),
        Line::Verbose(text) => log.verbose(&format!("{shown}: {text}")),
    })
}

/// The stream to `target`'s port, once IAP opened the session.
pub(super) async fn reach(target: &Target, trust: &Trust, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let road = super::Road::Iap(target.clone());
    let shown = road.shown();
    let tokens = Tokens::from_env(trust.clone()).map_err(|fault| refused(&shown, &fault))?;
    log.verbose(&format!("connecting to {shown}, port {}, through IAP ({})", target.port, iap::HOST));
    match carry::open(dial(target, Arc::new(tokens), trust), say_to(log, &shown)).await {
        Ok((stream, carried)) => {
            let (target, said) = (target.clone(), shown.clone());
            let why = move || carried.get().and_then(|end| ended(&said, &target, &end));
            let stream = Box::new(Told::new(stream, why, log.clone()));
            Ok(Reached { stream, relay: None, direct_proxy: None, layer: None })
        }
        Err(not) => {
            let (line, code) = not_open(&shown, target, &not);
            Err(NotReached { lines: vec![line], code })
        }
    }
}

fn refused(shown: &str, fault: &TokenFault) -> NotReached {
    let (why, code) = token_words(fault);
    NotReached { lines: vec![format!("{shown}: the token: {why}")], code }
}

/// A token's fault and the code of a command that says it.
pub fn token_words(fault: &TokenFault) -> (&str, i32) {
    match fault {
        TokenFault::Config(why) => (why.as_str(), EX_CONFIG),
        TokenFault::Refused(why) => (why.as_str(), EX_NOPERM),
        TokenFault::Unreachable(why) => (why.as_str(), EX_UNAVAILABLE),
    }
}

/// Why IAP opened no session, by its step, and the code of a command that
/// says so: 77 for a refusal of the account, 78 for a token that cannot be
/// read, 69 else.
pub fn not_open(shown: &str, target: &Target, not: &NotOpen<Fault>) -> (String, i32) {
    match not {
        NotOpen::Dial(Fault::Token(fault)) => {
            let (why, code) = token_words(fault);
            (format!("{shown}: the token: {why}"), code)
        }
        NotOpen::Dial(Fault::Upgrade(ConnectError::Refused { status: status @ (401 | 403), body })) => {
            let said = if body.is_empty() { String::new() } else { format!(": {body}") };
            let line = format!(
                "{shown}: IAP refused the upgrade (HTTP {status}{said}): the token may have expired, or the \
                 account lacks the role IAP-secured Tunnel User (roles/iap.tunnelResourceAccessor)"
            );
            (line, EX_NOPERM)
        }
        NotOpen::Dial(Fault::Upgrade(ConnectError::Config(why))) => {
            (format!("{shown}: the upgrade: {why}"), EX_CONFIG)
        }
        NotOpen::Dial(Fault::Upgrade(e)) => (format!("{shown}: the upgrade: {e}"), EX_UNAVAILABLE),
        NotOpen::Closed { code, reason } => match closed(target, *code, reason) {
            Some((line, refusal)) => (format!("{shown}: {line}"), if refusal { EX_NOPERM } else { EX_UNAVAILABLE }),
            None => {
                let line = format!("{shown}: IAP closed the link before the session: {}", close_words(*code, reason));
                (line, EX_UNAVAILABLE)
            }
        },
        NotOpen::Silent(wait) => (
            format!("{shown}: IAP sent no connect success within {} s of the upgrade", wait.as_secs()),
            EX_UNAVAILABLE,
        ),
        NotOpen::Fault(why) => (format!("{shown}: {why}"), EX_UNAVAILABLE),
    }
}

/// What a Close of IAP's names, when its code is one that tells; and
/// whether it refuses the account.
fn closed(target: &Target, code: Option<u16>, reason: &str) -> Option<(String, bool)> {
    let said = close_words(code, reason);
    match code? {
        close::NOT_AUTHORIZED => Some((
            format!(
                "IAP refused the account ({said}): it needs the role IAP-secured Tunnel User \
                 (roles/iap.tunnelResourceAccessor) on the project or the VM"
            ),
            true,
        )),
        close::FAILED_TO_CONNECT_TO_BACKEND => Some((
            format!(
                "IAP could not connect to port {} of the VM ({said}): a firewall rule must let TCP in from \
                 35.235.240.0/20, and the port must listen",
                target.port
            ),
            false,
        )),
        close::LOOKUP_FAILED | close::LOOKUP_FAILED_RECONNECT => {
            let (vm, zone, project) = (&target.instance, &target.zone, &target.project);
            Some((format!("IAP found no VM {vm} in zone {zone} of project {project} ({said})"), false))
        }
        _ => None,
    }
}

fn close_words(code: Option<u16>, reason: &str) -> String {
    match (code, reason.is_empty()) {
        (Some(code), true) => format!("close {code}"),
        (Some(code), false) => format!("close {code}, {reason}"),
        (None, _) => "a close with no code".into(),
    }
}

/// The line of a session that IAP ended, said once before SSH sees the end
/// of its stream; `None` for the stream's own end.
pub fn ended(shown: &str, target: &Target, end: &Ended) -> Option<String> {
    match end {
        Ended::Normal => None,
        Ended::Closed { code, reason } => Some(match closed(target, *code, reason) {
            Some((line, _)) => format!("{shown}: {line}"),
            None => format!("{shown}: IAP ended the session: {}", close_words(*code, reason)),
        }),
        Ended::Lost(why) => Some(format!("{shown}: the link to IAP was lost, and {why}")),
        Ended::Fault(why) => Some(format!("{shown}: {why}")),
    }
}
