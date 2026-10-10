//! The node's end of a pipe (T-175): `node:NAME`, the TARGET of the node of
//! the pair stored under the label NAME, or in `--pair-file`. The bytes go
//! over the operator's leg, in the resumable layer when the node offers it,
//! as `podssh operator` carries them: a lost leg is replaced, and the
//! session goes on. When the node's session ends, nothing more can come.

use std::future::Future;
use std::pin::Pin;

use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Wire};
use podssh_ws::ProxyChoice;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::pump::{End, Ending, Verdict};
use crate::exit_codes::EXIT_SOFTWARE;
use crate::layered::{Carried, Line};
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;

/// The pipe in memory, each way.
const PIPE: usize = 256 * 1024;

/// The session to the node of `label`: the end, or the exit code once `say`
/// has the lines.
pub async fn open(label: &str, args: &SshArgs, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    let shown = format!("node:{label}");
    let refused = |say: &mut dyn FnMut(&str), refusal: Refusal| {
        say(&format!("{shown}: {}", refusal.message));
        refusal.code
    };
    let part = match crate::pairs::operator_part(label, args.pair_file.as_deref()).and_then(|part| {
        crate::pairs::online()?;
        Ok(part)
    }) {
        Ok(part) => part,
        Err(refusal) => return Err(refused(say, refusal)),
    };
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (started, has_started) = oneshot::channel();
    let (task_label, task_shown) = (label.to_string(), shown.clone());
    let task = tokio::spawn(async move {
        let proxy = ProxyChoice::FromEnvironment;
        let config = OperatorConfig {
            relay: &part.relay,
            name: &part.name,
            connect_token: part.connect_token(),
            trust: &trust,
            proxy: &proxy,
            timeout: podssh_relay::open::CONNECT_TIMEOUT,
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        let (link, leg_end) = tokio::io::duplex(PIPE);
        let leg = match operator::start(&config, leg_end).await {
            Ok(leg) => {
                let _ = started.send(Ok(()));
                leg
            }
            Err(e) => {
                let _ = started.send(Err(crate::pairs::connect_refusal(&e, &task_label)));
                return None;
            }
        };
        // The pipe's own bytes are on stdout: each line goes to stderr.
        let say = |line: Line| {
            if let Line::Always(text) = line {
                eprintln!("podssh pipe: {task_shown}: {text}");
            }
        };
        Some(crate::layered::carry(&config, link, leg, theirs, Some(part.expires_ms), &say).await)
    });
    match has_started.await {
        Ok(Ok(())) => {
            let (read, write) = tokio::io::split(ours);
            Ok(End {
                read: Box::new(read),
                write: Box::new(write),
                child: None,
                last_word: true,
                ending: Some(Box::new(Session { task, label: label.to_string() })),
            })
        }
        Ok(Err(refusal)) => Err(refused(say, refusal)),
        Err(_) => {
            say(&format!("{shown}: the leg's task ended before it started"));
            Err(EXIT_SOFTWARE)
        }
    }
}

/// The session's task, judged at the end as `podssh operator` judges it.
struct Session {
    task: JoinHandle<Option<Carried>>,
    label: String,
}

impl Ending for Session {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            let Session { task, label } = *self;
            match task.await {
                Ok(Some(carried)) => crate::operator::judged(&label, &carried)
                    .map(|(code, why)| (code, vec![format!("node:{label}: {why}")])),
                Ok(None) => None,
                Err(e) => Some((EXIT_SOFTWARE, vec![format!("node:{label}: the session's task failed: {e}")])),
            }
        })
    }
}
