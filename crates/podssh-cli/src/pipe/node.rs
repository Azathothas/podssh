//! The node's end of a pipe (T-175): `node:NAME`, the TARGET of the node of
//! the pair stored under the label NAME, or in `--pair-file`. The bytes go
//! over the operator's leg, in the resumable layer when the node offers it,
//! as `podssh operator` carries them: a lost leg is replaced, and the
//! session goes on. When the node's session ends, nothing more can come. A
//! signal ends the session with its `CLOSE`, as an end of the input does
//! (T-586). With `--carrier ADDR`, the node is at the other end of a stream
//! that exists already, with no relay and no pair (T-595): each side and
//! each client of a listening side is a leg of the command's one stream.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Wire};
use podssh_ws::client::ConnectError;
use podssh_ws::{ProxyChoice, Trust};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::pump::{End, Ending, Verdict};
use crate::carrier::Client;
use crate::exit_codes::EXIT_SOFTWARE;
use crate::layered::{Carried, Line};
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;

/// The pipe in memory, each way.
const PIPE: usize = 256 * 1024;

/// Where the legs of a node go: the relay of its pair, with the trust of
/// its TLS, or the carrier's role in this process.
enum Legs {
    Pair(OperatorPart, Trust),
    Carrier(Arc<Client>),
}

impl Legs {
    /// The config of each leg, and the pair's expiry when a pair carries
    /// them.
    fn config<'a>(&'a self, proxy: &'a ProxyChoice) -> (OperatorConfig<'a>, Option<i64>) {
        match self {
            Legs::Pair(part, trust) => {
                let config = OperatorConfig {
                    relay: &part.relay,
                    name: &part.name,
                    connect_token: part.connect_token(),
                    trust,
                    proxy,
                    timeout: podssh_relay::open::CONNECT_TIMEOUT,
                    // The node's ready, a step of --ConnectTimeout (T-589).
                    limits: OperatorLimits { on_ready: Some(crate::connect_bound::ready), ..OperatorLimits::default() },
                    wire: Wire::Tls,
                };
                (config, Some(part.expires_ms))
            }
            Legs::Carrier(client) => (client.config(), None),
        }
    }

    /// A first leg that did not open, in the words of its road.
    fn refusal(&self, e: &ConnectError, label: &str) -> Refusal {
        match self {
            Legs::Pair(..) => crate::pairs::connect_refusal(e, label),
            Legs::Carrier(_) => crate::carrier::refusal_of(e),
        }
    }
}

/// The session to the node of `label`: the end, or the exit code once `say`
/// has the lines.
pub async fn open(label: &str, args: &SshArgs, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    let shown = format!("node:{label}");
    let refused = |say: &mut dyn FnMut(&str), refusal: Refusal| {
        say(&format!("{shown}: {}", refusal.message));
        refusal.code
    };
    // The channel of T-088: this client's key, and the node's by the pins of
    // the label or by --node-key.
    let ask = match crate::channel::Ask::of(
        args.client_key.as_deref(),
        args.iroh_key.as_deref(),
        args.node_key.as_deref(),
        args.no_e2e,
    ) {
        Ok(ask) => ask,
        Err(why) => return Err(refused(say, Refusal::usage(why))),
    };
    // The pair first, as a pipe that cannot go makes no key of this client;
    // a carrier has none, and its stream starts after the channel.
    let pair = match args.carrier.is_some() {
        true => None,
        false => match crate::pairs::operator_part(label, args.pair_file.as_deref()).and_then(|part| {
            crate::pairs::online()?;
            Ok(part)
        }) {
            Ok(part) => Some(part),
            Err(refusal) => return Err(refused(say, refusal)),
        },
    };
    let say_line = |line: String| podssh_ssh::err_line!("podssh pipe: {shown}: {line}");
    let channel = match ask.operator(crate::channel::Expect::Pinned(label.to_string()), &say_line) {
        Ok(channel) => channel,
        Err(why) => return Err(refused(say, Refusal::config(why))),
    };
    let legs = match (pair, args.carrier.as_deref()) {
        (Some(part), _) => Legs::Pair(part, crate::pairs::trust(args.ca_file.as_deref())),
        // The command's one stream, shared by each leg of the run (T-595).
        (None, text) => match crate::carrier::shared(text.unwrap_or_default()) {
            Ok(client) => Legs::Carrier(client),
            Err(refusal) => return Err(refused(say, refusal)),
        },
    };
    let carried = matches!(legs, Legs::Carrier(_));
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (started, has_started) = oneshot::channel();
    let (task_label, task_shown) = (label.to_string(), shown.clone());
    let task = tokio::spawn(async move {
        let proxy = ProxyChoice::FromEnvironment;
        let (config, expires_ms) = legs.config(&proxy);
        let (link, leg_end) = tokio::io::duplex(PIPE);
        let leg = match operator::start(&config, leg_end).await {
            Ok(leg) => {
                crate::connect_bound::step(format!("{task_shown}: the node did not answer ready"));
                // A signal ends the pipe with the node's session closed, not
                // kept by the node as a loss (T-586).
                crate::hangup::take(crate::hangup::Which::All);
                let _ = started.send(Ok(()));
                leg
            }
            Err(e) => {
                let _ = started.send(Err(legs.refusal(&e, &task_label)));
                return None;
            }
        };
        // The pipe's own bytes are on stdout: each line goes to stderr.
        let say = |line: Line| {
            if let Line::Always(text) = line {
                podssh_ssh::err_line!("podssh pipe: {task_shown}: {text}");
            }
        };
        let pin_shown = task_shown.clone();
        let pin_say = move |line: String| podssh_ssh::err_line!("podssh pipe: {pin_shown}: {line}");
        let carried = crate::layered::carry_through(&config, link, leg, theirs, expires_ms, &say, channel, pin_say);
        Some(carried.await)
    });
    match has_started.await {
        Ok(Ok(())) => {
            let (read, write) = tokio::io::split(ours);
            Ok(End {
                read: Box::new(read),
                write: Box::new(write),
                child: None,
                last_word: true,
                ending: Some(Box::new(Session { task, label: label.to_string(), carried })),
            })
        }
        Ok(Err(refusal)) => Err(refused(say, refusal)),
        Err(_) => {
            say(&format!("{shown}: the leg's task ended before it started"));
            Err(EXIT_SOFTWARE)
        }
    }
}

/// The session's task, judged at the end as `podssh operator` judges it, on
/// the pair's road or on a carrier.
struct Session {
    task: JoinHandle<Option<Carried>>,
    label: String,
    carried: bool,
}

impl Ending for Session {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            let Session { task, label, carried } = *self;
            match task.await {
                Ok(Some(ended)) => {
                    let verdict = match carried {
                        true => crate::carrier::judged(&ended),
                        false => crate::operator::judged(&label, &ended),
                    };
                    verdict.map(|(code, why)| (code, vec![format!("node:{label}: {why}")]))
                }
                Ok(None) => None,
                Err(e) => Some((EXIT_SOFTWARE, vec![format!("node:{label}: the session's task failed: {e}")])),
            }
        })
    }
}
