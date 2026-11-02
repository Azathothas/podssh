//! A connection that starts at an exit (T-431): one session to the exit
//! node NAME of the user's net, over the pair kept under NAME, in the
//! resumable layer and the end-to-end channel, whose word names the target
//! (`crate::channel::Ask::to_exit`); a lost leg is replaced, as `podssh
//! operator` replaces it. `podssh proxy --exit`, `podssh pipe --exit` and
//! each client of `podssh exit --listen` open theirs so.
//!
//! The node's verdict comes before any answer: the channel touches the
//! plain side of the session only once the node let the operator in and
//! reached the target, so that touch is the verdict, and a client of SOCKS
//! or of CONNECT learns whether its target was reached, as `-D` tells.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Wire};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::exit_codes::EXIT_SOFTWARE;
use crate::exitmap::{sysexits, Fault};
use crate::layered::{carry_through, Line};
use crate::pipe::pump::{End, Ending, Verdict};
use crate::relay_settings::Refusal;

/// Each direction of the pipe between a client and the channel.
const PIPE: usize = 256 * 1024;
/// How long the node's verdict may take: the leg, the layer's and the
/// channel's handshakes, and the exit's resolution and dial.
pub const VERDICT_WAIT: Duration = Duration::from_secs(60);

/// The exit, and the flags of its channel and its pair.
#[derive(Debug, Clone, Default)]
pub struct To {
    pub name: String,
    pub pair_file: Option<String>,
    pub client_key: Option<String>,
    pub node_key: Option<String>,
    pub ca_file: Option<String>,
    /// No line for each session that ends well.
    pub quiet: bool,
}

impl To {
    /// The exit of `--exit NAME`, with the flags of the channel and the pair
    /// that `args` gives.
    pub fn of_ssh(name: &str, args: &crate::ssh::args::SshArgs) -> To {
        To {
            name: name.to_string(),
            pair_file: args.pair_file.clone(),
            client_key: args.client_key.clone().or_else(|| args.iroh_key.clone()),
            node_key: args.node_key.clone(),
            ca_file: args.ca_file.clone(),
            quiet: args.quiet > 0,
        }
    }
}

/// What kind of refusal a client is told: SOCKS and CONNECT each have a
/// word for these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The node, or its net's policy, refused the target.
    NotAllowed,
    /// The node could not reach the target.
    Unreachable,
    /// The road to the node failed, or did not answer in time.
    Failed,
}

/// Why no connection came: the exit code, the line, and its kind.
#[derive(Debug, Clone)]
pub struct Refused {
    pub code: i32,
    pub line: String,
    pub kind: Kind,
}

impl Refused {
    fn of(refusal: Refusal, kind: Kind) -> Refused {
        Refused { code: refusal.code, line: refusal.message, kind }
    }
}

/// The verdict, once: the first touch of the plain side, or the session's
/// end before one.
type Tell = Arc<Mutex<Option<oneshot::Sender<Result<(), Refused>>>>>;

fn tell(told: &Tell, verdict: Result<(), Refused>) {
    let sender = told.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    if let Some(sender) = sender {
        let _ = sender.send(verdict);
    }
}

/// The session to the exit `to` for `host:port`: the end of the pipe once
/// the node reached the target, or why not.
pub async fn open(to: &To, host: &str, port: u16) -> Result<End, Refused> {
    let ask = crate::channel::Ask::of(to.client_key.as_deref(), None, to.node_key.as_deref(), false)
        .and_then(|ask| ask.to_exit(host, port))
        .map_err(|why| Refused::of(Refusal::usage(why), Kind::Failed))?;
    let part = crate::pairs::operator_part(&to.name, to.pair_file.as_deref())
        .and_then(|part| crate::pairs::online().map(|()| part))
        .map_err(|refusal| Refused::of(refusal, Kind::Failed))?;
    let trust = crate::pairs::trust(to.ca_file.as_deref());
    let label = to.name.clone();
    let shown = format!("exit {label}");
    let say_line = |line: String| podssh_ssh::err_line!("podssh: {shown}: {line}");
    // A member of the net is checked by the net's key; else by the pins.
    let channel = ask
        .operator(crate::channel::Expect::Pinned(label.clone()), &say_line)
        .map_err(|why| Refused::of(Refusal::config(why), Kind::Failed))?;
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (sender, verdict) = oneshot::channel();
    let told: Tell = Arc::new(Mutex::new(Some(sender)));
    let app = Told { inner: theirs, told: told.clone() };
    let quiet = to.quiet;
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
            Ok(leg) => leg,
            Err(e) => {
                tell(&told, Err(Refused::of(crate::pairs::connect_refusal(&e, &label), Kind::Failed)));
                return None;
            }
        };
        let shown = format!("exit {label}");
        let say = |line: Line| {
            if let (Line::Always(text), false) = (line, quiet) {
                podssh_ssh::err_line!("podssh: {shown}: {text}");
            }
        };
        let pin_shown = shown.clone();
        let pin_say = move |line: String| podssh_ssh::err_line!("podssh: {pin_shown}: {line}");
        let carried = carry_through(&config, link, leg, app, Some(part.expires_ms), &say, channel, pin_say).await;
        let judged = crate::operator::judged(&label, &carried);
        // Told already when the node let the session in; else its end is
        // the verdict.
        let kind = match &carried.channel {
            Some((Fault::Auth, _)) => Kind::NotAllowed,
            Some((_, why)) if why.starts_with("the node could not reach its target") => Kind::Unreachable,
            Some(_) => Kind::NotAllowed,
            None => Kind::Failed,
        };
        let (code, line) = judged.clone().unwrap_or((sysexits::EX_UNAVAILABLE, "the session ended at once".into()));
        tell(&told, Err(Refused { code, line, kind }));
        judged
    });
    match tokio::time::timeout(VERDICT_WAIT, verdict).await {
        Ok(Ok(Ok(()))) => {
            let (read, write) = tokio::io::split(ours);
            let ending = Some(Box::new(Session { task, label: to.name.clone() }) as Box<dyn Ending>);
            Ok(End { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending })
        }
        Ok(Ok(Err(refused))) => Err(refused),
        Ok(Err(_)) => Err(Refused {
            code: EXIT_SOFTWARE,
            line: "the session's task ended before the node's verdict".into(),
            kind: Kind::Failed,
        }),
        Err(_) => {
            task.abort();
            let line = format!("the exit gave no verdict within {} s", VERDICT_WAIT.as_secs());
            Err(Refused { code: sysexits::EX_UNAVAILABLE, line, kind: Kind::Failed })
        }
    }
}

/// The plain side of a session, which tells the verdict at its first touch:
/// the channel reads or writes it only once the node let it in.
struct Told<S> {
    inner: S,
    told: Tell,
}

impl<S> Told<S> {
    fn touched(&self) {
        tell(&self.told, Ok(()));
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Told<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.touched();
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Told<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        self.touched();
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The session's task, judged at the end as `podssh operator` judges it.
struct Session {
    task: JoinHandle<Option<(i32, String)>>,
    label: String,
}

impl Ending for Session {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            let Session { task, label } = *self;
            match task.await {
                Ok(judged) => judged.map(|(code, why)| (code, vec![format!("exit {label}: {why}")])),
                Err(e) => Some((EXIT_SOFTWARE, vec![format!("exit {label}: the session's task failed: {e}")])),
            }
        })
    }
}

/// `podssh proxy --exit NAME HOST PORT`: stdin and stdout, joined to
/// HOST:PORT from the exit, as `podssh proxy` joins them through the relay.
pub fn run_proxy(to: &To, host: &str, port: u16, err: &mut dyn Write) -> i32 {
    crate::session_log::target(host, Some(port), "exit");
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return crate::exit_codes::EXIT_NOT_IMPLEMENTED;
        }
    };
    let code = runtime.block_on(async {
        match open(to, host, port).await {
            Ok(end) => {
                crate::session_log::opened(None);
                let pumped = crate::pipe::pump::pump(crate::pipe::local::stdio(), end).await;
                crate::session_log::carried(pumped.carried.0, pumped.carried.1);
                crate::pipe::report(pumped, "podssh proxy", err).await
            }
            Err(refused) => {
                let _ = writeln!(err, "podssh proxy: --exit {}: {}", to.name, refused.line);
                refused.code
            }
        }
    });
    // A read on stdin may still be blocked in a helper thread.
    runtime.shutdown_background();
    code
}
