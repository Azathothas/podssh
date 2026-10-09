//! `podssh node NAME TARGET` (T-083): the node of the pair stored under the
//! label NAME, in front of the TCP service TARGET. Each session that an
//! operator opens is one connection to TARGET. The node runs until Ctrl-C or
//! SIGTERM (exit 0), or until the relay ends the pair. stdout stays empty:
//! a node has no answer to give.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::pair::Pair;
use podssh_relay::reverse::{self, Exit, NodeConfig, Settings, TcpHandler, Wire};
use podssh_ws::dial::ProxyChoice;
use podssh_ws::Trust;

use crate::exitmap::Fault;
use crate::pairs;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// What `podssh node` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeArgs {
    /// The label of a stored pair.
    pub name: Option<String>,
    /// `HOST:PORT`, or `[IPV6]:PORT`.
    pub target: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    /// A pair file to use in place of the store.
    pub pair_file: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Run the verb; returns the process exit code.
pub fn run_node(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    let ready = match prepare(args) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("node", err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh node: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    let code = runtime.block_on(serve(ready, err));
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

/// Each check that needs no network, in order: the arguments, the pins, the
/// pair.
struct Ready {
    label: String,
    pair: Pair,
    /// Whether the pair came from the store, whose copy goes when the relay
    /// says that the pair was stopped.
    stored: bool,
    host: String,
    port: u16,
    trust: Trust,
}

fn prepare(args: &NodeArgs) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the label of a pair (podssh relay pair NAME)")?;
    pairs::check_label(&label)?;
    let target = args.target.as_deref().ok_or("missing TARGET: the HOST:PORT that each session reaches")?;
    let (host, port) =
        crate::proxy::parse_target(Some(target), None).map_err(|why| Refusal::usage(format!("TARGET: {why}")))?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    let (pair, stored) = match &args.pair_file {
        Some(file) => (pairs::usable(pairs::from_file(file)?, &label)?, false),
        None => (pairs::stored(&label)?, true),
    };
    pairs::online()?;
    Ok(Ready { label, pair, stored, host, port, trust: pairs::trust(args.ca_file.as_deref()) })
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, pair, stored, host, port, trust } = ready;
    let target = podssh_ws::dial::authority(&host, port);
    let proxy = ProxyChoice::FromEnvironment;
    // TARGET first: a node that cannot reach it would serve no session.
    match podssh_ws::dial::dial(&host, port, &proxy, DIAL_LIMIT).await {
        Ok(probe) => drop(probe),
        Err(e) => {
            let refusal = Refusal { message: format!("TARGET {target}: {e}"), code: Fault::RelayUnreachable.code() };
            return refusal.report("node", err);
        }
    }
    let _ = writeln!(
        err,
        "podssh node: {label}: serving {target} through {} until Ctrl-C; the pair expires {}",
        pair.relay.host,
        pairs::utc(pair.expires_ms)
    );
    let mut config = NodeConfig {
        pair,
        label: stored.then(|| label.clone()),
        trust: &trust,
        proxy: &proxy,
        timeout: pairs::REQUEST_LIMIT,
        settings: Settings::default(),
        repair: None,
        wire: Wire::Tls,
    };
    let handler = Arc::new(TcpHandler { host, port, timeout: DIAL_LIMIT });
    let exit = reverse::run(&mut config, handler, stop_signal()).await;
    finish(&label, exit, err)
}

/// The exit code for each end of a node, by the table of `exitmap`, and what
/// to do next.
fn finish(label: &str, exit: Exit, err: &mut dyn Write) -> i32 {
    let remedy = format!("make a new pair with `podssh relay pair {label}`");
    let (fault, why) = match exit {
        Exit::Stopped => {
            let _ = writeln!(err, "podssh node: {label}: stopped");
            return 0;
        }
        Exit::NameInUse => {
            (Fault::RelayUnreachable, "another node serves this pair (409); a pair has one node at a time".to_string())
        }
        Exit::PairStopped => (Fault::Revoked, format!("the pair was stopped on the relay; {remedy}")),
        Exit::PairExpired => (Fault::PairExpired, format!("the pair expired; {remedy}")),
        Exit::Forbidden => {
            (Fault::Auth, format!("the relay refused the pair (403): it was stopped, or its token is wrong; {remedy}"))
        }
        Exit::Fault(close) => (
            Fault::SessionFault,
            format!("the relay closed the node for a fault of this node: {} {}", close.code, close.reason),
        ),
        Exit::Unusable(why) => (Fault::Config, why),
    };
    let _ = writeln!(err, "podssh node: {label}: {why}");
    fault.code()
}

/// Ctrl-C, or SIGTERM on Unix. When no signal can be watched, the node runs
/// until the relay ends it, and does not stop at once.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                stopped = tokio::signal::ctrl_c() => {
                    if stopped.is_err() {
                        term.recv().await;
                    }
                }
                _ = term.recv() => {}
            }
            return;
        }
    }
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
