//! The channels of `-R` (T-035): the server takes a connection on a port that
//! podssh asked it to listen on, and opens a `forwarded-tcpip` channel;
//! podssh connects to the forward's target, through the proxy as `--direct`
//! does, and joins the two. A channel for a port that podssh did not ask for
//! is refused, in the handler.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::client::{Handle, Msg};
use russh::Channel;

use crate::handler::Client;
use crate::log::Log;
use crate::options::{Options, RemoteForward};
use crate::run::HopError;

/// The bound on a connection to a forward's target: the bound on each step
/// of reaching a relay host.
const DIAL_LIMIT: Duration = Duration::from_secs(20);

/// A forward that the server took, with the port it listens on: the one it
/// chose when the forward asked for 0.
#[derive(Debug, Clone)]
pub struct Bound {
    pub port: u32,
    pub forward: RemoteForward,
}

/// The forwards that the server took, shared with the handler, which reads
/// it for each channel that the server opens.
pub type Table = Arc<Mutex<Vec<Bound>>>;

/// The destination's table, where a control master adds the forwards of
/// `-O forward -R` (T-039): a process runs one chain of connections.
static DESTINATION: Mutex<Option<Table>> = Mutex::new(None);

pub fn set_destination(table: Table) {
    *DESTINATION.lock().unwrap_or_else(|e| e.into_inner()) = Some(table);
}

pub fn destination() -> Option<Table> {
    DESTINATION.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Ask the server for each forward of `opts`, after the login. A refused one
/// ends the run when `ExitOnForwardFailure` asks for it, as in OpenSSH, and
/// is a warning else. After a loss of `--persist`, a refused one is asked
/// again first, as `opts.forwards_again` says (T-042).
pub async fn request(handle: &Handle<Client>, table: &Table, opts: &Options, log: &Log) -> Result<(), HopError> {
    let mut refused: Vec<&RemoteForward> = Vec::new();
    for forward in &opts.remote_forwards {
        if !ask(handle, table, forward, log).await {
            if opts.exit_on_forward_failure && opts.forwards_again.is_none() {
                return Err(HopError::Forward(failed("Error", forward)));
            }
            refused.push(forward);
        }
    }
    if let Some(again) = opts.forwards_again.filter(|_| !refused.is_empty()) {
        let started = Instant::now();
        let mut round = 0;
        while !refused.is_empty() && started.elapsed() < again.within && !handle.is_closed() {
            round += 1;
            let wait = (again.wait)(round).min(again.within.saturating_sub(started.elapsed()));
            let names: Vec<String> = refused.iter().map(|f| name(f)).collect();
            log.info(&format!(
                "the server refused {}, which it may still hold for the lost connection; asking again in {:.1} s",
                names.join(", "),
                wait.as_secs_f64()
            ));
            tokio::time::sleep(wait).await;
            let mut still = Vec::new();
            for forward in refused {
                if !ask(handle, table, forward, log).await {
                    still.push(forward);
                }
            }
            refused = still;
        }
    }
    if !refused.is_empty() && handle.is_closed() {
        return Err(HopError::Unreachable("the connection was lost while the forwards were asked for".into()));
    }
    for forward in refused {
        if opts.exit_on_forward_failure {
            return Err(HopError::Forward(failed("Error", forward)));
        }
        log.info(&failed("Warning", forward));
    }
    Ok(())
}

/// Ask the server for one forward: whether it took it, which is then in
/// `table`.
async fn ask(handle: &Handle<Client>, table: &Table, forward: &RemoteForward, log: &Log) -> bool {
    let Ok(chosen) = handle.tcpip_forward(forward.sent_address(), u32::from(forward.port)).await else {
        return false;
    };
    // The server names a port only when it chose one; it may choose another
    // on each connection of a run.
    let port = if forward.port == 0 { chosen } else { u32::from(forward.port) };
    if forward.port == 0 {
        log.info(&format!("Allocated port {port} for remote forward to {}:{}", forward.host, forward.host_port));
    }
    table.lock().unwrap_or_else(|e| e.into_inner()).push(Bound { port, forward: forward.clone() });
    // In the list of ~# from now on (T-041).
    crate::tally::of(&name(forward));
    true
}

/// OpenSSH's line for a forward that the server refused.
fn failed(level: &str, forward: &RemoteForward) -> String {
    format!("{level}: remote port forwarding failed for listen port {}", forward.port)
}

/// The forward that a channel for `address:port` belongs to, if podssh asked
/// for one. The server names the port it listens on, and the address that
/// podssh sent; the port decides, and the address between two forwards on
/// one port.
pub fn find(table: &Table, address: &str, port: u32) -> Option<RemoteForward> {
    let bound = table.lock().unwrap_or_else(|e| e.into_inner());
    let on_port: Vec<&Bound> = bound.iter().filter(|b| b.port == port).collect();
    match on_port.as_slice() {
        [one] => Some(one.forward.clone()),
        many => many.iter().find(|b| b.forward.sent_address() == address).map(|b| b.forward.clone()),
    }
}

/// Join an accepted channel to its forward's target: connect through the
/// proxy, then copy both ways, each end of input passed on. A connection
/// that fails closes this channel only, and says why.
pub async fn join(channel: Channel<Msg>, forward: RemoteForward, log: Arc<Log>) {
    let target = podssh_ws::dial::authority(&forward.host, forward.host_port);
    let counts = crate::tally::of(&name(&forward));
    let choice = podssh_ws::dial::ProxyChoice::FromEnvironment;
    let tcp = match podssh_ws::dial::dial(&forward.host, forward.host_port, &choice, DIAL_LIMIT).await {
        Ok(tcp) => tcp,
        Err(e) => {
            counts.failed();
            log.info(&format!("remote forward to {target}: cannot connect: {e}"));
            let _ = channel.close().await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    if let Err(e) = crate::tally::copy(tcp, channel.into_stream(), &counts).await {
        log.verbose(&format!("remote forward to {target} ended: {e}"));
    }
}

/// A remote forward as `-R` writes it, for the lines of its counts (T-041).
pub fn name(forward: &RemoteForward) -> String {
    let bind = forward.bind.as_deref().map(|b| format!("{b}:")).unwrap_or_default();
    format!("-R {bind}{}:{}", forward.port, podssh_ws::dial::authority(&forward.host, forward.host_port))
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
