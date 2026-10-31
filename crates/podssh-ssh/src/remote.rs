//! The channels of `-R` (T-035, T-365): the server takes a connection on a
//! port, or on a socket path, that podssh asked it to listen on, and opens a
//! `forwarded-tcpip` or a `forwarded-streamlocal@openssh.com` channel;
//! podssh joins it to the forward's target (`remote_join`). A channel for a
//! port or a path that podssh did not ask for is refused, in the handler.
//! `~C` asks for one more, or stops one (T-291).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use russh::client::{Handle, Msg};
use russh::Channel;

use crate::handler::Client;
use crate::log::Log;
use crate::options::{Options, RemoteForward, RemoteListen};
use crate::run::HopError;

/// Where the server listens for a forward that it took: the port that it
/// chose when the forward asked for 0, or the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listening {
    Port(u32),
    Path(String),
}

/// A forward that the server took, with where it listens.
#[derive(Debug, Clone)]
pub struct Bound {
    pub at: Listening,
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
    // One that `~C -KR` stopped stays stopped on a new connection (T-291).
    for forward in opts.remote_forwards.iter().filter(|f| !crate::tally::is_closed(&name(f))) {
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

/// Where the server will listen for `forward` before it answers: a port or
/// a path named in advance; `None` for a port of 0, which the server names.
fn named(forward: &RemoteForward) -> Option<Listening> {
    match &forward.listen {
        RemoteListen::Port { port: 0, .. } => None,
        RemoteListen::Port { port, .. } => Some(Listening::Port(u32::from(*port))),
        RemoteListen::Path(path) => Some(Listening::Path(path.clone())),
    }
}

/// Ask the server to listen for `forward`: `tcpip-forward` for a port,
/// `streamlocal-forward@openssh.com` for a path; where it listens, or `None`
/// when it refused.
pub(crate) async fn open_on_server(handle: &Handle<Client>, forward: &RemoteForward) -> Option<Listening> {
    match &forward.listen {
        RemoteListen::Port { port, .. } => {
            let chosen = handle.tcpip_forward(forward.sent_address(), u32::from(*port)).await.ok()?;
            Some(Listening::Port(if *port == 0 { chosen } else { u32::from(*port) }))
        }
        RemoteListen::Path(path) => {
            handle.streamlocal_forward(path.clone()).await.ok()?;
            Some(Listening::Path(path.clone()))
        }
    }
}

/// Ask the server to stop listening at `at` for `forward`.
pub(crate) async fn close_on_server(
    handle: &Handle<Client>,
    forward: &RemoteForward,
    at: &Listening,
) -> Result<(), String> {
    let done = match at {
        Listening::Port(port) => handle.cancel_tcpip_forward(forward.sent_address(), *port).await,
        Listening::Path(path) => handle.cancel_streamlocal_forward(path.clone()).await,
    };
    done.map_err(|e| format!("the server kept the forward: {}", crate::run::describe(&e)))
}

/// Ask the server for one forward: whether it took it, which is then in
/// `table`.
pub(crate) async fn ask(handle: &Handle<Client>, table: &Table, forward: &RemoteForward, log: &Log) -> bool {
    // A port or a path named in advance is in the table before the request,
    // as OpenSSH's client records it: the server may open a channel for it
    // as soon as it answers, before this task reads the answer.
    let early = named(forward);
    if let Some(at) = &early {
        table.lock().unwrap_or_else(|e| e.into_inner()).push(Bound { at: at.clone(), forward: forward.clone() });
    }
    let Some(at) = open_on_server(handle, forward).await else {
        if let Some(at) = early {
            table.lock().unwrap_or_else(|e| e.into_inner()).retain(|b| !(b.at == at && b.forward == *forward));
        }
        return false;
    };
    // The server names a port only when it chose one; it may choose another
    // on each connection of a run.
    if early.is_none() {
        if let Listening::Port(chosen) = &at {
            log.info(&format!("Allocated port {chosen} for remote forward to {}", target_words(forward)));
        }
        table.lock().unwrap_or_else(|e| e.into_inner()).push(Bound { at, forward: forward.clone() });
    }
    // In the list of ~# from now on (T-041), open again if ~C had stopped it.
    crate::tally::opened(&name(forward));
    true
}

/// The target of `forward` in OpenSSH's line of an allocated port.
fn target_words(forward: &RemoteForward) -> String {
    match &forward.target {
        crate::options::RemoteTarget::Tcp { host, port } => format!("{host}:{port}"),
        crate::options::RemoteTarget::Socket(path) => path.clone(),
        crate::options::RemoteTarget::Socks => "the SOCKS proxy of this client".into(),
    }
}

/// OpenSSH's line for a forward that the server refused.
pub(crate) fn failed(level: &str, forward: &RemoteForward) -> String {
    format!("{level}: {}", refused(forward))
}

/// OpenSSH's words for a forward that the server refused, with no level, as
/// a control master answers them.
pub(crate) fn refused(forward: &RemoteForward) -> String {
    match &forward.listen {
        RemoteListen::Port { port, .. } => format!("remote port forwarding failed for listen port {port}"),
        RemoteListen::Path(path) => format!("remote port forwarding failed for listen path {path}"),
    }
}

/// Stop the forward that the server listens for at `[bind:]port` (`~C -KR`,
/// T-291), as OpenSSH finds it: by the port that the server listens on, and
/// by the address sent, when one is given. Its name once the server let it
/// go; `None` when no forward listens there.
pub(crate) async fn cancel(
    handle: &Handle<Client>,
    table: &Table,
    bind: Option<&str>,
    port: u32,
) -> Result<Option<String>, String> {
    let address = crate::remote_spec::sent(bind);
    let at = Listening::Port(port);
    cancel_where(handle, table, &at, |forward| bind.is_none() || forward.sent_address() == address).await
}

/// Stop the forward that the server listens for at `path` (`~C -KR PATH`).
pub(crate) async fn cancel_path(handle: &Handle<Client>, table: &Table, path: &str) -> Result<Option<String>, String> {
    cancel_where(handle, table, &Listening::Path(path.to_string()), |_| true).await
}

/// Stop the first forward at `at` that `matches`: its name once the server
/// let it go, and a channel for it is refused from then on.
async fn cancel_where(
    handle: &Handle<Client>,
    table: &Table,
    at: &Listening,
    matches: impl Fn(&RemoteForward) -> bool,
) -> Result<Option<String>, String> {
    let found = {
        let bound = table.lock().unwrap_or_else(|e| e.into_inner());
        bound.iter().find(|b| b.at == *at && matches(&b.forward)).map(|b| b.forward.clone())
    };
    let Some(forward) = found else { return Ok(None) };
    close_on_server(handle, &forward, at).await?;
    table.lock().unwrap_or_else(|e| e.into_inner()).retain(|b| !(b.at == *at && b.forward == forward));
    let name = name(&forward);
    crate::tally::closed(&name);
    Ok(Some(name))
}

/// The forward that a channel for `address:port` belongs to, if podssh asked
/// for one. The server names the port it listens on, and the address that
/// podssh sent; the port decides, and the address between two forwards on
/// one port.
pub fn find(table: &Table, address: &str, port: u32) -> Option<RemoteForward> {
    let bound = table.lock().unwrap_or_else(|e| e.into_inner());
    let on_port: Vec<&Bound> = bound.iter().filter(|b| b.at == Listening::Port(port)).collect();
    match on_port.as_slice() {
        [one] => Some(one.forward.clone()),
        many => many.iter().find(|b| b.forward.sent_address() == address).map(|b| b.forward.clone()),
    }
}

/// The forward that a channel for the socket `path` belongs to, if podssh
/// asked for one: the server names the path that it listens on.
pub fn find_path(table: &Table, path: &str) -> Option<RemoteForward> {
    let bound = table.lock().unwrap_or_else(|e| e.into_inner());
    bound.iter().find(|b| b.at == Listening::Path(path.to_string())).map(|b| b.forward.clone())
}

/// Join an accepted channel to its forward's target (`remote_join`).
pub async fn join(channel: Channel<Msg>, forward: RemoteForward, log: Arc<Log>) {
    crate::remote_join::join(channel, forward, log).await;
}

/// A remote forward as `-R` writes it, for the lines of its counts (T-041).
pub fn name(forward: &RemoteForward) -> String {
    forward.to_string()
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
