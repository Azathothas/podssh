//! One connection to a server for `cp` or `mv`, and the road of its files:
//! SFTP, or a command for each step when the server has none (T-135). The
//! server can be a node of a pair, reached through its pair (T-296).

use std::sync::Arc;

use podssh_relay::relay::{byte_budget, time_budget, SESSION_BUDGET_ENV};
use podssh_ssh::run::HopError;
use podssh_ssh::sftp::{Limits, Sftp, SftpError};
use podssh_ssh::{Connection, Log, RelayStatus};

use super::byexec::Far;
use super::transfer::{Cause, Failed};
use crate::exitmap::Fault;
use crate::ssh::resolve::{Resolved, Transport};

/// Room for the framing of SSH and SFTP around the bytes of one request.
const OVERHEAD: u64 = 64 << 10;

/// How the files of one session go: SFTP, or a command for each step.
pub enum Road {
    Sftp(Sftp),
    Exec(Far),
}

/// A connection, with its hops, and the road of its files.
pub struct Link {
    handles: Vec<Connection>,
    pub road: Road,
    pub meter: Meter,
    /// The task of the resumable layer that carries the connection, on a
    /// road that runs one (T-296, T-300): the close waits for its `CLOSE`.
    layer: Option<crate::ssh::transport::Carriage>,
}

/// What one session may still carry before a copy opens a new one: through
/// the relay, its payload bytes and its age, against podssh's budgets
/// (T-137); on a road that ends each session after a time, its age (EICE's
/// tunnel, T-351). A direct connection has no cap.
#[derive(Debug, Clone)]
pub struct Meter {
    relay: Option<RelayStatus>,
    budget: u64,
    /// When the road ends the session, less a margin.
    until: Option<std::time::Instant>,
}

impl Meter {
    /// The meter of a session: `relay` when the relay carries it.
    pub fn new(relay: Option<RelayStatus>) -> Meter {
        Meter::lasting(relay, None)
    }

    /// The same, for a session that its road ends after `age`.
    pub fn lasting(relay: Option<RelayStatus>, age: Option<std::time::Duration>) -> Meter {
        let budget = byte_budget(std::env::var(SESSION_BUDGET_ENV).ok().as_deref());
        Meter { relay, budget, until: age.map(|age| std::time::Instant::now() + age) }
    }

    /// Whether the relay carries the session: its tasks then share its room.
    pub fn through_relay(&self) -> bool {
        self.relay.is_some()
    }

    /// The bytes that the session may still carry; no end without a relay.
    pub fn left(&self) -> u64 {
        if self.until.is_some_and(|until| std::time::Instant::now() >= until) {
            return 0;
        }
        match &self.relay {
            None => u64::MAX,
            Some(status) if status.age() >= time_budget(&podssh_relay::pool::in_use()) => 0,
            Some(status) => self.budget.saturating_sub(status.bytes()),
        }
    }

    /// Whether a request that moves `n` more bytes must wait for a new
    /// session: the failure that says so, else `None`.
    pub fn spent(&self, n: u64) -> Option<Failed> {
        let message =
            if self.relay.is_some() { "the relay session is near its limits" } else { "the tunnel is near its end" };
        (self.left() < n.saturating_add(OVERHEAD)).then(|| Failed {
            fault: Fault::SessionFault,
            message: message.into(),
            cause: Cause::Spent,
        })
    }
}

impl Link {
    /// The destination's connection.
    pub fn handle(&self) -> &Connection {
        self.handles.last().expect("the destination's connection")
    }

    /// Whether the server copies a file within itself (`copy-data`), so that
    /// no byte comes through this host.
    pub fn copies_within(&self) -> bool {
        matches!(&self.road, Road::Sftp(sftp) if sftp.has("copy-data"))
    }

    /// End the SFTP session, then each connection.
    pub async fn close(self) {
        let Link { handles, road, layer, .. } = self;
        if let Road::Sftp(sftp) = road {
            let _ = sftp.close_session();
        }
        podssh_ssh::run::disconnect_all(&handles).await;
        drop(handles);
        crate::ssh::transport::settle(layer).await;
    }
}

/// Connect to `resolved`'s server and open the road of its files, with a
/// copy by exec when the server has no SFTP.
pub async fn connect(resolved: &Resolved, log: &Arc<Log>) -> Result<Link, Failed> {
    match open(resolved, log, true).await? {
        Some(link) => Ok(link),
        None => Err(Failed::new(Fault::RelayUnreachable, "the server has no SFTP".into())),
    }
}

/// Connect to `resolved`'s server for SFTP only, on the subsystem `name`
/// (`podssh sftp`, `-s NAME`).
pub async fn open_sftp(resolved: &Resolved, log: &Arc<Log>, name: &str) -> Result<Link, Failed> {
    let (handles, relay, layer) = hops(resolved, log).await?;
    let handle = handles.last().expect("the destination's connection");
    let host = &resolved.options.destination.host;
    match Sftp::open_named(handle, name, Limits::default()).await {
        Ok(sftp) => Ok(Link { handles, road: Road::Sftp(sftp), meter: meter(resolved, relay), layer }),
        Err(e) => {
            podssh_ssh::run::disconnect_all(&handles).await;
            let why = match e {
                SftpError::NoSftp => format!("{host} has no {name} subsystem"),
                e => format!("{host}: {e}"),
            };
            Err(Failed::new(Fault::RelayUnreachable, why))
        }
    }
}

/// The connection to `resolved`'s server, each hop logged in; the relay
/// leg's status when the relay carries it, and the layer's task when the
/// layer does.
type Hops = (Vec<Connection>, Option<RelayStatus>, Option<crate::ssh::transport::Carriage>);

async fn hops(resolved: &Resolved, log: &Arc<Log>) -> Result<Hops, Failed> {
    let reached = match &resolved.transport {
        // A node of a pair, through its pair, as `ssh node://` reaches it
        // (T-296). Its session has no relay status here: the resumable layer
        // moves it to a new leg before the relay's limits (T-155).
        Transport::Node { label, pair_file, trust, channel, .. } => {
            crate::ssh::node::reach(label, pair_file.as_deref(), trust, channel, log).await
        }
        _ => crate::ssh::transport::reach(resolved, log).await,
    };
    let reached = match reached {
        Ok(reached) => reached,
        Err(not) => {
            for line in &not.lines {
                log.error(line);
            }
            let message = format!("{}: no connection to the server", resolved.options.destination.host);
            return Err(Failed::new(fault_of(not.code), message));
        }
    };
    let handles = podssh_ssh::run::connect_hops(reached.stream, &resolved.options, log).await.map_err(hop_failure)?;
    Ok((handles, reached.relay, reached.layer))
}

/// Connect to `resolved`'s server and open the road of its files. With no
/// SFTP, `exec` probes for a copy by exec, and says so once; without it the
/// answer is `None`.
pub async fn open(resolved: &Resolved, log: &Arc<Log>, exec: bool) -> Result<Option<Link>, Failed> {
    let (handles, relay, layer) = hops(resolved, log).await?;
    let handle = handles.last().expect("the destination's connection");
    let host = &resolved.options.destination.host;
    let road = match Sftp::open(handle, Limits::default()).await {
        Ok(sftp) => Road::Sftp(sftp),
        Err(SftpError::NoSftp) if !exec => {
            podssh_ssh::run::disconnect_all(&handles).await;
            return Ok(None);
        }
        // No SFTP: each step a command (T-135), said once.
        Err(SftpError::NoSftp) => {
            log.info(&format!("{host} has no SFTP subsystem: the copy goes by exec"));
            match Far::probe(handle, log).await {
                Ok(far) => Road::Exec(far),
                Err(failed) => {
                    podssh_ssh::run::disconnect_all(&handles).await;
                    return Err(failed);
                }
            }
        }
        Err(e) => {
            podssh_ssh::run::disconnect_all(&handles).await;
            return Err(Failed::new(Fault::RelayUnreachable, format!("{host}: {e}")));
        }
    };
    Ok(Some(Link { handles, road, meter: meter(resolved, relay), layer }))
}

/// The meter of a session of `resolved`'s road: a tunnel of EICE ends at
/// its duration (T-351).
fn meter(resolved: &Resolved, relay: Option<RelayStatus>) -> Meter {
    Meter::lasting(relay, crate::ssh::cloud::age_limit(&resolved.transport))
}

/// The fault of a sysexits code that `transport::reach` gave.
fn fault_of(code: i32) -> Fault {
    [Fault::Usage, Fault::Auth, Fault::Config].into_iter().find(|f| f.code() == code).unwrap_or(Fault::RelayUnreachable)
}

/// A connection that failed, as the fault of `cp`.
fn hop_failure(e: HopError) -> Failed {
    let fault = match e {
        HopError::Unreachable(_) | HopError::Forward(_) => Fault::RelayUnreachable,
        HopError::HostKey(_) | HopError::Auth(_) => Fault::Auth,
    };
    Failed::new(fault, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_is_spent_before_its_budget_and_a_direct_one_never() {
        let direct = Meter { relay: None, budget: 1 << 20, until: None };
        assert_eq!(direct.left(), u64::MAX);
        assert!(direct.spent(u64::MAX / 2).is_none());
        let relayed = Meter { relay: Some(RelayStatus::default()), budget: 1 << 20, until: None };
        assert_eq!(relayed.left(), 1 << 20, "a new session has the whole budget");
        assert!(relayed.spent(1000).is_none());
        let spent = relayed.spent(1 << 20).expect("a request that would pass the budget, with its framing");
        assert_eq!((spent.cause, spent.fault), (Cause::Spent, Fault::SessionFault));
    }

    /// A tunnel that its road ends after a time is spent at that time, and
    /// not before (T-351).
    #[test]
    fn a_tunnel_is_spent_at_its_age() {
        let young = Meter::lasting(None, Some(std::time::Duration::from_secs(3300)));
        assert!(young.spent(1 << 30).is_none());
        let old = Meter { relay: None, budget: 1 << 20, until: Some(std::time::Instant::now()) };
        assert_eq!(old.left(), 0);
        let spent = old.spent(1).expect("spent at its age");
        assert_eq!((spent.cause, spent.message.as_str()), (Cause::Spent, "the tunnel is near its end"));
    }
}
