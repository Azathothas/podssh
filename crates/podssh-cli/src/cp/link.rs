//! One connection to a server for `cp` or `mv`, and the road of its files:
//! SFTP, or a command for each step when the server has none (T-135).

use std::sync::Arc;

use podssh_ssh::run::HopError;
use podssh_ssh::sftp::{Limits, Sftp, SftpError};
use podssh_ssh::{Connection, Log};

use super::byexec::Far;
use super::transfer::Failed;
use crate::exitmap::Fault;
use crate::ssh::resolve::Resolved;

/// How the files of one session go: SFTP, or a command for each step.
pub enum Road {
    Sftp(Sftp),
    Exec(Far),
}

/// A connection, with its hops, and the road of its files.
pub struct Link {
    handles: Vec<Connection>,
    pub road: Road,
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
        let Link { handles, road } = self;
        if let Road::Sftp(sftp) = road {
            let _ = sftp.close_session();
        }
        podssh_ssh::run::disconnect_all(&handles).await;
    }
}

/// Connect to `resolved`'s server and open the road of its files, with a
/// copy by exec when the server has no SFTP.
pub async fn connect(resolved: &Resolved, log: &Arc<Log>) -> Result<Link, Failed> {
    match open(resolved, log, true).await? {
        Some(link) => Ok(link),
        None => Err(Failed { fault: Fault::RelayUnreachable, message: "the server has no SFTP".into() }),
    }
}

/// Connect to `resolved`'s server and open the road of its files. With no
/// SFTP, `exec` probes for a copy by exec, and says so once; without it the
/// answer is `None`.
pub async fn open(resolved: &Resolved, log: &Arc<Log>, exec: bool) -> Result<Option<Link>, Failed> {
    let reached = match crate::ssh::transport::reach(resolved, log).await {
        Ok(reached) => reached,
        Err(not) => {
            for line in &not.lines {
                log.error(line);
            }
            let message = format!("{}: no connection to the server", resolved.options.destination.host);
            return Err(Failed { fault: fault_of(not.code), message });
        }
    };
    let handles = podssh_ssh::run::connect_hops(reached.stream, &resolved.options, log).await.map_err(hop_failure)?;
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
            return Err(Failed { fault: Fault::RelayUnreachable, message: format!("{host}: {e}") });
        }
    };
    Ok(Some(Link { handles, road }))
}

/// The fault of a sysexits code that `transport::reach` gave.
fn fault_of(code: i32) -> Fault {
    [Fault::Usage, Fault::Auth, Fault::Config].into_iter().find(|f| f.code() == code).unwrap_or(Fault::RelayUnreachable)
}

/// A connection that failed, as the fault of `cp`.
fn hop_failure(e: HopError) -> Failed {
    let fault = match e {
        HopError::Unreachable(_) => Fault::RelayUnreachable,
        HopError::HostKey(_) | HopError::Auth(_) => Fault::Auth,
    };
    Failed { fault, message: e.to_string() }
}
