//! The forwards of `-O forward` and `-O cancel` on a master (T-039). A
//! local or a dynamic one gets its listeners from the caller's binder, and
//! the master serves it on its connection; a remote one asks the server, as
//! `-R` does, and the handler joins its channels. An empty listening host
//! is none, as OpenSSH's master reads it.

use super::master::{kind_name, Job};
use super::proto::{Fwd, FwdKind, Message, PORT_STREAMLOCAL};
use crate::options::RemoteForward;
use crate::remote::Bound;

pub(super) async fn open(job: &Job<'_>, rid: u32, fwd: Fwd) -> Message {
    let result = match fwd.kind {
        FwdKind::Remote => return remote_open(job, rid, &fwd).await,
        FwdKind::Local | FwdKind::Dynamic => match job.binder() {
            Some(binder) => match binder(fwd.clone()).await {
                Ok(forward) => job.open_local(fwd.clone(), forward).await,
                Err(why) => Err(why),
            },
            None => Err("this master takes no local forward".into()),
        },
    };
    match result {
        Ok(()) => {
            job.log().verbose(&format!("control socket: a {} forward opened", kind_name(fwd.kind)));
            Message::Ok { rid }
        }
        Err(reason) => Message::Failure { rid, reason },
    }
}

/// The forward of the server that `fwd` names, as `-R` would send it.
fn remote_forward(fwd: &Fwd) -> Result<RemoteForward, String> {
    if fwd.listen_port == PORT_STREAMLOCAL || fwd.connect_port == PORT_STREAMLOCAL {
        return Err("a socket path is not carried by -R yet".into());
    }
    let port = u16::try_from(fwd.listen_port).map_err(|_| format!("listen port {} is not a port", fwd.listen_port))?;
    let host_port =
        u16::try_from(fwd.connect_port).map_err(|_| format!("connect port {} is not a port", fwd.connect_port))?;
    let bind = (!fwd.listen_host.is_empty()).then(|| fwd.listen_host.clone());
    Ok(RemoteForward { bind, port, host: fwd.connect_host.clone(), host_port })
}

async fn remote_open(job: &Job<'_>, rid: u32, fwd: &Fwd) -> Message {
    let forward = match remote_forward(fwd) {
        Ok(forward) => forward,
        Err(reason) => return Message::Failure { rid, reason },
    };
    let Some(table) = crate::remote::destination() else {
        return Message::Failure { rid, reason: "the master has no connection to forward on".into() };
    };
    match job.handle().tcpip_forward(forward.sent_address(), u32::from(forward.port)).await {
        Ok(chosen) => {
            let port = if forward.port == 0 { chosen } else { u32::from(forward.port) };
            table.lock().unwrap_or_else(|e| e.into_inner()).push(Bound { port, forward: forward.clone() });
            if forward.port == 0 {
                Message::RemotePort { rid, port }
            } else {
                Message::Ok { rid }
            }
        }
        Err(_) => {
            Message::Failure { rid, reason: format!("remote port forwarding failed for listen port {}", forward.port) }
        }
    }
}

pub(super) async fn close(job: &Job<'_>, rid: u32, fwd: Fwd) -> Message {
    let result = match fwd.kind {
        FwdKind::Remote => remote_close(job, &fwd).await,
        FwdKind::Local | FwdKind::Dynamic => job.close_local(fwd).await,
    };
    match result {
        Ok(()) => Message::Ok { rid },
        Err(reason) => Message::Failure { rid, reason },
    }
}

async fn remote_close(job: &Job<'_>, fwd: &Fwd) -> Result<(), String> {
    let wanted = remote_forward(fwd)?;
    let table = crate::remote::destination().ok_or("the master has no connection")?;
    let found = {
        let bound = table.lock().unwrap_or_else(|e| e.into_inner());
        bound.iter().position(|b| {
            (b.port == u32::from(wanted.port) || wanted.port == 0)
                && b.forward.host == wanted.host
                && b.forward.host_port == wanted.host_port
                && b.forward.sent_address() == wanted.sent_address()
        })
    };
    let at = found.ok_or("no such remote forward")?;
    let port = table.lock().unwrap_or_else(|e| e.into_inner())[at].port;
    job.handle()
        .cancel_tcpip_forward(wanted.sent_address(), port)
        .await
        .map_err(|e| format!("the server kept the forward: {e}"))?;
    let mut bound = table.lock().unwrap_or_else(|e| e.into_inner());
    if at < bound.len() {
        bound.remove(at);
    }
    Ok(())
}
