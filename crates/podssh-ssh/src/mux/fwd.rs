//! The forwards of `-O forward` and `-O cancel` on a master (T-039). A
//! local or a dynamic one gets its listeners from the caller's binder, and
//! the master serves it on its connection; a remote one asks the server, as
//! `-R` does, and the handler joins its channels. An empty listening host
//! is none, as OpenSSH's master reads it.

use super::master::{kind_name, Job};
use super::proto::{Fwd, FwdKind, Message, PORT_STREAMLOCAL};
use crate::options::{RemoteForward, RemoteListen, RemoteTarget};
use crate::remote::{Bound, Listening};

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

/// The forward of the server that `fwd` names, as `-R` would send it: a
/// path on either side is the port `PORT_STREAMLOCAL`, and the SOCKS form
/// has no host and the port 0, as OpenSSH's master reads them (T-365).
fn remote_forward(fwd: &Fwd) -> Result<RemoteForward, String> {
    let listen = if fwd.listen_port == PORT_STREAMLOCAL {
        RemoteListen::Path(fwd.listen_host.clone())
    } else {
        let port =
            u16::try_from(fwd.listen_port).map_err(|_| format!("listen port {} is not a port", fwd.listen_port))?;
        RemoteListen::Port { bind: (!fwd.listen_host.is_empty()).then(|| fwd.listen_host.clone()), port }
    };
    let target = if fwd.connect_port == PORT_STREAMLOCAL {
        RemoteTarget::Socket(fwd.connect_host.clone())
    } else if fwd.connect_host.is_empty() && fwd.connect_port == 0 {
        RemoteTarget::Socks
    } else {
        let port =
            u16::try_from(fwd.connect_port).map_err(|_| format!("connect port {} is not a port", fwd.connect_port))?;
        RemoteTarget::Tcp { host: fwd.connect_host.clone(), port }
    };
    Ok(RemoteForward { listen, target })
}

async fn remote_open(job: &Job<'_>, rid: u32, fwd: &Fwd) -> Message {
    let forward = match remote_forward(fwd) {
        Ok(forward) => forward,
        Err(reason) => return Message::Failure { rid, reason },
    };
    let Some(table) = crate::remote::destination() else {
        return Message::Failure { rid, reason: "the master has no connection to forward on".into() };
    };
    match crate::remote::open_on_server(job.handle(), &forward).await {
        Some(at) => {
            table.lock().unwrap_or_else(|e| e.into_inner()).push(Bound { at: at.clone(), forward: forward.clone() });
            match (forward.port(), at) {
                (Some(0), Listening::Port(port)) => Message::RemotePort { rid, port },
                _ => Message::Ok { rid },
            }
        }
        None => Message::Failure { rid, reason: crate::remote::refused(&forward) },
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
    // The same listening side and target; a port of 0 is the one that the
    // server chose.
    let same = |b: &Bound| match (&b.forward.listen, &wanted.listen) {
        (RemoteListen::Port { port, .. }, RemoteListen::Port { port: asked, .. }) => {
            (port == asked || *asked == 0)
                && b.forward.sent_address() == wanted.sent_address()
                && b.forward.target == wanted.target
        }
        _ => b.forward == wanted,
    };
    let found = {
        let bound = table.lock().unwrap_or_else(|e| e.into_inner());
        bound.iter().position(same).map(|i| (i, bound[i].at.clone(), bound[i].forward.clone()))
    };
    let (index, at, forward) = found.ok_or("no such remote forward")?;
    crate::remote::close_on_server(job.handle(), &forward, &at).await?;
    let mut bound = table.lock().unwrap_or_else(|e| e.into_inner());
    if index < bound.len() {
        bound.remove(index);
    }
    Ok(())
}
