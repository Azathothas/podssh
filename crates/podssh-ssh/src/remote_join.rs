//! Each channel of a remote forward, joined to its target from this host
//! (T-035, T-365): a host and a port, dialed through the proxy as `--direct`
//! dials; a socket here, as `podssh pipe unix-connect:` reaches one; or the
//! SOCKS proxy of `-R [bind_address:]port`, whose request names its target,
//! read with `-D`'s code and answered after the dial, so that the client
//! learns whether the target was reached. A target that fails closes that
//! channel only, and says why.

use std::sync::Arc;
use std::time::Duration;

use russh::client::Msg;
use russh::Channel;

use crate::log::Log;
use crate::options::{RemoteForward, RemoteTarget};
use crate::tally::Counts;

/// The bound on a connection to a forward's target: the bound on each step
/// of reaching a relay host.
const DIAL_LIMIT: Duration = Duration::from_secs(20);

/// The bound on a SOCKS client's request, read on its channel.
const REQUEST_LIMIT: Duration = Duration::from_secs(30);

pub async fn join(channel: Channel<Msg>, forward: RemoteForward, log: Arc<Log>) {
    let counts = crate::tally::of(&crate::remote::name(&forward));
    match &forward.target {
        RemoteTarget::Tcp { host, port } => tcp(channel, host, *port, &counts, &log).await,
        RemoteTarget::Socket(path) => socket(channel, path, &counts, &log).await,
        RemoteTarget::Socks => socks(channel, &counts, &log).await,
    }
}

async fn tcp(channel: Channel<Msg>, host: &str, port: u16, counts: &Arc<Counts>, log: &Log) {
    let target = podssh_ws::dial::authority(host, port);
    let choice = podssh_ws::dial::ProxyChoice::FromEnvironment;
    let tcp = match podssh_ws::dial::dial(host, port, &choice, DIAL_LIMIT).await {
        Ok(tcp) => tcp,
        Err(e) => {
            counts.failed();
            log.info(&format!("remote forward to {target}: cannot connect: {e}"));
            let _ = channel.close().await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    if let Err(e) = crate::tally::copy(tcp, channel.into_stream(), counts).await {
        log.verbose(&format!("remote forward to {target} ended: {e}"));
    }
}

#[cfg(unix)]
async fn socket(channel: Channel<Msg>, path: &str, counts: &Arc<Counts>, log: &Log) {
    let connected = tokio::time::timeout(DIAL_LIMIT, tokio::net::UnixStream::connect(path)).await;
    let stream = match connected {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return refuse(channel, counts, log, &format!("remote forward to {path}: cannot connect: {e}")).await
        }
        Err(_) => {
            let why = format!("remote forward to {path}: no answer within {} s", DIAL_LIMIT.as_secs());
            return refuse(channel, counts, log, &why).await;
        }
    };
    if let Err(e) = crate::tally::copy(stream, channel.into_stream(), counts).await {
        log.verbose(&format!("remote forward to {path} ended: {e}"));
    }
}

/// Windows has sockets of the family, which tokio does not reach.
#[cfg(not(unix))]
async fn socket(channel: Channel<Msg>, path: &str, counts: &Arc<Counts>, log: &Log) {
    refuse(channel, counts, log, &format!("remote forward to {path}: a socket on this host is reached on Unix only"))
        .await;
}

async fn refuse(channel: Channel<Msg>, counts: &Arc<Counts>, log: &Log, why: &str) {
    counts.failed();
    log.info(why);
    let _ = channel.close().await;
}

/// The SOCKS proxy of the client: a request on the channel, its target
/// dialed as each target of `-R` is, then the answer, and the copy.
async fn socks(channel: Channel<Msg>, counts: &Arc<Counts>, log: &Log) {
    let (mut read, mut write) = tokio::io::split(channel.into_stream());
    let asked = tokio::time::timeout(REQUEST_LIMIT, crate::socks::read_request(&mut read, &mut write)).await;
    let request = match asked {
        Ok(Ok(request)) => request,
        Ok(Err(why)) => {
            counts.failed();
            return log.verbose(&format!("remote forward, SOCKS: {why}"));
        }
        Err(_) => {
            counts.failed();
            return log.verbose(&format!("remote forward, SOCKS: no request within {} s", REQUEST_LIMIT.as_secs()));
        }
    };
    let target = podssh_ws::dial::authority(&request.host, request.port);
    let choice = podssh_ws::dial::ProxyChoice::FromEnvironment;
    let tcp = match podssh_ws::dial::dial(&request.host, request.port, &choice, DIAL_LIMIT).await {
        Ok(tcp) => tcp,
        Err(e) => {
            counts.failed();
            let _ = crate::socks::answer(&mut write, request.version, Err(crate::socks::Refusal::Refused)).await;
            return log.info(&format!("remote forward, SOCKS to {target}: cannot connect: {e}"));
        }
    };
    if crate::socks::answer(&mut write, request.version, Ok(())).await.is_err() {
        counts.failed();
        return;
    }
    let _ = tcp.set_nodelay(true);
    if let Err(e) = crate::tally::copy(tcp, read.unsplit(write), counts).await {
        log.verbose(&format!("remote forward, SOCKS to {target} ended: {e}"));
    }
}
