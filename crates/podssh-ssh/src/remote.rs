//! The channels of `-R` (T-035): the server takes a connection on a port that
//! podssh asked it to listen on, and opens a `forwarded-tcpip` channel;
//! podssh connects to the forward's target, through the proxy as `--direct`
//! does, and joins the two. A channel for a port that podssh did not ask for
//! is refused, in the handler.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::Channel;

use crate::handler::Client;
use crate::log::Log;
use crate::options::{Options, RemoteForward};

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

/// Ask the server for each forward of `opts`, after the login. A refused one
/// ends the run when `ExitOnForwardFailure` asks for it, as in OpenSSH, and
/// is a warning else.
pub async fn request(handle: &Handle<Client>, table: &Table, opts: &Options, log: &Log) -> Result<(), String> {
    for forward in &opts.remote_forwards {
        match handle.tcpip_forward(forward.sent_address(), u32::from(forward.port)).await {
            Ok(chosen) => {
                // The server names a port only when it chose one.
                let port = if forward.port == 0 { chosen } else { u32::from(forward.port) };
                if forward.port == 0 {
                    log.info(&format!(
                        "Allocated port {port} for remote forward to {}:{}",
                        forward.host, forward.host_port
                    ));
                }
                table.lock().unwrap_or_else(|e| e.into_inner()).push(Bound { port, forward: forward.clone() });
            }
            Err(_) if opts.exit_on_forward_failure => {
                return Err(format!("Error: remote port forwarding failed for listen port {}", forward.port));
            }
            Err(_) => log.info(&format!("Warning: remote port forwarding failed for listen port {}", forward.port)),
        }
    }
    Ok(())
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
    let choice = podssh_ws::dial::ProxyChoice::FromEnvironment;
    let mut tcp = match podssh_ws::dial::dial(&forward.host, forward.host_port, &choice, DIAL_LIMIT).await {
        Ok(tcp) => tcp,
        Err(e) => {
            log.info(&format!("remote forward to {target}: cannot connect: {e}"));
            let _ = channel.close().await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    let mut stream = channel.into_stream();
    if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await {
        log.verbose(&format!("remote forward to {target} ended: {e}"));
    }
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
