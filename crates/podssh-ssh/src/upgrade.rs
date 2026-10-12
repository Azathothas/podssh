//! A run in two halves, for `podssh ssh --upgrade` (T-167): the login, whose
//! connection stays open for the caller's commands (the probe for a podssh
//! on the server, the temporary node), and then the request on it, when the
//! session stays there. Each half fails as a whole run fails, in the same
//! words. And the phase of the second login, through the node, which tells
//! the caller when the first connection may close.

use std::sync::Arc;
use std::time::Duration;

use russh::client::Handle;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::handler::Client;
use crate::log::Log;
use crate::options::Options;
use crate::relay_stream::{RelayEnd, RelayStatus};
use crate::retry::{self, Phase};
use crate::run::{connect_hops, failure_lines, run_handles, EXIT_FAILURE};

/// How often the phase of a login is looked at.
const PHASE_EVERY: Duration = Duration::from_millis(50);

/// Each hop of `opts` logged in over `stream`, its connections open; or the
/// lines that a run would say of the failure.
pub async fn login<S>(
    stream: S,
    opts: &Options,
    relay: Option<&RelayStatus>,
    log: &Arc<Log>,
) -> Result<Vec<Handle<Client>>, Vec<String>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    retry::begin();
    match connect_hops(stream, opts, log).await {
        Ok(handles) => Ok(handles),
        Err(e) => Err(failed(&e.to_string(), e.class(), opts, relay)),
    }
}

/// The request of `opts` on `handles`, which [`login`] gave: its exit code,
/// as [`crate::run::run`] gives it, with each line of a failure said.
pub async fn request(handles: Vec<Handle<Client>>, opts: &Options, relay: Option<&RelayStatus>, log: Arc<Log>) -> i32 {
    match run_handles(handles, opts, &log).await {
        Ok(code) => code,
        Err(message) => {
            for line in failed(&message, "session", opts, relay) {
                log.error(&line);
            }
            EXIT_FAILURE
        }
    }
}

/// A new login's phase from its handshake on, so that [`logged_in`] and
/// [`reached`] tell of that login alone.
pub fn begin() {
    retry::begin();
}

/// Once the login since [`begin`] has reached its destination: from then on
/// its request may go out.
pub async fn logged_in() {
    while !reached() {
        tokio::time::sleep(PHASE_EVERY).await;
    }
}

/// Whether the login since [`begin`] reached its destination.
pub fn reached() -> bool {
    retry::phase() >= Phase::Ready
}

/// The class of a failure for `--result-file` (the relay's abnormal end
/// first, as [`crate::run::run_outcome`] gives it, else `class`), and its
/// lines, with the relay's end when it says more.
fn failed(message: &str, class: &'static str, opts: &Options, relay: Option<&RelayStatus>) -> Vec<String> {
    let end = relay.and_then(RelayStatus::get);
    match &end {
        Some(RelayEnd::Failed(_)) => crate::outcome::failure_is("relay"),
        Some(RelayEnd::Closed { code: Some(code), .. }) if *code != 1000 => crate::outcome::failure_is("relay"),
        _ => crate::outcome::failed(class),
    }
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let target = podssh_ws::dial::authority(&first.host, first.port);
    failure_lines(message, end.as_ref(), &target)
}
