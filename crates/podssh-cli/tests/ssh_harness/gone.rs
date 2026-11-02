//! A server that ends the connection right after the login (T-464, GitHub
//! #104): for a user `gone-...` it cuts the connection with no word when a
//! session channel is asked for; `gone-said-...` sends a DISCONNECT first,
//! as a gateway whose far host stopped; `gone-fwd-...` ends it so at a
//! `tcpip-forward` of `-R`. Neither answers the open or the request. A user
//! `nosession-...` refuses each session channel, administratively
//! prohibited. Each other user's session opens, and its `tcpip-forward` is
//! refused, as russh's server does by default.

use russh::server::{ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelOpenFailure, Disconnect};

use super::cut::Cut;

/// The words of the server's DISCONNECT.
pub const STOPPED: &str = "the far host stopped";

/// How a user's server ends after the login.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Gone {
    #[default]
    No,
    Cut,
    Said,
    AtForward,
    Refuses,
}

/// The way of `user`.
pub(super) fn of(user: &str) -> Gone {
    if user.starts_with("gone-said-") {
        Gone::Said
    } else if user.starts_with("gone-fwd-") {
        Gone::AtForward
    } else if user.starts_with("gone-") {
        Gone::Cut
    } else if user.starts_with("nosession-") {
        Gone::Refuses
    } else {
        Gone::No
    }
}

/// The open of a session channel: accepted, but for the users of `gone`.
pub(super) async fn open_session(
    gone: Gone,
    link: &Cut,
    channel: Channel<Msg>,
    reply: ChannelOpenHandle,
    session: &mut Session,
) -> Result<(), russh::Error> {
    match gone {
        Gone::Refuses => reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await,
        // The reply is held, unanswered, as the drop of it would refuse.
        Gone::Cut => {
            super::forward::never(channel, reply);
            link.now();
        }
        Gone::Said => {
            super::forward::never(channel, reply);
            session.disconnect(Disconnect::ByApplication, STOPPED, "en")?;
        }
        Gone::No | Gone::AtForward => reply.accept().await,
    }
    Ok(())
}

/// A `tcpip-forward` of `-R`: refused; for `gone-fwd-...`, the DISCONNECT
/// goes first, and the client reads nothing after it.
pub(super) fn forward(gone: Gone, session: &mut Session) -> Result<bool, russh::Error> {
    if gone == Gone::AtForward {
        session.disconnect(Disconnect::ByApplication, STOPPED, "en")?;
    }
    Ok(false)
}
