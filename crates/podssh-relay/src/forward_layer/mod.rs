//! The forward road with the resumable layer at podssh's relay role (T-173):
//! a session to a standard sshd that outlives a drop of the client's link.
//! The contract's `/connect/` ends the target's connection with its
//! WebSocket; the role's `/v1/layer/HOST/PORT` (`crate::serve`, feature
//! `serve`) is the far end of the layer (`crate::session`) instead, and holds
//! the connection to the target while a link is lost, until the client
//! resumes the session on a new link to the same host, or the layer's
//! deadline passes.
//!
//! - [`offer`]: whether a host offers it, by its `/relays.json`, read at run
//!   time, as nothing is assumed of a relay, and the name of the process
//!   that holds each session of it, where several share one name;
//! - [`client`]: the links of one session to the host that holds it, and the
//!   session across them.
//!
//! The layer's secret stays in memory: each resume proves it in the layer's
//! records, and the path names only the target, as `/connect/` does.

pub mod client;
pub mod offer;

pub use client::{carry, no_room, Dialer, Missed};
pub use offer::{offered, Offer};

/// The head of the path; the target follows it as on `/connect/`.
pub const PATH: &str = "/v1/layer/";

/// The path of a session to `host:port`, `/v1/layer/<host>/<port>`, by the
/// rules of the forward path: nothing that a user types can add a segment,
/// a query or a header to it.
pub fn path(host: &str, port: u16) -> Result<String, String> {
    let forward = crate::relay::forward_path(host, port)?;
    let target = forward.strip_prefix("/connect/").unwrap_or(&forward);
    Ok(format!("{PATH}{target}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_names_the_target_as_the_forward_path_does() {
        assert_eq!(path("github.com", 22).unwrap(), "/v1/layer/github.com/22");
        assert_eq!(path("2001:db8::1", 22).unwrap(), "/v1/layer/2001:db8::1/22");
        for (host, port) in [("a/b", 22), ("a?b=1", 22), ("host", 0), ("", 22)] {
            assert!(path(host, port).is_err(), "{host}:{port}");
        }
    }
}
