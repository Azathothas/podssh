//! What a Close carries: its payload, written and read, and what the relay's
//! Close of a forward session means (out of `session.rs`, at its 500 lines).

use crate::frame;

/// A Close payload: the code (big-endian), then a reason cut to fit the
/// 125-byte control-frame limit on a character boundary.
pub fn close_payload(code: Option<u16>, reason: &str) -> Vec<u8> {
    let Some(code) = code else { return Vec::new() };
    let mut out = code.to_be_bytes().to_vec();
    let mut end = reason.len().min(frame::MAX_CONTROL_PAYLOAD - 2);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    out.extend_from_slice(&reason.as_bytes()[..end]);
    out
}

/// The status code and reason of a received Close frame's payload.
pub fn close_code_and_reason(payload: &[u8]) -> (Option<u16>, String) {
    if payload.len() < 2 {
        return (None, String::new());
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    // The reason is the peer's text and is printed to the user's terminal.
    (Some(code), crate::text::one_line(&String::from_utf8_lossy(&payload[2..])))
}

/// The part of a forward session that a Close of the relay names, by its
/// code and reason (the relay's own words; `docs/relay.md`, "Errors and
/// close codes"). `podssh ssh` and `podssh proxy` both use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardClose {
    /// 1000: the target or the client ended the session.
    Normal,
    /// A limit of the relay: 1001 (idle, session time) or 1009 (bytes, frame).
    Limit,
    /// The relay's connection to the target failed or broke.
    Target,
    /// The connection between podssh and the relay broke; also no Close.
    Client,
    /// A code or a reason that the relay's table does not list.
    Unknown,
}

/// Classify a Close of the forward path; `None` is a connection that ended
/// with no Close.
pub fn forward_close(code: Option<u16>, reason: &str) -> ForwardClose {
    const TARGET: [&str; 4] =
        ["connect failed", "target closed before sending anything", "wrong target banner", "write failed"];
    match code {
        None => ForwardClose::Client,
        Some(1000) => ForwardClose::Normal,
        Some(1001 | 1009) => ForwardClose::Limit,
        Some(1011) if TARGET.iter().any(|t| reason.starts_with(t)) => ForwardClose::Target,
        Some(1011) if reason.starts_with("client send failed") || reason.starts_with("client error") => {
            ForwardClose::Client
        }
        Some(1013) if reason.starts_with("target write backlog") => ForwardClose::Target,
        Some(1013) if reason.starts_with("client receive backlog") => ForwardClose::Client,
        Some(_) => ForwardClose::Unknown,
    }
}

impl ForwardClose {
    /// What broke, in words: `target` is the `host:port` that the relay dials.
    pub fn what(self, target: &str) -> String {
        match self {
            ForwardClose::Normal => format!("{target} ended the connection"),
            ForwardClose::Limit => "the relay ended the session at one of its limits".into(),
            ForwardClose::Target => format!("the relay lost its connection to {target}"),
            ForwardClose::Client => "the connection between podssh and the relay broke".into(),
            ForwardClose::Unknown => "the relay closed the session".into(),
        }
    }

    /// What may help, when something may. The limits are the relay's
    /// (`/relays.json`, measured 2026-10-08): 180 s idle, 64 MiB, 12 h.
    pub fn remedy(self, reason: &str) -> Option<&'static str> {
        match self {
            ForwardClose::Target => Some("another relay host may reach it: --relay-host HOST"),
            // The link held; what crossed it came too slowly for the relay.
            ForwardClose::Client if reason.starts_with("client receive backlog") => Some(
                "the relay closes a session when 2 MiB wait for podssh: the link to the relay, or the reader of \
                 podssh's output, is slower than the target",
            ),
            ForwardClose::Client => Some("podssh doctor checks the way to the relay"),
            ForwardClose::Limit if reason.contains("idle") => {
                Some("the relay closes a session after 180 s with no traffic; set ServerAliveInterval below 180")
            }
            ForwardClose::Limit if reason.contains("byte cap") => {
                Some("a session carries 64 MiB at most through the relay; use a new session for more")
            }
            ForwardClose::Limit if reason.contains("time cap") => {
                Some("a session lasts 12 h at most through the relay; connect again")
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod forward_close_tests {
    use super::*;

    /// One case for each row of the relay's table, and an unknown code.
    #[test]
    fn forward_close_names_the_hop_for_each_row() {
        let cases = [
            (Some(1000), "target closed", ForwardClose::Normal),
            (Some(1001), "idle timeout", ForwardClose::Limit),
            (Some(1001), "session time cap", ForwardClose::Limit),
            (Some(1009), "session byte cap", ForwardClose::Limit),
            (Some(1009), "frame larger than 262144 bytes", ForwardClose::Limit),
            (Some(1011), "connect failed: refused", ForwardClose::Target),
            (Some(1011), "target closed before sending anything", ForwardClose::Target),
            (Some(1011), "wrong target banner SSH-1.5", ForwardClose::Target),
            (Some(1011), "write failed: Network connection lost.", ForwardClose::Target),
            (Some(1011), "client send failed: reset", ForwardClose::Client),
            (Some(1011), "client error", ForwardClose::Client),
            (Some(1013), "target write backlog", ForwardClose::Target),
            (Some(1013), "client receive backlog", ForwardClose::Client),
            (None, "", ForwardClose::Client),
            (Some(4321), "something new", ForwardClose::Unknown),
            (Some(1011), "a reason the table does not list", ForwardClose::Unknown),
        ];
        for (code, reason, want) in cases {
            assert_eq!(forward_close(code, reason), want, "{code:?} {reason}");
        }
        assert_eq!(ForwardClose::Target.what("railway.new:22"), "the relay lost its connection to railway.new:22");
        assert!(ForwardClose::Limit.remedy("idle timeout").unwrap().contains("ServerAliveInterval"));
        assert!(ForwardClose::Unknown.remedy("x").is_none());
        assert!(ForwardClose::Client.remedy("client receive backlog").unwrap().contains("2 MiB wait for podssh"));
        assert!(ForwardClose::Client.remedy("client send failed: reset").unwrap().contains("doctor"));
    }
}
