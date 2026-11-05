//! The dialect of a node's or an operator's upgrade (T-643): its
//! `X-Podssh-Proto`, or none, which is the dialect of before. One that the
//! role does not read gets `426` with one sentence that names both and
//! whom to update, and the role's own dialect in `X-Podssh-Proto`, so that
//! the peer ends with words where it would else meet a frame that one side
//! drops. The role asks only once the pair's token passed, so that a peer
//! with no token learns nothing of it.

use podssh_ws::http::request::{self, Request};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::reverse::control::{self, PROTO, PROTO_HEADER};
use crate::serve::answer;

/// The sentence of an upgrade at `kind`'s path (`node` or `connect`) whose
/// dialect the role does not read; `None` for one that it reads.
pub fn unread(head: &Request, kind: &str) -> Option<String> {
    let peer = if kind == "node" { "the node" } else { "the operator" };
    let skew = control::accept_header(head.header(PROTO_HEADER)).err()?;
    Some(format!("reverse: {}", skew.sentence("the relay", peer)))
}

/// Answer `426` to an upgrade whose dialect the role does not read: true
/// when it did, and the request is over.
pub async fn refused<S>(stream: &mut S, head: &Request, kind: &str) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(why) = unread(head, kind) else { return false };
    let ours = PROTO.to_string();
    answer(stream, request::refusal(426, &why, &[(PROTO_HEADER, ours.as_str())])).await;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(proto: Option<&str>) -> Request {
        let stated = proto.map(|p| format!("X-Podssh-Proto: {p}\r\n")).unwrap_or_default();
        let text = format!("GET /v1/node/p-a HTTP/1.1\r\nHost: relay-a.test\r\n{stated}\r\n");
        request::parse_request(text.as_bytes()).expect("a head")
    }

    #[test]
    fn no_header_and_the_role_s_own_dialect_pass() {
        assert_eq!(unread(&head(None), "node"), None, "no header is the dialect of before");
        assert_eq!(unread(&head(Some("1")), "connect"), None);
    }

    #[test]
    fn another_dialect_names_both_and_whom_to_update() {
        let why = unread(&head(Some("2")), "node").expect("refused");
        assert!(why.starts_with("reverse: the node speaks the reverse road's dialect 2"), "{why}");
        assert!(why.contains(&format!("the relay reads dialect {PROTO}")), "{why}");
        assert!(why.ends_with(": update the relay"), "{why}");
        let why = unread(&head(Some("0")), "connect").expect("refused");
        assert!(why.starts_with("reverse: the operator speaks") && why.ends_with("update the operator"), "{why}");
        let why = unread(&head(Some("v2")), "connect").expect("refused");
        assert!(why.contains("dialect \"v2\"") && why.ends_with("update the relay or the operator"), "{why}");
    }
}
