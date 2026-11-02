//! Replies to global requests with data after their type, as a server of
//! Go's x/crypto/ssh sends them (`Request.Reply(ok, payload)`): each leaves
//! the session up and gives the caller its answer, where each ended the
//! whole connection with `TrailingData` before.
#![allow(clippy::unwrap_used)] // as in the test suite

use ssh_encoding::Encode;
use tokio::sync::oneshot;

use super::tests::{TestHandler, keyboard_interactive_session};
use crate::msg;
use crate::session::EncryptedState;

/// The 15 bytes after a server's failure that podssh's GitHub #83 met.
const DATA: &[u8] = b"unknown request";

/// The words after a refused `tcpip-forward` of a gliderlabs/ssh server.
const REFUSED: &[u8] = b"port forwarding is disabled";

fn reply(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![kind];
    packet.extend_from_slice(data);
    packet
}

/// The session's state after the login, where the replies come.
fn logged_in(session: &mut super::Session) {
    session.common.encrypted.as_mut().unwrap().state = EncryptedState::Authenticated;
}

#[tokio::test]
async fn a_failure_with_data_after_a_keepalive_leaves_the_session_up() {
    let (mut session, _sender, _replies) = keyboard_interactive_session();
    logged_in(&mut session);
    session.send_keepalive(true).unwrap();
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_FAILURE, DATA))
        .await
        .unwrap();
    assert!(session.open_global_requests.is_empty());
    // The next reply answers the next request, as the order of the replies
    // is the order of the requests (RFC 4254, section 4).
    let (pong, mut answered) = oneshot::channel();
    session.send_ping(pong).unwrap();
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_FAILURE, b""))
        .await
        .unwrap();
    assert!(matches!(answered.try_recv(), Ok(())));
}

#[tokio::test]
async fn a_success_with_data_after_a_keepalive_or_a_ping_answers_it() {
    let (mut session, _sender, _replies) = keyboard_interactive_session();
    logged_in(&mut session);
    session.send_keepalive(true).unwrap();
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_SUCCESS, DATA))
        .await
        .unwrap();
    let (pong, mut answered) = oneshot::channel();
    session.send_ping(pong).unwrap();
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_SUCCESS, DATA))
        .await
        .unwrap();
    assert!(matches!(answered.try_recv(), Ok(())));
    assert!(session.open_global_requests.is_empty());
}

#[tokio::test]
async fn a_failure_with_words_after_tcpip_forward_is_a_refusal() {
    let (mut session, _sender, _replies) = keyboard_interactive_session();
    logged_in(&mut session);
    let (tx, mut answer) = oneshot::channel();
    session.tcpip_forward(Some(tx), "127.0.0.1", 12345).unwrap();
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_FAILURE, REFUSED))
        .await
        .unwrap();
    assert!(matches!(answer.try_recv(), Ok(None)));
    // A cancel that the server took, with data, is taken too.
    let (tx, mut cancelled) = oneshot::channel();
    session.cancel_tcpip_forward(Some(tx), "127.0.0.1", 12345).unwrap();
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_SUCCESS, DATA))
        .await
        .unwrap();
    assert!(matches!(cancelled.try_recv(), Ok(true)));
}

#[tokio::test]
async fn a_success_of_tcpip_forward_gives_its_port_and_drops_the_rest() {
    let (mut session, _sender, _replies) = keyboard_interactive_session();
    logged_in(&mut session);
    let (tx, mut answer) = oneshot::channel();
    session.tcpip_forward(Some(tx), "127.0.0.1", 0).unwrap();
    let mut data = Vec::new();
    40_000u32.encode(&mut data).unwrap();
    data.extend_from_slice(DATA);
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_SUCCESS, &data))
        .await
        .unwrap();
    assert!(matches!(answer.try_recv(), Ok(Some(40_000))));
}

/// The control: replies with no data are read as before.
#[tokio::test]
async fn replies_with_no_data_are_read_as_before() {
    let (mut session, _sender, _replies) = keyboard_interactive_session();
    logged_in(&mut session);
    let (tx, mut answer) = oneshot::channel();
    session.tcpip_forward(Some(tx), "127.0.0.1", 12345).unwrap();
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_SUCCESS, b""))
        .await
        .unwrap();
    assert!(matches!(answer.try_recv(), Ok(Some(0))));
    let (pong, mut answered) = oneshot::channel();
    session.send_ping(pong).unwrap();
    session
        .process_packet(&mut TestHandler, &reply(msg::REQUEST_FAILURE, b""))
        .await
        .unwrap();
    assert!(matches!(answered.try_recv(), Ok(())));
}
