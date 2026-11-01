//! An RPC stream of the edge against bytes of the reference encoder,
//! `capnp encode` of Cap'n Proto 1.0, with `rpc.capnp` of capnproto2 v2.18.0
//! and cloudflared's schema at 2026.10.6, the content typed
//! (`scripts/quick-fixtures.sh`). The push is that of cloudflared's own test,
//! `TestManageConfiguration` (`tunnelrpc/quic/request_server_stream_test.go`):
//! the version 168 and the rules `TestManageConfiguration`.

use super::*;
use crate::quick::capnp::Builder;
use crate::quick::rpc::Outcome;

const BOOTSTRAP: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-bootstrap.bin");
const PUSH: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-call-update-configuration.bin");
const PUSH_IMPORTED: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-call-update-configuration-imported.bin");
const UDP: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-call-unregister-udp-session.bin");
const RELEASE: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-release.bin");
const ABORT: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-abort.bin");
const PUSHED: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-return-update-configuration.bin");
const CAPABILITY: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-return-capability.bin");

const NOT_OURS: &str = "podssh exports one capability, at the bootstrap";
const NOT_A_PUSH: &str = "podssh serves a push of configuration here, and no UDP";

/// The answer to the bootstrap of question 0, as the reference encoder
/// wrote it, with the one word that its text form cannot write: the content,
/// the pointer of capability 0 of the table (the kind 3; Cap'n Proto's
/// encoding of an interface). It is word 6 of the segment, counted from 0:
/// after the root, the message's two words and the return's three.
fn capability_answer() -> Vec<u8> {
    let mut bytes = CAPABILITY.to_vec();
    assert_eq!(bytes[56..64], [0; 8], "the content, unset in the text form");
    bytes[56..64].copy_from_slice(&3u64.to_le_bytes());
    bytes
}

#[test]
fn the_answers_are_the_reference_encoder_s_bytes() {
    assert_eq!(rpc::capability(0, EXPORT), capability_answer());
    let message = Message::read(PUSH).unwrap();
    let Incoming::Call(call) = rpc::read(&message).unwrap() else { panic!("not a call") };
    assert_eq!((call.question, call.target, call.method), (1, Target::Promised(0), 0));
    assert_eq!(call.interface, configuration::CONFIGURATION_MANAGER);
    let params = call.params;
    assert_eq!(params.and_then(|p| p.get_data(0).ok().flatten()), Some(&b"TestManageConfiguration"[..]));
    let answer = rpc::results(1, configuration::RESULTS, |b, at| configuration::results(params, b, at));
    assert_eq!(answer, PUSHED);
}

#[test]
fn a_push_on_the_bootstrap_s_promise_gets_the_capability_then_its_version() {
    let mut stream = RpcStream::default();
    let out = stream.feed(&[BOOTSTRAP, PUSH].concat()).unwrap();
    assert_eq!(out, [capability_answer(), PUSHED.to_vec()].concat());
}

#[test]
fn a_push_on_the_capability_once_the_bootstrap_was_finished_gets_its_version() {
    let mut stream = RpcStream::default();
    assert_eq!(stream.feed(BOOTSTRAP).unwrap(), capability_answer());
    assert!(stream.feed(&rpc::finish(0)).unwrap().is_empty(), "a finish needs no answer");
    assert_eq!(stream.feed(PUSH_IMPORTED).unwrap(), PUSHED);
    // The promise of a bootstrap that the edge finished is no capability.
    assert_eq!(stream.feed(PUSH).unwrap(), rpc::unimplemented(1, NOT_OURS));
}

#[test]
fn a_push_with_no_bootstrap_before_it_is_on_no_capability_of_podssh_s() {
    let mut stream = RpcStream::default();
    assert_eq!(stream.feed(PUSH).unwrap(), rpc::unimplemented(1, NOT_OURS));
}

#[test]
fn another_method_gets_an_exception_and_a_release_nothing() {
    let mut stream = RpcStream::default();
    stream.feed(BOOTSTRAP).unwrap();
    let refused = stream.feed(UDP).unwrap();
    assert_eq!(refused, rpc::unimplemented(2, NOT_A_PUSH));
    let message = Message::read(&refused).unwrap();
    let Incoming::Return { answer: 2, outcome: Outcome::Exception(_) } = rpc::read(&message).unwrap() else {
        panic!("not an exception to question 2")
    };
    assert!(stream.feed(RELEASE).unwrap().is_empty());
}

#[test]
fn frames_that_come_one_byte_at_a_time_are_answered_once_whole() {
    let mut stream = RpcStream::default();
    let mut out = Vec::new();
    for byte in [BOOTSTRAP, PUSH].concat() {
        out.extend(stream.feed(&[byte]).unwrap());
    }
    assert_eq!(out, [capability_answer(), PUSHED.to_vec()].concat());
}

/// The version is the push's own, a negative one too; parameters with no
/// version, as a shorter struct, read as Go's zero.
#[test]
fn the_version_is_the_push_s_and_none_reads_as_zero() {
    let push = |version: Option<i32>| {
        let size = if version.is_some() { (1, 1) } else { (0, 0) };
        let (manager, method) = (configuration::CONFIGURATION_MANAGER, configuration::UPDATE_CONFIGURATION);
        rpc::call(1, 0, manager, method, size, |b, at| {
            if let Some(version) = version {
                b.set_u32(at, 0, version as u32);
                b.set_data(at, 0, b"{}");
            }
        })
    };
    for (version, applied) in [(Some(7), 7), (Some(-3), -3), (None, 0)] {
        let mut stream = RpcStream::default();
        let out = stream.feed(&[BOOTSTRAP, &push(version)[..]].concat()).unwrap();
        let message = Message::read(&out[capability_answer().len()..]).unwrap();
        let Incoming::Return { answer: 1, outcome: Outcome::Results(payload) } = rpc::read(&message).unwrap() else {
            panic!("no results for {version:?}")
        };
        let response = rpc::content(payload).unwrap().get_struct(0).unwrap().expect("the response");
        assert_eq!(response.u32(0) as i32, applied, "{version:?}");
        assert_eq!(response.get_text(0).unwrap(), None, "no err");
    }
}

#[test]
fn an_abort_a_message_that_does_not_read_and_one_past_a_push_end_the_stream() {
    let mut stream = RpcStream::default();
    assert_eq!(stream.feed(ABORT).unwrap_err(), Failure::Aborted("the edge ends the connection".into()));
    let mut stream = RpcStream::default();
    assert!(matches!(stream.feed(&[0xff, 0xff, 0, 0]), Err(Failure::Malformed(_))));
    // A frame that holds more than a push: refused as its bytes come.
    let (mut b, root) = Builder::new(0, 1);
    b.set_data(root, 0, &vec![0u8; configuration::MAX_PUSH + 64 * 1024]);
    let mut stream = RpcStream::default();
    assert!(matches!(stream.feed(&b.frame()), Err(Failure::Malformed(_))));
}
