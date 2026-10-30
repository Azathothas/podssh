//! The control stream against bytes of the reference encoder
//! (`scripts/quick-fixtures.sh`), whole and in pieces.

use super::*;
use crate::quick::capnp::tests::registration;
use crate::quick::capnp::Builder;

const BOOTSTRAP_BYTES: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-bootstrap.bin");
const CALL_REGISTER: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-call-register.bin");
const CALL_UNREGISTER: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-call-unregister.bin");
const RETURN_DETAILS: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-return-details.bin");
const RETURN_EXCEPTION: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-return-exception.bin");
const RETURN_UNIMPLEMENTED: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-return-unimplemented.bin");
const ABORT: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-abort.bin");

/// A `Return` of `answer` with results whose content is not set: what the
/// edge answers to a bootstrap (a capability) or to a method with no results,
/// as far as this end reads it.
fn empty_return(answer: u32) -> Vec<u8> {
    let (mut b, root) = Builder::new(1, 1);
    b.set_u16(root, 0, 3);
    let ret = b.init_struct(root, 0, 2, 1);
    b.set_u32(ret, 0, answer);
    b.init_struct(ret, 0, 0, 2);
    b.frame()
}

fn details() -> Registered {
    let uuid = vec![0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0];
    Registered::Details { uuid, location: "msp01".into(), remotely_managed: false }
}

#[test]
fn the_registration_asks_for_the_bootstrap_and_calls_on_its_promise() {
    let (_, first) = Control::register(&registration());
    assert_eq!(first, [BOOTSTRAP_BYTES, CALL_REGISTER].concat());
}

#[test]
fn the_answers_register_the_connection_and_finish_the_question() {
    let (mut control, _) = Control::register(&registration());
    let (events, out) = control.feed(&empty_return(0)).unwrap();
    assert!(events.is_empty() && out.is_empty(), "the bootstrap's answer needs nothing");
    let (events, out) = control.feed(RETURN_DETAILS).unwrap();
    assert_eq!(events, vec![Event::Registered(details())]);
    assert_eq!(out, rpc::finish(1));
}

#[test]
fn a_frame_that_comes_one_byte_at_a_time_is_read_once_whole() {
    let (mut control, _) = Control::register(&registration());
    let bytes = [empty_return(0), RETURN_DETAILS.to_vec()].concat();
    let mut events = Vec::new();
    for byte in &bytes {
        events.extend(control.feed(std::slice::from_ref(byte)).unwrap().0);
    }
    assert_eq!(events, vec![Event::Registered(details())]);
}

#[test]
fn the_end_unregisters_on_the_same_capability_and_finishes_both_questions() {
    let (mut control, _) = Control::register(&registration());
    assert_eq!(control.unregister(), CALL_UNREGISTER);
    let (events, out) = control.feed(&empty_return(2)).unwrap();
    assert_eq!(events, vec![Event::Unregistered]);
    assert_eq!(out, [rpc::finish(2), rpc::finish(0)].concat());
}

#[test]
fn an_exception_or_an_abort_ends_the_stream_with_its_reason() {
    let (mut control, _) = Control::register(&registration());
    let failed = control.feed(RETURN_EXCEPTION).unwrap_err();
    assert_eq!(failed, Failure::Exception { question: 1, why: "the edge refused the call".into() });
    assert_eq!(failed.to_string(), "the edge refused the registration: the edge refused the call");
    let (mut control, _) = Control::register(&registration());
    assert_eq!(control.feed(ABORT).unwrap_err(), Failure::Aborted("the edge ends the connection".into()));
    let (mut control, _) = Control::register(&registration());
    assert!(matches!(control.feed(&[0xff, 0xff, 0, 0]), Err(Failure::Malformed(_))));
}

#[test]
fn a_question_of_the_edge_gets_an_exception_of_the_reference_encoder_s_bytes() {
    assert_eq!(rpc::unimplemented(7, "podssh exports no capability"), RETURN_UNIMPLEMENTED);
    let (mut control, _) = Control::register(&registration());
    // The edge's own bootstrap and call, as question 0 and 1 of its side.
    let (events, out) = control.feed(&[BOOTSTRAP_BYTES, CALL_REGISTER].concat()).unwrap();
    assert!(events.is_empty());
    let expected =
        [rpc::unimplemented(0, "podssh exports no capability"), rpc::unimplemented(1, "podssh exports no capability")];
    assert_eq!(out, expected.concat());
}
