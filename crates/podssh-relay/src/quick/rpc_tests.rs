//! The RPC's messages against bytes of the reference encoder, `capnp encode`
//! of Cap'n Proto 1.0, with `rpc.capnp` of capnproto2 v2.18.0, its content
//! typed (`scripts/quick-fixtures.sh`).

use super::*;
use crate::quick::capnp::tests::registration;
use crate::quick::register::{read_results, Registered, REGISTER_CONNECTION, REGISTER_PARAMS, REGISTRATION_SERVER};

const BOOTSTRAP: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-bootstrap.bin");
const CALL_REGISTER: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-call-register.bin");
const FINISH: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-finish.bin");
const RETURN_DETAILS: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-return-details.bin");
const RETURN_EXCEPTION: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-return-exception.bin");
const ABORT: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-abort.bin");

#[test]
fn bootstrap_call_and_finish_are_the_reference_encoder_s_bytes() {
    assert_eq!(bootstrap(0), BOOTSTRAP);
    let call = call(1, 0, REGISTRATION_SERVER, REGISTER_CONNECTION, REGISTER_PARAMS, |b, params| {
        registration().write(b, params)
    });
    assert_eq!(call, CALL_REGISTER);
    assert_eq!(finish(1), FINISH);
}

#[test]
fn a_return_with_results_reads_as_the_registration_s_answer() {
    let message = Message::read(RETURN_DETAILS).unwrap();
    let Incoming::Return { answer, outcome: Outcome::Results(payload) } = read(&message).unwrap() else {
        panic!("not results")
    };
    assert_eq!(answer, 1);
    let Registered::Details { location, .. } = read_results(content(payload).unwrap()).unwrap() else {
        panic!("not details")
    };
    assert_eq!(location, "msp01");
}

#[test]
fn an_exception_and_an_abort_give_their_reasons() {
    let message = Message::read(RETURN_EXCEPTION).unwrap();
    let Incoming::Return { answer: 1, outcome: Outcome::Exception(why) } = read(&message).unwrap() else {
        panic!("not an exception")
    };
    assert_eq!(why, "the edge refused the call");
    let message = Message::read(ABORT).unwrap();
    let Incoming::Abort(why) = read(&message).unwrap() else { panic!("not an abort") };
    assert_eq!(why, "the edge ends the connection");
    // Another kind of message is named, not read.
    assert!(matches!(read(&Message::read(&finish(3)).unwrap()).unwrap(), Incoming::Other(4)));
}
