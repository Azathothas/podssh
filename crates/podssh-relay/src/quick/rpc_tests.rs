//! The RPC's messages against bytes of the reference encoder, `capnp encode`
//! of Cap'n Proto 1.0, with `rpc.capnp` of capnproto2 v2.18.0, its content
//! typed (`scripts/quick-fixtures.sh`).

use super::*;
use crate::quick::capnp::tests::registration;
use crate::quick::register::{read_results, Registered, REGISTER_CONNECTION, REGISTER_PARAMS, REGISTRATION_SERVER};

const BOOTSTRAP: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-bootstrap.bin");
const CALL_REGISTER: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-call-register.bin");
const CALL_IMPORTED: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-call-update-configuration-imported.bin");
const RELEASE: &[u8] = include_bytes!("../../tests/fixtures/quick/rpc-release.bin");
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
    // A finish names its question (T-411); another kind of message, as a
    // release, is named, not read.
    assert!(matches!(read(&Message::read(&finish(3)).unwrap()).unwrap(), Incoming::Finish(3)));
    assert!(matches!(read(&Message::read(RELEASE).unwrap()).unwrap(), Incoming::Other(6)));
}

/// The other end's questions, as a server reads them (T-411): a bootstrap,
/// and a call with its target, its interface, its method and its
/// parameters, on the promise of the bootstrap or on the capability.
#[test]
fn a_bootstrap_and_a_call_read_as_the_server_needs_them() {
    let message = Message::read(BOOTSTRAP).unwrap();
    assert!(matches!(read(&message).unwrap(), Incoming::Bootstrap(0)));
    let message = Message::read(CALL_REGISTER).unwrap();
    let Incoming::Call(call) = read(&message).unwrap() else { panic!("not a call") };
    assert_eq!((call.question, call.target), (1, Target::Promised(0)));
    assert_eq!((call.interface, call.method), (REGISTRATION_SERVER, REGISTER_CONNECTION));
    let params = call.params.expect("the parameters");
    assert_eq!(params.get_data(1).unwrap().map(<[u8]>::len), Some(16), "the tunnel's id");
    let message = Message::read(CALL_IMPORTED).unwrap();
    let Incoming::Call(call) = read(&message).unwrap() else { panic!("not a call") };
    assert_eq!((call.question, call.target, call.method), (1, Target::Imported(0), 0));
    // A promise with a transform reaches into an answer: no capability.
    let (mut b, root) = Builder::new(1, 1);
    b.set_u16(root, 0, 2);
    let call = b.init_struct(root, 0, 3, 3);
    let target = b.init_struct(call, 0, 1, 1);
    b.set_u16(target, 4, 1);
    let promised = b.init_struct(target, 0, 1, 1);
    let ops = b.init_struct_list(promised, 0, 1, 1, 0);
    b.set_u16(ops[0], 0, 1);
    let frame = b.frame();
    let message = Message::read(&frame).unwrap();
    let Incoming::Call(call) = read(&message).unwrap() else { panic!("not a call") };
    assert_eq!(call.target, Target::Other);
}

/// The other end's reason, with ESC, BEL and a CR, reads as one line with
/// none of them (T-401).
#[test]
fn a_reason_reads_with_no_control_character() {
    let frame = unimplemented(7, "gone\x1b]0;x\x07\r\nnow");
    let message = Message::read(&frame).unwrap();
    let Incoming::Return { answer: 7, outcome: Outcome::Exception(why) } = read(&message).unwrap() else {
        panic!("not an exception")
    };
    assert_eq!(why, "gone]0;x now");
}
