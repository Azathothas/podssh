//! The handshake of the resumable layer (T-151).
//!
//! The keys are those of RFC 7748, section 6.1 (Alice is the client, Bob the
//! far end), and the nonces and the id are fixed runs of bytes. The secret
//! and the proofs that they must give were computed apart from podssh: an
//! X25519 written from the RFC's pseudo-code and checked against its
//! vectors, and HKDF and HMAC from Python's standard library. Then the
//! refusals: a wrong secret, a replayed `PROOF`, an unknown session.

use std::collections::VecDeque;

use podssh_relay::session::secret::KEY_LEN;
use podssh_relay::session::{
    Acceptance, Ask, ClientHandshake, Entropy, FarHandshake, HandshakeError, NoRandom, Opening, Proof, Record,
    RefuseCode, Role, Secret, SessionId, Sessions, Step,
};

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}

fn run_of(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start + i as u8).collect()
}

const ALICE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
/// HKDF-SHA256(salt = far nonce 00..1f and client nonce 20..3f, input = the
/// X25519 value of RFC 7748, info = "podssh-session v1 secret", 0, the id
/// 40..4f, Alice's and Bob's public keys).
const SECRET: &str = "8a41f649f2368978f6347123774594ddaf044033837b7f0bd30736f923318998";
/// HMAC-SHA256 under SECRET of "podssh-session v1 client proof", 0, the id,
/// the far nonce 80..9f, the client nonce a0..bf and the offset 1000.
const CLIENT_PROOF: &str = "44f2167e46064b4dbb88c717034770a0cbef195b22489be9ff70e235297b0958";
/// The same with "podssh-session v1 far proof" and the offset 2000.
const FAR_PROOF: &str = "3faedde01956c848d852d53cc0af0586490e10aa662ffd36dc4fcbb428fc88eb";

/// A planted source that gives these draws in order, and then none.
struct Script(VecDeque<Vec<u8>>);

impl Script {
    fn new(draws: &[Vec<u8>]) -> Script {
        Script(draws.iter().cloned().collect())
    }
}

impl Entropy for Script {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), NoRandom> {
        let draw = self.0.pop_front().ok_or(NoRandom)?;
        assert_eq!(draw.len(), buf.len(), "a draw of another length");
        buf.copy_from_slice(&draw);
        Ok(())
    }
}

fn id() -> SessionId {
    SessionId(run_of(0x40, 16).try_into().unwrap())
}

fn secret() -> Secret {
    Secret::from_bytes(hex(SECRET).try_into().unwrap())
}

/// A far end that keeps the session of the vectors, with 2000 bytes
/// received; its next link has the nonce 80..9f.
fn far_with_the_session() -> (Sessions, FarHandshake, Record) {
    let mut sessions = Sessions::new();
    let (mut far, greeting) = FarHandshake::start(Role::NODE, &[], &mut Script::new(&[run_of(0x00, 32)])).unwrap();
    let (mut client, open) =
        ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32), hex(ALICE)])).unwrap();
    client.handle(greeting).unwrap();
    let mut entropy = Script::new(&[hex(BOB), run_of(0x40, 16)]);
    far.handle(open, &mut sessions, &mut entropy).unwrap();
    sessions.set_received(&id(), 2000);
    let (far, greeting) = FarHandshake::start(Role::NODE, &[], &mut Script::new(&[run_of(0x80, 32)])).unwrap();
    (sessions, far, greeting)
}

#[test]
fn a_new_session_gives_both_ends_the_secret_of_the_vectors() {
    let mut sessions = Sessions::new();
    let (mut far, greeting) =
        FarHandshake::start(Role::NODE, &["replay.v1", "x.v9"], &mut Script::new(&[run_of(0x00, 32)])).unwrap();
    let (mut client, open) = ClientHandshake::start(
        Ask::New,
        &["heartbeat.v1", "replay.v1"],
        &mut Script::new(&[run_of(0x20, 32), hex(ALICE)]),
    )
    .unwrap();
    // x25519-dalek's public key is that of the RFC.
    let Record::Open { opening: Opening::New { public }, .. } = &open else { panic!("{open:?}") };
    assert_eq!(public.to_vec(), hex(ALICE_PUBLIC));

    assert!(matches!(client.handle(greeting).unwrap(), Step::Wait));
    let mut entropy = Script::new(&[hex(BOB), run_of(0x40, 16)]);
    let Step::Established(Some(accept), at_far) = far.handle(open, &mut sessions, &mut entropy).unwrap() else {
        panic!("the far end did not accept")
    };
    assert_eq!(accept, Record::Accept(Acceptance::New { id: id(), public: hex(BOB_PUBLIC).try_into().unwrap() }));
    assert_eq!(at_far.secret.bytes().to_vec(), hex(SECRET));
    assert_eq!(at_far.features, vec!["replay.v1".to_string()]);
    assert!(sessions.contains(&id()));

    let Step::Established(None, at_client) = client.handle(accept).unwrap() else { panic!("no session") };
    assert_eq!(at_client.id, id());
    assert_eq!(at_client.secret.bytes().to_vec(), hex(SECRET));
    assert_eq!((at_client.received, at_client.peer_received, at_client.resumed), (0, 0, false));
    assert_eq!(at_client.peer_role, Role::NODE);
    assert_eq!(at_client.features, vec!["replay.v1".to_string()]);
}

#[test]
fn a_resume_proves_the_secret_both_ways_with_the_proofs_of_the_vectors() {
    let (mut sessions, mut far, greeting) = far_with_the_session();
    let ask = Ask::Resume { id: id(), secret: secret(), received: 1000 };
    let (mut client, open) = ClientHandshake::start(ask, &[], &mut Script::new(&[run_of(0xa0, 32)])).unwrap();
    assert!(matches!(far.handle(open, &mut sessions, &mut Script::new(&[])).unwrap(), Step::Wait));

    let Step::Send(proof) = client.handle(greeting).unwrap() else { panic!("no PROOF") };
    assert_eq!(proof, Record::Proof { offset: 1000, proof: Proof(hex(CLIENT_PROOF).try_into().unwrap()) });

    let Step::Established(Some(accept), at_far) = far.handle(proof, &mut sessions, &mut Script::new(&[])).unwrap()
    else {
        panic!("the far end did not accept the resume")
    };
    assert_eq!(
        accept,
        Record::Accept(Acceptance::Resume { offset: 2000, proof: Proof(hex(FAR_PROOF).try_into().unwrap()) })
    );
    assert_eq!((at_far.received, at_far.peer_received, at_far.resumed), (2000, 1000, true));

    let Step::Established(None, at_client) = client.handle(accept).unwrap() else { panic!("no session") };
    assert_eq!((at_client.received, at_client.peer_received, at_client.resumed), (1000, 2000, true));
    assert_eq!(at_client.secret.bytes().to_vec(), hex(SECRET));
}

fn refused(step: Step) -> (RefuseCode, HandshakeError) {
    match step {
        Step::Refuse(Record::Refuse { code, .. }, error) => (code, error),
        other => panic!("not refused: {other:?}"),
    }
}

#[test]
fn a_wrong_secret_is_refused() {
    let (mut sessions, mut far, greeting) = far_with_the_session();
    let ask = Ask::Resume { id: id(), secret: Secret::from_bytes([0x11; KEY_LEN]), received: 1000 };
    let (mut client, open) = ClientHandshake::start(ask, &[], &mut Script::new(&[run_of(0xa0, 32)])).unwrap();
    far.handle(open, &mut sessions, &mut Script::new(&[])).unwrap();
    let Step::Send(proof) = client.handle(greeting).unwrap() else { panic!() };
    let step = far.handle(proof, &mut sessions, &mut Script::new(&[])).unwrap();
    assert_eq!(refused(step), (RefuseCode::BAD_PROOF, HandshakeError::BadProof));
}

/// A relay that keeps the `OPEN` and the `PROOF` of one link and plays them
/// on the next gets nothing: the next link greets with a new nonce.
#[test]
fn a_replayed_proof_is_refused() {
    let (mut sessions, mut far, greeting) = far_with_the_session();
    let ask = Ask::Resume { id: id(), secret: secret(), received: 1000 };
    let (mut client, open) = ClientHandshake::start(ask, &[], &mut Script::new(&[run_of(0xa0, 32)])).unwrap();
    far.handle(open.clone(), &mut sessions, &mut Script::new(&[])).unwrap();
    let Step::Send(proof) = client.handle(greeting).unwrap() else { panic!() };
    assert!(matches!(far.handle(proof.clone(), &mut sessions, &mut Script::new(&[])).unwrap(), Step::Established(..)));

    let (mut next, _greeting) = FarHandshake::start(Role::NODE, &[], &mut Script::new(&[run_of(0xc0, 32)])).unwrap();
    assert!(matches!(next.handle(open, &mut sessions, &mut Script::new(&[])).unwrap(), Step::Wait));
    let step = next.handle(proof, &mut sessions, &mut Script::new(&[])).unwrap();
    assert_eq!(refused(step), (RefuseCode::BAD_PROOF, HandshakeError::BadProof));
}

#[test]
fn an_unknown_session_is_refused() {
    let (mut sessions, mut far, _greeting) = far_with_the_session();
    let ask = Ask::Resume { id: SessionId([0x99; 16]), secret: secret(), received: 0 };
    let (_client, open) = ClientHandshake::start(ask, &[], &mut Script::new(&[run_of(0xa0, 32)])).unwrap();
    let (code, _) = refused(far.handle(open, &mut sessions, &mut Script::new(&[])).unwrap());
    assert_eq!(code, RefuseCode::UNKNOWN_SESSION);
}

/// A session that the far end forgot (its deadline passed) is unknown too.
#[test]
fn a_removed_session_is_unknown() {
    let (mut sessions, mut far, _greeting) = far_with_the_session();
    assert!(sessions.remove(&id()));
    let ask = Ask::Resume { id: id(), secret: secret(), received: 0 };
    let (_client, open) = ClientHandshake::start(ask, &[], &mut Script::new(&[run_of(0xa0, 32)])).unwrap();
    let (code, _) = refused(far.handle(open, &mut sessions, &mut Script::new(&[])).unwrap());
    assert_eq!(code, RefuseCode::UNKNOWN_SESSION);
}

/// The client checks the far end too: a far end that does not have the
/// secret cannot make the proof of its `ACCEPT`.
#[test]
fn the_client_refuses_a_far_end_that_does_not_prove_the_secret() {
    let (_sessions, _far, greeting) = far_with_the_session();
    let ask = Ask::Resume { id: id(), secret: secret(), received: 1000 };
    let (mut client, _open) = ClientHandshake::start(ask, &[], &mut Script::new(&[run_of(0xa0, 32)])).unwrap();
    client.handle(greeting).unwrap();
    // The client's own proof, sent back as the far end's: each side has its
    // own label, so a reflection fails.
    let reflected =
        Record::Accept(Acceptance::Resume { offset: 1000, proof: Proof(hex(CLIENT_PROOF).try_into().unwrap()) });
    assert_eq!(client.handle(reflected).unwrap_err(), HandshakeError::BadProof);
}

/// A public key of low order gives the same value for each secret: both
/// ends refuse it (RFC 7748, section 6.1).
#[test]
fn a_public_key_of_low_order_is_refused() {
    let mut sessions = Sessions::new();
    let (mut far, greeting) = FarHandshake::start(Role::NODE, &[], &mut Script::new(&[run_of(0, 32)])).unwrap();
    let (mut client, open) =
        ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32), hex(ALICE)])).unwrap();
    let Record::Open { hello, .. } = open else { panic!() };
    let weak = Record::Open { hello, opening: Opening::New { public: [0; 32] } };
    let step = far.handle(weak, &mut sessions, &mut Script::new(&[hex(BOB), run_of(0x40, 16)])).unwrap();
    assert_eq!(refused(step), (RefuseCode::PROTOCOL, HandshakeError::WeakKey));
    assert!(sessions.is_empty());

    client.handle(greeting).unwrap();
    let accept = Record::Accept(Acceptance::New { id: id(), public: [0; 32] });
    assert_eq!(client.handle(accept).unwrap_err(), HandshakeError::WeakKey);
}

/// A source that gives no bytes is an error at each step, never a panic.
#[test]
fn no_random_bytes_is_an_error() {
    assert!(matches!(FarHandshake::start(Role::NODE, &[], &mut Script::new(&[])), Err(HandshakeError::NoRandom)));
    assert!(matches!(ClientHandshake::start(Ask::New, &[], &mut Script::new(&[])), Err(HandshakeError::NoRandom)));
    assert!(matches!(
        ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32)])),
        Err(HandshakeError::NoRandom)
    ));
    let mut sessions = Sessions::new();
    let (mut far, _) = FarHandshake::start(Role::NODE, &[], &mut Script::new(&[run_of(0, 32)])).unwrap();
    let (_, open) = ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32), hex(ALICE)])).unwrap();
    assert_eq!(far.handle(open, &mut sessions, &mut Script::new(&[hex(BOB)])).unwrap_err(), HandshakeError::NoRandom);
    assert!(sessions.is_empty());
}

#[test]
fn versions_and_roles_that_cannot_be_are_refused() {
    let (_, open) = ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32), hex(ALICE)])).unwrap();
    let Record::Open { hello, opening } = open else { panic!() };
    let mut sessions = Sessions::new();
    let far = || FarHandshake::start(Role::NODE, &[], &mut Script::new(&[run_of(0, 32)])).unwrap();

    let mut v0 = hello.clone();
    v0.version = 0;
    let (mut f, _) = far();
    let step = f.handle(Record::Open { hello: v0, opening: opening.clone() }, &mut sessions, &mut Script::new(&[]));
    assert_eq!(refused(step.unwrap()).0, RefuseCode::VERSION);

    let mut node = hello.clone();
    node.role = Role::NODE;
    let (mut f, _) = far();
    let step = f.handle(Record::Open { hello: node, opening: opening.clone() }, &mut sessions, &mut Script::new(&[]));
    assert_eq!(refused(step.unwrap()).0, RefuseCode::ROLE);

    // A far end of a later version is spoken to in version 1; one that says
    // it is a client is not a far end.
    let (_, greeting) = far();
    let Record::Greeting(mut far_hello) = greeting else { panic!() };
    far_hello.role = Role::CLIENT;
    let (mut client, _) =
        ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32), hex(ALICE)])).unwrap();
    assert_eq!(client.handle(Record::Greeting(far_hello.clone())).unwrap_err(), HandshakeError::Role(Role::CLIENT));
    far_hello.role = Role(9);
    far_hello.version = 7;
    let (mut client, _) =
        ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32), hex(ALICE)])).unwrap();
    assert!(matches!(client.handle(Record::Greeting(far_hello)), Ok(Step::Wait)));
}

#[test]
fn records_out_of_their_place_are_refused() {
    let (mut client, _) =
        ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32), hex(ALICE)])).unwrap();
    let accept = Record::Accept(Acceptance::New { id: id(), public: hex(BOB_PUBLIC).try_into().unwrap() });
    assert_eq!(client.handle(accept).unwrap_err(), HandshakeError::Unexpected("ACCEPT before GREETING"));

    let mut sessions = Sessions::new();
    let (mut far, _) = FarHandshake::start(Role::NODE, &[], &mut Script::new(&[run_of(0, 32)])).unwrap();
    let data = Record::Data { offset: 0, bytes: b"SSH-2.0-x\r\n".to_vec() };
    assert_eq!(refused(far.handle(data, &mut sessions, &mut Script::new(&[])).unwrap()).0, RefuseCode::PROTOCOL);

    let (mut client, _) =
        ClientHandshake::start(Ask::New, &[], &mut Script::new(&[run_of(0x20, 32), hex(ALICE)])).unwrap();
    let refusal = Record::Refuse { code: RefuseCode::BUSY, reason: "16 sessions".into() };
    assert_eq!(
        client.handle(refusal).unwrap_err(),
        HandshakeError::Refused { code: RefuseCode::BUSY, reason: "16 sessions".into() }
    );
}

/// The secret never shows in a message.
#[test]
fn debug_hides_the_secret() {
    let shown = format!("{:?}", secret());
    assert_eq!(shown, "Secret(..)");
    let (mut sessions, mut far, greeting) = far_with_the_session();
    let ask = Ask::Resume { id: id(), secret: secret(), received: 1000 };
    let (mut client, open) = ClientHandshake::start(ask, &[], &mut Script::new(&[run_of(0xa0, 32)])).unwrap();
    far.handle(open, &mut sessions, &mut Script::new(&[])).unwrap();
    let Step::Send(proof) = client.handle(greeting).unwrap() else { panic!() };
    let step = far.handle(proof, &mut sessions, &mut Script::new(&[])).unwrap();
    let shown = format!("{step:?} {sessions:?}");
    assert!(!shown.contains(&SECRET[..8]) && !shown.contains(&FAR_PROOF[..8]), "{shown}");
}
