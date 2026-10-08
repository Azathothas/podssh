//! Task 4 tests: request shapes, the response machine, the refusal paths,
//! and the key-file parser. No live server here — the wrong-key rejection
//! against a real sshd is Task 6's; everything else proves without one.

use podssh_core::ssh::auth::{
    AuthError, AuthOutcome, AuthProgress, confirm_pk_ok, parse_openssh_private_key,
    parse_server_message, parse_service_accept, service_request, sign_data, userauth_query,
    userauth_signed, UserKey,
};
use podssh_core::ssh::types::{Reader, put_string};

fn user_key() -> UserKey {
    UserKey::ed25519(&[7u8; 32])
}

fn failure_msg(methods: &[&str], partial: bool) -> Vec<u8> {
    let mut out = vec![51u8];
    let joined = methods.join(",");
    let mut len = (joined.len() as u32).to_be_bytes().to_vec();
    out.append(&mut len);
    out.extend_from_slice(joined.as_bytes());
    out.push(u8::from(partial));
    out
}

#[test]
fn service_request_names_userauth_and_accept_parses() {
    let req = service_request();
    assert_eq!(req[0], 5);
    let mut r = Reader::new(&req[1..]);
    assert_eq!(r.string().unwrap(), b"ssh-userauth");
    let mut accept = vec![6u8];
    put_string(&mut accept, b"ssh-userauth");
    parse_service_accept(&accept).expect("matching service accepts");
    let mut wrong = vec![6u8];
    put_string(&mut wrong, b"ssh-connection");
    let err = parse_service_accept(&wrong).unwrap_err();
    assert!(matches!(err, AuthError::ServiceMismatch { .. }), "{err}");
}

#[test]
fn unsigned_query_carries_false_and_signed_carries_true() {
    let key = user_key();
    let q = userauth_query("alice", &key);
    assert_eq!(q[0], 50);
    // The boolean sits after user + service + method strings.
    let mut r = Reader::new(&q[1..]);
    assert_eq!(r.string().unwrap(), b"alice");
    assert_eq!(r.string().unwrap(), b"ssh-connection");
    assert_eq!(r.string().unwrap(), b"publickey");
    assert_eq!(r.u8().unwrap(), 0, "query must not claim a signature");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let s = userauth_signed(b"session-id", "alice", &key, &signing);
    let mut rs = Reader::new(&s[1..]);
    assert_eq!(rs.string().unwrap(), b"alice");
    assert_eq!(rs.string().unwrap(), b"ssh-connection");
    assert_eq!(rs.string().unwrap(), b"publickey");
    assert_eq!(rs.u8().unwrap(), 1, "signed request must claim its signature");
}

#[test]
fn signed_request_verifies_and_wrong_session_does_not() {
    use ed25519_dalek::{Signature, Verifier};
    let signing = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let key = UserKey::ed25519(signing.verifying_key().as_bytes());
    let session = b"the-session";
    let req = userauth_signed(session, "bob", &key, &signing);
    // The signature is the last string: `string alg || string sig`.
    let sig_outer_off = req.len() - (4 + "ssh-ed25519".len() + 4 + 64);
    let mut rsig = Reader::new(&req[sig_outer_off..]);
    assert_eq!(rsig.string().unwrap(), b"ssh-ed25519");
    let sig_bytes = rsig.string().unwrap();
    // The signed data is session || body (body = request without signature).
    let data = sign_data(session, "bob", &key);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key.blob[key.blob.len() - 32..].try_into().unwrap()).unwrap();
    vk.verify(&data, &Signature::from_slice(sig_bytes).unwrap())
        .expect("signature over session||body verifies");
    let mut bad_session = session.to_vec();
    bad_session[0] ^= 1;
    let bad_data = sign_data(&bad_session, "bob", &key);
    assert!(vk.verify(&bad_data, &Signature::from_slice(sig_bytes).unwrap()).is_err());
}

#[test]
fn failure_partial_drives_publickey_then_password_refusal() {
    let mut prog = AuthProgress::new();
    // Server allows publickey + password, partial: publickey first.
    let out = parse_server_message(&failure_msg(&["publickey", "password"], true)).unwrap();
    let AuthOutcome::Failure { methods, partial } = out else { panic!("{out:?}") };
    assert!(partial);
    let remaining = prog.on_failure(&methods);
    assert_eq!(prog.next_method(&remaining).unwrap(), "publickey");
    // publickey spent, password next: REFUSED naming the gap, never skipped.
    let out2 = parse_server_message(&failure_msg(&["password"], false)).unwrap();
    let AuthOutcome::Failure { methods: m2, .. } = out2 else { panic!("{out2:?}") };
    let remaining2 = prog.on_failure(&m2);
    let err = prog.next_method(&remaining2).unwrap_err();
    assert!(matches!(err, AuthError::PasswordRefused), "{err}");
    assert!(format!("{err}").contains("password"), "{err}");
}

#[test]
fn failure_with_no_methods_is_exhausted_naming_what_was_tried() {
    let mut prog = AuthProgress::new();
    let out = parse_server_message(&failure_msg(&["publickey"], false)).unwrap();
    let AuthOutcome::Failure { methods, .. } = out else { panic!("{out:?}") };
    let remaining = prog.on_failure(&methods);
    assert_eq!(prog.next_method(&remaining).unwrap(), "publickey");
    let out2 = parse_server_message(&failure_msg(&[], false)).unwrap();
    let AuthOutcome::Failure { methods: m2, .. } = out2 else { panic!("{out2:?}") };
    let remaining2 = prog.on_failure(&m2);
    let err = prog.next_method(&remaining2).unwrap_err();
    assert!(matches!(err, AuthError::Exhausted { .. }), "{err}");
    assert!(format!("{err}").contains("publickey"), "{err}");
}

#[test]
fn failure_is_never_success_and_success_parses() {
    let f = parse_server_message(&failure_msg(&["publickey"], false)).unwrap();
    assert!(!matches!(f, AuthOutcome::Success), "{f:?}");
    assert_eq!(parse_server_message(&[52u8]).unwrap(), AuthOutcome::Success);
    let mut banner = vec![53u8];
    put_string(&mut banner, b"hello");
    put_string(&mut banner, b"en");
    let AuthOutcome::Banner { message, .. } =
        parse_server_message(&banner).unwrap() else { panic!("banner") };
    assert_eq!(message, "hello");
}

#[test]
fn pk_ok_echo_mismatch_is_substitution() {
    let key = user_key();
    let mut ok = vec![60u8];
    put_string(&mut ok, b"ssh-ed25519");
    put_string(&mut ok, &key.blob);
    let out = parse_server_message(&ok).unwrap();
    confirm_pk_ok(&key, &out).expect("exact echo confirms");
    let other = UserKey::ed25519(&[8u8; 32]);
    assert!(matches!(confirm_pk_ok(&other, &out), Err(AuthError::PkOkMismatch)));
    let mut swapped = vec![60u8];
    put_string(&mut swapped, b"ssh-ed25519");
    put_string(&mut swapped, &other.blob);
    let out2 = parse_server_message(&swapped).unwrap();
    assert!(matches!(confirm_pk_ok(&key, &out2), Err(AuthError::PkOkMismatch)));
}

/// A minimal `id_ed25519` (cipher named by the caller) built the way OpenSSH
/// writes one: magic, cipher/kdf names, one public section, one private
/// section with agreeing checkints and 1,2,3... padding.
fn fixture_key(seed: &[u8; 32], cipher: &str, comment: &str) -> String {
    use base64::Engine;
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let pubb = sk.verifying_key().to_bytes();
    let mut privsec = Vec::new();
    privsec.extend_from_slice(&0xA5A5A5A5u32.to_be_bytes());
    privsec.extend_from_slice(&0xA5A5A5A5u32.to_be_bytes());
    put_string(&mut privsec, b"ssh-ed25519");
    put_string(&mut privsec, &pubb);
    let mut priv64 = seed.to_vec();
    priv64.extend_from_slice(&pubb);
    put_string(&mut privsec, &priv64);
    put_string(&mut privsec, comment.as_bytes());
    let mut pad: u8 = 1;
    while privsec.len() % 8 != 0 {
        privsec.push(pad);
        pad += 1;
    }
    let mut pubsec = Vec::new();
    put_string(&mut pubsec, b"ssh-ed25519");
    put_string(&mut pubsec, &pubb);
    let mut blob = Vec::new();
    blob.extend_from_slice(b"openssh-key-v1\x00");
    put_string(&mut blob, cipher.as_bytes());
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"");
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, &pubsec);
    put_string(&mut blob, &privsec);
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    )
}

#[test]
fn key_file_round_trip_and_refusals() {
    use ed25519_dalek::{Signer, Verifier};
    let seed = [11u8; 32];
    let pem = fixture_key(&seed, "none", "alice@example");
    let key = parse_openssh_private_key(&pem).expect("valid fixture parses");
    assert_eq!(key.comment, "alice@example");
    let pubb = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(key.user_key(), UserKey::ed25519(&pubb));
    // A signature from the parsed key verifies under the parsed public.
    let sig = key.signing_key().sign(b"probe");
    ed25519_dalek::VerifyingKey::from_bytes(&pubb)
        .unwrap()
        .verify(b"probe", &sig)
        .expect("parsed key signs");
    // Encrypted key refused naming the cipher.
    let enc = fixture_key(&seed, "aes256-ctr", "x");
    let err = parse_openssh_private_key(&enc).unwrap_err();
    assert!(matches!(err, AuthError::EncryptedKey { .. }), "{err}");
    assert!(format!("{err}").contains("aes256-ctr"), "{err}");
    // Garbage armor refused.
    assert!(matches!(
        parse_openssh_private_key("not a key\n").unwrap_err(),
        AuthError::BadArmor
    ));
}
