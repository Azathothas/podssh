//! The security keys of `podssh agent`: added as OpenSSH's `ssh-add` adds
//! them, listed after russh's keys, removed, refused while locked, gone at
//! the end of their lifetime; and a signature with no device fails with
//! FAILURE, which a client reads as a key that did not sign.

use russh::keys::ssh_encoding::Encode;

use super::super::soft::SoftKey;
use super::super::{private_key, Alg, Enrolled, DEVICE_VARIABLE, USER_PRESENCE_REQUIRED};
use super::*;

/// A key of a device in software, as OpenSSH's `ssh-add` sends it: the
/// request's code, the key with its handle, the comment, and the
/// constraints.
fn add_request(alg: Alg, constraints: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let device = SoftKey::new(alg);
    let enrolled = Enrolled { public: device.point(), key_handle: vec![5; 40] };
    let key = private_key(alg, &enrolled, "ssh:", USER_PRESENCE_REQUIRED, "").unwrap();
    let mut request = vec![if constraints.is_empty() { ADD_IDENTITY } else { ADD_ID_CONSTRAINED }];
    request.extend_from_slice(&key.key_data().encode_vec().unwrap());
    put_string(&mut request, b"key@host");
    request.extend_from_slice(constraints);
    (request, key.public_key().to_bytes().unwrap())
}

/// The constraints of `ssh-add -t SECONDS` for a security key.
fn provider_and_lifetime(seconds: u32) -> Vec<u8> {
    let mut out = vec![CONSTRAIN_LIFETIME];
    out.extend_from_slice(&seconds.to_be_bytes());
    out.push(CONSTRAIN_EXTENSION);
    put_string(&mut out, SK_PROVIDER.as_bytes());
    put_string(&mut out, b"internal");
    out
}

/// russh's answer to a request for the keys: one key of its own.
fn russh_list() -> Zeroizing<Vec<u8>> {
    let mut out = vec![IDENTITIES_ANSWER, 0, 0, 0, 1];
    put_string(&mut out, b"its key");
    put_string(&mut out, b"its comment");
    Zeroizing::new(out)
}

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
}

#[test]
fn security_keys_are_added_listed_and_removed() {
    let held = Held::default();
    for alg in [Alg::Ed25519, Alg::EcdsaP256] {
        let (request, blob) = add_request(alg, &provider_and_lifetime(600));
        assert_eq!(run(held.answer(&request, false)).as_deref().map(Vec::as_slice), Some(&[SUCCESS][..]));
        let list = held.after(&[REQUEST_IDENTITIES], russh_list(), false);
        let mut rest = &list[1..];
        assert_eq!(list[0], IDENTITIES_ANSWER);
        assert_eq!(take_u32(&mut rest), Some(2), "{alg:?}: russh's key and this one");
        assert_eq!(take_string(&mut rest).unwrap(), b"its key");
        assert_eq!(take_string(&mut rest).unwrap(), b"its comment");
        assert_eq!(take_string(&mut rest).unwrap(), blob);
        assert_eq!(take_string(&mut rest).unwrap(), b"key@host");
        assert!(rest.is_empty());

        let mut remove = vec![REMOVE_IDENTITY];
        put_string(&mut remove, &blob);
        assert_eq!(run(held.answer(&remove, true)).as_deref().map(Vec::as_slice), Some(&[FAILURE][..]), "locked");
        assert_eq!(run(held.answer(&remove, false)).as_deref().map(Vec::as_slice), Some(&[SUCCESS][..]));
        assert_eq!(held.count(), 0);
        assert!(run(held.answer(&remove, false)).is_none(), "a key that is not held goes to russh's server");
    }
}

/// A plain key goes to russh's server; a security key with a constraint
/// that nobody here can meet, or added while the agent is locked, is
/// refused.
#[test]
fn what_the_agent_cannot_keep_is_refused() {
    let held = Held::default();
    let plain = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let mut request = vec![ADD_IDENTITY];
    request.extend_from_slice(&plain.key_data().encode_vec().unwrap());
    put_string(&mut request, b"");
    assert!(run(held.answer(&request, false)).is_none());

    let confirm = [2u8];
    let (request, _) = add_request(Alg::Ed25519, &confirm);
    assert_eq!(run(held.answer(&request, false)).as_deref().map(Vec::as_slice), Some(&[FAILURE][..]));
    let mut other = vec![CONSTRAIN_EXTENSION];
    put_string(&mut other, b"restrict-destination-v00@openssh.com");
    let (request, _) = add_request(Alg::Ed25519, &other);
    assert_eq!(run(held.answer(&request, false)).as_deref().map(Vec::as_slice), Some(&[FAILURE][..]));
    let (request, _) = add_request(Alg::Ed25519, &[]);
    assert_eq!(run(held.answer(&request, true)).as_deref().map(Vec::as_slice), Some(&[FAILURE][..]));
    assert_eq!(held.count(), 0);
}

#[test]
fn a_lifetime_ends_and_a_removal_of_all_takes_them() {
    let held = Held::default();
    let (request, _) = add_request(Alg::Ed25519, &provider_and_lifetime(0));
    assert_eq!(run(held.answer(&request, false)).as_deref().map(Vec::as_slice), Some(&[SUCCESS][..]));
    assert_eq!(held.count(), 0, "a lifetime of 0 s ends at once");
    let (request, _) = add_request(Alg::EcdsaP256, &[]);
    run(held.answer(&request, false));
    assert_eq!(held.count(), 1);
    let failed = held.after(&[REMOVE_ALL_IDENTITIES], Zeroizing::new(vec![FAILURE]), false);
    assert_eq!(failed.as_slice(), [FAILURE]);
    assert_eq!(held.count(), 1, "russh's server refused, so nothing goes");
    held.after(&[REMOVE_ALL_IDENTITIES], Zeroizing::new(vec![SUCCESS]), false);
    assert_eq!(held.count(), 0);
    let locked = held.after(&[REQUEST_IDENTITIES], russh_list(), true);
    assert_eq!(locked, russh_list(), "a locked agent lists nothing of its own");
}

/// With no device, the agent answers FAILURE, as for a key that did not
/// sign, and the probe's reason goes to its stderr.
#[test]
fn a_signature_with_no_device_fails() {
    std::env::set_var(DEVICE_VARIABLE, "none");
    let held = Held::default();
    let (request, blob) = add_request(Alg::Ed25519, &[]);
    run(held.answer(&request, false));
    let mut sign = vec![SIGN_REQUEST];
    put_string(&mut sign, &blob);
    put_string(&mut sign, b"the data");
    sign.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(run(held.answer(&sign, false)).as_deref().map(Vec::as_slice), Some(&[FAILURE][..]));
    assert_eq!(run(held.answer(&sign, true)).as_deref().map(Vec::as_slice), Some(&[FAILURE][..]));
    let mut unknown = vec![SIGN_REQUEST];
    put_string(&mut unknown, b"another key");
    put_string(&mut unknown, b"the data");
    assert!(run(held.answer(&unknown, false)).is_none(), "another key goes to russh's server");
}
