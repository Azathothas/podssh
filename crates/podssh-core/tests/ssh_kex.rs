//! Task 2 tests: wire types, KEXINIT round-trip, server-order selection, the
//! exchange hash input order, KDF determinism, and host-key verification.
//! No invented vectors: DH symmetry, hash sensitivity, and sign/verify
//! round-trips carry the proof, and the live server closes it (Task 6).

use podssh_core::ssh::kex::{KexInit, decode_kexinit, must_ignore_next, our_kexinit, select};
use podssh_core::ssh::keys::{
    Ephemeral, derive_key, ed25519_blob, exchange_hash, parse_host_key, verify_host_signature,
};
use podssh_core::ssh::types::{Reader, put_mpint, put_string};

fn kexinit_named(kex: &[&str], hostkey: &[&str], cipher: &[&str]) -> KexInit {
    // A server KEXINIT built through our own encoder, then decoded — the
    // decode path is what is under test, not a hand-assembled struct.
    let mut out = vec![20u8];
    out.extend_from_slice(&[9u8; 16]);
    for list in [kex, hostkey, cipher, cipher, &["hmac-sha2-256"], &["hmac-sha2-256"], &["none"], &["none"]] {
        let joined = list.join(",");
        put_string(&mut out, joined.as_bytes());
    }
    put_string(&mut out, &[]);
    put_string(&mut out, &[]);
    out.extend_from_slice(&[0, 0, 0, 0, 0]);
    decode_kexinit(&out[1..]).expect("built KEXINIT must decode")
}

#[test]
fn our_kexinit_decodes_to_our_closed_set() {
    let payload = our_kexinit();
    assert_eq!(payload[0], 20);
    let k = decode_kexinit(&payload[1..]).unwrap();
    assert_eq!(k.kex, vec!["curve25519-sha256"]);
    assert_eq!(k.hostkey, vec!["ssh-ed25519", "rsa-sha2-256"]);
    assert_eq!(k.cipher_c2s, vec!["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com"]);
    assert!(!k.first_kex_follows, "⛔ we never guess — the flag is always false");
}

#[test]
fn decode_refuses_trailing_bytes() {
    let mut payload = our_kexinit();
    payload.push(0);
    let err = decode_kexinit(&payload[1..]).unwrap_err();
    assert!(matches!(err, podssh_core::ssh::kex::KexError::TrailingBytes { .. }), "got {err}");
}

#[test]
fn selection_follows_server_order_inside_our_set() {
    // Server prefers aes-gcm over chacha: we take aes-gcm even though our
    // list leads with chacha. Server order wins; our set only bounds.
    let theirs = kexinit_named(
        &["curve25519-sha256"],
        &["rsa-sha2-256", "ssh-ed25519"],
        &["aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
    );
    let s = select(&theirs).unwrap();
    assert_eq!(s.kex, "curve25519-sha256");
    assert_eq!(s.hostkey, "rsa-sha2-256");
    assert_eq!(s.cipher_c2s, "aes128-gcm@openssh.com");
    assert_eq!(s.cipher_s2c, "aes128-gcm@openssh.com");
}

#[test]
fn selection_with_no_overlap_names_the_server_head() {
    let theirs = kexinit_named(&["diffie-hellman-group14-sha256"], &["ssh-ed25519"], &[
        "chacha20-poly1305@openssh.com",
    ]);
    let err = select(&theirs).unwrap_err();
    let text = format!("{err}");
    assert!(text.contains("kex"), "{text}");
    assert!(text.contains("diffie-hellman-group14-sha256"), "{text}");
}

#[test]
fn first_kex_follows_miss_is_detected() {
    let mut theirs = kexinit_named(&["curve25519-sha256"], &["ssh-ed25519"], &[
        "chacha20-poly1305@openssh.com",
    ]);
    theirs.first_kex_follows = true;
    let s = select(&theirs).unwrap();
    assert!(!must_ignore_next(&theirs, &s), "a correct guess is not ignored");
    theirs.kex = vec!["diffie-hellman-group14-sha256".to_string(), "curve25519-sha256".to_string()];
    let s2 = select(&theirs).unwrap();
    assert!(must_ignore_next(&theirs, &s2), "a wrong guess must be ignored");
}

#[test]
fn mpint_zero_is_empty_and_high_bit_gets_a_pad() {
    let mut out = Vec::new();
    put_mpint(&mut out, &[]);
    assert_eq!(out, vec![0, 0, 0, 0]);
    let mut out = Vec::new();
    put_mpint(&mut out, &[0x80, 0x01]);
    assert_eq!(out, vec![0, 0, 0, 3, 0, 0x80, 0x01]);
    let mut out = Vec::new();
    put_mpint(&mut out, &[0x00, 0x00, 0x7F]);
    assert_eq!(out, vec![0, 0, 0, 1, 0x7F]);
    // And the reader normalizes back.
    let mut r = Reader::new(&out);
    assert_eq!(r.mpint().unwrap(), &[0x7F]);
}

#[test]
fn mpint_without_its_pad_is_malformed_not_truncated() {
    let raw = [0, 0, 0, 1, 0x80];
    let mut r = Reader::new(&raw);
    let err = r.mpint().unwrap_err();
    assert!(matches!(err, podssh_core::ssh::types::TypeError::BadMpint { .. }), "got {err}");
}

#[test]
fn namelist_refuses_empty_entries() {
    let mut out = Vec::new();
    put_string(&mut out, b"a,,b");
    let mut r = Reader::new(&out);
    let err = r.namelist().unwrap_err();
    assert!(matches!(err, podssh_core::ssh::types::TypeError::BadNameList { .. }));
    let mut out = Vec::new();
    put_string(&mut out, b"");
    let mut r = Reader::new(&out);
    assert!(r.namelist().unwrap().is_empty());
}

#[test]
fn diffie_hellman_is_symmetric_and_nontrivial() {
    // Fixed secrets (test-only seam): both directions agree, the secret is
    // 32 non-degenerate bytes, and a third party gets something else.
    let a = Ephemeral::from_bytes([1u8; 32]);
    let b = Ephemeral::from_bytes([2u8; 32]);
    let c = Ephemeral::from_bytes([3u8; 32]);
    let ab = a.agree(&b.public_bytes()).unwrap();
    let ba = b.agree(&a.public_bytes()).unwrap();
    assert_eq!(ab, ba);
    assert!(ab.iter().any(|x| *x != 0));
    assert_ne!(ab, a.agree(&c.public_bytes()).unwrap());
    assert!(a.agree(&[0u8; 31]).is_err());
}

#[test]
fn exchange_hash_matches_a_hand_assembled_preimage() {
    // ⛔ The order is pinned by a SECOND transcription of RFC 8731 §1.2,
    // written by hand in the test: `string(V_C) || string(V_S) || ...` with
    // K mpint-encoded. A production swap of two inputs changes H without
    // breaking determinism — this test breaks instead, which is the point.
    // (Determinism + per-input sensitivity are asserted in the next test.)
    use sha2::{Digest, Sha256};
    let (vc, vs) = (b"SSH-2.0-a".as_slice(), b"SSH-2.0-b".as_slice());
    let (ic, is_) = (b"Ic".as_slice(), b"Is".as_slice());
    let (ks, qc, qs, k) = (b"Ks".as_slice(), [1u8; 32], [2u8; 32], [3u8; 32].as_slice());
    let mut pre = Vec::new();
    for part in [vc, vs, ic, is_, ks, &qc[..], &qs[..]] {
        pre.extend_from_slice(&(part.len() as u32).to_be_bytes());
        pre.extend_from_slice(part);
    }
    let mut km = Vec::new();
    put_mpint(&mut km, k);
    pre.extend_from_slice(&km);
    let mut h = Sha256::new();
    h.update(&pre);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(exchange_hash(vc, vs, ic, is_, ks, &qc, &qs, k), expected);
}

#[test]
fn exchange_hash_is_deterministic_and_every_input_matters() {
    let h1 = exchange_hash(b"SSH-2.0-a", b"SSH-2.0-b", b"Ic", b"Is", b"Ks", &[1u8; 32], &[2u8; 32], &[3u8; 32]);
    let h2 = exchange_hash(b"SSH-2.0-a", b"SSH-2.0-b", b"Ic", b"Is", b"Ks", &[1u8; 32], &[2u8; 32], &[3u8; 32]);
    assert_eq!(h1, h2);
    // ⛔ Every input flipped alone changes H: the ORDER is the correctness,
    // so each position is proved separately rather than one combined flip.
    // Variable-length inputs grow by a byte; fixed 32-byte inputs flip one.
    let h1v = h1.to_vec();
    let cases: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], Vec<u8>)> = vec![
        (b"SSH-2.0-aX".to_vec(), b"SSH-2.0-b".to_vec(), b"Ic".to_vec(), b"Is".to_vec(), b"Ks".to_vec(), [1u8; 32], [2u8; 32], vec![3u8; 32]),
        (b"SSH-2.0-a".to_vec(), b"SSH-2.0-bX".to_vec(), b"Ic".to_vec(), b"Is".to_vec(), b"Ks".to_vec(), [1u8; 32], [2u8; 32], vec![3u8; 32]),
        (b"SSH-2.0-a".to_vec(), b"SSH-2.0-b".to_vec(), b"IcX".to_vec(), b"Is".to_vec(), b"Ks".to_vec(), [1u8; 32], [2u8; 32], vec![3u8; 32]),
        (b"SSH-2.0-a".to_vec(), b"SSH-2.0-b".to_vec(), b"Ic".to_vec(), b"IsX".to_vec(), b"Ks".to_vec(), [1u8; 32], [2u8; 32], vec![3u8; 32]),
        (b"SSH-2.0-a".to_vec(), b"SSH-2.0-b".to_vec(), b"Ic".to_vec(), b"Is".to_vec(), b"KsX".to_vec(), [1u8; 32], [2u8; 32], vec![3u8; 32]),
        (b"SSH-2.0-a".to_vec(), b"SSH-2.0-b".to_vec(), b"Ic".to_vec(), b"Is".to_vec(), b"Ks".to_vec(), [9u8; 32], [2u8; 32], vec![3u8; 32]),
        (b"SSH-2.0-a".to_vec(), b"SSH-2.0-b".to_vec(), b"Ic".to_vec(), b"Is".to_vec(), b"Ks".to_vec(), [1u8; 32], [9u8; 32], vec![3u8; 32]),
        (b"SSH-2.0-a".to_vec(), b"SSH-2.0-b".to_vec(), b"Ic".to_vec(), b"Is".to_vec(), b"Ks".to_vec(), [1u8; 32], [2u8; 32], vec![9u8; 32]),
    ];
    for (i, (vc, vs, ic, is_, ks, qc, qs, k)) in cases.into_iter().enumerate() {
        let hv = exchange_hash(&vc, &vs, &ic, &is_, &ks, &qc, &qs, &k);
        assert_ne!(h1v, hv.to_vec(), "input {i} does not affect H");
    }
}

#[test]
fn kdf_is_deterministic_with_distinct_letters_and_prefix_free() {
    let k = [7u8; 32];
    let h = [8u8; 32];
    let a1 = derive_key(&k, &h, b'A', b"session", 64);
    let a2 = derive_key(&k, &h, b'A', b"session", 64);
    assert_eq!(a1, a2);
    assert_eq!(a1.len(), 64);
    let c = derive_key(&k, &h, b'C', b"session", 64);
    assert_ne!(&a1[..32], &c[..32], "letters A and C must differ");
    // Extension: asking for more returns the prefix plus more.
    let a96 = derive_key(&k, &h, b'A', b"session", 96);
    assert_eq!(&a96[..64], &a1[..]);
}

#[test]
fn ed25519_host_key_verifies_and_tampering_fails() {
    use ed25519_dalek::{Signer, SigningKey};
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let verifying = signing.verifying_key();
    let blob = ed25519_blob(verifying.as_bytes());
    // `K_S` IS the blob (`string alg || key-parts`), not a string of it —
    // wrapping it once more is the test's bug, not the parser's.
    let key = parse_host_key(&blob).unwrap();
    assert_eq!(key.alg, "ssh-ed25519");
    let h = [1u8; 32];
    let sig = signing.sign(&h);
    let mut outer = Vec::new();
    put_string(&mut outer, b"ssh-ed25519");
    put_string(&mut outer, &sig.to_bytes());
    verify_host_signature(&key, &h, &outer).expect("valid signature verifies");
    // Tampered message fails.
    let bad_h = [2u8; 32];
    assert!(verify_host_signature(&key, &bad_h, &outer).is_err());
    // Signature under a different alg name than the key is a substitution.
    let mut swapped = Vec::new();
    put_string(&mut swapped, b"rsa-sha2-256");
    put_string(&mut swapped, &sig.to_bytes());
    assert!(verify_host_signature(&key, &h, &swapped).is_err());
}

#[test]
fn unknown_host_key_algorithm_is_refused() {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-dss");
    put_string(&mut blob, &[0u8; 32]);
    let err = parse_host_key(&blob).unwrap_err();
    assert!(matches!(err, podssh_core::ssh::keys::KeyError::UnknownHostKey { .. }));
}
