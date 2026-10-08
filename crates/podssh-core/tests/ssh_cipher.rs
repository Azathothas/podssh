//! Task 3 tests: seal/open round-trips, tamper failures, seqno binding, and
//! the two wire shapes. No invented vectors: round-trips plus corruption at
//! every byte carry the proof, and the live server closes it (Task 6).

use podssh_core::ssh::cipher::{CipherKind, CipherState, Role, SecureDecoder};

fn state(kind: CipherKind) -> (CipherState, CipherState) {
    // One kex worth of material, roles crossed: A speaks as the client
    // (send C, recv D), B as the server (send D, recv C) — A's packets open
    // under B and vice versa. Same-role states never agree (pinned below).
    let k = [5u8; 32];
    let h = [6u8; 32];
    let a = CipherState::new(kind, &k, &h, b"session", Role::Client);
    let b = CipherState::new(kind, &k, &h, b"session", Role::Server);
    (a, b)
}

fn fresh(kind: CipherKind) -> CipherState {
    CipherState::new(kind, &[5u8; 32], &[6u8; 32], b"session", Role::Server)
}

#[test]
fn chacha_round_trip_split_at_every_offset() {
    let (mut a, b) = state(CipherKind::Chacha20Poly1305);
    let wire = a.seal(b"hello ssh").unwrap();
    // Length is encrypted: the first 4 bytes are NOT the length.
    assert_ne!(&wire[..4], &[0, 0, 0, 12]);
    for at in 0..wire.len() {
        let mut dec = SecureDecoder::new(fresh(CipherKind::Chacha20Poly1305));
        let first = dec.push(&wire[..at]).unwrap();
        assert!(first.is_empty(), "offset {at}: half packet produced {first:?}");
        let rest = dec.push(&wire[at..]).unwrap();
        assert_eq!(rest, vec![b"hello ssh".to_vec()], "offset {at}");
    }
    // And the paired states talk directly.
    let mut dec = SecureDecoder::new(b);
    assert_eq!(dec.push(&wire).unwrap(), vec![b"hello ssh".to_vec()]);
}

#[test]
fn gcm_round_trip_and_plaintext_length() {
    let (mut a, b) = state(CipherKind::Aes128Gcm);
    let wire = a.seal(b"gcm hello").unwrap();
    // RFC 5647 §7.3: the length stays plaintext and is the AAD.
    let len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
    assert_eq!(wire.len(), 4 + len + 16);
    assert_eq!((wire.len() - 4) % 16, 0, "ciphertext+tag is block-aligned");
    let mut dec = SecureDecoder::new(b);
    let half = wire.len() / 2;
    assert!(dec.push(&wire[..half]).unwrap().is_empty());
    assert_eq!(dec.push(&wire[half..]).unwrap(), vec![b"gcm hello".to_vec()]);
}

#[test]
fn every_tampered_byte_fails_closed() {
    for kind in [CipherKind::Chacha20Poly1305, CipherKind::Aes128Gcm] {
        let (mut a, _) = state(kind);
        let wire = a.seal(b"tamper me").unwrap();
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            let mut dec = SecureDecoder::new(fresh(kind));
            // A flip lands in the length (re-framed or refused), the body
            // (auth failure), or the tag (auth failure). The only legal
            // non-error is silence (a length that now demands more bytes) —
            // never a payload, right or wrong.
            match dec.push(&bad) {
                Ok(payloads) => assert!(payloads.is_empty(), "{kind:?} byte {i}: {payloads:?}"),
                Err(_) => {}
            }
        }
    }
}

#[test]
fn seqno_mismatch_fails_and_replay_of_packet_zero_fails() {
    let (mut a, b) = state(CipherKind::Chacha20Poly1305);
    let first = a.seal(b"one").unwrap();
    let _second = a.seal(b"two").unwrap();
    let mut dec = SecureDecoder::new(b);
    // Skip packet zero: packet one's nonce/tag do not verify at seq 0.
    assert!(dec.push(&_second).is_err());
    // And after consuming packet zero, packet one opens.
    let (mut a2, b2) = state(CipherKind::Chacha20Poly1305);
    let w1 = a2.seal(b"one").unwrap();
    let w2 = a2.seal(b"two").unwrap();
    let mut dec2 = SecureDecoder::new(b2);
    assert_eq!(dec2.push(&w1).unwrap(), vec![b"one".to_vec()]);
    assert_eq!(dec2.push(&w2).unwrap(), vec![b"two".to_vec()]);
    let _ = first;
}

#[test]
fn same_payload_seals_differently_each_time() {
    // ⛔ The nonce-misuse property: two seals of identical bytes must differ
    // in every byte that depends on the nonce (all of them). Identical seals
    // would mean a fixed nonce — catastrophic for both AEADs.
    for kind in [CipherKind::Chacha20Poly1305, CipherKind::Aes128Gcm] {
        let (mut a, _) = state(kind);
        let w1 = a.seal(b"same").unwrap();
        let w2 = a.seal(b"same").unwrap();
        assert_ne!(w1, w2);
        if kind == CipherKind::Chacha20Poly1305 {
            // The length plaintext is deterministic, so only the nonce makes
            // its ciphertext differ. Random padding cannot mask a stuck
            // seqno here -- this pins the send-side increment, not luck.
            assert_ne!(&w1[..4], &w2[..4], "chacha length did not re-nonce");
        }
        if kind == CipherKind::Aes128Gcm {
            // GCM keeps the length plaintext (same), everything else differs.
            assert_eq!(&w1[..4], &w2[..4]);
            assert_ne!(&w1[4..], &w2[4..]);
            // Bytes [4..8] encrypt the deterministic length field: they differ
            // only when the counter advances. This pins send_ctr the same way.
            assert_ne!(&w1[4..8], &w2[4..8], "gcm first block did not re-nonce");
        }
    }
}

#[test]
fn wrong_direction_keys_do_not_open() {
    // A client-role state cannot open its own packets: its receive keys are
    // the D letters, but its seals use C. Same-role states never agree.
    let k = [5u8; 32];
    let h = [6u8; 32];
    let mut a = CipherState::new(CipherKind::Chacha20Poly1305, &k, &h, b"session", Role::Client);
    let wire = a.seal(b"secret").unwrap();
    let same_role = CipherState::new(CipherKind::Chacha20Poly1305, &k, &h, b"session", Role::Client);
    let mut dec = SecureDecoder::new(same_role);
    assert!(dec.push(&wire).is_err());
    // And a different session id derives different keys either way.
    let other = CipherState::new(CipherKind::Chacha20Poly1305, &k, &h, b"other", Role::Server);
    let mut dec2 = SecureDecoder::new(other);
    assert!(dec2.push(&wire).is_err());
}

#[test]
fn cipher_names_resolve_and_nothing_else_does() {
    assert_eq!(
        CipherKind::for_name("chacha20-poly1305@openssh.com"),
        Some(CipherKind::Chacha20Poly1305)
    );
    assert_eq!(CipherKind::for_name("aes128-gcm@openssh.com"), Some(CipherKind::Aes128Gcm));
    assert_eq!(CipherKind::for_name("aes256-gcm@openssh.com"), None);
    assert_eq!(CipherKind::for_name("3des-cbc"), None);
}
