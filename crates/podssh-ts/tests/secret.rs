//! `podssh-ts` secret tests: redaction, refusal, expiry.

use podssh_ts::secret::AuthKey;

#[test]
fn empty_key_is_refused() {
    assert_eq!(AuthKey::new(Vec::new()).unwrap_err(), "empty auth key");
}

#[test]
fn debug_never_shows_bytes() {
    let key = AuthKey::new(b"tskey-auth-SECRET".to_vec()).unwrap();
    let shown = format!("{:?}", key);
    assert!(!shown.contains("SECRET"), "{shown}");
    assert!(shown.contains("REDACTED"), "{shown}");
}

#[test]
fn expire_zeros_and_locks() {
    let mut key = AuthKey::new(b"tskey-auth-SECRET".to_vec()).unwrap();
    assert!(key.expose().is_ok());
    key.expire();
    assert_eq!(key.expose(), Err("auth key already expired"));
}

/// The bytes are cleared when the key is dropped: the type says so, and the
/// build fails without it (T-241). A test that read freed memory would not be
/// sound, so this is the proof that a test can give.
#[test]
fn the_key_is_cleared_on_drop() {
    fn cleared_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    cleared_on_drop::<AuthKey>();
    // A buffer that clears itself goes in with no copy.
    let key = AuthKey::new(zeroize::Zeroizing::new(b"tskey-auth-SECRET".to_vec())).unwrap();
    assert_eq!(key.expose(), Ok(&b"tskey-auth-SECRET"[..]));
}
