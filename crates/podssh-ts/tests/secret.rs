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
