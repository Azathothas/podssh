//! The tests of `node_derp`.

use super::fallback_from;

#[test]
fn podssh_derp_turns_the_fallback_off_with_no_and_refuses_another_word() {
    for on in [None, Some(""), Some("yes"), Some("On"), Some("1")] {
        assert!(fallback_from(on).unwrap(), "{on:?}");
    }
    for off in ["no", "OFF", "0", "false"] {
        assert!(!fallback_from(Some(off)).unwrap(), "{off}");
    }
    let refused = fallback_from(Some("maybe")).unwrap_err();
    assert_eq!(refused.code, 78);
    assert!(refused.message.contains("PODSSH_DERP=maybe"), "{}", refused.message);
}
