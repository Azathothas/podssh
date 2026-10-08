//! `podssh-ts` 1008-split tests: the reason decides the fault.

use podssh_ts::classify::{Fault, classify_1008};

#[test]
fn not_authorized_is_77() {
    assert_eq!(classify_1008(Some("not authorized")), Fault::NotAuthorized);
}

#[test]
fn mesh_bad_client_info_duplicate_and_empty_are_70() {
    for reason in [
        Some("mesh not supported"),
        Some("bad client info"),
        Some("duplicate login"),
        Some(""),
        None,
    ] {
        assert_eq!(classify_1008(reason), Fault::Session, "{reason:?}");
    }
}
