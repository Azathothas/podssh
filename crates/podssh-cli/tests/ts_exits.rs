//! The exit of `podssh ts` for a failure of the node (T-105): a key that the relay refuses is 77,
//! with what it needs, whether the DERP link's state or a call of the fork said it; another close
//! is 70; a relay link that never came up is 78; the control server's silence is 78.
#![cfg(feature = "ts")]

use podssh_cli::ts::exits::node_error_exit;
use podssh_ts::node::NodeError;

fn exit(e: NodeError) -> (i32, String) {
    let mut err: Vec<u8> = Vec::new();
    let code = node_error_exit(&e, &mut err);
    (code, String::from_utf8(err).unwrap())
}

const NOT_AUTHORIZED: &str = "websocket closed: code=1008 reason=\"not authorized\"";

#[test]
fn a_refused_key_is_77_and_says_what_it_needs() {
    let (code, text) = exit(NodeError::DerpRefused { reason: NOT_AUTHORIZED.into() });
    assert_eq!(code, 77, "{text}");
    assert!(text.contains("1008") && text.contains("allowlist") && text.contains("--ts-wait-allowlist"), "{text}");
    // The same, from the text of a call of the fork.
    assert_eq!(exit(NodeError::Fork(NOT_AUTHORIZED.into())).0, 77);
    // Refused until the end of a wait for admission.
    let (code, text) = exit(NodeError::DerpPending { last: Some(NOT_AUTHORIZED.into()), refused: true });
    assert_eq!(code, 77, "{text}");
    assert!(text.contains("allowlist"), "{text}");
}

#[test]
fn another_close_is_70_and_a_link_that_never_came_up_is_78() {
    let (code, text) =
        exit(NodeError::DerpRefused { reason: "websocket closed: code=1008 reason=\"duplicate login\"".into() });
    assert_eq!(code, 70, "{text}");
    assert!(!text.contains("allowlist"), "{text}");
    let (code, text) = exit(NodeError::DerpPending { last: Some("connection reset".into()), refused: false });
    assert_eq!(code, 78, "{text}");
    assert!(text.contains("connection reset"), "{text}");
    let (code, text) = exit(NodeError::NetmapPending);
    assert_eq!(code, 78);
    assert!(text.contains("control server") && !text.contains("allowlist likely"), "{text}");
}

#[test]
fn a_relays_words_are_made_safe() {
    let (_, text) = exit(NodeError::DerpRefused { reason: "code=1008 reason=\"not\u{1b}[2J authorized\"".into() });
    assert!(!text.contains('\u{1b}'), "{text:?}");
}
