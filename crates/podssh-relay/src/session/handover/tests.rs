//! The bytes of a handover (T-668): a session's state comes back whole, and
//! bytes that would resume a session with a gap are refused.

use std::time::Duration;

use super::*;
use crate::session::link::Link;
use crate::session::record::Record;

fn id() -> SessionId {
    SessionId([7u8; 16])
}

/// A link that sent 300 bytes, of which the peer acknowledged 100, and that
/// received 50, 20 of them not yet written to the target.
fn busy_link() -> Link {
    let mut link = Link::new(0, 0).with_replay(1 << 20).with_heartbeat().with_moves().with_ends();
    let mut out = Vec::new();
    link.send(&[0x5a; 300], &mut out).unwrap();
    link.on_record(Record::Ack { offset: 100 }).unwrap();
    link.on_record(Record::Data { offset: 0, bytes: vec![1; 50] }).unwrap();
    link.holding(20);
    link
}

fn carried() -> LayerState {
    let carry = CarryParts { undelivered: vec![1; 20], app_ended: false, app_shut: false };
    LayerState {
        id: id(),
        secret: Secret::from_bytes([9u8; 32]),
        left: Duration::from_secs(590),
        kept: Kept::Carried { link: busy_link().parts(), carry },
    }
}

#[test]
fn a_carried_session_comes_back_whole() {
    let state = carried();
    let bytes = state.encode();
    let back = LayerState::decode(&bytes).unwrap();
    assert_eq!(back.id, state.id);
    assert_eq!(back.secret.bytes(), state.secret.bytes());
    assert_eq!(back.left, Duration::from_secs(590));
    let (Kept::Carried { link, carry }, Kept::Carried { link: was, carry: was_carry }) = (&back.kept, &state.kept)
    else {
        panic!("{back:?}");
    };
    assert_eq!((link, carry), (was, was_carry));
    assert_eq!(*back.encode(), *bytes, "the same bytes again");
}

/// The link from the values resumes as the one before would: from the
/// peer's offset, with the bytes that the peer lacks.
#[test]
fn a_link_from_its_parts_resumes_as_the_one_before() {
    let mut before = busy_link();
    let mut after = Link::from_parts(before.parts()).unwrap();
    let (mut a, mut b) = (Vec::new(), Vec::new());
    assert_eq!(before.resume(150, &mut a), after.resume(150, &mut b));
    assert_eq!(a, b);
    assert_eq!(after.received(), 50);
    assert_eq!(after.sent(), 300);
    // Bytes that the peer acknowledged are not kept, here as there.
    assert!(Link::from_parts(busy_link().parts()).unwrap().resume(99, &mut Vec::new()).is_err());
}

#[test]
fn a_session_closed_here_comes_back_with_its_words() {
    let state = LayerState {
        id: id(),
        secret: Secret::from_bytes([3u8; 32]),
        left: Duration::from_secs(10),
        kept: Kept::Closed { received: 77, reason: "its target could not move".into() },
    };
    let back = LayerState::decode(&state.encode()).unwrap();
    match back.kept {
        Kept::Closed { received, reason } => assert_eq!((received, reason.as_str()), (77, "its target could not move")),
        Kept::Carried { .. } => panic!("closed, not carried"),
    }
}

/// Another version, a cut, bytes after the end, or a buffer that does not
/// end at the sent offset: each refused, never a session with a gap.
#[test]
fn bytes_that_do_not_hold_together_are_refused() {
    let bytes = carried().encode();
    let mut other = bytes.to_vec();
    other[0] = VERSION + 1;
    assert!(LayerState::decode(&other).unwrap_err().0.contains("version"));
    assert!(LayerState::decode(&bytes[..bytes.len() - 1]).unwrap_err().0.contains("ends inside"));
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(LayerState::decode(&longer).unwrap_err().0.contains("follow"));
    let mut parts = busy_link().parts();
    if let Some(replay) = parts.replay.as_mut() {
        replay.bytes.pop();
    }
    assert!(Link::from_parts(parts).unwrap_err().contains("replay buffer"));
    let mut ahead = busy_link().parts();
    ahead.acknowledged = ahead.sent + 1;
    assert!(Link::from_parts(ahead).is_err());
}

#[test]
fn the_task_names_the_session_whose_target_opens() {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    assert_eq!(current(), None);
    let seen = runtime.block_on(scope(id(), async { current() }));
    assert_eq!(seen, Some(id()));
}
