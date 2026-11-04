//! Each channel's window at the target that the handler gives at each data
//! message (podssh's patch): a smaller target withholds the adjusts at once,
//! a larger one is granted at the next message, each channel keeps its own,
//! and a handler that gives none keeps the configured window, as before.
//! russh 0.65.0 adjusted each channel to the configured window alone. And
//! the room left under which a window goes back to its target, which the
//! handler gives too (a later patch): russh's own is half the target.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)] // as in the test suite

use std::collections::HashMap;

use byteorder::{BigEndian, ByteOrder};

use super::tests::{TestHandler, keyboard_interactive_session};
use super::{Handler, Session};
use crate::cert::PublicKeyOrCertificate;
use crate::session::EncryptedState;
use crate::{ChannelId, msg};

const KIB: u32 = 1024;

/// A handler that gives a target for some channels, a room for some, and
/// counts the adjusts that `adjust_window` hears.
#[derive(Default)]
struct Targets {
    of: HashMap<ChannelId, u32>,
    low: HashMap<ChannelId, u32>,
    heard: u32,
}

impl Handler for Targets {
    type Error = crate::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn window_target(&mut self, channel: ChannelId, window: u32) -> u32 {
        self.of.get(&channel).copied().unwrap_or(window)
    }

    fn window_low(&mut self, channel: ChannelId, target: u32) -> u32 {
        self.low.get(&channel).copied().unwrap_or(target / 2)
    }

    fn adjust_window(&mut self, _channel: ChannelId, window: u32) -> u32 {
        self.heard += 1;
        window
    }
}

/// The ends of the session's queues, kept for as long as the test runs.
type Ends = (tokio::sync::mpsc::Sender<super::Msg>, tokio::sync::mpsc::UnboundedReceiver<super::Reply>);

/// A session after the login with a channel that the server confirmed, its
/// window `window` as the client advertised it.
fn with_channel(window: u32) -> (Session, ChannelId, Ends) {
    let (mut session, sender, replies) = keyboard_interactive_session();
    let id = open(&mut session, window);
    (session, id, (sender, replies))
}

fn open(session: &mut Session, window: u32) -> ChannelId {
    let enc = session.common.encrypted.as_mut().unwrap();
    enc.state = EncryptedState::Authenticated;
    let id = enc.new_channel(window, 32 * KIB);
    let channel = enc.channels.get_mut(&id).unwrap();
    channel.confirmed = true;
    channel.recipient_channel = 40 + id.0;
    id
}

/// CHANNEL_DATA of `len` bytes on `id`.
fn data(id: ChannelId, len: u32) -> Vec<u8> {
    let mut packet = vec![msg::CHANNEL_DATA];
    packet.extend_from_slice(&id.0.to_be_bytes());
    packet.extend_from_slice(&len.to_be_bytes());
    packet.resize(packet.len() + len as usize, 0);
    packet
}

/// CHANNEL_EXTENDED_DATA (stderr) of `len` bytes on `id`.
fn extended(id: ChannelId, len: u32) -> Vec<u8> {
    let mut packet = vec![msg::CHANNEL_EXTENDED_DATA];
    packet.extend_from_slice(&id.0.to_be_bytes());
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&len.to_be_bytes());
    packet.resize(packet.len() + len as usize, 0);
    packet
}

/// The adjusts written since the last call, as (recipient channel, bytes).
fn adjusts(session: &mut Session) -> Vec<(u32, u32)> {
    let enc = session.common.encrypted.as_mut().unwrap();
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= enc.write.len() {
        let len = BigEndian::read_u32(&enc.write[at..]) as usize;
        let payload = &enc.write[at + 4..at + 4 + len];
        if payload[0] == msg::CHANNEL_WINDOW_ADJUST {
            out.push((BigEndian::read_u32(&payload[1..]), BigEndian::read_u32(&payload[5..])));
        }
        at += 4 + len;
    }
    enc.write.clear();
    out
}

#[tokio::test]
async fn a_smaller_target_withholds_the_adjust_until_half_of_it_is_left() {
    let (mut session, id, _ends) = with_channel(64 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(id, 16 * KIB);
    // 56 KiB of 64 come with no adjust: 8 KiB left is not under half of 16.
    for _ in 0..7 {
        session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    }
    assert_eq!(adjusts(&mut session), vec![]);
    // The last 8 KiB leave none: the window goes back to 16 KiB, not to the
    // configured 2 MiB.
    session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 16 * KIB)]);
    assert_eq!(handler.heard, 1, "adjust_window hears each adjust that went out");
    // From now on each adjust tops the window up to 16 KiB again.
    session.process_packet(&mut handler, &data(id, 12 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 12 * KIB)]);
}

#[tokio::test]
async fn a_larger_target_is_granted_at_the_next_message() {
    let (mut session, id, _ends) = with_channel(64 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(id, 16 * KIB);
    session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![]);
    // The target grows to 4 MiB: the next message brings the window to it.
    handler.of.insert(id, 4096 * KIB);
    session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 4096 * KIB - 48 * KIB)]);
}

#[tokio::test]
async fn stderr_counts_against_the_same_target() {
    let (mut session, id, _ends) = with_channel(16 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(id, 16 * KIB);
    session.process_packet(&mut handler, &extended(id, 6 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![]);
    session.process_packet(&mut handler, &extended(id, 6 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 12 * KIB)]);
}

#[tokio::test]
async fn each_channel_keeps_its_own_target() {
    let (mut session, small, _ends) = with_channel(64 * KIB);
    let large = open(&mut session, 64 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(small, 16 * KIB);
    handler.of.insert(large, 1024 * KIB);
    session.process_packet(&mut handler, &data(small, 8 * KIB)).await.unwrap();
    session.process_packet(&mut handler, &data(large, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + large.0, 1024 * KIB - 56 * KIB)]);
}

/// The control: a handler that gives no target, or 0, keeps the configured
/// window (2 MiB, russh's default), as russh 0.65.0 did.
#[tokio::test]
async fn a_handler_that_gives_no_target_keeps_the_configured_window() {
    let (mut session, id, _ends) = with_channel(64 * KIB);
    session.process_packet(&mut TestHandler, &data(id, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 2048 * KIB - 56 * KIB)]);

    let (mut session, id, _ends) = with_channel(64 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(id, 0);
    session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 2048 * KIB - 56 * KIB)]);
}

/// The handler's room: with a quarter of a target of 64 KiB used, the window
/// goes back to the target once less than 48 KiB is left; with russh's own,
/// half, once less than 32 KiB is.
#[tokio::test]
async fn a_handlers_room_adjusts_the_window_once_it_is_under_it() {
    let (mut session, quarter, _ends) = with_channel(64 * KIB);
    let half = open(&mut session, 64 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(quarter, 64 * KIB);
    handler.of.insert(half, 64 * KIB);
    handler.low.insert(quarter, 48 * KIB);
    for _ in 0..2 {
        session.process_packet(&mut handler, &data(quarter, 8 * KIB)).await.unwrap();
    }
    assert_eq!(adjusts(&mut session), vec![], "48 KiB left is not under 48 KiB");
    session.process_packet(&mut handler, &data(quarter, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + quarter.0, 24 * KIB)]);
    for _ in 0..4 {
        session.process_packet(&mut handler, &data(half, 8 * KIB)).await.unwrap();
    }
    assert_eq!(adjusts(&mut session), vec![], "32 KiB left is not under half of 64");
    session.process_packet(&mut handler, &data(half, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + half.0, 40 * KIB)]);
    assert_eq!(handler.heard, 2, "adjust_window hears each adjust that went out");
}

/// A room over the target is the target: a window granted before, larger
/// than the target, is not taken back, and once less than the target is
/// left each message tops it up.
#[tokio::test]
async fn a_room_over_the_target_is_the_target() {
    let (mut session, id, _ends) = with_channel(64 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(id, 16 * KIB);
    handler.low.insert(id, u32::MAX);
    session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![], "56 KiB left is over the target of 16");
    for _ in 0..6 {
        session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    }
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 8 * KIB)]);
    session.process_packet(&mut handler, &data(id, 4 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 4 * KIB)]);
}

/// A room of 0 keeps russh's own, half the target, as a handler that gives
/// none does (the control above, with the configured window).
#[tokio::test]
async fn a_room_of_0_keeps_russhs_half() {
    let (mut session, id, _ends) = with_channel(64 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(id, 64 * KIB);
    handler.low.insert(id, 0);
    for _ in 0..4 {
        session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    }
    assert_eq!(adjusts(&mut session), vec![]);
    session.process_packet(&mut handler, &data(id, 8 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 40 * KIB)]);
}

#[tokio::test]
async fn stderr_is_adjusted_under_the_same_room() {
    let (mut session, id, _ends) = with_channel(16 * KIB);
    let mut handler = Targets::default();
    handler.of.insert(id, 16 * KIB);
    handler.low.insert(id, 12 * KIB);
    session.process_packet(&mut handler, &extended(id, 4 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![], "12 KiB left is not under 12 KiB");
    session.process_packet(&mut handler, &extended(id, 2 * KIB)).await.unwrap();
    assert_eq!(adjusts(&mut session), vec![(40 + id.0, 6 * KIB)]);
}
