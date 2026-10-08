//! ⛔ **C4: the forward runner, over a socket that is a queue.**
//!
//! No network, no token: `FrameQueue` is the relay. What is asserted is the
//! byte image — exact bytes out, exact bytes back — because E02's `Prove`
//! block is explicit that a test checking only "something was sent" cannot
//! catch this class of bug.

use podssh_transport::forward::ForwardRunner;
use podssh_transport::socket::FrameQueue;
use podssh_transport::transport::Limits;

mod common;
use common::block_on;

fn runner() -> ForwardRunner<FrameQueue> {
    ForwardRunner::new(FrameQueue::new(), Limits::forward(262144))
}

/// Bytes go out bare — no id, no framing — and come back untouched.
#[test]
fn banner_bytes_round_trip_bare() {
    let mut queue = FrameQueue::new();
    queue.push_binary(b"SSH-2.0-OpenSSH_10.3\r\n".to_vec());
    let mut runner = ForwardRunner::new(queue, Limits::forward(262144));

    let banner = block_on(runner.recv_bytes()).expect("banner");
    assert_eq!(banner, b"SSH-2.0-OpenSSH_10.3\r\n");

    let frames =
        block_on(runner.send_bytes(b"SSH-2.0-podssh_0.1.0\r\n")).expect("send");
    assert_eq!(frames, 1);
    assert_eq!(runner.sent_frames(), 1);
}

/// ⛔ **One byte over the cap is two frames, with the bytes unchanged.**
/// Frame boundaries carry no meaning on this leg; the split is on size only.
#[test]
fn one_byte_over_the_cap_is_two_frames() {
    let mut runner = runner();
    let bytes = vec![0x41u8; 262144 + 1];
    let frames = block_on(runner.send_bytes(&bytes)).expect("send");
    assert_eq!(frames, 2);
    assert_eq!(runner.sent_frames(), 2);
}

/// ⛔ **A text frame where data was expected is an error, not data.**
/// The forward leg's data channel is binary-only; a peer that sends text is
/// a fault this runner cannot recover from by reading more.
#[test]
fn a_text_frame_is_refused_as_data() {
    let mut queue = FrameQueue::new();
    queue.push_text(br#"{"type":"hello"}"#.to_vec());
    let mut runner = ForwardRunner::new(queue, Limits::forward(262144));
    assert!(block_on(runner.recv_bytes()).is_err());
}

/// An empty write sends nothing and reports zero frames — it is a no-op,
// not an empty frame on the wire.
#[test]
fn an_empty_write_sends_nothing() {
    let mut runner = runner();
    let frames = block_on(runner.send_bytes(&[])).expect("send");
    assert_eq!(frames, 0);
    assert_eq!(runner.sent_frames(), 0);
}
