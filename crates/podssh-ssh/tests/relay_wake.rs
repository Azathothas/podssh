//! The forward road asks the relay when this host wakes (T-663), on tokio's
//! paused clock. A tick of the clocks that comes more than 2 s late, as
//! after a sleep or a stop of the process, sends the relay stream's Ping of
//! a question with no key typed, so the notice of a silent relay (T-307)
//! comes within its wait of the wake. While the ticks come on time, nothing
//! is sent. A planted relay stream that does not run the check fails it.

use std::time::Duration;

use podssh_ssh::relay_stream::spawn;
use podssh_ws::frame::{decode, Frame, Role, OPCODE_PING};
use podssh_ws::RelaySession;
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::time::Instant;

/// The payload of the relay stream's question, which no Ping of
/// `podssh ping` carries.
const ASK: &[u8] = b"podssh-ask";
/// The notice's wait for an answer (`hearing::WAIT` of the layer).
const WAIT: Duration = Duration::from_secs(5);

/// The next frame that the relay reads within `within`, if one comes.
async fn frame_up(relay: &mut DuplexStream, within: Duration) -> Option<Frame> {
    let mut wire = Vec::new();
    let deadline = Instant::now() + within;
    loop {
        if let Some((frame, _)) = decode(&wire, Role::Client).expect("a frame") {
            return Some(frame);
        }
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout_at(deadline, relay.read(&mut buf)).await.ok()?.expect("read");
        assert!(n > 0, "the relay stream ended");
        wire.extend_from_slice(&buf[..n]);
    }
}

#[tokio::test(start_paused = true)]
async fn a_tick_that_comes_late_asks_the_relay_at_once_and_a_tick_on_time_asks_nothing() {
    let (ours, mut relay) = tokio::io::duplex(1 << 20);
    let session = RelaySession::new(ours, Vec::new(), None, Duration::from_secs(5));
    let (_ssh, status) = spawn(session);
    // Three ticks on time: no frame, and no question.
    assert!(frame_up(&mut relay, Duration::from_secs(3)).await.is_none(), "nothing asked on time");
    assert_eq!(status.silent(Instant::now(), Duration::ZERO), None, "no question waits");

    // The host was away 4 s that the timers did not count.
    tokio::time::advance(Duration::from_secs(4)).await;
    let woke = Instant::now();
    let asked = frame_up(&mut relay, Duration::from_millis(100)).await.expect("asked at once");
    assert_eq!((asked.opcode, &asked.payload[..]), (OPCODE_PING, ASK));

    // The question counts from the wake: the notice comes after its wait.
    assert_eq!(status.silent(Instant::now(), WAIT), None, "a young question");
    tokio::time::sleep_until(woke + WAIT).await;
    let silent = status.silent(Instant::now(), WAIT).expect("the relay said nothing to the question");
    assert!(silent >= WAIT, "{silent:?}");
}
