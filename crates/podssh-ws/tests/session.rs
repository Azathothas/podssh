//! `RelaySession` against a scripted peer on an in-memory stream: full duplex,
//! control frames, fragmentation, the closing handshake, and timeouts.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::session::{close_code_and_reason, close_payload, RelaySession};
use podssh_ws::SessionError;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// A frame as the relay (the server) sends it: unmasked.
fn from_server(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    frame::encode(&Frame { fin, opcode, payload: payload.to_vec() }, Role::Server, [0; 4])
}

/// Read the next frame podssh (the client) wrote.
async fn next_from_client(peer: &mut DuplexStream, buf: &mut Vec<u8>) -> Frame {
    loop {
        if let Some((f, used)) = frame::decode(buf, Role::Client).expect("a valid client frame") {
            buf.drain(..used);
            return f;
        }
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut chunk))
            .await
            .expect("a client frame within 5 s")
            .unwrap();
        assert!(n > 0, "the client closed the stream");
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn session(stream: DuplexStream, idle: Option<Duration>) -> Arc<RelaySession<DuplexStream>> {
    Arc::new(RelaySession::new(stream, Vec::new(), idle, Duration::from_secs(5)))
}

#[tokio::test]
async fn a_pending_read_does_not_block_a_send() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let s = session(client, None);
    let reader = s.clone();
    let read = tokio::spawn(async move { reader.read_frame().await });
    tokio::time::sleep(Duration::from_millis(50)).await; // the read is now waiting

    tokio::time::timeout(Duration::from_secs(2), s.send_binary(b"keystroke"))
        .await
        .expect("a send must not wait for the pending read")
        .unwrap();
    let mut buf = Vec::new();
    let sent = next_from_client(&mut peer, &mut buf).await;
    assert_eq!((sent.opcode, sent.payload.as_slice()), (frame::OPCODE_BINARY, &b"keystroke"[..]));

    peer.write_all(&from_server(frame::OPCODE_BINARY, true, b"echo")).await.unwrap();
    let got = read.await.unwrap().unwrap();
    assert_eq!(got.payload, b"echo");
}

#[tokio::test]
async fn bytes_that_arrived_with_the_upgrade_are_read_first() {
    let (client, _peer) = tokio::io::duplex(1024);
    let early = from_server(frame::OPCODE_BINARY, true, b"SSH-2.0-banner");
    let s = RelaySession::new(client, early, None, Duration::from_secs(5));
    assert_eq!(s.read_frame().await.unwrap().payload, b"SSH-2.0-banner");
}

#[tokio::test]
async fn a_ping_is_answered_and_never_returned() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let s = session(client, None);
    peer.write_all(&from_server(frame::OPCODE_PING, true, b"are you there")).await.unwrap();
    peer.write_all(&from_server(frame::OPCODE_PONG, true, b"stray pong")).await.unwrap();
    peer.write_all(&from_server(frame::OPCODE_BINARY, true, b"data")).await.unwrap();

    assert_eq!(s.read_frame().await.unwrap().payload, b"data");
    let mut buf = Vec::new();
    let pong = next_from_client(&mut peer, &mut buf).await;
    assert_eq!((pong.opcode, pong.payload.as_slice()), (frame::OPCODE_PONG, &b"are you there"[..]));
}

#[tokio::test]
async fn empty_frames_are_delivered_as_empty_data() {
    // The relay's keepalives are zero-length binary frames; the session hands
    // them over and the caller decides to skip them.
    let (client, mut peer) = tokio::io::duplex(1024);
    let s = session(client, None);
    peer.write_all(&from_server(frame::OPCODE_BINARY, true, b"")).await.unwrap();
    let f = s.read_frame().await.unwrap();
    assert_eq!((f.opcode, f.payload.len()), (frame::OPCODE_BINARY, 0));
}

#[tokio::test]
async fn fragments_are_reassembled_around_control_frames() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let s = session(client, None);
    peer.write_all(&from_server(frame::OPCODE_BINARY, false, b"ab")).await.unwrap();
    peer.write_all(&from_server(frame::OPCODE_PING, true, b"")).await.unwrap();
    peer.write_all(&from_server(frame::OPCODE_CONTINUATION, false, b"cd")).await.unwrap();
    peer.write_all(&from_server(frame::OPCODE_CONTINUATION, true, b"ef")).await.unwrap();
    let f = s.read_frame().await.unwrap();
    assert_eq!((f.fin, f.opcode, f.payload.as_slice()), (true, frame::OPCODE_BINARY, &b"abcdef"[..]));
}

#[tokio::test]
async fn a_continuation_with_nothing_to_continue_is_an_error() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let s = session(client, None);
    peer.write_all(&from_server(frame::OPCODE_CONTINUATION, true, b"x")).await.unwrap();
    let err = s.read_frame().await.unwrap_err();
    assert!(matches!(err, SessionError::Protocol(_)), "{err:?}");
    assert!(err.to_string().contains("continuation"), "{err}");
}

#[tokio::test]
async fn a_close_from_the_relay_is_returned_and_echoed_once() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let s = session(client, None);
    peer.write_all(&from_server(frame::OPCODE_CLOSE, true, &close_payload(Some(1000), "session ended"))).await.unwrap();

    let close = s.read_frame().await.unwrap();
    assert_eq!(close.opcode, frame::OPCODE_CLOSE);
    assert_eq!(close_code_and_reason(&close.payload), (Some(1000), "session ended".to_string()));
    assert!(s.close_sent(), "receiving a Close must answer it");

    let mut buf = Vec::new();
    let echo = next_from_client(&mut peer, &mut buf).await;
    assert_eq!(echo.opcode, frame::OPCODE_CLOSE);
    assert_eq!(close_code_and_reason(&echo.payload).0, Some(1000));

    // A later close is a no-op: one Close per session.
    s.send_close(1000, "again").await.unwrap();
    drop(s);
    let mut rest = Vec::new();
    peer.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty() && buf.is_empty(), "a second Close was sent");
}

#[tokio::test]
async fn send_close_puts_the_code_and_reason_on_the_wire() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let s = session(client, None);
    s.send_close(1000, "bye").await.unwrap();
    let mut buf = Vec::new();
    let f = next_from_client(&mut peer, &mut buf).await;
    assert_eq!(f.opcode, frame::OPCODE_CLOSE);
    assert_eq!(close_code_and_reason(&f.payload), (Some(1000), "bye".to_string()));
}

#[test]
fn a_close_reason_is_cut_to_fit_a_control_frame_on_a_character_boundary() {
    let long = "é".repeat(100); // 200 bytes
    let p = close_payload(Some(1001), &long);
    assert!(p.len() <= frame::MAX_CONTROL_PAYLOAD, "{} bytes", p.len());
    assert!(std::str::from_utf8(&p[2..]).is_ok(), "the reason was cut inside a character");
    assert!(close_payload(None, "ignored").is_empty());
}

#[tokio::test]
async fn an_idle_link_times_out_instead_of_hanging() {
    let (client, _peer) = tokio::io::duplex(1024);
    let s = session(client, Some(Duration::from_millis(100)));
    let started = std::time::Instant::now();
    let err = s.read_frame().await.unwrap_err();
    assert!(matches!(err, SessionError::Idle(_)), "{err:?}");
    assert!(err.to_string().contains("no data from the relay"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn end_of_stream_without_a_close_is_an_error() {
    let (client, peer) = tokio::io::duplex(1024);
    let s = session(client, None);
    drop(peer);
    let err = s.read_frame().await.unwrap_err();
    assert!(matches!(err, SessionError::ClosedWithoutClose(_)), "{err:?}");
    assert!(err.to_string().contains("without a WebSocket Close"), "{err}");
}

/// A peer that never reads: the write stalls, and its limit ends it.
#[tokio::test]
async fn a_write_to_a_peer_that_never_reads_stalls_and_ends() {
    let (client, _peer) = tokio::io::duplex(64);
    let s = RelaySession::new(client, Vec::new(), None, Duration::from_millis(100));
    let err = tokio::time::timeout(Duration::from_secs(5), s.send_binary(&[0u8; 4096]))
        .await
        .expect("the write limit ends the write")
        .unwrap_err();
    assert!(matches!(err, SessionError::WriteStalled(_)), "{err:?}");
    assert!(err.to_string().contains("stalled"), "{err}");
}

/// A close reason is the peer's text and is printed; controls are removed.
#[test]
fn a_close_reason_cannot_carry_terminal_controls() {
    let mut payload = 1000u16.to_be_bytes().to_vec();
    payload.extend_from_slice(b"bye\x1b]0;owned\x07\rnow");
    assert_eq!(close_code_and_reason(&payload), (Some(1000), "bye]0;owned now".to_string()));
}

/// A scripted relay for the liveness tests: answers the first `pongs` Pings,
/// ignores the rest, and sends a data frame every `chatter` if one is given.
fn scripted_relay(peer: DuplexStream, pongs: usize, chatter: Option<Duration>) {
    let (mut rd, mut wr) = tokio::io::split(peer);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let tx_chatter = tx.clone();
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
    if let Some(every) = chatter {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                if tx_chatter.send(from_server(frame::OPCODE_BINARY, true, b"data")).is_err() {
                    break;
                }
            }
        });
    }
    tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut answered = 0;
        loop {
            if let Some((f, used)) = frame::decode(&buf, Role::Client).expect("a valid client frame") {
                buf.drain(..used);
                if f.opcode == frame::OPCODE_PING && answered < pongs {
                    answered += 1;
                    let _ = tx.send(from_server(frame::OPCODE_PONG, true, &f.payload));
                }
                continue;
            }
            let mut chunk = [0u8; 4096];
            match rd.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    });
}

fn keep_reading(s: &Arc<RelaySession<DuplexStream>>) {
    let reader = s.clone();
    tokio::spawn(async move { while reader.read_frame().await.is_ok() {} });
}

/// A link that answers a ping and then goes silent is declared dead after the
/// allowed silent intervals, long before any idle read limit.
#[tokio::test]
async fn a_link_that_goes_silent_is_found_dead_by_pinging() {
    let (client, peer) = tokio::io::duplex(64 * 1024);
    scripted_relay(peer, 1, None);
    let s = session(client, None);
    keep_reading(&s);
    let reason = tokio::time::timeout(Duration::from_secs(2), s.watch_liveness(Duration::from_millis(50), 3))
        .await
        .expect("a silent link must be declared dead");
    assert!(matches!(reason, SessionError::Dead(_)), "{reason:?}");
    assert!(reason.to_string().contains("dead"), "{reason}");
    assert_eq!(s.pongs_received(), 1);
}

/// A relay that never answers pings is not mistaken for a dead one.
#[tokio::test]
async fn a_relay_that_never_answers_pings_is_not_declared_dead() {
    let (client, peer) = tokio::io::duplex(64 * 1024);
    scripted_relay(peer, 0, None);
    let s = session(client, None);
    keep_reading(&s);
    let outcome =
        tokio::time::timeout(Duration::from_millis(600), s.watch_liveness(Duration::from_millis(50), 3)).await;
    assert!(outcome.is_err(), "declared dead without ever seeing a pong: {outcome:?}");
}

/// Pongs can wait behind a large upload; data still arriving means the link
/// is alive.
#[tokio::test]
async fn data_arriving_keeps_a_link_alive_when_pongs_stop() {
    let (client, peer) = tokio::io::duplex(64 * 1024);
    scripted_relay(peer, 1, Some(Duration::from_millis(30)));
    let s = session(client, None);
    keep_reading(&s);
    let outcome =
        tokio::time::timeout(Duration::from_millis(600), s.watch_liveness(Duration::from_millis(50), 3)).await;
    assert!(outcome.is_err(), "declared dead while data was arriving: {outcome:?}");
    assert!(s.frames_received() > 3);
}
