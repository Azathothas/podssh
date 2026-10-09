//! The two ends of the resumable layer over in-memory streams (T-151): a
//! client finds a far end with no layer by its first byte and passes the
//! bytes as they are; with the layer, a session carries 1 MiB each way
//! whole; a refusal reaches the client with its reason; and a link with a
//! gap delivers the bytes before the gap and nothing after.

use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use podssh_relay::session::client::{self, ClientError, Found, Outcome};
use podssh_relay::session::far;
use podssh_relay::session::{
    Acceptance, Ask, Decoder, End, HandshakeError, LinkError, OffsetError, OsEntropy, Record, RefuseCode, Role,
    SessionId, Sessions, Settings,
};

const PIPE: usize = 256 * 1024;
const LIMIT: Duration = Duration::from_secs(20);

fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Read records from `link` until one whole record comes.
async fn read_record(link: &mut DuplexStream, decoder: &mut Decoder) -> Record {
    let mut buf = [0u8; 4096];
    loop {
        if let Some(record) = decoder.next().unwrap() {
            return record;
        }
        let n = link.read(&mut buf).await.unwrap();
        assert!(n > 0, "the client closed the link");
        decoder.push(&buf[..n]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_end_with_no_layer_gets_the_bytes_as_they_are() {
    let (client_link, mut server) = tokio::io::duplex(PIPE);
    let started =
        tokio::spawn(async move { client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy).await });
    server.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
    let client = tokio::time::timeout(LIMIT, started).await.unwrap().unwrap().unwrap();
    assert_eq!(client.found(), &Found::Plain { first: Some(b'S') });

    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let run = tokio::spawn(client.run(app_end));
    let mut banner = [0u8; 21];
    app.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-OpenSSH_9.6\r\n");
    app.write_all(b"SSH-2.0-podssh\r\n").await.unwrap();
    let mut line = [0u8; 16];
    server.read_exact(&mut line).await.unwrap();
    assert_eq!(&line, b"SSH-2.0-podssh\r\n", "no record went to a far end with no layer");
    drop(server);
    drop(app);
    let outcome = tokio::time::timeout(LIMIT, run).await.unwrap().unwrap();
    assert!(matches!(outcome, Outcome::Plain(_)), "{outcome:?}");
}

/// A far end of the layer in front of an echo: 1 MiB each way comes back
/// whole, and the client's end of its bytes ends the session at both ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_layer_carries_a_session_both_ways() {
    let (client_link, far_link) = tokio::io::duplex(PIPE);
    let sessions = std::sync::Arc::new(Mutex::new(Sessions::new()));

    let far_sessions = sessions.clone();
    let far_end = tokio::spawn(async move {
        let accepted =
            far::accept(far_link, Role::NODE, Settings::default(), &far_sessions, &mut OsEntropy).await.unwrap();
        // The target is an echo, connected after the handshake.
        let (target, mut echo) = tokio::io::duplex(PIPE);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match echo.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if echo.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = echo.shutdown().await;
        });
        accepted.run(target, &far_sessions).await
    });

    let client = tokio::time::timeout(LIMIT, client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy))
        .await
        .unwrap()
        .unwrap();
    let Found::Layer { peer_role, features, resumed, .. } = client.found().clone() else {
        panic!("{:?}", client.found())
    };
    assert_eq!((peer_role, features, resumed), (Role::NODE, vec!["replay.v1".to_string()], false));
    let id = client.established().unwrap().id;
    assert!(sessions.lock().unwrap().contains(&id));

    let (app, app_end) = tokio::io::duplex(PIPE);
    let run = tokio::spawn(client.run(app_end));
    let sent = pseudo_random(1 << 20, 0x5eed);
    let (mut app_r, mut app_w) = tokio::io::split(app);
    let writer = {
        let sent = sent.clone();
        tokio::spawn(async move {
            app_w.write_all(&sent).await.unwrap();
            app_w
        })
    };
    let mut back = vec![0u8; sent.len()];
    tokio::time::timeout(LIMIT, app_r.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(Sha256::digest(&back), Sha256::digest(&sent));

    let mut app_w = writer.await.unwrap();
    app_w.shutdown().await.unwrap();
    let client_end = tokio::time::timeout(LIMIT, run).await.unwrap().unwrap();
    let Outcome::Layer(ended) = client_end else { panic!("{client_end:?}") };
    assert!(matches!(ended.end, End::LocalEnd), "{ended:?}");
    assert_eq!((ended.received, ended.sent), (1 << 20, 1 << 20));

    let far_ended = tokio::time::timeout(LIMIT, far_end).await.unwrap().unwrap();
    assert!(matches!(far_ended.end, End::Closed(_)), "{far_ended:?}");
    assert_eq!(sessions.lock().unwrap().received(&id), Some(1 << 20));
}

/// A scripted far end: the bytes of a real `GREETING`, then what the test
/// sends.
async fn scripted_far_end(server: &mut DuplexStream) -> Decoder {
    let greeting = Record::Greeting(podssh_relay::session::Hello {
        version: 1,
        role: Role::NODE,
        nonce: podssh_relay::session::Nonce([7; 32]),
        features: vec![],
    });
    server.write_all(&greeting.to_bytes().unwrap()).await.unwrap();
    Decoder::new()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_reaches_the_client_with_its_reason() {
    let (client_link, mut server) = tokio::io::duplex(PIPE);
    let started =
        tokio::spawn(async move { client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy).await });
    let mut decoder = scripted_far_end(&mut server).await;
    let open = read_record(&mut server, &mut decoder).await;
    assert!(matches!(open, Record::Open { .. }), "{open:?}");
    let refusal = Record::Refuse { code: RefuseCode::BUSY, reason: "64 sessions\x1b[2J".into() };
    server.write_all(&refusal.to_bytes().unwrap()).await.unwrap();
    let error = match tokio::time::timeout(LIMIT, started).await.unwrap().unwrap() {
        Err(ClientError::Handshake(e)) => e,
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the client went on"),
    };
    assert_eq!(error, HandshakeError::Refused { code: RefuseCode::BUSY, reason: "64 sessions\x1b[2J".into() });
    // The message is safe to print: no escape reaches the terminal.
    assert_eq!(error.to_string(), "refused (busy): 64 sessions[2J");
}

/// A relay that drops a frame makes a gap: the client delivers each byte
/// before it, and none after, even the bytes that would fill it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gap_ends_the_link_and_nothing_after_it_is_delivered() {
    let (client_link, mut server) = tokio::io::duplex(PIPE);
    let started =
        tokio::spawn(async move { client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy).await });
    let mut decoder = scripted_far_end(&mut server).await;
    let _open = read_record(&mut server, &mut decoder).await;
    // RFC 7748's public key of Bob: any key that is not of low order.
    let public: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83,
        0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ];
    let mut bytes = Record::Accept(Acceptance::New { id: SessionId([1; 16]), public }).to_bytes().unwrap();
    for (offset, data) in [(0u64, &b"abc"[..]), (10, b"klm"), (3, b"defghij")] {
        bytes.extend(Record::Data { offset, bytes: data.to_vec() }.to_bytes().unwrap());
    }
    server.write_all(&bytes).await.unwrap();

    let client = tokio::time::timeout(LIMIT, started).await.unwrap().unwrap().unwrap();
    assert!(matches!(client.found(), Found::Layer { .. }));
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let outcome = tokio::time::timeout(LIMIT, client.run(app_end)).await.unwrap();
    let mut delivered = Vec::new();
    app.read_to_end(&mut delivered).await.unwrap();
    assert_eq!(delivered, b"abc");
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let gap = LinkError::Offset(OffsetError::Gap { expected: 3, got: 10 });
    assert!(matches!(&ended.end, End::Broken(e) if *e == gap), "{ended:?}");
    assert_eq!(ended.received, 3);
}
