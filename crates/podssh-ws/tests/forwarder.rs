//! The forwarders of T-369 against stand-ins on the loopback: one that
//! takes the target from its query, as Mudlet's Worker does, and one from a
//! first frame of JSON, answered with `{"status":"ok"}` in a binary frame,
//! as ssheasy's proxy does. Through each, 1 MiB each way to an echo server
//! comes back with an equal digest; the forwarder's text frames are notes,
//! never bytes of the stream; a Close before the target's bytes and a
//! failed answer name the forwarder and say why; no request carries a
//! token; a template with one placeholder, or one twice, and a target with
//! `&`, are refused before anything is dialed.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::forwarder::{self, Dial, Ended, Form, ForwarderError, Template};
use podssh_ws::{frame, ProxyChoice, RelaySession, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(30);

/// What a stand-in does once it has the target.
#[derive(Clone)]
enum Act {
    /// Dial it and carry its bytes, after these text frames.
    Carry(Vec<&'static str>),
    /// A Close with this code and reason, as a Worker that cannot reach it.
    Close(u16, &'static str),
    /// The frame form's failure, with this error.
    Fail(&'static str),
}

/// What a stand-in saw: each request's target and headers, each target that
/// it was asked for, and each first frame.
#[derive(Default)]
struct Seen {
    requests: Vec<(String, Vec<(String, String)>)>,
    targets: Vec<(String, u16)>,
    first_frames: Vec<String>,
}

/// A stand-in forwarder of `form` on the loopback: its port, and what it saw.
async fn stand_in(form: Form, act: Act) -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve(tcp, form, act.clone(), kept.clone()));
        }
    });
    (port, seen)
}

/// `%XX` back to its byte, for the host of a query.
fn decoded(text: &str) -> String {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The target of a query, `?host=H&port=P`, as the Worker reads it.
fn query_target(target: &str) -> (String, u16) {
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let get = |name: &str| {
        query.split('&').find_map(|pair| pair.strip_prefix(&format!("{name}="))).map(decoded).unwrap_or_default()
    };
    (get("host"), get("port").parse().unwrap_or(23))
}

async fn serve(mut tcp: TcpStream, form: Form, act: Act, seen: Arc<Mutex<Seen>>) {
    let Ok((head, pending)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
    seen.lock().unwrap().requests.push((head.target.clone(), head.headers.clone()));
    let Ok(key) = podssh_ws::server::check_upgrade(&head) else {
        let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
        return;
    };
    tcp.write_all(&podssh_ws::server::switching(&key)).await.unwrap();
    let session = Arc::new(podssh_ws::server::session(tcp, pending, None));
    let target = match form {
        Form::Query => query_target(&head.target),
        Form::Frame => {
            let Ok(first) = session.read_frame().await else { return };
            let text = String::from_utf8_lossy(&first.payload).into_owned();
            seen.lock().unwrap().first_frames.push(text.clone());
            let doc: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            (doc["Host"].as_str().unwrap_or_default().to_string(), doc["Port"].as_u64().unwrap_or(0) as u16)
        }
    };
    seen.lock().unwrap().targets.push(target.clone());
    match act {
        Act::Close(code, reason) => {
            let _ = session.send_close(code, reason).await;
            let _ = session.read_frame().await;
        }
        Act::Fail(error) => {
            let body = serde_json::json!({ "status": "failed", "error": error }).to_string();
            let _ = session.send_binary(body.as_bytes()).await;
            let _ = session.send_close(1000, "").await;
            let _ = session.read_frame().await;
        }
        Act::Carry(notes) => {
            let Ok(target) = TcpStream::connect((target.0.as_str(), target.1)).await else {
                let _ = session.send_close(1011, "connect failed").await;
                return;
            };
            if form == Form::Frame {
                // ssheasy's answer comes in a binary frame.
                let _ = session.send_binary(br#"{"status":"ok"}"#).await;
            }
            for note in notes {
                let _ = session.send_text(note).await;
            }
            pump(session, target).await;
        }
    }
}

/// The stand-in's copy, both ways, as the Worker's: binary frames to the
/// target, the target's bytes in binary frames, and a Close at its end.
async fn pump(session: Arc<RelaySession<TcpStream>>, target: TcpStream) {
    let (mut rd, mut wr) = target.into_split();
    let s = session.clone();
    let up = tokio::spawn(async move {
        while let Ok(f) = s.read_frame().await {
            match f.opcode {
                frame::OPCODE_BINARY => {
                    if wr.write_all(&f.payload).await.is_err() {
                        break;
                    }
                }
                frame::OPCODE_CLOSE => break,
                _ => {}
            }
        }
        let _ = wr.shutdown().await;
    });
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if session.send_binary(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = session.send_close(1000, "TCP connection closed").await;
    let _ = up.await;
}

/// An echo server on the loopback: its port.
async fn echo() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// The road's settings for a test, its notes kept.
fn dial(notes: &Arc<Mutex<Vec<String>>>) -> Dial<'static> {
    static TRUST: Trust = Trust::Default;
    static PROXY: ProxyChoice = ProxyChoice::Direct;
    let kept = notes.clone();
    Dial {
        trust: &TRUST,
        proxy: &PROXY,
        timeout: LIMIT,
        close_at_end: true,
        note: Arc::new(move |text: &str| kept.lock().unwrap().push(text.to_string())),
    }
}

/// 1 MiB to the echo server through `template`, and what came back: the
/// digests of both, and the end of the session once this side closed it. A
/// WebSocket's Close is no half-close: data may not follow it (RFC 6455
/// section 5.5.1), so the echo is read in full before this side ends.
async fn round_trip(template: &str, target: u16, notes: &Arc<Mutex<Vec<String>>>) -> ([u8; 32], [u8; 32], Ended) {
    let template = Template::parse(template).unwrap();
    let carried = forwarder::open(&template, "127.0.0.1", target, &dial(notes)).await.unwrap();
    let data: Vec<u8> = (0..MIB as u32).map(|i| (i % 251) as u8).collect();
    let sent: [u8; 32] = Sha256::digest(&data).into();
    let (mut rd, mut wr) = tokio::io::split(carried.stream);
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr
    });
    let mut back = vec![0u8; MIB];
    tokio::time::timeout(LIMIT, rd.read_exact(&mut back)).await.expect("the echo within the limit").unwrap();
    let got: [u8; 32] = Sha256::digest(&back).into();
    // Nothing more: the forwarder's notes and answer are not bytes.
    let mut more = [0u8; 1];
    let extra = tokio::time::timeout(Duration::from_millis(300), rd.read(&mut more)).await;
    assert!(extra.is_err(), "a byte that no one sent: {extra:?}");
    let mut wr = writer.await.unwrap();
    wr.shutdown().await.unwrap();
    let started = std::time::Instant::now();
    let end = loop {
        if let Some(end) = carried.status.get() {
            break end;
        }
        assert!(started.elapsed() < LIMIT, "the session did not end");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    (sent, got, end)
}

fn no_token(seen: &Arc<Mutex<Seen>>) {
    for (_, headers) in &seen.lock().unwrap().requests {
        assert!(headers.iter().all(|(name, _)| name != "x-relay-token" && name != "authorization"), "{headers:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_query_form_carries_a_mebibyte_each_way_and_its_notes_stay_out() {
    let target = echo().await;
    let (port, seen) = stand_in(Form::Query, Act::Carry(vec![r#"{"type":"game.connected"}"#])).await;
    let notes = Arc::default();
    let template = format!("ws://127.0.0.1:{port}/?host={{host}}&port={{port}}");
    let (sent, got, end) = round_trip(&template, target, &notes).await;
    assert_eq!(sent, got, "equal digests");
    assert!(matches!(end, Ended::Closed { code: Some(1000), .. }), "{end:?}");
    assert_eq!(*notes.lock().unwrap(), vec![r#"{"type":"game.connected"}"#.to_string()]);
    let seen_now = seen.lock().unwrap();
    assert_eq!(seen_now.requests[0].0, format!("/?host=127.0.0.1&port={target}"));
    assert_eq!(seen_now.targets, vec![("127.0.0.1".to_string(), target)]);
    drop(seen_now);
    no_token(&seen);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_frame_form_sends_the_target_first_and_keeps_the_answer_out() {
    let target = echo().await;
    let (port, seen) = stand_in(Form::Frame, Act::Carry(Vec::new())).await;
    let notes = Arc::default();
    let (sent, got, _) = round_trip(&format!("ws://127.0.0.1:{port}/p"), target, &notes).await;
    assert_eq!(sent, got, "equal digests: the answer is not in the stream");
    let seen_now = seen.lock().unwrap();
    assert_eq!(seen_now.requests[0].0, "/p");
    assert_eq!(seen_now.first_frames, vec![format!(r#"{{"Host":"127.0.0.1","Port":{target}}}"#)]);
    drop(seen_now);
    no_token(&seen);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_before_the_target_s_bytes_names_the_forwarder_and_its_reason() {
    let (port, _) = stand_in(Form::Query, Act::Close(1011, "Connections to port 25 are prohibited")).await;
    let template = Template::parse(&format!("ws://127.0.0.1:{port}/?host={{host}}&port={{port}}")).unwrap();
    let notes = Arc::default();
    let refused = forwarder::open(&template, "github.com", 25, &dial(&notes)).await.unwrap_err();
    assert!(matches!(refused, ForwarderError::Closed { code: Some(1011), .. }), "{refused:?}");
    let line = refused.line(template.shown());
    assert_eq!(
        line,
        format!(
            "the forwarder ws://127.0.0.1:{port}/ closed the WebSocket before the target's bytes: 1011 Connections to \
             port 25 are prohibited"
        )
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_answer_says_why_and_the_session_does_not_start() {
    let (port, _) = stand_in(Form::Frame, Act::Fail("dial tcp 192.0.2.1:22: i/o timeout")).await;
    let template = Template::parse(&format!("ws://127.0.0.1:{port}/p")).unwrap();
    let notes = Arc::default();
    let refused = forwarder::open(&template, "192.0.2.1", 22, &dial(&notes)).await.unwrap_err();
    let line = refused.line(template.shown());
    assert!(line.contains("could not reach the target (failed): dial tcp 192.0.2.1:22: i/o timeout"), "{line}");
    assert!(line.starts_with(&format!("the forwarder ws://127.0.0.1:{port}/p")), "{line}");
}

/// A template that is not one, and a target that would change its URL, are
/// refused before anything is dialed: no stand-in sees a request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_template_or_target_dials_nothing() {
    let (port, seen) = stand_in(Form::Query, Act::Carry(Vec::new())).await;
    for bad in [format!("ws://127.0.0.1:{port}/?host={{host}}"), format!("ws://127.0.0.1:{port}/{{port}}/{{port}}")] {
        assert!(Template::parse(&bad).is_err(), "{bad}");
    }
    let template = Template::parse(&format!("ws://127.0.0.1:{port}/?host={{host}}&port={{port}}")).unwrap();
    let notes = Arc::default();
    let refused = forwarder::open(&template, "a&port=25", 22, &dial(&notes)).await.unwrap_err();
    assert!(matches!(refused, ForwarderError::Target(_)), "{refused:?}");
    assert!(seen.lock().unwrap().requests.is_empty(), "nothing was dialed");
}
