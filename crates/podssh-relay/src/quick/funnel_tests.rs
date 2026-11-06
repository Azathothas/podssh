use std::sync::Mutex;

use super::*;

#[test]
fn a_request_closes_and_an_answer_loses_its_chunks() {
    let head = b"GET / HTTP/1.1\r\nHost: a.example\r\nConnection: keep-alive\r\nKeep-Alive: 5\r\n\r\n";
    let closed = String::from_utf8(closing(head)).unwrap();
    assert_eq!(closed, "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n");
    let answer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n";
    assert!(chunked(answer));
    let plain = String::from_utf8(unchunked(answer)).unwrap();
    assert_eq!(plain, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
    assert_eq!(status_of(answer), Some(200));
    assert_eq!(status_of(b"SSH-2.0-x\r\n\r\n"), None);
    assert!(upgrades(b"GET / HTTP/1.1\r\nUpgrade: WebSocket\r\n\r\n"));
    assert!(!upgrades(b"GET / HTTP/1.1\r\n\r\n"));
}

/// A TARGET in memory, which answers `answer` to one request and keeps
/// the request that it read.
fn target(answer: &'static [u8], seen: Arc<Mutex<Vec<u8>>>) -> Dial {
    Arc::new(move || {
        let seen = seen.clone();
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(async move {
                let mut theirs = theirs;
                let (head, _) = read_head(&mut theirs).await.unwrap();
                seen.lock().unwrap().extend_from_slice(&head);
                theirs.write_all(answer).await.unwrap();
                let _ = theirs.shutdown().await;
            });
            Ok(Box::new(ours) as Box<dyn Stream>)
        }) as Dialed
    })
}

/// The origin's side of one request: what the edge's side reads back.
async fn ask(funnel: &Funnel, request: &[u8]) -> Vec<u8> {
    let mut conn = funnel.connect(None);
    conn.write_all(request).await.unwrap();
    let mut got = Vec::new();
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), conn.read_to_end(&mut got)).await;
    read.expect("the answer within 5 s").unwrap();
    got
}

#[tokio::test]
async fn a_chunked_answer_reaches_the_edge_decoded_and_an_interim_one_is_dropped() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answer: &[u8] =
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let funnel = Funnel::new(target(answer, seen.clone()), Arc::new(|_| {}));
    let got = ask(&funnel, b"GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n").await;
    assert_eq!(String::from_utf8(got).unwrap(), "HTTP/1.1 200 OK\r\n\r\nhello world");
    let request = String::from_utf8(seen.lock().unwrap().clone()).unwrap();
    assert!(request.contains("Connection: close\r\n"), "{request}");
}

#[tokio::test]
async fn a_websocket_s_head_and_its_101_pass_unchanged() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answer: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nFRAMES";
    let funnel = Funnel::new(target(answer, seen.clone()), Arc::new(|_| {}));
    let request = b"GET /ws HTTP/1.1\r\nHost: a.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    let got = ask(&funnel, request).await;
    assert!(got.ends_with(b"\r\n\r\nFRAMES"), "{}", String::from_utf8_lossy(&got));
    assert_eq!(seen.lock().unwrap().as_slice(), request, "the upgrade's head as it came");
}

#[tokio::test]
async fn a_target_that_does_not_answer_the_dial_is_a_502_and_a_line() {
    let said = Arc::new(Mutex::new(Vec::new()));
    let lines = said.clone();
    let dial: Dial = Arc::new(|| Box::pin(async { Err("connection refused".to_string()) }) as Dialed);
    let funnel = Funnel::new(dial, Arc::new(move |line| lines.lock().unwrap().push(line)));
    let got = String::from_utf8(ask(&funnel, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await).unwrap();
    assert!(got.starts_with("HTTP/1.1 502 "), "{got}");
    // The line is said once the task ends, after its answer.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(said.lock().unwrap().iter().any(|l| l.contains("connection refused")));
}
