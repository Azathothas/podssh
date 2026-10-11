//! The bounds of what the relay crate reads (T-201): the body of the pool,
//! from a relay host that sends more, and a file of the cache, which a
//! larger file never becomes. The relay host is an in-memory stream.

mod cleanup;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podssh_relay::cache::{load_file_from, load_from, store_file_in_first, store_in_first, MAX_FILE, MIN_REMAINING_MS};
use podssh_relay::pool::{self, MAX_BODY};
use podssh_relay::relay::DEFAULT_RELAY_HOST;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const LIMIT: Duration = Duration::from_secs(30);
const NOW: i64 = 1_900_000_000_000;
const TOKEN: &str = "ephm1.1900000000000.forward.TESTONLYNOTACREDENTIAL";
const HOST: &str = "tcp-us-east-1.ssh.relay.ajam.dev";

/// A `/relays.json` of `size` bytes, with one host and spaces after it.
fn pool_document(size: usize) -> Vec<u8> {
    let mut doc = format!(r#"{{"pool":[{{"host":"{HOST}"}}]}}"#).into_bytes();
    doc.resize(size, b' ');
    doc
}

/// Read the request's head, to its blank line.
async fn request_head(relay: &mut DuplexStream) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match relay.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
}

/// A pool of [`MAX_BODY`] bytes is read; one byte more is refused by its
/// length, before the body is read.
#[tokio::test]
async fn a_pool_body_past_256_kib_is_refused() {
    for (size, fits) in [(MAX_BODY, true), (MAX_BODY + 1, false)] {
        let (mut client, mut relay) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            request_head(&mut relay).await;
            let doc = pool_document(size);
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", doc.len());
            let _ = relay.write_all(head.as_bytes()).await;
            let _ = relay.write_all(&doc).await;
        });
        let got = tokio::time::timeout(LIMIT, pool::request(&mut client, "relay.test", DEFAULT_RELAY_HOST))
            .await
            .expect("the request ends");
        drop(client);
        server.await.unwrap();
        match (got, fits) {
            (Ok(hosts), true) => assert_eq!(hosts, [HOST]),
            (Err(why), false) => assert!(why.contains("larger than allowed"), "{why}"),
            (other, _) => panic!("a pool of {size} bytes: {other:?}"),
        }
    }
}

/// A body with no length that never ends: the read stops past the bound,
/// and the relay host could send no more than the bound and a buffer.
#[tokio::test]
async fn an_endless_pool_body_stops_at_256_kib() {
    let (mut client, mut relay) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        request_head(&mut relay).await;
        let mut sent = 0usize;
        if relay.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
            return sent;
        }
        let chunk = vec![b' '; 4096];
        while sent < 16 * MAX_BODY {
            if relay.write_all(&chunk).await.is_err() {
                break;
            }
            sent += chunk.len();
        }
        sent
    });
    let got = tokio::time::timeout(LIMIT, pool::request(&mut client, "relay.test", DEFAULT_RELAY_HOST))
        .await
        .expect("the request ends");
    drop(client);
    let sent = server.await.unwrap();
    assert!(matches!(&got, Err(why) if why.contains("larger than allowed")), "{got:?}");
    assert!(sent < MAX_BODY + 128 * 1024, "the relay host sent {sent} bytes");
}

/// A new, empty directory of its own for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-limits-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// Spaces at the end of `path` until it holds `size` bytes: JSON still.
fn pad_to(path: &Path, size: u64) {
    let have = std::fs::metadata(path).unwrap().len();
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&vec![b' '; (size - have) as usize]).unwrap();
}

/// A file of the cache of [`MAX_FILE`] bytes is read; one byte more and it
/// is ignored, as a file that the cache makes again: the pool's and a
/// token's.
#[test]
fn a_cache_file_past_64_kib_is_ignored() {
    let dir = scratch("cache");
    let dirs = std::slice::from_ref(&dir);
    let pool = store_file_in_first(dirs, "relay-pool-test.json", br#"{"fetched_ms":1,"hosts":[]}"#).unwrap();
    pad_to(&pool, MAX_FILE);
    assert!(load_file_from(dirs, "relay-pool-test.json").is_some(), "a file of the bound");
    pad_to(&pool, MAX_FILE + 1);
    assert!(load_file_from(dirs, "relay-pool-test.json").is_none(), "a file past the bound");

    let token = store_in_first(dirs, "relay.example", TOKEN, NOW + MIN_REMAINING_MS + 1, "relay.example").unwrap();
    pad_to(&token, MAX_FILE);
    assert!(load_from(dirs, "relay.example", NOW).is_some(), "a token file of the bound");
    pad_to(&token, MAX_FILE + 1);
    assert!(load_from(dirs, "relay.example", NOW).is_none(), "a token file past the bound");
}
