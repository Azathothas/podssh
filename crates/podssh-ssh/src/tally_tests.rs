use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// A known number of bytes each way through a forward's copy: its counts
/// say them once, with one connection opened and ended.
#[tokio::test]
async fn forward_counts_the_bytes_each_way_once() {
    let counts = of("-L forward-counts-test:1");
    let (local, mut client) = tokio::io::duplex(64 * 1024);
    let (channel, mut server) = tokio::io::duplex(64 * 1024);
    let copying = tokio::spawn({
        let counts = counts.clone();
        async move { copy(local, channel, &counts).await }
    });
    let up = vec![7u8; 262_144];
    let talk = async {
        client.write_all(&up).await.unwrap();
        client.shutdown().await.unwrap();
        let mut back = Vec::new();
        client.read_to_end(&mut back).await.unwrap();
        back
    };
    let echo = async {
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        server.write_all(&got[..1000]).await.unwrap();
        server.shutdown().await.unwrap();
        got.len()
    };
    let (back, got) = tokio::join!(talk, echo);
    assert_eq!((got, back.len()), (262_144, 1000));
    copying.await.unwrap().unwrap();
    assert_eq!(counts.line(), "1 connection (0 open, 0 failed), 262144 bytes up, 1000 bytes down");
}

/// One name, one forward: its counts go on across connections; a failure
/// counts too; and `~#` lists each forward in the order of its first use.
#[test]
fn forward_counts_one_name_and_the_listing() {
    let a = of("-R forward-counts-test:2");
    a.failed();
    {
        let _first = a.connection();
        let _second = a.connection();
        assert!(a.line().starts_with("2 connections (2 open, 1 failed)"), "{}", a.line());
    }
    assert!(of("-R forward-counts-test:2").line().starts_with("2 connections (0 open, 1 failed)"));
    of("-W forward-counts-test:3").add_up(5);
    let listing = listing();
    let first = listing.find("-R forward-counts-test:2:").expect("listed");
    let second = listing.find("-W forward-counts-test:3: 0 connections").expect("listed");
    assert!(listing.starts_with("The forwards of this session:\n") && first < second, "{listing}");
    assert!(listing.contains(", 5 bytes up, 0 bytes down"), "{listing}");
}

/// `~#` asks for the list, and `~?` names it.
#[test]
fn forward_counts_are_asked_with_tilde_hash() {
    let mut escapes = crate::escape::Escapes::new(b'~');
    let (out, commands) = escapes.feed(b"~#ls\r");
    assert_eq!((out.as_slice(), commands.as_slice()), (&b"ls\r"[..], &[crate::escape::Command::List][..]));
    assert!(escapes.help().contains("~#   - list forwarded connections"), "{}", escapes.help());
}
