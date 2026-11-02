//! The reach of a later hop of `-J` (T-462): the mark of the first byte,
//! the lines of `-v` while nothing comes, and the words of each failure.

use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

fn reach(limit: u64) -> Reach {
    let hop = Hop { host: "10.0.0.5".into(), port: 22, user: None, tls: false };
    Reach::new("jump.example:443".into(), &hop, Duration::from_secs(limit))
}

/// The mark stays down until a byte is read, and russh's writes leave it.
#[tokio::test]
async fn the_first_byte_read_marks_the_stream() {
    let (ours, mut theirs) = tokio::io::duplex(1024);
    let mut stream = Heard::new(ours);
    let heard = stream.heard();
    stream.write_all(b"SSH-2.0-podssh\r\n").await.unwrap();
    assert!(!heard.load(Ordering::Relaxed), "a write is no byte heard");
    theirs.write_all(b"S").await.unwrap();
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await.unwrap();
    assert!(heard.load(Ordering::Relaxed));
}

/// A stream that ends with nothing leaves the mark down.
#[tokio::test]
async fn a_stream_that_ends_with_nothing_is_never_heard() {
    let (ours, theirs) = tokio::io::duplex(1024);
    let mut stream = Heard::new(ours);
    let heard = stream.heard();
    drop(theirs);
    let mut rest = Vec::new();
    assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
    assert!(!heard.load(Ordering::Relaxed));
}

/// `-v`'s line each 10 s while nothing came, and none once a byte came.
#[tokio::test(start_paused = true)]
async fn the_wait_is_said_each_10_s_until_a_byte_comes() {
    let reach = reach(60);
    let heard = Arc::new(AtomicBool::new(false));
    let said = Arc::new(Mutex::new(Vec::new()));
    let (mark, into) = (heard.clone(), said.clone());
    let waiting = tokio::spawn(async move {
        let say = move |line: String| into.lock().unwrap().push(line);
        reach.waiting(&mark, &say).await;
    });
    tokio::time::sleep(Duration::from_secs(25)).await;
    let lines = said.lock().unwrap().clone();
    assert_eq!(
        lines,
        [
            "nothing yet from 10.0.0.5:22 through the hop jump.example:443, after 10 s",
            "nothing yet from 10.0.0.5:22 through the hop jump.example:443, after 20 s",
        ]
    );
    heard.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert!(waiting.is_finished(), "the wait ends once a byte came");
    assert_eq!(said.lock().unwrap().len(), 2, "no line after the byte");
}

/// A login that heard nothing names the hop and its channel: past the
/// limit as the silence of GitHub #86, before it as a channel that closed;
/// a login that heard a byte keeps its own words.
#[tokio::test(start_paused = true)]
async fn a_login_that_heard_nothing_names_the_hop() {
    let log = Log::new(crate::options::LogLevel::Quiet);
    let reach = reach(3);
    let timed_out = async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        Err::<(), _>(HopError::Unreachable("10.0.0.5: the SSH handshake did not finish within 3 s".into()))
    };
    let silent = reach.login(Arc::new(AtomicBool::new(false)), timed_out, &log).await.unwrap_err().to_string();
    assert_eq!(
        silent,
        "the hop jump.example:443 opened its channel to 10.0.0.5:22, and no byte came on it within 3 s: no SSH \
         server answered behind the hop"
    );
    let closed = async { Err::<(), _>(HopError::Unreachable("10.0.0.5: the connection closed unexpectedly".into())) };
    let closed = reach.login(Arc::new(AtomicBool::new(false)), closed, &log).await.unwrap_err().to_string();
    assert_eq!(
        closed,
        "the hop jump.example:443 opened its channel to 10.0.0.5:22, and it closed before any byte came: no SSH \
         server answered behind the hop"
    );
    let heard = async { Err::<(), _>(HopError::Unreachable("10.0.0.5: the SSH handshake did not finish".into())) };
    let kept = reach.login(Arc::new(AtomicBool::new(true)), heard, &log).await.unwrap_err().to_string();
    assert_eq!(kept, "10.0.0.5: the SSH handshake did not finish");
    let refused = async { Err::<(), _>(HopError::Auth("Permission denied".into())) };
    let auth = reach.login(Arc::new(AtomicBool::new(false)), refused, &log).await.unwrap_err();
    assert_eq!(auth, HopError::Auth("Permission denied".into()), "only a failure to reach is read so");
}

/// A hop that never answers the open: its line names the hop and the
/// target.
#[test]
fn an_unanswered_open_names_the_hop_and_the_target() {
    assert_eq!(
        reach(60).unanswered(),
        "the hop jump.example:443 did not answer the open of a channel to 10.0.0.5:22 within 60 s"
    );
}
