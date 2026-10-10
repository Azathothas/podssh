//! Two runners of `podssh chat` (T-099) talk over a pipe in memory, and over
//! the end-to-end channel of the roads (T-088): messages both ways, each
//! acknowledged; files of 0, 1 and 200,000 bytes taken into the directory of
//! `--accept-dir`, with equal digests; a file that the user did not accept,
//! never written; a declined file; `--send` and `--file`, which end once
//! done; and a message with no acknowledgement, said at the end.

mod cleanup;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use podssh_cli::chat::output::Output;
use podssh_cli::chat::{converse, Ended, Once, Options, Summary};
use tokio::io::{AsyncWrite, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const LIMIT: Duration = Duration::from_secs(30);
const PIPE: usize = 256 * 1024;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-chat-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// stdout, kept.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// One side of a conversation: its lines, its stdout and its notices.
struct Side {
    lines: Option<mpsc::Sender<String>>,
    stdout: Sink,
    notes: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<Summary>,
}

impl Side {
    fn start(stream: DuplexStream, nick: &str, accept_dir: Option<&Path>, here: &Path, once: Once) -> Side {
        let (tx, rx) = mpsc::channel(64);
        let stdout = Sink::default();
        let notes = Arc::new(Mutex::new(Vec::new()));
        let opts = Options {
            nick: nick.into(),
            accept_dir: accept_dir.map(Path::to_path_buf),
            here: here.to_path_buf(),
            once: once.clone(),
        };
        let (out_sink, kept) = (stdout.clone(), notes.clone());
        let task = tokio::spawn(async move {
            let mut out = Output::new(out_sink, false, move |line| kept.lock().unwrap().push(line));
            converse(stream, rx, &mut out, opts).await
        });
        let lines = matches!(once, Once::No).then_some(tx);
        Side { lines, stdout, notes, task }
    }

    async fn say(&self, line: &str) {
        self.lines.as_ref().unwrap().send(line.to_string()).await.unwrap();
    }

    /// Wait until a notice or stdout holds `needle`.
    async fn wait_for(&self, needle: &str) {
        let deadline = Instant::now() + LIMIT;
        loop {
            let seen =
                self.notes.lock().unwrap().iter().any(|n| n.contains(needle)) || self.stdout.text().contains(needle);
            if seen {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no {needle:?} in {:?} / {:?}",
                self.notes.lock().unwrap(),
                self.stdout.text()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn end(mut self) -> Summary {
        drop(self.lines.take());
        tokio::time::timeout(LIMIT, self.task).await.expect("the conversation ends").unwrap()
    }
}

fn pair() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(PIPE)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sides_talk_and_each_message_is_acknowledged() {
    let here = scratch("talk");
    let (a_end, b_end) = pair();
    let a = Side::start(a_end, "ana", None, &here, Once::No);
    let b = Side::start(b_end, "bo", None, &here, Once::No);
    a.say("hello, bo").await;
    b.say("hi there \u{1b}[2J").await;
    a.say("//not a command").await;
    b.wait_for("ana: hello, bo").await;
    b.wait_for("ana: /not a command").await;
    a.wait_for("bo: hi there").await;
    assert!(!a.stdout.text().contains('\u{1b}'), "the peer's words reach the terminal unsafe");
    let (a, b) = (a.end().await, b.end().await);
    assert_eq!(a, Summary { ended: Ended::Done, undelivered: vec![] });
    assert!(b.undelivered.is_empty() && matches!(b.ended, Ended::Done | Ended::PeerLeft), "{b:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_arrive_whole_into_the_accept_dir() {
    let (here, inbox) = (scratch("files-here"), scratch("files-inbox"));
    let big: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
    for (name, bytes) in [("empty", &b""[..]), ("one", &b"x"[..]), ("big.bin", &big[..])] {
        std::fs::write(here.join(name), bytes).unwrap();
    }
    let (a_end, b_end) = pair();
    let a = Side::start(a_end, "ana", None, &here, Once::No);
    let b = Side::start(b_end, "bo", Some(&inbox), &here, Once::No);
    for name in ["empty", "one", "big.bin"] {
        a.say(&format!("/file {}", here.join(name).display())).await;
    }
    for id in 1..=3 {
        a.wait_for(&format!("file {id} arrived whole")).await;
    }
    for (name, bytes) in [("empty", &b""[..]), ("one", &b"x"[..]), ("big.bin", &big[..])] {
        assert_eq!(std::fs::read(inbox.join(name)).unwrap(), bytes, "{name}");
    }
    let leftovers: Vec<_> = std::fs::read_dir(&inbox).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(leftovers.len(), 3, "no temporary file is left: {leftovers:?}");
    let (a, _) = (a.end().await, b.end().await);
    assert_eq!(a.ended, Ended::Done);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_that_the_user_did_not_accept_is_never_written() {
    let (here, theirs) = (scratch("noaccept-here"), scratch("noaccept-theirs"));
    std::fs::write(here.join("secret.txt"), b"never written").unwrap();
    let (a_end, b_end) = pair();
    let a = Side::start(a_end, "ana", None, &here, Once::No);
    let b = Side::start(b_end, "bo", None, &theirs, Once::No);
    a.say(&format!("/file {}", here.join("secret.txt").display())).await;
    b.wait_for("offers secret.txt (13 bytes) as file 1").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(std::fs::read_dir(&theirs).unwrap().count(), 0, "a file was written with no accept");
    b.say("/decline 1").await;
    a.wait_for("declined file 1").await;
    b.say("/accept 1").await;
    b.wait_for("no file waits under the number 1").await;
    assert_eq!(std::fs::read_dir(&theirs).unwrap().count(), 0);
    let _ = (a.end().await, b.end().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_and_file_end_once_done() {
    let (here, inbox) = (scratch("once-here"), scratch("once-inbox"));
    let (a_end, b_end) = pair();
    let a = Side::start(a_end, "ana", None, &here, Once::Send("ping".into()));
    let b = Side::start(b_end, "bo", None, &here, Once::No);
    b.wait_for("ana: ping").await;
    assert_eq!(a.end().await, Summary { ended: Ended::Done, undelivered: vec![] });
    let _ = b.end().await;

    std::fs::write(here.join("report.txt"), b"the report").unwrap();
    let (a_end, b_end) = pair();
    let a = Side::start(a_end, "ana", None, &here, Once::File(here.join("report.txt")));
    let b = Side::start(b_end, "bo", Some(&inbox), &here, Once::No);
    assert_eq!(a.end().await.ended, Ended::Done);
    assert_eq!(std::fs::read(inbox.join("report.txt")).unwrap(), b"the report");
    let _ = b.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_with_no_acknowledgement_is_said_at_the_end() {
    let here = scratch("lost");
    let (a_end, mut b_end) = pair();
    let a = Side::start(a_end, "ana", None, &here, Once::No);
    a.say("never acknowledged").await;
    // The peer greets and goes, with no acknowledgement.
    use tokio::io::AsyncWriteExt;
    let hello = podssh_core::chat::Session::new().hello("ghost").encode();
    b_end.write_all(&hello).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(b_end);
    let summary = a.end().await;
    assert_eq!(summary, Summary { ended: Ended::PeerLeft, undelivered: vec!["never acknowledged".into()] });
}

/// The same conversation over the end-to-end channel, as the roads carry it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conversation_runs_over_the_end_to_end_channel() {
    use podssh_relay::e2e::ends;
    use podssh_relay::identity::Identity;
    let (here, inbox) = (scratch("e2e-here"), scratch("e2e-inbox"));
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(here.join("big.bin"), &big).unwrap();
    let node = ends::Node::open_to_all(Arc::new(Identity::from_seed(&[2; 32])), Arc::new(|_: String| {}));
    let (link, node_link) = pair();
    let (plain_node_side, chat_b) = pair();
    tokio::spawn(async move {
        ends::serve_node(node_link, &node, move || std::future::ready(Ok::<_, String>(plain_node_side))).await;
    });
    let (chat_a, app) = pair();
    let (cipher, session) = ends::operator(app, Arc::new(Identity::from_seed(&[1; 32])), |_| Ok(()));
    tokio::spawn(session);
    tokio::spawn(async move {
        let (mut a, mut b) = (cipher, link);
        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    });
    let a = Side::start(chat_a, "ana", None, &here, Once::No);
    let b = Side::start(chat_b, "bo", Some(&inbox), &here, Once::No);
    a.say("over the channel").await;
    b.wait_for("ana: over the channel").await;
    a.say(&format!("/file {}", here.join("big.bin").display())).await;
    a.wait_for("file 2 arrived whole").await;
    assert_eq!(std::fs::read(inbox.join("big.bin")).unwrap(), big);
    let _ = (a.end().await, b.end().await);
}

/// A file of the name that the user's directory already has is declined,
/// and the file that is there stays as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_accepted_file_never_goes_over_a_file_that_is_there() {
    let (here, inbox) = (scratch("over-here"), scratch("over-inbox"));
    std::fs::write(here.join("notes.txt"), b"theirs").unwrap();
    std::fs::write(inbox.join("notes.txt"), b"mine, kept").unwrap();
    let (a_end, b_end) = pair();
    let a = Side::start(a_end, "ana", None, &here, Once::No);
    let b = Side::start(b_end, "bo", Some(&inbox), &here, Once::No);
    a.say(&format!("/file {}", here.join("notes.txt").display())).await;
    a.wait_for("declined file 1").await;
    b.wait_for("exists, and podssh writes over no file").await;
    assert_eq!(std::fs::read(inbox.join("notes.txt")).unwrap(), b"mine, kept");
    let _ = (a.end().await, b.end().await);
}

/// A peer whose bytes do not have the SHA-256 that it offered: the file is
/// not kept, and the peer hears so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_whose_digest_differs_is_not_kept() {
    use podssh_core::chat::{Decoder, Record, Session};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (here, inbox) = (scratch("damaged-here"), scratch("damaged-inbox"));
    let (mut liar, b_end) = pair();
    let b = Side::start(b_end, "bo", Some(&inbox), &here, Once::No);
    let offer = Record::Offer { id: 1, size: 4, sha256: [0; 32], name: "fake.bin".into() };
    for record in [Session::new().hello("liar"), offer] {
        liar.write_all(&record.encode()).await.unwrap();
    }
    // Its accept comes; then four bytes that do not have that digest.
    let mut decoder = Decoder::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + LIMIT;
    'accept: loop {
        let n = tokio::time::timeout(LIMIT, liar.read(&mut buf)).await.unwrap().unwrap();
        decoder.push(&buf[..n]);
        while let Some(record) = decoder.next_record().unwrap() {
            if record == (Record::Accept { id: 1 }) {
                break 'accept;
            }
        }
        assert!(Instant::now() < deadline);
    }
    liar.write_all(&Record::Chunk { id: 1, offset: 0, data: b"abcd".to_vec() }.encode()).await.unwrap();
    let done = loop {
        let n = tokio::time::timeout(LIMIT, liar.read(&mut buf)).await.unwrap().unwrap();
        decoder.push(&buf[..n]);
        if let Some(Record::Done { id, whole }) = decoder.next_record().unwrap() {
            break (id, whole);
        }
    };
    assert_eq!(done, (1, false), "the peer hears that the file was not kept");
    b.wait_for("did not match").await;
    assert_eq!(std::fs::read_dir(&inbox).unwrap().count(), 0, "a damaged file, or its temporary file, was kept");
    drop(liar);
    let _ = b.end().await;
}
