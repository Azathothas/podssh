//! Files of `podssh chat --irc` (T-252) between two conversations, through
//! a relay in this test that speaks as much IRC as a channel needs: the
//! welcome, the `JOIN`, `PING`, and each `PRIVMSG` to the channel or to one
//! nick, with its sender's prefix, as a server relays it. The core's chunks
//! were measured against real servers (T-097); here the conversation's part
//! is tested: the offer to the channel, the accept, the chunks between the two
//! nicks alone, the digest and the word that the file was kept.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_cli::chat::irc::{irc_converse, IrcOptions, IrcSummary};
use podssh_cli::chat::output::Output;
use podssh_cli::chat::{Ended, Lines, Once};
use podssh_core::irc::{ReapPolicy, Server, Session};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::mpsc;

const LIMIT: Duration = Duration::from_secs(60);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-chat-irc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

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

/// The relay: each client's lines, answered or passed on.
fn relay(clients: Vec<(String, DuplexStream)>) {
    relay_with(clients, false);
}

/// The relay; with `corrupt`, it changes one character of the payload of
/// the first chunk, as a hop that damages a line would.
fn relay_with(clients: Vec<(String, DuplexStream)>, corrupt: bool) {
    let (tx, mut rx) = mpsc::unbounded_channel::<(String, String)>();
    let mut writers = HashMap::new();
    for (nick, stream) in clients {
        let (read, write) = tokio::io::split(stream);
        writers.insert(nick.to_ascii_lowercase(), write);
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send((nick.clone(), line));
            }
        });
    }
    tokio::spawn(async move {
        let mut joined: Vec<String> = Vec::new();
        let mut damaged = false;
        while let Some((nick, line)) = rx.recv().await {
            let prefix = format!(":{nick}!u@relay.test");
            let mut out: Vec<(String, String)> = Vec::new();
            let mut words = line.splitn(2, ' ');
            let verb = words.next().unwrap_or_default().to_ascii_uppercase();
            let rest = words.next().unwrap_or_default();
            match verb.as_str() {
                "CAP" if rest.starts_with("LS") => {
                    out.push((nick.clone(), ":relay.test CAP * LS :multi-prefix".into()))
                }
                "USER" => out.push((nick.clone(), format!(":relay.test 001 {nick} :Welcome {nick}"))),
                "PING" => out.push((nick.clone(), format!(":relay.test PONG relay.test {rest}"))),
                "JOIN" => {
                    let channel = rest.trim_start_matches(':').to_string();
                    joined.push(nick.clone());
                    for member in &joined {
                        out.push((member.clone(), format!("{prefix} JOIN :{channel}")));
                    }
                }
                "PRIVMSG" => {
                    let (target, _) = rest.split_once(' ').unwrap_or((rest, ""));
                    let mut relayed = format!("{prefix} PRIVMSG {rest}");
                    if corrupt && !damaged && relayed.contains("|chunk|") {
                        damaged = true;
                        let at = relayed.rfind('|').unwrap() + 1;
                        let c = if relayed.as_bytes()[at] == b'A' { "B" } else { "A" };
                        relayed.replace_range(at..at + 1, c);
                    }
                    if target.starts_with('#') {
                        for member in joined.iter().filter(|m| **m != nick) {
                            out.push((member.clone(), relayed.clone()));
                        }
                    } else {
                        out.push((target.to_string(), relayed));
                    }
                }
                _ => {}
            }
            for (to, text) in out {
                if let Some(writer) = writers.get_mut(&to.to_ascii_lowercase()) {
                    let _ = writer.write_all(format!("{text}\r\n").as_bytes()).await;
                }
            }
        }
    });
}

struct Run {
    task: tokio::task::JoinHandle<IrcSummary>,
    notes: Arc<Mutex<Vec<String>>>,
}

fn start(end: DuplexStream, nick: &str, once: Once, accept_dir: Option<&Path>, here: &Path, mut lines: Lines) -> Run {
    let notes = Arc::new(Mutex::new(Vec::new()));
    let kept = notes.clone();
    let opts = IrcOptions {
        channel: "#f".into(),
        once,
        accept_dir: accept_dir.map(Path::to_path_buf),
        here: here.to_path_buf(),
    };
    let server = Server {
        host: "relay.test".into(),
        port: 6697,
        nick: nick.into(),
        username: nick.into(),
        realname: "p".into(),
    };
    let task = tokio::spawn(async move {
        let mut session = Session::new(server, ReapPolicy::default());
        let mut out = Output::new(Sink::default(), false, move |line| kept.lock().unwrap().push(line));
        irc_converse(end, &mut session, true, &mut lines, &mut out, &opts, std::future::pending()).await
    });
    Run { task, notes }
}

async fn wait_for(run: &Run, needle: &str) {
    let deadline = tokio::time::Instant::now() + LIMIT;
    while !run.notes.lock().unwrap().iter().any(|n| n.contains(needle)) {
        assert!(tokio::time::Instant::now() < deadline, "no {needle:?} in {:?}", run.notes.lock().unwrap());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn end(run: Run) -> IrcSummary {
    tokio::time::timeout(LIMIT, run.task).await.expect("the conversation ends").unwrap()
}

/// `--file` offers to the channel; the side with `--accept-dir` takes it,
/// and the file arrives whole: the sender ends with the word that it was
/// kept. Files of 0, 1 and 2000 bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_offered_to_the_channel_arrives_whole_once_taken() {
    let (here, inbox) = (scratch("files-here"), scratch("files-inbox"));
    let big: Vec<u8> = (0..2000u32).map(|i| (i * 13 % 251) as u8).collect();
    for (name, bytes) in [("empty.bin", &b""[..]), ("one.bin", &b"x"[..]), ("two-k.bin", &big[..])] {
        std::fs::write(here.join(name), bytes).unwrap();
        let (a, a_relay) = tokio::io::duplex(64 * 1024);
        let (b, b_relay) = tokio::io::duplex(64 * 1024);
        relay(vec![("pa".into(), a_relay), ("pb".into(), b_relay)]);
        let (_tx, lines) = Lines::channel(8);
        let b_run = start(b, "pb", Once::No, Some(&inbox), &inbox, lines);
        wait_for(&b_run, "joined #f").await;
        let a_run = start(a, "pa", Once::File(here.join(name)), None, &here, Lines::none());
        let a_summary = end(a_run).await;
        assert_eq!(a_summary.ended, Ended::Done, "{name}");
        wait_for(&b_run, "its SHA-256 matched").await;
        assert_eq!(std::fs::read(inbox.join(name)).unwrap(), bytes, "{name}");
        b_run.task.abort();
    }
    let left: Vec<_> = std::fs::read_dir(&inbox).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(left.len(), 3, "no temporary file is left: {left:?}");
}

/// A file that nobody takes is never written, and a decline is said to its
/// sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_that_the_user_did_not_take_is_never_written() {
    let (here, theirs) = (scratch("decline-here"), scratch("decline-theirs"));
    std::fs::write(here.join("secret.txt"), b"never written").unwrap();
    let (a, a_relay) = tokio::io::duplex(64 * 1024);
    let (b, b_relay) = tokio::io::duplex(64 * 1024);
    relay(vec![("pa".into(), a_relay), ("pb".into(), b_relay)]);
    let (b_tx, b_lines) = Lines::channel(8);
    let b_run = start(b, "pb", Once::No, None, &theirs, b_lines);
    wait_for(&b_run, "joined #f").await;
    let (a_tx, a_lines) = Lines::channel(8);
    let a_run = start(a, "pa", Once::No, None, &here, a_lines);
    wait_for(&a_run, "joined #f").await;
    a_tx.send(format!("/file {}", here.join("secret.txt").display())).await.unwrap();
    wait_for(&b_run, "offers secret.txt (13 bytes) as file 1").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(std::fs::read_dir(&theirs).unwrap().count(), 0, "a file was written with no accept");
    b_tx.send("/decline 1".into()).await.unwrap();
    wait_for(&a_run, "pb declined file 1").await;
    assert_eq!(std::fs::read_dir(&theirs).unwrap().count(), 0);
    drop((a_tx, b_tx));
    let _ = (end(a_run).await, end(b_run).await);
}

/// A chunk damaged on the way: the digest at the end does not match, the
/// file is not kept, and its sender hears so, and ends with that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_damaged_on_the_way_is_not_kept_and_its_sender_hears_so() {
    let (here, inbox) = (scratch("damaged-here"), scratch("damaged-inbox"));
    let bytes: Vec<u8> = (0..1500u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(here.join("f.bin"), &bytes).unwrap();
    let (a, a_relay) = tokio::io::duplex(64 * 1024);
    let (b, b_relay) = tokio::io::duplex(64 * 1024);
    relay_with(vec![("pa".into(), a_relay), ("pb".into(), b_relay)], true);
    let (_tx, lines) = Lines::channel(8);
    let b_run = start(b, "pb", Once::No, Some(&inbox), &inbox, lines);
    wait_for(&b_run, "joined #f").await;
    let a_run = start(a, "pa", Once::File(here.join("f.bin")), None, &here, Lines::none());
    assert_eq!(end(a_run).await.ended, Ended::Damaged);
    wait_for(&b_run, "file 1:").await;
    assert_eq!(std::fs::read_dir(&inbox).unwrap().count(), 0, "a damaged file, or its temporary file, was kept");
    b_run.task.abort();
}
