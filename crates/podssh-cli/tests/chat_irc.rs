//! `podssh chat --irc` (T-252): the conversation in a channel over a byte
//! stream, against a script of the lines that real servers wrote, as the
//! tests of the IRC client captured them on 2026-10-10 in the build image
//! (InspIRCd 4.11.0 with `echo-message`, ngircd 27 without). No listener:
//! the server's end is the other half of an in-memory stream.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_cli::chat::irc::{irc_converse, IrcOptions, IrcSummary};
use podssh_cli::chat::output::Output;
use podssh_cli::chat::{Ended, Lines, Once};
use podssh_core::irc::{ReapPolicy, Server, Session};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

const LIMIT: Duration = Duration::from_secs(10);

// InspIRCd 4.11.0 (podssh-core's `tests/cap_list.rs`).
const INSPIRCD_LS: &[u8] = b":irc.inspircd.test CAP * LS :account-notify away-notify cap-notify echo-message extended-join inspircd.org/poison inspircd.org/stats-tags no-implicit-names standard-replies \r\n";
const INSPIRCD_ACK: &[u8] = b":irc.inspircd.test CAP pc2 ACK :echo-message\r\n";
const INSPIRCD_WELCOME: &[u8] = b":irc.inspircd.test 001 pe1 :Welcome to the PodTest IRC Network pe1!pe1@127.0.0.1\r\n";
const INSPIRCD_ECHO: &[u8] = b":pe1!pe1@127.0.0.1 PRIVMSG #podtest :hello channel\r\n";
// The JOIN's form of ngircd and InspIRCd, the channel as a trailing (the
// grammar's fixture).
const INSPIRCD_JOINED: &[u8] = b":pe1!pe1@127.0.0.1 JOIN :#podtest\r\n";

// ngircd 27 (podssh-core's `tests/own_nick.rs`).
const NGIRCD_LS: &[u8] = b":irc.ngircd.test CAP * LS :multi-prefix\r\n";
const NGIRCD_WELCOME: &[u8] = b":irc.ngircd.test 001 pa :Welcome to the Internet Relay Network pa!~pa@127.0.0.1\r\n";
const NGIRCD_005: &[u8] = b":irc.ngircd.test 005 pa CHANNELLEN=50 NICKLEN=9 TOPICLEN=490 AWAYLEN=127 KICKLEN=400 MODES=5 MAXLIST=beI:50 EXCEPTS=e INVEX=I PENALTY FNC :are supported on this server\r\n";
const NGIRCD_JOINED: &[u8] = b":pa!~pa@127.0.0.1 JOIN :#t\r\n";
const NGIRCD_PEER_JOIN: &[u8] = b":pb!~pb@127.0.0.1 JOIN :#t\r\n";

/// What the conversation wrote to stdout.
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

/// The server's end: the client's lines, and the script's answers.
struct Far {
    lines: BufReader<ReadHalf<DuplexStream>>,
    write: WriteHalf<DuplexStream>,
    seen: Vec<String>,
}

impl Far {
    fn new(end: DuplexStream) -> Far {
        let (read, write) = tokio::io::split(end);
        Far { lines: BufReader::new(read), write, seen: Vec::new() }
    }

    /// The client's lines up to the first that starts with `start`.
    async fn expect(&mut self, start: &str) -> String {
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(LIMIT, self.lines.read_line(&mut line))
                .await
                .unwrap_or_else(|_| panic!("no {start:?} within {LIMIT:?}; seen {:?}", self.seen))
                .unwrap();
            assert!(n > 0, "the client ended before {start:?}; seen {:?}", self.seen);
            let line = line.trim_end().to_string();
            self.seen.push(line.clone());
            if line.starts_with(start) {
                return line;
            }
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.write.write_all(bytes).await.unwrap();
    }
}

fn session(nick: &str) -> Session {
    let server = Server {
        host: "irc.test".into(),
        port: 6697,
        nick: nick.into(),
        username: nick.into(),
        realname: "podssh".into(),
    };
    Session::new(server, ReapPolicy::default())
}

struct Run {
    task: tokio::task::JoinHandle<(IrcSummary, Session)>,
    stdout: Sink,
    notes: Arc<Mutex<Vec<String>>>,
}

/// The conversation of `nick` in `channel`, over `end`, as a task.
fn start(end: DuplexStream, nick: &str, channel: &str, once: Once, mut lines: Lines) -> Run {
    let (stdout, notes) = (Sink::default(), Arc::new(Mutex::new(Vec::new())));
    let (sink, kept) = (stdout.clone(), notes.clone());
    let opts = IrcOptions { channel: channel.into(), once, accept_dir: None, here: std::env::temp_dir() };
    let mut session = session(nick);
    let task = tokio::spawn(async move {
        let mut out = Output::new(sink, false, move |line| kept.lock().unwrap().push(line));
        let summary = irc_converse(end, &mut session, true, &mut lines, &mut out, &opts, std::future::pending()).await;
        (summary, session)
    });
    Run { task, stdout, notes }
}

async fn end(run: Run) -> (IrcSummary, Session, String, Vec<String>) {
    let (summary, session) = tokio::time::timeout(LIMIT, run.task).await.expect("the conversation ends").unwrap();
    let notes = run.notes.lock().unwrap().clone();
    (summary, session, run.stdout.text(), notes)
}

/// InspIRCd echoes each message: `--send` ends once the echo came, with a
/// `QUIT`, and nothing is left undelivered.
#[tokio::test]
async fn a_message_is_delivered_once_the_server_echoes_it() {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let run = start(ours, "pe1", "#podtest", Once::Send("hello channel".into()), Lines::none());
    let mut far = Far::new(theirs);
    far.expect("CAP LS").await;
    far.expect("USER").await;
    far.send(INSPIRCD_LS).await;
    assert_eq!(far.expect("CAP REQ").await, "CAP REQ :echo-message");
    far.send(INSPIRCD_ACK).await;
    far.expect("CAP END").await;
    far.send(INSPIRCD_WELCOME).await;
    assert_eq!(far.expect("JOIN").await, "JOIN #podtest");
    far.send(INSPIRCD_JOINED).await;
    assert_eq!(far.expect("PRIVMSG").await, "PRIVMSG #podtest :hello channel");
    far.send(INSPIRCD_ECHO).await;
    far.expect("QUIT").await;
    let (summary, _, stdout, notes) = end(run).await;
    assert_eq!(summary.ended, Ended::Done, "{notes:?}");
    assert!(summary.undelivered.is_empty() && summary.joined, "{summary:?}");
    assert!(stdout.is_empty(), "this client's own echo is not shown: {stdout:?}");
    assert!(notes.iter().any(|n| n.contains("joined #podtest as pe1")), "{notes:?}");
}

/// With no echo, a message that the server did not echo before the end
/// would be said; here the stream ends first, and the message is listed.
#[tokio::test]
async fn a_message_with_no_echo_is_said_at_the_end() {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let run = start(ours, "pe1", "#podtest", Once::Send("hello channel".into()), Lines::none());
    let mut far = Far::new(theirs);
    far.expect("USER").await;
    far.send(INSPIRCD_LS).await;
    far.expect("CAP REQ").await;
    far.send(INSPIRCD_ACK).await;
    far.expect("CAP END").await;
    far.send(INSPIRCD_WELCOME).await;
    far.expect("JOIN").await;
    far.send(INSPIRCD_JOINED).await;
    far.expect("PRIVMSG").await;
    drop(far);
    let (summary, _, _, _) = end(run).await;
    assert_eq!(summary.ended, Ended::PeerLeft);
    assert_eq!(summary.undelivered, vec!["hello channel".to_string()]);
}

/// ngircd offers no `echo-message`: podssh says once that nothing proves a
/// message arrived; a peer's message reaches stdout, and the user's goes to
/// the channel.
#[tokio::test]
async fn a_server_with_no_echo_gets_messages_both_ways_and_says_so() {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (tx, lines) = Lines::channel(8);
    let run = start(ours, "pa", "#t", Once::No, lines);
    let mut far = Far::new(theirs);
    far.expect("USER").await;
    far.send(NGIRCD_LS).await;
    far.expect("CAP END").await;
    far.send(NGIRCD_WELCOME).await;
    far.send(NGIRCD_005).await;
    far.expect("JOIN #t").await;
    far.send(NGIRCD_JOINED).await;
    far.send(NGIRCD_PEER_JOIN).await;
    far.send(b":pb!~pb@127.0.0.1 PRIVMSG #t :hi pa \x1b[2J\r\n").await;
    tx.send("hello pb".into()).await.unwrap();
    assert_eq!(far.expect("PRIVMSG").await, "PRIVMSG #t :hello pb");
    drop(tx);
    far.expect("QUIT").await;
    let (summary, _, stdout, notes) = end(run).await;
    assert_eq!(summary.ended, Ended::Done, "{notes:?}");
    assert!(stdout.contains("pb: hi pa"), "{stdout:?}");
    assert!(!stdout.contains('\u{1b}'), "a peer's words reach the terminal unsafe: {stdout:?}");
    assert!(notes.iter().any(|n| n.contains("does not echo messages")), "{notes:?}");
    assert!(notes.iter().any(|n| n.contains("pb joined")), "{notes:?}");
}

/// A channel that refuses this client, by a ban or a `KICK`, ends the run as
/// a refusal.
#[tokio::test]
async fn a_ban_or_a_kick_is_a_refusal() {
    for refusal in [
        &b":irc.ngircd.test 474 pa #t :Cannot join channel (+b) -- You are banned\r\n"[..],
        &b":pb!~pb@127.0.0.1 KICK #t pa :out\r\n"[..],
    ] {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (_tx, lines) = Lines::channel(8);
        let run = start(ours, "pa", "#t", Once::No, lines);
        let mut far = Far::new(theirs);
        far.expect("USER").await;
        far.send(NGIRCD_LS).await;
        far.expect("CAP END").await;
        far.send(NGIRCD_WELCOME).await;
        far.expect("JOIN").await;
        if refusal.windows(4).any(|w| w == b"KICK") {
            far.send(NGIRCD_JOINED).await;
        }
        far.send(refusal).await;
        let (summary, _, _, _) = end(run).await;
        assert!(matches!(summary.ended, Ended::Refused(_)), "{summary:?}");
    }
}

/// A new connection of the same session rejoins in its burst, before the
/// welcome, and sends no second `JOIN` after it.
#[tokio::test]
async fn a_reconnect_rejoins_once() {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (tx, lines) = Lines::channel(8);
    let run = start(ours, "pa", "#t", Once::No, lines);
    let mut far = Far::new(theirs);
    far.expect("USER").await;
    far.send(NGIRCD_LS).await;
    far.expect("CAP END").await;
    far.send(NGIRCD_WELCOME).await;
    far.expect("JOIN").await;
    far.send(NGIRCD_JOINED).await;
    drop(far);
    let (summary, mut session, _, _) = end(run).await;
    assert_eq!(summary.ended, Ended::PeerLeft);
    assert!(summary.joined);

    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    drop(tx);
    let mut lines = Lines::none();
    let opts = IrcOptions {
        channel: "#t".into(),
        once: Once::No,
        accept_dir: Some(std::env::temp_dir()),
        here: std::env::temp_dir(),
    };
    let notes = Arc::new(Mutex::new(Vec::new()));
    let kept = notes.clone();
    let task = tokio::spawn(async move {
        let mut out = Output::new(Sink::default(), false, move |line| kept.lock().unwrap().push(line));
        irc_converse(ours, &mut session, false, &mut lines, &mut out, &opts, std::future::pending()).await
    });
    let mut far = Far::new(theirs);
    let join = far.expect("JOIN").await;
    assert!(far.seen.iter().all(|l| !l.contains(" 001 ")), "the rejoin came before the welcome");
    assert_eq!(join, "JOIN #t");
    far.send(NGIRCD_LS).await;
    far.expect("CAP END").await;
    far.send(NGIRCD_WELCOME).await;
    far.send(NGIRCD_JOINED).await;
    far.send(b"PING :check\r\n").await;
    far.expect("PONG").await;
    // A second round trip: each line written before it is in by then.
    far.send(b"PING :again\r\n").await;
    far.expect("PONG :again").await;
    assert_eq!(far.seen.iter().filter(|l| l.starts_with("JOIN")).count(), 1, "{:?}", far.seen);
    drop(far);
    let summary = tokio::time::timeout(LIMIT, task).await.unwrap().unwrap();
    assert_eq!(summary.ended, Ended::PeerLeft);
}

/// The server's `ERROR` before the channel is a refusal, with its words: a
/// ban, or a throttle that a fast new try would only make longer.
#[tokio::test]
async fn the_servers_error_before_the_channel_is_a_refusal_with_its_words() {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (_tx, lines) = Lines::channel(8);
    let run = start(ours, "pa", "#t", Once::No, lines);
    let mut far = Far::new(theirs);
    far.expect("USER").await;
    // ergo 2.18.0's form, the text as a middle (the grammar's fixture).
    far.send(b"ERROR Quit\r\n").await;
    drop(far);
    let (summary, _, _, _) = end(run).await;
    assert_eq!(summary.ended, Ended::Refused("the server closed the link: Quit".into()), "{summary:?}");
}
