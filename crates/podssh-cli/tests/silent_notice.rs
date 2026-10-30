//! The notice while the far end is silent (T-302), from end to end, in a
//! pty of Linux: `podssh ssh -t node://` through the stand-in relay's
//! reverse road to the tests' SSH server, whose `watch` prints `READY`,
//! then `KEYS HEX` for each key. The stand-in proxy of the client holds
//! each byte both ways for 20 s (`--pause`, T-203), less than the 30 s
//! after which the layer finds a link dead; a key typed then waits. The
//! terminal is taken for xterm (`XTERM_VERSION`), which keeps a stack of
//! titles.
//!
//! Pass: the notice comes in the window's title within its limit, counts
//! up, and goes before the key's answer; with the terminal oracle (T-200),
//! the screen just before that answer is the screen before the pause, and
//! so is the title. It prints when the notice came and went: the
//! measurement of T-302. Ignored, as it needs Python and openssl for the
//! stand-ins, and half a minute:
//!
//! ```sh
//! cargo test -p podssh-cli --test silent_notice -- --ignored --nocapture
//! ```
//!
//! The planted defect: a notice written at the cursor, as a line (the
//! place `Line` for a terminal in raw mode, in `Facts::place`), fails the
//! check of the screen.

#![cfg(target_os = "linux")]

mod pty_harness;
#[path = "../../podssh-terminal/tests/screen/mod.rs"]
mod screen;
mod ssh_harness;
mod throughput_harness;

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use podssh_ssh::notice::title;
use screen::Screen;
use throughput_harness::{found, lines_of, scripts, wait_for, without_proxy, Cell, Session};

const ROWS: u16 = 24;
const COLS: u16 = 120;
/// How long the stand-in proxy holds each byte.
const PAUSE: Duration = Duration::from_secs(20);
const LIMIT: Duration = Duration::from_secs(60);
/// The start of the notice's title.
const NOTICE: &str = "\x1b]2;podssh: no word from node://lab for ";

/// A stand-in proxy, its names mapped, with `fault` from `start`: its URL.
fn proxy(session: &Session, name: &str, map: &str, fault: &[&str], start: &Path) -> String {
    let python = ["python3", "python"].into_iter().find(|p| found(p, &["--version"])).expect("Python");
    let port_file = session.home.join(format!("proxy-{name}.port"));
    let mut cmd = Command::new(python);
    cmd.arg(scripts().join("fake-proxy.py")).arg("--port-file").arg(&port_file);
    cmd.arg("--log").arg(session.home.join(format!("proxy-{name}.log"))).arg("--start-file").arg(start);
    cmd.arg("--map").arg(map).args(fault).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    session.keep(cmd.spawn().expect("the stand-in proxy"));
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            return format!("http://127.0.0.1:{port}");
        }
        assert!(Instant::now() < deadline, "the stand-in proxy did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait until the bytes of `term` hold `needle`: the time from `from`.
fn seen(term: &pty_harness::Pty, needle: &[u8], from: Instant) -> Duration {
    let deadline = Instant::now() + LIMIT;
    loop {
        if term.bytes().windows(needle.len()).any(|w| w == needle) {
            return from.elapsed();
        }
        assert!(Instant::now() < deadline, "no {:?} in: {:?}", String::from_utf8_lossy(needle), term.text());
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Where `needle` first is in `bytes`.
fn at(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes.windows(needle.len()).position(|w| w == needle)
}

/// The window's title after `bytes`, with XTWINOPS 22 and 23 kept as a
/// stack, which the `vt100` model does not keep.
fn title_after(bytes: &[u8]) -> String {
    let (mut now, mut stack) = (String::new(), Vec::new());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(title::PUSH) {
            stack.push(now.clone());
            i += title::PUSH.len();
        } else if rest.starts_with(title::POP) {
            now = stack.pop().unwrap_or_default();
            i += title::POP.len();
        } else if let Some(body) = rest.strip_prefix(b"\x1b]2;") {
            let end = body.iter().position(|b| *b == 0x07).unwrap_or(body.len());
            now = String::from_utf8_lossy(&body[..end]).into_owned();
            i += 4 + end;
        } else {
            i += 1;
        }
    }
    now
}

#[test]
#[ignore = "T-302: the notice through the stand-in relay with a pause of 20 s (Python, openssl, half a minute)"]
fn the_notice_shows_in_the_title_while_the_node_is_silent_and_leaves_the_screen() {
    let session = Session::start("notice");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let arg = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (arg("--relay-host"), arg("--ca-file"));
    let port = relay.rsplit_once(':').unwrap().1.to_string();
    let start = session.home.join("start");
    let map = format!("relay-a.test=127.0.0.1:{port}");
    let node_proxy = proxy(&session, "node", &map, &[], &start);
    let pause = format!("0:{}", PAUSE.as_secs());
    let client_proxy = proxy(&session, "client", &map, &["--pause", &pause], &start);
    // Each run goes through a stand-in proxy whose map names relay-a.test,
    // and pins no address: a pin to the loopback would go around the proxy
    // and its pause (T-318). The machine's proxy variables go first.
    let through = |proxy: &str, args: &[String]| {
        let mut cmd = without_proxy(session.command(args));
        cmd.env("HTTPS_PROXY", proxy).env("SSL_CERT_FILE", &ca);
        cmd
    };

    // The pair and its node, in front of the tests' SSH server.
    let args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay.clone()];
    let out = through(&node_proxy, &args).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port)];
    let mut node = through(&node_proxy, &args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");

    // The client in a pty, taken for xterm, which keeps a stack of titles.
    let mut args = vec!["ssh".to_string(), "-t".into()];
    args.extend(session.common());
    args.extend(["node://pty-tester@lab".to_string(), "watch".into()]);
    let mut cmd = through(&client_proxy, &args);
    cmd.env("XTERM_VERSION", "XTerm(390)").env("TERM", "xterm-256color");
    for name in ["TMUX", "STY", "PODSSH_TITLE_STACK", "VTE_VERSION"] {
        cmd.env_remove(name);
    }
    let mut term = pty_harness::Pty::start(cmd, ROWS, COLS);
    assert!(term.expect("READY", LIMIT), "the session: {:?}", term.text());
    // The screen settles: the size, then nothing more.
    std::thread::sleep(Duration::from_secs(2));
    let before = term.bytes();

    // The pause, and a key that waits in it.
    std::fs::write(&start, b"now").unwrap();
    let paused = Instant::now();
    term.send(b"a");
    let came = seen(&term, NOTICE.as_bytes(), paused);
    let first = term.bytes();
    let first_title = title_after(&first);
    // It counts up: a later title says another second.
    let deadline = Instant::now() + PAUSE;
    let counted = loop {
        let title = title_after(&term.bytes());
        if title != first_title && title.starts_with(&NOTICE[4..]) {
            break title;
        }
        assert!(Instant::now() < deadline, "the notice did not count up: {first_title:?}");
        std::thread::sleep(Duration::from_millis(200));
    };
    let answered = seen(&term, b"KEYS 61", paused);
    let all = term.bytes();
    eprintln!(
        "the notice came {:.1} s after the pause began ({first_title:?}, then {counted:?}); the key's answer \
         came after {:.1} s",
        came.as_secs_f64(),
        answered.as_secs_f64()
    );
    assert!(came < PAUSE, "the notice came within the pause");

    // The title came back before the answer, and the screen is the one
    // before the pause.
    let keys = at(&all, b"KEYS 61").expect("the answer");
    let popped = at(&all[before.len()..], title::POP).map(|i| i + before.len()).expect("the title came back");
    assert!(popped < keys, "the title came back before the far end's bytes");
    let (then, now) = (Screen::of(ROWS, COLS, &before), Screen::of(ROWS, COLS, &all[..keys]));
    assert_eq!(now.rows(), then.rows(), "the screen changed:\n{}", now.show());
    assert_eq!(now.cursor(), then.cursor(), "the cursor moved:\n{}", now.show());
    assert_eq!(title_after(&all[..keys]), title_after(&before), "the title came back");

    term.send(b"q");
    assert_eq!(term.wait(LIMIT), Some(0), "the session: {:?}", term.text());
}
