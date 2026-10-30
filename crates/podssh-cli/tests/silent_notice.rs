//! The notice while the far end is silent (T-302), from end to end, in a
//! pty of Linux: `podssh ssh -t node://` through the stand-in relay's
//! reverse road to the tests' SSH server, whose `watch` prints `READY`,
//! then `KEYS HEX` for each key; and `podssh ssh -t` on the forward road
//! through the same relay (T-307). The stand-in proxy of the client holds
//! each byte both ways for 20 s (`--pause`, T-203), less than the 30 s
//! after which the layer, and the forward road's pings, find a link dead;
//! a key typed then waits. The terminal is taken for xterm
//! (`XTERM_VERSION`), which keeps a stack of titles.
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
mod stand_harness;
mod throughput_harness;

use std::time::{Duration, Instant};

use podssh_ssh::notice::title;
use screen::Screen;
use stand_harness::Stand;

const ROWS: u16 = 24;
const COLS: u16 = 120;
/// How long the stand-in proxy holds each byte.
const PAUSE: Duration = Duration::from_secs(20);
const LIMIT: Duration = Duration::from_secs(60);
/// The start of the notice's title, on each road.
const NOTICE: &str = "\x1b]2;podssh: no word from node://lab for ";
/// The forward road names the host with its port, as it is not 22.
const NOTICE_FORWARD: &str = "\x1b]2;podssh: no word from 127.0.0.1:";

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
    let pause = format!("0:{}", PAUSE.as_secs());
    let Some(stand) = Stand::new("notice", &["--pause", &pause], &[]) else { return };
    stand.node();
    let args = stand.ssh(&["-t"], "pty-tester", "watch");
    through_a_pause(&stand, &args, NOTICE);
}

#[test]
#[ignore = "T-307: the notice on the forward road with a pause of 20 s (Python, openssl, half a minute)"]
fn the_notice_shows_on_the_forward_road_while_the_relay_is_silent_and_leaves_the_screen() {
    let pause = format!("0:{}", PAUSE.as_secs());
    let Some(stand) = Stand::new("notice-forward", &["--pause", &pause], &[]) else { return };
    let args = stand.forward(&["-t"], "pty-tester", "watch");
    through_a_pause(&stand, &args, NOTICE_FORWARD);
}

/// `podssh ARGS` in a pty through the client's proxy, a key in its pause:
/// the notice that starts with `notice` comes in the window's title,
/// counts up, and goes before the key's answer, with the screen and the
/// title as before the pause.
fn through_a_pause(stand: &Stand, args: &[String], notice: &str) {
    // The client in a pty, taken for xterm, which keeps a stack of titles.
    let mut cmd = stand.command(args);
    cmd.env("XTERM_VERSION", "XTerm(390)").env("TERM", "xterm-256color");
    for name in ["TMUX", "STY", "PODSSH_TITLE_STACK", "VTE_VERSION"] {
        cmd.env_remove(name);
    }
    let mut term = pty_harness::Pty::start(cmd, ROWS, COLS);
    assert!(term.expect("READY", LIMIT), "the session: {:?}", term.text());
    // The screen settles: the size, then nothing more.
    std::thread::sleep(Duration::from_secs(2));
    let before = term.bytes();

    // The pause, and a key that waits in it: sent once the proxies' clocks
    // run, so that it cannot pass before the pause.
    stand.start_faults();
    let paused = Instant::now();
    term.send(b"a");
    let came = seen(&term, notice.as_bytes(), paused);
    let first = term.bytes();
    let first_title = title_after(&first);
    // It counts up: a later title says another second.
    let deadline = Instant::now() + PAUSE;
    let counted = loop {
        let title = title_after(&term.bytes());
        if title != first_title && title.starts_with(&notice[4..]) {
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

/// On the forward road, a key that nothing echoes is no silence (T-307):
/// `sink` takes the keys and says nothing, and the relay's Pong to the
/// Ping that goes with each key answers it. A key each second for 12 s,
/// longer than the 10 s between the pings that find a dead link: without
/// that Ping, a question would wait for theirs, past the notice's 5 s.
#[test]
#[ignore = "T-307: no notice on the forward road for keys that nothing echoes (Python, openssl, a quarter of a minute)"]
fn the_forward_road_shows_no_notice_for_keys_that_nothing_echoes() {
    let Some(stand) = Stand::new("quiet-forward", &[], &[]) else { return };
    let mut cmd = stand.command(&stand.forward(&["-t"], "pty-tester", "sink"));
    cmd.env("XTERM_VERSION", "XTerm(390)").env("TERM", "xterm-256color");
    for name in ["TMUX", "STY", "PODSSH_TITLE_STACK", "VTE_VERSION"] {
        cmd.env_remove(name);
    }
    let mut term = pty_harness::Pty::start(cmd, ROWS, COLS);
    assert!(term.expect("R", LIMIT), "the session: {:?}", term.text());
    std::thread::sleep(Duration::from_secs(1));
    let before = term.bytes().len();
    for _ in 0..12 {
        term.send(b"x");
        std::thread::sleep(Duration::from_secs(1));
    }
    let after = term.bytes();
    assert_eq!(
        at(&after[before..], NOTICE_FORWARD.as_bytes()),
        None,
        "a notice while the relay answers: {:?}",
        term.text()
    );
    // The escape ends the session.
    term.send(b"\r~.");
    assert!(term.wait(LIMIT).is_some(), "the session ended: {:?}", term.text());
}

/// How long a forward session lives on a link that stays silent (T-307's
/// measure): the client's proxy holds each byte for 90 s, and the run
/// ends when the pings of the relay stream find the link dead, about 30 s
/// on, or sooner when SSH's own keepalives give up first. It prints both.
#[test]
#[ignore = "T-307: the end of a forward session on a silent link (Python, openssl, about a minute)"]
fn a_forward_session_on_a_silent_link_ends_when_its_pings_or_keepalives_give_up() {
    let mut took = Vec::new();
    for (tag, keepalive) in [
        ("end-forward", None),
        ("end-forward-alive", Some(["-o", "ServerAliveInterval=4", "-o", "ServerAliveCountMax=2"])),
    ] {
        // A stand of its own: a proxy's clock of faults starts once.
        let Some(stand) = Stand::new(tag, &["--pause", "0:90"], &[]) else { return };
        let extra: Vec<&str> = keepalive.map(|k| k.to_vec()).unwrap_or_default();
        let mut child = stand
            .command(&stand.forward(&extra, "tester", "sink"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("podssh runs");
        let mut out = child.stdout.take().unwrap();
        let mut first = [0u8; 2];
        std::io::Read::read_exact(&mut out, &mut first).expect("the sink's R");
        assert_eq!(&first, b"R\n");
        stand.start_faults();
        let paused = Instant::now();
        let deadline = paused + Duration::from_secs(85);
        let code = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status.code();
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("the session lived through the pause");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let mut err = String::new();
        let _ = std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err);
        let ended = paused.elapsed();
        eprintln!(
            "with {extra:?}: the session ended {:.1} s after the pause began, {code:?}: {}",
            ended.as_secs_f64(),
            err.trim()
        );
        assert_eq!(code, Some(255), "{err}");
        took.push(ended);
    }
    assert!(took[1] < took[0], "SSH's keepalives of 4 s end it sooner: {took:?}");
}
