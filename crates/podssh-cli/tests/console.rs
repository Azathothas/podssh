//! podssh in a Windows console (T-132), through a pseudo console
//! (`conpty_harness`), against the test's SSH server on the loopback: what
//! the console shows of the server's output, what reaches the server of a
//! resize, and the console's input mode after the session, read by a process
//! of the console around podssh (`console_wrapper`). Two tests state what a
//! fix must give, and are ignored until it lands: output after a byte that is
//! not UTF-8 (T-294), and Ctrl-Break (T-295).
#![cfg(windows)]

mod cleanup;
mod conpty_harness;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use conpty_harness::Console;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-console-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The test's server, with a new host key, on a runtime of its own.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

/// The arguments of `podssh ssh --direct` to the server.
fn ssh_words(home: &Path, port: u16, args: &[&str]) -> Vec<String> {
    let known = home.join("known_hosts");
    let mut words: Vec<String> = vec![
        "ssh".into(),
        "--direct".into(),
        "-p".into(),
        port.to_string(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known.display()),
    ];
    words.extend(args.iter().map(|a| a.to_string()));
    words
}

/// A command line of `words`, each quoted when it holds a space.
fn line(words: &[String]) -> String {
    let quoted: Vec<String> =
        words.iter().map(|w| if w.contains(' ') { format!("\"{w}\"") } else { w.clone() }).collect();
    quoted.join(" ")
}

/// The environment of podssh in the console: no ssh_config, and the test's
/// home; `wrap`, for the process of `console_wrapper`.
fn changes<'a>(home: &'a str, wrap: Option<&'a str>) -> Vec<(&'a str, Option<&'a str>)> {
    vec![
        ("PODSSH_SSH_CONFIG", Some("none")),
        ("HOME", Some(home)),
        ("USERPROFILE", Some(home)),
        ("PODSSH_OFFLINE", None),
        ("HTTPS_PROXY", None),
        ("ALL_PROXY", None),
        ("SSH_AUTH_SOCK", None),
        (WRAP, wrap),
    ]
}

/// `podssh ssh --direct` to the server, in a pseudo console of 24 by 80.
fn ssh(home: &Path, port: u16, args: &[&str]) -> Console {
    let mut words = vec![env!("CARGO_BIN_EXE_podssh").to_string()];
    words.extend(ssh_words(home, port, args));
    Console::start(&line(&words), &changes(home.to_str().unwrap(), None), 24, 80)
}

/// The words of podssh, separated by U+001F, for `console_wrapper`.
const WRAP: &str = "PODSSH_TEST_CONSOLE_WRAP";

/// The same, with this test binary's `console_wrapper` as the console's
/// process: it reads the console's input mode, runs podssh, and reads the
/// mode again. Not cmd: cmd sets the mode itself after each program.
fn wrapped(home: &Path, port: u16, args: &[&str]) -> Console {
    let me = std::env::current_exe().unwrap().display().to_string();
    let words = [me, "console_wrapper".into(), "--exact".into(), "--ignored".into(), "--nocapture".into()];
    let podssh = ssh_words(home, port, args).join("\u{1f}");
    Console::start(&line(&words), &changes(home.to_str().unwrap(), Some(&podssh)), 24, 80)
}

/// The console's input mode before podssh and after it, and podssh's code,
/// from what `console_wrapper` printed.
fn modes(console: &Console) -> Option<(String, String, String)> {
    if !console.expect("AFTER=", LIMIT) {
        return None;
    }
    let text = console.text();
    let field = |name: &str| {
        let at = text.find(&format!("{name}="))? + name.len() + 1;
        Some(text[at..].split(|c: char| c.is_whitespace()).next()?.to_string())
    };
    Some((field("BEFORE")?, field("RC")?, field("AFTER")?))
}

/// The console's own process in `wrapped`, which runs it with the words of
/// podssh in [`WRAP`]; with none, as under `--ignored`, it does nothing.
/// Ctrl-C and Ctrl-Break go to each process of a console: this one ignores
/// them, and podssh, its child, does not inherit that.
#[test]
#[ignore = "the console's process of the tests that need one; not a test of its own"]
fn console_wrapper() {
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleCtrlHandler, STD_INPUT_HANDLE};
    let Ok(words) = std::env::var(WRAP) else { return };
    unsafe extern "system" fn ignore(_event: u32) -> windows_sys::core::BOOL {
        1
    }
    // SAFETY: a handler that does nothing, for the life of the process.
    unsafe { SetConsoleCtrlHandler(Some(ignore), 1) };
    let mode = || {
        let mut mode = 0u32;
        // SAFETY: this process's console input, and an out pointer.
        let ok = unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut mode) };
        if ok != 0 {
            format!("{mode:#x}")
        } else {
            "none".to_string()
        }
    };
    let before = mode();
    let code = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(words.split('\u{1f}'))
        .status()
        .map_or(-1, |s| s.code().unwrap_or(-1));
    let after = mode();
    println!("\r\nBEFORE={before}\r\nRC={code}\r\nAFTER={after}\r");
}

const LIMIT: Duration = Duration::from_secs(20);

/// The server's text, in UTF-8 with letters that are not ASCII, shows as
/// sent: podssh writes the console in UTF-16, whatever its code page.
#[test]
fn text_that_is_not_ascii_shows_as_sent() {
    let home = scratch("utf8");
    let (_runtime, port) = server(&home);
    // "h\u{e9}llo \u{20ac} \u{2713}" in UTF-8.
    let console = ssh(&home, port, &["-T", "u@127.0.0.1", "bytes 68c3a96c6c6f20e282ac20e29c930d0a"]);
    assert!(console.expect("h\u{e9}llo \u{20ac} \u{2713}", LIMIT), "the console: {:?}", console.text());
    assert_eq!(console.wait(LIMIT), Some(0));
}

/// Output after a byte that is not UTF-8 still shows, the byte as U+FFFD,
/// as a terminal of Linux shows it (T-294).
#[test]
#[ignore = "fails until T-294: the console's writer refuses the byte, and podssh then drops each later byte"]
fn output_after_a_byte_that_is_not_utf8_shows() {
    let home = scratch("bytes");
    let (_runtime, port) = server(&home);
    // "before", a byte that is not UTF-8, "after": three messages.
    let console = ssh(&home, port, &["-T", "u@127.0.0.1", "bytes 6265666f72650d0a ff0d0a 61667465720d0a"]);
    assert!(console.expect("before", LIMIT), "the console: {:?}", console.text());
    assert!(console.expect("after", LIMIT), "the console: {:?}", console.text());
    assert!(console.text().contains('\u{fffd}'), "the console: {:?}", console.text());
    assert_eq!(console.wait(LIMIT), Some(0));
}

/// A resize of the console reaches the server: podssh reads the size every
/// 500 ms, as a console has no signal for it (450 to 505 ms measured).
#[test]
fn a_resize_reaches_the_server() {
    let home = scratch("resize");
    let (_runtime, port) = server(&home);
    let mut console = ssh(&home, port, &["-t", "pty-u@127.0.0.1", "watch"]);
    assert!(console.expect("SIZE 80x24", LIMIT), "the console: {:?}", console.text());
    for (rows, cols) in [(50, 120), (30, 100)] {
        let start = Instant::now();
        console.resize(rows, cols);
        let seen = console.expect(&format!("SIZE {cols}x{rows}"), Duration::from_secs(5));
        assert!(seen, "{cols}x{rows} within 5 s; the console: {:?}", console.text());
        println!("{cols}x{rows} reached the server after {} ms", start.elapsed().as_millis());
    }
    console.send(b"q");
    assert_eq!(console.wait(LIMIT), Some(0));
}

/// `~.` ends the session and leaves the console's input mode as it was.
#[test]
fn the_escape_leaves_the_console_mode_as_it_was() {
    let home = scratch("escape");
    let (_runtime, port) = server(&home);
    let mut console = wrapped(&home, port, &["-t", "pty-u@127.0.0.1", "watch"]);
    assert!(console.expect("SIZE 80x24", LIMIT), "the console: {:?}", console.text());
    console.send(b"\r~.");
    let (before, code, after) = modes(&console).expect("the wrapper's report");
    assert_eq!(code, "255");
    assert_eq!(after, before, "the console's input mode");
}

/// Ctrl-Break, a signal of the console in each mode, ends podssh and leaves
/// the console's input mode as it was (T-295).
#[test]
#[ignore = "fails until T-295: the default handler ends podssh with the console raw"]
fn ctrl_break_leaves_the_console_mode_as_it_was() {
    let home = scratch("break");
    let (_runtime, port) = server(&home);
    let mut console = wrapped(&home, port, &["-t", "pty-u@127.0.0.1", "watch"]);
    assert!(console.expect("SIZE 80x24", LIMIT), "the console: {:?}", console.text());
    // Ctrl+Break in the pseudo console's win32-input-mode: VK_CANCEL (3),
    // scan code 0x46, no character, with the left Ctrl; down, then up.
    console.send(b"\x1b[3;70;0;1;8;1_\x1b[3;70;0;0;8;1_");
    let (before, _, after) = modes(&console).expect("the wrapper's report");
    assert_eq!(after, before, "the console's input mode");
}
