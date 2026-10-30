//! Detach and attach again (T-158), from end to end: `podssh ssh node://`
//! through the stand-in relay's reverse road on the loopback, a node in
//! plain mode with no channel, which carries the bytes as they are, and
//! behind it the stand-in of a far end that keeps shells (`keep_harness`),
//! which speaks the resumable layer itself, as `podssh serve` will (T-159).
//! In a terminal (a pseudo console on Windows, a pty on Linux), a variable
//! is set in a shell and `~d` leaves it; the list names the kept shell, and
//! a new process joins it with `--attach NAME` and reads the variable back.
//! A planted far end that ends the shell on a detach fails that read. A far
//! end that keeps no shells gets `~d` as two bytes and refuses `--attach`;
//! the far end refuses an attach from inside the shell itself, and one to a
//! shell that a client has, unless `--take`. Each check says that it did
//! not run when this host has no Python or no openssl for the stand-in
//! relay, and the checks of `~d` where the test has no terminal.

#[cfg(windows)]
mod conpty_harness;
mod keep_harness;
#[cfg(target_os = "linux")]
mod pty_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keep_harness::{Plant, Shells};
use podssh_ssh::keep::SHELL_ID;
#[cfg(windows)]
use throughput_harness::PROXY_VARS;
use throughput_harness::{lines_of, wait_for, Cell, Session};

/// How long each step may take.
const LIMIT: Duration = Duration::from_secs(30);
/// The words before the name of a kept shell, in podssh's line.
const KEPT_AS: &str = "keeps the shell as ";
/// The terminal's size: wide, so that podssh's line is never cut.
const ROWS: u16 = 24;
const COLS: u16 = 200;

/// The pins of the stand-in relay's name, for each command.
fn pins() -> Vec<String> {
    vec!["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()]
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| w.to_string()).collect()
}

/// The stand-ins of one test: the relay, a pair, a plain node, and behind
/// it the far end that keeps shells.
struct Stand {
    session: Session,
    ca: String,
    shells: Arc<Mutex<Shells>>,
}

impl Stand {
    /// `None` when this host has no Python or no openssl for the stand-in
    /// relay, which the test says.
    fn new(tag: &str, plant: Plant) -> Option<Stand> {
        let session = Session::start(tag);
        let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
            Ok(cell) => cell,
            Err((_, why)) => {
                eprintln!("did not run: {why}");
                return None;
            }
        };
        let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
        let (relay, ca) = (at("--relay-host"), at("--ca-file"));
        let key = session.home.join("host_key");
        let (port, shells) = session.runtime.block_on(keep_harness::start(&key, plant));
        let stand = Stand { session, ca, shells };
        let mut args = words(&["relay", "pair", "lab", "--relay-host", &relay]);
        args.extend(pins());
        let out = stand.command(&args).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
        // The far end behind the node speaks the layer itself.
        let mut args = words(&["node", "lab", &format!("127.0.0.1:{port}"), "--plain", "--no-e2e"]);
        args.extend(pins());
        let mut node = stand.command(&args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let lines = lines_of(&mut node);
        stand.session.keep(node);
        wait_for(&lines, "serving").expect("the node starts");
        // The relay has the node's socket only from this line on.
        wait_for(&lines, "online").expect("the node is online");
        Some(stand)
    }

    /// `podssh ARGS` with the scratch HOME, the stand-in relay's trust and
    /// no proxy of the machine, and in no kept shell.
    fn command(&self, args: &[String]) -> Command {
        let mut cmd = self.session.stand_in(args, &self.ca);
        cmd.env_remove(SHELL_ID);
        cmd
    }

    /// The words of `podssh ssh` to the far end, with `extra` before the
    /// destination.
    fn ssh(&self, extra: &[&str]) -> Vec<String> {
        let mut args = vec!["ssh".to_string()];
        args.extend(self.session.common());
        args.extend(pins());
        args.push("--no-e2e".into());
        args.extend(words(extra));
        args.push("node://tester@lab".into());
        args
    }

    /// A run with no input, to its end: its code, stdout and stderr; in
    /// the shell `shell_id` of the far end, when one is given.
    fn run_from(&self, extra: &[&str], shell_id: Option<&str>) -> (Option<i32>, String, String) {
        let mut run = Run::start(self, extra, shell_id);
        run.stdin = None;
        run.end()
    }

    fn run(&self, extra: &[&str]) -> (Option<i32>, String, String) {
        self.run_from(extra, None)
    }
}

/// A run of `podssh ssh` with its input on a pipe: what it prints, as it
/// comes.
struct Run {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

/// Read `from` into `into` as it comes, on a thread of its own.
fn collect(mut from: impl Read + Send + 'static, into: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 {
                break;
            }
            into.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
}

impl Run {
    fn start(stand: &Stand, extra: &[&str], shell_id: Option<&str>) -> Run {
        let mut cmd = stand.command(&stand.ssh(extra));
        if let Some(id) = shell_id {
            cmd.env(SHELL_ID, id);
        }
        let mut child =
            cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh ssh runs");
        let (out, err) = (Arc::new(Mutex::new(String::new())), Arc::new(Mutex::new(String::new())));
        collect(child.stdout.take().unwrap(), out.clone());
        collect(child.stderr.take().unwrap(), err.clone());
        let stdin = child.stdin.take();
        Run { child, stdin, out, err }
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("the input is open");
        stdin.write_all(format!("{line}\n").as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    /// Wait until `what` holds `text`.
    fn wait_for(&mut self, what: &str, text: &str) {
        let started = Instant::now();
        loop {
            let seen = if what == "stdout" { &self.out } else { &self.err };
            if seen.lock().unwrap().contains(text) {
                return;
            }
            if started.elapsed() > LIMIT || self.child.try_wait().unwrap().is_some() {
                let _ = self.child.kill();
                let (out, err) = (self.out.lock().unwrap().clone(), self.err.lock().unwrap().clone());
                panic!("no {text:?} on {what}; stdout: {out:?}; stderr: {err:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The exit code, within the limit, stdout and stderr.
    fn end(&mut self) -> (Option<i32>, String, String) {
        let started = Instant::now();
        let code = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status.code();
            }
            if started.elapsed() > LIMIT {
                let _ = self.child.kill();
                panic!("podssh did not end; stderr: {:?}", self.err.lock().unwrap());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // A process ends before its readers have taken the last bytes from
        // the pipes; each reader drops its handle at the end of its stream.
        for seen in [&self.out, &self.err] {
            let reading = Instant::now();
            while Arc::strong_count(seen) > 1 && reading.elapsed() < LIMIT {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        (code, self.out.lock().unwrap().clone(), self.err.lock().unwrap().clone())
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(windows)]
type Term = conpty_harness::Console;
#[cfg(target_os = "linux")]
type Term = pty_harness::Pty;

impl Stand {
    /// `podssh ssh` in a pseudo console, with the environment of
    /// [`Stand::command`].
    #[cfg(windows)]
    fn terminal(&self, extra: &[&str]) -> Term {
        let mut line = vec![env!("CARGO_BIN_EXE_podssh").to_string()];
        line.extend(self.ssh(extra));
        let quoted: Vec<String> =
            line.iter().map(|w| if w.contains(' ') { format!("\"{w}\"") } else { w.clone() }).collect();
        let home = self.session.home.display().to_string();
        let cache = self.session.home.join("cache").display().to_string();
        let mut changes = vec![
            ("PODSSH_SSH_CONFIG", Some("none")),
            ("HOME", Some(home.as_str())),
            ("USERPROFILE", Some(home.as_str())),
            ("XDG_CACHE_HOME", Some(cache.as_str())),
            ("LOCALAPPDATA", Some(cache.as_str())),
            ("SSL_CERT_FILE", Some(self.ca.as_str())),
            ("PODSSH_OFFLINE", None),
            ("PODSSH_IROH_RELAY", None),
            ("PODSSH_TIMEOUT", None),
            ("SSH_AUTH_SOCK", None),
            (SHELL_ID, None),
        ];
        // No proxy of the machine: the stand-in relay is on the loopback.
        changes.extend(PROXY_VARS.iter().map(|&name| (name, None)));
        conpty_harness::Console::start(&quoted.join(" "), &changes, ROWS as i16, COLS as i16)
    }

    /// `podssh ssh` in a pty, with the environment of [`Stand::command`].
    #[cfg(target_os = "linux")]
    fn terminal(&self, extra: &[&str]) -> Term {
        pty_harness::Pty::start(self.command(&self.ssh(extra)), ROWS, COLS)
    }
}

/// In a terminal: a new shell, its variable, then `~d` at the start of a
/// line. podssh says the name that the far end keeps the shell as, and
/// exits 0: the name.
#[cfg(any(windows, target_os = "linux"))]
fn detach(stand: &Stand) -> String {
    let mut term = stand.terminal(&[]);
    assert!(term.expect("[shell] ready", LIMIT), "the terminal: {:?}", term.text());
    term.send(b"MARK=kept\r");
    term.send(b"~d");
    assert!(term.expect(KEPT_AS, LIMIT), "the terminal: {:?}", term.text());
    assert_eq!(term.wait(LIMIT), Some(0), "the terminal: {:?}", term.text());
    let text = term.text();
    let at = text.find(KEPT_AS).expect("the line") + KEPT_AS.len();
    let name: String = text[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    assert_eq!(name.len(), 8, "a new name has 8 digits: {text:?}");
    name
}

/// The check of T-158: a variable set in a shell, `~d`, the list, and
/// `--attach NAME` from a new process, which reads the variable back.
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn a_shell_left_with_tilde_d_is_attached_again_by_name() {
    let Some(stand) = Stand::new("again", Plant::None) else { return };
    let name = detach(&stand);
    {
        let shells = stand.shells.lock().unwrap();
        let shell = shells.kept(&name).expect("the far end keeps the shell");
        assert_eq!((shell.mark.as_deref(), shell.attached()), (Some("kept"), false));
    }
    // The list names it, with no client.
    let (code, out, err) = stand.run(&["--attach"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains(&format!("{name} detached")), "the list: {out:?}; {err}");
    // A new process, with no terminal, joins it and reads the variable back.
    let mut run = Run::start(&stand, &["--attach", &name], None);
    run.wait_for("stdout", &format!("[{name}] attached"));
    run.send("echo M=$MARK");
    run.wait_for("stdout", "M=kept");
    run.send("exit");
    let (code, _, err) = run.end();
    assert_eq!(code, Some(0), "{err}");
    assert!(stand.shells.lock().unwrap().kept(&name).is_none(), "exit ends the kept shell");
}

/// The control of the check above: a far end that answers a detach and
/// ends the shell fails it at the read of the variable.
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn a_far_end_that_ends_the_shell_on_a_detach_fails_the_check() {
    let Some(stand) = Stand::new("forget", Plant::Forget) else { return };
    let name = detach(&stand);
    assert!(stand.shells.lock().unwrap().kept(&name).is_none(), "the planted far end kept nothing");
    let (code, out, err) = stand.run(&["--attach", &name]);
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains(&format!("no kept shell named {name}")), "{err}");
    assert!(!out.contains("M=kept"), "{out}");
}

/// A far end that keeps no shells: `--attach` and the list end with 255
/// before a session opens, and `~d` goes to the shell as two bytes.
#[test]
fn a_far_end_that_keeps_no_shells_refuses_attach_and_gets_tilde_d_as_bytes() {
    let Some(stand) = Stand::new("nooffer", Plant::NoOffer) else { return };
    for extra in [&["--attach", "work"][..], &["--attach"][..]] {
        let (code, _, err) = stand.run(extra);
        assert_eq!(code, Some(255), "{extra:?}: {err}");
        assert!(err.contains("node://lab keeps no shells"), "{extra:?}: {err}");
    }
    tilde_d_as_bytes(&stand);
}

#[cfg(any(windows, target_os = "linux"))]
fn tilde_d_as_bytes(stand: &Stand) {
    let mut term = stand.terminal(&[]);
    assert!(term.expect("[shell] ready", LIMIT), "the terminal: {:?}", term.text());
    term.send(b"\r~d\r");
    assert!(term.expect("~d: not found", LIMIT), "the terminal: {:?}", term.text());
    term.send(b"exit\r");
    assert_eq!(term.wait(LIMIT), Some(0), "the terminal: {:?}", term.text());
    assert_eq!(stand.shells.lock().unwrap().detaches, 0, "no detach was asked");
}

#[cfg(not(any(windows, target_os = "linux")))]
fn tilde_d_as_bytes(_stand: &Stand) {
    eprintln!("did not run: ~d as two bytes needs a terminal of the test, on Windows or Linux");
}

/// The far end decides who joins a shell: an attach from inside the shell
/// itself and one with an unknown name are refused, a second client is
/// refused while one has it, and `--take` takes it, ending the first
/// client's session.
#[test]
fn the_far_end_refuses_a_nested_attach_and_a_second_client_unless_take() {
    let Some(stand) = Stand::new("refusals", Plant::None) else { return };
    let id = stand.shells.lock().unwrap().keep("work", "kept");
    let (code, _, err) = stand.run_from(&["--attach", "work"], Some(id.as_str()));
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("the attach comes from inside the shell work"), "{err}");
    let (code, _, err) = stand.run(&["--attach", "nope"]);
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("no kept shell named nope"), "{err}");
    let mut first = Run::start(&stand, &["--attach", "work"], None);
    first.wait_for("stdout", "[work] attached");
    let (code, _, err) = stand.run(&["--attach", "work"]);
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("the shell work has a client; --take takes it"), "{err}");
    let mut taker = Run::start(&stand, &["--attach", "work", "--take"], None);
    taker.wait_for("stdout", "[work] attached");
    let (code, out, err) = first.end();
    assert_eq!(code, Some(255), "the first client's session ends with no status: {err}");
    assert!(out.contains("[work] taken by another client"), "{out}");
    taker.send("echo M=$MARK");
    taker.wait_for("stdout", "M=kept");
    taker.send("exit");
    let (code, _, err) = taker.end();
    assert_eq!(code, Some(0), "{err}");
}

/// Each command line that `--attach` cannot serve exits 64 before anything
/// connects: no relay, and no pair, is needed to tell.
#[test]
fn attach_refuses_what_it_cannot_serve_before_anything_connects() {
    let home = throughput_harness::scratch("attach-args");
    for (args, says) in [
        (vec!["--attach", "work", "--direct", "host"], "--attach is for a node://NAME destination"),
        (vec!["--attach", "work", "node://lab", "ls"], "cannot be combined with a remote command"),
        (vec!["--attach", "work", "-N", "node://lab"], "cannot be combined with -N"),
        (vec!["--attach", "work", "-T", "node://lab"], "cannot be combined with -T"),
        (vec!["--attach", "a b", "node://lab"], "is not a name of a kept shell"),
        (vec!["--take", "node://lab"], "--take is for --attach NAME"),
        (vec!["--attach", "work", "--persist", "node://lab"], "--persist is for a standard sshd"),
    ] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.arg("ssh").args(&args).env("PODSSH_SSH_CONFIG", "none");
        cmd.env("HOME", &home).env("USERPROFILE", &home);
        cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
        let out = cmd.stdin(Stdio::null()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    let _ = std::fs::remove_dir_all(&home);
}
