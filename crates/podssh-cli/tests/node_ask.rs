//! `podssh node --ask` (T-638), through the binary: with no terminal on its
//! stdin and stderr, `--ask` is refused with 78, and beside a flag with
//! which nobody could answer, with 64. On Linux, in a pty, a node of a
//! carrier (`--carrier fd:3`, a socketpair whose other end is `podssh
//! operator --carrier fd:3`) asks its person of the operator's key: a `y`
//! lets the operator in, and a `n` refuses it with 77 and no byte of TARGET,
//! though a `y` was typed before the question showed.

mod live_harness;
#[cfg(target_os = "linux")]
mod pty_harness;

use std::path::PathBuf;

use live_harness::{run, scratch};

/// Removes the scratch directory, with its keys, however the test ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ask_with_no_terminal_is_refused_with_78() {
    let home = scratch("ask-no-tty");
    let _scratch = Scratch(home.clone());
    // stdin from /dev/null, stderr a pipe: neither is a terminal.
    let (code, out, err) = run(&home, &["node", "box", "127.0.0.1:9", "--ask"]);
    assert_eq!(code, 78, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("--ask asks a person at this node's terminal"), "{err}");
}

#[test]
fn ask_beside_a_flag_with_which_nobody_could_answer_is_refused_with_64() {
    let home = scratch("ask-flags");
    let _scratch = Scratch(home.clone());
    let cases: [(&[&str], &str); 5] = [
        (&["--detach"], "--detach"),
        (&["--install"], "--install"),
        (&["--no-e2e"], "--no-e2e"),
        (&["--temporary", "AAAA"], "--temporary"),
        (&["--carrier", "stdio"], "--carrier stdio"),
    ];
    for (more, flag) in cases {
        let mut args = vec!["node", "box", "127.0.0.1:9", "--ask"];
        args.extend_from_slice(more);
        let (code, out, err) = run(&home, &args);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
        assert!(err.contains(&format!("--ask with {flag}:")), "{args:?}: {err}");
    }
}

/// The node in a pty, the operator on the other end of its carrier.
#[cfg(target_os = "linux")]
mod pty {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::live_harness::{command, echo_server, scratch, LIMIT};
    use super::pty_harness::Pty;
    use super::Scratch;

    /// `cmd` with `sock` as its fd 3, the stream of `--carrier fd:3`.
    fn with_fd3(mut cmd: Command, sock: &UnixStream) -> Command {
        let fd = sock.as_raw_fd();
        // SAFETY: between fork and exec, dup2 and fcntl alone, which are
        // async-signal-safe; each result is checked.
        unsafe {
            cmd.pre_exec(move || {
                // dup2 onto itself would keep the flag that closes it at exec.
                let rc = if fd == 3 { libc::fcntl(3, libc::F_SETFD, 0) } else { libc::dup2(fd, 3) };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd
    }

    /// What an operator gave: its code, stdout and stderr.
    struct Gave {
        code: Option<i32>,
        out: Vec<u8>,
        err: String,
    }

    /// `podssh operator box` on `sock`, with `input` on stdin, on a thread of
    /// its own; it ends within [`LIMIT`].
    fn operator(home: &Path, sock: UnixStream, input: &'static [u8]) -> mpsc::Receiver<Gave> {
        let mut cmd = with_fd3(command(home, &["operator", "--carrier", "fd:3", "box"]), &sock);
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        // The operator holds its end now: this one would keep the stream open.
        drop(sock);
        let mut stdin = child.stdin.take().unwrap();
        std::thread::spawn(move || {
            let _ = stdin.write_all(input);
        });
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut out, mut err) = (Vec::new(), String::new());
            let mut stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            let reading = std::thread::spawn(move || {
                let _ = stderr.read_to_string(&mut err);
                err
            });
            let _ = stdout.read_to_end(&mut out);
            let deadline = Instant::now() + LIMIT;
            let code = loop {
                if let Ok(Some(status)) = child.try_wait() {
                    break status.code();
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let err = reading.join().unwrap_or_default();
            let _ = tx.send(Gave { code, out, err });
        });
        rx
    }

    /// The node of `home` in a pty, in front of an echo server, on one end
    /// of a socketpair; a `y` typed before any question; then the operator
    /// on the other end, and the question, answered with `answer`.
    fn ask(home: &Path, answer: &[u8]) -> (Gave, String) {
        let target = format!("127.0.0.1:{}", echo_server());
        let (node_end, operator_end) = UnixStream::pair().unwrap();
        let node = with_fd3(command(home, &["node", "box", &target, "--carrier", "fd:3", "--ask"]), &node_end);
        let mut pty = Pty::start(node, 24, 200);
        drop(node_end);
        assert!(pty.expect("asks at this terminal", LIMIT), "{}", pty.text());
        // A line typed for nothing: it must answer no question that comes later.
        pty.send(b"y\r");
        assert!(pty.expect("online: the carrier's client takes", LIMIT), "{}", pty.text());
        let gave = operator(home, operator_end, b"hello through the person\n");
        assert!(pty.expect("let it in? y or n", LIMIT), "{}", pty.text());
        pty.send(answer);
        let gave = gave.recv_timeout(LIMIT + Duration::from_secs(15)).expect("the operator ends");
        // The stream ended with the operator: so does the node.
        let _ = pty.wait(LIMIT);
        (gave, pty.text())
    }

    #[test]
    fn a_yes_at_the_node_s_terminal_lets_the_operator_in() {
        let home = scratch("ask-yes");
        let _scratch = Scratch(home.clone());
        let (gave, node) = ask(&home, b"y\r");
        assert_eq!(gave.code, Some(0), "{}\n{node}", gave.err);
        assert_eq!(gave.out, b"hello through the person\n", "{}\n{node}", gave.err);
        assert!(node.contains("the operator key SHA256:"), "{node}");
        assert!(node.contains("asks for the node's target, which the door lets in"), "{node}");
        assert!(node.contains("came in, by the door and a yes of the node's person"), "{node}");
    }

    #[test]
    fn a_no_at_the_node_s_terminal_refuses_the_operator_with_77() {
        let home = scratch("ask-no");
        let _scratch = Scratch(home.clone());
        let (gave, node) = ask(&home, b"n\r");
        assert_eq!(gave.code, Some(77), "{}\n{node}", gave.err);
        assert!(gave.out.is_empty(), "no byte of TARGET: {:?}", gave.out);
        assert!(gave.err.contains("refused this client's key"), "{}", gave.err);
        assert!(node.contains("the node's person said no; the no stands 15 s"), "{node}");
        assert!(!node.contains("came in"), "{node}");
    }
}
