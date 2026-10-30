//! The keys of the broadcast on Unix (T-185): SIGQUIT, the emergency stop,
//! as a terminal sends it at Ctrl-\; SIGINT, which goes to no host while
//! the input goes on, and after its end cuts the hosts that still run; and
//! on Linux, Ctrl-\ typed into a pty that is podssh's controlling terminal,
//! which drops the line that is half typed too.

use super::*;

/// Send `signal` to podssh, as a terminal does at a key.
fn kill(run: &Run, signal: libc::c_int) {
    // SAFETY: kill sends a signal to podssh's process and does nothing else.
    let sent = unsafe { libc::kill(run.child.id() as libc::pid_t, signal) };
    assert_eq!(sent, 0, "kill: {}", std::io::Error::last_os_error());
}

/// SIGINT while the input goes on: a word, and podssh goes on; the caller's
/// run then ends with 0, which a SIGINT that ended podssh would not give.
pub(super) fn ctrl_c_goes_to_no_host(run: &Run) {
    kill(run, libc::SIGINT);
    run.shows("podssh: Ctrl-C goes to no host");
}

/// The Prove's planted defect, SIGQUIT ignored, fails here: no word comes,
/// the line after the stop reaches the slow host, and its queue is not
/// cleared.
#[test]
fn interactive_sigquit_stops_the_broadcast_and_drops_what_waits() {
    let home = scratch("broadcast-stop");
    let (_runtime, port) = server(&home);
    let (a, slow) = (host("a", port), host("stall-b", port));
    let at = |name: &str| home.join(name).display().to_string();
    let mut run = Run::start(&home, &words(&home, &[], &[&a, &slow]));
    run.type_in("echo go\n");
    run.shows(&format!("{a}: go"));
    run.shows(&format!("{slow}: go"));
    // More than the slow shell's window, so that the last line waits in
    // its queue; the other host reads each line at once.
    run.type_in(&format!("{}touch {}\n", padding(48), at("queued")));
    assert!(until(LIMIT, || left(&home, "queued", "a")), "a never ran the line: {}", run.stderr());
    kill(&run, libc::SIGQUIT);
    run.shows("podssh: broadcast stopped; :all starts it again");
    run.type_in(&format!("touch {}\n:all\ntouch {}\n", at("nowhere"), at("after")));
    run.close();
    let code = run.end();
    let err = run.stderr();
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("bytes that waited were dropped"), "{err}");
    assert!(!left(&home, "queued", "stall-b"), "the line that waited for the slow host went to it: {err}");
    assert!(!left(&home, "nowhere", "a") && !left(&home, "nowhere", "stall-b"), "a line after the stop went out");
    assert!(left(&home, "after", "a") && left(&home, "after", "stall-b"), ":all started it again: {err}");
}

/// After the end of the input, SIGINT ends the wait for a shell that still
/// runs: its host is cut, with 130.
#[test]
fn interactive_ctrl_c_after_the_end_of_the_input_cuts_the_hosts() {
    let home = scratch("broadcast-cut");
    let (_runtime, port) = server(&home);
    let slow = host("stall-b", port);
    let mut run = Run::start(&home, &words(&home, &[], &[&slow]));
    run.type_in("echo go\n");
    run.shows(&format!("{slow}: go"));
    // The shell reads nothing for a while: it does not see the end yet.
    run.type_in(&padding(1));
    run.close();
    run.shows("podssh: the end of the input: each shell ends once it has read its lines");
    let sent = Instant::now();
    kill(&run, libc::SIGINT);
    let code = run.end();
    let err = run.stderr();
    assert_eq!(code, 130, "{err}");
    assert!(sent.elapsed() < super::shell::STALL, "the cut waited for the shell: {:?}", sent.elapsed());
    assert!(err.contains("podssh: Ctrl-C after the end of the input: the 1 hosts that still run are cut"), "{err}");
    assert!(err.contains(&format!("podssh each:   {slow}  130")), "{err}");
}

/// Ctrl-\ typed in a terminal whose program podssh is: the terminal drops
/// the line that is half typed and sends SIGQUIT, and the line never goes.
#[cfg(target_os = "linux")]
#[test]
fn interactive_ctrl_backslash_in_a_terminal_stops_the_broadcast() {
    use std::os::unix::process::CommandExt;

    let home = scratch("broadcast-pty");
    let (_runtime, port) = server(&home);
    let (a, b) = (host("a", port), host("b", port));
    let at = |name: &str| home.join(name).display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(words(&home, &[], &[&a, &b]));
    environment(&mut cmd, &home);
    // SAFETY: setsid and ioctl are safe between fork and exec, as pre_exec
    // asks. A session of its own, whose controlling terminal is the pty:
    // the terminal then sends Ctrl-\ to podssh as SIGQUIT.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut term = crate::pty_harness::Pty::start(cmd, 24, 160);
    term.send(b"echo go\r");
    for host in [&a, &b] {
        assert!(term.expect(&format!("{host}: go"), LIMIT), "{}", term.text());
    }
    term.send(format!("touch {}", at("half")).as_bytes());
    term.send(b"\x1c");
    assert!(term.expect("broadcast stopped; :all starts it again", LIMIT), "{}", term.text());
    term.send(format!(":all\rtouch {}\r\x04", at("after")).as_bytes());
    assert_eq!(term.wait(LIMIT), Some(0), "{}", term.text());
    assert!(!left(&home, "half", "a") && !left(&home, "half", "b"), "the half line went out: {}", term.text());
    assert!(left(&home, "after", "a") && left(&home, "after", "b"), "{}", term.text());
}

/// `--stop-key ^X` (T-322): Ctrl-X typed in the terminal stops the broadcast
/// and drops the line that is half typed, Ctrl-\\ is a plain key for the run,
/// and the terminal's QUIT character is Ctrl-\\ again after podssh. The
/// Prove's planted defect, the character left changed, fails the last check.
#[cfg(target_os = "linux")]
#[test]
fn interactive_stop_key_in_a_terminal_stops_the_broadcast_and_is_put_back() {
    use std::os::unix::process::CommandExt;

    let home = scratch("broadcast-stop-key");
    let (_runtime, port) = server(&home);
    let (a, b) = (host("a", port), host("b", port));
    let at = |name: &str| home.join(name).display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(words(&home, &["--stop-key", "^X"], &[&a, &b]));
    environment(&mut cmd, &home);
    // SAFETY: setsid and ioctl are safe between fork and exec, as pre_exec
    // asks: the pty becomes podssh's controlling terminal.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut term = crate::pty_harness::Pty::start(cmd, 24, 160);
    assert!(term.expect("Ctrl-X stops the broadcast at once", LIMIT), "{}", term.text());
    term.send(b"echo go\r");
    for host in [&a, &b] {
        assert!(term.expect(&format!("{host}: go"), LIMIT), "{}", term.text());
    }
    term.send(format!("touch {}", at("half")).as_bytes());
    term.send(b"\x18");
    assert!(term.expect("broadcast stopped; :all starts it again", LIMIT), "{}", term.text());
    term.send(format!(":all\rtouch {}\r\x04", at("after")).as_bytes());
    assert_eq!(term.wait(LIMIT), Some(0), "{}", term.text());
    assert!(!left(&home, "half", "a") && !left(&home, "half", "b"), "the half line went out: {}", term.text());
    assert!(left(&home, "after", "a") && left(&home, "after", "b"), "{}", term.text());
    assert_eq!(term.quit_char(), 0x1c, "the terminal's QUIT character after podssh");
}

/// A key that the terminal keeps for itself is refused with 64, before
/// anything connects.
#[test]
fn interactive_stop_key_that_the_terminal_keeps_is_refused() {
    let home = scratch("broadcast-stop-key-refused");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["each", "--interactive", "--stop-key", "^C", "a.example"]);
    environment(&mut cmd, &home);
    let out = cmd.stdin(std::process::Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(64), "{err}");
    assert!(err.contains("INTR (Ctrl-C)"), "{err}");
}
