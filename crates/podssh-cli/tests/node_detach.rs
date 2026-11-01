//! `podssh node --detach` (T-380) through the stand-in relay's reverse road
//! on the loopback: the parent returns 0 once the node is online, with the
//! child's pid, and a client then logs in through the node that runs in the
//! background. The check says that it did not run when this host has no
//! Python or no openssl for the stand-in.
#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;

use throughput_harness::{Cell, Session};

/// The parent's run to its end, within a minute: a node that never says
/// that it is ready must fail the test, not hold it.
fn within(cmd: &mut std::process::Command) -> std::process::Output {
    let mut child = cmd.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("the parent of --detach did not return within 60 s");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn a_detached_node_returns_once_online_and_serves_in_the_background() {
    let session = Session::start("detach");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| session.stand_in(args, &ca);
    let mut args = vec!["relay".to_string(), "pair".into(), "lab".into(), "--relay-host".into(), relay];
    args.extend(pins.iter().cloned());
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let mut args = vec!["node".to_string(), "lab".into(), format!("127.0.0.1:{}", session.port), "--detach".into()];
    args.extend(pins.iter().cloned());
    let out = within(command(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let online = err.find("online").expect("the node said online before the parent returned");
    let background = err.find("in the background, pid ").expect("the parent names the child");
    assert!(online < background, "{err}");
    let pid: i32 = err[background + "in the background, pid ".len()..]
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    struct Ends(i32);
    impl Drop for Ends {
        fn drop(&mut self) {
            // SAFETY: a signal to the test's own detached node.
            unsafe { libc::kill(self.0, libc::SIGTERM) };
        }
    }
    let _node = Ends(pid);
    let mut args = vec!["ssh".to_string(), "-v".into()];
    args.extend(session.common());
    args.extend(pins);
    args.extend(["node://tester@lab".to_string(), "greet".into()]);
    let out = command(&args).stdin(Stdio::null()).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(text, ssh_harness::GREETING);
}
