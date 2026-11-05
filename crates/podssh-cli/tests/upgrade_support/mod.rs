//! A session's bytes across a node's upgrade in place (T-668, T-679), for
//! the test of each road: the client's stdout counted, the node asked to
//! upgrade once a quarter of the bytes came, then the client's end within a
//! limit. The node becomes its binary again (the test's own, which its
//! probe takes), in the same process.

#![allow(dead_code)]

use std::io::Read;
use std::process::Child;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// What a client gave: the bytes on its stdout, its exit code, its stderr.
pub struct Came {
    pub total: u64,
    pub code: Option<i32>,
    pub err: String,
}

/// Count `client`'s stdout; once a quarter of `bytes` came, `upgrade` runs
/// (it asks the node, and waits for the node's lines); then the client's end,
/// within `limit` of each wait.
pub fn across(client: &mut Child, bytes: u64, limit: Duration, upgrade: impl FnOnce()) -> Came {
    let mut stdout = client.stdout.take().expect("the client's stdout");
    let (quarter_tx, quarter_rx) = mpsc::channel();
    let counted = std::thread::spawn(move || {
        let (mut buf, mut total, mut told) = (vec![0u8; 1 << 16], 0u64, false);
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            total += n as u64;
            if !told && total >= bytes / 4 {
                told = true;
                let _ = quarter_tx.send(());
            }
        }
        total
    });
    let mut stderr = client.stderr.take().expect("the client's stderr");
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    if quarter_rx.recv_timeout(limit).is_err() {
        let _ = client.kill();
        let _ = client.wait();
        let err = said.join().unwrap_or_default();
        panic!("a quarter of the bytes did not come before the upgrade: {err}");
    }
    upgrade();
    let deadline = Instant::now() + limit;
    let code = loop {
        if let Some(status) = client.try_wait().expect("the client's wait") {
            break status.code();
        }
        if Instant::now() > deadline {
            let _ = client.kill();
            let _ = client.wait();
            panic!("the bytes did not come within {} s of the upgrade", limit.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    Came { total: counted.join().unwrap_or_default(), code, err: said.join().unwrap_or_default() }
}

/// SIGUSR2 to the node of `pid`, as `podssh update` sends it.
#[cfg(unix)]
pub fn ask(pid: u32) {
    let pid = libc::pid_t::try_from(pid).expect("a pid");
    // SAFETY: a signal to the node that the test started, which runs.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR2) }, 0, "the signal went to the node");
}

/// Whether the node of `pid` runs: an exec in place keeps its pid.
#[cfg(unix)]
pub fn runs(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
    // SAFETY: a probe of a pid that the test started; no signal is sent.
    unsafe { libc::kill(pid, 0) == 0 }
}
