//! The test's side of `podssh pipe` to a server of the test (T-465): podssh
//! with its input, within 10 s, and what the test gave it and what its server
//! saw, each step with its time, for the words of a run past its limit.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// The hex SHA-256 of `bytes`, as the test's servers answer.
pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// What a server of the test saw, and what the test gave podssh's stdin,
/// each step with its time since the start: the words of a run past its
/// limit say where the bytes stopped (T-465), and whether the server's input
/// ended at podssh's shutdown or only when the test killed podssh.
pub struct Seen {
    start: Instant,
    pub read: AtomicUsize,
    ended: AtomicBool,
    answered: AtomicBool,
    given: AtomicUsize,
    closed: AtomicBool,
    /// Milliseconds since `start`, plus one, of each step; 0 for none.
    closed_ms: AtomicU64,
    last_read_ms: AtomicU64,
    ended_ms: AtomicU64,
    answered_ms: AtomicU64,
    killed_ms: AtomicU64,
}

impl Default for Seen {
    fn default() -> Seen {
        let zero = || AtomicU64::new(0);
        Seen {
            start: Instant::now(),
            read: AtomicUsize::new(0),
            ended: AtomicBool::new(false),
            answered: AtomicBool::new(false),
            given: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            closed_ms: zero(),
            last_read_ms: zero(),
            ended_ms: zero(),
            answered_ms: zero(),
            killed_ms: zero(),
        }
    }
}

impl Seen {
    /// Keep the time of a step in `at`.
    fn mark(&self, at: &AtomicU64) {
        at.store(self.start.elapsed().as_millis() as u64 + 1, Ordering::SeqCst);
    }

    fn said(&self) -> String {
        let yes = |b: &AtomicBool| if b.load(Ordering::SeqCst) { "yes" } else { "no" };
        let at = |ms: &AtomicU64| match ms.load(Ordering::SeqCst) {
            0 => "never".to_string(),
            ms => format!("{} ms", ms - 1),
        };
        format!(
            "the test gave stdin {} bytes (closed: {}); the server read {} bytes (its input ended: {}, it answered: \
             {}); at: stdin closed {}, last read {}, ended {}, answered {}, podssh killed {}",
            self.given.load(Ordering::SeqCst),
            yes(&self.closed),
            self.read.load(Ordering::SeqCst),
            yes(&self.ended),
            yes(&self.answered),
            at(&self.closed_ms),
            at(&self.last_read_ms),
            at(&self.ended_ms),
            at(&self.answered_ms),
            at(&self.killed_ms)
        )
    }
}

/// `podssh pipe stdio ADDRESS` with `input` on stdin, within 10 s: (code,
/// stdout, stderr). A server that never answers fails at the limit.
pub fn through(address: &str, input: Vec<u8>) -> (i32, String, String) {
    through_seen(address, input, &Arc::new(Seen::default()))
}

/// [`through`], whose words at the limit say what `seen` holds.
pub fn through_seen(address: &str, input: Vec<u8>, seen: &Arc<Seen>) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_podssh"))
        // -v says where each direction's input ended (T-465).
        .args(["pipe", "-v", "stdio", address])
        // The ssh_config of the machine that runs the test must not change it.
        .env("PODSSH_SSH_CONFIG", "none")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let mut stdin = child.stdin.take().unwrap();
    let giving = seen.clone();
    std::thread::spawn(move || {
        for chunk in input.chunks(64 * 1024) {
            if stdin.write_all(chunk).is_err() {
                break;
            }
            giving.given.fetch_add(chunk.len(), Ordering::SeqCst);
        }
        drop(stdin);
        giving.closed.store(true, Ordering::SeqCst);
        giving.mark(&giving.closed_ms);
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            seen.mark(&seen.killed_ms);
            let _ = child.kill();
            // What podssh said before its limit names where it waited.
            let said = child.wait_with_output().map(|o| String::from_utf8_lossy(&o.stderr).into_owned());
            // The server's steps after the kill, if any come.
            std::thread::sleep(Duration::from_millis(500));
            panic!("{address}: no end within 10 s; {}; podssh said: {said:?}", seen.said());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// The servers' answer: read to the end of the input, then send its digest;
/// `seen` counts each step.
pub fn answer(mut stream: impl Read + Write, seen: &Seen) {
    let (mut got, mut buf) = (Vec::new(), vec![0u8; 64 * 1024]);
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                seen.read.fetch_add(n, Ordering::SeqCst);
                seen.mark(&seen.last_read_ms);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("the server's read: {e}"),
        }
    }
    seen.ended.store(true, Ordering::SeqCst);
    seen.mark(&seen.ended_ms);
    let _ = stream.write_all(digest(&got).as_bytes());
    seen.answered.store(true, Ordering::SeqCst);
    seen.mark(&seen.answered_ms);
}

/// A server on `path` for one connection, that answers.
#[cfg(unix)]
pub fn digest_server(path: &std::path::Path, seen: Arc<Seen>) -> std::thread::JoinHandle<()> {
    let listener = std::os::unix::net::UnixListener::bind(path).expect("a socket of the test");
    std::thread::spawn(move || answer(listener.accept().unwrap().0, &seen))
}

/// The same server on an AF_UNIX socket of Windows, by WinSock.
#[cfg(windows)]
pub fn digest_server(path: &std::path::Path, seen: Arc<Seen>) -> std::thread::JoinHandle<()> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock as ws;
    let text = path.to_str().unwrap().as_bytes().to_vec();
    // SAFETY: WinSock calls on a socket of this test, owned by the thread.
    let listener = unsafe {
        let mut data: ws::WSADATA = std::mem::zeroed();
        assert_eq!(ws::WSAStartup(0x0202, &mut data), 0);
        let s = ws::socket(ws::AF_UNIX as i32, ws::SOCK_STREAM, 0);
        assert_ne!(s, ws::INVALID_SOCKET, "AF_UNIX on this Windows");
        let mut addr: ws::SOCKADDR_UN = std::mem::zeroed();
        addr.sun_family = ws::AF_UNIX;
        for (slot, b) in addr.sun_path.iter_mut().zip(&text) {
            *slot = *b as _;
        }
        let len = std::mem::size_of::<ws::SOCKADDR_UN>() as i32;
        assert_eq!(ws::bind(s, (&addr as *const ws::SOCKADDR_UN).cast(), len), 0, "bind");
        assert_eq!(ws::listen(s, 1), 0, "listen");
        s
    };
    std::thread::spawn(move || {
        // SAFETY: the listener and the accepted socket belong to this thread.
        let stream = unsafe {
            let c = ws::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
            ws::closesocket(listener);
            std::net::TcpStream::from_raw_socket(c as u64)
        };
        answer(stream, &seen);
    })
}
