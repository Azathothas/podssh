//! `podssh pipe A B` (T-174) as a process, with podssh itself as the child,
//! so that no other tool is needed, on Windows too: the child's output and
//! its status come through, an address is checked before anything starts,
//! and a descriptor that is not open is refused. `unix-connect:` (T-176)
//! reaches a server of the test that reads to the end of its input and
//! answers with the SHA-256 of what it read: an AF_UNIX socket, and on
//! Windows a named pipe too.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// `podssh pipe ARGS`, stdin at its end: (code, stdout, stderr).
fn pipe(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .arg("pipe")
        .args(args)
        // The ssh_config of the machine that runs the test must not change it.
        .env("PODSSH_SSH_CONFIG", "none")
        .env_remove("PAGER")
        .stdin(Stdio::null())
        .output()
        .expect("podssh runs");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// `exec:` of podssh itself with `words`, its path in quotes.
fn podssh_with(words: &str) -> String {
    format!("exec:'{}' {words}", env!("CARGO_BIN_EXE_podssh"))
}

#[test]
fn the_child_s_output_comes_through_and_its_status_is_the_pipe_s() {
    let (code, out, err) = pipe(&["stdio", &podssh_with("man --no-pager")]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("podssh pipe"), "the manual came through: {} bytes", out.len());
    // The child's own status, a usage error.
    let (code, _, err) = pipe(&["-", &podssh_with("man nonsense")]);
    assert_eq!(code, 64, "{err}");
    // With a child on each side, B's status.
    let (code, _, err) = pipe(&[&podssh_with("--version"), &podssh_with("man nonsense")]);
    assert_eq!(code, 64, "{err}");
}

#[test]
fn a_program_that_is_not_found_gives_127_as_a_shell_gives() {
    let (code, out, err) = pipe(&["stdio", "exec:podssh-no-such-program --x"]);
    assert_eq!(code, 127, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("podssh-no-such-program"), "{err}");
}

#[test]
fn each_address_is_checked_before_anything_starts() {
    for (args, code, says) in [
        (&["stdio", "-"][..], 64, "stdio on both sides"),
        (&["stdio"][..], 64, "missing B"),
        (&[][..], 64, "missing A and B"),
        (&["stdio", "udp:example.org:80"][..], 64, "the kinds are"),
        (&["stdio", "exec:sh -c 'exit"][..], 64, "does not close"),
        (&["stdio", "serial:/dev/ttyS0"][..], 70, "not built yet"),
        (&["fd:x", "stdio"][..], 64, "fd:"),
    ] {
        let (rc, out, err) = pipe(args);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: stdout {out:?}");
    }
}

/// A number that no test runner hands on: cargo's jobserver can leave low
/// ones open.
#[test]
fn a_descriptor_that_is_not_open_is_refused() {
    let (code, _, err) = pipe(&["fd:987", "stdio"]);
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("fd:987"), "{err}");
}

/// The hex SHA-256 of `bytes`, as the test's servers answer.
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// `podssh pipe stdio ADDRESS` with `input` on stdin, within 10 s: (code,
/// stdout, stderr). A server that never answers fails at the limit.
fn through(address: &str, input: Vec<u8>) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["pipe", "stdio", address])
        // The ssh_config of the machine that runs the test must not change it.
        .env("PODSSH_SSH_CONFIG", "none")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let mut stdin = child.stdin.take().unwrap();
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{address}: no end within 10 s: the server waits for the end of its input");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// A socket's path of this test, short enough for its address.
fn socket_path(tag: &str) -> std::path::PathBuf {
    let name = format!("podssh-{tag}-{}.sock", std::process::id());
    let tmp = std::env::temp_dir().join(&name);
    if tmp.as_os_str().len() < 90 {
        tmp
    } else {
        std::path::PathBuf::from("/tmp").join(name)
    }
}

/// The servers' answer: read to the end of the input, then send its digest.
fn answer(mut stream: impl Read + Write) {
    let mut got = Vec::new();
    stream.read_to_end(&mut got).unwrap();
    let _ = stream.write_all(digest(&got).as_bytes());
}

/// A server on `path` for one connection, that answers.
#[cfg(unix)]
fn digest_server(path: &std::path::Path) -> std::thread::JoinHandle<()> {
    let listener = std::os::unix::net::UnixListener::bind(path).expect("a socket of the test");
    std::thread::spawn(move || answer(listener.accept().unwrap().0))
}

/// The same server on an AF_UNIX socket of Windows, by WinSock.
#[cfg(windows)]
fn digest_server(path: &std::path::Path) -> std::thread::JoinHandle<()> {
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
        answer(stream);
    })
}

#[test]
fn unix_connect_passes_the_end_of_input_on_and_the_answer_comes_back() {
    let path = socket_path("digest");
    let _ = std::fs::remove_file(&path);
    let server = digest_server(&path);
    let sent: Vec<u8> = (0..1_000_000u32).map(|i| (i.wrapping_mul(31) % 251) as u8).collect();
    let want = digest(&sent);
    let address = format!("unix-connect:{}", path.display());
    let (code, out, err) = through(&address, sent);
    let _ = server.join();
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, want, "the far end's digest of 1,000,000 bytes");
}

#[test]
fn unix_connect_to_a_missing_socket_names_it_and_a_long_name_is_refused_first() {
    let path = socket_path("missing");
    let _ = std::fs::remove_file(&path);
    let address = format!("unix-connect:{}", path.display());
    let (code, _, err) = through(&address, Vec::new());
    assert_eq!(code, 69, "{err}");
    assert!(err.contains(&path.display().to_string()), "{err}");
    let long = format!("unix-connect:/{}", "x".repeat(200));
    let (code, _, err) = pipe(&["stdio", &long]);
    assert_eq!(code, 64, "{err}");
}

/// Linux's abstract namespace: `@NAME` names a socket with no file.
#[cfg(target_os = "linux")]
#[test]
fn unix_connect_reaches_a_name_in_linux_s_abstract_namespace() {
    use std::os::linux::net::SocketAddrExt;
    let name = format!("podssh-test-{}", std::process::id());
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind_addr(&addr).expect("an abstract socket of the test");
    let server = std::thread::spawn(move || answer(listener.accept().unwrap().0));
    let sent = b"through the abstract namespace".to_vec();
    let want = digest(&sent);
    let (code, out, err) = through(&format!("unix-connect:@{name}"), sent);
    let _ = server.join();
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, want, "{err}");
}

/// A named pipe of Windows: the server's greeting comes through, and its
/// close ends the pipe, as a named pipe has no half-close.
#[cfg(windows)]
#[test]
fn unix_connect_reaches_a_named_pipe_on_windows() {
    use tokio::io::AsyncWriteExt;
    let name = format!(r"\\.\pipe\podssh-test-{}", std::process::id());
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let mut server = runtime
        .block_on(async {
            tokio::net::windows::named_pipe::ServerOptions::new().first_pipe_instance(true).create(&name)
        })
        .expect("a named pipe of the test");
    let serving = std::thread::spawn(move || {
        runtime.block_on(async move {
            server.connect().await.unwrap();
            server.write_all(b"from a named pipe\n").await.unwrap();
            let _ = server.flush().await;
            // A close, not a disconnect, which would drop what the client
            // has not read yet.
            drop(server);
        })
    });
    let (code, out, err) = through(&format!("unix-connect:{name}"), Vec::new());
    let _ = serving.join();
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "from a named pipe\n", "{err}");
}
