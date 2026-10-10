//! `podssh pipe` with a listening side (T-177), podssh at both ends: the
//! server `podssh pipe LISTEN stdio`, and its client `podssh pipe stdio
//! CONNECT`. Bytes go both ways, each end of input passes on, and both end
//! with 0: through a Unix socket (mode 0600, and its file goes at the end),
//! `@NAME` on Linux, an AF_UNIX socket and a named pipe on Windows, and a
//! TCP port. `PODSSH_LISTEN=no` binds nothing (78); a file that is not a
//! socket is kept (64); a socket that answers is another's (69), and one
//! that nobody serves is replaced; `--keep-listening` takes each client.

use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(20);

/// A podssh of the test, killed when the test ends, also by a panic: a
/// listener left behind would hold the runner's output open.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Deref for Running {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for Running {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

/// `podssh pipe ARGS`, with no proxy of the machine's.
fn spawn(args: &[&str], envs: &[(&str, &str)]) -> Running {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.arg("pipe").args(args);
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_LISTEN"] {
        cmd.env_remove(name);
    }
    cmd.envs(envs.iter().copied());
    Running(cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs"))
}

/// What `from` gives, as it comes, on a thread of its own.
fn collect(mut from: impl Read + Send + 'static) -> Arc<Mutex<Vec<u8>>> {
    let into = Arc::new(Mutex::new(Vec::new()));
    let kept = into.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 {
                break;
            }
            kept.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    into
}

fn text(seen: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&seen.lock().unwrap()).into_owned()
}

/// Wait until `seen` holds `want`, or panic with `what`.
fn wait_for(seen: &Arc<Mutex<Vec<u8>>>, want: &str, what: &str) {
    let started = Instant::now();
    while !text(seen).contains(want) {
        assert!(started.elapsed() < LIMIT, "{what}: no {want:?} in {:?}", text(seen));
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The exit code within the limit.
fn ended(child: &mut Child, what: &str) -> i32 {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code().unwrap_or(-1);
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("{what} did not end");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A socket's path of this test, short enough for its address.
fn socket_path(tag: &str) -> String {
    let name = format!("podssh-l-{tag}-{}.sock", std::process::id());
    let tmp = std::env::temp_dir().join(&name);
    let path = if tmp.as_os_str().len() < 90 { tmp } else { std::path::PathBuf::from("/tmp").join(name) };
    path.to_string_lossy().into_owned()
}

/// The server listens on `listen`; a client reaches it with `connect`, or
/// with what the server's line names when `connect` is `None` (a TCP port
/// that the system chose). Bytes go each way, and both end with 0.
fn both_ways(listen: &str, connect: Option<&str>) -> String {
    let mut server = spawn(&[listen, "stdio"], &[]);
    let server_err = collect(server.stderr.take().unwrap());
    let server_out = collect(server.stdout.take().unwrap());
    wait_for(&server_err, "listening on", "the server");
    let connect = match connect {
        Some(connect) => connect.to_string(),
        None => {
            let line = text(&server_err);
            let at = line.split("listening on ").nth(1).unwrap().split(": ").next().unwrap().to_string();
            format!("tcp:{at}")
        }
    };
    let mut client = spawn(&["stdio", &connect], &[]);
    let client_out = collect(client.stdout.take().unwrap());
    let client_err = collect(client.stderr.take().unwrap());
    let mut client_in = client.stdin.take().unwrap();
    client_in.write_all(b"from the client\n").unwrap();
    drop(client_in);
    wait_for(&server_out, "from the client\n", "the client's bytes at the server");
    let mut server_in = server.stdin.take().unwrap();
    server_in.write_all(b"from the server\n").unwrap();
    drop(server_in);
    wait_for(&client_out, "from the server\n", "the server's bytes at the client");
    assert_eq!(ended(&mut client, "the client"), 0, "{}", text(&client_err));
    assert_eq!(ended(&mut server, "the server"), 0, "{}", text(&server_err));
    assert_eq!(text(&server_out), "from the client\n");
    assert_eq!(text(&client_out), "from the server\n");
    text(&server_err)
}

#[test]
fn a_tcp_port_joins_one_client_both_ways_and_says_who_can_connect() {
    let said = both_ways("tcp-listen:127.0.0.1:0", None);
    assert!(said.contains("each user of this host can connect"), "{said}");
}

#[test]
fn a_unix_socket_joins_one_client_both_ways() {
    let path = socket_path("ways");
    let _ = std::fs::remove_file(&path);
    let said = both_ways(&format!("unix-listen:{path}"), Some(&format!("unix-connect:{path}")));
    assert!(said.contains("for this user's programs only"), "{said}");
    assert!(!std::path::Path::new(&path).exists(), "the socket's file goes at the end");
}

#[cfg(unix)]
#[test]
fn a_unix_socket_is_the_user_s_alone_from_its_bind() {
    use std::os::unix::fs::PermissionsExt;
    let path = socket_path("mode");
    let _ = std::fs::remove_file(&path);
    let mut server = spawn(&[&format!("unix-listen:{path}"), "stdio"], &[]);
    let server_err = collect(server.stderr.take().unwrap());
    wait_for(&server_err, "listening on", "the server");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_file(&path);
    assert_eq!(mode, 0o600, "{mode:o}");
}

#[cfg(target_os = "linux")]
#[test]
fn a_name_in_linux_s_abstract_namespace_joins_one_client_both_ways() {
    let name = format!("@podssh-listen-{}", std::process::id());
    both_ways(&format!("unix-listen:{name}"), Some(&format!("unix-connect:{name}")));
}

#[cfg(windows)]
#[test]
fn a_named_pipe_joins_one_client_both_ways() {
    let name = format!(r"\\.\pipe\podssh-listen-{}", std::process::id());
    both_ways(&format!("unix-listen:{name}"), Some(&format!("unix-connect:{name}")));
}

#[test]
fn podssh_listen_no_turns_listening_off_before_anything_binds() {
    let path = socket_path("off");
    let _ = std::fs::remove_file(&path);
    for listen in [format!("unix-listen:{path}"), "tcp-listen:0".to_string()] {
        let mut server = spawn(&[&listen, "stdio"], &[("PODSSH_LISTEN", "no")]);
        let err = collect(server.stderr.take().unwrap());
        assert_eq!(ended(&mut server, "the server"), 78, "{}", text(&err));
        assert!(text(&err).contains("PODSSH_LISTEN=no"), "{}", text(&err));
    }
    assert!(!std::path::Path::new(&path).exists(), "nothing was bound");
    let mut keep = spawn(&["--keep-listening", "stdio", "exec:x"], &[]);
    assert_eq!(ended(&mut keep, "--keep-listening alone"), 64);
}

#[test]
fn a_file_that_is_not_a_socket_is_kept_and_a_socket_that_answers_is_another_s() {
    let path = socket_path("kept");
    std::fs::write(&path, b"a file of the user's").unwrap();
    let mut server = spawn(&[&format!("unix-listen:{path}"), "stdio"], &[]);
    let err = collect(server.stderr.take().unwrap());
    assert_eq!(ended(&mut server, "the server"), 64, "{}", text(&err));
    assert_eq!(std::fs::read(&path).unwrap(), b"a file of the user's");
    std::fs::remove_file(&path).unwrap();

    let mut first = spawn(&[&format!("unix-listen:{path}"), "stdio"], &[]);
    let first_err = collect(first.stderr.take().unwrap());
    wait_for(&first_err, "listening on", "the first server");
    let mut second = spawn(&[&format!("unix-listen:{path}"), "stdio"], &[]);
    let second_err = collect(second.stderr.take().unwrap());
    assert_eq!(ended(&mut second, "the second server"), 69, "{}", text(&second_err));
    assert!(text(&second_err).contains("listens on it already"), "{}", text(&second_err));
    let _ = first.kill();
    let _ = first.wait();
    let _ = std::fs::remove_file(&path);
}

/// A socket that nobody serves, as a program that died leaves it: the
/// server takes its place.
#[cfg(unix)]
#[test]
fn a_socket_that_nobody_serves_is_replaced() {
    let path = socket_path("stale");
    let _ = std::fs::remove_file(&path);
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(std::path::Path::new(&path).exists());
    both_ways(&format!("unix-listen:{path}"), Some(&format!("unix-connect:{path}")));
}

/// Each client gets its own program; SIGTERM ends the listener, and its
/// file goes.
#[test]
fn keep_listening_joins_each_client_to_a_new_instance_of_the_other_side() {
    let path = socket_path("keep");
    let _ = std::fs::remove_file(&path);
    let program = format!("exec:'{}' --version", env!("CARGO_BIN_EXE_podssh"));
    let mut server = spawn(&["--keep-listening", &format!("unix-listen:{path}"), &program], &[]);
    let server_err = collect(server.stderr.take().unwrap());
    wait_for(&server_err, "listening on", "the server");
    for n in 1..=2 {
        let mut client = spawn(&["stdio", &format!("unix-connect:{path}")], &[]);
        let out = collect(client.stdout.take().unwrap());
        drop(client.stdin.take());
        assert_eq!(ended(&mut client, "a client"), 0, "client {n}: {}", text(&server_err));
        assert!(text(&out).starts_with("podssh "), "client {n}: {:?}", text(&out));
    }
    assert!(server.try_wait().unwrap().is_none(), "the server still listens");
    #[cfg(unix)]
    {
        // SAFETY: a signal to the child that this test started.
        unsafe { libc::kill(server.id() as i32, libc::SIGTERM) };
        assert_eq!(ended(&mut server, "the server"), 143, "{}", text(&server_err));
        assert!(!std::path::Path::new(&path).exists(), "SIGTERM removes the socket's file");
    }
    #[cfg(not(unix))]
    {
        let _ = server.kill();
        let _ = server.wait();
        let _ = std::fs::remove_file(&path);
    }
}
