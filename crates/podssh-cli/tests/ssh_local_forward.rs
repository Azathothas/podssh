//! `-L` and `-D` (T-038) as processes: `podssh ssh -N` listens here, and
//! each connection goes on from the test's SSH server, which opens it to a
//! target service of the test. A listener that cannot be made, and
//! `PODSSH_LISTEN=no`, refuse the run before anything connects; `-W` clears
//! the forwards, as OpenSSH does.

mod cleanup;
mod ssh_harness;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-lfwd-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The tests of this file run one at a time. Each forward listens on a port
/// that nothing held a moment before (`free_port`), and a test that binds
/// port 0 meanwhile can be given that same port (seen on Windows): a client
/// then reached the other test's listener, whose end reset it.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

/// A process that is killed when the test ends, also when it fails.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The test's SSH server, its target service and a scratch directory.
struct Setup {
    home: PathBuf,
    port: u16,
    target: SocketAddr,
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    _runtime: tokio::runtime::Runtime,
}

fn setup(name: &str) -> Setup {
    let home = scratch(name);
    let key = home.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (port, connections) = runtime.block_on(ssh_harness::start_counting(&key));
    let target = runtime.block_on(target_service());
    Setup { home, port, target, connections, _runtime: runtime }
}

/// A service on the loopback that greets each client, then echoes a read.
async fn target_service() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(b"target says hi\n").await;
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            });
        }
    });
    at
}

/// A port of the loopback that nothing holds, for a moment.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Setup {
    /// `podssh ssh --direct` to the test's server, with `args` before the
    /// destination.
    fn podssh(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        let known = self.home.join("known_hosts");
        cmd.args(["ssh", "--direct", "-p", &self.port.to_string(), "-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=accept-new", "-o"])
            .arg(format!("UserKnownHostsFile={}", known.display()))
            .args(args)
            .arg("podtest@127.0.0.1")
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("PODSSH_SSH_CONFIG", "none")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in
            ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PODSSH_LISTEN"]
        {
            cmd.env_remove(name);
        }
        cmd
    }
}

/// Run to the end, within the limit.
fn ran(mut cmd: Command) -> Output {
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// A connection to `port` once something listens there, within the limit.
fn reach(port: u16, running: &mut Running) -> TcpStream {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream.set_read_timeout(Some(LIMIT)).unwrap();
            return stream;
        }
        if let Some(status) = running.0.try_wait().unwrap() {
            let mut err = String::new();
            let _ = running.0.stderr.take().unwrap().read_to_string(&mut err);
            panic!("podssh ended with {status} before it listened: {err}");
        }
        assert!(Instant::now() < deadline, "nothing listened on {port} within {LIMIT:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One line from `stream`.
fn line(stream: &mut impl Read) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while read_some(stream, &mut byte).unwrap() == 1 && byte[0] != b'\n' {
        out.push(byte[0]);
    }
    String::from_utf8(out).unwrap()
}

#[test]
fn local_forward_carries_connections_to_the_target() {
    let _one = one_at_a_time();
    let s = setup("local");
    let port = free_port();
    let spec = format!("127.0.0.1:{port}:{}", s.target);
    let mut running = Running(s.podssh(&["-N", "-L", &spec]).spawn().unwrap());
    for _ in 0..2 {
        let mut client = reach(port, &mut running);
        assert_eq!(line(&mut client), "target says hi");
        client.write_all(b"ping\n").unwrap();
        assert_eq!(line(&mut client), "ping");
    }
}

#[test]
fn dynamic_forward_is_a_socks5_proxy_to_the_target() {
    let _one = one_at_a_time();
    let s = setup("dynamic");
    let port = free_port();
    let spec = format!("127.0.0.1:{port}");
    let mut running = Running(s.podssh(&["-N", "-D", &spec]).spawn().unwrap());
    let mut client = reach(port, &mut running);
    let SocketAddr::V4(target) = s.target else { panic!("an IPv4 target") };
    let mut request = vec![5, 1, 0, 5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).unwrap();
    let mut reply = [0u8; 12];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0], "the method, then granted");
    assert_eq!(line(&mut client), "target says hi");
}

#[cfg(unix)]
#[test]
fn local_forward_listens_on_a_socket_of_mode_0600() {
    let _one = one_at_a_time();
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    let s = setup("socket");
    let path = s.home.join("l.sock");
    let spec = format!("{}:{}", path.display(), s.target);
    let mut running = Running(s.podssh(&["-N", "-L", &spec]).spawn().unwrap());
    let deadline = Instant::now() + LIMIT;
    let mut client = loop {
        if let Ok(stream) = UnixStream::connect(&path) {
            break stream;
        }
        assert!(running.0.try_wait().unwrap().is_none(), "podssh ended before it listened");
        assert!(Instant::now() < deadline, "nothing listened on {}", path.display());
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(line(&mut client), "target says hi");
}

#[test]
fn a_listener_that_cannot_be_made_refuses_before_anything_connects() {
    let _one = one_at_a_time();
    let s = setup("taken");
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let spec = format!("127.0.0.1:{port}:{}", s.target);
    let out = ran(s.podssh(&["-N", "-L", &spec]));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(err.contains(&format!("cannot listen on 127.0.0.1:{port}")) && err.contains("-W HOST:PORT"), "{err}");
    assert_eq!(s.connections.load(Ordering::SeqCst), 0, "nothing connected");
    // PODSSH_LISTEN=no turns each listener off: 78, nothing connected.
    let mut cmd = s.podssh(&["-N", "-L", &format!("127.0.0.1:{}:{}", free_port(), s.target)]);
    cmd.env("PODSSH_LISTEN", "no");
    let out = ran(cmd);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(78), "{err}");
    assert!(err.contains("PODSSH_LISTEN=no"), "{err}");
    assert_eq!(s.connections.load(Ordering::SeqCst), 0, "nothing connected");
}

#[test]
fn stdio_forward_clears_the_forwards_as_openssh_does() {
    let _one = one_at_a_time();
    let s = setup("stdio");
    let port = free_port();
    let mut cmd = s.podssh(&["-W", &s.target.to_string(), "-L", &format!("127.0.0.1:{port}:{}", s.target)]);
    cmd.stdin(Stdio::piped());
    let mut running = Running(cmd.spawn().unwrap());
    let mut stdout = running.0.stdout.take().unwrap();
    assert_eq!(line(&mut stdout), "target says hi", "-W carries the stream");
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "-W made -L listen");
}

/// One read, again while a signal interrupts it: `Read::read` does not
/// retry by itself, and a test's children send it SIGCHLD.
fn read_some(stream: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match stream.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}
