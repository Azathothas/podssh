//! `--chisel` (T-490) against a stand-in of chisel's server, written here:
//! a WebSocket that takes the subprotocol `chisel-v3` and answers anything
//! else with chisel's 404 "Not found", and russh's SSH server inside it with
//! a key and a password of the test. russh's server answers a global request
//! that it does not know with a failure, so the stand-in refuses chisel's
//! `config` as a server refuses a remote that its authfile does not allow:
//! each step before a tunnel runs here, with its words and its exit code.
//! The tunnel itself, sshd's banner and 1 MiB each way, run against chisel's
//! own server in `scripts/interop-chisel.sh`.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use russh::keys::ssh_key::private::{Ed25519Keypair, PrivateKey};
use russh::server::{self, Auth};
use sha2::Digest as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "podssh";
/// The password of the stand-in, made up for it.
const RIGHT: &str = "a-password-of-this-test";

struct Far;

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == RIGHT { Auth::Accept } else { Auth::reject() })
    }
}

/// The stand-in's key, and its fingerprint as chisel prints one.
fn key() -> (PrivateKey, String) {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    let wire = key.public_key().to_bytes().unwrap();
    let print = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&wire));
    (key, print)
}

/// Read a request's head; the bytes after it are none, as a client waits.
async fn head(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") && buf.len() < 16384 {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// One WebSocket frame of the client's, unmasked: its opcode and payload.
async fn frame(r: &mut (impl AsyncReadExt + Unpin)) -> Option<(u8, Vec<u8>)> {
    let mut two = [0u8; 2];
    r.read_exact(&mut two).await.ok()?;
    let len = match two[1] & 0x7f {
        126 => u64::from(r.read_u16().await.ok()?),
        127 => r.read_u64().await.ok()?,
        n => u64::from(n),
    };
    let mut mask = [0u8; 4];
    if two[1] & 0x80 != 0 {
        r.read_exact(&mut mask).await.ok()?;
    }
    let mut payload = vec![0u8; usize::try_from(len).ok()?];
    r.read_exact(&mut payload).await.ok()?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Some((two[0] & 0x0f, payload))
}

/// A server's frame: unmasked, as a server sends.
fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n < 65536 => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// The stand-in on the loopback: its port.
async fn stand_in(key: PrivateKey) -> u16 {
    let mut config = server::Config::default();
    config.keys.push(key);
    config.server_id = russh::SshId::Standard("SSH-chisel-v3-server".into());
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                let head = head(&mut tcp).await;
                let lower = head.to_ascii_lowercase();
                if !lower.contains("\r\nsec-websocket-protocol: chisel-v3\r\n") {
                    let _ = tcp.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot found").await;
                    return;
                }
                // The client's key as it sent it: base64 keeps its case.
                let key = head
                    .split("\r\n")
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.trim().eq_ignore_ascii_case("sec-websocket-key").then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                let accept = podssh_ws::handshake::accept_key(&key);
                let answer = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                if tcp.write_all(answer.as_bytes()).await.is_err() {
                    return;
                }
                bridge(tcp, config).await;
            });
        }
    });
    port
}

/// The WebSocket's binary frames to and from russh's server.
async fn bridge(tcp: TcpStream, config: Arc<server::Config>) {
    let (ours, theirs) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, theirs, Far).await {
            let _ = session.await;
        }
    });
    let (mut ws_read, mut ws_write) = tcp.into_split();
    let (mut ssh_read, mut ssh_write) = tokio::io::split(ours);
    let up = async move {
        while let Some((opcode, payload)) = frame(&mut ws_read).await {
            match opcode {
                2 | 0 => {
                    if ssh_write.write_all(&payload).await.is_err() {
                        return;
                    }
                }
                8 => return,
                _ => {}
            }
        }
    };
    let down = async move {
        let mut buf = vec![0u8; 32768];
        while let Ok(n) = ssh_read.read(&mut buf).await {
            if n == 0 || ws_write.write_all(&server_frame(2, &buf[..n])).await.is_err() {
                return;
            }
        }
    };
    tokio::join!(up, down);
}

/// A private file of the test with `text`.
fn private(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path.display().to_string()
}

/// `podssh proxy --chisel URL ARGS sshd.test 22`, with nothing on stdin and
/// none of the machine's settings: (code, stderr).
fn proxy(home: &Path, url: &str, args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["proxy", "--chisel", url]).args(args).args(["sshd.test", "22"]);
    cmd.env("HOME", home).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_CACHE_DIR", home.join("cache"));
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "PODSSH_CHISEL"] {
        cmd.env_remove(name);
    }
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn each_step_before_the_tunnel_says_its_words_and_its_code() {
    let (key, print) = key();
    let port = stand_in(key).await;
    let url = format!("http://127.0.0.1:{port}");
    let dir = tempfile_dir("chisel");
    let home = dir.to_path_buf();

    let right = private(&dir, "right", &format!("auth {USER}:{RIGHT}\nfingerprint {print}\n"));
    let wrong_pass = private(&dir, "wrong-pass", &format!("auth {USER}:not-{RIGHT}\nfingerprint {print}\n"));
    let other_print = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let wrong_print = private(&dir, "wrong-print", &format!("auth {USER}:{RIGHT}\nfingerprint {other_print}\n"));

    let run = |args: Vec<String>| {
        let home = home.clone();
        let url = url.clone();
        tokio::task::spawn_blocking(move || {
            let words: Vec<&str> = args.iter().map(String::as_str).collect();
            proxy(&home, &url, &words)
        })
    };
    let file = |f: &str| vec!["--chisel-auth-file".to_string(), f.to_string()];

    // The right user, password and key: the login passes, and the stand-in
    // refuses the `config` as an authfile refuses a remote.
    let (code, err) = run(file(&right)).await.unwrap();
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("refused the tunnel to sshd.test:22"), "{err}");
    assert!(!err.contains(RIGHT), "no password in the words: {err}");

    let (code, err) = run(file(&wrong_pass)).await.unwrap();
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("refused the user and password of --chisel-auth-file"), "{err}");

    // The plant of T-490: a key that is not checked passes this one.
    let (code, err) = run(file(&wrong_print)).await.unwrap();
    assert_eq!(code, 77, "{err}");
    assert!(err.contains(&format!("showed the key {print}, not the fingerprint {other_print}")), "{err}");

    let (code, err) = run(Vec::new()).await.unwrap();
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("asks for a user and password"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_is_not_chisel_s_says_chisel_s_404() {
    // A server that answers each upgrade with chisel's own 404, as one
    // whose subprotocol is not chisel-v3 does.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let _ = head(&mut tcp).await;
            let _ = tcp.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot found").await;
        }
    });
    let home = tempfile_dir("chisel-404");
    let url = format!("http://127.0.0.1:{port}");
    let (code, err) = tokio::task::spawn_blocking(move || proxy(&home, &url, &[])).await.unwrap();
    assert_eq!(code, 69, "{err}");
    assert!(err.contains("refused the WebSocket: 404 Not found; the words of a chisel server"), "{err}");
}

#[test]
fn a_flag_of_another_road_or_a_server_in_the_clear_is_refused_first() {
    let home = tempfile_dir("chisel-usage");
    let (code, err) = proxy(&home, "https://chisel.example.org", &["--vless", "servers.txt"]);
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("--chisel cannot go with --vless"), "{err}");
    let (code, err) = proxy(&home, "http://chisel.example.org", &[]);
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("in the clear"), "{err}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let open = home.join("open");
        std::fs::write(&open, "auth u:p\n").unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (code, err) = proxy(&home, "https://chisel.example.org", &["--chisel-auth-file", open.to_str().unwrap()]);
        assert_eq!(code, 78, "a file that others may read: {err}");
    }
}

/// A new directory of the test under the system's temporary one.
fn tempfile_dir(tag: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("podssh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A test's directory, gone when the test ends, failed or not: the gate
/// refuses a test that leaves one in the temporary directory.
struct Scratch(std::path::PathBuf);

impl std::ops::Deref for Scratch {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
