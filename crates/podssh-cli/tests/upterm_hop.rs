//! `-J upterm://SESSION@HOST` (T-495) against a stand-in of uptermd written
//! here: a WebSocket on the loopback that checks the two headers of upterm's
//! guest as uptermd does (`server/wsproxy.go`), answers 400 in its words when
//! one is missing, ends the WebSocket with a Close 1011 for a session that
//! it does not know, and else carries the SSH inside to the harness's server,
//! which stands for uptermd's SSH: it lets the session's user in and serves
//! the next hop's `direct-tcpip` channel, which reaches the "host's sshd", a
//! second server of the harness. The form `upterm+ws://` keeps it on this
//! host. uptermd's own certificate under `@cert-authority`, and a session of
//! a real upterm host, run against upterm's release in
//! `scripts/interop-upterm.sh`.

mod ssh_harness;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The ID of the session that the stand-in knows.
const SESSION: &str = "tester-session-1";
/// The header and value of a guest of upterm.
const VERSION: (&str, &str) = ("upterm-client-version", "SSH-2.0-upterm-client-client");

const STEERING: &[&str] =
    &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "SSH_AUTH_SOCK", "DISPLAY"];

/// A scratch directory, removed when the test ends, as it passes or fails.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("podssh-upterm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The stand-ins, kept up by the runtime: uptermd's WebSocket, the harness
/// server behind it, and the host's sshd; and the heads that the WebSocket
/// got.
struct Stand {
    // Held, not read: its servers run while it lives.
    _runtime: tokio::runtime::Runtime,
    ws_port: u16,
    sshd_port: u16,
    heads: Arc<Mutex<Vec<String>>>,
}

fn key(home: &Scratch, name: &str) -> PathBuf {
    let key = home.0.join(name);
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(&key)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
    key
}

fn stand(home: &Scratch) -> Stand {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let uptermd_ssh = runtime.block_on(ssh_harness::start(&key(home, "uptermd_key")));
    let sshd_port = runtime.block_on(ssh_harness::start(&key(home, "host_key")));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let ws_port = runtime.block_on(websocket(uptermd_ssh, heads.clone()));
    Stand { _runtime: runtime, ws_port, sshd_port, heads }
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

/// A header's value, by its name in any case.
fn header(head: &str, name: &str) -> Option<String> {
    head.split("\r\n").find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
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

/// uptermd's WebSocket: its port.
async fn websocket(ssh_port: u16, heads: Arc<Mutex<Vec<String>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let heads = heads.clone();
            tokio::spawn(async move {
                let head = head(&mut tcp).await;
                heads.lock().unwrap().push(head.clone());
                // uptermd's checks before the upgrade, in its words.
                if header(&head, VERSION.0).is_none() {
                    let body = "missing upterm client version";
                    let answer = format!("HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                    let _ = tcp.write_all(answer.as_bytes()).await;
                    return;
                }
                let user = header(&head, "authorization")
                    .and_then(|v| v.strip_prefix("Basic ").map(str::to_string))
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                    .and_then(|raw| String::from_utf8(raw).ok());
                let Some(user) = user else {
                    let body = "basic auth failed";
                    let answer = format!("HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                    let _ = tcp.write_all(answer.as_bytes()).await;
                    return;
                };
                let key = header(&head, "sec-websocket-key").unwrap_or_default();
                let accept = podssh_ws::handshake::accept_key(&key);
                let answer = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                if tcp.write_all(answer.as_bytes()).await.is_err() {
                    return;
                }
                let session = user.split_once(':').map_or(user.as_str(), |(id, _)| id).to_string();
                if session != SESSION {
                    // A Close 1011 with its reason, as uptermd's wsError.
                    let reason = format!("error resolving SSH user {session}: session not found");
                    let mut payload = 1011u16.to_be_bytes().to_vec();
                    payload.extend_from_slice(reason.as_bytes());
                    let _ = tcp.write_all(&server_frame(8, &payload)).await;
                    return;
                }
                if let Ok(ssh) = TcpStream::connect(("127.0.0.1", ssh_port)).await {
                    bridge(tcp, ssh).await;
                }
            });
        }
    });
    port
}

/// The WebSocket's binary frames to and from the SSH server behind it.
async fn bridge(ws: TcpStream, ssh: TcpStream) {
    let (mut ws_read, mut ws_write) = ws.into_split();
    let (mut ssh_read, mut ssh_write) = ssh.into_split();
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

/// `podssh ARGS` in `home`, with no proxy of the machine; its code, stdout
/// and stderr, within 60 s.
fn podssh(home: &Scratch, args: &[String]) -> (i32, Vec<u8>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("HOME", &home.0).env("XDG_CONFIG_HOME", home.0.join("config"));
    for name in STEERING {
        cmd.env_remove(name);
    }
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let started = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("podssh did not end within 60 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// `podssh ssh -J upterm+ws://SESSION@127.0.0.1:WS tester@127.0.0.1:SSHD
/// COMMAND`, the far ends' keys recorded in `known_hosts` of `home`.
fn through(home: &Scratch, stand: &Stand, session: &str, strict: &str, command: &str) -> (i32, Vec<u8>, String) {
    let args = [
        "ssh",
        "-o",
        &format!("StrictHostKeyChecking={strict}"),
        "-o",
        &format!("UserKnownHostsFile={}", home.0.join("known_hosts").display()),
        "-J",
        &format!("upterm+ws://{session}@127.0.0.1:{}", stand.ws_port),
        &format!("tester@127.0.0.1:{}", stand.sshd_port),
        command,
    ];
    podssh(home, &args.map(String::from))
}

#[test]
fn a_command_runs_on_the_host_s_sshd_with_an_upterm_session_as_the_first_hop() {
    let home = Scratch::new("hop");
    let stand = stand(&home);
    let (code, out, err) = through(&home, &stand, SESSION, "accept-new", "greet");
    assert_eq!(code, 0, "{err}");
    assert_eq!(String::from_utf8_lossy(&out), ssh_harness::GREETING, "{err}");
    let heads = stand.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "one WebSocket: {heads:?}");
    let expected = base64::engine::general_purpose::STANDARD.encode(format!("{SESSION}:"));
    assert_eq!(header(&heads[0], "authorization"), Some(format!("Basic {expected}")), "{}", heads[0]);
    assert_eq!(header(&heads[0], VERSION.0).as_deref(), Some(VERSION.1), "{}", heads[0]);
    assert!(heads[0].starts_with("GET / HTTP/1.1\r\n"), "{}", heads[0]);
    // uptermd's key is kept under its own name and port, as upterm keys it.
    let known = std::fs::read_to_string(home.0.join("known_hosts")).unwrap_or_default();
    assert!(known.contains(&format!("[127.0.0.1]:{}", stand.ws_port)), "{known}");
}

#[test]
fn a_session_that_uptermd_knows_not_is_refused_in_its_words() {
    let home = Scratch::new("gone");
    let stand = stand(&home);
    // podssh ssh exits 255 for any first hop that it did not reach, as
    // OpenSSH does; the words say why.
    let (code, _, err) = through(&home, &stand, "a-session-that-ended", "accept-new", "greet");
    assert_eq!(code, 255, "{err}");
    assert!(err.contains("knows no session a-session-that-ended"), "{err}");
    assert!(err.contains("1011"), "uptermd's code: {err}");
    // podssh proxy gives the road's own code: a refusal, 77.
    let target = format!("upterm+ws://a-session-that-ended@127.0.0.1:{}", stand.ws_port);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["proxy", &target]).env("HOME", &home.0);
    for name in STEERING {
        cmd.env_remove(name);
    }
    let out = cmd.stdin(Stdio::piped()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(77), "{err}");
    assert!(err.contains("knows no session a-session-that-ended"), "{err}");
}

/// The plant of T-495: a hop whose key is not checked takes this one.
#[test]
fn uptermd_with_a_key_that_known_hosts_does_not_hold_is_refused() {
    let home = Scratch::new("key");
    let stand = stand(&home);
    let other = key(&home, "other_key");
    let public = std::fs::read_to_string(other.with_extension("pub")).unwrap();
    let line = format!("[127.0.0.1]:{} {}", stand.ws_port, public.trim());
    std::fs::write(home.0.join("known_hosts"), format!("{line}\n")).unwrap();
    let (code, out, err) = through(&home, &stand, SESSION, "yes", "greet");
    assert_eq!(code, 255, "{err}");
    assert!(out.is_empty(), "nothing ran: {err}");
    assert!(err.to_ascii_lowercase().contains("host key"), "{err}");
}

#[test]
fn proxy_gives_uptermd_s_ssh_as_upterm_s_own_proxy_does() {
    let home = Scratch::new("proxy");
    let stand = stand(&home);
    let target = format!("upterm+ws://{SESSION}@127.0.0.1:{}", stand.ws_port);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["proxy", &target]).env("HOME", &home.0);
    for name in STEERING {
        cmd.env_remove(name);
    }
    // stdin stays open: its end would end the WebSocket at once.
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut first = [0u8; 8];
        let read = stdout.read_exact(&mut first).map(|()| first.to_vec());
        let _ = tx.send(read);
    });
    let got = rx.recv_timeout(Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();
    let first = got.expect("uptermd's first bytes within 30 s").expect("bytes on stdout");
    assert_eq!(&first, b"SSH-2.0-", "the server's version line, as SSH begins");
}

#[test]
fn a_far_uptermd_over_ws_and_a_session_with_no_id_are_refused_before_anything_connects() {
    let home = Scratch::new("usage");
    for (destination, says) in
        [("upterm+ws://abc@uptermd.example", "this host alone"), ("upterm://uptermd.example", "SESSION@HOST")]
    {
        let (code, _, err) = podssh(&home, &["ssh".to_string(), destination.to_string(), "true".to_string()]);
        assert_eq!(code, 64, "{destination}: {err}");
        assert!(err.contains(says), "{destination}: {err}");
    }
}
