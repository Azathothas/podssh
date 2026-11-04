//! What the tests of the HTTP road (T-319) run against: a dial of the
//! loopback in place of TLS; targets there (an echo, and OpenSSH's sshd where
//! this host has one); a session that carries bytes each way and compares
//! their digests; and a stand-in of a proxy that ends TLS, as a cloud
//! container's does (T-311). The stand-in refuses each request that asks for
//! an upgrade, with a page of its own; it holds each request's body to its
//! end before it sends the request on, and, asked to, each answer to its end
//! before it passes it; it carries one request on each connection, as many
//! such proxies do. Asked to, it loses the answer of each Nth batch after
//! the role took the batch, so that the client sends the same batch again,
//! and cuts each Nth answer with bytes down in its middle.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::http_road::client::{self, End, Opened, Road, Target};
use podssh_relay::http_road::conn::{BoxIo, Dial, Dialing};
use podssh_relay::http_road::{Form, Tuning};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

/// The bound of a whole session of a test.
pub const LIMIT: Duration = Duration::from_secs(300);
pub const MIB: usize = 1 << 20;
/// The words of the stand-in's refusal of an upgrade.
pub const REFUSAL: &str = "WebSocket upgrades are not allowed by this proxy";

/// TCP to the loopback's `port`, in place of TLS.
pub fn dial(port: u16) -> Dial {
    Arc::new(move || -> Dialing {
        Box::pin(async move {
            let tcp = TcpStream::connect(("127.0.0.1", port))
                .await
                .map_err(|e| podssh_ws::ConnectError::Http(format!("the loopback's port {port}: {e}")))?;
            let _ = tcp.set_nodelay(true);
            Ok(Box::new(tcp) as BoxIo)
        })
    })
}

/// The road to the loopback's `port`, whose requests name `authority`.
pub fn road(port: u16, authority: &str) -> Road {
    Road { dial: dial(port), authority: authority.to_string() }
}

/// A session of `road` to the loopback's `target`, with `token`, in `form`.
pub async fn open(road: &Road, target: u16, token: &str, form: Option<Form>) -> Opened {
    let to = Target { host: "127.0.0.1", port: target, family: None };
    match client::open(road, &to, token, form, Tuning::default()).await {
        Ok(opened) => opened,
        Err(e) => panic!("the road did not open: {e}"),
    }
}

/// Bytes that a seed fixes (xorshift64*).
pub fn bytes(size: usize, mut seed: u64) -> Vec<u8> {
    (0..size)
        .map(|_| {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            (seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// `size` bytes out through `opened` to a target that sends `greeting`,
/// then echoes: the greeting and each byte back, once, in order, with equal
/// digests. Then the end of what this side sends, which the role passes on
/// as TCP's half-close, so that the echo ends, and the session's end.
pub async fn each_way(opened: Opened, greeting: &[u8], size: usize, seed: u64) -> Option<End> {
    let Opened { stream, ended, .. } = opened;
    let out = bytes(size, seed);
    let want = Sha256::digest(&out).to_vec();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let writing = async {
        writer.write_all(&out).await.expect("the road takes the bytes");
        writer.shutdown().await.expect("the end of the bytes up");
    };
    let reading = async {
        let total = greeting.len() + size;
        let mut back = Vec::with_capacity(total);
        let mut buf = vec![0u8; 64 * 1024];
        while back.len() < total {
            let n = reader.read(&mut buf).await.expect("the echo");
            assert!(n > 0, "the session ended after {} bytes: {:?}", back.len(), ended.get());
            back.extend_from_slice(&buf[..n]);
        }
        back
    };
    let both = async { tokio::join!(writing, reading) };
    let ((), back) = tokio::time::timeout(LIMIT, both).await.expect("the bytes went each way in time");
    assert_eq!(&back[..greeting.len()], greeting, "the target's greeting first");
    let echoed = &back[greeting.len()..];
    assert_eq!(echoed.len(), size, "each byte came back once, in order: {} bytes, not {size}", echoed.len());
    assert!(Sha256::digest(echoed).to_vec() == want, "each byte came back once, in order: the digests differ");
    let mut rest = Vec::new();
    let read = tokio::time::timeout(LIMIT, reader.read_to_end(&mut rest)).await.expect("the session's end in time");
    read.expect("the session's end");
    assert!(rest.is_empty(), "nothing after the echo: {} bytes", rest.len());
    ended.get()
}

/// A target on the loopback that sends `greeting` to each connection, then
/// echoes each byte, and ends its side once the other side ended.
pub async fn echo_target(greeting: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                if tcp.write_all(greeting).await.is_err() {
                    return;
                }
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    port
}

/// One request of HTTP/1.1 to the loopback's `port`, written whole by the
/// test: the answer's status, and its head and body as text.
pub async fn raw(port: u16, request: &str) -> (u16, String) {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let mut buf = [0u8; 4096];
    // Up to the end of the head and of a body of its length, or the close.
    loop {
        let n = tokio::time::timeout(Duration::from_secs(20), tcp.read(&mut buf)).await.expect("in time").unwrap();
        answer.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&answer).into_owned();
        let whole = text.split_once("\r\n\r\n").is_some_and(|(head, body)| {
            let named = |line: &str| line.to_ascii_lowercase().strip_prefix("content-length:").map(str::to_string);
            let length = head.lines().find_map(named);
            length.and_then(|l| l.trim().parse::<usize>().ok()).is_some_and(|l| body.len() >= l)
        });
        if n == 0 || whole {
            let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
            return (status, text);
        }
    }
}

/// What the stand-in does to the requests that it carries.
#[derive(Debug, Clone, Copy, Default)]
pub struct Faults {
    /// Each answer held to its end before it goes on.
    pub hold_answers: bool,
    /// The answer of each Nth batch lost, once the role answered it.
    pub lose_batches: Option<usize>,
    /// Each Nth answer with bytes down cut in its middle.
    pub cut_answers: Option<usize>,
}

/// What the stand-in did.
#[derive(Debug, Default)]
pub struct Counts {
    pub requests: AtomicUsize,
    pub upgrades: AtomicUsize,
    pub batches: AtomicUsize,
    pub lost: AtomicUsize,
    pub answers_down: AtomicUsize,
    pub cut: AtomicUsize,
}

/// The stand-in proxy, in front of the loopback's `upstream`.
pub struct Proxy {
    pub port: u16,
    pub counts: Arc<Counts>,
    task: AbortHandle,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Proxy {
    pub async fn start(upstream: u16, faults: Faults) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
        let port = listener.local_addr().expect("its address").port();
        let counts = Arc::new(Counts::default());
        let seen = counts.clone();
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(carry(client, upstream, faults, seen.clone()));
            }
        });
        Proxy { port, counts, task: task.abort_handle() }
    }

    pub fn count(&self, which: fn(&Counts) -> &AtomicUsize) -> usize {
        which(&self.counts).load(Ordering::SeqCst)
    }
}

/// One request of a client: refused when it asks for an upgrade, else sent
/// on once its body ended, with its answer back, as `faults` say.
async fn carry(mut client: TcpStream, upstream: u16, faults: Faults, counts: Arc<Counts>) {
    let mut buf = Vec::new();
    let end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let mut chunk = [0u8; 4096];
        match client.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    counts.requests.fetch_add(1, Ordering::SeqCst);
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut body = buf.split_off(end);
    let lines: Vec<&str> = head.split("\r\n").filter(|line| !line.is_empty()).collect();
    let header = |name: &str| {
        lines.iter().skip(1).find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_ascii_lowercase())
        })
    };
    if header("upgrade").is_some() {
        counts.upgrades.fetch_add(1, Ordering::SeqCst);
        let top = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", REFUSAL.len());
        let _ = client.write_all(format!("{top}{REFUSAL}").as_bytes()).await;
        return;
    }
    // The whole body, held, of its length.
    let length: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    while body.len() < length {
        let mut chunk = vec![0u8; 64 * 1024];
        match client.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length);
    let mut forward = format!("{}\r\n", lines[0]);
    for line in &lines[1..] {
        let name = line.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        if !matches!(name.as_str(), "content-length" | "connection" | "keep-alive") {
            forward.push_str(&format!("{line}\r\n"));
        }
    }
    forward.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    let Ok(mut server) = TcpStream::connect(("127.0.0.1", upstream)).await else { return };
    if server.write_all(forward.as_bytes()).await.is_err() || server.write_all(&body).await.is_err() {
        return;
    }
    let target = lines[0].split(' ').nth(1).unwrap_or_default();
    let batch = lines[0].starts_with("POST ") && (target.contains("/up?") || target.contains("seq="));
    let down = target.contains("/down?") || target.contains("/x?");
    let nth = |every: Option<usize>, count: &AtomicUsize| {
        let n = count.fetch_add(1, Ordering::SeqCst) + 1;
        every.is_some_and(|every| n % every == 0)
    };
    if batch && nth(faults.lose_batches, &counts.batches) {
        // The role took the batch: its answer is read, and lost.
        let mut answer = Vec::new();
        let _ = server.read_to_end(&mut answer).await;
        counts.lost.fetch_add(1, Ordering::SeqCst);
        return;
    }
    if !faults.hold_answers && faults.cut_answers.is_none() {
        let _ = tokio::io::copy(&mut server, &mut client).await;
        let _ = client.shutdown().await;
        return;
    }
    let mut answer = Vec::new();
    if server.read_to_end(&mut answer).await.is_err() {
        return;
    }
    let body_at = answer.windows(4).position(|w| w == b"\r\n\r\n").map_or(answer.len(), |at| at + 4);
    let with_bytes = answer.starts_with(b"HTTP/1.1 200") && answer.len() > body_at + 1;
    if down && with_bytes && nth(faults.cut_answers, &counts.answers_down) {
        counts.cut.fetch_add(1, Ordering::SeqCst);
        answer.truncate(body_at + (answer.len() - body_at) / 2);
    }
    let _ = client.write_all(&answer).await;
    let _ = client.shutdown().await;
}

/// OpenSSH's server on this machine's loopback, software that podssh did
/// not write: it sends its version line to each connection. It runs until
/// it is dropped, and its scratch directory goes with it.
pub struct Sshd {
    child: Child,
    dir: PathBuf,
    pub port: u16,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A program on the PATH, else in /usr/sbin, where Debian puts sshd.
fn program(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect::<Vec<_>>()).unwrap_or_default();
    let found = paths.into_iter().map(|dir| dir.join(name)).find(|p| p.is_file());
    found.or_else(|| Some(PathBuf::from("/usr/sbin").join(name)).filter(|p| p.is_file()))
}

/// sshd with a host key of its own, made by OpenSSH's ssh-keygen; else why
/// none can run here.
pub fn sshd(tag: &str) -> Result<Sshd, String> {
    let (sshd, keygen) = (program("sshd").ok_or("no sshd here")?, program("ssh-keygen").ok_or("no ssh-keygen here")?);
    let dir = std::env::temp_dir().join(format!("podssh-http-road-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let key = dir.join("host_key");
    let made = Command::new(keygen).args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).stdin(Stdio::null()).status();
    if !made.is_ok_and(|s| s.success()) {
        return Err("ssh-keygen made no host key".into());
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?.local_addr().unwrap().port();
    let config = dir.join("sshd_config");
    let mut text = format!(
        "ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nPidFile none\n",
        key.display()
    );
    std::fs::write(&config, &text).map_err(|e| e.to_string())?;
    // OpenSSH 9.8 and later penalise a source of many connections; older
    // ones do not know the keyword.
    let mut knows = Command::new(&sshd);
    knows.arg("-t").arg("-f").arg(&config).args(["-o", "PerSourcePenalties=no"]);
    if knows.stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()) {
        text.push_str("PerSourcePenalties no\n");
        std::fs::write(&config, &text).map_err(|e| e.to_string())?;
    }
    let child = Command::new(&sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{}: {e}", sshd.display()))?;
    let server = Sshd { child, dir, port };
    let deadline = Instant::now() + Duration::from_secs(15);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        if Instant::now() > deadline {
            return Err("sshd did not listen within 15 s".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(server)
}
