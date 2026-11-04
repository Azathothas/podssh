//! The parts of the tests of the relay role's forward road in the resumable
//! layer (T-173): a forwarder in front of the role that cuts each of the
//! first links at a point of its own, with no word to either end, as a
//! client's network that drops; a target that sends back each byte; and
//! OpenSSH's own client and server, software that podssh did not write,
//! started on the loopback where this host has them.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::relay::Relay;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

/// The largest request head that a link sends.
const HEAD_MOST: usize = 16 * 1024;

/// The byte at `i` of the test's data: not one byte over and over, and the
/// same at each run.
pub fn byte_at(i: u64) -> u8 {
    (i.wrapping_mul(2_654_435_761) >> 13) as u8
}

/// The next number of an xorshift: the points of the cuts, the same at each
/// run, so that a failure can be run again.
pub fn next(x: &mut u32) -> u32 {
    *x ^= *x << 13;
    *x ^= *x >> 17;
    *x ^= *x << 5;
    *x
}

/// A forwarder on the loopback in front of the role, and what it saw.
pub struct Cutter {
    pub port: u16,
    cuts: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Cutter {
    /// In front of the role on `to`: while fewer than `cuts` links were cut,
    /// each new link is cut once it carried a count of bytes, both ways
    /// together, from `least` to `least + spread`, by the xorshift of `seed`;
    /// each link after them passes whole.
    pub async fn start(to: u16, cuts: usize, at: (usize, usize), seed: u32) -> Cutter {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
        Cutter::among(listener, vec![to], cuts, at, seed)
    }

    /// The same on `listener`, in front of each port of `to` in turn, by the
    /// order of the connections: one name that several processes of the
    /// role share, behind a balancer that sends each new connection to the
    /// next one (T-173).
    pub fn among(
        listener: TcpListener,
        to: Vec<u16>,
        cuts: usize,
        (least, spread): (usize, usize),
        seed: u32,
    ) -> Cutter {
        let port = listener.local_addr().unwrap().port();
        let (made, heads) = (Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(Vec::new())));
        let (made_in, heads_in) = (made.clone(), heads.clone());
        tokio::spawn(async move {
            let (mut x, mut turn) = (seed, 0usize);
            while let Ok((client, _)) = listener.accept().await {
                let cut = (made_in.load(Ordering::SeqCst) < cuts).then(|| least + next(&mut x) as usize % spread);
                let next_one = to[turn % to.len()];
                turn += 1;
                tokio::spawn(forward(client, next_one, cut, made_in.clone(), heads_in.clone()));
            }
        });
        Cutter { port, cuts: made, heads }
    }

    /// The role, as a client reaches it through this forwarder.
    pub fn relay(&self) -> Relay {
        Relay { host: "127.0.0.1".into(), port: self.port }
    }

    /// The links cut so far.
    pub fn cuts(&self) -> usize {
        self.cuts.load(Ordering::SeqCst)
    }

    /// The request head of each link, in the order they came.
    pub fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

/// One link: both ways until either ends, or until `cut` bytes passed;
/// then both connections are dropped at once, with no Close.
async fn forward(
    client: TcpStream,
    to: u16,
    cut: Option<usize>,
    made: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<String>>>,
) {
    let Ok(role) = TcpStream::connect(("127.0.0.1", to)).await else { return };
    let left = AtomicI64::new(cut.map_or(i64::MAX, |c| c as i64));
    let (client_read, client_write) = client.into_split();
    let (role_read, role_write) = role.into_split();
    let spent = tokio::select! {
        spent = copy(client_read, role_write, &left, Some(heads.as_ref())) => spent,
        spent = copy(role_read, client_write, &left, None) => spent,
    };
    if spent {
        made.fetch_add(1, Ordering::SeqCst);
    }
}

/// Copy `from` into `to` until its end, or until `left` is spent: whether
/// it was. The head of the request, when `heads` is given, is kept.
async fn copy(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    left: &AtomicI64,
    heads: Option<&Mutex<Vec<String>>>,
) -> bool {
    let mut buf = vec![0u8; 16 * 1024];
    let mut head = heads.map(|_| Vec::new());
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => n,
        };
        if let (Some(seen), Some(heads)) = (head.as_mut(), heads) {
            seen.extend_from_slice(&buf[..n]);
            if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                heads.lock().unwrap().push(String::from_utf8_lossy(&seen[..end]).into_owned());
                head = None;
            } else if seen.len() > HEAD_MOST {
                head = None;
            }
        }
        let before = left.fetch_sub(n as i64, Ordering::SeqCst);
        if before <= n as i64 {
            let _ = to.write_all(&buf[..before.max(0) as usize]).await;
            return true;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return false;
        }
    }
}

/// A target on the loopback that sends back each byte of each connection,
/// and ends a connection once it sent back `size` bytes, as a server ends
/// a session; the count of its connections.
pub async fn echo_target(size: usize) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let dials = Arc::new(AtomicUsize::new(0));
    let counted = dials.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut buf, mut done) = (vec![0u8; 64 * 1024], 0);
                while done < size {
                    let n = match tcp.read(&mut buf[..(size - done).min(64 * 1024)]).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if tcp.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                    done += n;
                }
                let _ = tcp.shutdown().await;
            });
        }
    });
    (port, dials)
}

/// `size` bytes of the test's data into `to`: their digest.
pub async fn send_data<W: AsyncWrite + Unpin>(to: &mut W, size: usize) -> Vec<u8> {
    let mut digest = Sha256::new();
    let mut at = 0u64;
    while (at as usize) < size {
        let n = (size - at as usize).min(64 * 1024);
        let chunk: Vec<u8> = (at..at + n as u64).map(byte_at).collect();
        digest.update(&chunk);
        if to.write_all(&chunk).await.is_err() {
            break;
        }
        at += n as u64;
    }
    digest.finalize().to_vec()
}

/// Each byte of `from` until its end: the count and the digest.
pub async fn received<R: AsyncRead + Unpin>(from: &mut R) -> (usize, Vec<u8>) {
    let (mut digest, mut count, mut buf) = (Sha256::new(), 0, vec![0u8; 64 * 1024]);
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => return (count, digest.finalize().to_vec()),
            Ok(n) => {
                digest.update(&buf[..n]);
                count += n;
            }
        }
    }
}

/// A directory of the test, removed when it goes, passed or not.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        let dir = std::env::temp_dir().join(format!("podssh-t173-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A child of the test, ended when the test ends.
pub struct Killed(pub Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// OpenSSH's programs on this host, and the user who logs in.
pub struct OpenSsh {
    ssh: PathBuf,
    sshd: PathBuf,
    keygen: PathBuf,
    user: String,
}

/// `name` on the PATH, else in `fallback`.
fn program(name: &str, fallback: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path).map(|dir| dir.join(name)).find(|p| p.is_file());
    found.or_else(|| Some(Path::new(fallback).join(name)).filter(|p| p.is_file()))
}

/// This user's name, for OpenSSH's login to the loopback's sshd.
fn this_user() -> Option<String> {
    let name = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).ok().filter(|u| !u.is_empty());
    name.or_else(|| {
        let out = Command::new("id").arg("-un").output().ok()?;
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string()).filter(|u| !u.is_empty())
    })
}

impl OpenSsh {
    /// OpenSSH here, or `None`: a host with none skips its tests.
    pub fn find() -> Option<OpenSsh> {
        Some(OpenSsh {
            ssh: program("ssh", "/usr/bin")?,
            sshd: program("sshd", "/usr/sbin")?,
            keygen: program("ssh-keygen", "/usr/bin")?,
            user: this_user()?,
        })
    }

    fn keygen(&self, file: &Path) -> Result<(), String> {
        let made = Command::new(&self.keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(file)
            .stdin(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        made.success().then_some(()).ok_or_else(|| format!("ssh-keygen exited {made}"))
    }

    /// sshd on a free port of the loopback, for this user and the key
    /// `dir/id`, which it makes: the server and its port.
    pub fn sshd(&self, dir: &Path) -> Result<(Killed, u16), String> {
        self.keygen(&dir.join("id"))?;
        self.keygen(&dir.join("host_key"))?;
        let port = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?.local_addr().unwrap().port();
        let config = dir.join("sshd_config");
        let mut text = format!(
            "ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\nPidFile none\n",
            dir.join("host_key").display(),
            dir.join("id.pub").display()
        );
        std::fs::write(&config, &text).map_err(|e| e.to_string())?;
        // OpenSSH 9.8 and later penalise a source of many sessions; older
        // ones do not know the keyword.
        let mut knows = Command::new(&self.sshd);
        knows.arg("-t").arg("-f").arg(&config).args(["-o", "PerSourcePenalties=no"]);
        if knows.stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()) {
            text.push_str("PerSourcePenalties no\n");
            std::fs::write(&config, &text).map_err(|e| e.to_string())?;
        }
        let log = std::fs::File::create(dir.join("sshd.log")).map_err(|e| e.to_string())?;
        let child = Command::new(&self.sshd)
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .map_err(|e| format!("{}: {e}", self.sshd.display()))?;
        let server = Killed(child);
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            if Instant::now() > deadline {
                return Err("sshd did not listen within 15 s".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok((server, port))
    }

    /// OpenSSH's client to the server behind `port`, as this user with the
    /// key `dir/id`, running `cat` there: `input` up, its bytes back into
    /// `output`. The server's key is not checked: the test made it.
    pub fn cat(&self, dir: &Path, port: u16, input: &Path, output: &Path) -> Result<Killed, String> {
        let stdin = std::fs::File::open(input).map_err(|e| e.to_string())?;
        let stdout = std::fs::File::create(output).map_err(|e| e.to_string())?;
        let child = Command::new(&self.ssh)
            .args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"])
            .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
            .arg("-i")
            .arg(dir.join("id"))
            .args(["-p", &port.to_string(), &format!("{}@127.0.0.1", self.user), "cat"])
            .stdin(stdin)
            .stdout(stdout)
            .stderr(std::fs::File::create(dir.join("ssh.log")).map_err(|e| e.to_string())?)
            .spawn()
            .map_err(|e| format!("{}: {e}", self.ssh.display()))?;
        Ok(Killed(child))
    }
}

/// `size` bytes of the test's data in `path`: their digest.
pub fn data_file(path: &Path, size: usize) -> Vec<u8> {
    let bytes: Vec<u8> = (0..size as u64).map(byte_at).collect();
    std::fs::write(path, &bytes).unwrap();
    Sha256::digest(&bytes).to_vec()
}

/// The exit of `child` within `limit`, read on a thread of its own.
pub async fn exit_of(mut child: Killed, limit: Duration) -> Option<std::process::ExitStatus> {
    tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + limit;
        loop {
            match child.0.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                _ => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}
