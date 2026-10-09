//! The SFTP client against OpenSSH's `sftp-server` over its pipes, and against
//! peers that never answer or break the protocol.
//!
//! `PODSSH_TEST_SFTP_SERVER` names the server: the gate installs
//! `openssh-sftp-server` and names it, and CI's Windows job names the copy of
//! Git for Windows. A name with no program there fails. With no name, a server
//! at a usual place serves, and with none the tests that need one say that
//! they did not run. The peers that never answer need no server.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use podssh_ssh::sftp::{FileAttributes, Limits, OpenFlags, Sftp, SftpError, CHUNK};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::process::{Child, Command};

/// Where OpenSSH's sftp-server usually is.
const USUAL: &[&str] = &[
    "/usr/lib/ssh/sftp-server",
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    r"C:\Program Files\Git\usr\lib\ssh\sftp-server.exe",
];

/// The limit of each test call: a call that passes it is a wait with no limit.
const OUTER: Duration = Duration::from_secs(10);

fn server_path() -> Option<PathBuf> {
    match std::env::var_os("PODSSH_TEST_SFTP_SERVER") {
        Some(named) => {
            let path = PathBuf::from(named);
            assert!(path.is_file(), "PODSSH_TEST_SFTP_SERVER names {}, and no program is there", path.display());
            Some(path)
        }
        None => USUAL.iter().map(PathBuf::from).find(|p| p.is_file()),
    }
}

/// An empty directory of the test's own, for the server to work in.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-sftp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// The server in `dir`, and a session over its pipes.
async fn start(server: &Path, dir: &Path) -> (Sftp, Child) {
    let mut child = Command::new(server)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("the sftp-server starts");
    let pipes = tokio::io::join(child.stdout.take().expect("stdout"), child.stdin.take().expect("stdin"));
    let sftp = bounded(Sftp::over(pipes, Limits::default())).await.expect("the version exchange");
    (sftp, child)
}

/// A call of a test, within [`OUTER`].
async fn bounded<T>(call: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(OUTER, call).await.expect("the call ended within the test's own limit of 10 s")
}

fn write_flags() -> OpenFlags {
    OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE
}

async fn put(sftp: &Sftp, path: &str, data: &[u8]) {
    let file = bounded(sftp.open_file(path, write_flags(), FileAttributes::default())).await.expect("open to write");
    bounded(sftp.write(&file, 0, data)).await.expect("write");
    bounded(sftp.close(&file)).await.expect("close");
}

macro_rules! need_server {
    () => {
        match server_path() {
            Some(path) => path,
            None => {
                eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
                return;
            }
        }
    };
}

#[tokio::test]
async fn a_file_goes_there_and_back_and_agrees_with_the_disk() {
    let server = need_server!();
    let dir = scratch("there-and-back");
    let (sftp, _child) = start(&server, &dir).await;
    let data: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(7) % 251) as u8).collect();
    put(&sftp, "a.bin", &data).await;
    assert_eq!(std::fs::read(dir.join("a.bin")).expect("on disk"), data, "the disk holds each byte written");
    let attrs = bounded(sftp.stat("a.bin")).await.expect("stat");
    assert_eq!(attrs.size, Some(data.len() as u64));

    let file = bounded(sftp.open_file("a.bin", OpenFlags::READ, FileAttributes::default())).await.expect("open");
    let mut back = Vec::new();
    while let Some(part) = bounded(sftp.read(&file, back.len() as u64, sftp.read_len())).await.expect("read") {
        assert!(!part.is_empty() && part.len() <= sftp.read_len() as usize, "{} bytes", part.len());
        back.extend(part);
    }
    bounded(sftp.close(&file)).await.expect("close");
    assert_eq!(back, data, "each byte came back");
    sftp.close_session().expect("the end of the session");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn rename_mkdir_list_and_remove_agree_with_the_disk() {
    let server = need_server!();
    let dir = scratch("names");
    let (sftp, _child) = start(&server, &dir).await;
    bounded(sftp.mkdir("sub", FileAttributes::default())).await.expect("mkdir");
    assert!(dir.join("sub").is_dir());
    put(&sftp, "sub/x", b"one").await;
    put(&sftp, "sub/y", b"two").await;
    // posix-rename replaces the target, as rename(2) does.
    bounded(sftp.rename("sub/x", "sub/y")).await.expect("rename over a file");
    assert!(!dir.join("sub/x").exists());
    assert_eq!(std::fs::read(dir.join("sub/y")).expect("on disk"), b"one");
    let mut names: Vec<String> =
        bounded(sftp.read_dir("sub")).await.expect("list").into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, [".", "..", "y"]);
    let here = bounded(sftp.realpath(".")).await.expect("realpath");
    let leaf = dir.file_name().and_then(|n| n.to_str()).expect("a name");
    assert!(here.ends_with(leaf), "{here} ends with {leaf}");
    bounded(sftp.remove("sub/y")).await.expect("remove");
    bounded(sftp.rmdir("sub")).await.expect("rmdir");
    assert!(!dir.join("sub").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_missing_path_is_a_sentence_with_its_path_and_the_limits_are_the_servers() {
    let server = need_server!();
    let dir = scratch("missing");
    let (sftp, _child) = start(&server, &dir).await;
    let e = bounded(sftp.stat("nothing")).await.expect_err("there is nothing");
    assert!(e.is_missing(), "{e:?}");
    assert!(e.to_string().starts_with("stat nothing: no such file or directory"), "{e}");
    if sftp.extensions().contains_key("limits@openssh.com") {
        assert!(sftp.read_len() > CHUNK && sftp.write_len() > CHUNK, "{} {}", sftp.read_len(), sftp.write_len());
    }
    assert!(sftp.extensions().contains_key("posix-rename@openssh.com"), "{:?}", sftp.extensions());
    let _ = std::fs::remove_dir_all(&dir);
}

// ───────────────────────────────── peers that podssh's tests play

/// How the played peer answers after the version exchange.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Plays {
    /// Never answers INIT.
    Mute,
    /// Answers OPEN with a handle, and nothing else.
    Silent,
    /// Answers a READ with one byte more than it asked for.
    LongRead,
    /// Closes its end after the version exchange.
    Leaves,
}

fn reply(out: &mut Vec<u8>, kind: u8, id: u32, body: &[u8]) {
    out.extend_from_slice(&(5 + body.len() as u32).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(body);
}

/// A peer that reads each request and answers as `plays` says.
fn play(plays: Plays) -> DuplexStream {
    let (client, mut peer) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        loop {
            let mut len = [0u8; 4];
            if peer.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            if peer.read_exact(&mut body).await.is_err() {
                return;
            }
            let id = body.get(1..5).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            let mut out = Vec::new();
            match (body[0], plays) {
                (1, Plays::Mute) => continue,
                // VERSION 3, no extension: the length counts the type and
                // the version.
                (1, _) => out.extend_from_slice(&[0, 0, 0, 5, 2, 0, 0, 0, 3]),
                (3, _) => reply(&mut out, 102, id, &[0, 0, 0, 1, b'h']),
                (5, Plays::LongRead) => {
                    let asked = u32::from_be_bytes([body[18], body[19], body[20], body[21]]);
                    let mut data = (asked + 1).to_be_bytes().to_vec();
                    data.resize(4 + asked as usize + 1, b'x');
                    reply(&mut out, 103, id, &data);
                }
                _ => continue,
            }
            if peer.write_all(&out).await.is_err() {
                return;
            }
            if plays == Plays::Leaves && body[0] == 1 {
                return;
            }
        }
    });
    client
}

const SHORT: Limits = Limits { metadata: Duration::from_secs(1), data: Duration::from_secs(3) };

/// The call fails by its limit, no later than one second after it.
async fn times_out<T: std::fmt::Debug>(call: impl std::future::Future<Output = Result<T, SftpError>>, limit: Duration) {
    let started = Instant::now();
    let e = bounded(call).await.expect_err("no reply, so no success");
    let took = started.elapsed();
    assert!(matches!(e, SftpError::Timeout { .. }), "{e:?}");
    assert!(took >= limit && took < limit + Duration::from_secs(1), "{took:?} for a limit of {limit:?}");
}

#[tokio::test]
async fn silent_version_exchange_fails_within_its_limit() {
    times_out(Sftp::over(play(Plays::Mute), SHORT), SHORT.metadata).await;
}

#[tokio::test]
async fn silent_metadata_requests_fail_within_their_limit() {
    let sftp = bounded(Sftp::over(play(Plays::Silent), SHORT)).await.expect("the version exchange");
    times_out(sftp.stat("a"), SHORT.metadata).await;
    times_out(sftp.lstat("a"), SHORT.metadata).await;
    times_out(sftp.realpath("."), SHORT.metadata).await;
    times_out(sftp.mkdir("d", FileAttributes::default()), SHORT.metadata).await;
    times_out(sftp.remove("a"), SHORT.metadata).await;
    times_out(sftp.rename("a", "b"), SHORT.metadata).await;
    times_out(sftp.read_dir("."), SHORT.metadata).await;
}

#[tokio::test]
async fn silent_reads_and_writes_fail_within_their_limit() {
    let sftp = bounded(Sftp::over(play(Plays::Silent), SHORT)).await.expect("the version exchange");
    let file = bounded(sftp.open_file("a", OpenFlags::READ, FileAttributes::default())).await.expect("a handle");
    times_out(sftp.read(&file, 0, 16), SHORT.data).await;
    times_out(sftp.write(&file, 0, b"abc"), SHORT.data).await;
    times_out(sftp.close(&file), SHORT.metadata).await;
}

#[tokio::test]
async fn a_read_reply_longer_than_its_request_breaks_the_protocol() {
    let sftp = bounded(Sftp::over(play(Plays::LongRead), SHORT)).await.expect("the version exchange");
    let file = bounded(sftp.open_file("a", OpenFlags::READ, FileAttributes::default())).await.expect("a handle");
    let e = bounded(sftp.read(&file, 0, 16)).await.expect_err("17 bytes for 16");
    assert!(matches!(&e, SftpError::Protocol(why) if why.contains("17 bytes in reply to a read of 16")), "{e:?}");
}

#[tokio::test]
async fn a_peer_that_leaves_ends_each_request_at_once() {
    let sftp = bounded(Sftp::over(play(Plays::Leaves), SHORT)).await.expect("the version exchange");
    let started = Instant::now();
    let e = bounded(sftp.stat("a")).await.expect_err("the peer is gone");
    assert!(matches!(e, SftpError::Closed(_) | SftpError::Timeout { .. }), "{e:?}");
    assert!(started.elapsed() <= SHORT.metadata + Duration::from_secs(1), "{:?}", started.elapsed());
}
