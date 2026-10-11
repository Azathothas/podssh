//! The requests in flight of a copy (T-140), against OpenSSH's `sftp-server`
//! over its pipes, through a double that stands between the client and the
//! server: it gives the replies to reads and writes out of order, cuts a read
//! short, fails a write, and counts what is in flight from the client's side.
//!
//! The server is found as `tests/sftp_client.rs` finds it
//! (`PODSSH_TEST_SFTP_SERVER`, else a usual place); with none, each test says
//! that it did not run.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ssh::sftp::{FileAttributes, Limits, OpenFlags, Pipeline, Reads, Sftp, Writes, IN_FLIGHT};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

const USUAL: &[&str] = &[
    "/usr/lib/ssh/sftp-server",
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    r"C:\Program Files\Git\usr\lib\ssh\sftp-server.exe",
];

/// The limit of each test call.
const OUTER: Duration = Duration::from_secs(30);

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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-pipeline-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

async fn bounded<T>(call: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(OUTER, call).await.expect("the call ended within the test's own limit")
}

/// What the double does to the packets between the client and the server.
#[derive(Clone, Default)]
struct Plan {
    /// Hold a reply to a read or a write until the next one, and give the
    /// two to the client in the reverse order.
    reorder: bool,
    /// Cut the reply to this read (by its order among the reads) to half.
    short_read: Option<usize>,
    /// Fail this write (by its order among the writes) with
    /// `SSH_FX_FAILURE`, without the server.
    fail_write: Option<usize>,
}

/// What the double saw, from the client's side.
#[derive(Debug, Default)]
struct Seen {
    /// Each request of a read or a write that has no reply yet: its bytes.
    open: HashMap<u32, u64>,
    in_flight: u64,
    /// The most bytes in flight at once: asked for by reads, carried by
    /// writes.
    max_bytes: u64,
    /// The most reads and writes in flight at once.
    max_requests: usize,
    /// Replies given before the reply to an earlier request.
    reordered: usize,
    reads: usize,
    writes: usize,
}

const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_STATUS: u8 = 101;
const FXP_DATA: u8 = 103;

/// One packet, its length included; `None` at the end.
async fn packet(from: &mut (impl AsyncRead + Unpin)) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    from.read_exact(&mut len).await.ok()?;
    let mut packet = len.to_vec();
    packet.resize(4 + u32::from_be_bytes(len) as usize, 0);
    from.read_exact(&mut packet[4..]).await.ok()?;
    Some(packet)
}

fn u32_at(p: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(p[at..at + 4].try_into().expect("four bytes"))
}

/// The id of a packet that has one.
fn id_of(p: &[u8]) -> u32 {
    u32_at(p, 5)
}

/// The bytes of a read or a write: what a read asks for, or what a write
/// carries. After the type and the id come a string handle and an offset,
/// then the read's length, or the length of the write's data.
fn bytes_of(p: &[u8]) -> u64 {
    let after_handle = 9 + 4 + u32_at(p, 9) as usize;
    u64::from(u32_at(p, after_handle + 8))
}

/// A status reply with `code`.
fn status(id: u32, code: u32) -> Vec<u8> {
    let mut body = vec![FXP_STATUS];
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&code.to_be_bytes());
    for text in ["planted", ""] {
        body.extend_from_slice(&(text.len() as u32).to_be_bytes());
        body.extend_from_slice(text.as_bytes());
    }
    let mut packet = (body.len() as u32).to_be_bytes().to_vec();
    packet.extend(body);
    packet
}

/// A data reply cut to half its data.
fn halved(p: &[u8]) -> Vec<u8> {
    let len = u32_at(p, 9) as usize;
    let keep = len / 2;
    let mut body = p[4..13].to_vec();
    body[5..9].copy_from_slice(&(keep as u32).to_be_bytes());
    body.extend_from_slice(&p[13..13 + keep]);
    let mut packet = (body.len() as u32).to_be_bytes().to_vec();
    packet.extend(body);
    packet
}

/// The server in `dir`, a session through the double, and what it saw.
async fn start(server: &Path, dir: &Path, plan: Plan) -> (Sftp, Child, Arc<Mutex<Seen>>) {
    let mut child = Command::new(server)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("the sftp-server starts");
    let mut to_server = child.stdin.take().expect("stdin");
    let mut from_server = child.stdout.take().expect("stdout");
    let (client_end, double_end) = tokio::io::duplex(1 << 20);
    let (mut from_client, mut to_client) = tokio::io::split(double_end);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let data_ids = Arc::new(Mutex::new(HashSet::new()));
    // The server's replies and the planted ones, in one queue: a read of a
    // pipe is never cancelled half done.
    let (replies, mut replies_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let planted = replies.clone();
    tokio::spawn(async move {
        while let Some(p) = packet(&mut from_server).await {
            if replies.send(p).is_err() {
                break;
            }
        }
    });
    // The client's requests: counted, and failed or sent on.
    let (up_seen, up_ids, up_plan) = (seen.clone(), data_ids.clone(), plan.clone());
    tokio::spawn(async move {
        while let Some(p) = packet(&mut from_client).await {
            if matches!(p[4], FXP_READ | FXP_WRITE) {
                let (id, bytes) = (id_of(&p), bytes_of(&p));
                up_ids.lock().unwrap().insert(id);
                let fail = {
                    let mut s = up_seen.lock().unwrap();
                    s.open.insert(id, bytes);
                    s.in_flight += bytes;
                    s.max_bytes = s.max_bytes.max(s.in_flight);
                    s.max_requests = s.max_requests.max(s.open.len());
                    if p[4] == FXP_WRITE {
                        s.writes += 1;
                        up_plan.fail_write == Some(s.writes - 1)
                    } else {
                        false
                    }
                };
                if fail {
                    let _ = planted.send(status(id, 4));
                    continue;
                }
            }
            if to_server.write_all(&p).await.is_err() {
                break;
            }
        }
        let _ = to_server.shutdown().await;
    });
    // The server's replies, and the planted ones: reordered or cut, then
    // given to the client, which then has them.
    let (down_seen, down_ids) = (seen.clone(), data_ids);
    tokio::spawn(async move {
        let give = |p: &[u8]| {
            if p[4] != 2 {
                let mut s = down_seen.lock().unwrap();
                if let Some(bytes) = s.open.remove(&id_of(p)) {
                    s.in_flight -= bytes;
                }
            }
        };
        let mut held: Option<Vec<u8>> = None;
        loop {
            let next = tokio::select! {
                p = replies_rx.recv() => p,
                _ = tokio::time::sleep(Duration::from_millis(30)), if held.is_some() => {
                    let p = held.take().expect("a held reply");
                    give(&p);
                    if to_client.write_all(&p).await.is_err() { break; }
                    continue;
                }
            };
            let Some(mut p) = next else {
                if let Some(p) = held.take() {
                    give(&p);
                    let _ = to_client.write_all(&p).await;
                }
                break;
            };
            let data = p[4] != 2 && down_ids.lock().unwrap().contains(&id_of(&p));
            if data && p[4] == FXP_DATA {
                let read = {
                    let mut s = down_seen.lock().unwrap();
                    s.reads += 1;
                    s.reads - 1
                };
                if plan.short_read == Some(read) {
                    p = halved(&p);
                }
            }
            let mut out = Vec::new();
            match held.take() {
                Some(first) if data && plan.reorder => {
                    down_seen.lock().unwrap().reordered += 1;
                    out.push(p);
                    out.push(first);
                }
                Some(first) => {
                    out.push(first);
                    out.push(p);
                }
                None if data && plan.reorder => held = Some(p),
                None => out.push(p),
            }
            for p in out {
                give(&p);
                if to_client.write_all(&p).await.is_err() {
                    return;
                }
            }
        }
    });
    let sftp = bounded(Sftp::over(client_end, Limits::default())).await.expect("the version exchange");
    (sftp, child, seen)
}

fn data(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

/// `path` read with `pipe`, block by block.
async fn download(sftp: &Sftp, path: &str, pipe: Pipeline) -> Vec<u8> {
    let file = bounded(sftp.open_file(path, OpenFlags::READ, FileAttributes::default())).await.expect("open");
    let mut back = Vec::new();
    {
        let mut reads = Reads::new(sftp, &file, 0, pipe);
        while let Some(block) = bounded(reads.next(&mut |_, _| true)).await.expect("a read") {
            back.extend(block);
        }
    }
    bounded(sftp.close(&file)).await.expect("close");
    back
}

/// `bytes` written to a new `path` with `pipe` from `offset`: the end of the
/// acknowledged part, or the first failure and that end.
async fn upload(sftp: &Sftp, path: &str, bytes: &[u8], offset: u64, pipe: Pipeline) -> Result<u64, (String, u64)> {
    let flags = OpenFlags::CREATE | OpenFlags::WRITE;
    let file = bounded(sftp.open_file(path, flags, FileAttributes::default())).await.expect("open");
    let mut writes = Writes::new(sftp, &file, offset, pipe);
    let block = writes.block() as usize;
    let mut sent = Ok(());
    for part in bytes[offset as usize..].chunks(block) {
        sent = bounded(writes.send(part.to_vec())).await;
        if sent.is_err() {
            break;
        }
    }
    let result = match sent {
        Ok(()) => bounded(writes.finish()).await.map_err(|e| (e.to_string(), writes.acked())),
        Err(e) => Err((e.to_string(), writes.acked())),
    };
    bounded(sftp.close(&file)).await.expect("close");
    result
}

/// Reads and writes with requests in flight together, through replies given
/// out of order: each byte comes back, and the file on disk agrees.
#[tokio::test]
async fn pipelined_copies_agree_through_replies_out_of_order() {
    let server = need_server!();
    let dir = scratch("reorder");
    let (sftp, _child, seen) = start(&server, &dir, Plan { reorder: true, ..Plan::default() }).await;
    let want = data(3_000_000);
    std::fs::write(dir.join("down.bin"), &want).expect("written");
    for pipe in [Pipeline::default(), Pipeline { requests: 16, len: 32 * 1024, ..Pipeline::default() }] {
        assert_eq!(download(&sftp, "down.bin", pipe).await, want, "each byte came back, {pipe:?}");
        assert_eq!(upload(&sftp, "up.bin", &want, 0, pipe).await, Ok(want.len() as u64), "{pipe:?}");
        assert_eq!(std::fs::read(dir.join("up.bin")).expect("on disk"), want, "the disk agrees, {pipe:?}");
    }
    let seen = seen.lock().unwrap();
    assert!(seen.reordered > 10, "replies out of order: {seen:?}");
    assert!(seen.max_requests > 2, "requests in flight together: {seen:?}");
    drop(seen);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A read that the server cuts short: the rest of its block is asked for
/// before the blocks after it, and each byte comes back in order.
#[tokio::test]
async fn pipelined_reads_ask_again_for_the_rest_of_a_short_read() {
    let server = need_server!();
    let dir = scratch("short");
    let (sftp, _child, _seen) = start(&server, &dir, Plan { short_read: Some(1), ..Plan::default() }).await;
    let want = data(1_000_000);
    std::fs::write(dir.join("down.bin"), &want).expect("written");
    let pipe = Pipeline { requests: 8, len: 32 * 1024, ..Pipeline::default() };
    assert_eq!(download(&sftp, "down.bin", pipe).await, want, "each byte came back in order");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Never more bytes in flight than the window that podssh gives a server,
/// whatever the requests asked; with small blocks, as many requests as
/// asked.
#[tokio::test]
async fn the_window_bounds_the_bytes_in_flight() {
    let server = need_server!();
    let dir = scratch("window");
    let want = data(4_000_000);
    std::fs::write(dir.join("down.bin"), &want).expect("written");
    for (pipe, requests) in [
        (Pipeline { requests: 64, len: 0, ..Pipeline::default() }, None),
        (Pipeline { requests: 64, len: 32 * 1024, ..Pipeline::default() }, Some(16)),
        (Pipeline { requests: 4, len: 32 * 1024, ..Pipeline::default() }, Some(4)),
    ] {
        let (sftp, _child, seen) = start(&server, &dir, Plan::default()).await;
        assert_eq!(download(&sftp, "down.bin", pipe).await, want);
        assert_eq!(upload(&sftp, "up.bin", &want, 0, pipe).await, Ok(want.len() as u64));
        let seen = seen.lock().unwrap();
        assert!(seen.max_bytes <= u64::from(IN_FLIGHT), "{pipe:?}: {seen:?}");
        if let Some(requests) = requests {
            assert_eq!(seen.max_requests, requests, "{pipe:?}: {seen:?}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// One request at a time, as before: never two in flight.
#[tokio::test]
async fn one_request_waits_for_each_reply() {
    let server = need_server!();
    let dir = scratch("one");
    let (sftp, _child, seen) = start(&server, &dir, Plan::default()).await;
    let want = data(700_000);
    std::fs::write(dir.join("down.bin"), &want).expect("written");
    let pipe = Pipeline { requests: 1, len: 0, ..Pipeline::default() };
    assert_eq!(download(&sftp, "down.bin", pipe).await, want);
    assert_eq!(upload(&sftp, "up.bin", &want, 0, pipe).await, Ok(want.len() as u64));
    assert_eq!(seen.lock().unwrap().max_requests, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A write that fails while later ones land: the acknowledged part ends
/// before it, though the far file is longer, and a second attempt from that
/// end makes the file whole (T-136). Taking the far file's size would leave
/// the failed block empty.
#[tokio::test]
async fn a_failed_write_keeps_the_acknowledged_part_contiguous() {
    let server = need_server!();
    let dir = scratch("failed");
    let want = data(2_000_000);
    let pipe = Pipeline { requests: 8, len: 32 * 1024, ..Pipeline::default() };
    let (sftp, _child, _seen) = start(&server, &dir, Plan { fail_write: Some(1), ..Plan::default() }).await;
    let (why, acked) = upload(&sftp, "up.bin", &want, 0, pipe).await.expect_err("the planted failure");
    assert!(why.contains("write at 32768"), "{why}");
    assert_eq!(acked, 32 * 1024, "the end of the first write");
    let far = std::fs::metadata(dir.join("up.bin")).expect("on disk").len();
    assert!(far > acked, "the writes after the failed one landed: {far}");
    drop(sftp);
    let (sftp, _child, _seen) = start(&server, &dir, Plan::default()).await;
    assert_eq!(upload(&sftp, "up.bin", &want, acked, pipe).await, Ok(want.len() as u64));
    assert_eq!(std::fs::read(dir.join("up.bin")).expect("on disk"), want, "the file is whole");
    let _ = std::fs::remove_dir_all(&dir);
}
