//! The limit on a stuck write of `--direct` (T-227), on real TCP sockets of
//! the loopback under tokio's paused clock: a peer that reads nothing ends a
//! write after the relay leg's 60 s with an error, where it once waited for
//! ever; a peer that reads keeps the stream going; and a quiet peer is not a
//! stuck one, as reads have no limit.

mod cleanup;
mod ssh_harness;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use podssh_ws::client::WRITE_TIMEOUT;
use podssh_ws::write_limit::WriteLimit;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A connected pair: the client's stream, and the server's.
async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    (client.unwrap(), accepted.unwrap().0)
}

#[tokio::test(start_paused = true)]
async fn direct_write_limit_ends_a_write_that_the_peer_never_reads() {
    let (client, _server) = pair().await;
    let mut stream = WriteLimit::new(client, WRITE_TIMEOUT);
    let chunk = vec![0x5a_u8; 64 * 1024];
    let started = tokio::time::Instant::now();
    let mut sent = 0_u64;
    let error = loop {
        match stream.write_all(&chunk).await {
            Ok(()) => sent += chunk.len() as u64,
            Err(e) => break e,
        }
        // The buffers of the loopback take a few MiB at most.
        assert!(sent < 1 << 30, "1 GiB went to a peer that reads nothing");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
    assert!(error.to_string().contains("no progress for 60 s"), "{error}");
    let waited = started.elapsed();
    assert!(waited >= WRITE_TIMEOUT && waited < WRITE_TIMEOUT + Duration::from_secs(5), "{waited:?}");
}

#[tokio::test]
async fn direct_write_limit_lets_a_reading_peer_take_each_byte() {
    let (client, mut server) = pair().await;
    let mut stream = WriteLimit::new(client, Duration::from_millis(500));
    let reader = tokio::spawn(async move {
        let mut buf = vec![0_u8; 64 * 1024];
        let mut total = 0_usize;
        loop {
            match server.read(&mut buf).await {
                Ok(0) | Err(_) => return total,
                Ok(n) => total += n,
            }
        }
    });
    let chunk = vec![0x5a_u8; 64 * 1024];
    for _ in 0..256 {
        stream.write_all(&chunk).await.expect("a peer that reads is never stuck");
    }
    stream.shutdown().await.unwrap();
    drop(stream);
    assert_eq!(reader.await.unwrap(), 256 * 64 * 1024);
}

#[tokio::test(start_paused = true)]
async fn direct_write_limit_puts_no_limit_on_a_quiet_peer() {
    let (client, mut server) = pair().await;
    let mut stream = WriteLimit::new(client, WRITE_TIMEOUT);
    let read = tokio::spawn(async move {
        let mut buf = [0_u8; 5];
        stream.read_exact(&mut buf).await.map(|_| buf)
    });
    // Ten minutes of the paused clock with no byte: the read still waits.
    tokio::time::sleep(Duration::from_secs(600)).await;
    server.write_all(b"hello").await.unwrap();
    assert_eq!(&read.await.unwrap().unwrap(), b"hello");
}

/// A writer that never completes and never wakes its task: only the limit
/// can end the wait, at 60 s of the paused clock, as the Prove asks.
struct Never;

impl tokio::io::AsyncWrite for Never {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn direct_write_limit_fails_a_writer_that_never_completes_at_60_s() {
    let mut stream = WriteLimit::new(Never, WRITE_TIMEOUT);
    let started = tokio::time::Instant::now();
    let error = stream.write_all(b"x").await.expect_err("a writer that never completes");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
    assert_eq!(started.elapsed(), WRITE_TIMEOUT);
    let started = tokio::time::Instant::now();
    let error = stream.flush().await.expect_err("a flush that never completes");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
    assert_eq!(started.elapsed(), WRITE_TIMEOUT, "each wait counts on its own");
}

/// A forwarder to `to` that passes 64 KiB from its client, then reads no
/// more from it, with a small receive buffer: a stall below SSH, as the
/// gate's `scripts/stall-forward.py` makes it.
async fn stall_forwarder(to: u16) -> u16 {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(8).unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(("127.0.0.1", to)).await else { return };
                let (mut from_client, mut to_client) = client.into_split();
                let (mut from_server, mut to_server) = server.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut from_server, &mut to_client).await;
                });
                let mut passed = 0;
                let mut buf = vec![0_u8; 16 * 1024];
                while passed < 64 * 1024 {
                    match from_client.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) if to_server.write_all(&buf[..n]).await.is_ok() => passed += n,
                        Ok(_) => return,
                    }
                }
                // The stall: the client's socket stays open, and nothing reads it.
                std::future::pending::<()>().await;
            });
        }
    });
    port
}

/// The binary, through the forwarder, with 20 MB on stdin: the session ends
/// with 255 near the limit, and says why. 60 s of real time, so run on demand
/// (`-- --ignored`); the gate runs the same fault with OpenSSH.
#[test]
#[ignore = "60 s of real time; the gate runs the fault (scripts/interop-faults.sh)"]
fn direct_write_limit_ends_podssh_ssh_through_a_stalled_forwarder() {
    let dir = std::env::temp_dir().join(format!("podssh-stall-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    let forward = runtime.block_on(stall_forwarder(port));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &forward.to_string(), "-o", "BatchMode=yes"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(["tester@127.0.0.1", "sink"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", &dir).env("USERPROFILE", &dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let started = Instant::now();
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    std::thread::spawn(move || {
        let block = vec![0_u8; 1 << 20];
        for _ in 0..20 {
            if stdin.write_all(&block).is_err() {
                return;
            }
        }
    });
    let deadline = started + Duration::from_secs(300);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh ssh --direct still waited after 300 s on a write that makes no progress");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let took = started.elapsed();
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    eprintln!("exit {:?} after {took:?}: {err}", out.status.code());
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(took < Duration::from_secs(90), "{took:?}: {err}");
    assert!(err.contains("no progress"), "{err}");
}
