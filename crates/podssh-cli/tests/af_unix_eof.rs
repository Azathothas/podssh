//! T-465's question, on Windows alone: does the end of input of an AF_UNIX
//! socket reach its peer, after a megabyte and a shutdown of the sending
//! half, by a blocking client of the standard library, and by the
//! non-blocking one that `podssh pipe` uses (tokio over mio's AFD poll)?
//! `pipe`'s test lost that end 2 runs in 50 on a runner where podssh said
//! that its shutdown was taken. A probe of the platform, not a test of the
//! gate: ignored, and run by hand with `suite-repeat.yml` (`ignored=yes`).
//! It counts the runs whose server saw no end within 5 s, and fails when
//! one did, naming which client lost it.

#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::windows::io::FromRawSocket;
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Networking::WinSock as ws;

/// The runs of each client.
const RUNS: usize = 100;
/// The bytes of each run, as many as `pipe`'s test sends.
const BYTES: usize = 1_000_000;
/// How long a server waits for its end.
const WAIT: Duration = Duration::from_secs(5);

/// An AF_UNIX address at `path`.
fn address(path: &str) -> ws::SOCKADDR_UN {
    // SAFETY: an all-zero SOCKADDR_UN is valid.
    let mut addr: ws::SOCKADDR_UN = unsafe { std::mem::zeroed() };
    addr.sun_family = ws::AF_UNIX;
    for (slot, b) in addr.sun_path.iter_mut().zip(path.as_bytes()) {
        *slot = *b as _;
    }
    addr
}

/// A listening AF_UNIX socket at `path`.
fn listen(path: &str) -> ws::SOCKET {
    let addr = address(path);
    let len = std::mem::size_of::<ws::SOCKADDR_UN>() as i32;
    // SAFETY: WinSock calls on a socket of this probe.
    unsafe {
        let mut data: ws::WSADATA = std::mem::zeroed();
        assert_eq!(ws::WSAStartup(0x0202, &mut data), 0);
        let s = ws::socket(ws::AF_UNIX as i32, ws::SOCK_STREAM, 0);
        assert_ne!(s, ws::INVALID_SOCKET, "AF_UNIX on this Windows");
        assert_eq!(ws::bind(s, (&addr as *const ws::SOCKADDR_UN).cast(), len), 0, "bind");
        assert_eq!(ws::listen(s, 1), 0, "listen");
        s
    }
}

/// A blocking AF_UNIX stream connected to `path`.
fn connect(path: &str) -> TcpStream {
    let addr = address(path);
    let len = std::mem::size_of::<ws::SOCKADDR_UN>() as i32;
    // SAFETY: as in `listen`; the socket is owned by the stream from here.
    unsafe {
        let s = ws::socket(ws::AF_UNIX as i32, ws::SOCK_STREAM, 0);
        assert_ne!(s, ws::INVALID_SOCKET, "AF_UNIX on this Windows");
        assert_eq!(ws::connect(s, (&addr as *const ws::SOCKADDR_UN).cast(), len), 0, "connect");
        TcpStream::from_raw_socket(s as u64)
    }
}

/// One run: a server that reads to its end and says how many bytes came,
/// and `client` given a connected stream, which hands back what keeps its
/// reading half open, as podssh's is, until the wait ends; whether the end
/// came within [`WAIT`]. A server that saw none is left blocked: the probe
/// ends with its process.
fn one<T>(run: usize, tag: &str, client: impl FnOnce(TcpStream) -> T) -> bool {
    let path = std::env::temp_dir().join(format!("podssh-eof-{tag}-{}-{run}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let text = path.to_str().unwrap().to_string();
    let listener = listen(&text);
    let (said, heard) = mpsc::channel();
    std::thread::spawn(move || {
        // SAFETY: the listener belongs to this thread; the accepted socket
        // is owned by the stream from here.
        let mut stream = unsafe {
            let c = ws::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
            ws::closesocket(listener);
            TcpStream::from_raw_socket(c as u64)
        };
        let (mut total, mut buf) = (0usize, vec![0u8; 64 * 1024]);
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = said.send(total);
    });
    let open = client(connect(&text));
    let ended = matches!(heard.recv_timeout(WAIT), Ok(n) if n == BYTES);
    drop(open);
    let _ = std::fs::remove_file(&path);
    ended
}

/// The bytes of a run.
fn bytes() -> Vec<u8> {
    (0..BYTES as u32).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

#[test]
#[ignore = "a probe of the platform, run by hand (T-465)"]
fn the_end_of_an_af_unix_stream_reaches_its_peer_by_each_client() {
    let data = bytes();
    let blocking_lost = (0..RUNS)
        .filter(|&run| {
            !one(run, "std", |mut s| {
                s.write_all(&data).expect("the bytes");
                s.shutdown(Shutdown::Write).expect("the shutdown");
                s
            })
        })
        .count();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let tokio_lost = (0..RUNS)
        .filter(|&run| {
            !one(run, "tokio", |s| {
                runtime.block_on(async {
                    use tokio::io::AsyncWriteExt;
                    s.set_nonblocking(true).expect("non-blocking");
                    let s = tokio::net::TcpStream::from_std(s).expect("a stream of tokio");
                    let (read, mut write) = s.into_split();
                    write.write_all(&data).await.expect("the bytes");
                    write.shutdown().await.expect("the shutdown");
                    // The write half goes, as podssh's copy drops it; the
                    // read half stays, as podssh's does.
                    drop(write);
                    read
                })
            })
        })
        .count();
    println!("af_unix_eof: blocking {blocking_lost} of {RUNS} lost the end; tokio {tokio_lost} of {RUNS}");
    assert_eq!((blocking_lost, tokio_lost), (0, 0), "runs whose server saw no end (blocking, tokio)");
}
