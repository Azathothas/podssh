//! The forward road through the live relay's own loop (the operator's
//! decision of 2026-10-31, Q42 and Q38): a CONNECT proxy on the loopback
//! whose upstream, for each connection, is `podssh proxy HOST PORT`, a
//! forward session through the relay to the relay's own host and port 443.
//! A client whose `HTTPS_PROXY` is this proxy reaches a node of the live
//! relay with each byte crossing the relay twice, so its figure is a lower
//! bound of the forward road's. The proxy counts the connections that it
//! carried: a run that did not go through it is not the cell's figure.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The bound on a CONNECT request's head, and its size.
const HEAD_LIMIT: Duration = Duration::from_secs(30);
const HEAD_MAX: usize = 8192;
/// How long a forward session may outlive both of its directions.
const END_LIMIT: Duration = Duration::from_secs(10);

/// Start the proxy, whose `podssh proxy` runs with the scratch HOME `home`:
/// its port, and the count of the connections that it carried.
pub fn start(home: PathBuf) -> std::io::Result<(u16, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let carried = Arc::new(AtomicUsize::new(0));
    let count = carried.clone();
    std::thread::spawn(move || {
        for client in listener.incoming().map_while(Result::ok) {
            let (home, count) = (home.clone(), count.clone());
            std::thread::spawn(move || {
                if let Err(why) = carry(client, &home, &count) {
                    eprintln!("relay loop: {why}");
                }
            });
        }
    });
    Ok((port, carried))
}

/// One CONNECT: the forward session to its target, both ways, until each
/// side ends.
fn carry(mut client: TcpStream, home: &std::path::Path, count: &AtomicUsize) -> Result<(), String> {
    client.set_read_timeout(Some(HEAD_LIMIT)).map_err(|e| e.to_string())?;
    let head = read_head(&mut client)?;
    let target = head
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("CONNECT "))
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| format!("not a CONNECT: {:?}", head.lines().next()))?;
    let (host, port) = target.rsplit_once(':').ok_or_else(|| format!("no port in {target:?}"))?;
    // Each forward session's words, in a log of the scratch HOME.
    let n = count.load(Ordering::SeqCst) + 1;
    let log = std::fs::File::create(home.join(format!("relay-loop-{n}.log"))).map(Stdio::from).unwrap_or(Stdio::null());
    let mut forward = super::command_in(home, &["proxy".to_string(), host.to_string(), port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(log)
        .spawn()
        .map_err(|e| format!("podssh proxy: {e}"))?;
    client.set_read_timeout(None).map_err(|e| e.to_string())?;
    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").map_err(|e| e.to_string())?;
    count.fetch_add(1, Ordering::SeqCst);
    let (stdin, stdout) = (forward.stdin.take().unwrap(), forward.stdout.take().unwrap());
    let up_from = client.try_clone().map_err(|e| e.to_string())?;
    // The forward session's end of input when the client's ends: stdin is
    // dropped with the thread.
    let up = std::thread::spawn(move || pump(up_from, stdin));
    let down_to = client.try_clone().map_err(|e| e.to_string())?;
    let (down, down_end) = pump(stdout, down_to);
    let _ = client.shutdown(Shutdown::Both);
    let (up, up_end) = up.join().unwrap_or((0, "the thread panicked".into()));
    end(&mut forward);
    // The bytes of each way, after the forward session's own words.
    if let Ok(mut log) = std::fs::OpenOptions::new().append(true).open(home.join(format!("relay-loop-{n}.log"))) {
        let _ = writeln!(log, "relay loop: {up} bytes up ({up_end}), {down} bytes down ({down_end})");
    }
    Ok(())
}

/// Each byte of `from` into `to` as it comes, until either ends: the
/// bytes, and how it ended. A read and a write, not `std::io::copy`: with it
/// the forward session got no byte of the client's on this cloud session's
/// host, and the relay said "target closed before sending anything"
/// (measured 2026-11-01); its fast path from a socket into a pipe is the
/// suspect.
fn pump(mut from: impl Read, mut to: impl Write) -> (u64, String) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut moved = 0u64;
    loop {
        match from.read(&mut buf) {
            Ok(0) => return (moved, "the end".into()),
            Ok(n) => {
                if let Err(e) = to.write_all(&buf[..n]).and_then(|()| to.flush()) {
                    return (moved, format!("write: {e}"));
                }
                moved += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return (moved, format!("read: {e}")),
        }
    }
}

/// The request's head, up to its empty line.
fn read_head(client: &mut TcpStream) -> Result<String, String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HEAD_MAX {
            return Err("a request head of more than 8 KiB".into());
        }
        match client.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            Ok(_) => return Err("the client ended before its request".into()),
            Err(e) => return Err(format!("the request: {e}")),
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Wait for the forward session's end, and kill it past the limit.
fn end(forward: &mut Child) {
    let deadline = Instant::now() + END_LIMIT;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = forward.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = forward.kill();
    let _ = forward.wait();
}

/// The last lines of each forward session's log, for a run that failed.
pub fn words(home: &std::path::Path) -> String {
    let mut words = Vec::new();
    for n in 1.. {
        let Ok(text) = std::fs::read_to_string(home.join(format!("relay-loop-{n}.log"))) else { break };
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        let last = lines[lines.len().saturating_sub(4)..].join(" / ");
        words.push(format!("{n}: {last}"));
    }
    if words.is_empty() {
        "none started".to_string()
    } else {
        words.join(" | ")
    }
}
