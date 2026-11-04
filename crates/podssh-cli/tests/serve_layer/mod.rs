//! `podssh proxy` in the resumable layer of `podssh relay serve` (T-173):
//! OpenSSH's client, with `podssh proxy` as its ProxyCommand and
//! `PODSSH_RELAY_LAYER=yes`, logs in through the role to OpenSSH's server
//! and copies 16 MiB each way through its `cat`, while a stand-in of the
//! host's proxy cuts the link of `podssh proxy` at 10 points of its own, with
//! no word to either end: the session lives on, as the role holds the
//! connection to sshd and each new link resumes it, and the digests are
//! equal. Another word in the variable is refused before any connection.
//! `podssh ssh` does the same on the road (`ssh_layer`), and a session past
//! the role's budget goes on the contract's road with one line. Unset, the
//! variable takes the layer where the first host offered it (`unasked`).

mod ssh_layer;
mod unasked;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{digest_of, ran, ran_with, relay_flags, role, said, this_user, LIMIT};
use crate::live_harness;
use crate::throughput_harness::{self, Session};

/// The cuts of the session, each at a point of its own.
const CUTS: usize = 10;
/// The bytes of a tunnel, both ways, before its cut: 256 KiB and up to
/// 1.5 MiB more, so that each cut comes before the session's 32 MiB end.
const LEAST: usize = 256 * 1024;
const SPREAD: usize = 3 * 512 * 1024;

/// A stand-in HTTP CONNECT proxy on the loopback, which carries each tunnel
/// to the role on `role_port`, whatever host the CONNECT names: while fewer
/// than `cuts` tunnels were cut, each new one is cut once it carried a
/// count of bytes, both ways together, of its own; the cuts made so far.
fn cutting_proxy(role_port: u16, cuts: usize) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let made = Arc::new(AtomicUsize::new(0));
    let counted = made.clone();
    std::thread::spawn(move || {
        let mut x: u32 = 0x0173_c0de;
        for client in listener.incoming().map_while(Result::ok) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let cut = (counted.load(Ordering::SeqCst) < cuts).then_some(LEAST + x as usize % SPREAD);
            let counted = counted.clone();
            std::thread::spawn(move || tunnel(client, role_port, cut, &counted));
        }
    });
    (port, made)
}

fn tunnel(client: TcpStream, role_port: u16, cut: Option<usize>, made: &AtomicUsize) {
    let _ = client.set_read_timeout(Some(LIMIT));
    let (Ok(mut answer), Ok(client_end)) = (client.try_clone(), client.try_clone()) else { return };
    // The reader keeps what came after the head, for the tunnel.
    let mut reader = BufReader::new(client);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(n) if n > 0 && line != "\r\n" => continue,
            _ => break,
        }
    }
    if answer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return;
    }
    let Ok(far) = TcpStream::connect(("127.0.0.1", role_port)) else { return };
    let (Ok(far_writer), Ok(far_end)) = (far.try_clone(), far.try_clone()) else { return };
    let left = Arc::new(AtomicI64::new(cut.map_or(i64::MAX, |c| c as i64)));
    let ends = Arc::new([client_end, far_end]);
    let up = {
        let (left, ends) = (left.clone(), ends.clone());
        std::thread::spawn(move || copy(reader, far_writer, &left, &ends[..]))
    };
    let down = copy(far, answer, &left, &ends[..]);
    let up = up.join().unwrap_or(false);
    if up || down {
        made.fetch_add(1, Ordering::SeqCst);
    }
}

/// Copy `from` into `to` until its end, which goes on as a half-close, or
/// until `left` is spent: then both connections end at once, each way, with
/// no word. Whether it was spent.
fn copy(mut from: impl Read, mut to: TcpStream, left: &AtomicI64, ends: &[TcpStream]) -> bool {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = to.shutdown(Shutdown::Write);
                return false;
            }
            Ok(n) => n,
        };
        let before = left.fetch_sub(n as i64, Ordering::SeqCst);
        if before <= n as i64 {
            let _ = to.write_all(&buf[..before.max(0) as usize]);
            for end in ends {
                let _ = end.shutdown(Shutdown::Both);
            }
            return true;
        }
        if to.write_all(&buf[..n]).is_err() {
            return false;
        }
    }
}

/// The value of `flag` among `args`.
fn value_of(args: &[String], flag: &str) -> String {
    args.iter().position(|a| a == flag).map(|i| args[i + 1].clone()).unwrap()
}

#[test]
fn openssh_through_podssh_proxy_in_the_layer_lives_on_10_cuts_of_its_link() {
    let s = Session::start("serve-layer");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let (Some(user), true) = (this_user(), throughput_harness::found("ssh", &["-V"])) else {
        eprintln!("did not run: no OpenSSH client or no user name here");
        return;
    };
    let dir = s.home.join("openssh-layer");
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("id");
    let mut keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f"].map(String::from).to_vec();
    keygen.push(key.display().to_string());
    let made = ran(s.command(&keygen));
    assert!(made.status.success(), "{}", said(&made));
    let sshd = match live_harness::sshd::start(&dir, &key.with_extension("pub")) {
        Ok(sshd) => sshd,
        Err(why) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let data = dir.join("data");
    let bytes: Vec<u8> = (0..16u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    std::fs::write(&data, &bytes).unwrap();
    let want = digest_of(&data).expect("sha256sum");
    // The role by its name, which the stand-in proxy is asked for, and its
    // CA: no pinned address, so that each connection takes the proxy.
    let flags = relay_flags(&cell);
    let relay_host = value_of(&flags, "--relay-host");
    let role_port: u16 = relay_host.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).expect("the role's port");
    let (proxy_port, cuts) = cutting_proxy(role_port, CUTS);
    let bin = env!("CARGO_BIN_EXE_podssh");
    let proxy = format!("{bin} proxy --relay-host {relay_host} --ca-file {} %h %p", value_of(&flags, "--ca-file"));
    let back = dir.join("back");
    let mut ssh = Command::new("ssh");
    ssh.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"])
        .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
        .arg("-i")
        .arg(&key)
        .arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .args(["-p", &sshd.port.to_string(), &format!("{user}@127.0.0.1"), "cat"])
        .env("HOME", &s.home)
        .env("XDG_CACHE_HOME", s.home.join("cache"))
        .env("PODSSH_RELAY_LAYER", "yes")
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy_port}"));
    for name in ["https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"]
    {
        ssh.env_remove(name);
    }
    ssh.stdin(std::fs::File::open(&data).unwrap());
    ssh.stdout(std::fs::File::create(&back).unwrap()).stderr(Stdio::piped());
    let mut child = ssh.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("ssh did not end within {LIMIT:?}, after {} cuts", cuts.load(Ordering::SeqCst));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    assert!(out.status.success(), "ssh: {stderr}; the role: {events}");
    assert_eq!(digest_of(&back).as_deref(), Some(want.as_str()), "the 16 MiB came back whole: {stderr}");
    assert!(cuts.load(Ordering::SeqCst) >= CUTS, "{} cuts: {stderr}", cuts.load(Ordering::SeqCst));
    assert!(events.contains("upgrade layer"), "the layer's road: {events}");
    assert!(events.contains("layer resumed"), "the role resumed the session: {events}");
    assert!(stderr.contains("the session resumed after"), "podssh proxy says each resume: {stderr}");
}

#[test]
fn another_word_of_the_variable_is_refused_before_any_connection() {
    let s = Session::start("serve-layer-word");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let mut args = vec!["proxy".to_string()];
    args.extend(relay_flags(&cell));
    args.extend(["127.0.0.1".into(), "22".into()]);
    let out = ran_with(s.command(&args), &[("PODSSH_RELAY_LAYER", "perhaps")]);
    assert_eq!(out.status.code(), Some(78), "{}", said(&out));
    assert!(said(&out).contains("PODSSH_RELAY_LAYER: yes or no"), "{}", said(&out));
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    assert!(!events.contains("upgrade"), "no connection: {events}");
}
