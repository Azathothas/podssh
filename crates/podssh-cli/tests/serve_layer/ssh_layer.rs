//! `podssh ssh` in the resumable layer of `podssh relay serve` (T-173): to
//! OpenSSH's sshd, with `PODSSH_RELAY_LAYER` unset, so by the role's offer
//! that one read of its `/relays.json` gave, its link cut at points of
//! its own by the stand-in of the host's proxy while 8 MiB go each way
//! through the server's `cat`: the session lives on, and the digests are
//! equal. And a role whose budget holds one session: a second session, with
//! the same ask, takes the contract's road with one line, and its bytes come.

use std::io::Read;
use std::net::TcpListener;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{cutting_proxy, value_of};
use crate::live_harness;
use crate::throughput_harness::Session;
use crate::{banner_target, digest_of, ran, ran_with, relay_flags, role, said, this_user, LIMIT};

/// The cuts of the session, each at a point of its own, before its 16 MiB
/// both ways end.
const SSH_CUTS: usize = 6;
/// The proxies of the machine, which a run here must not take.
const PROXIES: [&str; 7] =
    ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "PODSSH_RELAY_TOKEN"];

#[test]
fn podssh_ssh_in_the_layer_lives_on_cuts_of_its_link() {
    let s = Session::start("serve-layer-ssh");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let Some(user) = this_user() else {
        eprintln!("did not run: no user name here");
        return;
    };
    let dir = s.home.join("ssh-layer");
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
    let bytes: Vec<u8> = (0..8u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    std::fs::write(&data, &bytes).unwrap();
    let want = digest_of(&data).expect("sha256sum");
    // The role by its name, which the stand-in proxy is asked for, and its
    // CA: no pinned address, so that each connection takes the proxy.
    let flags = relay_flags(&cell);
    let relay_host = value_of(&flags, "--relay-host");
    let role_port: u16 = relay_host.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).expect("the role's port");
    let (proxy_port, cuts) = cutting_proxy(role_port, SSH_CUTS);
    let known = dir.join("known_hosts");
    let mut args: Vec<String> = ["ssh", "-i"].map(String::from).to_vec();
    args.push(key.display().to_string());
    args.extend(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"].map(String::from));
    args.push(format!("UserKnownHostsFile={}", known.display()));
    args.extend(["--relay-host".to_string(), relay_host, "--ca-file".into(), value_of(&flags, "--ca-file")]);
    args.extend(["-p".to_string(), sshd.port.to_string(), format!("{user}@127.0.0.1"), "cat".into()]);
    let back = dir.join("back");
    let mut cmd = s.command(&args);
    for name in PROXIES.iter().chain(&["PODSSH_RELAY"]) {
        cmd.env_remove(name);
    }
    cmd.env_remove("PODSSH_RELAY_LAYER").env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy_port}"));
    cmd.stdin(std::fs::File::open(&data).unwrap());
    cmd.stdout(std::fs::File::create(&back).unwrap()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh ssh did not end within {LIMIT:?}, after {} cuts", cuts.load(Ordering::SeqCst));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    assert!(out.status.success(), "podssh ssh did not live on its cuts: {stderr}; the role: {events}");
    assert_eq!(digest_of(&back).as_deref(), Some(want.as_str()), "the 8 MiB came back whole: {stderr}");
    assert!(cuts.load(Ordering::SeqCst) >= SSH_CUTS, "{} cuts: {stderr}", cuts.load(Ordering::SeqCst));
    assert!(events.contains("upgrade layer"), "the layer's road: {events}");
    assert!(events.contains("layer resumed"), "the role resumed the session: {events}");
    assert!(stderr.contains("the session resumed after"), "podssh ssh says each resume: {stderr}");
    // Unset, by the offer of one read, then kept: no read at each resume.
    let reads = events.lines().filter(|l| l.trim() == "relays.json").count();
    assert_eq!(reads, 1, "the offer was read once: {events}");
}

/// A target that takes each connection and holds it, reading until its end;
/// the connections that it took.
fn holding_target() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let took = Arc::new(AtomicUsize::new(0));
    let counted = took.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            counted.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    (port, took)
}

#[test]
fn a_new_session_past_the_role_s_budget_goes_on_the_contract_s_road_with_one_line() {
    let s = Session::start("serve-layer-budget");
    // Room for one session of the default buffer.
    let Some(cell) = role(&s, &["--allow-private", "--resume-budget", "4", "--resume-deadline", "2m"]) else {
        return;
    };
    let flags = relay_flags(&cell);
    let proxy = |port: u16| {
        let mut args = vec!["proxy".to_string()];
        args.extend(flags.iter().cloned());
        args.extend(["127.0.0.1".into(), port.to_string()]);
        args
    };
    // The session that holds the budget: its stdin stays open.
    let (held_port, took) = holding_target();
    let mut first = s.command(&proxy(held_port));
    for name in PROXIES.iter().chain(&["PODSSH_RELAY"]) {
        first.env_remove(name);
    }
    first.env("PODSSH_RELAY_LAYER", "yes").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
    let mut first = first.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while took.load(Ordering::SeqCst) == 0 {
        if Instant::now() > deadline || first.try_wait().unwrap().is_some() {
            let _ = first.kill();
            let out = first.wait_with_output().unwrap();
            panic!("the first session did not reach its target: {}", String::from_utf8_lossy(&out.stderr));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // The role charges it once its target is dialed.
    std::thread::sleep(Duration::from_millis(500));
    let target = banner_target("SSH-2.0-past-the-budget\r\n");
    let out = ran_with(s.command(&proxy(target)), &[("PODSSH_RELAY_LAYER", "yes")]);
    let _ = first.kill();
    let _ = first.wait();
    let text = said(&out);
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    assert!(out.status.success(), "the session past the budget did not go on: {text}; the role: {events}");
    assert!(text.contains("SSH-2.0-past-the-budget"), "the contract's road carried it: {text}");
    let line =
        "has no room for a new resumable session (this relay keeps 1 resumable session (4 MiB of replay buffers)";
    assert!(text.contains(line) && text.contains("the session goes on with no resume"), "{text}");
    assert!(events.contains("layer: this relay keeps 1 resumable session"), "the owner hears it: {events}");
    let first_line = std::fs::read_to_string(s.home.join("fake-relay-normal-role.log")).unwrap_or_default();
    let budget = "sessions within 4 MiB of replay buffers (1 session of 4 MiB), each kept 2 min after a loss";
    assert!(first_line.contains(budget), "the role's first line says its budget: {first_line}");
    // The flags of the sessions go with serve alone.
    let elsewhere = ran(s.command(&["relay", "info", "--resume-budget", "4"].map(String::from)));
    assert_eq!(elsewhere.status.code(), Some(64), "{}", said(&elsewhere));
    assert!(said(&elsewhere).contains("--resume-budget, --resume-host and --http2 go with `podssh relay serve` only"));
}
