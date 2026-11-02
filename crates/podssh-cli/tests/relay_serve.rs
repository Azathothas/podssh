//! `podssh relay serve` (T-169): the relay's forward road served by podssh
//! itself, on the loopback with a certificate of a test CA (made by
//! `openssl`, as for the stand-in relay), against podssh's own client: bytes
//! both ways through `podssh ssh`, the policy's refusals, a relay that mints
//! for no one, and the documents that `podssh relay` reads. The suite of the
//! stand-in also runs against the role with `PODSSH_RELAY_UNDER_TEST=podssh`.

mod live_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);

/// The role with `extra` flags, or `None` when this host cannot make its
/// certificate.
fn role(s: &Session, extra: &[&str]) -> Option<Cell> {
    match Cell::podssh_relay(s, "podssh's relay role", extra) {
        Ok(cell) => Some(cell),
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

/// The relay flags of a cell: its host, its CA and the pinned address.
fn relay_flags(cell: &Cell) -> Vec<String> {
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    vec![
        "--relay-host".into(),
        at("--relay-host"),
        "--ca-file".into(),
        at("--ca-file"),
        "--relay-addr".into(),
        "relay-a.test=127.0.0.1".into(),
    ]
}

fn ran(mut cmd: Command) -> Output {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn said(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// A target that greets each connection with one line.
fn banner_target(line: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            let _ = stream.write_all(line.as_bytes());
        }
    });
    port
}

#[test]
fn podssh_ssh_carries_8_mib_each_way_through_the_relay_role() {
    let s = Session::start("serve-bytes");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    // The harness's run checks the count of the bytes that arrived.
    let up = throughput_harness::run(&s, &cell, true, 8 << 20).expect("8 MiB up through the role");
    let down = throughput_harness::run(&s, &cell, false, 8 << 20).expect("8 MiB down through the role");
    eprintln!("through podssh relay serve: up {up:.1} MiB/s, down {down:.1} MiB/s");
}

#[test]
fn a_private_target_and_port_25_are_refused_by_the_policy() {
    let s = Session::start("serve-policy");
    let Some(cell) = role(&s, &[]) else { return };
    let target = banner_target("SSH-2.0-never-reached\r\n");
    let mut args = vec!["proxy".to_string()];
    args.extend(relay_flags(&cell));
    args.extend(["127.0.0.1".into(), target.to_string()]);
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(!out.status.success(), "a loopback target through a relay that dials public ones: {text}");
    assert!(text.contains("ALLOW list") && text.contains("not a public address"), "{text}");
    assert!(!text.contains("SSH-2.0-never-reached"), "{text}");

    let mut args = vec!["proxy".to_string()];
    args.extend(relay_flags(&cell));
    // An address of GitHub's: the port is refused before any dial.
    args.extend(["140.82.112.3".into(), "25".into()]);
    let text = said(&ran(s.command(&args)));
    assert!(text.contains("port 25 is refused"), "{text}");
}

#[test]
fn a_relay_that_mints_for_no_one_says_503_and_is_not_asked_again() {
    let s = Session::start("serve-nobody");
    let Some(cell) = role(&s, &["--allow-private", "--mint", "nobody"]) else { return };
    let target = banner_target("SSH-2.0-never-reached\r\n");
    let mut args = vec!["proxy".to_string()];
    args.extend(relay_flags(&cell));
    args.extend(["127.0.0.1".into(), target.to_string()]);
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("503") || text.contains("mints no token"), "{text}");
}

#[test]
fn status_info_and_trace_read_the_role_as_they_read_the_default_relay() {
    let s = Session::start("serve-docs");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let mut args = vec!["relay".to_string(), "status".into(), "--json".into()];
    args.extend(relay_flags(&cell));
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    // The service is checked to be tcp-ssh-relay before a host counts as ok.
    assert!(text.contains("\"ok\":true") && text.contains("\"version\":\"podssh "), "{text}");

    let target = banner_target("SSH-2.0-relay-role-trace\r\n");
    let mut args = vec!["relay".to_string(), "trace".into(), "127.0.0.1".into(), target.to_string()];
    args.extend(relay_flags(&cell));
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("SSH-2.0-relay-role-trace"), "the trace reads the target's first line: {text}");

    let mut args = vec!["relay".to_string(), "info".into(), "github.com".into(), "22".into()];
    args.extend(relay_flags(&cell));
    let out = ran(s.command(&args));
    let text = said(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("262144") || text.contains("256 KiB"), "the five limits: {text}");
}

#[test]
fn serve_refuses_a_missing_certificate_or_listener_and_its_flags_elsewhere() {
    let s = Session::start("serve-usage");
    let cases: [(&[&str], &str); 4] = [
        (&["relay", "serve", "--cert", "c.pem", "--key", "k.pem"], "needs --listen"),
        (&["relay", "serve", "--listen", "127.0.0.1:0"], "needs --cert FILE and --key FILE"),
        (
            &["relay", "serve", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k", "--mint", "some"],
            "anyone or nobody",
        ),
        (&["relay", "spec", "--listen", "127.0.0.1:0"], "go with `podssh relay serve` only"),
    ];
    for (args, says) in cases {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let out = ran(s.command(&args));
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", said(&out));
        assert!(said(&out).contains(says), "{args:?}: {}", said(&out));
    }
}

/// The SHA-256 of `path`, by the system's `sha256sum`.
fn digest_of(path: &std::path::Path) -> Option<String> {
    let out = Command::new("sha256sum").arg(path).output().ok()?;
    String::from_utf8(out.stdout).ok()?.split_whitespace().next().map(str::to_string)
}

/// This user's name, for OpenSSH's login to the loopback's sshd.
fn this_user() -> Option<String> {
    let name = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).ok().filter(|u| !u.is_empty());
    name.or_else(|| {
        let out = Command::new("id").arg("-un").output().ok()?;
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string()).filter(|u| !u.is_empty())
    })
}

#[test]
fn openssh_through_podssh_proxy_and_the_role_reaches_openssh_with_equal_digests() {
    let s = Session::start("serve-openssh");
    let Some(cell) = role(&s, &["--allow-private"]) else { return };
    let (Some(user), true) = (this_user(), throughput_harness::found("ssh", &["-V"])) else {
        eprintln!("did not run: no OpenSSH client or no user name here");
        return;
    };
    let dir = s.home.join("openssh");
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("id");
    let made = ran(s.command(&[
        "keygen".into(),
        "-q".into(),
        "-t".into(),
        "ed25519".into(),
        "-N".into(),
        "".into(),
        "-f".into(),
        key.display().to_string(),
    ]));
    assert!(made.status.success(), "{}", said(&made));
    let sshd = match live_harness::sshd::start(&dir, &key.with_extension("pub")) {
        Ok(sshd) => sshd,
        Err(why) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    // 8 MiB that are not all one byte, in a file that sshd's shell reads too.
    let data = dir.join("data");
    let bytes: Vec<u8> = (0..8u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    std::fs::write(&data, &bytes).unwrap();
    let want = digest_of(&data).expect("sha256sum");
    let proxy = format!("{} proxy {} %h %p", env!("CARGO_BIN_EXE_podssh"), relay_flags(&cell).join(" "));
    let ssh = |remote: &str| {
        let mut cmd = Command::new("ssh");
        cmd.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"])
            .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
            .arg("-i")
            .arg(&key)
            .arg("-o")
            .arg(format!("ProxyCommand={proxy}"))
            .args(["-p", &sshd.port.to_string(), &format!("{user}@127.0.0.1"), remote])
            .env("HOME", &s.home)
            .env("XDG_CACHE_HOME", s.home.join("cache"));
        for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
            cmd.env_remove(name);
        }
        cmd
    };
    // Up: the bytes into the far end's sha256sum.
    let mut up = ssh("sha256sum");
    up.stdin(std::fs::File::open(&data).unwrap()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = up.output().unwrap();
    let text = said(&out);
    assert!(out.status.success(), "up: {text}");
    assert_eq!(text.split_whitespace().next(), Some(want.as_str()), "up: {text}");
    // Down: the far end's copy of the same file, back through the role.
    let back = dir.join("back");
    let mut down = ssh(&format!("cat {}", data.display()));
    down.stdin(Stdio::null()).stdout(std::fs::File::create(&back).unwrap()).stderr(Stdio::piped());
    let out = down.output().unwrap();
    assert!(out.status.success(), "down: {}", said(&out));
    assert_eq!(digest_of(&back).as_deref(), Some(want.as_str()), "down: the 8 MiB came back whole");
}
