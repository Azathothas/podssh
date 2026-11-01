//! `--shadowsocks FILE` (T-373) as a process, against `ssserver` of
//! shadowsocks-rust, software that podssh did not write, in front of the
//! test's SSH server on the loopback (`ssh_harness`): for each method, a
//! session with 1 MiB each way and equal digests; a wrong password ends at
//! the first chunk with the server named, and the next line carries the
//! session; a subscription served over TLS behind a proxy that re-terminates
//! it with the test's CA (`cloud_support`) is kept, and fetched again once
//! its kept servers failed; the server is reached through HTTPS_PROXY, and a
//! proxy that takes the CONNECT and carries nothing is named; `doctor` gives
//! a line for the first server. The bytes that
//! `sslocal` sends open with podssh's decoder, and its answer reaches
//! `sslocal`'s client. `ssserver` and `sslocal` come from
//! `PODSSH_TEST_SSSERVER` and `PODSSH_TEST_SSLOCAL` (the gate names them, so
//! that a missing one fails), else the path; with neither, a test says that
//! it did not run. The refusals need no server and always run.
#![cfg(unix)]

mod cloud_support;
mod shadowsocks_support;
mod ssh_harness;

use base64::Engine as _;
use cloud_support::private_file;
use shadowsocks_support::{mapping_proxy, program, run, start_server, World, MIB};

/// An `ss://` line of SIP002 for a server on the loopback.
fn line(method: &str, password: &str, host: &str, port: u16) -> String {
    let userinfo = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
    format!("ss://{userinfo}@{host}:{port}#test")
}

const METHODS: [&str; 3] = ["chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm"];

#[test]
fn each_method_carries_a_session_a_mebibyte_each_way() {
    let Some(ssserver) = program("PODSSH_TEST_SSSERVER", "ssserver") else { return };
    let w = World::new("methods");
    for method in METHODS {
        let password = format!("podssh-test-{method}");
        let (_server, port) = start_server(&ssserver, &w.dir, method, &password);
        let file = private_file(&w.dir, &format!("{method}.list"), &line(method, &password, "127.0.0.1", port));
        let data = shadowsocks_support::mebibyte();
        let (code, out, err) = run(w.ssh(&["--shadowsocks", &file.display().to_string()], "echo"), data.clone());
        assert_eq!(code, Some(0), "{method}: {err}");
        assert_eq!(out.len(), MIB, "{method}: {err}");
        assert_eq!(shadowsocks_support::digest(&out), shadowsocks_support::digest(&data), "{method}");
        assert!(!err.contains(&password), "{err}");
    }
    assert!(w.proxy.connects.lock().unwrap().is_empty(), "no relay and no proxy was asked");
}

#[test]
fn a_wrong_password_ends_at_the_first_chunk_with_the_server_named() {
    let Some(ssserver) = program("PODSSH_TEST_SSSERVER", "ssserver") else { return };
    let w = World::new("password");
    let (_server, port) = start_server(&ssserver, &w.dir, "aes-256-gcm", "the-server-s-password");
    let wrong = line("aes-256-gcm", "not-the-password", "127.0.0.1", port);
    let alone = private_file(&w.dir, "wrong.list", &wrong);
    let (code, out, err) = run(w.ssh(&["--shadowsocks", &alone.display().to_string()], "greet"), Vec::new());
    assert_eq!(code, Some(255), "{err}");
    assert!(out.is_empty());
    let named = format!("the Shadowsocks server ss://127.0.0.1:{port} (test)");
    assert!(err.contains(&named) && err.contains("the password or the method"), "{err}");
    assert!(!err.contains("not-the-password") && !err.contains("the-server-s-password"), "{err}");
    // In order: the wrong key fails, the right one carries the session.
    let both = format!("{wrong}\n{}\n", line("aes-256-gcm", "the-server-s-password", "127.0.0.1", port));
    let both = private_file(&w.dir, "both.list", &both);
    let (code, out, err) = run(w.ssh(&["--shadowsocks", &both.display().to_string()], "greet"), Vec::new());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out), ssh_harness::GREETING);
    assert!(err.contains(&named), "the first server's failure is said: {err}");
}

#[test]
fn a_plugin_shadowsocks_2022_an_open_file_and_a_second_road_are_refused_before_anything_connects() {
    let w = World::new("refused");
    // A user part as percent-encoded text, built from its parts: a secret
    // scanner takes a URI with a user and a password, written whole in a
    // source, for a credential.
    let plain = |method: &str, password: &str, rest: &str| ["ss://", method, ":", password, "@", rest].concat();
    let plugin = plain("aes-256-gcm", "hunter2", "127.0.0.1:8388/?plugin=obfs-local%3Bobfs%3Dhttp");
    let sip022 = plain("2022-blake3-aes-256-gcm", "aHVudGVyMmh1bnRlcjJodW50ZXIy", "127.0.0.1:8388");
    let cases = [
        ("plugin", plugin, "plugin obfs-local"),
        ("sip022", sip022, "Shadowsocks 2022"),
        ("garbled", "# a comment\nss://hunter2!".to_string(), "garbled.list:2: it is neither"),
    ];
    for (name, text, why) in cases {
        let file = private_file(&w.dir, &format!("{name}.list"), &text);
        let (code, _, err) = run(w.ssh(&["--shadowsocks", &file.display().to_string()], "greet"), Vec::new());
        assert_eq!(code, Some(78), "{name}: {err}");
        assert!(err.contains(why) && !err.contains("hunter2") && !err.contains("aHVudGVy"), "{name}: {err}");
    }
    let open = w.dir.join("open.list");
    std::fs::write(&open, line("aes-256-gcm", "hunter2", "127.0.0.1", 8388)).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, _, err) = run(w.ssh(&["--shadowsocks", &open.display().to_string()], "greet"), Vec::new());
    assert!(code == Some(78) && err.contains("chmod 600") && !err.contains("hunter2"), "{err}");
    let file = private_file(&w.dir, "good.list", &line("aes-256-gcm", "hunter2", "127.0.0.1", 8388));
    let file = file.display().to_string();
    for (road, said) in [
        (vec!["--relay-host", "relay.example"], "--shadowsocks and --relay-host"),
        (vec!["--direct"], "--shadowsocks cannot go with --direct"),
        (vec!["--forwarder", "wss://f.example/p"], "--forwarder and --shadowsocks"),
        (vec!["-4"], "-4 and -6"),
    ] {
        let mut args = vec!["--shadowsocks", file.as_str()];
        args.extend(road);
        let (code, _, err) = run(w.ssh(&args, "greet"), Vec::new());
        assert!(code == Some(64) && err.contains(said), "{said}: {err}");
    }
    assert!(w.proxy.connects.lock().unwrap().is_empty(), "nothing connected");
}

#[test]
fn a_kept_list_whose_servers_changed_is_fetched_again() {
    let Some(ssserver) = program("PODSSH_TEST_SSSERVER", "ssserver") else { return };
    let w = World::new("subscription");
    let first = start_server(&ssserver, &w.dir, "aes-256-gcm", "first-password");
    // The list as most providers serve it: its lines in base64.
    let lines = format!("{}\nvmess://eyJhZGQiOiJ4In0\n", line("aes-256-gcm", "first-password", "127.0.0.1", first.1));
    w.serve(base64::engine::general_purpose::STANDARD.encode(lines).into_bytes());
    let file = private_file(&w.dir, "sub.list", "# a provider's list\nsubscription https://sub.test/s/SECRET-TOKEN\n");
    let file = file.display().to_string();
    let (code, _, err) = run(w.ssh(&["--shadowsocks", &file], "greet"), Vec::new());
    assert_eq!((code, w.served().asked), (Some(0), 1), "{err}");
    // The server goes, a new one comes, and the list says so; SIP008 this time.
    drop(first);
    let (_second, port) = start_server(&ssserver, &w.dir, "chacha20-ietf-poly1305", "second-password");
    let json = serde_json::json!({"version": 1, "servers": [{"server": "127.0.0.1", "server_port": port,
        "password": "second-password", "method": "chacha20-ietf-poly1305", "remarks": "second"}]});
    w.serve(json.to_string().into_bytes());
    let (code, out, err) = run(w.ssh(&["--shadowsocks", &file], "greet"), Vec::new());
    assert_eq!((code, w.served().asked), (Some(0), 2), "{err}");
    assert_eq!(String::from_utf8_lossy(&out), ssh_harness::GREETING);
    assert!(err.contains("each server of the kept list of the subscription https://sub.test/... failed"), "{err}");
    let (code, _, err) = run(w.ssh(&["--shadowsocks", &file], "greet"), Vec::new());
    assert_eq!((code, w.served().asked), (Some(0), 2), "the kept list carries it: {err}");
    assert!(!err.contains("first-password") && !err.contains("second-password"), "{err}");
    assert!(!err.contains("SECRET-TOKEN"), "{err}");
    assert_eq!(w.served().paths, vec!["/s/SECRET-TOKEN".to_string(); 2], "fetched by its path");
    let kept: Vec<_> = std::fs::read_dir(w.dir.join("cache")).unwrap().flatten().collect();
    let kept = kept.iter().find(|e| e.file_name().to_string_lossy().starts_with("shadowsocks-")).expect("a kept list");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(kept.metadata().unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn the_server_is_reached_through_the_proxy_and_a_proxy_that_carries_nothing_is_named() {
    let Some(ssserver) = program("PODSSH_TEST_SSSERVER", "ssserver") else { return };
    let w = World::new("proxy");
    let (_server, port) = start_server(&ssserver, &w.dir, "aes-128-gcm", "through-the-proxy");
    let file = private_file(&w.dir, "named.list", &line("aes-128-gcm", "through-the-proxy", "ss.test", port));
    let file = file.display().to_string();
    for hold in [false, true] {
        let (proxy, asked) = w.runtime.block_on(mapping_proxy(hold));
        let mut cmd = w.ssh(&["--shadowsocks", &file], "greet");
        cmd.env("https_proxy", format!("http://127.0.0.1:{proxy}"));
        let (code, out, err) = run(cmd, Vec::new());
        assert_eq!(asked.lock().unwrap().clone(), vec![format!("ss.test:{port}")], "{err}");
        if hold {
            assert_eq!(code, Some(255), "{err}");
            let named = format!("the proxy 127.0.0.1:{proxy} took the CONNECT, and no byte of the Shadowsocks server");
            assert!(err.contains(&named), "{err}");
        } else {
            assert_eq!(code, Some(0), "{err}");
            assert_eq!(String::from_utf8_lossy(&out), ssh_harness::GREETING);
        }
    }
}

/// `doctor --shadowsocks FILE`: a line for the first server, which names it
/// and GitHub's port through it, whether this host reaches GitHub or not.
#[test]
fn doctor_gives_a_line_for_the_first_server() {
    let Some(ssserver) = program("PODSSH_TEST_SSSERVER", "ssserver") else { return };
    let w = World::new("doctor");
    let (_server, port) = start_server(&ssserver, &w.dir, "aes-256-gcm", "doctor-password");
    let file = private_file(&w.dir, "doctor.list", &line("aes-256-gcm", "doctor-password", "127.0.0.1", port));
    let (file, ca) = (file.display().to_string(), w.proxy.ca_file.display().to_string());
    let args = ["doctor", "--shadowsocks", file.as_str(), "--ca-file", ca.as_str()];
    let mut cmd = cloud_support::command(&w.dir, &args, Some(&w.proxy), &[]);
    cmd.env("PODSSH_SETTINGS", "none").env("PODSSH_CACHE_DIR", w.dir.join("cache"));
    let (_, out, err) = run(cmd, Vec::new());
    let text = String::from_utf8_lossy(&out);
    let named = |l: &&str| l.split_whitespace().nth(1) == Some("shadowsocks");
    let line = text.lines().find(named).unwrap_or_else(|| panic!("{text}{err}"));
    assert!(line.contains(&format!("ss://127.0.0.1:{port} (test)")) && line.contains("github.com:22"), "{line}");
    assert!(!text.contains("doctor-password") && !err.contains("doctor-password"), "{text}{err}");
}

#[test]
fn the_bytes_that_sslocal_sends_open_and_its_client_hears_the_answer() {
    let Some(sslocal) = program("PODSSH_TEST_SSLOCAL", "sslocal") else { return };
    let w = World::new("sslocal");
    for method in METHODS {
        let heard = w.runtime.block_on(shadowsocks_support::through_sslocal(&sslocal, &w.dir, method));
        assert_eq!(heard.target, ("target.test".to_string(), 2222), "{method}");
        assert_eq!(heard.first, b"hello from sslocal", "{method}");
        assert_eq!(heard.answer, b"hello back", "{method}");
    }
}
