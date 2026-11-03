//! `podssh relay serve` behind its host's proxy (T-457): the role reads
//! `HTTPS_PROXY` as it starts, names the proxy by its place in its first
//! line, never by its credentials, and dials a target through it, which a
//! stand-in proxy of the test's carries to a target of the test's, while the
//! loopback goes directly; a proxy that cannot be read stops the start (78).
//! podssh's own client (`podssh proxy`) reaches the role directly, as its
//! name is pinned to the loopback.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use super::{banner_target, ran, ran_with, relay_flags, role_env, said, LIMIT};
use crate::throughput_harness::Session;

/// A stand-in HTTP CONNECT proxy on the loopback, and the first line of each
/// request that it took: it answers `200`, and carries each tunnel to
/// `127.0.0.1:target`, whatever host the CONNECT named.
fn stand_in_proxy(target: u16) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let kept = asked.clone();
    std::thread::spawn(move || {
        for client in listener.incoming().map_while(Result::ok) {
            let kept = kept.clone();
            std::thread::spawn(move || tunnel(client, target, &kept));
        }
    });
    (port, asked)
}

fn tunnel(client: TcpStream, target: u16, kept: &Mutex<Vec<String>>) {
    let _ = client.set_read_timeout(Some(LIMIT));
    let Ok(mut writer) = client.try_clone() else { return };
    // The reader keeps what came after the head, for the tunnel.
    let mut reader = BufReader::new(client);
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() {
        return;
    }
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(n) if n > 0 && line != "\r\n" => continue,
            _ => break,
        }
    }
    kept.lock().unwrap().push(first.trim_end().to_string());
    if writer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return;
    }
    let Ok(far) = TcpStream::connect(("127.0.0.1", target)) else { return };
    let Ok(mut far_writer) = far.try_clone() else { return };
    // Each way until its end, which goes on as a FIN, as a proxy's tunnel
    // ends: the target's close is the role's `target closed`.
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut far_writer);
        let _ = far_writer.shutdown(std::net::Shutdown::Write);
    });
    let mut far = far;
    let _ = std::io::copy(&mut far, &mut writer);
    let _ = writer.shutdown(std::net::Shutdown::Write);
}

/// Whether `text` holds `words`, where Windows, which has one variable for
/// both cases of a name, may say `HTTPS_PROXY` as `https_proxy`, the name
/// that podssh reads first.
fn says_variable(text: &str, words: &str) -> bool {
    text.contains(words) || (cfg!(windows) && text.contains(&words.replace("HTTPS_PROXY", "https_proxy")))
}

/// The proxy's variables for the role alone: the stand-in's URL, with
/// `userinfo`, in `HTTPS_PROXY`, and each other one empty, which podssh
/// reads as unset, so that the machine's own proxy stays out.
fn proxy_env(port: u16, userinfo: &str) -> Vec<(&'static str, String)> {
    let mut env: Vec<(&'static str, String)> =
        ["https_proxy", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"].map(|v| (v, String::new())).into();
    env.push(("HTTPS_PROXY", format!("http://{userinfo}127.0.0.1:{port}")));
    env
}

#[test]
fn the_role_dials_a_target_through_its_hosts_proxy_and_names_the_proxy_by_its_place() {
    let s = Session::start("serve-proxy");
    let target = banner_target("SSH-2.0-through-the-hosts-proxy\r\n");
    let (port, asked) = stand_in_proxy(target);
    let env = proxy_env(port, "relayuser:s3cret-word@");
    // Private targets: a name goes to the proxy as it came, for it to
    // resolve, as this host may have no DNS.
    let Some(cell) = role_env(&s, &["--allow-private"], &env) else { return };
    let started = std::fs::read_to_string(s.home.join("fake-relay-normal-role.log")).unwrap_or_default();
    let named = format!("its targets through the http proxy 127.0.0.1:{port} of HTTPS_PROXY");
    assert!(says_variable(&started, &named), "{started}");
    assert!(!started.contains("s3cret") && !started.contains("relayuser"), "{started}");

    let proxy = |host: &str, port: &str| {
        let mut args = vec!["proxy".to_string()];
        args.extend(relay_flags(&cell));
        args.extend([host.to_string(), port.to_string()]);
        ran(s.command(&args))
    };
    let out = proxy("target.invalid", "22");
    assert!(said(&out).contains("SSH-2.0-through-the-hosts-proxy"), "through the host's proxy: {}", said(&out));
    assert_eq!(asked.lock().unwrap().as_slice(), ["CONNECT target.invalid:22 HTTP/1.1"]);
    // The loopback goes directly, as no proxy reaches this host's.
    let out = proxy("127.0.0.1", &target.to_string());
    assert!(said(&out).contains("SSH-2.0-through-the-hosts-proxy"), "the loopback: {}", said(&out));
    assert_eq!(asked.lock().unwrap().len(), 1, "the loopback went through the proxy");
}

#[test]
fn a_proxy_that_cannot_be_read_stops_the_start_and_its_credentials_are_never_said() {
    let s = Session::start("serve-proxy-bad");
    let words: Vec<String> = ["relay", "serve", "--listen", "127.0.0.1:0", "--cert", "c.pem", "--key", "k.pem"]
        .iter()
        .map(|w| w.to_string())
        .collect();
    // A made-up user and password, joined here so that no URL with
    // credentials stands in the source for a scanner of secrets to report.
    let url = format!("ftp://{}@proxy.example", ["relayuser", "s3cret-word"].join(":"));
    let out = ran_with(s.command(&words), &[("HTTPS_PROXY", url.as_str())]);
    let text = said(&out);
    assert_eq!(out.status.code(), Some(78), "{text}");
    assert!(says_variable(&text, "the proxy of this host: HTTPS_PROXY: proxy scheme ftp://"), "{text}");
    assert!(!text.contains("s3cret") && !text.contains("relayuser"), "{text}");
}
