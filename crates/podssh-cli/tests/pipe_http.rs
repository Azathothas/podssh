//! `podssh pipe http-listen:` (T-367), the HTTP CONNECT proxy, with curl as
//! its client, software that podssh did not write: a page over TLS from a
//! test server comes through `tcp:%h:%p`, and through `relay:%h:%p` to the
//! stand-in relay, with the bytes of a direct fetch; the stand-in's refusal
//! of its policy is a 403 that names it, and a target that it cannot reach a
//! 502. A CONNECT through `ssh:` to the test's sshd gets its banner. A GET
//! gets 405, and a request with no credential, or a wrong one, 407 with its
//! challenge, and the target sees no connection for either; with the right
//! one, it does. `PODSSH_LISTEN=no` exits 78 before any bind, and a proxy
//! off loopback with no credential file 64. A check that needs a program
//! that this host lacks (curl, Python, openssl) says that it did not run.

mod ssh_harness;
mod throughput_harness;
mod update_support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

use throughput_harness::{found, lines_of, wait_for, without_proxy, Cell, Session, PROXY_VARS};

/// The bound on each wait of a test.
const LIMIT: Duration = Duration::from_secs(30);

/// Whether curl runs here; else the check says that it did not run.
fn curl_here() -> bool {
    let here = found("curl", &["--version"]);
    if !here {
        eprintln!("did not run: no curl here");
    }
    here
}

/// `curl ARGS`, with no proxy of the machine's and no `.curlrc`, within its
/// own limit: (exit code, stdout, stderr). Schannel would check revocation,
/// which a test CA has none of.
fn curl(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new("curl");
    cmd.args(["-q", "-sS", "--max-time", "30", "--ssl-no-revoke"]).args(args);
    for name in PROXY_VARS.iter().chain(&["http_proxy", "HTTP_PROXY"]) {
        cmd.env_remove(name);
    }
    let out = cmd.stdin(Stdio::null()).output().expect("curl runs");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// `podssh pipe FLAGS http-listen:127.0.0.1:0 OTHER`.
fn args(flags: &[String], other: &str) -> Vec<String> {
    let mut args = vec!["pipe".to_string()];
    args.extend(flags.iter().cloned());
    args.extend(["http-listen:127.0.0.1:0".to_string(), other.to_string()]);
    args
}

/// The proxy of `cmd`, kept until the session ends: the URL that its line
/// names for HTTPS_PROXY, with no place for a credential, and its lines.
fn proxy(session: &Session, mut cmd: Command) -> (String, Receiver<String>) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut child);
    session.keep(child);
    let line = wait_for(&lines, "HTTPS_PROXY=").expect("the proxy listens");
    let url = line.split("HTTPS_PROXY=").nth(1).unwrap().split(',').next().unwrap().trim();
    (url.replace("USER:PASSWORD@", ""), lines)
}

/// The stand-in relay of `mode`'s flags, or `None` when it cannot run here.
fn relay_flags(session: &Session, mode: &str) -> Option<Vec<String>> {
    let cell = match Cell::fake_relay_mode(session, mode, "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let mut flags = vec!["--relay-host".to_string(), at("--relay-host"), "--ca-file".into(), at("--ca-file")];
    flags.extend(["--relay-addr".to_string(), "relay-a.test=127.0.0.1".into()]);
    Some(flags)
}

/// A page of 256 KiB that is not one byte repeated.
fn page() -> Vec<u8> {
    (0..262_144u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

/// The test's TLS server with `page` at `/page`: its URL and its CA's file.
fn server(session: &Session, page: &[u8]) -> (String, String) {
    let server = session.runtime.block_on(update_support::Server::start(&session.home));
    server.body("/page", page.to_vec());
    let url = format!("{}/page", server.url());
    (url, server.ca_file.display().to_string())
}

/// The page through the proxy at `proxy`, and directly: each fetch's bytes.
fn both_fetches(session: &Session, proxy: &str, url: &str, ca: &str) -> (Vec<u8>, Vec<u8>) {
    let (direct, through) = (session.home.join("direct.bin"), session.home.join("through.bin"));
    let (d, t) = (direct.display().to_string(), through.display().to_string());
    let (code, _, err) = curl(&["--cacert", ca, "-o", &d, url]);
    assert_eq!(code, 0, "the direct fetch: {err}");
    let (code, _, err) = curl(&["--cacert", ca, "-x", proxy, "-o", &t, url]);
    assert_eq!(code, 0, "the fetch through the proxy: {err}");
    (std::fs::read(direct).unwrap(), std::fs::read(through).unwrap())
}

/// A target that counts the connections that it takes, and closes each.
fn counting_target() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, count)
}

/// A file that only this user can read, as `--proxy-auth-file` takes it.
fn private_file(path: &Path, text: &str) {
    let _ = std::fs::remove_file(path);
    let mut file = podssh_relay::cache::create_new_private(path).unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

/// What the proxy answered a CONNECT of curl to `url`, with curl's own
/// configuration in `config` when there is one: (the status, curl's stderr).
fn connect_status(proxy: &str, url: &str, config: Option<&Path>, out: &Path) -> (String, String) {
    let (out, shown) = (out.display().to_string(), config.map(|c| c.display().to_string()));
    let mut args: Vec<&str> = vec!["-v", "-o", out.as_str(), "-w", "%{http_connect}", "-x", proxy, url];
    if let Some(config) = &shown {
        args.extend(["-K", config.as_str()]);
    }
    let (_, status, err) = curl(&args);
    (status.trim().to_string(), err)
}

#[test]
fn curl_fetches_a_page_over_tls_through_tcp_with_the_bytes_of_a_direct_fetch() {
    let session = Session::start("http-tcp");
    if !curl_here() {
        return;
    }
    let page = page();
    let (url, ca) = server(&session, &page);
    let (proxy_url, _lines) = proxy(&session, without_proxy(session.command(&args(&[], "tcp:%h:%p"))));
    let (direct, through) = both_fetches(&session, &proxy_url, &url, &ca);
    assert_eq!(direct, page, "the direct fetch");
    assert!(through == direct, "the fetch through the proxy differs: {} bytes", through.len());
}

#[test]
fn through_the_relay_a_page_comes_whole_its_policy_is_403_and_a_dead_target_502() {
    let session = Session::start("http-relay");
    if !curl_here() {
        return;
    }
    let Some(flags) = relay_flags(&session, "normal") else { return };
    let page = page();
    let (url, ca) = server(&session, &page);
    let (proxy_url, _lines) = proxy(&session, without_proxy(session.command(&args(&flags, "relay:%h:%p"))));
    let (direct, through) = both_fetches(&session, &proxy_url, &url, &ca);
    assert!(through == direct && direct == page, "{} and {} bytes", through.len(), direct.len());
    // A port that nobody serves: the relay's 502, with its words.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let out = session.home.join("out.bin");
    let (status, err) = connect_status(&proxy_url, &format!("https://127.0.0.1:{dead}/"), None, &out);
    assert_eq!(status, "502", "{err}");
    // The relay's policy refuses the target: 403, with its words.
    let Some(flags) = relay_flags(&session, "policy") else { return };
    let (proxy_url, lines) = proxy(&session, without_proxy(session.command(&args(&flags, "relay:%h:%p"))));
    let (status, err) = connect_status(&proxy_url, &url, None, &out);
    assert_eq!(status, "403", "{err}");
    assert!(err.contains("ALLOW list"), "the client hears the relay's words: {err}");
    wait_for(&lines, "ALLOW list").expect("podssh's line names the relay's refusal");
}

#[test]
fn a_connect_through_ssh_gets_the_banner_of_the_sshd_s_own_port() {
    let session = Session::start("http-ssh");
    let mut flags = vec!["--direct".to_string()];
    flags.extend(session.common());
    let other = format!("ssh:tester@127.0.0.1:{},%h:%p", session.port);
    let (proxy_url, _lines) = proxy(&session, without_proxy(session.command(&args(&flags, &other))));
    let mut stream = std::net::TcpStream::connect(proxy_url.trim_start_matches("http://")).unwrap();
    stream.set_read_timeout(Some(LIMIT)).unwrap();
    let port = session.port;
    write!(stream, "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").unwrap();
    let (mut got, mut buf) = (Vec::new(), [0u8; 1024]);
    while !String::from_utf8_lossy(&got).contains("SSH-2.0-") {
        let n = read_some(&mut stream, &mut buf).expect("the answer within the limit");
        assert!(n > 0, "the tunnel ended: {:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    let said = String::from_utf8_lossy(&got);
    assert!(said.starts_with("HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-"), "{said}");
}

#[test]
fn a_get_is_405_a_missing_or_wrong_credential_407_and_neither_is_dialed() {
    let session = Session::start("http-refuse");
    if !curl_here() {
        return;
    }
    let (target, count) = counting_target();
    let out = session.home.join("out.bin");
    let (proxy_url, _lines) = proxy(&session, without_proxy(session.command(&args(&[], "tcp:%h:%p"))));
    let shown = out.display().to_string();
    let (_, status, err) =
        curl(&["-o", &shown, "-w", "%{http_code}", "-x", &proxy_url, &format!("http://127.0.0.1:{target}/")]);
    assert_eq!(status.trim(), "405", "{err}");
    let file = session.home.join("proxy-credentials");
    private_file(&file, "# the clients of the test\ntester:a long secret\n");
    let flags = ["--proxy-auth-file".to_string(), file.display().to_string()];
    let (proxy_url, _lines) = proxy(&session, without_proxy(session.command(&args(&flags, "tcp:%h:%p"))));
    let https = format!("https://127.0.0.1:{target}/");
    let (status, err) = connect_status(&proxy_url, &https, None, &out);
    assert_eq!(status, "407", "{err}");
    assert!(err.contains("Proxy-Authenticate: Basic realm=\"podssh\""), "{err}");
    let config = session.home.join("curl-config");
    private_file(&config, "proxy-user = \"tester:a wrong secret\"\n");
    let (status, err) = connect_status(&proxy_url, &https, Some(&config), &out);
    assert_eq!(status, "407", "{err}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(count.load(Ordering::SeqCst), 0, "a refused request was dialed");
    // The control: with the credential, the target is dialed.
    private_file(&config, "proxy-user = \"tester:a long secret\"\n");
    let (status, err) = connect_status(&proxy_url, &https, Some(&config), &out);
    assert_eq!(status, "200", "{err}");
    let started = Instant::now();
    while count.load(Ordering::SeqCst) == 0 {
        assert!(started.elapsed() < LIMIT, "the target saw no connection");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `podssh ARGS`, within the limit: (exit code, stderr).
fn refused(session: &Session, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let mut cmd = without_proxy(session.command(&args));
    cmd.env_remove("PODSSH_LISTEN").envs(env.iter().copied());
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut err = String::new();
    let mut stderr = child.stderr.take().unwrap();
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code().unwrap_or(-1);
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh {args:?} did not end");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = child.wait();
    let _ = stderr.read_to_string(&mut err);
    (code, err)
}

#[test]
fn listening_off_is_78_before_any_bind_and_a_proxy_off_loopback_needs_credentials() {
    let session = Session::start("http-rules");
    let (code, err) = refused(&session, &["pipe", "http-listen:127.0.0.1:0", "tcp:%h:%p"], &[("PODSSH_LISTEN", "no")]);
    assert_eq!(code, 78, "{err}");
    assert!(err.contains("PODSSH_LISTEN=no"), "{err}");
    let (code, err) = refused(&session, &["pipe", "http-listen:0.0.0.0:0", "relay:%h:%p"], &[]);
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("--proxy-auth-file"), "{err}");
    for other in ["stdio", "relay:example.org:443", "tcp:%h:443"] {
        let (code, err) = refused(&session, &["pipe", "http-listen:127.0.0.1:0", other], &[]);
        assert_eq!(code, 64, "{other}: {err}");
    }
    let (code, err) = refused(&session, &["pipe", "--proxy-auth-file", "f", "stdio", "tcp:127.0.0.1:9"], &[]);
    assert_eq!(code, 64, "{err}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open = session.home.join("open-credentials");
        std::fs::write(&open, "tester:a long secret\n").unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
        let file = open.display().to_string();
        let (code, err) =
            refused(&session, &["pipe", "--proxy-auth-file", &file, "http-listen:127.0.0.1:0", "tcp:%h:%p"], &[]);
        assert_eq!(code, 78, "a file that others can read: {err}");
        assert!(!err.contains("a long secret"), "{err}");
    }
}

/// Live (T-367's Prove): git, a program that knows only HTTPS_PROXY, through
/// the proxy and the live relay behind it. podssh reaches the relay as this
/// host does, through its own proxy when it has one.
#[test]
#[ignore = "live: the relay and github.com"]
fn live_git_ls_remote_through_the_proxy_and_the_live_relay() {
    let session = Session::start("http-live");
    if !found("git", &["--version"]) {
        eprintln!("did not run: no git here");
        return;
    }
    let (proxy_url, _lines) = proxy(&session, session.command(&args(&[], "relay:%h:%p")));
    let mut git = Command::new("git");
    git.args(["-c", &format!("http.proxy={proxy_url}"), "ls-remote", "https://github.com/Azathothas/podssh", "HEAD"]);
    git.env("HTTPS_PROXY", &proxy_url).env("https_proxy", &proxy_url).env("GIT_TERMINAL_PROMPT", "0");
    for name in ["NO_PROXY", "no_proxy"] {
        git.env_remove(name);
    }
    let mut child = git.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            panic!("git did not end within 120 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{said} {}", String::from_utf8_lossy(&out.stderr));
    assert!(said.contains("\tHEAD"), "{said}");
}

/// One read, again while a signal interrupts it: `Read::read` does not
/// retry by itself, and a test's children send it SIGCHLD.
fn read_some(stream: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match stream.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}
