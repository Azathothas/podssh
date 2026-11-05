//! A list of keys at an `https://` URL for `podssh relay serve --mint
//! keys:URL` (T-646): a server of the test's, over TLS of a CA of the test
//! that `--ca-file` names, serves the list. The role mints for its keys
//! alone; takes a key off after its TTL; keeps its copy while the server
//! answers 503, until the TTL and the stale window pass, then lets no key
//! mint until a fetch works; lets no key mint on an answer that is no list;
//! and does not start (78) when its first fetch fails. No line shows the
//! URL's path. Unix, as `serve_certs` is.

#![cfg(unix)]

use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::identity::Identity;
use podssh_relay::keyed;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::serve_certs::{ca_and_leaf, podssh, replace, until, Killed, Scratch};

const NAME: &str = "relay-a.test";
const WAIT: Duration = Duration::from_secs(30);
/// The secret of the list's URL, which no line of the role may show.
const SECRET: &str = "owners-SECRET-path";

/// The line of a list that holds the key of `seed`.
fn line(seed: u8) -> String {
    format!("{} the key of seed {seed}\n", Identity::from_seed(&[seed; 32]).public().fingerprint())
}

/// The list's server: one answer for each connection, the status and the
/// body that the test sets now; each request's first line kept.
struct Lists {
    port: u16,
    answer: Arc<Mutex<(u16, String)>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Lists {
    fn start(rt: &tokio::runtime::Runtime, cert: &str, key: &str) -> Lists {
        let alpn = [podssh_ws::tls_server::HTTP1];
        let acceptor = podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &alpn).expect("the list's TLS");
        let answer = Arc::new(Mutex::new((200u16, String::new())));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (served, heard) = (answer.clone(), asked.clone());
        rt.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, served, heard) = (acceptor.clone(), served.clone(), heard.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let (mut head, mut chunk) = (Vec::new(), [0u8; 1024]);
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let first = String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string();
                    heard.lock().unwrap().push(first);
                    let (status, body) = served.lock().unwrap().clone();
                    let head = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{}",
                        body.len(),
                        "Connection: close\r\n\r\n"
                    );
                    let _ = tls.write_all(format!("{head}{body}").as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Lists { port, answer, asked }
    }

    fn answer(&self, status: u16, body: &str) {
        *self.answer.lock().unwrap() = (status, body.to_string());
    }
}

/// The status and body of a mint by the key of `seed`, as podssh's client
/// sends it: the contract's `{}`, then the key's proof of the challenge.
fn mint(rt: &tokio::runtime::Runtime, port: u16, trust: &Trust, seed: u8) -> (u16, String) {
    let post = |body: Vec<u8>| {
        let sent = podssh_ws::https_post_json(NAME, port, "/v1/mint", &body, trust, &ProxyChoice::Direct, WAIT);
        rt.block_on(sent).expect("the role answers")
    };
    let asked = keyed::challenge_of(&post(b"{}".to_vec())).expect("a 401 with a challenge");
    let signed = keyed::proof(&Identity::from_seed(&[seed; 32]), &keyed::host_header(NAME, port), "/v1/mint", &asked);
    let answer = post(signed);
    (answer.status, answer.body_text(200))
}

/// Until a mint by `seed` gets `status`, a mint each half second: the
/// role's brake counts each.
fn until_mint(rt: &tokio::runtime::Runtime, port: u16, trust: &Trust, seed: u8, status: u16, log: &std::path::Path) {
    let end = Instant::now() + WAIT;
    loop {
        let (got, body) = mint(rt, port, trust, seed);
        if got == status {
            return;
        }
        let said = std::fs::read_to_string(log).unwrap_or_default();
        assert!(Instant::now() < end, "a mint of seed {seed} never got {status}, last {got} {body}; the role:\n{said}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// `podssh relay serve` with its list at `url`, its stderr in `log`.
fn role(s: &Scratch, url: &str, port_file: &std::path::Path, log: &std::path::Path) -> Child {
    let file = |name: &str| s.0.join(name);
    podssh(&s.0)
        .args(["relay", "serve", "--listen", "127.0.0.1:0", "--mint", &format!("keys:{url}")])
        .args(["--list-ttl", "1", "--list-stale", "2", "--relay-addr", &format!("{NAME}=127.0.0.1")])
        .arg("--cert")
        .arg(file("cert.pem"))
        .arg("--key")
        .arg(file("key.pem"))
        .arg("--ca-file")
        .arg(file("ca.pem"))
        .arg("--port-file")
        .arg(port_file)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(log.with_extension("events")).unwrap())
        .stderr(std::fs::File::create(log).unwrap())
        .spawn()
        .unwrap()
}

#[test]
fn a_role_mints_for_the_keys_of_a_list_at_a_url_until_its_copy_is_too_old() {
    let name = format!("podssh-t646-{}-{:08x}", std::process::id(), rand::random::<u32>());
    let s = Scratch(std::env::temp_dir().join(name));
    std::fs::create_dir_all(s.0.join("cache")).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (ca, cert, key) = ca_and_leaf("list");
    std::fs::write(s.0.join("ca.pem"), &ca).unwrap();
    replace(&s.0.join("cert.pem"), &cert);
    replace(&s.0.join("key.pem"), &key);
    let lists = Lists::start(&rt, &cert, &key);
    let url = format!("https://{NAME}:{}/{SECRET}?k=1", lists.port);
    podssh_ws::resolve::set_pins(podssh_ws::resolve::parse_pins(&format!("{NAME}=127.0.0.1")).unwrap());
    let trust = Trust::File(s.0.join("ca.pem"));

    // The first fetch fails: no start (78), and no word of the path.
    lists.answer(503, "");
    let (log, port_file) = (s.0.join("refused.log"), s.0.join("refused.port"));
    let mut refused = Killed(role(&s, &url, &port_file, &log));
    let end = Instant::now() + WAIT;
    let code = loop {
        if let Some(status) = refused.0.try_wait().unwrap() {
            break status.code();
        }
        assert!(Instant::now() < end, "a role whose list did not come is still up");
        std::thread::sleep(Duration::from_millis(100));
    };
    let said = std::fs::read_to_string(&log).unwrap();
    assert_eq!(code, Some(78), "{said}");
    let shown = format!("https://{NAME}:{}/...", lists.port);
    assert!(said.contains(&format!("--mint keys:{shown}: HTTP 503")) && !said.contains("SECRET"), "{said}");

    // The list holds the key of 0x61: it mints, and 0x62 does not.
    lists.answer(200, &line(0x61));
    let (log, port_file) = (s.0.join("role.log"), s.0.join("role.port"));
    let _role = Killed(role(&s, &url, &port_file, &log));
    let mut port = 0;
    until("the role's port", &log, || {
        port = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0);
        port != 0
    });
    let first = std::fs::read_to_string(&log).unwrap();
    assert!(first.contains(&format!("minting for the keys of the list at {shown} (1 key now;")), "{first}");
    assert_eq!(mint(&rt, port, &trust, 0x61).0, 200);
    let (status, body) = mint(&rt, port, &trust, 0x62);
    assert!(status == 403 && body.contains("not on this relay's list"), "{status} {body}");

    // The owner takes 0x61 off and puts 0x62 on: after the TTL, each counts.
    lists.answer(200, &line(0x62));
    until_mint(&rt, port, &trust, 0x61, 403, &log);
    assert_eq!(mint(&rt, port, &trust, 0x62).0, 200);

    // The server fails: the copy holds until its TTL and stale window pass.
    lists.answer(503, "");
    assert_eq!(mint(&rt, port, &trust, 0x62).0, 200, "the copy of a second ago");
    until_mint(&rt, port, &trust, 0x62, 403, &log);
    let (_, body) = mint(&rt, port, &trust, 0x62);
    assert!(body.contains("this relay cannot read its list of keys"), "{body}");
    // A fetch that works lets the list's keys in again.
    lists.answer(200, &line(0x62));
    until_mint(&rt, port, &trust, 0x62, 200, &log);

    // An answer that is no list lets no key mint.
    lists.answer(200, "<html><body>sign in</body></html>\n");
    until_mint(&rt, port, &trust, 0x62, 403, &log);

    let said = std::fs::read_to_string(&log).unwrap();
    let events = std::fs::read_to_string(log.with_extension("events")).unwrap_or_default();
    assert!(said.contains(&format!("{shown}: HTTP 503 Test")), "a fetch that failed is a line: {said}");
    assert!(said.contains(&format!("{shown}: its answer holds no key")), "{said}");
    assert!(!said.contains("SECRET") && !events.contains("SECRET"), "the path shows: {said}{events}");
    let asked = lists.asked.lock().unwrap().clone();
    assert!(asked.iter().all(|l| l == &format!("GET /{SECRET}?k=1 HTTP/1.1")), "{asked:?}");
}
