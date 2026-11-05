//! A name published on `podssh relay serve` (T-649, GitHub #147), through the
//! binary on the loopback: the role, its pairs in a file that the test
//! writes, with `--publish site.publish.test=PAIR`; `podssh node
//! --publish-tls` of that pair in front of an HTTPS server of Python's `ssl`,
//! whose certificate openssl made for the published name alone; and TLS
//! clients of Python's. The client of the published name gets that server's
//! certificate and its answer, never the role's certificate; a client of the
//! role's own name gets the role's, and `/health`; the role's line names the
//! name and the visitor. Python and openssl are probed: with either missing,
//! the test says so and does not run.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::throughput_harness::{found, lines_of, wait_for, without_proxy, Cell, Session};

const SITE: &str = "site.publish.test";
/// The pair that the role keeps from the start, and its three tokens: the
/// test's own, as `--publish` names a pair that exists before the role.
const PAIR: &str = "p-7e57c0de7e57c0de7e57c0de7e57c0de";
const NODE_TOKEN: &str = "t649-node-of-the-test-0000000000";
const CONNECT_TOKEN: &str = "t649-connect-of-the-test-00000000";
const STOP_TOKEN: &str = "t649-stop-of-the-test-0000000000";
const LIMIT: Duration = Duration::from_secs(60);

/// The node's HTTPS server: its certificate, its key, then a line with its
/// port; each client gets the test's words and what it sent.
const SERVER: &str = r#"
import socket, ssl, sys, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(16)
print(srv.getsockname()[1], flush=True)
def serve(conn):
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        asked = tls.recv(4096)
        tls.sendall(b"the site of the test: " + asked)
        tls.close()
    except Exception:
        conn.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
"#;

/// A TLS client of the port in argv[1], by the name in argv[2], which sends
/// argv[3]: the SHA-256 of the leaf that it got, then what came back.
const CLIENT: &str = r#"
import hashlib, socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=20) as raw:
    with ctx.wrap_socket(raw, server_hostname=sys.argv[2]) as tls:
        print(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest())
        tls.sendall(sys.argv[3].encode())
        got = b""
        while True:
            part = tls.recv(4096)
            if not part:
                break
            got += part
        print(got.decode(errors="replace"))
"#;

fn said(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `text` into `path`, a file that only its owner reads, as the role and the
/// node take a file of pairs.
fn private(path: &Path, text: &str) {
    let mut file =
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).expect("a private file");
    file.write_all(text.as_bytes()).unwrap();
}

/// The SHA-256 of the leaf of the PEM file `pem`, by openssl.
fn leaf_digest(pem: &Path) -> String {
    let out = Command::new("openssl").args(["x509", "-outform", "DER", "-in"]).arg(pem).output().unwrap();
    assert!(out.status.success(), "openssl x509: {}", said(&out));
    hex(&Sha256::digest(&out.stdout))
}

/// The client of [`CLIENT`] to `port` by `name`, sending `words`: the
/// digest of its leaf, and the answer.
fn visit(python: &str, port: u16, name: &str, words: &str) -> (String, String) {
    let out = Command::new(python).args(["-c", CLIENT, &port.to_string(), name, words]).output().unwrap();
    assert!(out.status.success(), "the client of {name}: {}", said(&out));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (leaf, answer) = text.split_once('\n').unwrap_or((&text, ""));
    (leaf.trim().to_string(), answer.to_string())
}

/// The site's certificate and key for [`SITE`] alone, made by openssl.
fn site_certificate(dir: &Path) -> (PathBuf, PathBuf) {
    let (cert, key) = (dir.join("site.pem"), dir.join("site.key"));
    let out = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2"])
        .args(["-subj", &format!("/CN={SITE}"), "-addext", &format!("subjectAltName=DNS:{SITE}")])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "openssl req: {}", said(&out));
    (cert, key)
}

#[test]
fn a_published_name_reaches_the_node_s_https_server_and_the_role_s_own_name_the_role() {
    let s = Session::start("serve-publish");
    let python = ["python3", "python"].into_iter().find(|p| found(p, &["--version"]));
    let (Some(python), true) = (python, found("openssl", &["version"])) else {
        eprintln!("did not run: no Python or no openssl here, for the site of the test");
        return;
    };
    let dir = s.home.join("publish");
    std::fs::create_dir_all(&dir).unwrap();
    let (site_pem, site_key) = site_certificate(&dir);
    let mut site = Command::new(python);
    site.args(["-c", SERVER]).arg(&site_pem).arg(&site_key);
    let mut site = site.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut first = String::new();
    BufReader::new(site.stdout.take().unwrap()).read_line(&mut first).unwrap();
    let site_port: u16 = first.trim().parse().expect("the site's port");
    s.keep(site);

    // The role's pairs, by the digests of their tokens, as its file keeps
    // them; the pair lives 71 h more.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let expires = now + 71 * 3_600_000;
    let digest = |token: &str| hex(&Sha256::digest(token.as_bytes()));
    let pairs = dir.join("pairs.json");
    let kept = serde_json::json!({ "pairs": [{
        "name": PAIR, "expires": expires,
        "node": digest(NODE_TOKEN), "connect": digest(CONNECT_TOKEN), "stop": digest(STOP_TOKEN),
    }] });
    private(&pairs, &kept.to_string());
    let (pairs_arg, published) = (pairs.display().to_string(), format!("{SITE}={PAIR}"));
    let extra = ["--allow-private", "--pairs", pairs_arg.as_str(), "--publish", published.as_str()];
    let role = match Cell::podssh_relay(&s, "podssh's relay role", &extra) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| role.args.iter().position(|a| a == flag).map(|i| role.args[i + 1].clone()).unwrap();
    let (host, ca) = (at("--relay-host"), at("--ca-file"));
    let role_port: u16 = host.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).expect("the role's port");

    // The node of that pair, from a file of its own.
    let pair_file = dir.join("site-pair.json");
    let pair = serde_json::json!({
        "relay": host, "name": PAIR, "node_token": NODE_TOKEN, "connect_token": CONNECT_TOKEN,
        "stop_token": STOP_TOKEN, "expires": expires,
    });
    private(&pair_file, &pair.to_string());
    let args: Vec<String> = ["node", "site", "--pair-file"]
        .iter()
        .map(|a| a.to_string())
        .chain([pair_file.display().to_string(), "--publish-tls".into(), format!("127.0.0.1:{site_port}")])
        .collect();
    let mut node = without_proxy(s.command(&args))
        .env("SSL_CERT_FILE", &ca)
        .env("PODSSH_RELAY_ADDR", "relay-a.test=127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    let first = wait_for(&lines, "publishing").expect("the node's first line");
    assert!(first.contains(&format!("podssh relay serve --publish SITE={PAIR}")), "{first}");
    assert!(first.contains("the relay reads that name, never the bytes"), "{first}");
    wait_for(&lines, "online").expect("the node is online on the role");

    // The published name: the site's leaf and its answer.
    let (site_leaf, role_leaf) = (leaf_digest(&site_pem), leaf_digest(&s.home.join("fake-relay").join("relay.pem")));
    let (leaf, answer) = visit(python, role_port, SITE, "hello through the role");
    assert_eq!(leaf, site_leaf, "the site's own certificate, through the role");
    assert_eq!(answer.trim_end(), "the site of the test: hello through the role");
    // The role's own name: its leaf, and its /health.
    let health = "GET /health HTTP/1.1\r\nHost: relay-a.test\r\nConnection: close\r\n\r\n";
    let (leaf, answer) = visit(python, role_port, "relay-a.test", health);
    assert_eq!(leaf, role_leaf, "the role's own certificate");
    assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");

    // The role's line names the name, the visitor and the pair.
    let events = s.home.join("fake-relay-normal-events.log");
    let wanted = format!("publish {SITE} from 127.0.0.1: to the node of {PAIR}");
    let deadline = Instant::now() + LIMIT;
    while !std::fs::read_to_string(&events).unwrap_or_default().contains(&wanted) {
        assert!(Instant::now() < deadline, "the role never said {wanted:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}
