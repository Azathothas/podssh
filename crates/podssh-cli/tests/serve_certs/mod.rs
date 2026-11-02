//! The certificate of `podssh relay serve` read again (T-447): two CAs of
//! the test, each with a leaf for relay-a.test, made by rcgen and signed by
//! p256's keys. The role starts with the first CA's pair; its files are
//! replaced by the second's and SIGHUP makes the next handshakes take them,
//! while a session through `podssh proxy` that was open before goes on. A
//! pair whose key is not its certificate's is said, and the pair of before
//! stays. Windows has no SIGHUP: this runs on Unix.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const NAME: &str = "relay-a.test";
const WAIT: Duration = Duration::from_secs(30);

/// The test's directory, removed when it goes, passed or not.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A child of the test, ended when the test ends.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// A P-256 key of p256, for rcgen's certificates and the role's `--key`.
struct Key {
    signing: p256::ecdsa::SigningKey,
    public: Vec<u8>,
}

impl Key {
    fn new() -> Key {
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing, public }
    }

    /// SEC1's `EC PRIVATE KEY`, its curve named, as `openssl ecparam` writes it.
    fn pem(&self) -> String {
        let mut body = vec![0x02, 0x01, 0x01, 0x04, 0x20];
        body.extend_from_slice(self.signing.to_bytes().as_slice());
        body.extend_from_slice(&[0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        pem("EC PRIVATE KEY", &der)
    }
}

impl rcgen::PublicKeyData for Key {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.signing.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

fn serial() -> rcgen::SerialNumber {
    rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>())
}

/// A CA of the test, and a leaf of it for NAME with its key: each as PEM.
fn ca_and_leaf(tag: &str) -> (String, String, String) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name = rcgen::DistinguishedName::new();
    ca.distinguished_name.push(rcgen::DnType::CommonName, format!("podssh test CA {tag}"));
    ca.serial_number = Some(serial());
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec![NAME.to_string()]).unwrap();
    leaf.serial_number = Some(serial());
    let leaf = leaf.signed_by(&leaf_key, &rcgen::Issuer::new(ca, &ca_key)).unwrap();
    (pem("CERTIFICATE", ca_cert.der()), pem("CERTIFICATE", leaf.der()), leaf_key.pem())
}

/// `path` replaced whole by `text`, by a rename, as a renewal replaces it.
fn replace(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, text).unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// A TLS handshake with the role, for NAME, trusting `ca` alone.
fn handshake(rt: &tokio::runtime::Runtime, port: u16, ca: &Path) -> Result<(), String> {
    let trust = podssh_ws::Trust::File(ca.to_path_buf());
    let tls = podssh_ws::client::open_tls("127.0.0.1", port, NAME, &trust, &podssh_ws::ProxyChoice::Direct, WAIT);
    rt.block_on(tls).map(drop).map_err(|e| e.to_string())
}

/// Wait until `done`, or fail with what the role said in `log`.
fn until(what: &str, log: &Path, mut done: impl FnMut() -> bool) {
    let end = Instant::now() + WAIT;
    while !done() {
        let said = std::fs::read_to_string(log).unwrap_or_default();
        assert!(Instant::now() < end, "{what}, not within {WAIT:?}; the role said:\n{said}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A target that sends back each line that it gets.
fn echo_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut back = stream.try_clone().unwrap();
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    if writeln!(back, "{line}").is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

fn podssh(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_RELAY_TOKEN"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", dir).env("PODSSH_CACHE_DIR", dir.join("cache")).env("PODSSH_SSH_CONFIG", "none");
    cmd
}

#[test]
fn sighup_takes_the_new_certificate_for_the_next_handshakes_and_the_open_session_goes_on() {
    let name = format!("podssh-t447-{}-{:08x}", std::process::id(), rand::random::<u32>());
    let s = Scratch(std::env::temp_dir().join(name));
    std::fs::create_dir_all(s.0.join("cache")).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let ((ca_a, leaf_a, key_a), (ca_b, leaf_b, key_b)) = (ca_and_leaf("a"), ca_and_leaf("b"));
    let (ca_a_file, ca_b_file) = (s.0.join("ca-a.pem"), s.0.join("ca-b.pem"));
    let (cert, key) = (s.0.join("cert.pem"), s.0.join("key.pem"));
    std::fs::write(&ca_a_file, ca_a).unwrap();
    std::fs::write(&ca_b_file, ca_b).unwrap();
    replace(&cert, &leaf_a);
    replace(&key, &key_a);

    let (log, port_file) = (s.0.join("role.log"), s.0.join("port"));
    let role = podssh(&s.0)
        .args(["relay", "serve", "--listen", "127.0.0.1:0", "--mint", "anyone", "--allow-private"])
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .arg("--port-file")
        .arg(&port_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let pid = role.id() as libc::pid_t;
    let mut role = Killed(role);
    let mut port = 0;
    until("the role's port", &log, || {
        port = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0);
        port != 0
    });
    handshake(&rt, port, &ca_a_file).expect("the first CA's pair, at the start");
    assert!(handshake(&rt, port, &ca_b_file).is_err(), "not yet the second's");

    // A session through the role, open across the reload.
    let target = echo_target();
    let mut proxy = podssh(&s.0)
        .arg("proxy")
        .args(["--relay-host", &format!("{NAME}:{port}"), "--relay-addr", &format!("{NAME}=127.0.0.1")])
        .arg("--ca-file")
        .arg(&ca_a_file)
        .args(["127.0.0.1", &target.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(s.0.join("proxy.log")).unwrap())
        .spawn()
        .unwrap();
    let (mut to_proxy, from_proxy) = (proxy.stdin.take().unwrap(), proxy.stdout.take().unwrap());
    let _proxy = Killed(proxy);
    let (lines_tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(from_proxy).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });
    let proxy_log = s.0.join("proxy.log");
    let mut through = |text: &str| {
        writeln!(to_proxy, "{text}").unwrap();
        to_proxy.flush().unwrap();
        let back = lines.recv_timeout(WAIT);
        back.map_err(|e| format!("{e}; the proxy said: {}", std::fs::read_to_string(&proxy_log).unwrap_or_default()))
    };
    assert_eq!(through("before").unwrap(), "before");

    // The renewal: each file replaced whole, then SIGHUP.
    replace(&cert, &leaf_b);
    replace(&key, &key_b);
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    until("the second CA's pair after SIGHUP", &log, || handshake(&rt, port, &ca_b_file).is_ok());
    assert!(handshake(&rt, port, &ca_a_file).is_err(), "the next handshakes take the new pair alone");
    assert_eq!(through("after").unwrap(), "after", "the session open before the reload goes on");
    let said = std::fs::read_to_string(&log).unwrap();
    assert!(said.contains("SIGHUP: read ") && said.contains(&format!("for {NAME}, until ")), "{said}");

    // A key that is not the certificate's: said, and the pair of before stays.
    let refusals = || std::fs::read_to_string(&log).unwrap_or_default().matches("not the one of the").count();
    let before = refusals();
    replace(&key, &key_a);
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    until("the refusal of a key that is not the certificate's", &log, || refusals() > before);
    handshake(&rt, port, &ca_b_file).expect("the pair of before stays");
    assert!(role.0.try_wait().unwrap().is_none(), "SIGHUP never ends the role");
}
