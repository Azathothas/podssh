//! The TLS 1.2 suites of podssh's provider (T-067), each against OpenSSL's
//! `s_server` held to TLS 1.2 and to that one suite: the handshake, then
//! lines that the server sends back reversed, so that records go each way
//! after the handshake. A server that also speaks TLS 1.3 gets 1.3, and a
//! TLS 1.2 server with only a CBC suite gets no handshake. The checks say
//! that they did not run when this host has no openssl, and fail instead
//! with `PODSSH_TEST_OPENSSL` set, as the gate sets it.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use podssh_ws::Trust;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{CipherSuite, ProtocolVersion};

const LIMIT: Duration = Duration::from_secs(20);

/// The key of a leaf certificate.
#[derive(Clone, Copy)]
enum Key {
    Ecdsa,
    Rsa,
}

/// `s_server`, stopped when the test ends.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn openssl(args: &[&str]) -> Result<(), String> {
    let out = Command::new("openssl").args(args).stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("openssl {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// A directory of the temporary directory, removed when it is dropped: the
/// gate fails a run of the tests that leaves one (T-272).
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Result<Scratch, String> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("podssh-tls12-{}-{what}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Scratch(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The files that a test's server and client read.
const FILES: [&str; 5] = ["ca.pem", "ecdsa.pem", "ecdsa.key", "rsa.pem", "rsa.key"];

/// Each of [`FILES`] with its bytes.
type Files = Vec<(&'static str, Vec<u8>)>;

/// A CA, and a leaf for `localhost` with each key, as bytes: made once for
/// this test binary, in a directory that goes at once; `None` when this host
/// has no openssl.
fn certificates() -> Option<&'static [(&'static str, Vec<u8>)]> {
    static MADE: OnceLock<Option<Files>> = OnceLock::new();
    MADE.get_or_init(|| {
        let made = Scratch::new("make").and_then(|dir| {
            make(&dir.0)?;
            FILES
                .iter()
                .map(|name| std::fs::read(dir.0.join(name)).map(|b| (*name, b)).map_err(|e| e.to_string()))
                .collect()
        });
        if let Err(why) = &made {
            if std::env::var_os("PODSSH_TEST_OPENSSL").is_some() {
                panic!("PODSSH_TEST_OPENSSL is set, and openssl could not make the certificates: {why}");
            }
            eprintln!("did not run: {why}");
        }
        made.ok()
    })
    .as_deref()
}

fn make(dir: &Path) -> Result<(), String> {
    let p = |name: &str| dir.join(name).display().to_string();
    // A configuration of its own: a host's default one can add extensions
    // that its openssl cannot parse (Git for Windows' does).
    std::fs::write(dir.join("req.cnf"), "[req]\ndistinguished_name = dn\n[dn]\n").map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("ext"),
        "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n\
         extendedKeyUsage=serverAuth\n",
    )
    .map_err(|e| e.to_string())?;
    let (cnf, ca_key, ca, ext) = (p("req.cnf"), p("ca.key"), p("ca.pem"), p("ext"));
    openssl(&[
        "req",
        "-config",
        &cnf,
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=podssh-tls12-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        &ca_key,
        "-out",
        &ca,
    ])?;
    for (name, key) in
        [("ecdsa", &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"][..]), ("rsa", &["-newkey", "rsa:2048"])]
    {
        let (leaf_key, csr, leaf) = (p(&format!("{name}.key")), p(&format!("{name}.csr")), p(&format!("{name}.pem")));
        let mut req = vec!["req", "-config", &cnf];
        req.extend_from_slice(key);
        req.extend(["-nodes", "-subj", "/CN=localhost", "-keyout", &leaf_key, "-out", &csr]);
        openssl(&req)?;
        openssl(&[
            "x509",
            "-req",
            "-in",
            &csr,
            "-CA",
            &ca,
            "-CAkey",
            &ca_key,
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            &ext,
            "-out",
            &leaf,
        ])?;
    }
    Ok(())
}

/// How many ports a server is given before the test fails.
const TRIES: usize = 5;

/// `s_server -rev` with `key`'s certificate and `extra`, once it listens:
/// its port. The port is free when it is chosen, but a test that binds port
/// 0 meanwhile can be given it before `s_server` binds it (seen on Windows,
/// where `s_server` then ends), so a server that ends before it listens is
/// started again on a new port.
fn server(dir: &Path, key: Key, extra: &[&str]) -> (Server, u16) {
    let mut why = Vec::new();
    for _ in 0..TRIES {
        match listen(dir, key, extra) {
            Ok(up) => return up,
            Err(ended) => why.push(ended),
        }
    }
    panic!("openssl s_server ended before it listened, {TRIES} times: {}", why.join("; "));
}

/// One `s_server` once it listens, or why it ended before that.
fn listen(dir: &Path, key: Key, extra: &[&str]) -> Result<(Server, u16), String> {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let name = match key {
        Key::Ecdsa => "ecdsa",
        Key::Rsa => "rsa",
    };
    let (cert, leaf_key) = (dir.join(format!("{name}.pem")), dir.join(format!("{name}.key")));
    let mut child = Command::new("openssl")
        .args(["s_server", "-rev", "-naccept", "1", "-accept", &format!("127.0.0.1:{port}")])
        .arg("-cert")
        .arg(&cert)
        .arg("-key")
        .arg(&leaf_key)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl s_server starts");
    // `ACCEPT` once it listens; what it says on stderr, read as it comes so
    // that the pipe never fills.
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let stderr = child.stderr.take().unwrap();
    let said =
        std::thread::spawn(move || BufReader::new(stderr).lines().map_while(Result::ok).collect::<Vec<_>>().join(" "));
    let deadline = Instant::now() + LIMIT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) if line.contains("ACCEPT") => return Ok((Server(child), port)),
            Ok(_) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                panic!("openssl s_server did not listen within {LIMIT:?}")
            }
            // Its stdout closed: it ended.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let status = child.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
                let said = said.join().unwrap_or_default();
                return Err(format!("on port {port}, {status}: {said}"));
            }
        }
    }
}

/// A handshake, then lines sent and their reversals read back: the version
/// and the suite that were agreed.
async fn exchange(port: u16, ca: PathBuf) -> Result<(ProtocolVersion, CipherSuite), String> {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
    let tls = podssh_ws::tls::connect_over(tcp, "localhost", &Trust::File(ca), LIMIT).await?;
    let (_, connection) = tls.get_ref();
    let version = connection.protocol_version().ok_or("no version")?;
    let suite = connection.negotiated_cipher_suite().ok_or("no suite")?.suite();
    let (read, mut write) = tokio::io::split(tls);
    let mut lines = tokio::io::BufReader::new(read).lines();
    for n in 0..20 {
        let line = format!("{n:02}-{}", "abcdefghijklmnopqrstuvwxyz".repeat(40));
        write.write_all(format!("{line}\n").as_bytes()).await.map_err(|e| e.to_string())?;
        let back = tokio::time::timeout(LIMIT, lines.next_line())
            .await
            .map_err(|_| format!("line {n}: no answer within {LIMIT:?}"))?
            .map_err(|e| format!("line {n}: {e}"))?
            .ok_or(format!("line {n}: the server closed"))?;
        if back != line.chars().rev().collect::<String>() {
            return Err(format!("line {n} came back as {back:?}"));
        }
    }
    let _ = write.write_all(b"CLOSE\n").await;
    Ok((version, suite))
}

fn agreed(key: Key, extra: &[&str]) -> Option<Result<(ProtocolVersion, CipherSuite), String>> {
    let files = certificates()?;
    // Declared before the server, so dropped after it: the server ends
    // before its files go.
    let dir = Scratch::new("run").expect("a scratch directory");
    for (name, bytes) in files {
        std::fs::write(dir.0.join(name), bytes).expect("the certificates written");
    }
    let (_server, port) = server(&dir.0, key, extra);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    Some(
        runtime
            .block_on(async { tokio::time::timeout(LIMIT * 3, exchange(port, dir.0.join("ca.pem"))).await })
            .unwrap_or(Err("the exchange passed its limit".into())),
    )
}

/// The suite `name` of OpenSSL, and TLS 1.2 alone: agreed as `want`.
fn suite_works(key: Key, name: &str, want: CipherSuite) {
    let Some(agreed) = agreed(key, &["-tls1_2", "-cipher", name]) else { return };
    let (version, suite) = agreed.unwrap_or_else(|why| panic!("{name}: {why}"));
    assert_eq!(version, ProtocolVersion::TLSv1_2, "{name}");
    assert_eq!(suite, want, "{name}");
}

#[test]
fn ecdhe_ecdsa_with_aes_256_gcm_sha384() {
    suite_works(Key::Ecdsa, "ECDHE-ECDSA-AES256-GCM-SHA384", CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
}

#[test]
fn ecdhe_ecdsa_with_aes_128_gcm_sha256() {
    suite_works(Key::Ecdsa, "ECDHE-ECDSA-AES128-GCM-SHA256", CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
}

#[test]
fn ecdhe_ecdsa_with_chacha20_poly1305_sha256() {
    suite_works(
        Key::Ecdsa,
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    );
}

#[test]
fn ecdhe_rsa_with_aes_256_gcm_sha384() {
    suite_works(Key::Rsa, "ECDHE-RSA-AES256-GCM-SHA384", CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}

#[test]
fn ecdhe_rsa_with_aes_128_gcm_sha256() {
    suite_works(Key::Rsa, "ECDHE-RSA-AES128-GCM-SHA256", CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
}

#[test]
fn ecdhe_rsa_with_chacha20_poly1305_sha256() {
    suite_works(Key::Rsa, "ECDHE-RSA-CHACHA20-POLY1305", CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
}

/// The server's PKCS #1 v1.5 signature of its key exchange, which a TLS 1.2
/// server may make when the client offers it.
#[test]
fn an_rsa_key_exchange_signed_with_pkcs1_is_taken() {
    let Some(agreed) =
        agreed(Key::Rsa, &["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-sigalgs", "RSA+SHA256"])
    else {
        return;
    };
    let (version, _) = agreed.unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(version, ProtocolVersion::TLSv1_2);
}

#[test]
fn a_server_that_speaks_tls13_gets_tls13() {
    let Some(agreed) = agreed(Key::Ecdsa, &[]) else { return };
    let (version, _) = agreed.unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(version, ProtocolVersion::TLSv1_3);
}

#[test]
fn a_tls12_server_with_only_a_cbc_suite_gets_no_handshake() {
    let Some(agreed) = agreed(Key::Ecdsa, &["-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-SHA256"]) else { return };
    assert!(agreed.is_err(), "a CBC suite was agreed: {agreed:?}");
}
