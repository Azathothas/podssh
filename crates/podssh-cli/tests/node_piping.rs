//! The Piping Server road from end to end (T-451): the commands, not the
//! library. Something on the way refuses each WebSocket upgrade in a proxy's
//! words (the stand-in relay's mode `noupgrade`, as a proxy that ends TLS
//! does), and nothing else. `podssh node` probes the upgrade at its start,
//! finds it refused on the way, and serves the Piping Server road alone,
//! unasked (Q65); `podssh ssh node://` meets the same refusal on the pair's
//! leg and takes the same road. The road's server is nwtgck's
//! piping-server-rust on the loopback, with a certificate of `ppng.io` from
//! the stand-in's CA, which the stand-in proxy's map reaches by that name, so
//! that the unasked road's own server is the one dialed. It says "did not
//! run" with no server's binary, Python or openssl:
//!
//! ```sh
//! PODSSH_TEST_PIPING_RUST=/path/piping-server cargo test -p podssh-cli --test node_piping -- --nocapture
//! ```

mod ssh_harness;
mod stand_harness;
mod throughput_harness;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use stand_harness::{proxy, LABEL};
use throughput_harness::{found, lines_of, wait_for, Cell, Session};

/// The unasked road's own server, which the proxy's map sends to the
/// loopback.
const PIPING: &str = "ppng.io";
/// The bound on the session through the road.
const SESSION_LIMIT: Duration = Duration::from_secs(60);

/// A port that nothing holds now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A certificate of `ppng.io` signed by the stand-in's CA in `dir`, as the
/// harness signs the relay's: the certificate and its key.
fn piping_certificate(dir: &Path) -> Result<(String, String), String> {
    let p = |name: &str| dir.join(name).display().to_string();
    let ext = format!(
        "subjectAltName=DNS:{PIPING}\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n\
         extendedKeyUsage=serverAuth\n"
    );
    std::fs::write(dir.join("piping.ext"), ext).map_err(|e| e.to_string())?;
    let steps: [Vec<String>; 2] = [
        ["req", "-config", &p("req.cnf"), "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
            .iter()
            .map(|s| s.to_string())
            .chain(["-subj".into(), format!("/CN={PIPING}"), "-keyout".into(), p("piping.key")])
            .chain(["-out".into(), p("piping.csr")])
            .collect(),
        ["x509", "-req", "-in", &p("piping.csr"), "-CA", &p("ca.pem"), "-CAkey", &p("ca.key"), "-CAcreateserial"]
            .iter()
            .map(|s| s.to_string())
            .chain(["-days".into(), "2".into(), "-extfile".into(), p("piping.ext"), "-out".into(), p("piping.pem")])
            .collect(),
    ];
    for step in steps {
        let out = Command::new("openssl").args(&step).stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("openssl {}: {}", step[0], String::from_utf8_lossy(&out.stderr).trim()));
        }
    }
    Ok((p("piping.pem"), p("piping.key")))
}

/// The words of piping-server-rust on the loopback over HTTPS.
struct Piping {
    program: String,
    cert: String,
    key: String,
    http: u16,
    https: u16,
}

impl Piping {
    /// The server, started once it answers on its port; the test stops it
    /// and starts it again on the same ports, for a resume.
    fn start(&self) -> Child {
        let child = Command::new(&self.program)
            .args(["--host", "127.0.0.1", "--http-port", &self.http.to_string(), "--enable-https"])
            .args(["--https-port", &self.https.to_string(), "--crt-path", &self.cert, "--key-path", &self.key])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("piping-server");
        let deadline = Instant::now() + Duration::from_secs(20);
        while std::net::TcpStream::connect(("127.0.0.1", self.https)).is_err() {
            assert!(Instant::now() < deadline, "piping-server did not listen on {}", self.https);
            std::thread::sleep(Duration::from_millis(50));
        }
        child
    }
}

/// The lines of `out`, as they come.
fn lines_from(out: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

/// The next line of `lines` within `limit`; the words of podssh else.
fn next_line(lines: &Receiver<String>, limit: Duration, what: &str) -> String {
    lines.recv_timeout(limit).unwrap_or_else(|_| panic!("no {what} within {} s", limit.as_secs()))
}

/// A node and a client behind a proxy that refuses the upgrade: the node
/// serves the Piping Server road alone, a session runs through it, and
/// resumes after the Piping Server's restart.
#[test]
fn a_node_and_its_client_behind_a_refused_upgrade_meet_on_the_piping_server_road() {
    let Ok(program) = std::env::var("PODSSH_TEST_PIPING_RUST") else {
        eprintln!("did not run: PODSSH_TEST_PIPING_RUST names no piping-server");
        return;
    };
    if !found("openssl", &["version"]) {
        eprintln!("did not run: no openssl here");
        return;
    }
    let session = Session::start("node-piping");
    let cell = match Cell::fake_relay_mode(&session, "noupgrade", "the stand-in relay that refuses upgrades") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let dir = Path::new(&ca).parent().unwrap().to_path_buf();
    let (cert, key) = piping_certificate(&dir).expect("the certificate of the Piping Server");
    let piping = Piping { program, cert, key, http: free_port(), https: free_port() };
    let mut server = piping.start();
    let relay_port = relay.rsplit_once(':').unwrap().1.to_string();
    let maps = [format!("relay-a.test=127.0.0.1:{relay_port}"), format!("{PIPING}=127.0.0.1:{}", piping.https)];
    let start = session.home.join("start");
    std::fs::write(&start, b"now").unwrap();
    let node_proxy = proxy(&session, "node", &maps, &[], &start);
    let client_proxy = proxy(&session, "client", &maps, &[], &start);
    // The road unasked: PODSSH_PIPING unset, as a user leaves it.
    let through = |proxy: &str, args: &[String]| {
        let mut cmd = session.stand_in(args, &ca);
        cmd.env("HTTPS_PROXY", proxy).env_remove("PODSSH_PIPING");
        cmd
    };

    let pair = ["relay", "pair", LABEL, "--relay-host", &relay].map(String::from);
    let out = through(&node_proxy, &pair).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));

    let node_args = ["node".to_string(), LABEL.into(), format!("127.0.0.1:{}", session.port)];
    let mut node = through(&node_proxy, &node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let serving = wait_for(&lines, "serving").expect("the node starts");
    assert!(serving.contains("over the Piping Server road through"), "{serving}");
    let why = wait_for(&lines, "was refused on the way").expect("the node says why it serves the road alone");
    assert!(why.contains("Piping Server road alone, unasked"), "{why}");

    let mut args = vec!["ssh".to_string(), "-v".into()];
    args.extend(session.common());
    // `echo` of the tests' SSH server sends its input back.
    args.extend([format!("node://tester@{LABEL}"), "echo".into()]);
    let mut ssh = through(&client_proxy, &args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = ssh.stdin.take().unwrap();
    let echoed = lines_from(ssh.stdout.take().unwrap());
    stdin.write_all(b"before-the-restart\n").unwrap();
    assert_eq!(next_line(&echoed, SESSION_LIMIT, "echo of the first line"), "before-the-restart");
    // The Piping Server goes away and comes back on its port: the session
    // resumes on a new link of the road, with no byte lost.
    let _ = server.kill();
    let _ = server.wait();
    std::thread::sleep(Duration::from_secs(1));
    let mut server = piping.start();
    stdin.write_all(b"after-the-restart\n").unwrap();
    assert_eq!(next_line(&echoed, SESSION_LIMIT, "echo after the restart"), "after-the-restart");
    drop(stdin);
    let deadline = Instant::now() + SESSION_LIMIT;
    while ssh.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = ssh.kill();
            let out = ssh.wait_with_output().unwrap();
            panic!("no end within {} s: {}", SESSION_LIMIT.as_secs(), String::from_utf8_lossy(&out.stderr));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = ssh.wait_with_output().unwrap();
    let _ = server.kill();
    let _ = server.wait();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(echoed.try_recv().is_err(), "no other line came back: {err}");
    // Each byte went by the server on the loopback, not by the relay.
    let log = std::fs::read_to_string(session.home.join("proxy-client.log")).unwrap_or_default();
    assert!(log.contains(&format!("CONNECT {PIPING}:443")), "the client's proxy carried no road to {PIPING}: {log}");
}
