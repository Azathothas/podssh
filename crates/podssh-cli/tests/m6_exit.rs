//! The exit of M6 (T-156), on this machine's loopback: a session survives a
//! stopped relay host, a new address of its client, and a stall of 3
//! minutes, on the resumable layer over the reverse road (the stand-in
//! relay serves it) and on the iroh road. A stand-in proxy between the
//! client and the relay makes the fault when the session is in the middle
//! of 20 MiB that go up and come back (`echo` of the tests' SSH server); the
//! far end has a proxy of its own, which makes the fault too when the relay
//! host stops, as that ends each of the host's connections. The new address
//! and the stall are the client's. Pass: exit 0, each byte back once and in
//! order, and on the layer one line on stderr for each loss and one for its
//! resume. The controls: the same faults end a session of the forward road,
//! which has no resumable layer, with 255. Ignored, as they take some
//! minutes:
//!
//! ```sh
//! cargo test -p podssh-cli --test m6_exit -- --ignored --test-threads 1
//! cargo test -p podssh-cli --features iroh-test --test m6_exit -- --ignored --test-threads 1
//! ```

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use throughput_harness::{found, lines_of, scripts, wait_for, Cell, Session};

const MIB: usize = 1 << 20;
const BYTES: usize = 20 * MIB;
/// The fault starts when this much of the 20 MiB is written.
const TRIGGER: usize = 8 * MIB;
const LIMIT: Duration = Duration::from_secs(600);

/// The stand-ins of one check: the relay, and a proxy for each end.
struct Stand {
    session: Session,
    relay: String,
    ca: String,
    /// The client's, with the fault.
    proxy: String,
    /// The node's.
    node_proxy: String,
    start: PathBuf,
}

impl Stand {
    /// The stand-in relay, the client's proxy in front of it with `fault`,
    /// and the node's with `node_fault`; `None` when this host has no Python
    /// or no openssl, which the test says.
    fn new(tag: &str, fault: &[&str], node_fault: &[&str]) -> Option<Stand> {
        let session = Session::start(tag);
        let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
            Ok(cell) => cell,
            Err((_, why)) => {
                eprintln!("skipped: {why}");
                return None;
            }
        };
        let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
        let (relay, ca) = (at("--relay-host"), at("--ca-file"));
        let port = relay.rsplit_once(':').unwrap().1.to_string();
        let start = session.home.join("start");
        let map = [format!("relay-a.test=127.0.0.1:{port}")];
        let node_proxy = proxy(&session, "node", &map, node_fault, &start);
        let proxy = proxy(&session, "client", &map, fault, &start);
        Some(Stand { session, relay, ca, proxy, node_proxy, start })
    }

    /// `podssh ARGS` through the client's proxy, with the stand-in relay's
    /// trust.
    fn command(&self, args: &[String]) -> Command {
        self.through(&self.proxy, args)
    }

    fn through(&self, proxy: &str, args: &[String]) -> Command {
        let mut cmd = self.session.command(args);
        cmd.env("HTTPS_PROXY", proxy).env("SSL_CERT_FILE", &self.ca);
        cmd
    }

    /// A pair on the stand-in relay, and its node in front of the tests'
    /// SSH server: the pair's label.
    fn node(&self) -> String {
        let label = "m6".to_string();
        let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
        let mut args =
            vec!["relay".to_string(), "pair".into(), label.clone(), "--relay-host".into(), self.relay.clone()];
        args.extend(pins.iter().cloned());
        let out = self.through(&self.node_proxy, &args).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
        let mut args = vec!["node".to_string(), label.clone(), format!("127.0.0.1:{}", self.session.port)];
        args.extend(pins);
        let mut node =
            self.through(&self.node_proxy, &args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let lines = lines_of(&mut node);
        self.session.keep(node);
        wait_for(&lines, "serving").expect("the node starts");
        label
    }
}

/// A stand-in proxy, its names mapped, with `fault` from `start`: its URL.
fn proxy(session: &Session, name: &str, maps: &[String], fault: &[&str], start: &std::path::Path) -> String {
    let python = ["python3", "python"].into_iter().find(|p| found(p, &["--version"])).expect("Python");
    let port_file = session.home.join(format!("proxy-{name}.port"));
    let mut cmd = Command::new(python);
    cmd.arg(scripts().join("fake-proxy.py")).arg("--port-file").arg(&port_file);
    cmd.arg("--log").arg(session.home.join(format!("proxy-{name}.log"))).arg("--start-file").arg(start);
    for map in maps {
        cmd.arg("--map").arg(map);
    }
    cmd.args(fault).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    session.keep(cmd.spawn().expect("the stand-in proxy"));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            return format!("http://127.0.0.1:{port}");
        }
        assert!(Instant::now() < deadline, "the stand-in proxy did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Bytes that are not all alike, so that a byte out of place shows.
fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// 20 MiB up and back through `podssh ssh ARGS echo`, the fault started
/// when 8 MiB are written: (exit code, the bytes back whole, stderr).
fn echo(mut child: Child, start: &std::path::Path) -> (i32, bool, String) {
    let sent = pattern(BYTES);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let home = start.parent().expect("the start file is in the session's directory").to_path_buf();
    let start = start.to_path_buf();
    let writing = {
        let sent = sent.clone();
        std::thread::spawn(move || {
            for (i, chunk) in sent.chunks(64 * 1024).enumerate() {
                if stdin.write_all(chunk).is_err() {
                    return;
                }
                if (i + 1) * 64 * 1024 == TRIGGER {
                    std::fs::write(&start, b"now").unwrap();
                }
            }
        })
    };
    let reading = std::thread::spawn(move || {
        let mut got = Vec::with_capacity(BYTES);
        let _ = stdout.read_to_end(&mut got);
        got
    });
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status.code().unwrap_or(-1));
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = writing.join();
    let got = reading.join().unwrap();
    let err = said.join().unwrap();
    let Some(code) = code else {
        panic!(
            "the session did not end within {} s: {err}
{}",
            LIMIT.as_secs(),
            logs(&home)
        )
    };
    (code, got == sent, err)
}

/// The logs of the stand-ins in `home`, for a check that fails: the session's
/// directory goes when the check ends.
fn logs(home: &std::path::Path) -> String {
    let mut text = String::new();
    for entry in std::fs::read_dir(home).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "log") {
            let body = std::fs::read_to_string(&path).unwrap_or_default();
            text.push_str(&format!(
                "--- {}
{body}",
                path.display()
            ));
        }
    }
    text
}

/// A session to the node of the reverse road, with the resumable layer.
fn through_the_layer(fault: &[&str], node_fault: &[&str], tag: &str) {
    let Some(stand) = Stand::new(tag, fault, node_fault) else { return };
    let label = stand.node();
    let mut args = vec!["ssh".to_string()];
    args.extend(stand.session.common());
    args.extend([
        "--relay-addr".to_string(),
        "relay-a.test=127.0.0.1".into(),
        format!("node://tester@{label}"),
        "echo".into(),
    ]);
    let child =
        stand.command(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let started = Instant::now();
    let (code, whole, err) = echo(child, &stand.start);
    eprintln!("{tag}: exit {code} in {} s", started.elapsed().as_secs());
    assert_eq!(code, 0, "{err}");
    assert!(whole, "the bytes came back changed: {err}");
    // A relay host that stops ends the client's link and the node's, not at
    // one instant: the client can resume before the node's loss, and again
    // after it. Each loss is said once, with its resume.
    let lost = err.matches("resuming the session").count();
    assert!((1..=2).contains(&lost), "the fault came, and no loop of losses: {err}");
    assert_eq!(err.matches("the session resumed").count(), lost, "a resume for each loss: {err}");
}

/// The control: a session of the forward road, which has no layer.
fn on_the_forward_road(fault: &[&str], tag: &str) {
    let Some(stand) = Stand::new(tag, fault, &[]) else { return };
    let mut args = vec!["ssh".to_string()];
    args.extend(stand.session.common());
    args.extend([
        "--relay-host".to_string(),
        stand.relay.clone(),
        "--relay-addr".into(),
        "relay-a.test=127.0.0.1".into(),
    ]);
    args.extend(["-p".to_string(), stand.session.port.to_string(), "tester@127.0.0.1".into(), "echo".into()]);
    let child =
        stand.command(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let started = Instant::now();
    let (code, _, err) = echo(child, &stand.start);
    eprintln!("{tag}: exit {code} in {} s", started.elapsed().as_secs());
    assert_eq!(code, 255, "the forward road survived its fault: {err}");
}

#[test]
#[ignore = "M6's exit: a stopped relay host, on the resumable layer"]
fn the_layer_survives_a_stopped_relay_host() {
    through_the_layer(&["--stop-after", "0"], &["--stop-after", "0"], "stop");
}

#[test]
#[ignore = "M6's exit: a new address of the client, on the resumable layer (about a minute)"]
fn the_layer_survives_a_new_address() {
    through_the_layer(&["--move", "0:127.0.0.2"], &[], "move");
}

#[test]
#[ignore = "M6's exit: a stall of 3 minutes, on the resumable layer (about 4 minutes)"]
fn the_layer_survives_a_stall_of_3_minutes() {
    through_the_layer(&["--pause", "0:180"], &[], "pause");
}

#[test]
#[ignore = "M6's exit, a control: a stopped relay host ends a session of the forward road"]
fn the_forward_road_ends_at_a_stopped_relay_host() {
    on_the_forward_road(&["--stop-after", "0"], "control-stop");
}

#[test]
#[ignore = "M6's exit, a control: a new address of the client ends a session of the forward road"]
fn the_forward_road_ends_at_a_new_address() {
    on_the_forward_road(&["--move", "0:127.0.0.2"], "control-move");
}

#[test]
#[ignore = "M6's exit, a control: a stall of 3 minutes ends a session of the forward road"]
fn the_forward_road_ends_at_a_stall_of_3_minutes() {
    on_the_forward_road(&["--pause", "0:180"], "control-pause");
}

/// The control of the stand-ins: with no fault, the session carries its
/// bytes, and says nothing of a loss.
#[test]
#[ignore = "M6's exit, the control of the stand-ins: a few seconds"]
fn with_no_fault_the_layer_carries_the_session() {
    let Some(stand) = Stand::new("none", &[], &[]) else { return };
    let label = stand.node();
    let mut args = vec!["ssh".to_string(), "-v".into()];
    args.extend(stand.session.common());
    args.extend([
        "--relay-addr".to_string(),
        "relay-a.test=127.0.0.1".into(),
        format!("node://tester@{label}"),
        "echo".into(),
    ]);
    let child =
        stand.command(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (code, whole, err) = echo(child, &stand.start);
    assert_eq!(code, 0, "{err}");
    assert!(whole, "the bytes came back changed: {err}");
    assert!(!err.contains("resuming the session"), "{err}");
}

/// The iroh road (T-162 to T-165): iroh's relay server under a name that only
/// the proxies resolve, so that each byte of the road passes them, and no
/// direct path (`PODSSH_IROH_UDP=off`). QUIC can outlive a short fault with
/// no resume of the layer, so each check reads in the proxy's log, or on the
/// clock, that its fault came.
#[cfg(feature = "iroh-test")]
mod iroh {
    use super::*;

    const NAME: &str = "relay-i.test";

    /// The stand-ins and the node of one check. The fields end in their
    /// order: the processes, then the relay, then its runtime.
    struct Road {
        session: Session,
        _relay: podssh_iroh::test_relay::TestRelay,
        _runtime: tokio::runtime::Runtime,
        url: String,
        cert: String,
        proxy: String,
        start: PathBuf,
        ticket: String,
        client_key: String,
    }

    impl Road {
        /// The relay, the client's proxy with `fault`, the node's with
        /// `node_fault`, and the node, which lets the client's key in; `None`
        /// when this host has no Python, which the test says.
        fn new(tag: &str, fault: &[&str], node_fault: &[&str]) -> Option<Road> {
            if !["python3", "python"].into_iter().any(|p| found(p, &["--version"])) {
                eprintln!("skipped: no Python for the stand-in proxy");
                return None;
            }
            let session = Session::start(tag);
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            let relay = runtime
                .block_on(podssh_iroh::test_relay::spawn_named(&session.home, NAME))
                .expect("an iroh relay on the loopback");
            let port = relay.url.port().expect("the relay's port");
            let start = session.home.join("start");
            let map = [format!("{NAME}=127.0.0.1:{port}")];
            let node_proxy = proxy(&session, "node", &map, node_fault, &start);
            let proxy = proxy(&session, "client", &map, fault, &start);
            // The client's key, made here, so that the node's allowlist holds it.
            let client_key = session.home.join("client.key");
            let place = podssh_iroh::keys::Place::File(client_key.clone());
            let key = podssh_iroh::keys::load(&place, &mut podssh_relay::session::OsEntropy).expect("a key");
            let allow = session.home.join("allow");
            let line = format!("{} the test's client\n", podssh_iroh::keys::fingerprint(&key.public()));
            std::fs::write(&allow, line).unwrap();
            let (url, cert) = (relay.url.to_string(), relay.cert.to_string_lossy().into_owned());
            let text = |p: &std::path::Path| p.to_string_lossy().into_owned();
            let args = [
                "node".to_string(),
                "m6i".into(),
                format!("127.0.0.1:{}", session.port),
                "--iroh".into(),
                "--iroh-relay".into(),
                url.clone(),
                "--ca-file".into(),
                cert.clone(),
                "--iroh-allow".into(),
                text(&allow),
                "--iroh-key".into(),
                text(&session.home.join("node.key")),
            ];
            let mut cmd = session.command(&args);
            cmd.env("HTTPS_PROXY", &node_proxy).env("PODSSH_IROH_UDP", "off");
            let mut node = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
            let lines = lines_of(&mut node);
            session.keep(node);
            let line = wait_for(&lines, "ticket iroh:").expect("the node's ticket");
            let ticket = line[line.find("iroh:").unwrap()..].trim().to_string();
            Some(Road {
                session,
                _relay: relay,
                _runtime: runtime,
                url,
                cert,
                proxy,
                start,
                ticket,
                client_key: text(&client_key),
            })
        }

        /// 20 MiB up and back to the node's TARGET: the client's stderr and
        /// log of the client's proxy, and the time that it took.
        fn carry(&self) -> (String, String, Duration) {
            let mut args = vec!["ssh".to_string()];
            args.extend(self.session.common());
            args.extend([
                "--ca-file".to_string(),
                self.cert.clone(),
                "--iroh-relay".into(),
                self.url.clone(),
                "--iroh-key".into(),
                self.client_key.clone(),
                format!("tester@{}", self.ticket),
                "echo".into(),
            ]);
            let mut cmd = self.session.command(&args);
            cmd.env("HTTPS_PROXY", &self.proxy).env("PODSSH_IROH_UDP", "off");
            let child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            let started = Instant::now();
            let (code, whole, err) = echo(child, &self.start);
            let took = started.elapsed();
            assert_eq!(code, 0, "{err}");
            assert!(whole, "the bytes came back changed: {err}");
            let lost = err.matches("resuming the session").count();
            eprintln!("exit {code} in {} s, {lost} loss of the layer", took.as_secs());
            assert!(lost <= 1 && err.matches("the session resumed").count() == lost, "a loss, and its resume: {err}");
            let log = std::fs::read_to_string(self.session.home.join("proxy-client.log")).unwrap_or_default();
            (err, log, took)
        }
    }

    #[test]
    #[ignore = "M6's exit: a stopped relay host, on the iroh road"]
    fn the_iroh_road_survives_a_stopped_relay_host() {
        let Some(road) = Road::new("iroh-stop", &["--stop-after", "0"], &["--stop-after", "0"]) else { return };
        let (_, log, _) = road.carry();
        assert!(log.contains("ended with RST"), "the relay host stopped: {log}");
    }

    #[test]
    #[ignore = "M6's exit: a new address of the client, on the iroh road (about a minute)"]
    fn the_iroh_road_survives_a_new_address() {
        let Some(road) = Road::new("iroh-move", &["--move", "0:127.0.0.2"], &[]) else { return };
        let (_, log, _) = road.carry();
        assert!(log.contains("from 127.0.0.2"), "the client came back from its new address: {log}");
    }

    #[test]
    #[ignore = "M6's exit: a stall of 3 minutes, on the iroh road (about 4 minutes)"]
    fn the_iroh_road_survives_a_stall_of_3_minutes() {
        let Some(road) = Road::new("iroh-pause", &["--pause", "0:180"], &[]) else { return };
        let (_, _, took) = road.carry();
        assert!(took > Duration::from_secs(170), "the stall held the bytes: {} s", took.as_secs());
    }

    /// The control of the stand-ins: with no fault, the session carries its
    /// bytes, and says nothing of a loss.
    #[test]
    #[ignore = "M6's exit, the control of the iroh road's stand-ins: a few seconds"]
    fn with_no_fault_the_iroh_road_carries_the_session() {
        let Some(road) = Road::new("iroh-none", &[], &[]) else { return };
        let (err, log, _) = road.carry();
        assert!(!err.contains("resuming the session"), "{err}");
        assert!(log.contains(&format!("CONNECT {NAME}:")), "the road passed the proxy: {log}");
    }
}
