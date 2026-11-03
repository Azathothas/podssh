//! The direct road after a relay that reached no IPv6 host (T-253), on this
//! machine's loopback. `scripts/fake-relay.py` in its mode `v6close` is the
//! built-in relay, reached through `scripts/fake-proxy.py`, whose map sends
//! the relay's name to it, as a run that names no relay reaches the default
//! relay. The stand-in opens a session to an IPv6 target and closes it at
//! the client's first bytes with `1011 target closed before sending
//! anything`, as the default relay did on 2026-10-08. podssh then tries the
//! direct road once, with its line, also under `-6`, and logs in at the
//! test's SSH server through a door on `::1`; with `PODSSH_DIRECT=no` it ends
//! with the note that names the roads with IPv6; an IPv4 target goes through
//! the stand-in. A host with no IPv6 loopback, no Python or no openssl says
//! so, and the test does not run there.

mod ssh_harness;
mod throughput_harness;

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ssh_harness::GREETING;
use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(90);
/// The words of the line before the direct road's dial: not the try of the
/// relay once more (T-025), whose line says "podssh tries once more".
const FELL_BACK: &str = "directly (PODSSH_DIRECT=no turns this off";

/// What a run of these tests needs: the session, with its SSH server; the
/// stand-in proxy's port and its log; the stand-in's CA; and the port of the
/// door on `::1`.
struct Place {
    session: Session,
    proxy: u16,
    proxy_log: std::path::PathBuf,
    ca: String,
    door: u16,
}

/// The place, or `None`, with why, where this host cannot give it.
fn place(tag: &str) -> Option<Place> {
    let session = Session::start(tag);
    let door = door_on_v6(session.port)?;
    let cell = match Cell::fake_relay_mode(&session, "v6close", "the stand-in relay that reaches no IPv6 host") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let after = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone());
    let (relay, ca) = (after("--relay-host")?, after("--ca-file")?);
    let relay_port = relay.rsplit_once(':')?.1.to_string();
    let proxy_log = session.home.join("proxy.log");
    let proxy = stand_in_proxy(&session, &relay_port, &proxy_log)?;
    Some(Place { session, proxy, proxy_log, ca, door })
}

/// A door on `::1` to the test's SSH server on 127.0.0.1:`port`, each
/// connection copied both ways: its port, or `None` on a host with no IPv6
/// loopback.
fn door_on_v6(port: u16) -> Option<u16> {
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("did not run: this host has no IPv6 loopback ({e})");
            return None;
        }
    };
    let door = listener.local_addr().ok()?.port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(outer) = conn else { return };
            let Ok(inner) = TcpStream::connect(("127.0.0.1", port)) else { continue };
            let (Ok(outer_too), Ok(inner_too)) = (outer.try_clone(), inner.try_clone()) else { continue };
            for (mut from, mut to) in [(outer, inner), (inner_too, outer_too)] {
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut from, &mut to);
                    let _ = to.shutdown(std::net::Shutdown::Write);
                });
            }
        }
    });
    Some(door)
}

/// `scripts/fake-proxy.py`, whose map sends the built-in relay's name to the
/// stand-in relay at `relay_port`, and refuses each other name: its port.
fn stand_in_proxy(session: &Session, relay_port: &str, log: &std::path::Path) -> Option<u16> {
    let python = ["python3", "python"].into_iter().find(|p| throughput_harness::found(p, &["--version"]))?;
    let port_file = session.home.join("proxy.port");
    let child = Command::new(python)
        .arg(throughput_harness::scripts().join("fake-proxy.py"))
        .arg("--port-file")
        .arg(&port_file)
        .arg("--log")
        .arg(log)
        .arg("--map")
        .arg(format!("{}=127.0.0.1:{relay_port}", podssh_relay::relay::DEFAULT_RELAY_HOST))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    session.keep(child);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            return Some(port);
        }
        if Instant::now() > deadline {
            eprintln!("did not run: the stand-in proxy did not start within 30 s");
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `podssh ssh ARGS` with no relay named, through the stand-in proxy, with
/// the stand-in's CA, and none of the machine's settings: its code, stdout
/// and stderr, within the limit.
fn ssh(at: &Place, args: &[&str], set: &[(&str, &str)]) -> (i32, String, String) {
    let mut words = vec!["ssh".to_string()];
    words.extend(at.session.common());
    words.extend(["--ca-file".to_string(), at.ca.clone()]);
    words.extend(args.iter().map(|a| a.to_string()));
    let mut cmd = throughput_harness::without_proxy(at.session.command(&words));
    cmd.env("HTTPS_PROXY", format!("http://127.0.0.1:{}", at.proxy));
    // The direct road alone after the relay: no forwarder of another product.
    cmd.env("PODSSH_SETTINGS", "none").env("PODSSH_FORWARDER_FALLBACK", "no");
    for name in ["PODSSH_RELAY", "PODSSH_RELAY_TOKEN", "PODSSH_RELAY_ADDR", "PODSSH_DIRECT", "PODSSH_MPTCP"] {
        cmd.env_remove(name);
    }
    cmd.env_remove("SSL_CERT_FILE").envs(set.iter().copied());
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh");
    let (mut stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status.code().unwrap_or(-1);
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh ssh {args:?} still ran after {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (code, out.join().unwrap(), err.join().unwrap())
}

#[test]
fn an_ipv6_target_that_the_relay_closed_at_once_falls_back_to_the_direct_road() {
    let Some(at) = place("v6-falls-back") else { return };
    let door = at.door.to_string();
    let (rc, out, err) = ssh(&at, &["-v", "-p", &door, "tester@::1", "greet"], &[]);
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the direct road");
    let said = err.lines().find(|l| l.contains(FELL_BACK)).unwrap_or_else(|| panic!("no fallback line: {err}"));
    assert!(said.contains("closed it before any byte came, as a relay with no IPv6 route out does"), "{said}");
    assert!(said.contains(&format!("podssh tries [::1]:{door} directly")), "{said}");
    assert!(err.contains("the direct road carried the session"), "-v names the road: {err}");
    // The run took the built-in relay, through the proxy, before the direct road.
    let asked = std::fs::read_to_string(&at.proxy_log).unwrap_or_default();
    let builtin = format!("CONNECT {}:443", podssh_relay::relay::DEFAULT_RELAY_HOST);
    assert!(asked.lines().any(|l| l.starts_with("200 ") && l.contains(&builtin)), "{asked}");
}

#[test]
fn under_6_too_the_direct_road_follows_a_relay_that_reached_no_ipv6_host() {
    let Some(at) = place("v6-under-6") else { return };
    let door = at.door.to_string();
    let (rc, out, err) = ssh(&at, &["-6", "-p", &door, "tester@::1", "greet"], &[]);
    assert_eq!(rc, 0, "-6 fell back: stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING);
    assert!(err.contains(&format!("podssh tries [::1]:{door} directly")), "{err}");
    // A name under -6: the stand-in closes it by ?family=6, and the direct
    // road dials the name's IPv6 addresses alone, where it has one here.
    let named = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 22)).map(|mut a| a.any(|a| a.is_ipv6()));
    if named.unwrap_or(false) {
        let (rc, out, err) = ssh(&at, &["-6", "-p", &door, "tester@localhost", "greet"], &[]);
        assert_eq!((rc, out.as_str()), (0, GREETING), "a name under -6: {err}");
        assert!(err.contains(&format!("podssh tries localhost:{door} directly")), "{err}");
    } else {
        eprintln!("did not run: localhost has no IPv6 address here, for a name under -6");
    }
}

#[test]
fn with_podssh_direct_no_the_note_names_the_roads_and_ipv4_goes_through_the_stand_in() {
    let Some(at) = place("v6-no-direct") else { return };
    let door = at.door.to_string();
    let (rc, _, err) = ssh(&at, &["-p", &door, "tester@::1", "true"], &[("PODSSH_DIRECT", "no")]);
    assert_eq!(rc, 255, "{err}");
    assert!(!err.contains(FELL_BACK), "PODSSH_DIRECT=no fell back: {err}");
    assert!(err.contains("the relay has no IPv6 route out") && err.contains("podssh relay serve"), "{err}");
    // The control: the stand-in carries an IPv4 target, with no fallback.
    let port = at.session.port.to_string();
    let (rc, out, err) = ssh(&at, &["-v", "-p", &port, "tester@127.0.0.1", "greet"], &[]);
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    assert!(!err.contains(FELL_BACK), "an IPv4 target fell back: {err}");
}
