//! A rank in a session's background (T-608), as a process: `podssh ssh` on
//! the default list, whose hosts a stand-in HTTP CONNECT proxy of the test
//! carries to one stand-in relay (`scripts/fake-relay.py`) with a
//! certificate of the default relay's names, and Q89's waits shortened by
//! `PODSSH_RELAY_RANK_PACE`, which only a build with debug assertions reads.
//! The stand-in writes a line for each connect, with its query and its time,
//! and for the end of each session and each probe. With `RelayRank auto`,
//! the probes come one at a time, each with `?dial=lazy` and no target
//! dialed, none before the session opened and none after it ended; the next
//! session goes on with the hosts that the first one left, and a whole rank
//! makes no new one that day. Off by default, and a variable that is set
//! wins over the file's `auto`.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use crate::throughput_harness::{Cell, Session};

/// The test's waits, in place of 60 s and 10 s.
const DELAY_MS: i64 = 400;
const GAP_MS: i64 = 1200;
/// The bound on each wait of the test.
const WAIT: Duration = Duration::from_secs(60);

/// The default host, then its seed pool: the plan of a day's rank, as a
/// fresh cache gives it, each name with its port.
fn plan() -> Vec<String> {
    let seed = podssh_relay::pool::SEED.iter().copied();
    let hosts = std::iter::once(podssh_relay::relay::DEFAULT_RELAY_HOST).chain(seed);
    hosts.take(podssh_relay::rank_auto::MOST).map(|h| format!("{h}:443")).collect()
}

/// A stand-in HTTP CONNECT proxy: each tunnel, whatever host it names, to
/// `127.0.0.1:relay`, so that each host of the default list is the stand-in.
fn proxy_to(relay: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for client in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || tunnel(client, relay));
        }
    });
    port
}

fn tunnel(client: TcpStream, relay: u16) {
    let _ = client.set_read_timeout(Some(super::LIMIT));
    let Ok(mut writer) = client.try_clone() else { return };
    // The reader keeps what came after the head, for the tunnel.
    let mut reader = BufReader::new(client);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(n) if n > 0 && line != "\r\n" => continue,
            _ => break,
        }
    }
    let Ok(far) = TcpStream::connect(("127.0.0.1", relay)) else { return };
    let Ok(mut far_writer) = far.try_clone() else { return };
    if writer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return;
    }
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut far_writer);
        let _ = far_writer.shutdown(std::net::Shutdown::Write);
    });
    let mut far = far;
    let _ = std::io::copy(&mut far, &mut writer);
    let _ = writer.shutdown(std::net::Shutdown::Write);
}

/// The stand-in relay and the proxy in front of it: the file of its events,
/// the CA of its certificate, and the proxy's port; none, with why, where
/// this host has no Python or no openssl.
fn stand_ins(s: &Session) -> Option<(PathBuf, PathBuf, u16)> {
    let (relay, events) = match Cell::fake_relay_default(s, "normal") {
        Ok(found) => found,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    Some((events, s.home.join("fake-relay").join("ca.pem"), proxy_to(relay)))
}

/// A settings file of the test's, `RelayRank auto`, that only its owner may
/// change, as podssh reads none other: its path.
fn settings_auto(s: &Session) -> String {
    let settings = s.home.join("settings");
    std::fs::write(&settings, "# podssh\nRelayRank auto\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    settings.display().to_string()
}

/// `podssh ARGS` through the test's proxy, with the test's waits, no
/// settings file but those of `set`, and none of this host's relay settings.
fn command(s: &Session, args: &[String], proxy: u16, set: &[(&str, &str)]) -> Command {
    let mut cmd = super::podssh(&s.home, args);
    for name in ["PODSSH_RELAY_ADDR", "PODSSH_RELAY_RANK", "PODSSH_RELAY_FAILOVER", "PODSSH_CACHE_DIR"] {
        cmd.env_remove(name);
    }
    cmd.env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy}")).env("NO_PROXY", "").env("no_proxy", "");
    // The relay's road alone: neither the direct road nor a forwarder after it.
    cmd.env("PODSSH_DIRECT", "no").env("PODSSH_FORWARDER_FALLBACK", "no").env("PODSSH_SETTINGS", "none");
    cmd.env(podssh_relay::rank_auto::PACE_ENV, format!("{DELAY_MS},{GAP_MS}"));
    cmd.envs(set.iter().copied());
    cmd
}

/// A session of `podssh ssh ... sink` on the default list, its stdin held
/// open by the test: the session ends when the test closes it.
struct Run {
    child: Child,
    out: Receiver<String>,
    err: std::thread::JoinHandle<String>,
}

impl Run {
    fn start(s: &Session, ca: &Path, proxy: u16, set: &[(&str, &str)]) -> Run {
        let mut args = vec!["ssh".to_string()];
        args.extend(s.common());
        args.extend(["--ca-file".to_string(), ca.display().to_string(), "-p".into(), s.port.to_string()]);
        args.extend(["tester@127.0.0.1".to_string(), "sink".into()]);
        let mut child = command(s, &args, proxy, set).stdin(Stdio::piped()).spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, out) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let mut stderr = child.stderr.take().unwrap();
        let err = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            text
        });
        Run { child, out, err }
    }

    /// Wait for the sink's `R`: the session opened, and its command runs.
    fn opened(mut self) -> Run {
        match self.out.recv_timeout(WAIT) {
            Ok(line) if line.trim() == "R" => self,
            other => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("the session did not open: {other:?}; {}", self.err.join().unwrap_or_default());
            }
        }
    }

    /// End the session: its stdin closes, and the sink ends with its count.
    fn end(mut self) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the session did not end within {WAIT:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let err = self.err.join().unwrap_or_default();
        assert_eq!(status.code(), Some(0), "{err}");
    }
}

/// The stand-in's lines so far, but a last one not yet whole.
fn events(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let whole = text.rfind('\n').map_or("", |at| &text[..at]);
    whole.lines().map(str::to_string).collect()
}

/// The lines after the first `from`, once `done` holds for them.
fn wait_lines(path: &Path, from: usize, what: &str, done: impl Fn(&[String]) -> bool) -> Vec<String> {
    let deadline = Instant::now() + WAIT;
    loop {
        let new = events(path).get(from..).unwrap_or_default().to_vec();
        if done(&new) {
            return new;
        }
        assert!(Instant::now() < deadline, "no {what} within {WAIT:?}: {new:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether a line is of the session's own connection, to the test's server.
fn own(line: &str) -> bool {
    line.contains(" /connect/127.0.0.1/")
}

/// The lines of a session, once the end of each of its connections, those
/// of its race too, is among them.
fn session_lines(path: &Path, from: usize) -> Vec<String> {
    let whole = |new: &[String]| {
        let count = |word: &str| new.iter().filter(|l| l.starts_with(word) && own(l)).count();
        count("connect ") > 0 && count("ended ") == count("connect ")
    };
    wait_lines(path, from, "end of the session", whole)
}

/// The probes that ended, among `lines`.
fn ended_probes(lines: &[String]) -> usize {
    lines.iter().filter(|l| l.starts_with("lazy closed ")).count()
}

/// The time of an event, in ms of the stand-in's clock.
fn ms(line: &str) -> i64 {
    line.split_whitespace().nth(1).and_then(|m| m.parse().ok()).unwrap_or_else(|| panic!("no time in {line:?}"))
}

/// The probes of one session's lines, checked: each with `?dial=lazy`, and
/// no target dialed; one at a time; the first a delay after the session's
/// own connect, each a gap after the one before; none after the session's
/// end. How many there were.
fn probes_of(lines: &[String]) -> usize {
    let opened = lines.iter().find(|l| l.starts_with("connect ") && own(l)).map(|l| ms(l));
    let opened = opened.unwrap_or_else(|| panic!("no session: {lines:?}"));
    // The last end: a host of the race that opened too late was closed first.
    // Its place in the log, as a probe and the end can share a millisecond.
    let ended = lines.iter().rposition(|l| l.starts_with("ended ") && own(l));
    let ended = ended.unwrap_or_else(|| panic!("the session did not end: {lines:?}"));
    let (mut probes, mut open) = (Vec::new(), false);
    for (at, line) in lines.iter().enumerate() {
        if line.starts_with("connect ") && line.contains("dial=lazy") {
            assert!(line.ends_with(" /connect/github.com/22?dial=lazy"), "{line}");
            assert!(!open, "two probes at once: {lines:?}");
            assert!(at < ended, "a probe after the session ended: {lines:?}");
            open = true;
            probes.push(ms(line));
        } else if line.starts_with("lazy closed ") {
            open = false;
        }
        assert!(!line.starts_with("lazy dial "), "a probe's target was dialed: {lines:?}");
    }
    if let Some(first) = probes.first() {
        assert!(first - opened >= DELAY_MS, "a probe {} ms after the open: {lines:?}", first - opened);
    }
    for pair in probes.windows(2) {
        assert!(pair[1] - pair[0] >= GAP_MS - 200, "{} ms between two probes: {lines:?}", pair[1] - pair[0]);
    }
    probes.len()
}

/// The rank's file, in the test's own cache.
fn rank_file(home: &Path) -> serde_json::Value {
    let files = super::found(home, "relay-rank.json");
    assert_eq!(files.len(), 1, "{files:?}");
    serde_json::from_str(&std::fs::read_to_string(&files[0]).unwrap()).unwrap()
}

/// The hosts that a rank holds, by name.
fn hosts_of(rank: &serde_json::Value) -> BTreeSet<String> {
    let hosts = rank["hosts"].as_array().cloned().unwrap_or_default();
    hosts.iter().filter_map(|h| h["host"].as_str().map(str::to_string)).collect()
}

#[test]
fn background_probes_come_one_at_a_time_inside_the_session_and_once_a_day() {
    let s = Session::start("rank-background");
    let Some((path, ca, proxy)) = stand_ins(&s) else { return };
    let file = settings_auto(&s);
    let with = [("PODSSH_SETTINGS", file.as_str())];
    let plan = plan();

    // The first session ends after three probes: what it measured is kept.
    let before = events(&path).len();
    let run = Run::start(&s, &ca, proxy, &with).opened();
    wait_lines(&path, before, "three probes", |new| ended_probes(new) >= 3);
    run.end();
    let lines = session_lines(&path, before);
    let first = probes_of(&lines);
    assert!((3..plan.len()).contains(&first), "{lines:?}");
    let kept = rank_file(&s.home);
    assert_eq!((kept["source"].as_str(), kept["partial"].as_bool()), (Some("background"), Some(true)), "{kept}");
    let measured = hosts_of(&kept);
    // A probe that the session's end dropped is not kept.
    assert!(first == measured.len() || first == measured.len() + 1, "{first} probes: {kept}");
    assert_eq!(measured, plan[..measured.len()].iter().cloned().collect::<BTreeSet<_>>(), "the plan's first: {kept}");
    let egress = kept["egress"].as_str().unwrap_or_default();
    assert!(egress.len() == 16 && egress.chars().all(|c| c.is_ascii_hexdigit()), "the proxy's digest: {kept}");

    // status and relay rank --cached name it, with no connection.
    let mut status = command(&s, &["status".to_string()], proxy, &with);
    status.env("PODSSH_OFFLINE", "1");
    let doc: serde_json::Value = serde_json::from_slice(&super::ran(status).stdout).expect("one JSON object");
    let (rank, auto) = (&doc["relay_rank"], &doc["relay_rank_auto"]);
    assert_eq!((rank["source"].as_str(), rank["holds"].as_bool()), (Some("background"), Some(true)), "{rank}");
    assert_eq!((auto["asked"].as_bool(), auto["by"].as_str()), (Some(true), Some("RelayRank auto")), "{auto}");
    assert!(auto["last_age_s"].as_i64().is_some() && auto["partial"] == true, "{auto}");
    assert_eq!(doc["relay_order"], "rank");
    let cached = super::ran(command(&s, &super::words(&["relay", "rank", "--cached"]), proxy, &with));
    let said = super::text(&cached.stdout);
    assert!(said.contains("in a session's background, of part of its hosts so far, for this egress"), "{said}");

    // The next session goes on with the hosts that the first one left, and
    // stops at the plan's end.
    let before = events(&path).len();
    let left = plan.len() - measured.len();
    let run = Run::start(&s, &ca, proxy, &with).opened();
    wait_lines(&path, before, "the plan's last probe", |new| ended_probes(new) >= left);
    std::thread::sleep(Duration::from_millis(2 * GAP_MS as u64));
    run.end();
    let lines = session_lines(&path, before);
    assert_eq!(probes_of(&lines), left, "each host once: {lines:?}");
    let kept = rank_file(&s.home);
    assert_eq!(kept["partial"].as_bool(), Some(false), "{kept}");
    assert_eq!(hosts_of(&kept), plan.iter().cloned().collect::<BTreeSet<_>>(), "{kept}");
    let each = kept["hosts"].as_array().cloned().unwrap_or_default();
    assert!(each.iter().all(|h| h["tries"] == 1 && h["opened"] == 1), "one probe of each, opened: {kept}");

    // A whole rank that holds makes no new one: once a day.
    let before = events(&path).len();
    let run = Run::start(&s, &ca, proxy, &with).opened();
    std::thread::sleep(Duration::from_millis((DELAY_MS + 2 * GAP_MS) as u64));
    run.end();
    let lines = session_lines(&path, before);
    assert_eq!(probes_of(&lines), 0, "{lines:?}");
}

#[test]
fn background_rank_makes_no_probe_unless_asked() {
    let s = Session::start("rank-background-off");
    let Some((path, ca, proxy)) = stand_ins(&s) else { return };
    let file = settings_auto(&s);
    // Nothing asks; then the file's auto, below a variable that says yes.
    let cases: [Vec<(&str, &str)>; 2] =
        [Vec::new(), vec![("PODSSH_SETTINGS", file.as_str()), ("PODSSH_RELAY_RANK", "yes")]];
    for set in cases {
        let before = events(&path).len();
        let run = Run::start(&s, &ca, proxy, &set).opened();
        std::thread::sleep(Duration::from_millis((DELAY_MS + 2 * GAP_MS) as u64));
        run.end();
        let lines = session_lines(&path, before);
        assert_eq!(probes_of(&lines), 0, "{set:?}: {lines:?}");
    }
    // The races' samples are kept, and no rank.
    let kept = rank_file(&s.home);
    assert!(kept["hosts"].as_array().is_none_or(|h| h.is_empty()), "{kept}");
    assert!(kept["samples"].as_object().is_some_and(|m| !m.is_empty()), "{kept}");
}
