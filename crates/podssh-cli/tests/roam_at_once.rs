//! Roam at once (T-305): a spare link beside a silent one. `podssh ssh -v
//! node://` carries 20 MiB up and back (`echo` of the tests' SSH server)
//! through the stand-in proxy and relay on the loopback; when 8 MiB are
//! written, the proxy's `--move` leaves the open tunnels silent, with no
//! RST, and each new one leaves from 127.0.0.2, as a client whose address
//! changed. Pass: the session resumes within 10 s of the move, where the
//! heartbeat alone finds the link dead after 30 s; a link that stalls for
//! 5 s (`--pause`) and recovers keeps the session with no resume. With
//! `PODSSH_SPARE_LINKS=no` in the environment of the run, the planted
//! client with no spare link, the first check fails. The measurement of
//! item 1: the time from the move to "the session resumed", 5 runs with
//! no spare link and 5 with one, on the pair's road. On the iroh road, with
//! the feature `iroh-test`, a new address opens no spare link, as QUIC
//! carries the session across it by itself (the planted iroh road with
//! spare links fails it). Ignored, as each needs Python and openssl, and
//! some minutes:
//!
//! ```sh
//! cargo test -p podssh-cli --test roam_at_once -- --ignored --test-threads 1 --nocapture
//! cargo test -p podssh-cli --features iroh-test --test roam_at_once -- --ignored --test-threads 1 --nocapture
//! ```

mod ssh_harness;
mod stand_harness;
mod throughput_harness;

use std::process::Stdio;
use std::time::Duration;

use stand_harness::{echo, Echoed, Stand};

const MIB: usize = 1 << 20;
const BYTES: usize = 20 * MIB;
/// The fault starts when this much is written.
const TRIGGER: usize = 8 * MIB;
/// The words of a resume, and of a loss.
const RESUMED: &str = "the session resumed";
const LOST: &str = "resuming the session";
/// How soon a session resumes after a new address, with a spare link.
const AT_ONCE: Duration = Duration::from_secs(10);

/// 20 MiB through a node of the pair's road, with `fault` at the client's
/// proxy, and `spares` false for a client with no spare link.
fn through_the_pair(tag: &str, fault: &[&str], spares: bool) -> Option<Echoed> {
    let stand = Stand::new(tag, fault, &[])?;
    stand.node();
    let mut cmd = stand.command(&stand.ssh(&["-v"], "tester", "echo"));
    if !spares {
        cmd.env("PODSSH_SPARE_LINKS", "no");
    }
    let child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let ran = echo(child, &stand.start, BYTES, TRIGGER);
    assert_eq!(ran.code, 0, "{}", ran.err);
    assert!(ran.whole, "the bytes came back changed: {}", ran.err);
    Some(ran)
}

/// The time to the resume of `ran`, in seconds, for the measurement.
fn resumed_after(ran: &Echoed) -> f64 {
    ran.when(RESUMED).map_or(f64::NAN, |at| at.as_secs_f64())
}

#[test]
#[ignore = "T-305: a new address, on the pair's road (about a minute)"]
fn after_a_new_address_the_session_resumes_within_10_s() {
    let Some(ran) = through_the_pair("roam", &["--move", "0:127.0.0.2"], true) else { return };
    let resumed = ran.when(RESUMED).unwrap_or_else(|| panic!("no resume: {}", ran.err));
    eprintln!("the session resumed {:.1} s after the move", resumed.as_secs_f64());
    assert!(resumed < AT_ONCE, "the session resumed {resumed:?} after the move: {}", ran.err);
    assert!(ran.err.contains("a spare link opens beside it"), "-v says the spare link: {}", ran.err);
    assert_eq!(ran.err.matches(LOST).count(), 1, "one loss, and its resume: {}", ran.err);
}

#[test]
#[ignore = "T-305: a stall of 5 s, on the pair's road (about a minute)"]
fn a_link_that_stalls_for_5_s_keeps_the_session_with_no_resume() {
    let Some(ran) = through_the_pair("stall", &["--pause", "0:5"], true) else { return };
    assert!(!ran.err.contains(LOST), "the stall ended no link: {}", ran.err);
    // A spare that opened in the stall closed when the link spoke again.
    let spares = ran.err.matches("a spare link opens beside it").count();
    assert_eq!(ran.err.matches("the spare link closed").count(), spares, "{}", ran.err);
}

#[test]
#[ignore = "T-305, item 1: 5 runs with no spare link and 5 with one, on the pair's road (some minutes)"]
fn measure_the_time_to_resume_after_a_new_address_on_the_pair_s_road() {
    for spares in [false, true] {
        let mut times = Vec::new();
        for run in 0..5 {
            let tag = format!("measure-{spares}-{run}");
            let Some(ran) = through_the_pair(&tag, &["--move", "0:127.0.0.2"], spares) else { return };
            times.push(resumed_after(&ran));
        }
        let spare = if spares { "a spare link" } else { "no spare link" };
        eprintln!("the pair's road, {spare}: resumed after {times:.1?} s");
    }
}

/// The iroh road (T-162 to T-165), as `m6_exit.rs` sets it up: iroh's relay
/// server under a name that only the proxies resolve, and no direct path.
#[cfg(feature = "iroh-test")]
mod iroh {
    use std::process::Stdio;

    use super::{resumed_after, BYTES, TRIGGER};
    use crate::stand_harness::{echo, proxy, Echoed};
    use crate::throughput_harness::{found, lines_of, wait_for, without_proxy, Session};

    const NAME: &str = "relay-i.test";

    /// 20 MiB to a node of the iroh road, with `fault` at the client's
    /// proxy; `None` when this host has no Python.
    fn through_iroh(tag: &str, fault: &[&str]) -> Option<Echoed> {
        if !["python3", "python"].into_iter().any(|p| found(p, &["--version"])) {
            eprintln!("did not run: no Python for the stand-in proxy");
            return None;
        }
        let session = Session::start(tag);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let relay = runtime.block_on(podssh_iroh::test_relay::spawn_named(&session.home, NAME)).expect("an iroh relay");
        let port = relay.url.port().expect("the relay's port");
        let start = session.home.join("start");
        let map = [format!("{NAME}=127.0.0.1:{port}")];
        let node_proxy = proxy(&session, "node", &map, &[], &start);
        let client_proxy = proxy(&session, "client", &map, fault, &start);
        let client_key = session.home.join("client.key");
        let place = podssh_iroh::keys::Place::File(client_key.clone());
        let key = podssh_iroh::keys::load(&place, &mut podssh_relay::session::OsEntropy).expect("a key");
        let allow = session.home.join("allow");
        let line = format!("{} the test's client\n", podssh_iroh::keys::fingerprint(&key.public()));
        std::fs::write(&allow, line).unwrap();
        let (url, cert) = (relay.url.to_string(), relay.cert.to_string_lossy().into_owned());
        let text = |p: &std::path::Path| p.to_string_lossy().into_owned();
        let target = format!("127.0.0.1:{}", session.port);
        let mut args = vec!["node".to_string(), "roam".into(), target, "--iroh".into(), "--iroh-relay".into()];
        args.extend([url.clone(), "--ca-file".into(), cert.clone(), "--iroh-allow".into(), text(&allow)]);
        args.extend(["--iroh-key".to_string(), text(&session.home.join("node.key"))]);
        let mut cmd = without_proxy(session.command(&args));
        cmd.env("HTTPS_PROXY", &node_proxy).env("PODSSH_IROH_UDP", "off");
        let mut node = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let lines = lines_of(&mut node);
        session.keep(node);
        let line = wait_for(&lines, "ticket iroh:").expect("the node's ticket");
        let ticket = line[line.find("iroh:").unwrap()..].trim().to_string();
        let mut args = vec!["ssh".to_string(), "-v".into()];
        args.extend(session.common());
        args.extend(["--ca-file".to_string(), cert, "--iroh-relay".into(), url, "--iroh-key".into()]);
        args.extend([text(&client_key), format!("tester@{ticket}"), "echo".into()]);
        let mut cmd = without_proxy(session.command(&args));
        cmd.env("HTTPS_PROXY", &client_proxy).env("PODSSH_IROH_UDP", "off");
        let child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let ran = echo(child, &start, BYTES, TRIGGER);
        // The processes end first, then the relay, then its runtime.
        drop(session);
        drop(relay);
        drop(runtime);
        assert_eq!(ran.code, 0, "{}", ran.err);
        assert!(ran.whole, "the bytes came back changed: {}", ran.err);
        Some(ran)
    }

    /// Item 1 measured the iroh road with spare links: 3 runs of 5 resumed
    /// the layer, 15.8 to 20.2 s after the move, where 5 runs of 5 with no
    /// spare link needed no resume. A spare there is a stream of the same
    /// QUIC connection, and comes no sooner than the old one.
    #[test]
    #[ignore = "T-305: a new address on the iroh road opens no spare link, 3 runs (some minutes)"]
    fn on_the_iroh_road_a_new_address_opens_no_spare_link_and_the_session_goes_on() {
        let mut times = Vec::new();
        for run in 0..3 {
            let tag = format!("iroh-{run}");
            let Some(ran) = through_iroh(&tag, &["--move", "0:127.0.0.2"]) else { return };
            assert!(!ran.err.contains("a spare link opens beside it"), "no spare link: {}", ran.err);
            times.push(resumed_after(&ran));
        }
        eprintln!("the iroh road: resumed after {times:.1?} s (NaN: no resume of the layer)");
    }
}
