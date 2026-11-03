//! The OpenTunnel road (T-530) against the stand-in server of
//! `opentunnel_stand_in`, over pipes: a node makes a tunnel, keeps it, binds
//! the CSR of its name and attaches its route; a client reaches it by TLS by
//! name, checked against the stand-in's CA, and a session of the resumable
//! layer carries 1 MiB to the node's echo and back; a node started again
//! keeps its tunnel and binds no new CSR, and one whose certificate was not
//! ready binds the same CSR again; the service's refusals are named: a wrong
//! token, a route that another bridge holds, the limit of tunnels with its
//! wait, a CSR of other names; a visitor of a route that no bridge holds is
//! closed; a bridge that the service ends is attached again, and the session
//! resumes on a new link. The end-to-end channel above the layer is the
//! command line's, in `podssh-cli`'s `opentunnel_road` (T-531). Planted
//! (`scripts/plants/t530-tunnel-not-kept.patch`): the node keeps no tunnel,
//! and the test of the second start fails, as it binds a new CSR.
#![cfg(feature = "opentunnel")]

mod cleanup;
mod opentunnel_stand_in;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentunnel_stand_in::keys::{NoWildcard, TestCredentials};
use opentunnel_stand_in::StandIn;
use podssh_relay::opentunnel::api::{Api, ApiError};
use podssh_relay::opentunnel::bridge::{self, Failed};
use podssh_relay::opentunnel::{self, far, Dialer, Name, Store};
use podssh_relay::session::resume::Note;
use podssh_relay::session::Settings;
use podssh_ws::Trust;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::Instant;

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(90);
/// The replay buffers that a node keeps, at most, as a node of the CLI does.
const BUDGET: usize = 64 << 20;

/// The lines of one end, kept for the test, and on stderr.
#[derive(Clone, Default)]
struct Said(Arc<Mutex<Vec<String>>>);

impl Said {
    fn say(&self, who: &'static str) -> opentunnel::Say {
        let lines = self.0.clone();
        Arc::new(move |line: String| {
            eprintln!("{who}: {line}");
            lines.lock().unwrap().push(line);
        })
    }

    fn any(&self, needle: &str) -> bool {
        self.0.lock().unwrap().iter().any(|line| line.contains(needle))
    }
}

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-opentunnel-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// The stand-in's API, its retries hurried.
fn api(stand_in: &Arc<StandIn>) -> Api {
    Api::new(StandIn::service(), stand_in.api()).hurried(100)
}

fn store(dir: &std::path::Path, label: &str) -> Store {
    Store::in_dirs(vec![dir.to_path_buf()], vec![dir.to_path_buf()], &StandIn::service(), label)
}

/// The trust of the stand-in's CA, which issues each tunnel's leaf.
fn trust(stand_in: &StandIn, dir: &std::path::Path) -> Trust {
    let path = dir.join("ca.pem");
    std::fs::write(&path, &stand_in.ca.pem).unwrap();
    Trust::File(path)
}

/// An echo of each byte, as a node's target.
async fn echo() -> Result<DuplexStream, String> {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(theirs);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Ok(ours)
}

/// Bytes that a seed fixes (xorshift64*).
fn bytes(size: usize, mut seed: u64) -> Vec<u8> {
    (0..size)
        .map(|_| {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            (seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// Until `check` holds, within the limit.
async fn until(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + LIMIT;
    while !check() {
        assert!(Instant::now() < deadline, "not in time: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A node of the stand-in, online and serving an echo, with its name.
async fn serving(
    stand_in: &Arc<StandIn>,
    dir: &std::path::Path,
    said: &Said,
) -> (String, tokio::task::JoinHandle<String>) {
    let (node, provisioned) = far::online(api(stand_in), store(dir, "lab"), &TestCredentials, said.say("node"))
        .await
        .expect("the node's tunnel");
    assert!(provisioned.record.ready());
    let name = node.name();
    let task = tokio::spawn(far::serve(node, Settings::default(), BUDGET, echo));
    until("the node's bridge attaches", || stand_in.bridges() == 1).await;
    (name, task)
}

/// 1 MiB to the node's echo and back in a session of the layer; when `cut`
/// is given, each bridge ends once a third came back. The session's notes.
async fn echo_mib(dialer: &Dialer, cut: Option<&StandIn>) -> Vec<Note> {
    let notes = Mutex::new(Vec::new());
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out = bytes(MIB, 3);
    let want = Sha256::digest(&out).to_vec();
    let carrying = Box::pin(opentunnel::carry(dialer, app, Settings::default(), |note: Note| {
        notes.lock().unwrap().push(note);
    }));
    let cut_done = AtomicBool::new(false);
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let writing = async { writer.write_all(&out).await.expect("the layer takes the bytes") };
        let reading = async {
            let (mut back, mut buf) = (Vec::with_capacity(out.len()), vec![0u8; 64 * 1024]);
            while back.len() < out.len() {
                let n = reader.read(&mut buf).await.expect("the echo");
                assert!(n > 0, "the session ended after {} bytes", back.len());
                back.extend_from_slice(&buf[..n]);
                if let Some(stand_in) = cut.filter(|_| back.len() >= out.len() / 3) {
                    if !cut_done.swap(true, Ordering::SeqCst) {
                        stand_in.cut_bridges();
                    }
                }
            }
            back
        };
        let ((), back) = tokio::join!(writing, reading);
        drop((reader, writer));
        back
    };
    let (carried, back) =
        tokio::time::timeout(LIMIT, async { tokio::join!(carrying, using) }).await.expect("the session ended in time");
    carried.expect("the session");
    assert_eq!(Sha256::digest(&back).to_vec(), want, "each byte came back once, in order");
    notes.into_inner().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_makes_a_tunnel_and_a_client_echoes_one_mib_by_tls_by_name() {
    let (stand_in, dir, said) = (StandIn::new(), scratch("mib"), Said::default());
    let (name, task) = serving(&stand_in, &dir, &said).await;
    assert_eq!(stand_in.created.load(Ordering::SeqCst), 1, "one tunnel");
    assert_eq!(stand_in.new_csrs.load(Ordering::SeqCst), 1, "one CSR");
    let name = Name::parse(&name).expect("the node's name");
    assert!(stand_in.hostnames().contains(&name.hostname), "the route is under the tunnel's name: {name}");
    assert_eq!(name.route.len(), 26, "a random route: {name}");
    let kept = store(&dir, "lab").load(&StandIn::service()).expect("the tunnel is kept");
    assert!(kept.ready() && kept.name() == name.to_string());
    let dialer = Dialer::new(name, stand_in.visit(), trust(&stand_in, &dir), said.say("client"));
    echo_mib(&dialer, None).await;
    assert!(stand_in.opens.load(Ordering::SeqCst) >= 1);
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_started_again_keeps_its_tunnel_and_binds_no_new_csr() {
    let (stand_in, dir, said) = (StandIn::new(), scratch("again"), Said::default());
    let (first, made) =
        far::online(api(&stand_in), store(&dir, "lab"), &TestCredentials, said.say("node")).await.unwrap();
    assert!(made.made && made.new_csr);
    let (second, kept) =
        far::online(api(&stand_in), store(&dir, "lab"), &TestCredentials, said.say("node")).await.unwrap();
    assert!(!kept.made && !kept.new_csr, "the second start made or bound nothing new");
    assert_eq!(second.name(), first.name(), "the same name");
    assert_eq!(stand_in.created.load(Ordering::SeqCst), 1);
    assert_eq!(stand_in.new_csrs.load(Ordering::SeqCst), 1, "no new CSR: the service counts 5 a day");
    // A start that stopped before the certificate was ready binds the same
    // CSR again, which counts against no limit.
    let mut pending = kept.record.clone();
    (pending.certificate, pending.chain, pending.expiry) = (None, None, None);
    store(&dir, "lab").save(&pending).unwrap();
    let (third, resumed) =
        far::online(api(&stand_in), store(&dir, "lab"), &TestCredentials, said.say("node")).await.unwrap();
    assert!(!resumed.made && !resumed.new_csr && resumed.record.ready());
    assert_eq!(third.name(), first.name());
    assert_eq!(stand_in.new_csrs.load(Ordering::SeqCst), 1);
    assert_eq!(stand_in.same_csrs.load(Ordering::SeqCst), 1, "the same CSR, bound again");
    assert!(said.any("resuming the tunnel"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_token_is_named_and_a_tunnel_that_refuses_the_kept_one_is_made_again() {
    let (stand_in, dir, said) = (StandIn::new(), scratch("token"), Said::default());
    let (_, made) = far::online(api(&stand_in), store(&dir, "lab"), &TestCredentials, said.say("node")).await.unwrap();
    let id = made.record.id.clone();
    let refused = api(&stand_in).certificate("wrong-token", &id).await.expect_err("a wrong token is refused");
    assert!(matches!(refused, ApiError::Refused { status: 401, .. }), "{refused}");
    assert!(refused.to_string().contains("UnauthorizedError") && !refused.to_string().contains("wrong-token"));
    let routes = vec![made.record.route.clone()];
    let failed = bridge::attach(&api(&stand_in), &id, "wrong-token", &routes).await.expect_err("bad_token");
    assert!(matches!(&failed, Failed::Fatal(why) if why.contains("bad_token")), "{failed}");
    let mut wrong = made.record.clone();
    wrong.token = zeroize::Zeroizing::new("wrong-token".into());
    store(&dir, "lab").save(&wrong).unwrap();
    let (_, again) = far::online(api(&stand_in), store(&dir, "lab"), &TestCredentials, said.say("node")).await.unwrap();
    assert!(again.made && again.record.id != id, "a new tunnel");
    assert!(said.any("no longer knows the tunnel"), "the start said why");
    assert_eq!(stand_in.created.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_that_another_bridge_holds_is_a_conflict_and_a_visitor_of_no_route_is_closed() {
    let (stand_in, dir, said) = (StandIn::new(), scratch("route"), Said::default());
    let (name, task) = serving(&stand_in, &dir, &said).await;
    let record = store(&dir, "lab").load(&StandIn::service()).unwrap();
    let routes = vec![record.route.clone()];
    let failed = bridge::attach(&api(&stand_in), &record.id, &record.token, &routes).await.expect_err("held");
    assert!(matches!(&failed, Failed::Again(why) if why.contains("route_conflict")), "{failed}");
    let other = Name { route: "other".into(), hostname: Name::parse(&name).unwrap().hostname };
    let dialer = Dialer::new(other, stand_in.visit(), trust(&stand_in, &dir), said.say("client"));
    let why = dialer.link().await.expect_err("no bridge holds the route");
    assert!(why.contains("no node holds the name"), "{why}");
    assert!(stand_in.visitors_closed.load(Ordering::SeqCst) >= 1);
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_service_s_limit_of_tunnels_is_said_at_once_with_its_wait() {
    let (stand_in, dir, said) = (StandIn::new(), scratch("limit"), Said::default());
    stand_in.refuse_creates.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let why = far::online(api(&stand_in), store(&dir, "lab"), &TestCredentials, said.say("node"))
        .await
        .err()
        .expect("the limit refuses the tunnel");
    assert!(why.contains("429 (RateLimitedError)") && why.contains("Retry-After: 1800 s"), "{why}");
    assert!(started.elapsed() < Duration::from_secs(5), "no retry waits for a limit of half an hour");
    assert_eq!(stand_in.created.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_csr_of_other_names_than_the_tunnel_s_is_given_up_and_said() {
    let (stand_in, dir, said) = (StandIn::new(), scratch("csr"), Said::default());
    let why = far::online(api(&stand_in), store(&dir, "lab"), &NoWildcard, said.say("node"))
        .await
        .err()
        .expect("a CSR with no wildcard");
    assert!(why.contains("gave up the certificate") && why.contains("other names"), "{why}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridge_that_the_service_ends_attaches_again_and_the_session_resumes() {
    let (stand_in, dir, said) = (StandIn::new(), scratch("cut"), Said::default());
    let (name, task) = serving(&stand_in, &dir, &said).await;
    let dialer = Dialer::new(Name::parse(&name).unwrap(), stand_in.visit(), trust(&stand_in, &dir), said.say("client"));
    let notes = echo_mib(&dialer, Some(&stand_in)).await;
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "a resume: {notes:?}");
    assert!(stand_in.attaches.load(Ordering::SeqCst) >= 2, "the node attached again");
    assert!(said.any("the bridge to OpenTunnel ended") && said.any("attached again"));
    task.abort();
}
