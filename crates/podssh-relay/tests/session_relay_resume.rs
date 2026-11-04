//! The relay role's forward road in the resumable layer (T-173): the role is
//! the far end of the layer for a target that speaks no layer, a standard
//! sshd among them. A forwarder in front of the role cuts the client's link
//! at 20 points of its own, with no word to either end, while 32 MiB go each
//! way; the client resumes on a new link to the same host each time, the
//! role dials the target once for the whole session, the digests are equal,
//! and each link's request names the target alone, never the layer's
//! secret. OpenSSH's client and server do the same where this host has
//! them. The role offers the road in `/relays.json`, and refuses a link
//! before the upgrade as `/connect/` does. Behind one name that two
//! processes of the role share, each link goes to the process that named
//! itself in its offer; and a new session past the role's budget is refused
//! in its handshake, before its client sent a byte of it.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod relay_resume_harness;
mod role_harness;

use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::Engine as _;
use podssh_relay::forward_layer::{carry, no_room, offer, Dialer};
use podssh_relay::relay::Relay;
use podssh_relay::serve::layer::Resumes;
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{tokens, Mint};
use podssh_relay::session::client::{self, Found, Outcome};
use podssh_relay::session::{Ask, End, Ended, OsEntropy, Settings};
use podssh_ws::ConnectError;
use relay_resume_harness::{byte_at, data_file, echo_target, exit_of, received, send_data, Cutter, OpenSsh, Scratch};
use role_harness::Role;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MIB: usize = 1 << 20;
/// The bytes of each way.
const SIZE: usize = 32 * MIB;
/// The cuts of a session, each at a point of its own.
const CUTS: usize = 20;
/// The bytes of each way, and the cuts, of a session behind a shared name.
const NAMED_SIZE: usize = 16 * MIB;
const NAMED_CUTS: usize = 10;
/// The bytes of a link, both ways, before its cut: 256 KiB and up to 2 MiB
/// more, so that each cut comes before the session's 64 MiB end.
const CUT_AT: (usize, usize) = (256 * 1024, 2 * MIB);
const LIMIT: Duration = Duration::from_secs(300);

/// The role, which dials the loopback, and a token of its own.
async fn private_role() -> (Role, String) {
    let role = Role::configured(Mint::Anyone, Policy { private: true, ..Policy::default() }, Default::default()).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    (role, token)
}

/// Whether a session ended well: its far end's `CLOSE`, with no reason, as
/// its target ended, or this side's, answered.
fn ended_well(outcome: &Outcome) -> bool {
    match outcome {
        Outcome::Layer(Ended { end: End::Closed(why), .. }) => why.is_empty(),
        Outcome::Layer(Ended { end: End::LocalEnd, .. }) => true,
        _ => false,
    }
}

/// Until the role keeps no session, 20 s at most: a session that ended is
/// forgotten at once, its target shut.
async fn until_forgotten(role: &Role) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while role.cfg.resumes.kept() > 0 {
        assert!(tokio::time::Instant::now() < deadline, "the role still keeps {} sessions", role.cfg.resumes.kept());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_through_the_role_lives_on_20_cuts_with_one_dial_of_its_target() {
    let (role, token) = private_role().await;
    let (target, dials) = echo_target(SIZE).await;
    let seed = 0x5eed_0173;
    let cutter = Cutter::start(role.relay.port, CUTS, CUT_AT, seed).await;
    let dialer = Dialer::on_loopback(cutter.relay(), "127.0.0.1", target, &token).unwrap();
    let first = dialer.link(&mut |_: &str| {}).await.expect("the first link");
    let client = client::start(first, Ask::New, Settings::default(), &mut OsEntropy).await.expect("the handshake");
    assert!(matches!(client.found(), Found::Layer { resumed: false, .. }), "{}", client.found());
    let secret = *client.established().expect("a session of the layer").secret.bytes();

    let (app, ours) = tokio::io::duplex(256 * 1024);
    let (mut from_app, mut to_app) = tokio::io::split(ours);
    let sent = tokio::spawn(async move { send_data(&mut to_app, SIZE).await });
    let back = tokio::spawn(async move { received(&mut from_app).await });
    let mut notes = Vec::new();
    let session = carry(&dialer, client, app, |note| notes.push(note));
    let outcome = tokio::time::timeout(LIMIT, session).await.expect("the session ended within the limit");
    assert!(
        ended_well(&outcome),
        "the session did not live on its cuts: {outcome:?}, after {} cuts (seed {seed:#x}); {notes:?}",
        cutter.cuts()
    );
    let (count, digest) = tokio::time::timeout(LIMIT, back).await.expect("the bytes back").unwrap();
    assert_eq!(count, SIZE, "each byte came back");
    assert_eq!(digest, sent.await.unwrap(), "the digests of what went and what came back");
    assert!(cutter.cuts() >= CUTS, "{} cuts", cutter.cuts());
    assert_eq!(dials.load(Ordering::SeqCst), 1, "one connection to the target for the whole session");
    assert!(role.said("layer resumed"), "the role resumed the session on a new link");
    until_forgotten(&role).await;

    // No URL holds the layer's secret: each link asked for the target's
    // path alone, and a resume proves the secret inside the layer's records.
    let want = format!("GET /v1/layer/127.0.0.1/{target} HTTP/1.1");
    let heads = cutter.heads();
    assert!(heads.len() > CUTS, "a link for each cut and the last: {}", heads.len());
    let engines = [&base64::engine::general_purpose::STANDARD, &base64::engine::general_purpose::URL_SAFE_NO_PAD];
    let mut shown: Vec<String> = engines.iter().map(|e| e.encode(secret)).collect();
    shown.push(secret.iter().map(|b| format!("{b:02x}")).collect());
    for head in &heads {
        assert_eq!(head.lines().next(), Some(want.as_str()), "the request line of a link");
        assert!(!shown.iter().any(|s| head.contains(s.as_str())), "a link's request holds the layer's secret");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_through_the_role_lives_on_20_cuts_with_equal_digests() {
    let Some(openssh) = OpenSsh::find() else {
        eprintln!("did not run: no OpenSSH (ssh, sshd, ssh-keygen) or no user name here");
        return;
    };
    let dir = Scratch::new("openssh");
    let (_sshd, sshd_port) = match openssh.sshd(&dir.0) {
        Ok(server) => server,
        Err(why) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let (role, token) = private_role().await;
    let cutter = Cutter::start(role.relay.port, CUTS, CUT_AT, 0x0173_5eed).await;
    let dialer = Dialer::on_loopback(cutter.relay(), "127.0.0.1", sshd_port, &token).unwrap();
    let want = data_file(&dir.0.join("data"), SIZE);
    // OpenSSH's client reaches the layer's client through a socket of the
    // test, as it would reach `podssh proxy` through its stdin and stdout.
    let door = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let door_port = door.local_addr().unwrap().port();
    let ssh = openssh.cat(&dir.0, door_port, &dir.0.join("data"), &dir.0.join("back")).expect("ssh");
    let (app, _) = tokio::time::timeout(LIMIT, door.accept()).await.expect("ssh connected").unwrap();
    let first = dialer.link(&mut |_: &str| {}).await.expect("the first link");
    let client = client::start(first, Ask::New, Settings::default(), &mut OsEntropy).await.expect("the handshake");
    let outcome = tokio::time::timeout(LIMIT, carry(&dialer, client, app, |_| {})).await.expect("the session's end");
    let status = exit_of(ssh, LIMIT).await;
    let said = std::fs::read_to_string(dir.0.join("ssh.log")).unwrap_or_default();
    assert!(ended_well(&outcome), "the session did not live on its cuts: {outcome:?}; ssh said {said:?}");
    assert!(status.is_some_and(|s| s.success()), "ssh exited {status:?}: {said}");
    let back = std::fs::read(dir.0.join("back")).unwrap();
    assert_eq!(back.len(), SIZE, "each byte came back through sshd's cat");
    assert_eq!(Sha256::digest(&back).to_vec(), want, "the digests");
    assert!(cutter.cuts() >= CUTS, "{} cuts", cutter.cuts());
    assert!(role.said("layer resumed"), "the role resumed the session on a new link");
    until_forgotten(&role).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_role_offers_the_road_and_refuses_a_link_before_the_upgrade_as_connect_does() {
    let role = Role::start().await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let mut tcp = TcpStream::connect(("127.0.0.1", role.relay.port)).await.unwrap();
    let offered = offer::over(&mut tcp, &format!("127.0.0.1:{}", role.relay.port), &role.relay).await;
    let offered = offered.expect("/relays.json");
    assert!(offered.layer, "/relays.json offers the road");
    assert_eq!(offered.at, None, "a role with no name of its own names none: {offered:?}");
    let refused = |r: Result<_, ConnectError>| match r {
        Err(ConnectError::Refused { status, body }) => (status, body),
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the upgrade was taken"),
    };
    let (status, body) = refused(role.socket("/v1/layer/127.0.0.1/22", "wrong").await);
    assert_eq!((status, body.contains("missing or wrong token")), (403, true), "{body}");
    // The default policy dials public targets alone, as on `/connect/`.
    let (status, body) = refused(role.socket("/v1/layer/127.0.0.1/22", &token).await);
    assert_eq!((status, body.contains("ALLOW list")), (403, true), "{body}");
    let (status, body) = refused(role.socket("/v1/layer/127.0.0.1", &token).await);
    assert_eq!((status, body.contains("/v1/layer/HOST/PORT")), (400, true), "{body}");
    assert_eq!(role.http("GET", "/v1/layer/127.0.0.1/22", Some(&token)).await.0, 426, "no upgrade");
    assert!(!role.said("upgrade layer"), "no link was taken");
}

/// A role on the loopback that dials it, with `resumes` for its sessions.
async fn role_with(resumes: Resumes) -> Role {
    Role::configured_with(Mint::Anyone, Policy { private: true, ..Policy::default() }, Default::default(), resumes)
        .await
}

/// Two processes of the role behind one name, each with a name of its own
/// in its offer: the client reads the offer through the shared name, which
/// a balancer sends to each process in turn, and sends each link of the
/// session to the process that answered, by its own name, where each cut and
/// resume then goes; the other process never sees a link. Through the shared
/// name, a resume would reach the other process half the time, which does
/// not know the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn behind_one_name_each_link_goes_to_the_process_that_named_itself() {
    let (door_a, door_b) = (bind().await, bind().await);
    let own = |door: &TcpListener| Relay { host: "127.0.0.1".into(), port: door.local_addr().unwrap().port() };
    let a = role_with(Resumes::default().named(own(&door_a))).await;
    let b = role_with(Resumes::default().named(own(&door_b))).await;
    // The harness's roles share the secret of their tokens, as the
    // processes behind one name must for a client's token to hold at each.
    let (token, _) = a.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let (target, dials) = echo_target(NAMED_SIZE).await;
    let seed = 0x0173_0003;
    let to_a = Cutter::among(door_a, vec![a.relay.port], NAMED_CUTS, CUT_AT, seed);
    let to_b = Cutter::among(door_b, vec![b.relay.port], NAMED_CUTS, CUT_AT, seed ^ 0x55);
    let shared = Cutter::among(bind().await, vec![a.relay.port, b.relay.port], NAMED_CUTS, CUT_AT, seed ^ 0xaa);
    let mut tcp = TcpStream::connect(("127.0.0.1", shared.port)).await.unwrap();
    let offered = offer::over(&mut tcp, &format!("127.0.0.1:{}", shared.port), &shared.relay()).await;
    drop(tcp);
    let offered = offered.expect("the offer, through the shared name");
    assert!(offered.layer && offered.refused.is_none(), "{offered:?}");
    let dialer = Dialer::on_loopback_for(&shared.relay(), &offered, "127.0.0.1", target, &token).unwrap();
    let (held, other, door) = if dialer.relay().port == to_a.port { (&a, &b, &to_a) } else { (&b, &a, &to_b) };

    let first = dialer.link(&mut |_: &str| {}).await.expect("the first link");
    let client = client::start(first, Ask::New, Settings::default(), &mut OsEntropy).await.expect("the handshake");
    let (app, ours) = tokio::io::duplex(256 * 1024);
    let (mut from_app, mut to_app) = tokio::io::split(ours);
    let sent = tokio::spawn(async move { send_data(&mut to_app, NAMED_SIZE).await });
    let back = tokio::spawn(async move { received(&mut from_app).await });
    let mut notes = Vec::new();
    let session = carry(&dialer, client, app, |note| notes.push(note));
    let outcome = tokio::time::timeout(LIMIT, session).await.expect("the session ended within the limit");
    assert!(
        ended_well(&outcome),
        "the session did not live on its cuts: {outcome:?}, after {} cuts at the door of {} and {} at the shared \
         name; {notes:?}",
        door.cuts(),
        dialer.relay().port,
        shared.cuts()
    );
    let (count, digest) = tokio::time::timeout(LIMIT, back).await.expect("the bytes back").unwrap();
    assert_eq!((count, digest), (NAMED_SIZE, sent.await.unwrap()), "each byte came back, in order");
    assert!(door.cuts() >= NAMED_CUTS, "{} cuts at the process's own name", door.cuts());
    assert_eq!(dials.load(Ordering::SeqCst), 1, "one connection to the target for the whole session");
    assert!(held.said("layer resumed"), "the process that named itself resumed the session");
    assert!(!other.said("upgrade layer"), "no link of the session went to the other process");
    until_forgotten(held).await;
}

/// A role whose budget holds one session: a second new session is refused
/// in its handshake with the layer's `REFUSE` (busy) and the role's words,
/// before its client sent a byte of it, and its target is never dialed; the
/// session that holds the budget resumes on a new link meanwhile, as a
/// resume needs no more room.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_session_past_the_budget_is_refused_in_its_handshake_and_dials_nothing() {
    let role = role_with(Resumes::new(Settings::default(), 4 * MIB)).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    // It sends back each byte, and ends the connection after 2 MiB.
    let (target, dials) = echo_target(2 * MIB).await;
    // One cut of the first link of the session that holds the budget.
    let cutter = Cutter::start(role.relay.port, 1, (64 * 1024, 64 * 1024), 0x0173_0005).await;
    let dialer = Dialer::on_loopback(cutter.relay(), "127.0.0.1", target, &token).unwrap();
    let first = dialer.link(&mut |_: &str| {}).await.expect("the first link");
    let client = client::start(first, Ask::New, Settings::default(), &mut OsEntropy).await.expect("the first session");
    let (app, ours) = tokio::io::duplex(256 * 1024);
    let (mut from_app, mut to_app) = tokio::io::split(ours);
    let want: Vec<u8> = (0..(2 * MIB) as u64).map(byte_at).collect();
    let probe = async {
        let mut back = vec![0u8; MIB];
        // Each MiB up while it comes back, as the pipes hold less.
        let up = to_app.write_all(&want[..MIB]);
        let (wrote, read) = tokio::join!(up, tokio::time::timeout(LIMIT, from_app.read_exact(&mut back)));
        wrote.unwrap();
        read.expect("the first MiB back").unwrap();
        assert!(back[..] == want[..MIB], "the first MiB came back whole across its cut");
        // The budget is full: a second new session, on a link of its own.
        let second = Dialer::on_loopback(role.relay.clone(), "127.0.0.1", target, &token).unwrap();
        let link = second.link(&mut |_: &str| {}).await.expect("a link of the second session");
        let refused = client::start(link, Ask::New, Settings::default(), &mut OsEntropy).await;
        let up = to_app.write_all(&want[MIB..]);
        let (wrote, read) = tokio::join!(up, tokio::time::timeout(LIMIT, from_app.read_exact(&mut back)));
        wrote.unwrap();
        read.expect("the second MiB back").unwrap();
        assert!(back[..] == want[MIB..], "the second MiB came back whole");
        refused
    };
    // The second MiB comes back through the session after the refusal, so
    // the session held the budget then; it ends in the poll that hands the
    // probe its last bytes, so the two run side by side.
    let session = carry(&dialer, client, app, |_| {});
    let (refused, outcome) = tokio::join!(probe, tokio::time::timeout(LIMIT, session));
    let outcome = outcome.expect("the session's end");
    assert!(ended_well(&outcome), "{outcome:?}");
    let e = match refused {
        Ok(_) => panic!("a second session was let in past the budget of one"),
        Err(e) => e,
    };
    let words = no_room(&e).unwrap_or_else(|| panic!("not the refusal of the budget: {e}"));
    let head = "this relay keeps 1 resumable session (4 MiB of replay buffers): 1 with a link";
    assert!(words.starts_with(head), "{words}");
    assert_eq!(dials.load(Ordering::SeqCst), 1, "the refused session dialed nothing");
    assert!(cutter.cuts() >= 1 && role.said("layer resumed"), "the session resumed on a full budget");
    assert!(role.said(&format!("layer: {head}")), "the owner heard the refusal");
    until_forgotten(&role).await;
}

async fn bind() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback")
}
