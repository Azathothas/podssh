//! The Piping Server road against `https://ppng.io` (T-437), live and short,
//! as the operator's ruling Q65 allows: a node and a client in this process,
//! through the proxy of the environment, with a key of this run's so that
//! no other run meets these paths; a session of the resumable layer carries
//! 64 KiB each way through a node in front of an echo. `PODSSH_PIPING` names
//! another server. No throughput is measured on a server that one person
//! runs for everyone.
//!
//!     cargo test -p podssh-relay --features piping --test piping_live -- --ignored --nocapture

#![cfg(feature = "piping")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::piping::{self as road, dial, Dialer, Http, Node, Secret, Server};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::{Entropy, OsEntropy, Settings};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const SIZE: usize = 64 * 1024;
const LIMIT: Duration = Duration::from_secs(120);

async fn echo() -> Result<DuplexStream, String> {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(theirs);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Ok(ours)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: ppng.io, or the server of PODSSH_PIPING, through the proxy of the environment"]
async fn a_session_through_ppng_io_carries_64_kib_each_way() {
    let server = match std::env::var("PODSSH_PIPING").ok().filter(|v| v.starts_with("https://")) {
        Some(url) => Server::parse(&url).expect("PODSSH_PIPING names a server"),
        None => Server::default(),
    };
    eprintln!("server: {server}");
    let mut key = [0u8; 32];
    OsEntropy.fill(&mut key).expect("random bytes");
    let secret = || Secret::from_bytes(key);
    let http = || Http::new(server.clone(), dial::tls(Trust::Default, ProxyChoice::FromEnvironment));
    let say = |who: &'static str| -> road::Say { Arc::new(move |line: String| eprintln!("{who}: {line}")) };
    let settings = Settings { features: road::FEATURES, ..Settings::default() };
    let node = Node { secret: Arc::new(secret()), http: Arc::new(http()), say: say("node") };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(road::far::serve_kept(node, settings, 64 << 20, echo, keeper));
    let dialer = Dialer::new(secret(), http(), say("client"));
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let mut back = vec![0u8; SIZE];
        let ((), ()) = tokio::join!(
            async { writer.write_all(&out).await.expect("the layer takes the bytes") },
            async { reader.read_exact(&mut back).await.map(|_| ()).expect("the echo") },
        );
        drop((reader, writer));
        back
    };
    let both = async { tokio::join!(road::carry(&dialer, app, settings, |_| {}), using) };
    let (carried, back) = tokio::time::timeout(LIMIT, both).await.expect("the session ended in time");
    assert_eq!(Sha256::digest(&back), Sha256::digest(&out), "each byte came back once, in order");
    carried.expect("the session ran");
    eprintln!("protocol: {:?}; numbered pieces: {}", dialer.proto(), dialer.numbered());
    serving.abort();
    dialer.close().await;
}
