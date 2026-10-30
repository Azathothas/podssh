//! A podssh node behind a `cf://` name (`podssh node --quick-tunnel`,
//! T-300): its first frame on the WebSocket is the resumable layer's
//! `GREETING`, where cloudflared's SSH service speaks SSH first. The session
//! then runs in the layer, with the end-to-end channel of T-088 above it,
//! and a new WebSocket to the name carries it after each lost one. SSH runs
//! on the other end of a pipe, as on the first hop of any road; when the
//! carriage fails, the task says why, and SSH sees its stream end.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::session::client::Greeted;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{Ask, Ended, OsEntropy};
use podssh_ssh::keep::Offer;
use podssh_ssh::notice::Silence;
use podssh_ssh::Log;
use tokio::io::DuplexStream;

use crate::layered::{self, Line};
use crate::ssh::transport::Carriage;

/// Each direction of the pipe between the SSH client and the layer.
const PIPE: usize = 256 * 1024;

/// What the session shares with the run of SSH: whether the far end keeps
/// shells (T-158), and its silence, for a notice (T-302).
pub(crate) struct Shared {
    pub offer: Offer,
    pub silence: Silence,
}

/// Start the layer on `greeted`, the first link, whose far end said
/// `GREETING`; then carry the session in a task, on a new link of `dial`
/// after each lost one, and give back the SSH client's end, and the task's
/// end. `channel` goes above the layer (none with `--no-e2e`); `shown`
/// names the far end in each line.
pub(crate) async fn carry<D, F>(
    greeted: Greeted<DuplexStream>,
    mut dial: D,
    channel: Option<crate::channel::Operator>,
    shared: Shared,
    shown: String,
    log: Arc<Log>,
) -> Result<(DuplexStream, Carriage), String>
where
    D: FnMut() -> F + Send + 'static,
    F: Future<Output = Next<DuplexStream>> + Send,
{
    // `keep.v1` named, as `podssh ssh` names it (T-158): a copy asks for
    // no shell, so the offer changes nothing of it.
    let client = greeted
        .start(Ask::New, layered::ssh_settings(), &mut OsEntropy)
        .await
        .map_err(|e| format!("the far end greets with the resumable layer, but its handshake failed: {e}"))?;
    log.verbose(&format!("{shown}: {}", client.found()));
    layered::learn(client.found(), &shared.offer);
    let client = layered::heard(client, &shared.silence);
    let (ssh_end, layer_end) = tokio::io::duplex(PIPE);
    let me = channel.as_ref().map(|c| c.identity.clone());
    let pin_say = {
        let (log, shown) = (log.clone(), shown.clone());
        move |line: String| log.info(&format!("{shown}: {line}"))
    };
    let (app, session) = crate::channel::around(layer_end, channel, pin_say);
    let (ended, done) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let say = |line: Line| match line {
            Line::Always(text) => log.info(&format!("{shown}: {text}")),
            Line::Verbose(text) => log.verbose(&format!("{shown}: {text}")),
        };
        let note = |note: Note| {
            if !layered::folded(&note, Some(&shared.silence)) {
                say(layered::line_of(note));
            }
        };
        let connect = |_: &Ended| dial();
        let channel = async move {
            match session {
                Some(session) => session.await.err(),
                None => None,
            }
        };
        let mut entropy = OsEntropy;
        let (outcome, failed) = tokio::join!(resume::run(client, app, connect, note, &mut entropy), channel);
        // The channel says more than the layer: a refused key, a changed
        // node key.
        if let Some((fault, why)) = failed.as_ref().and_then(|e| crate::channel::judged(e, me.as_deref())) {
            log.error(&format!("{shown}: {why}"));
            crate::ssh::result::channel_failed(&fault);
        } else if let Some(why) = layered::why_ended(outcome) {
            log.error(&format!("{shown}: {why}"));
        }
        let _ = ended.send(());
    });
    Ok((ssh_end, done))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use podssh_relay::e2e::ends::Admit;
    use podssh_relay::identity::{Identity, PublicKey};
    use podssh_relay::reverse::framing::SessionId;
    use podssh_relay::reverse::{self, E2e, Handler, Layered, Opening};
    use podssh_relay::session::client;
    use podssh_relay::session::resume::Next;
    use podssh_ssh::options::LogLevel;
    use podssh_ssh::Log;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::task::JoinHandle;

    use super::{carry, Shared};
    use crate::channel::{Expect, Operator};
    use crate::ssh::transport::Carriage;

    const LIMIT: Duration = Duration::from_secs(20);
    const SHOWN: &str = "cf://four-words-of-a.trycloudflare.com";

    /// TARGET: an echo, which counts its opens, as the node's dials of a
    /// TCP TARGET would be counted; in memory, as a test listens nowhere.
    struct Echo {
        opened: Arc<AtomicUsize>,
    }

    impl Handler for Echo {
        type Stream = DuplexStream;

        fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
            self.opened.fetch_add(1, Ordering::SeqCst);
            let (ours, theirs) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Box::pin(async move { Ok(ours) })
        }
    }

    /// The node as `podssh node --quick-tunnel` serves each visitor's
    /// WebSocket: the layer, the channel above it, then TARGET; and each
    /// link's task, to cut it.
    struct Node {
        handler: Layered<E2e<Echo>>,
        ids: AtomicU64,
        links: Mutex<Vec<JoinHandle<()>>>,
    }

    impl Node {
        /// The node, and the count of TARGET's opens.
        fn new(admit: Arc<Admit>) -> (Arc<Node>, Arc<AtomicUsize>) {
            let opened = Arc::new(AtomicUsize::new(0));
            let target = Echo { opened: opened.clone() };
            let channel = crate::channel::node_end("quick", Identity::from_seed(&[2; 32]), admit);
            let handler =
                Layered::new(E2e::new(target, channel), crate::layered::settings(), reverse::layered::NODE_BUDGET);
            (Arc::new(Node { handler, ids: AtomicU64::new(1), links: Mutex::new(Vec::new()) }), opened)
        }

        /// A visitor's link, as the edge brings one.
        async fn link(self: &Arc<Node>) -> DuplexStream {
            let (visitor, theirs) = tokio::io::duplex(64 * 1024);
            let id = SessionId::parse(format!("{:032x}", self.ids.fetch_add(1, Ordering::SeqCst)).as_bytes()).unwrap();
            let mut session = self.handler.open(id).await.unwrap();
            let task = tokio::spawn(async move {
                let mut theirs = theirs;
                let _ = tokio::io::copy_bidirectional(&mut theirs, &mut session).await;
            });
            self.links.lock().unwrap().push(task);
            visitor
        }

        /// Cut each link: the edge lost them.
        fn cut(&self) {
            for task in self.links.lock().unwrap().drain(..) {
                task.abort();
            }
        }
    }

    fn operator(node: PublicKey) -> Operator {
        Operator { identity: Arc::new(Identity::from_seed(&[1; 32])), expect: Expect::Ticket(node), route: None }
    }

    fn log_file(name: &str) -> (std::path::PathBuf, Arc<Log>) {
        let path = std::env::temp_dir().join(format!("podssh-cf-layer-{name}-{:016x}", rand::random::<u64>()));
        (path.clone(), Arc::new(Log::to_file(LogLevel::Verbose, &path).unwrap()))
    }

    /// The SSH client's end of a session to `node`, carried by [`carry`],
    /// and the end of its task.
    async fn session(node: &Arc<Node>, log: Arc<Log>) -> (DuplexStream, Carriage) {
        let greeted = client::greeted(node.link().await).await.unwrap();
        assert!(greeted.layer(), "a node's first frame is the layer's GREETING");
        let dial = {
            let node = node.clone();
            move || {
                let node = node.clone();
                async move { Next::Link(node.link().await) }
            }
        };
        let channel = Some(operator(Identity::from_seed(&[2; 32]).public()));
        let shared = Shared { offer: Default::default(), silence: Default::default() };
        let (ssh, done) = tokio::time::timeout(LIMIT, carry(greeted, dial, channel, shared, SHOWN.into(), log))
            .await
            .unwrap()
            .unwrap();
        (ssh, done)
    }

    async fn round(ssh: &mut DuplexStream, seed: u32) {
        let sent: Vec<u8> = (0..(1u32 << 20)).map(|i| (i.wrapping_mul(31).wrapping_add(seed) % 251) as u8).collect();
        let (mut r, mut w) = tokio::io::split(ssh);
        let mut back = vec![0u8; sent.len()];
        let (wrote, read) = tokio::join!(w.write_all(&sent), tokio::time::timeout(LIMIT, r.read_exact(&mut back)));
        wrote.unwrap();
        read.unwrap().unwrap();
        assert_eq!(Sha256::digest(&back), Sha256::digest(&sent), "the echo came back whole");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_node_s_session_goes_both_ways_and_resumes_on_a_new_websocket() {
        let client = Identity::from_seed(&[1; 32]).public();
        let admit: Arc<Admit> =
            Arc::new(move |key: &PublicKey| if *key == client { Ok(()) } else { Err("not in the list".into()) });
        let (node, dials) = Node::new(admit);
        let (path, log) = log_file("resume");
        let (mut ssh, done) = session(&node, log).await;
        round(&mut ssh, 0).await;
        node.cut();
        round(&mut ssh, 7).await;
        assert_eq!(dials.load(Ordering::SeqCst), 1, "one connection to TARGET for the session, across its links");
        assert!(node.ids.load(Ordering::SeqCst) >= 3, "a second link carried the session");
        // SSH's end closes: the layer's CLOSE, then the task ends.
        drop(ssh);
        tokio::time::timeout(LIMIT, done).await.expect("the task ends after the session").unwrap();
        let said = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        assert!(said.contains(&format!("{SHOWN}: the session resumed after")), "{said}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_key_out_of_the_node_s_allowlist_is_refused_and_target_is_never_opened() {
        let (node, dials) = Node::new(Arc::new(|_: &PublicKey| Err("not in the list".to_string())));
        let (path, log) = log_file("refused");
        let (mut ssh, done) = session(&node, log).await;
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(LIMIT, ssh.read(&mut buf)).await.unwrap();
        assert!(matches!(read, Ok(0) | Err(_)), "SSH sees its stream end: {read:?}");
        // The run waits for the task, which says why first.
        tokio::time::timeout(LIMIT, done).await.expect("the task ends").unwrap();
        let said = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        let fingerprint = Identity::from_seed(&[1; 32]).public().to_string();
        assert!(said.contains(&format!("{SHOWN}: the node refused this client's key {fingerprint}")), "{said}");
        assert!(said.contains("adds the key to the file of --allow"), "{said}");
        assert_eq!(dials.load(Ordering::SeqCst), 0, "no key, no TARGET");
    }
}
