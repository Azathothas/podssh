//! `GET /v1/layer/<host>/<port>` (T-173): the forward road with the
//! resumable layer at the role, for a standard sshd. The contract's
//! `/connect/` ends the target's connection when its WebSocket ends; here
//! the role is the far end of podssh's layer (`crate::session`), as a node
//! is for its TARGET: each WebSocket is one link, the target is dialed once,
//! after a new session's handshake, and it waits while the client's link is
//! lost, until a resume on a new link carries the session on, or the layer's
//! deadline passes and the target is shut.
//!
//! The token, the upgrade and the policy are checked before the upgrade, as
//! on `/connect/`, with the same refusals. The layer's secret never crosses
//! the role: each resume proves it, and the path names the target alone. A
//! resume must reach this process, which holds the session, so a client
//! sends each link of a session to the host that opened it. Each link keeps
//! the contract's limits; the layer's heartbeat is payload, and the client
//! moves the session before a link's 64 MiB or 12 h (T-155).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::{self, Request};
use podssh_ws::server;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::forward;
use super::policy::Refused;
use super::{answer, Config};
use crate::forward_layer::PATH;
use crate::session::budget::{holders, Census};
use crate::session::far::{self, TARGET_LIMIT};
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::secret::OsEntropy;
use crate::session::Settings;

/// The replay memory of the role's sessions in all: 64 sessions of the
/// default buffer at once, four times a node's, as a relay's host serves
/// more clients than a cage.
pub const BUDGET: usize = 256 << 20;
/// Each direction of the pipe between a link's WebSocket and the layer.
const PIPE: usize = 256 * 1024;
/// How often the sessions whose link is lost are checked for the deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

/// The sessions of the road, kept across links, with their targets.
pub struct Resumes {
    keeper: Arc<Keeper<TcpStream>>,
    settings: Settings,
    budget: usize,
    sweeping: AtomicBool,
}

impl Default for Resumes {
    fn default() -> Self {
        Resumes::new(Settings::default(), BUDGET)
    }
}

impl std::fmt::Debug for Resumes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Resumes({} kept)", self.keeper.kept())
    }
}

impl Resumes {
    /// Sessions of `settings` (their replay buffer, their deadline), within
    /// `budget` bytes of replay buffers in all.
    pub fn new(settings: Settings, budget: usize) -> Resumes {
        let keeper = Arc::new(Keeper::new(settings.resume_deadline));
        Resumes { keeper, settings, budget, sweeping: AtomicBool::new(false) }
    }

    /// The sessions kept with their target, with a link or waiting for one.
    pub fn kept(&self) -> usize {
        self.keeper.kept()
    }

    /// One task forgets the sessions whose deadline passed, and shuts their
    /// targets; started with the first link, inside the role's runtime.
    fn sweep(&self) {
        if self.sweeping.swap(true, Ordering::SeqCst) {
            return;
        }
        let keeper = Arc::downgrade(&self.keeper);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(keeper) = keeper.upgrade() else { return };
                keeper.expire().await;
            }
        });
    }
}

/// Whether `path`, with no query, is this road's.
pub fn serves(path: &str) -> bool {
    path.starts_with(PATH)
}

/// Serve one link of the road on `stream`, `pending` the bytes that came
/// after its head.
pub async fn connect<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let token_ok = head.header("x-relay-token").is_some_and(|t| cfg.tokens.check(t, super::tokens::now_ms()));
    if !token_ok {
        return answer(&mut stream, request::refusal(403, "layer: missing or wrong token", &[])).await;
    }
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => return answer(&mut stream, refused.answer()).await,
    };
    // The target and its options, read as `/connect/` reads them: `?family`
    // holds; the dial waits for the layer's handshake whatever the rest say.
    let target = head.target.strip_prefix(PATH).unwrap_or_default();
    let Some(asked) = forward::asked(&format!("/connect/{target}")) else {
        let why = format!("{}: the path is {PATH}HOST/PORT", head.target);
        return answer(&mut stream, request::refusal(400, &why, &[])).await;
    };
    // A resume's path is checked too: the policy holds for each link.
    let plan = match cfg.policy.plan(&asked.host, asked.port, asked.family, &cfg.egress).await {
        Ok(plan) => plan,
        Err(Refused::Policy(why)) => {
            return answer(&mut stream, request::refusal(403, &format!("forward: {why}"), &[])).await
        }
        Err(Refused::Unreachable(why)) => {
            return answer(&mut stream, request::refusal(502, &format!("relay: {why}"), &[])).await
        }
    };
    if stream.write_all(&server::switching(&key)).await.is_err() {
        return;
    }
    cfg.event("upgrade layer");
    let session = Arc::new(server::session(stream, pending, None));
    let resumes = &cfg.resumes;
    resumes.sweep();
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (keeper, settings, budget) = (resumes.keeper.clone(), resumes.settings, resumes.budget);
    let (far_cfg, dial_cfg) = (cfg.clone(), cfg.clone());
    // The layer's end of the link runs on its own: the session that it
    // carries outlives this link.
    tokio::spawn(async move {
        let host = asked.host;
        let open = || async move { forward::dial(&host, &plan, &dial_cfg).await };
        serve_link(ours, settings, budget, &keeper, open, &far_cfg).await;
    });
    forward::pump(session, tokio::io::split(theirs), Vec::new(), cfg).await;
}

/// The layer on one link: its handshake, then a resume goes on with the
/// target that its session kept, and a new session reaches its target with
/// `open`, after the handshake, so a link that never completes one costs no
/// dial. A new session past `budget` bytes of replay buffers, or whose
/// target cannot be reached, ends at once, its reason in a `CLOSE`.
async fn serve_link<L, O, F>(
    link: L,
    settings: Settings,
    budget: usize,
    keeper: &Keeper<TcpStream>,
    open: O,
    cfg: &Config,
) where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: FnOnce() -> F,
    F: std::future::Future<Output = Result<TcpStream, String>>,
{
    let accepted = match far::accept(link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy).await {
        Ok(accepted) => accepted,
        // A link that never completed its handshake: nothing to keep.
        Err(_) => return,
    };
    if accepted.established().resumed {
        // The handshake proved the session's secret on this new link.
        cfg.event("layer resumed");
        let _ = keeper.run_resumed(accepted).await;
        return;
    }
    let each = settings.replay_capacity;
    let census = keeper.census(each);
    if census.held.saturating_add(each) > budget {
        let reason = refusal(&census, budget);
        // The owner hears it too, once a minute at most; the lock goes
        // before any await.
        let said = keeper.told().refusal(tokio::time::Instant::now());
        if said {
            cfg.event(&format!("layer: {reason}"));
        }
        accepted.close(&reason, &keeper.sessions).await;
        return;
    }
    match tokio::time::timeout(TARGET_LIMIT, open()).await {
        Ok(Ok(target)) => {
            keeper.run_new(accepted, target).await;
        }
        Ok(Err(why)) => {
            accepted.close(&format!("the relay could not reach its target: {why}"), &keeper.sessions).await;
        }
        Err(_) => {
            let reason = format!("the target did not answer the relay within {} s", TARGET_LIMIT.as_secs());
            accepted.close(&reason, &keeper.sessions).await;
        }
    }
}

/// The refusal of a new session that `budget` has no room for, in the
/// role's words: what holds it, and the road with no resume that is left.
pub fn refusal(census: &Census, budget: usize) -> String {
    let n = census.sessions();
    format!(
        "this relay keeps {n} resumable session{} ({} MiB of replay buffers): {}; with PODSSH_RELAY_LAYER=no a \
         session goes on with no resume",
        if n == 1 { "" } else { "s" },
        budget >> 20,
        holders(census)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_road_has_its_own_path_beside_the_contract() {
        assert!(serves("/v1/layer/github.com/22"));
        for path in ["/connect/github.com/22", "/v1/connect/name", "/v1/layers", "/health"] {
            assert!(!serves(path), "{path}");
        }
    }

    #[test]
    fn a_refusal_for_the_budget_names_what_holds_it_and_the_road_left() {
        let census = Census { held: 256 << 20, live: 60, waiting: 4, first_free: Some(Duration::from_secs(90)) };
        let words = refusal(&census, BUDGET);
        let head = "this relay keeps 64 resumable sessions (256 MiB of replay buffers): 60 with a link,";
        assert!(words.starts_with(head), "{words}");
        assert!(words.contains("4 waiting for their client, the first of them for 1 min 30 s more"), "{words}");
        assert!(words.ends_with("with PODSSH_RELAY_LAYER=no a session goes on with no resume"), "{words}");
    }

    #[test]
    fn the_default_keeps_a_session_for_the_layers_deadline_within_the_budget() {
        let resumes = Resumes::default();
        let deadline = crate::session::resume::RESUME_DEADLINE;
        assert_eq!((resumes.budget, resumes.settings.resume_deadline), (BUDGET, deadline));
        assert_eq!(resumes.kept(), 0);
    }
}
