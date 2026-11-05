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
//! sends each link of a session to the host that opened it, or to the name
//! that this process gives itself in `/relays.json` ([`Resumes::offer`]),
//! where several processes share one name. Each link keeps the contract's
//! limits; the layer's heartbeat is payload, and the client moves the
//! session before a link's 64 MiB or 12 h (T-155).
//!
//! A new session is let in before its `ACCEPT`, within the budget of replay
//! buffers, which counts the sessions let in whose target is not dialed yet;
//! one past it is refused in its handshake, before its client sent a byte of
//! it, so that the client can take `/connect/` instead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::http::request::{self, Request};
use podssh_ws::server;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::forward;
use super::{answer, Config};
use crate::forward_layer::PATH;
use crate::relay::Relay;
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
    /// The name of this process, for each link of a session, where several
    /// processes share the name that a client was given.
    name: Option<Relay>,
    /// The UDP port of the role's QUIC, which the offer names (T-667).
    quic: Option<u16>,
    /// The new sessions let in whose target is not dialed yet: the budget
    /// counts them, so that new sessions at once do not pass it together.
    pending: Mutex<usize>,
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
    /// `budget` bytes of replay buffers in all; 0 offers no session.
    pub fn new(settings: Settings, budget: usize) -> Resumes {
        let keeper = Arc::new(Keeper::new(settings.resume_deadline));
        let (name, quic) = (None, None);
        Resumes { keeper, settings, budget, name, quic, pending: Mutex::new(0), sweeping: AtomicBool::new(false) }
    }

    /// These sessions, with `name`, this process's own, in the offer: a
    /// name of its certificate that reaches this process alone.
    pub fn named(self, name: Relay) -> Resumes {
        Resumes { name: Some(name), ..self }
    }

    /// These sessions, with the UDP port of the role's QUIC in the offer,
    /// where `podssh relay serve --quic yes` serves it (T-667).
    pub fn with_quic(self, port: u16) -> Resumes {
        Resumes { quic: Some(port), ..self }
    }

    /// The sessions kept with their target, with a link or waiting for one.
    pub fn kept(&self) -> usize {
        self.keeper.kept()
    }

    /// The bytes of replay buffers that the sessions may hold in all.
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// How long a session whose link is lost is kept.
    pub fn deadline(&self) -> Duration {
        self.settings.resume_deadline
    }

    /// The name of this process in the offer, if its owner gave one.
    pub fn name(&self) -> Option<&Relay> {
        self.name.as_ref()
    }

    /// `forward` of `/relays.json`: whether a new session can have room at
    /// all, and the name of this process for each link of one, `HOST` or
    /// `HOST:PORT`, or null where its owner gave none; and `quic`, the UDP
    /// port of the role's QUIC, where it serves QUIC (T-667).
    pub fn offer(&self) -> serde_json::Value {
        let host = self.name.as_ref().map(crate::token::relay_name);
        let mut offer = serde_json::json!({ "layer": self.budget >= self.settings.replay_capacity, "host": host });
        if let Some(port) = self.quic {
            offer["quic"] = port.into();
        }
        offer
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
    // Each link is a session of its key's, with its budget (T-636).
    let meter = match super::usage::meter_of(&cfg, &head) {
        Ok(meter) => meter,
        Err(why) => return answer(&mut stream, request::refusal(403, &format!("layer: {why}"), &[])).await,
    };
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
        Err(refused) => {
            if let Some(line) = refused.logged() {
                cfg.event(&line);
            }
            return answer(&mut stream, request::refusal(refused.status(), &refused.answer(), &[])).await;
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
    // A link's Close ends the link alone: the layer's `END` is its half-close.
    forward::pump(session, tokio::io::split(theirs), Vec::new(), cfg, forward::AfterClose::Ends, meter).await;
}

/// The layer on one link: its handshake, then a resume goes on with the
/// target that its session kept, and a new session reaches its target with
/// `open`, after the handshake, so a link that never completes one costs no
/// dial. A new session past `budget` bytes of replay buffers is refused in
/// its handshake ([`reserve`]); one whose target cannot be reached ends at
/// once, its reason in a `CLOSE`.
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
    let (each, pending) = (settings.replay_capacity, &cfg.resumes.pending);
    let let_in = AtomicBool::new(false);
    let say = |line: &str| cfg.event(line);
    let room: far::Room<'_> =
        &|| reserve(keeper, pending, each, budget, &say).map(|()| let_in.store(true, Ordering::SeqCst));
    let accepted =
        far::accept_with_room(link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy, Some(room)).await;
    // A session let in is counted until the keeper holds it, or it ended.
    let counted = let_in.load(Ordering::SeqCst).then(|| Counted(pending));
    let accepted = match accepted {
        Ok(accepted) => accepted,
        // A link that never completed its handshake, or had no room:
        // nothing to keep.
        Err(_) => return,
    };
    if accepted.established().resumed {
        // The handshake proved the session's secret on this new link.
        cfg.event("layer resumed");
        let _ = keeper.run_resumed(accepted).await;
        return;
    }
    match tokio::time::timeout(TARGET_LIMIT, open()).await {
        Ok(Ok(target)) => {
            // The keeper charges it from here on.
            drop(counted);
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

/// Room for one more new session of `each` bytes within `budget`: the
/// sessions that `keeper` charges and those let in before whose target is
/// not dialed yet (`pending`), one more of which it counts. Else the words
/// of the refusal, which the owner hears too, by `say`, once a minute at
/// most.
fn reserve(
    keeper: &Keeper<TcpStream>,
    pending: &Mutex<usize>,
    each: usize,
    budget: usize,
    say: &(dyn Fn(&str) + Sync),
) -> Result<(), String> {
    let mut waiting = pending.lock().unwrap_or_else(|e| e.into_inner());
    let census = keeper.census(each);
    let held = census.held.saturating_add(waiting.saturating_mul(each));
    if held.saturating_add(each) <= budget {
        *waiting += 1;
        return Ok(());
    }
    let shown = Census { held, live: census.live + *waiting, ..census };
    drop(waiting);
    let reason = refusal(&shown, budget);
    // The lock of the lines goes before the line is said.
    let said = keeper.told().refusal(tokio::time::Instant::now());
    if said {
        say(&format!("layer: {reason}"));
    }
    Err(reason)
}

/// A new session let in, counted in the budget until the keeper charges it.
struct Counted<'a>(&'a Mutex<usize>);

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        let mut waiting = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *waiting = waiting.saturating_sub(1);
    }
}

/// The refusal of a new session that `budget` has no room for, in the
/// role's words: what holds it, and how its owner changes it. A client of
/// podssh takes the contract's road then, with no resume.
pub fn refusal(census: &Census, budget: usize) -> String {
    const CHANGES: &str = "--resume-budget and --resume-deadline of podssh relay serve change it";
    if budget == 0 {
        return format!("this relay keeps no resumable session (--resume-budget 0); {CHANGES}");
    }
    let n = census.sessions();
    format!(
        "this relay keeps {n} resumable session{} ({} MiB of replay buffers): {}; {CHANGES}",
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
    fn a_refusal_for_the_budget_names_what_holds_it_and_how_its_owner_changes_it() {
        let census = Census { held: 256 << 20, live: 60, waiting: 4, first_free: Some(Duration::from_secs(90)) };
        let words = refusal(&census, BUDGET);
        let head = "this relay keeps 64 resumable sessions (256 MiB of replay buffers): 60 with a link,";
        assert!(words.starts_with(head), "{words}");
        assert!(words.contains("4 waiting for their client, the first of them for 1 min 30 s more"), "{words}");
        assert!(words.ends_with("--resume-budget and --resume-deadline of podssh relay serve change it"), "{words}");
        let none = refusal(&Census::default(), 0);
        assert!(none.starts_with("this relay keeps no resumable session (--resume-budget 0);"), "{none}");
    }

    #[test]
    fn the_default_keeps_a_session_for_the_layers_deadline_within_the_budget() {
        let resumes = Resumes::default();
        let deadline = crate::session::resume::RESUME_DEADLINE;
        assert_eq!((resumes.budget(), resumes.deadline()), (BUDGET, deadline));
        assert_eq!((resumes.kept(), resumes.name()), (0, None));
        assert_eq!(resumes.offer(), serde_json::json!({ "layer": true, "host": null }));
    }

    /// The process names itself in the offer, where its owner gave a name;
    /// a budget with no room for one session offers no road (T-173).
    #[test]
    fn the_offer_names_this_process_and_a_budget_of_none_offers_nothing() {
        let name = Relay { host: "relay-2.relay.example.org".into(), port: 443 };
        let named = Resumes::default().named(name.clone());
        assert_eq!(named.offer(), serde_json::json!({ "layer": true, "host": "relay-2.relay.example.org" }));
        let on_a_port = Resumes::default().named(Relay { port: 8443, ..name });
        assert_eq!(on_a_port.offer()["host"], "relay-2.relay.example.org:8443");
        let body = on_a_port.offer().to_string();
        let doc = format!(r#"{{"forward":{body}}}"#);
        let asked = Relay { host: "relay.example.org".into(), port: 443 };
        let read = crate::forward_layer::offer::of(doc.as_bytes(), &asked);
        assert_eq!(read.holder(&asked), Relay { host: "relay-2.relay.example.org".into(), port: 8443 });
        let none = Resumes::new(Settings::default(), 0);
        assert_eq!(none.offer()["layer"], false);
        let short = Resumes::new(Settings::default(), (4 << 20) - 1);
        assert_eq!(short.offer()["layer"], false, "less than one buffer holds no session");
    }

    /// Two sessions let in at once do not pass the budget together: each
    /// counts until the keeper charges it, and a refused one counts nothing.
    #[test]
    fn a_new_session_counts_until_its_target_is_dialed() {
        let resumes = Resumes::new(Settings::default(), 8 << 20);
        let (keeper, pending, each) = (&resumes.keeper, &resumes.pending, resumes.settings.replay_capacity);
        let said = Mutex::new(Vec::new());
        let say = |line: &str| said.lock().unwrap().push(line.to_string());
        assert_eq!(reserve(keeper, pending, each, resumes.budget, &say), Ok(()));
        let first = Counted(pending);
        assert_eq!(reserve(keeper, pending, each, resumes.budget, &say), Ok(()));
        let words = reserve(keeper, pending, each, resumes.budget, &say).unwrap_err();
        let head = "this relay keeps 2 resumable sessions (8 MiB of replay buffers): 2 with a link";
        assert!(words.starts_with(head), "{words}");
        assert_eq!(*pending.lock().unwrap(), 2, "the refused one counts nothing");
        assert_eq!(*said.lock().unwrap(), vec![format!("layer: {words}")], "the owner hears it");
        drop(first);
        assert_eq!(*pending.lock().unwrap(), 1);
        assert_eq!(reserve(keeper, pending, each, resumes.budget, &say), Ok(()), "room again");
    }
}
