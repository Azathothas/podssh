//! podssh's own node and operator in the run of `reverse_drops_live.rs`
//! (T-255): a node of the resumable layer in front of an echo, and one
//! session of the layer through it that echoes a byte each 10 s for the
//! whole run, on a pair of their own. Each end of the node's socket and each
//! loss of the session's leg is printed with its UTC time, with what it
//! cost: the time until the node was online again, and until the session
//! resumed. The pair is stopped at the end; no token is printed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::pair::{self, PairContext};
use podssh_relay::relay::Relay;
use podssh_relay::reverse::{self, operator, Handler, Layered, NodeConfig, Opening, OperatorConfig, OperatorLimits};
use podssh_relay::reverse::{Outcome as LegOutcome, SessionId, Wire};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{Ask, End, Ended, OsEntropy, Settings};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

/// The bound on a request and on a socket's open.
const STEP: Duration = Duration::from_secs(15);
const PIPE: usize = 64 * 1024;
/// How often the session echoes a byte, and how long one may take: more
/// than a resume after a drop needs.
const EVERY: Duration = Duration::from_secs(10);
const ECHO_WAIT: Duration = Duration::from_secs(90);
/// As `podssh ssh node://` sets a leg of the layer.
const LEG_WAIT: Duration = Duration::from_secs(5);
const NODE_ENDS: Duration = Duration::from_secs(35);

/// The words of each line, as the parent's `say`.
pub type Say = fn(&str, &str);

/// What podssh's own ends saw.
#[derive(Default)]
pub struct Costs {
    /// From each end of the node's socket to its next `online again`.
    pub node_back: Vec<Duration>,
    /// How long each resume of the session took.
    pub resumed: Vec<Duration>,
    /// Losses of the session's leg.
    pub losses: u32,
    /// Echoes that did not come back within [`ECHO_WAIT`].
    pub missed: u32,
    /// How the session ended.
    pub end: String,
}

impl Costs {
    /// One line of the summary.
    pub fn summary(&self) -> String {
        let longest =
            |times: &[Duration]| times.iter().max().map_or("none".into(), |t| format!("{:.1} s", t.as_secs_f64()));
        format!(
            "node back online {} times (the longest {}); the session lost its leg {} times and resumed {} (the \
             longest {}); echoes missed {}; it ended: {}",
            self.node_back.len(),
            longest(&self.node_back),
            self.losses,
            self.resumed.len(),
            longest(&self.resumed),
            self.missed,
            self.end
        )
    }
}

/// Each session echoes what it takes.
struct Echo;

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(ours)
        })
    }
}

/// The legs of the session, as `podssh ssh node://` opens them.
struct Legs {
    relay: Relay,
    trust: Trust,
    name: String,
    token: String,
    current: Mutex<Option<JoinHandle<LegOutcome>>>,
    say: Say,
}

impl Legs {
    async fn open(&self) -> Result<DuplexStream, String> {
        let proxy = ProxyChoice::FromEnvironment;
        let config = OperatorConfig {
            relay: &self.relay,
            name: &self.name,
            connect_token: &self.token,
            trust: &self.trust,
            proxy: &proxy,
            timeout: STEP,
            limits: OperatorLimits { node_ends: Some(NODE_ENDS), ..OperatorLimits::default() },
            wire: Wire::Tls,
        };
        let (link, leg) = tokio::io::duplex(PIPE);
        let handle = operator::start(&config, leg).await.map_err(|e| e.to_string())?;
        *self.current.lock().unwrap() = Some(handle);
        Ok(link)
    }

    /// The next link after a loss; how the lost leg ended is said first.
    async fn next(&self, moving: bool) -> Next<DuplexStream> {
        let lost = if moving { None } else { self.current.lock().unwrap().take() };
        if let Some(handle) = lost {
            if let Ok(Ok(outcome)) = tokio::time::timeout(LEG_WAIT, handle).await {
                (self.say)("podssh leg", &format!("the leg ended: {outcome:?}"));
            }
        }
        match self.open().await {
            Ok(link) => Next::Link(link),
            Err(why) => Next::Retry(why),
        }
    }
}

/// podssh's node and one session through it, until `until`.
pub async fn hold(relay: Relay, trust: Trust, until: Instant, say: Say) -> Costs {
    let proxy = ProxyChoice::FromEnvironment;
    let ctx = PairContext { relay: &relay, trust: &trust, proxy: &proxy, timeout: STEP };
    let made = match pair::create(&ctx).await {
        Ok(made) => made,
        Err(e) => {
            say("podssh", &format!("no pair: {e}"));
            return Costs { end: "no pair".into(), ..Costs::default() };
        }
    };
    let (name, token) = (made.name.clone(), made.connect_token().to_string());
    let costs = Arc::new(Mutex::new(Costs::default()));
    let online = Arc::new(AtomicBool::new(false));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let node = async {
        // When the node's socket last ended, for the time until it is back.
        let ended: Mutex<Option<Instant>> = Mutex::new(None);
        let line = |line: String| {
            say("podssh node", &line);
            let now = Instant::now();
            let mut at = ended.lock().unwrap();
            if line.contains("; connecting again") && at.is_none() {
                *at = Some(now);
            }
            if line.starts_with("online") {
                online.store(true, Ordering::SeqCst);
                if let Some(since) = at.take() {
                    costs.lock().unwrap().node_back.push(now - since);
                }
            }
        };
        let mut config = NodeConfig {
            pair: made,
            label: None,
            trust: &trust,
            proxy: &proxy,
            timeout: STEP,
            settings: reverse::Settings::default(),
            repair: None,
            wire: Wire::Tls,
            say: Some(&line),
        };
        let layer = Settings::default().on_the_pair();
        let handler = Arc::new(Layered::new(Echo, layer, reverse::layered::NODE_BUDGET));
        let exit = reverse::run(&mut config, handler, async {
            let _ = stopped.await;
        })
        .await;
        say("podssh node", &format!("ended: {exit:?}"));
        config.pair
    };
    let session = async {
        let legs =
            Arc::new(Legs { relay: relay.clone(), trust: trust.clone(), name, token, current: Mutex::default(), say });
        let end = echo_until(&legs, &online, &costs, until, say).await;
        costs.lock().unwrap().end = end;
        let _ = stop.send(());
    };
    let (pair, ()) = tokio::join!(node, session);
    say("podssh", &format!("the pair is stopped: {:?}", pair::stop(&ctx, &pair).await));
    // The session's task may hold a copy still, when it did not end in time.
    let mut held = costs.lock().unwrap();
    std::mem::take(&mut *held)
}

/// The session: a byte each [`EVERY`] up and back, until `until`; how it
/// ended, in words.
async fn echo_until(
    legs: &Arc<Legs>,
    online: &AtomicBool,
    costs: &Arc<Mutex<Costs>>,
    until: Instant,
    say: Say,
) -> String {
    while !online.load(Ordering::SeqCst) {
        if Instant::now() > until {
            return "the node was never online".into();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let first = match legs.open().await {
        Ok(first) => first,
        Err(why) => return format!("no first leg: {why}"),
    };
    let client = match client::start(first, Ask::New, Settings::default().on_the_pair(), &mut OsEntropy).await {
        Ok(client) => client,
        Err(e) => return format!("no layer: {e}"),
    };
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let run = {
        let (legs, costs) = (legs.clone(), costs.clone());
        tokio::spawn(async move {
            let connect = move |ended: &Ended| {
                let (legs, moving) = (legs.clone(), matches!(ended.end, End::Moving));
                async move { legs.next(moving).await }
            };
            let note = move |note: Note| {
                match &note {
                    Note::Lost { .. } => costs.lock().unwrap().losses += 1,
                    Note::Resumed { after, .. } => costs.lock().unwrap().resumed.push(*after),
                    _ => {}
                }
                say("podssh session", &format!("{note:?}"));
            };
            resume::run(client, app_end, connect, note, &mut OsEntropy).await
        })
    };
    let mut ticker = tokio::time::interval(EVERY);
    let mut byte = [0u8; 1];
    while Instant::now() + EVERY < until {
        ticker.tick().await;
        if app.write_all(b"t").await.is_err() {
            break;
        }
        match tokio::time::timeout(ECHO_WAIT, app.read_exact(&mut byte)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return format!("the session ended: {e}"),
            Err(_) => {
                costs.lock().unwrap().missed += 1;
                say("podssh session", &format!("no echo within {} s", ECHO_WAIT.as_secs()));
            }
        }
    }
    let _ = app.shutdown().await;
    match tokio::time::timeout(STEP + NODE_ENDS, run).await {
        Ok(Ok(Outcome::Layer(ended))) => format!("{:?}", ended.end),
        Ok(Ok(other)) => format!("{other:?}"),
        Ok(Err(e)) => format!("its task: {e}"),
        Err(_) => "it did not end in time".into(),
    }
}
