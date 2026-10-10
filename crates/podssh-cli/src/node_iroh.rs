//! `podssh node NAME TARGET --iroh` (T-163): the node in front of the TCP
//! service TARGET, over the iroh road. Its key is its identity, kept in a
//! private file and shown by its public half; its ticket (`iroh:...`),
//! printed when it starts and again when its home relay changes, is its
//! address. A client gets in only when its key is in the file of
//! `--iroh-allow`, read again for each connection. With the pair NAME, or
//! the one of `--pair-file`, the node serves the pair's road too, with one
//! keeper of sessions for both, so that a session resumes on either road
//! (T-164). Each session runs the resumable layer, and reaches TARGET only
//! after its handshake. stdout stays empty: the lines are on stderr.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use iroh::{PublicKey, RelayUrl};
use podssh_iroh::keys::{self, Place};
use podssh_iroh::{ticket, Allowlist, Options, Udp};
use podssh_relay::pair::Pair;
use podssh_relay::reverse::{self, Layered, NodeConfig, TcpHandler, Wire};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::{OsEntropy, Settings};
use podssh_ws::{ProxyChoice, Trust};
use tokio::sync::watch;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// How long the node may take to have a home relay: with none, no client
/// can reach it.
const ONLINE_LIMIT: Duration = Duration::from_secs(30);
/// How long the endpoint may take to close when the node stops.
const CLOSE_LIMIT: Duration = Duration::from_secs(5);

/// Run the node; returns the process exit code.
pub fn run(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    let ready = match prepare(args) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("node", err),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh node: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    // On the heap, as each large future here: Windows gives the main
    // thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(serve(ready, err)));
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

/// Each check that needs no network, in order.
struct Ready {
    label: String,
    host: String,
    port: u16,
    place: Place,
    allow: Option<PathBuf>,
    relays: Vec<RelayUrl>,
    trust: Trust,
    /// The pair's road: the pair, and whether it came from the store; or
    /// why there is none.
    pair: Result<(Pair, bool), String>,
    /// The end-to-end channel on both roads (T-088); off with `--no-e2e`.
    e2e: bool,
}

fn prepare(args: &NodeArgs) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    let target = args.target.as_deref().ok_or("missing TARGET: the HOST:PORT that each session reaches")?;
    let (host, port) =
        crate::proxy::parse_target(Some(target), None).map_err(|why| Refusal::usage(format!("TARGET: {why}")))?;
    // One key for both roads (T-087), by the flags' names of T-087 or T-163.
    let flags = crate::node::key_flags(args)?;
    let place: Place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    // A bad flag is a usage error, a bad variable a configuration error.
    let relays = match podssh_iroh::relays::from_environment(args.iroh_relay.as_deref()) {
        Ok((relays, _)) => relays,
        Err(why) if args.iroh_relay.is_some() => return Err(Refusal::usage(why)),
        Err(why) => return Err(Refusal::config(why)),
    };
    crate::pins::apply(args.relay_addr.as_deref())?;
    // A pair that `--pair-file` names must be good; a stored one may be
    // missing or expired, and the node then serves the iroh road alone.
    let pair = match &args.pair_file {
        Some(file) => Ok((crate::pairs::usable(crate::pairs::from_file(file)?, &label)?, false)),
        None => crate::pairs::stored(&label).map(|pair| (pair, true)).map_err(|refusal| refusal.message),
    };
    crate::pairs::online()?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    let allow = flags.allow;
    Ok(Ready { label, host, port, place, allow, relays, trust, pair, e2e: !args.no_e2e })
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, host, port, place, allow, relays, trust, pair, e2e } = ready;
    // The pair's road needs these after the iroh road has taken its own.
    let (label_text, host_pair, trust_pair) = (label.clone(), host.clone(), trust.clone());
    let target = podssh_ws::dial::authority(&host, port);
    let proxy = ProxyChoice::FromEnvironment;
    // TARGET first: a node that cannot reach it would serve no session.
    match podssh_ws::dial::dial(&host, port, &proxy, DIAL_LIMIT).await {
        Ok(probe) => drop(probe),
        Err(e) => {
            let refusal = Refusal { message: format!("TARGET {target}: {e}"), code: Fault::RelayUnreachable.code() };
            return refusal.report("node", err);
        }
    }
    let key = match keys::load(&place, &mut OsEntropy) {
        Ok(key) => key,
        Err(why) => return Refusal::config(format!("the node's key: {why}")).report("node", err),
    };
    // The first relay of the list that answers `/ping` is the home relay,
    // and the ticket names it for the run (T-165).
    let (home, missed) = podssh_iroh::relays::home(&relays, &trust, &proxy).await;
    for why in &missed {
        let _ = writeln!(err, "podssh node: {label}: an iroh relay did not answer: {why}");
    }
    let options = Options {
        relays: home,
        proxy,
        trust,
        udp: Udp::from_environment(),
        secret: Some(key.secret.clone()),
        accepts: true,
        ..Options::default()
    };
    let endpoint = match Box::pin(podssh_iroh::bind(&options)).await {
        Ok(endpoint) => endpoint,
        Err(e) => return Refusal::config(e.to_string()).report("node", err),
    };
    let relay = match tokio::time::timeout(ONLINE_LIMIT, endpoint.online()).await {
        Ok(()) => ticket::home_relay(&endpoint),
        Err(_) => None,
    };
    let Some(relay) = relay else {
        let relays: Vec<String> = relays.iter().map(ToString::to_string).collect();
        let refusal = Refusal {
            message: format!(
                "no iroh relay answered within {} s ({}); podssh doctor checks the way to them",
                ONLINE_LIMIT.as_secs(),
                relays.join(", ")
            ),
            code: Fault::RelayUnreachable.code(),
        };
        let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
        return refusal.report("node", err);
    };
    let fingerprint = keys::fingerprint(&key.public());
    let kept = match (&key.path, key.made) {
        (None, _) => "a key for this run only: the ticket lasts as long as the run".to_string(),
        (Some(path), true) => format!("a new key, in {}: the ticket is new", path.display()),
        (Some(path), false) => format!("in {}", path.display()),
    };
    let roads = match &pair {
        Ok((pair, _)) => format!(
            "the iroh road and the pair's road through {} (the pair expires {})",
            pair.relay.host,
            crate::pairs::utc(pair.expires_ms)
        ),
        Err(why) => format!("the iroh road alone ({why})"),
    };
    let _ = writeln!(err, "podssh node: {label}: serving {target} over {roads} until Ctrl-C");
    let _ =
        writeln!(err, "podssh node: {label}: key {fingerprint}, the node iroh:{} ({kept})", keys::name(&key.public()));
    let _ = writeln!(err, "podssh node: {label}: ticket {}", ticket::of(&endpoint, &relay));
    let _ = writeln!(err, "podssh node: {label}: {}", who_may(allow.as_deref()));
    // The channel of T-088 on both roads, with this node's key: a session
    // made on one road may resume on the other, so each session has it. On
    // the pair's road with no allowlist, each operator with the connect
    // token comes in.
    let channel = match e2e {
        true => Some(crate::channel::node_end(
            &label,
            podssh_relay::identity::Identity::from_seed(&key.identity.seed()),
            crate::channel::admit_of(allow.clone()),
        )),
        false => {
            let _ = writeln!(err, "podssh node: {label}: no end-to-end channel (--no-e2e): the relay sees each byte");
            None
        }
    };

    let say = move |line: String| eprintln!("podssh node: {label}: {line}");
    // A client needs the new ticket when the home relay changes.
    let follow = tokio::spawn(ticket::follow(endpoint.clone(), Some(relay), {
        let say = say.clone();
        move |ticket| say(format!("the home relay changed; the ticket is now {ticket}"))
    }));
    let admit = {
        let say = say.clone();
        move |key: &PublicKey| admits(allow.as_deref(), key, &say)
    };
    // Each session of either road is a pipe (T-164): with the channel, TARGET
    // is dialled once the operator's key is let in.
    let open = {
        let channel = channel.clone();
        move || {
            let (host, channel) = (host.clone(), channel.clone());
            async move {
                let dial = move || async move {
                    podssh_ws::dial::dial(&host, port, &ProxyChoice::FromEnvironment, DIAL_LIMIT)
                        .await
                        .map_err(|e| e.to_string())
                };
                crate::channel::piped(channel, dial).await
            }
        }
    };
    let settings = Settings { features: podssh_iroh::FEATURES, ..crate::layered::settings() };
    let budget = podssh_relay::reverse::layered::NODE_BUDGET;
    // One keeper for both roads: a session resumes on either (T-164).
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let (stop, stopped) = watch::channel(false);
    let until_stopped = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let iroh_road = async {
        tokio::select! {
            () = Box::pin(podssh_iroh::far::serve_kept(endpoint.clone(), settings, budget, open, admit, keeper.clone())) => {}
            () = until_stopped(stopped.clone()) => {}
        }
    };
    let pair_road = async {
        let Ok((pair, stored)) = pair else { return };
        let say_pair = |line: String| say(line);
        let proxy = ProxyChoice::FromEnvironment;
        let mut config = NodeConfig {
            pair,
            label: stored.then(|| label_text.clone()),
            trust: &trust_pair,
            proxy: &proxy,
            timeout: crate::pairs::REQUEST_LIMIT,
            settings: reverse::Settings {
                rejoin: crate::layered::settings().resume_deadline,
                ..reverse::Settings::default()
            },
            repair: None,
            wire: Wire::Tls,
            say: Some(&say_pair),
        };
        let tcp = TcpHandler { host: host_pair.clone(), port, timeout: DIAL_LIMIT };
        let piped = crate::channel::Piped { inner: Arc::new(tcp), channel: channel.clone() };
        let layered = Layered::with_keeper(piped, crate::layered::settings(), budget, keeper.clone());
        let exit = Box::pin(reverse::run(&mut config, Arc::new(layered), until_stopped(stopped.clone()))).await;
        if let Some((_, why)) = crate::node::ended(&label_text, exit) {
            say(format!("the pair's road ended: {why}; the iroh road goes on"));
        }
    };
    let signal = async {
        crate::node::stop_signal().await;
        let _ = stop.send(true);
    };
    tokio::join!(iroh_road, pair_road, signal);
    follow.abort();
    let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
    say("stopped".into());
    0
}

/// Who may connect, as the node starts.
fn who_may(allow: Option<&std::path::Path>) -> String {
    let Some(path) = allow else {
        return "no client may connect over the iroh road: --allow FILE names the client keys that may, one on each line".into();
    };
    match Allowlist::read(path) {
        Ok(list) if list.bad_lines().is_empty() => {
            format!("{} client keys may connect ({})", list.len(), path.display())
        }
        Ok(list) => format!(
            "{} client keys may connect ({}); lines {} are not keys",
            list.len(),
            path.display(),
            lines(list.bad_lines())
        ),
        Err(why) => format!("no client may connect yet: {why}"),
    }
}

/// Whether the client `key` may connect: the allowlist is read again for
/// each connection, so a key added counts at once. A refusal is said with
/// the key, which is the line to add.
fn admits(allow: Option<&std::path::Path>, key: &PublicKey, say: &impl Fn(String)) -> bool {
    let shown = keys::fingerprint(key);
    let Some(path) = allow else {
        say(format!("refused the client key {shown}: no --allow file"));
        return false;
    };
    match Allowlist::read(path) {
        Ok(list) if list.admits(key) => {
            say(format!("the client key {shown} connected"));
            true
        }
        Ok(_) => {
            say(format!("refused the client key {shown}: it is not in {}", path.display()));
            false
        }
        Err(why) => {
            say(format!("refused the client key {shown}: {why}"));
            false
        }
    }
}

fn lines(numbers: &[usize]) -> String {
    numbers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}
