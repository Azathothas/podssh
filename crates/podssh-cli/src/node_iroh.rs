//! `podssh node NAME TARGET --iroh` (T-163): the node in front of the TCP
//! service TARGET, over the iroh road, with no pair. Its key is its
//! identity, kept in a private file and shown by its public half; its
//! ticket (`iroh:...`), printed when it starts and again when its home relay
//! changes, is its address. A client gets in only when its key is in the
//! file of `--iroh-allow`, read again for each connection. Each session runs
//! the resumable layer, and reaches TARGET only after its handshake. stdout
//! stays empty: the lines are on stderr.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use iroh::{PublicKey, RelayUrl};
use podssh_iroh::keys::{self, Place};
use podssh_iroh::{ticket, Allowlist, Options, Udp};
use podssh_relay::session::{OsEntropy, Settings};
use podssh_ws::{ProxyChoice, Trust};

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
    let code = runtime.block_on(serve(ready, err));
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
}

fn prepare(args: &NodeArgs) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    let target = args.target.as_deref().ok_or("missing TARGET: the HOST:PORT that each session reaches")?;
    let (host, port) =
        crate::proxy::parse_target(Some(target), None).map_err(|why| Refusal::usage(format!("TARGET: {why}")))?;
    if args.pair_file.is_some() {
        return Err(Refusal::usage("--pair-file is for the reverse road; the iroh road needs no pair"));
    }
    let place = match (&args.iroh_key, args.iroh_ephemeral) {
        (Some(_), true) => {
            return Err(Refusal::usage("--iroh-ephemeral keeps the key in no file, and --iroh-key names one"))
        }
        (Some(file), false) => Place::File(file.into()),
        (None, true) => Place::Ephemeral,
        (None, false) => Place::Cache(keys::node_file(&label)),
    };
    // A bad flag is a usage error, a bad variable a configuration error.
    let relays = match podssh_iroh::relays::from_environment(args.iroh_relay.as_deref()) {
        Ok((relays, _)) => relays,
        Err(why) if args.iroh_relay.is_some() => return Err(Refusal::usage(why)),
        Err(why) => return Err(Refusal::config(why)),
    };
    crate::pins::apply(args.relay_addr.as_deref())?;
    crate::pairs::online()?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    Ok(Ready { label, host, port, place, allow: args.iroh_allow.as_ref().map(PathBuf::from), relays, trust })
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, host, port, place, allow, relays, trust } = ready;
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
        udp: Udp::Probe,
        secret: Some(key.secret.clone()),
        accepts: true,
        ..Options::default()
    };
    let endpoint = match podssh_iroh::bind(&options).await {
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
    let _ = writeln!(err, "podssh node: {label}: serving {target} over the iroh road until Ctrl-C");
    let _ = writeln!(err, "podssh node: {label}: key {fingerprint} ({kept})");
    let _ = writeln!(err, "podssh node: {label}: ticket {}", ticket::of(&endpoint, &relay));
    let _ = writeln!(err, "podssh node: {label}: {}", who_may(allow.as_deref()));

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
    let open = move || {
        let host = host.clone();
        async move {
            podssh_ws::dial::dial(&host, port, &ProxyChoice::FromEnvironment, DIAL_LIMIT)
                .await
                .map_err(|e| e.to_string())
        }
    };
    let settings = Settings { features: podssh_iroh::FEATURES, ..crate::layered::settings() };
    let budget = podssh_relay::reverse::layered::NODE_BUDGET;
    tokio::select! {
        () = podssh_iroh::far::serve(endpoint.clone(), settings, budget, open, admit) => {}
        () = crate::node::stop_signal() => {}
    }
    follow.abort();
    let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
    say("stopped".into());
    0
}

/// Who may connect, as the node starts.
fn who_may(allow: Option<&std::path::Path>) -> String {
    let Some(path) = allow else {
        return "no client may connect: --iroh-allow FILE names the client keys that may, one on each line".into();
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
        say(format!("refused the client key {shown}: no --iroh-allow file"));
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
