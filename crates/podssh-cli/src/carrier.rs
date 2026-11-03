//! A carrier (T-595): the node's road over a byte stream that exists
//! already, for a host whose every road out is closed but that grants one
//! channel, such as the exec channel of a platform's own SSH. `--carrier
//! ADDR` names it at either end, in `pipe`'s words: `stdio` (or `-`), `fd:N`
//! (Unix) or `exec:CMD`, a program that the end which names it starts, with
//! no shell. The node (`node_carrier`) runs its socket of the reverse road on
//! the stream; the client's end runs the relay role's side of that socket in
//! its own process (`podssh_relay::serve::reverse::carrier`), and each
//! operator's leg is a pipe to that role. No relay, no pair and no token: the
//! stream is the door. NAME is a label alone, under which the client pins the
//! node's key. The clients of a node (`ssh`, `cp`, `scp` and `sftp`) share
//! one client for the command ([`shared`]): one program, one node, each
//! session a leg of its own, until the command ends ([`end_shared`]).

use std::io::{IsTerminal as _, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use podssh_relay::relay::Relay;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome, Wire};
use podssh_relay::serve::reverse::carrier::{self, Again, Door, Link, Role};
use podssh_ws::client::ConnectError;
use podssh_ws::{ProxyChoice, Trust};
use tokio::process::Child;

use crate::exitmap::Fault;
use crate::layered::{Carried, Line};
use crate::operator::OperatorArgs;
use crate::pipe::address::{self, Address};
use crate::relay_settings::Refusal;

/// The kinds of a carrier, as the refusals name them.
const KINDS: &str = "stdio (or -), fd:N (Unix) or exec:CMD";
/// How long the node may take to read a stream that was just started: a
/// program that logs in somewhere first, and a node that dials its TARGET.
const READY_LIMIT: Duration = Duration::from_secs(60);
/// How long the client waits for its Close to go out, then for the program
/// that carries the stream to end, before it ends it.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);
const CHILD_LIMIT: Duration = Duration::from_secs(5);
/// Each direction of the pipe between the layer and the leg.
const PIPE: usize = 256 * 1024;
/// How often a client of a stream with one life looks whether its node left.
const LOOK: Duration = Duration::from_millis(250);

/// The client that each leg of a command shares, once one asked for it.
static SHARED: Mutex<Option<Arc<Client>>> = Mutex::new(None);

/// `--carrier ADDR`: a local end of `pipe`, and only those.
pub(crate) fn parse(text: &str) -> Result<Address, Refusal> {
    match address::parse(text) {
        Ok(found @ (Address::Stdio | Address::Fd(_) | Address::Exec(_))) => Ok(found),
        Err(refusal) if text.starts_with("fd:") || text.starts_with("exec:") => {
            Err(Refusal::usage(format!("--carrier {}", refusal.message)))
        }
        _ => Err(Refusal::usage(format!("--carrier {text}: a carrier is a stream that exists already: {KINDS}"))),
    }
}

/// `--carrier ADDR` of a client of a node: [`parse`]'s, but stdio, as this
/// end's stdin and stdout are its own (`why`): stdio is the node's end.
pub(crate) fn for_a_client(text: &str, why: &str) -> Result<Address, Refusal> {
    let found = parse(text)?;
    if found == Address::Stdio {
        return Err(Refusal::usage(format!("--carrier {text}: {why}; name fd:N or exec:CMD")));
    }
    Ok(found)
}

/// A terminal on stdin is a person's keys, which a node would read as
/// frames: `--carrier stdio` is for a program's stream.
pub(crate) fn no_terminal(found: &Address, stdin_is_terminal: bool) -> Result<(), Refusal> {
    if *found == Address::Stdio && stdin_is_terminal {
        return Err(Refusal::usage(
            "--carrier stdio: stdin is a terminal, whose keys the node would read as frames; the program that \
             carries the stream starts the node, as ssh -T HOST podssh node --carrier stdio NAME TARGET",
        ));
    }
    Ok(())
}

pub(crate) fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

/// The stream of `found`, in a tokio runtime, and the program that carries
/// it when the end started one.
pub(crate) fn open(found: &Address) -> Result<(Link, Option<Child>), Refusal> {
    let end = crate::pipe::local::open(found)
        .map_err(|unopened| Refusal { message: format!("the carrier: {}", unopened.why), code: unopened.code })?;
    Ok((Box::new(tokio::io::join(end.read, end.write)), end.child))
}

/// The client's end of a carrier: the relay role's side of its node, in
/// this process, and the program that carries the stream now.
pub(crate) struct Client {
    door: Door,
    child: Arc<Mutex<Option<Child>>>,
    relay: Relay,
    trust: Trust,
    proxy: ProxyChoice,
    /// A stream that this end was given (`stdio`, `fd:N`), which nothing
    /// starts again: its end is the client's (T-596).
    one_life: bool,
}

impl Client {
    /// The stream of `found`, which `text` names, and the role over it; in
    /// a tokio runtime. A program is started again for the next link of a
    /// resume; a stream that this end was given has one life.
    pub(crate) fn start(text: &str, found: &Address) -> Result<Client, Refusal> {
        let (link, child) = open(found)?;
        let child = Arc::new(Mutex::new(child));
        let again: Option<Again> = match found {
            Address::Exec(_) => {
                let (found, child) = (found.clone(), child.clone());
                Some(Box::new(move || -> Result<Link, String> {
                    let (link, started) = open(&found).map_err(|refusal| refusal.message)?;
                    // The program of a stream that ended goes with it, and
                    // is reaped.
                    if let Some(mut old) = std::mem::replace(&mut *lock(&child), started) {
                        let _ = old.start_kill();
                        tokio::spawn(async move {
                            let _ = old.wait().await;
                        });
                    }
                    Ok(link)
                }))
            }
            _ => None,
        };
        let one_life = again.is_none();
        let role = Role::new(text, again, None).map_err(Refusal::config)?;
        role.attach(link).map_err(Refusal::config)?;
        let relay = Relay { host: carrier::NAME.into(), port: 0 };
        let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
        Ok(Client { door: Door::of(role), child, relay, trust, proxy, one_life })
    }

    /// Until the node left a stream that this end cannot start again, for a
    /// client that serves while the stream lives (`exit --listen`, T-596); a
    /// stream of `exec:` is started again for the next leg, so never.
    pub(crate) async fn left(&self) {
        if !self.one_life {
            return std::future::pending().await;
        }
        while self.door.role().joined() {
            tokio::time::sleep(LOOK).await;
        }
    }

    /// The operator's legs of this carrier: no relay, no token, the role in
    /// this process. The node's ready is a step of `--ConnectTimeout`, which
    /// does nothing with no watch.
    pub(crate) fn config(&self) -> OperatorConfig<'_> {
        OperatorConfig {
            relay: &self.relay,
            name: carrier::NAME,
            connect_token: "",
            trust: &self.trust,
            proxy: &self.proxy,
            timeout: READY_LIMIT,
            limits: OperatorLimits { on_ready: Some(crate::connect_bound::ready), ..OperatorLimits::default() },
            wire: Wire::Carrier(self.door),
        }
    }

    /// The end: the node hears a Close 1000, so that it exits 0, and the
    /// program that carries the stream is waited for, then ended.
    pub(crate) async fn finish(self) {
        self.end().await;
    }

    /// [`Client::finish`], for a client that the legs of a command share.
    pub(crate) async fn end(&self) {
        self.door.role().close(CLOSE_LIMIT).await;
        let child = lock(&self.child).take();
        if let Some(mut child) = child {
            if tokio::time::timeout(CHILD_LIMIT, child.wait()).await.is_err() {
                let _ = child.kill().await;
            }
        }
    }
}

/// The client of the carrier `text` that each leg of this command shares,
/// started at the first ask, in a tokio runtime: one program, one node, and
/// each session a leg of its own, until [`end_shared`]. A command names one
/// carrier, so a later ask takes the first client.
pub(crate) fn shared(text: &str) -> Result<Arc<Client>, Refusal> {
    let mut held = lock(&SHARED);
    if let Some(client) = held.as_ref() {
        return Ok(client.clone());
    }
    let found = parse(text)?;
    let client = Arc::new(Client::start(text, &found)?);
    *held = Some(client.clone());
    Ok(client)
}

/// The end of the shared client, when one started: the node hears its
/// Close, and the program of the stream ends. A second call does nothing.
pub(crate) async fn end_shared() {
    let client = lock(&SHARED).take();
    if let Some(client) = client {
        client.end().await;
    }
}

/// `podssh operator --carrier ADDR NAME`, and `podssh proxy --carrier ADDR
/// node://NAME` (T-587's pipe): stdin to the TARGET of the node at the other
/// end of the stream, and its bytes to stdout, as on the pair's road, with
/// the layer and the end-to-end channel; each line names `verb`.
pub(crate) fn operator(args: &OperatorArgs, verb: &'static str, err: &mut dyn Write) -> i32 {
    let (label, text, found, ask, bound) = match prepare(args) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report(verb, err),
    };
    // --ConnectTimeout (T-589): the node's read of the stream, its ready,
    // then the layer and the channel, each step named past the bound.
    let _bound = crate::connect_bound::watch(bound, verb, "the carrier's node did not read the stream");
    let say_line = |line: String| podssh_ssh::err_line!("podssh {verb}: {label}: {line}");
    // The node's key, pinned under NAME: a stream that something else
    // answers is seen.
    let channel = match ask.operator(crate::channel::Expect::Pinned(label.clone()), &say_line) {
        Ok(channel) => channel,
        Err(why) => return Refusal::config(why).report(verb, err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh {verb}: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    let say = |line: Line| {
        if let Line::Always(text) = line {
            podssh_ssh::err_line!("podssh {verb}: {label}: {text}");
        }
    };
    let ran = runtime.block_on(async {
        let client = Client::start(&text, &found)?;
        let carried = carry(&client, &label, verb, &say, channel).await;
        client.finish().await;
        carried
    });
    // A read on stdin may still be blocked in a helper thread.
    runtime.shutdown_background();
    match ran {
        Ok(carried) => match judged(&carried) {
            None => 0,
            Some((code, why)) => {
                let _ = writeln!(err, "podssh {verb}: {label}: {why}");
                code
            }
        },
        Err(refusal) => refusal.report(verb, err),
    }
}

/// stdin and stdout <-> the resumable layer <-> the operator's leg, a new
/// leg after each lost one, as on the pair's road.
async fn carry(
    client: &Client,
    label: &str,
    verb: &'static str,
    say: &(dyn Fn(Line) + Sync),
    channel: Option<crate::channel::Operator>,
) -> Result<Carried, Refusal> {
    let config = client.config();
    let (link, leg_end) = tokio::io::duplex(PIPE);
    let first = operator::start(&config, leg_end).await.map_err(|e| refusal_of(&e))?;
    crate::connect_bound::step("the node did not answer ready");
    // OpenSSH ends its ProxyCommand with SIGHUP (T-586).
    crate::hangup::take(crate::hangup::Which::All);
    let io = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    let shown = label.to_string();
    let pin_say = move |line: String| podssh_ssh::err_line!("podssh {verb}: {shown}: {line}");
    Ok(crate::layered::carry_through(&config, link, first, io, None, say, channel, pin_say).await)
}

/// What a run of `operator --carrier` needs once its command line is
/// checked: the label, the carrier in the user's words and as `pipe` reads
/// it, the channel's ask and the bound of `--ConnectTimeout`.
type Prepared = (String, String, Address, crate::channel::Ask, Option<Duration>);

/// The checks before anything starts: the carrier, the bound, NAME and its
/// route, the channel's flags; a relay's or a pair's flag has nothing to
/// apply to.
fn prepare(args: &OperatorArgs) -> Result<Prepared, Refusal> {
    let text = args.carrier.clone().unwrap_or_default();
    let found = for_a_client(&text, "stdin and stdout carry the session's bytes here")?;
    // A bad bound is refused before anything is read (T-589).
    let bound = crate::connect_bound::parse(args.connect_timeout.as_deref())?;
    let flags = [
        (args.pair_file.is_some(), "--pair-file"),
        (args.relay_addr.is_some(), "--relay-addr"),
        (args.ca_file.is_some(), "--ca-file"),
    ];
    if let Some((_, flag)) = flags.into_iter().find(|(given, _)| *given) {
        return Err(Refusal::usage(format!("{flag} is for a relay and its pair, and --carrier has neither")));
    }
    let name = args.name.clone().ok_or("missing NAME: the label of the node, under which its key is pinned")?;
    let (label, route) = crate::node::label_and_route(&name)?;
    let ask = crate::channel::Ask::of(args.client_key.as_deref(), None, args.node_key.as_deref(), args.no_e2e)
        .and_then(|ask| ask.to_route(route.as_deref()))
        .map_err(Refusal::usage)?;
    if args.no_e2e && args.client_key.is_some() {
        return Err(Refusal::usage(
            "--client-key is this operator's key in the end-to-end channel, which --no-e2e turns off",
        ));
    }
    crate::layered::own_deadline(args.resume_deadline.as_deref())?;
    // --no-resume as on the pair's road: no stream of exec: is started again
    // for a resume (T-612).
    crate::no_resume::ask(args.no_resume);
    Ok((label, text, found, ask, bound))
}

/// A first leg that did not open: a stream that ended or a node that never
/// read it (69); a role that this end could not make (78).
pub(crate) fn refusal_of(e: &ConnectError) -> Refusal {
    let code = match e {
        ConnectError::Config(_) => Fault::Config.code(),
        _ => Fault::RelayUnreachable.code(),
    };
    Refusal { message: e.to_string(), code }
}

/// How a session over a carrier ended: the exit code and the line that says
/// why, or `None` for a clean end.
pub(crate) fn judged(carried: &Carried) -> Option<(i32, String)> {
    // A refused key, or a changed node key, first.
    if let Some((fault, why)) = &carried.channel {
        return Some((fault.code(), why.clone()));
    }
    match carried {
        Carried { why: Some(why), .. } => Some((Fault::SessionFault.code(), why.clone())),
        Carried { why: None, signalled: true, .. } => None,
        Carried { why: None, leg: Some(outcome), .. } => ended(outcome),
        Carried { why: None, leg: None, .. } => {
            Some((Fault::RelayUnreachable.code(), "the carrier's node did not end the session in time".into()))
        }
    }
}

/// What a leg's end on a carrier says of a session that failed, for `podssh
/// ssh`, whose exit is the session's: nothing for a clean end.
pub(crate) fn said(outcome: &Outcome) -> Option<String> {
    ended(outcome).map(|(_, why)| why)
}

/// The words of a leg's end on a carrier, where the role's closes name the
/// stream, not a relay.
fn ended(outcome: &Outcome) -> Option<(i32, String)> {
    let unreachable = Fault::RelayUnreachable.code();
    Some(match outcome {
        Outcome::LocalEnd | Outcome::Ended { code: 1000, .. } => return None,
        Outcome::NeverReady { reason, .. } => (unreachable, format!("the node did not take the session: {reason}")),
        Outcome::Ended { code: 1011, reason } if reason.trim().eq_ignore_ascii_case("node disconnected") => {
            (unreachable, "the carrier's stream ended, and the session with it".into())
        }
        Outcome::Ended { code: code @ (1003 | 1008 | 1009), reason } => {
            (Fault::SessionFault.code(), format!("the session ended for a fault (close {code}): {reason}"))
        }
        Outcome::Ended { code, reason } => (unreachable, format!("the session ended (close {code}): {reason}")),
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_carrier_is_a_local_end_of_pipe_and_only_one() {
        assert_eq!(parse("stdio").unwrap(), Address::Stdio);
        assert_eq!(parse("-").unwrap(), Address::Stdio);
        let words = ["ssh", "-T", "box", "podssh", "node", "--carrier", "stdio", "lab"];
        let exec = Address::Exec(words.iter().map(|w| w.to_string()).collect());
        assert_eq!(parse("exec:ssh -T box podssh node --carrier stdio lab").unwrap(), exec);
        if cfg!(unix) {
            assert_eq!(parse("fd:3").unwrap(), Address::Fd(3));
        }
        for bad in ["tcp:127.0.0.1:22", "node:lab", "tcp-listen:2222", "relay:example.org:22", "nonsense", "fd:2"] {
            let refusal = parse(bad).unwrap_err();
            assert_eq!(refusal.code, 64, "{bad}");
            assert!(refusal.message.starts_with("--carrier "), "{bad}: {}", refusal.message);
        }
        assert!(parse("tcp:127.0.0.1:22").unwrap_err().message.contains(KINDS));
        assert!(parse("exec:").unwrap_err().message.contains("names no program"));
    }

    #[test]
    fn a_client_of_a_node_takes_no_stdio_which_is_its_own() {
        let refusal = for_a_client("stdio", "its own").unwrap_err();
        assert_eq!(refusal.code, 64);
        assert!(refusal.message.starts_with("--carrier stdio: its own; name fd:N or exec:CMD"), "{}", refusal.message);
        assert_eq!(for_a_client("-", "its own").unwrap_err().code, 64);
        assert_eq!(for_a_client("exec:cat", "its own").unwrap(), Address::Exec(vec!["cat".into()]));
        assert_eq!(for_a_client("tcp:127.0.0.1:22", "its own").unwrap_err().code, 64);
    }

    #[test]
    fn a_terminal_on_stdin_is_refused_for_stdio_alone() {
        assert_eq!(no_terminal(&Address::Stdio, true).unwrap_err().code, 64);
        assert!(no_terminal(&Address::Stdio, false).is_ok());
        assert!(no_terminal(&Address::Exec(vec!["cat".into()]), true).is_ok(), "a program's stream is its own");
    }

    #[test]
    fn the_end_of_a_leg_names_the_stream_and_a_clean_end_is_none() {
        assert_eq!(ended(&Outcome::LocalEnd), None);
        assert_eq!(ended(&Outcome::Ended { code: 1000, reason: String::new() }), None);
        let lost = ended(&Outcome::Ended { code: 1011, reason: "node disconnected".into() }).unwrap();
        assert_eq!(lost.0, 69);
        assert!(lost.1.contains("the carrier's stream ended"), "{}", lost.1);
        assert!(!lost.1.contains("relay"), "no relay on a carrier: {}", lost.1);
        assert_eq!(ended(&Outcome::Ended { code: 1009, reason: "frame byte cap".into() }).unwrap().0, 70);
        let never = ended(&Outcome::NeverReady { code: Some(1013), reason: "node open timeout".into() }).unwrap();
        assert_eq!(never.0, 69);
    }
}
