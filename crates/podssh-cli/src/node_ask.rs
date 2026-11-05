//! `podssh node NAME --ask` (T-638, GitHub #136): a person at the node's
//! terminal lets each operator key in, after the node's door, on each road of
//! the node. The node asks on stderr and reads the answer on stdin: each must
//! be a terminal, which the start probes, and with none `--ask` is refused
//! (78), as a flag that asks for a person must say at once that none is
//! there. A process is one node, so its gate is the process's
//! (`podssh_relay::e2e::person`), and each road's channel takes it
//! (`crate::channel::node_end`).
//!
//! One question shows at a time, and a line typed before it is no answer: a
//! thread of its own reads stdin from the start, each line with the time it
//! came, so a `y` typed for nothing never answers the next key. The thread
//! is no helper program: it is this process reading its own stdin.

use std::io::{BufRead, IsTerminal as _};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use podssh_relay::e2e::person::{Answer, Asker, Gate, Question, Times};
use podssh_relay::e2e::{exit_word, Ask};
use podssh_relay::identity::PublicKey;
use tokio::sync::{mpsc, Mutex};

use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The gate of this process's node, once `--ask` set it.
static GATE: OnceLock<Arc<Gate>> = OnceLock::new();

/// Why `--ask` cannot ask here.
const NO_TERMINAL: &str = "--ask asks a person at this node's terminal, on stderr, and reads the answer on stdin, \
                           and here they are not both a terminal: run the node in one, or with no --ask";

/// A line of stdin, and when it came.
type Line = (Instant, String);

/// The lines of stdin, for one question at a time.
type Lines = Mutex<mpsc::UnboundedReceiver<Line>>;

/// The gate of this node's person, when `--ask` set one: each road's
/// channel takes it.
pub fn gate() -> Option<Arc<Gate>> {
    GATE.get().cloned()
}

/// `--ask` of `args`: its flags (64), then the probe of the terminal (78);
/// then the gate is the process's, with its reader of stdin, and the node
/// says how it asks. Nothing of it with no `--ask`.
pub fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if !args.ask {
        return Ok(());
    }
    flags(args)?;
    probe(std::io::stdin().is_terminal(), std::io::stderr().is_terminal())?;
    let label = args.name.clone().unwrap_or_default();
    let _ = GATE.set(Gate::new(asker(label.clone())));
    let times = Times::DEFAULT;
    podssh_ssh::err_line!(
        "podssh node: {label}: asks at this terminal: each operator key that the door or a grant lets in waits \
         for y or n here, {} s, and no answer is a no; a yes lets the key in while one of its sessions is open \
         and {} s after its last, and a no stands {} s",
        times.question.as_secs(),
        times.cover.as_secs(),
        times.stands.as_secs()
    );
    Ok(())
}

/// The flags with which no person could answer (64), before anything is
/// probed.
pub fn flags(args: &NodeArgs) -> Result<(), Refusal> {
    let stdio = matches!(args.carrier.as_deref(), Some("stdio" | "-"));
    let refused = [
        (args.detach, "--detach", "a node in the background has no terminal to ask at"),
        (args.install, "--install", "a service has no terminal to ask at"),
        (args.uninstall, "--uninstall", "it serves nothing to ask of"),
        (args.temporary.is_some(), "--temporary", "nobody is at the far end of an upgrade to answer"),
        (args.no_e2e, "--no-e2e", "the person is asked of each operator key, which the end-to-end channel proves"),
        (stdio, "--carrier stdio", "stdin is then the stream, where the answers would come"),
    ];
    match refused.iter().find(|(given, ..)| *given) {
        Some((_, flag, why)) => Err(Refusal::usage(format!("--ask with {flag}: {why}"))),
        None => Ok(()),
    }
}

/// The probe's verdict: stdin and stderr each a terminal, else 78.
pub fn probe(stdin: bool, stderr: bool) -> Result<(), Refusal> {
    match stdin && stderr {
        true => Ok(()),
        false => Err(Refusal::config(NO_TERMINAL)),
    }
}

/// The asker of the node's person at this terminal: a thread reads stdin
/// from now on, and each question waits for its turn on the terminal.
fn asker(label: String) -> Arc<Asker> {
    let (tx, rx) = mpsc::unbounded_channel();
    let reader = label.clone();
    let started = std::thread::Builder::new().name("podssh-ask".into()).spawn(move || read_lines(&reader, tx));
    if let Err(e) = started {
        // Its sender went with the thread that never ran: each question is a no.
        podssh_ssh::err_line!("podssh node: {label}: stdin cannot be read ({e}): each operator key is refused");
    }
    let lines: Arc<Lines> = Arc::new(Mutex::new(rx));
    Arc::new(move |question: Question| -> Answer {
        let (label, lines) = (label.clone(), lines.clone());
        Box::pin(async move { ask(&label, question, &lines).await })
    })
}

/// Each line of stdin, with the time it came, until stdin ends.
fn read_lines(label: &str, tx: mpsc::UnboundedSender<Line>) {
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if tx.send((Instant::now(), line.trim().to_string())).is_err() {
                    return;
                }
            }
        }
    }
    podssh_ssh::err_line!(
        "podssh node: {label}: stdin ended, so nobody can answer: each operator key that comes now is refused"
    );
}

/// One question on the terminal; the next waits its turn, within its own
/// limit, which the gate holds.
async fn ask(label: &str, question: Question, lines: &Lines) -> Result<(), String> {
    let end = Instant::now() + question.limit;
    let mut lines = lines.lock().await;
    let shown = Instant::now();
    let left = end.saturating_duration_since(shown);
    podssh_ssh::err_line!("podssh node: {label}: {}", words(&question, member_of(&question.key), left));
    loop {
        let Some((at, line)) = lines.recv().await else {
            return Err("stdin ended, so nobody can answer, which is a no".into());
        };
        // A line typed before the question showed is no answer to it.
        if at < shown {
            continue;
        }
        match answer_of(&line) {
            Some(true) => return Ok(()),
            Some(false) => return Err("the node's person said no".into()),
            None => {
                let left = end.saturating_duration_since(Instant::now()).as_secs();
                podssh_ssh::err_line!("podssh node: {label}: answer y or n, within {left} s");
            }
        }
    }
}

/// A line as an answer: y or yes, n or no, in any case; else none.
pub fn answer_of(line: &str) -> Option<bool> {
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

/// The words of a question: the key, its name in the net, what it asks, how
/// it came through the door, and the time left to answer.
pub fn words(question: &Question, member: Option<String>, left: Duration) -> String {
    let who = member.map(|name| format!(", {name},")).unwrap_or_default();
    let what = match &question.ask {
        Ask::Target => "the node's target".to_string(),
        Ask::Route(route) => format!("the route {route}"),
        Ask::Exit { host, port } => format!("{} through this exit", exit_word(host, *port)),
    };
    let door = if question.granted { " with a grant, which holds" } else { ", which the door lets in" };
    let (key, left) = (question.key, left.as_secs());
    format!("the operator key {key}{who} asks for {what}{door}: let it in? y or n, within {left} s")
}

/// The key's name in the net held here, for the question; none for a key
/// that it does not name.
fn member_of(key: &PublicKey) -> Option<String> {
    let held = crate::net::store::held_or_none()?;
    let doc = &held.signed.doc;
    let member = doc.member_of_key(key)?;
    // The owner signed the names; the terminal still gets no control byte.
    let clean = podssh_ws::text::one_line;
    Some(format!("the member {} of the net {}", clean(&member.name), clean(&doc.name)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_relay::identity::Identity;

    #[test]
    fn the_flags_with_which_no_person_could_answer_are_refused_with_64() {
        let targets = vec!["127.0.0.1:22".into()];
        let ask = NodeArgs { name: Some("lab".into()), targets, ask: true, ..NodeArgs::default() };
        assert!(flags(&ask).is_ok(), "--ask alone");
        assert!(flags(&NodeArgs { carrier: Some("fd:3".into()), ..ask.clone() }).is_ok(), "a carrier off stdin");
        for (args, flag) in [
            (NodeArgs { detach: true, ..ask.clone() }, "--detach"),
            (NodeArgs { install: true, ..ask.clone() }, "--install"),
            (NodeArgs { uninstall: true, ..ask.clone() }, "--uninstall"),
            (NodeArgs { temporary: Some("k".into()), ..ask.clone() }, "--temporary"),
            (NodeArgs { no_e2e: true, ..ask.clone() }, "--no-e2e"),
            (NodeArgs { carrier: Some("stdio".into()), ..ask.clone() }, "--carrier stdio"),
            (NodeArgs { carrier: Some("-".into()), ..ask.clone() }, "--carrier stdio"),
        ] {
            let refusal = match flags(&args) {
                Ok(()) => panic!("{flag} passed"),
                Err(refusal) => refusal,
            };
            assert_eq!(refusal.code, 64, "{flag}");
            assert!(refusal.message.starts_with(&format!("--ask with {flag}:")), "{}", refusal.message);
        }
    }

    #[test]
    fn a_node_with_no_terminal_to_ask_at_is_refused_with_78() {
        assert!(probe(true, true).is_ok());
        for (stdin, stderr) in [(false, true), (true, false), (false, false)] {
            let refusal = match probe(stdin, stderr) {
                Ok(()) => panic!("{stdin} {stderr} passed"),
                Err(refusal) => refusal,
            };
            assert_eq!(refusal.code, 78);
            assert!(refusal.message.contains("--ask") && refusal.message.contains("terminal"), "{}", refusal.message);
        }
    }

    #[test]
    fn a_node_with_no_ask_sets_no_gate() {
        assert!(check(&NodeArgs::default()).is_ok());
        assert!(gate().is_none(), "no test of this binary sets the process's gate");
    }

    #[test]
    fn an_answer_is_y_or_n_in_any_case() {
        for yes in ["y", "Y", "yes", " YES ", "Yes\r"] {
            assert_eq!(answer_of(yes), Some(true), "{yes:?}");
        }
        for no in ["n", "N", "no", "No "] {
            assert_eq!(answer_of(no), Some(false), "{no:?}");
        }
        for neither in ["", "yy", "maybe", "y n", "ok"] {
            assert_eq!(answer_of(neither), None, "{neither:?}");
        }
    }

    #[test]
    fn the_question_names_the_key_its_member_what_it_asks_and_how_it_came() {
        let key = Identity::from_seed(&[9; 32]).public();
        let route = Question { key, ask: Ask::Route("web".into()), granted: false, limit: Duration::from_secs(100) };
        let member = Some("the member laptop of the net home".to_string());
        let text = words(&route, member, Duration::from_secs(97));
        let named = format!("the operator key {key}, the member laptop of the net home, asks");
        assert!(text.starts_with(&named), "{text}");
        assert!(text.contains("the route web, which the door lets in"), "{text}");
        assert!(text.ends_with("y or n, within 97 s"), "{text}");
        let exit = Question { ask: Ask::Exit { host: "2001:db8::1".into(), port: 22 }, granted: true, ..route };
        let text = words(&exit, None, Duration::from_secs(100));
        assert!(text.contains(&format!("{key} asks for [2001:db8::1]:22 through this exit with a grant")), "{text}");
    }
}
