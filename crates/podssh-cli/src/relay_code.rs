//! `podssh relay pair NAME --code` and `podssh relay join NAME` (T-086):
//! the operator's part of a pair moves by a short code, which a person reads
//! on the node's host and types on the operator's, in place of a file. The
//! node's host gives the pair stored under NAME while it has 10 minutes
//! left (else it makes the next one first), with the node's key, which the
//! operator pins under its label before the first session; the operator's
//! key comes back, and goes into the node's allowlist when `--allow FILE`
//! names it. The code shows on the giver's terminal alone, never on stdout,
//! in a log or in argv; the taker reads it at a prompt, or one line of a
//! pipe. The two ends meet at a mailbox (`podssh_relay::code`). The net's
//! invitation (T-616, `crate::net`) shows, reads and refuses its code by the
//! same calls.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::Path;
use std::sync::Arc;

use podssh_relay::cache::{self, Others};
use podssh_relay::code::exchange::{Done, Offer};
use podssh_relay::code::phrase::TYPED_MOST;
use podssh_relay::code::run::{self, Ends, Waits};
use podssh_relay::code::{self, Code, Failed};
use podssh_relay::identity::allow::Allowlist;
use podssh_relay::identity::pins::{self, Seen};
use podssh_relay::identity::{file, PublicKey};
use podssh_relay::pair::{self, OperatorPart, Pair};
use podssh_ws::dial::ProxyChoice;
use podssh_ws::url::WsUrl;
use zeroize::Zeroizing;

use crate::exitmap::Fault;
use crate::pairs;
use crate::relay_cmd::{block_on, RelayArgs};
use crate::relay_settings::Refusal;

/// A flag of the pairing by code given where it means nothing.
pub(crate) fn misplaced(args: &RelayArgs) -> Option<&'static str> {
    let sub = args.subcommand.as_deref();
    let giving = sub == Some("pair") && args.code;
    if args.code && (sub != Some("pair") || args.renew || args.operator_file.is_some()) {
        return Some("--code goes with `podssh relay pair NAME --code` alone, in place of --operator-file and --renew");
    }
    if args.allow.is_some() && !giving {
        return Some("--allow goes with `podssh relay pair NAME --code` only: the node's allowlist takes the key");
    }
    if args.pair_mailbox.is_some() && !giving && sub != Some("join") {
        return Some("--pair-mailbox goes with `podssh relay pair NAME --code` and `podssh relay join NAME` only");
    }
    if args.client_key.is_some() && sub != Some("join") {
        return Some("--client-key goes with `podssh relay join NAME` only");
    }
    None
}

/// `pair NAME --code`: the pair under NAME, given by a code to one operator.
pub(crate) fn give(args: &RelayArgs, label: &str, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Refusal> {
    pairs::check_label(label)?;
    let ends = ends(args)?;
    // Before any request: a run with no terminal could show the code nowhere.
    let Some(mut terminal) = Terminal::open() else {
        return Err(Refusal::usage(
            "--code shows the code on this run's terminal alone, and it has none: run it at a terminal, or give \
             the operator's part as a file with --operator-file FILE",
        ));
    };
    let allow = args.allow.as_deref().map(Path::new);
    if let Some(path) = allow {
        cache::read_own(path, Others::Read).map_err(|why| Refusal::config(format!("--allow {why}")))?;
    }
    crate::pins::apply(args.relay_addr.as_deref())?;
    pairs::online()?;
    let pair = living_or_made(args, label, err)?;
    let key = crate::channel::load_node_key(&file::node_place(label))?;
    let node = key.identity.public();
    if key.made {
        let _ = writeln!(err, "podssh relay: a new key for the node {label}: {node}");
    }
    let offer = Offer { label: label.to_string(), node, part: Some(OperatorPart::of(&pair)) };
    let minutes = code::LIFETIME.as_secs() / 60;
    let mut show = |made: &Code, mailbox: &str| {
        terminal.line(&format!(
            "podssh relay: the code for {label}, for one operator, valid for {minutes} minutes: {}",
            made.for_terminal()
        ));
        terminal.line(&format!(
            "podssh relay: on the operator's host, podssh relay join NAME, then type it (they meet at {mailbox})"
        ));
    };
    let mut said = None;
    let mut admit = |key: &PublicKey| {
        let (done, here) = admitted(allow, label, key);
        said = Some(here);
        done
    };
    let given = block_on(run::give(&ends, &Waits::default(), &offer, &mut show, &mut admit))?;
    let given = given.map_err(|failed| refusal(failed, "podssh relay pair NAME --code makes a new code"))?;
    if let Some(here) = said {
        let _ = writeln!(err, "podssh relay: {here}");
    }
    let _ = writeln!(out, "{label}: given to {}; expires {}", given.operator, pairs::utc(pair.expires_ms));
    Ok(())
}

/// The pair under `label` while it has 10 minutes left and `--once` asks
/// for no new one, said; else the next pair, made as `pair NAME` makes it.
fn living_or_made(args: &RelayArgs, label: &str, err: &mut dyn Write) -> Result<Pair, Refusal> {
    let enough = pairs::now_ms().saturating_add(podssh_relay::cache::MIN_REMAINING_MS);
    match pair::load(label) {
        Ok(Some(stored)) if stored.expires_ms > enough && !args.once => {
            let until = pairs::utc(stored.expires_ms);
            let _ = writeln!(err, "podssh relay: the pair stored under {label:?} goes, which expires at {until}");
            Ok(stored)
        }
        Ok(_) => crate::relay_cmd::make(args, label, &mut std::io::sink(), err),
        Err(e) => Err(pairs::refusal(&e)),
    }
}

/// What the node's host did with the operator's `key`: the words for the
/// operator, and its own line, which may name a path of this host.
fn admitted(allow: Option<&Path>, label: &str, key: &PublicKey) -> (Done, String) {
    let Some(path) = allow else {
        let said = format!(
            "the node {label} names no allowlist, so the pair's connect token is its door; give it --allow FILE \
             with this key's line to let the key in by name"
        );
        let here = format!("the operator's key is {key}; podssh node {label} --allow FILE lets it in by its line");
        return (Done { admitted: false, said }, here);
    };
    let shown = path.display();
    match add_line(path, key) {
        Ok(true) => {
            let said = format!("the node {label} lets this key in: its line is in the node's allowlist");
            (Done { admitted: true, said }, format!("the operator's key {key} is in {shown} now"))
        }
        Ok(false) => {
            let said = format!("the node {label} lets this key in: its allowlist named it already");
            (Done { admitted: true, said }, format!("the operator's key {key} was in {shown} already"))
        }
        Err(why) => {
            let said = format!("the node {label} could not add this key to its allowlist");
            (Done { admitted: false, said }, format!("the operator's key {key} is not in {shown}: {why}"))
        }
    }
}

/// Add `key`'s line to the allowlist at `path`, made with mode 0600 when it
/// is missing: `false` when a line names it already.
fn add_line(path: &Path, key: &PublicKey) -> Result<bool, String> {
    let text = cache::read_own(path, Others::Read)?.unwrap_or_default();
    if Allowlist::parse(&text).admits(key) {
        return Ok(false);
    }
    let start = if text.is_empty() || text.ends_with('\n') { "" } else { "\n" };
    let line = format!("{start}{} # paired by a code, {}\n", key.fingerprint(), pairs::utc(pairs::now_ms()));
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut written = options.open(path).map_err(|e| e.to_string())?;
    written.write_all(line.as_bytes()).and_then(|()| written.sync_all()).map_err(|e| e.to_string())?;
    Ok(true)
}

/// `join NAME`: the code typed, the node's part taken, its key pinned under
/// NAME, and this operator's key given.
pub(crate) fn join(args: &RelayArgs, label: &str, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Refusal> {
    pairs::check_label(label)?;
    if matches!(pair::load(label), Ok(Some(_))) {
        return Err(Refusal::config(format!(
            "a pair is stored under {label:?} on this host, which is its node's host: join under another label"
        )));
    }
    let ends = ends(args)?;
    let code = read_code(err, "podssh relay: the code that the node's host shows: ")?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    pairs::online()?;
    let say = |line: String| podssh_ssh::err_line!("podssh relay: {line}");
    let me = crate::channel::client_identity(args.client_key.as_deref(), &say).map_err(Refusal::config)?.public();
    let mut pinned = None;
    let mut check = |offer: &Offer| {
        if offer.part.is_none() {
            return Err("the node's host gave no pair: it has none to give".to_string());
        }
        match pins::check(label, &offer.node) {
            Ok(seen) => {
                pinned = Some(seen);
                Ok(())
            }
            Err(why) => Err(format!(
                "the node's key {} is not the one pinned for {label}: {why}; the part is not kept",
                offer.node
            )),
        }
    };
    let taken = block_on(run::take(&ends, &Waits::default(), &code, &me, &mut check))?;
    drop(code);
    let taken = taken.map_err(|failed| refusal(failed, "ask the node's host for a new code"))?;
    let Some(part) = taken.offer.part.as_ref() else { return Err(Refusal::config("the node's host gave no pair")) };
    pair::part::store(label, part).map_err(|e| Refusal::config(format!("the operator's part: {e}")))?;
    match pinned {
        Some(Seen::Pinned(path)) => {
            let _ = writeln!(
                err,
                "podssh relay: the node's key {} is pinned for {label} in {}",
                taken.offer.node,
                path.display()
            );
        }
        Some(Seen::NotPinned(why)) => {
            let _ = writeln!(err, "podssh relay: the node's key {} could not be pinned: {why}", taken.offer.node);
        }
        _ => {}
    }
    let _ = writeln!(err, "podssh relay: the node's host says: {}", taken.done.said);
    let _ = writeln!(
        out,
        "{label}: joined the node {} ({}); expires {}",
        taken.offer.label,
        taken.offer.node,
        pairs::utc(part.expires_ms)
    );
    Ok(())
}

/// The mailboxes of `--pair-mailbox` or of the variable, and how to reach
/// them; a line for each mailbox that fails.
fn ends(args: &RelayArgs) -> Result<Ends, Refusal> {
    let value = std::env::var(code::ENV).ok();
    let mailboxes = code::mailboxes(args.pair_mailbox.as_deref(), value.as_deref());
    ends_of(mailboxes, args.pair_mailbox.is_some(), args.ca_file.as_deref(), "podssh relay")
}

/// The ends of `mailboxes`, which `--pair-mailbox` gave when `named`, else
/// the variable, reached with the trust of `ca_file`; each line under `who`.
pub(crate) fn ends_of(
    mailboxes: Result<Vec<WsUrl>, String>,
    named: bool,
    ca_file: Option<&str>,
    who: &'static str,
) -> Result<Ends, Refusal> {
    let mailboxes = mailboxes.map_err(|why| if named { Refusal::usage(why) } else { Refusal::config(why) })?;
    let say: code::Say = Arc::new(move |line: String| podssh_ssh::err_line!("{who}: {line}"));
    Ok(Ends { mailboxes, trust: pairs::trust(ca_file), proxy: ProxyChoice::FromEnvironment, say })
}

/// The code, from a prompt on the terminal, or from one line of a pipe;
/// never from argv. A wrong one is refused with no word of it.
pub(crate) fn read_code(err: &mut dyn Write, prompt: &str) -> Result<Code, Refusal> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        let _ = write!(err, "{prompt}");
        let _ = err.flush();
    }
    let mut line = Zeroizing::new(String::new());
    let read = stdin.lock().take(TYPED_MOST as u64 + 1).read_line(&mut line);
    read.map_err(|e| Refusal::usage(format!("the code could not be read: {e}")))?;
    Code::parse(&line).map_err(Refusal::usage)
}

/// A failure of the pairing, with its code and the way that is left.
pub(crate) fn refusal(failed: Failed, way: &str) -> Refusal {
    let code = match failed {
        Failed::WrongCode | Failed::Nobody | Failed::Mine(_) => Fault::Auth.code(),
        Failed::Peer(_) => Fault::SessionFault.code(),
        Failed::NoRandom => Fault::Config.code(),
        Failed::Unreachable(_) | Failed::Refused(_) | Failed::Broken(_) | Failed::Expired(_) => {
            Fault::RelayUnreachable.code()
        }
    };
    let message = match failed {
        Failed::WrongCode | Failed::Nobody | Failed::Expired(_) => format!("{failed}; {way}"),
        other => other.to_string(),
    };
    Refusal { message, code }
}

/// Where the code goes: this run's terminal, and nowhere else.
pub(crate) enum Terminal {
    Stderr,
    Device(std::fs::File),
}

impl Terminal {
    /// stderr when it is a terminal, else the process's terminal device
    /// when it has one; `None` with neither.
    pub(crate) fn open() -> Option<Terminal> {
        if std::io::stderr().is_terminal() {
            return Some(Terminal::Stderr);
        }
        let device = if cfg!(windows) { "CONOUT$" } else { "/dev/tty" };
        std::fs::OpenOptions::new().write(true).open(device).ok().map(Terminal::Device)
    }

    pub(crate) fn line(&mut self, text: &str) {
        let _ = match self {
            Terminal::Stderr => writeln!(std::io::stderr(), "{text}"),
            Terminal::Device(device) => writeln!(device, "{text}"),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_or_spent_code_is_77_and_says_the_way_left() {
        let wrong = refusal(Failed::WrongCode, "ask for a new code");
        assert_eq!(wrong.code, 77);
        assert!(wrong.message.ends_with("; ask for a new code"), "{}", wrong.message);
        assert_eq!(refusal(Failed::Nobody, "x").code, 77);
        assert_eq!(refusal(Failed::Unreachable("m".into()), "x").code, 69);
        assert_eq!(refusal(Failed::Peer("p".into()), "x").message, "p");
    }

    #[test]
    fn a_key_goes_into_an_allowlist_once_and_its_file_is_private() {
        let dir = std::env::temp_dir().join(format!("podssh-relay-code-{}", std::process::id()));
        podssh_relay::cache::private_dir(&dir).unwrap();
        let path = dir.join("allow");
        let key = PublicKey([5; 32]);
        assert_eq!(add_line(&path, &key), Ok(true));
        assert_eq!(add_line(&path, &key), Ok(false), "a key that a line names is not added again");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.starts_with(&format!("{} # paired by a code, ", key.fingerprint())), "{text}");
        assert!(Allowlist::parse(&text).admits(&key));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let (done, here) = admitted(None, "lab", &key);
        assert!(!done.admitted && done.said.contains("connect token is its door"), "{}", done.said);
        assert!(here.contains(&key.fingerprint()));
        let (done, here) = admitted(Some(path.as_path()), "lab", &PublicKey([6; 32]));
        assert!(done.admitted && !done.said.contains(&dir.display().to_string()), "no path of this host goes out");
        assert!(here.contains(&path.display().to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
