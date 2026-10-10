//! What `podssh chat` was asked (T-099), and its checks that need no
//! network: who the peer is, which side this is, the keys of the channel,
//! and the one thing of a script.

use std::path::{Path, PathBuf};

use clap::ArgMatches;
use podssh_core::chat::record::{MAX_NICK, MAX_TEXT};
use podssh_relay::identity::file::Place;

use super::converse::{Once, Options};
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_NOINPUT};
use crate::relay_settings::Refusal;

/// What `podssh chat` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChatArgs {
    /// NAME, `node:NAME`, `node://NAME` or `iroh:TICKET`; with `--listen`,
    /// the label of the pair that this side serves.
    pub peer: Option<String>,
    pub send: Option<String>,
    pub sendfile: Option<String>,
    pub file: Option<String>,
    pub accept_dir: Option<String>,
    pub nick: Option<String>,
    /// This side waits, as the node of the pair.
    pub listen: bool,
    /// With `--listen`: the iroh road too.
    pub iroh: bool,
    /// The key of the side that waits.
    pub key: Option<String>,
    pub ephemeral_key: bool,
    /// The keys that may reach the side that waits.
    pub allow: Option<String>,
    /// The key of the side that reaches.
    pub client_key: Option<String>,
    /// The key of the side that waits, in place of the pins.
    pub node_key: Option<String>,
    pub pair_file: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    pub iroh_relay: Option<String>,
}

impl ChatArgs {
    pub fn from_matches(m: &ArgMatches) -> ChatArgs {
        let get = |id: &str| m.get_one::<String>(id).cloned();
        ChatArgs {
            peer: get("peer"),
            send: get("send"),
            sendfile: get("sendfile"),
            file: get("file"),
            accept_dir: get("accept-dir"),
            nick: get("nick"),
            listen: m.get_flag("listen"),
            iroh: m.get_flag("iroh"),
            key: get("key"),
            ephemeral_key: m.get_flag("ephemeral-key"),
            allow: get("allow"),
            client_key: get("client-key"),
            node_key: get("node-key"),
            pair_file: get("pair-file"),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
            iroh_relay: get("iroh-relay"),
        }
    }
}

/// The peer, as PEER names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Peer {
    /// The node of the pair under this label.
    Pair(String),
    /// A node of the iroh road: its ticket, `iroh:` and all.
    Iroh(String),
}

/// Which side this is.
pub(super) enum Side {
    /// `--listen`: the node of the pair `label`, with its key and allowlist.
    Listen { label: String, place: Place, allow: Option<PathBuf>, iroh: bool },
    /// The side that reaches the peer, with its channel's flags.
    Reach { peer: Peer, ask: crate::channel::Ask },
}

/// Where the user's lines come from.
pub(super) enum Input {
    Stdin,
    /// `--sendfile`: the file, open.
    File(std::fs::File),
    /// `--send` and `--file`: no lines.
    None,
}

/// The run, once each check that needs no network passed.
pub(super) struct Plan {
    pub side: Side,
    pub opts: Options,
    pub input: Input,
}

/// The checks, in order: the command line first (64), then the files that
/// it names.
pub(super) fn plan(args: &ChatArgs) -> Result<Plan, Refusal> {
    let given = args.peer.as_deref().ok_or(
        "missing PEER: the node of a pair (NAME), or an iroh ticket (iroh:TICKET); with --listen, the label of \
         the pair that this side serves",
    )?;
    let things = [args.send.is_some(), args.sendfile.is_some(), args.file.is_some()];
    if things.iter().filter(|given| **given).count() > 1 {
        return Err(Refusal::usage("--send, --sendfile and --file each give the run its one thing: give one"));
    }
    if let Some(text) = &args.send {
        if text.len() > MAX_TEXT {
            return Err(Refusal::usage(format!(
                "--send: a message of {} bytes; a message has {MAX_TEXT} bytes at most",
                text.len()
            )));
        }
    }
    let nick = nick(args.nick.as_deref())?;
    let side = side(args, given)?;
    let opts = Options {
        nick,
        accept_dir: accept_dir(args.accept_dir.as_deref())?,
        here: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        once: once(args)?,
    };
    let input = match (&args.sendfile, &opts.once) {
        (Some(path), _) => Input::File(
            std::fs::File::open(path)
                .map_err(|e| Refusal { message: format!("--sendfile {path}: {e}"), code: EX_NOINPUT })?,
        ),
        (None, Once::No) => Input::Stdin,
        (None, _) => Input::None,
    };
    Ok(Plan { side, opts, input })
}

/// The side, from `--listen` and PEER, with only its own flags.
fn side(args: &ChatArgs, given: &str) -> Result<Side, Refusal> {
    let label = given.strip_prefix("node://").or_else(|| given.strip_prefix("node:")).unwrap_or(given);
    let iroh_road = given.starts_with("iroh:");
    if args.iroh_relay.is_some() && !(args.iroh || (iroh_road && !args.listen)) {
        return Err(Refusal::usage("--iroh-relay is for the iroh road: --listen --iroh, or a peer iroh:TICKET"));
    }
    if args.listen {
        if iroh_road {
            return Err(Refusal::usage(
                "--listen serves the pair NAME, not a ticket; --iroh serves the iroh road too, and prints the ticket",
            ));
        }
        if args.client_key.is_some() || args.node_key.is_some() {
            return Err(Refusal::usage(
                "--client-key and --node-key are for the side that reaches the peer; the side that waits has --key \
                 and --allow",
            ));
        }
        crate::pairs::check_label(label)?;
        let place = crate::channel::node_place(label, args.key.as_deref(), args.ephemeral_key)?;
        let allow = args.allow.as_ref().map(PathBuf::from);
        return Ok(Side::Listen { label: label.to_string(), place, allow, iroh: args.iroh });
    }
    if args.key.is_some() || args.ephemeral_key || args.allow.is_some() || args.iroh {
        return Err(Refusal::usage(
            "--key, --ephemeral-key, --allow and --iroh are for the side that waits: add --listen",
        ));
    }
    let ask = crate::channel::Ask::of(args.client_key.as_deref(), None, args.node_key.as_deref(), false)
        .map_err(Refusal::usage)?;
    if iroh_road {
        if args.pair_file.is_some() {
            return Err(Refusal::usage("--pair-file names a pair; a peer iroh:TICKET needs none"));
        }
        return Ok(Side::Reach { peer: Peer::Iroh(given.to_string()), ask });
    }
    crate::pairs::check_label(label)?;
    Ok(Side::Reach { peer: Peer::Pair(label.to_string()), ask })
}

/// The nick of `--nick`, else of the user's account, else `podssh`: what the
/// peer sees, so it is checked as the peer would show it.
fn nick(given: Option<&str>) -> Result<String, Refusal> {
    let Some(nick) = given else {
        let account = ["USER", "USERNAME"].iter().find_map(|name| std::env::var(name).ok());
        let usable =
            account.filter(|n| !n.trim().is_empty() && n.len() <= MAX_NICK && !n.chars().any(char::is_control));
        return Ok(usable.unwrap_or_else(|| "podssh".to_string()));
    };
    if nick.trim().is_empty() || nick.len() > MAX_NICK || nick.chars().any(char::is_control) {
        return Err(Refusal::usage(format!(
            "--nick {nick:?}: a nick has 1 to {MAX_NICK} bytes, and no control character"
        )));
    }
    Ok(nick.to_string())
}

/// `--accept-dir`: a directory that is there, as the files go into it.
fn accept_dir(given: Option<&str>) -> Result<Option<PathBuf>, Refusal> {
    let Some(dir) = given else { return Ok(None) };
    if !Path::new(dir).is_dir() {
        return Err(Refusal { message: format!("--accept-dir {dir}: not a directory"), code: EX_CANTCREAT });
    }
    Ok(Some(PathBuf::from(dir)))
}

/// The one thing of the run, its file read once now to fail before any
/// connection.
fn once(args: &ChatArgs) -> Result<Once, Refusal> {
    if let Some(text) = &args.send {
        return Ok(Once::Send(text.clone()));
    }
    let Some(path) = &args.file else { return Ok(Once::No) };
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => Ok(Once::File(PathBuf::from(path))),
        Ok(_) => Err(Refusal { message: format!("--file {path}: not a regular file"), code: EX_NOINPUT }),
        Err(e) => Err(Refusal { message: format!("--file {path}: {e}"), code: EX_NOINPUT }),
    }
}
