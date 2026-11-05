//! `podssh share` (T-433): a running node's local services by name, for its
//! net, as Tailscale's serve offers a node's; `podssh serve` is M5's server
//! in the cage, so this one takes another word. A share is a line
//! `NAME=HOST:PORT` of the node's share file (`file`), which the node reads
//! again for each session (`serve`): a share added while it runs is reached
//! at its next session as `node://NODE/NAME`, and one removed is refused.
//! The net's policy holds a share as it holds a route (T-430), and so does
//! an allowlist's `routes=`. `add NAME=TARGET`, `rm NAME` and `ls` change and
//! read that file, for a node of this host, under its lock; `ls --net` lists
//! the shares that the net's owner lists for each member (T-429). stdout
//! carries the list; podssh's words go to stderr.

pub mod file;
pub mod serve;

use std::io::Write;
use std::path::PathBuf;

use clap::ArgMatches;
use podssh_relay::cache;

use crate::relay_settings::Refusal;
use file::{Place, Share, Shares};

/// What `podssh share` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareArgs {
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    /// `--node NAME`: the node of this host whose shares.
    pub node: Option<String>,
    /// `--shares FILE`: its share file, as the node's `--shares FILE`.
    pub shares: Option<String>,
    /// `--net` of `ls`: the shares that the net's document lists.
    pub net: bool,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl ShareArgs {
    /// The arguments of `share` in `matches`.
    pub fn from_matches(matches: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> ShareArgs {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        ShareArgs {
            subcommand: get("subcommand"),
            args: matches.get_many::<String>("args").map(|v| v.cloned().collect()).unwrap_or_default(),
            node: get("node"),
            shares: get("shares"),
            net: matches.get_flag("net"),
            refused,
        }
    }
}

/// The subcommands, as a refusal names them.
const SUBCOMMANDS: &str = "add NAME=HOST:PORT, rm NAME or ls";

/// Run the verb; returns the process exit code.
pub fn run(args: &ShareArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let done = checked(args).and_then(|word| match word {
        "ls" if args.net => ls_net(out, err),
        word => {
            let (label, place) = place_of(args)?;
            match word {
                "add" => add(&args.args[0], label.as_deref(), &place, err),
                "rm" => rm(&args.args[0], label.as_deref(), &place, err),
                _ => ls(label.as_deref(), &place, out, err),
            }
        }
    });
    match done {
        Ok(code) => code,
        Err(refusal) => refusal.report("share", err),
    }
}

/// The subcommand, its count of words and its flags, checked before
/// anything is read.
fn checked(args: &ShareArgs) -> Result<&str, Refusal> {
    let word =
        args.subcommand.as_deref().ok_or_else(|| Refusal::usage(format!("missing SUBCOMMAND: {SUBCOMMANDS}")))?;
    let (words, shape) = match word {
        "add" => (1, "add NAME=HOST:PORT"),
        "rm" => (1, "rm NAME"),
        "ls" => (0, "ls"),
        other => return Err(Refusal::usage(format!("{other:?} is not a subcommand: {SUBCOMMANDS}"))),
    };
    if args.args.len() != words {
        return Err(Refusal::usage(format!("podssh share {shape}: {} words given", args.args.len())));
    }
    if args.net && word != "ls" {
        return Err(Refusal::usage("--net is for podssh share ls, which lists the shares that the net names"));
    }
    if args.net && (args.node.is_some() || args.shares.is_some()) {
        return Err(Refusal::usage("--net lists each member's shares: --node and --shares name one node of this host"));
    }
    Ok(word)
}

/// The node's label, when it is known, and where its shares are: the file
/// of `--shares`, else `node-NAME.shares` in the cache for `--node NAME`,
/// else for the one node of this host.
fn place_of(args: &ShareArgs) -> Result<(Option<String>, Place), Refusal> {
    if let Some(node) = &args.node {
        crate::pairs::check_label(node)?;
    }
    if let Some(path) = &args.shares {
        return Ok((args.node.clone(), Place::File(PathBuf::from(path))));
    }
    if cache::candidate_dirs().is_empty() {
        return Err(Refusal::config(format!(
            "{}=none keeps no file, so a node's shares are in the file of --shares FILE, the node's and this one's",
            cache::DIR_ENV
        )));
    }
    let label = match &args.node {
        Some(node) => node.clone(),
        None => the_one_node()?,
    };
    let place = Place::Cache(file::file_name(&label));
    Ok((Some(label), place))
}

/// The one node of this host: its key, or its shares, in the cache. A host
/// of none or of several is asked which.
fn the_one_node() -> Result<String, Refusal> {
    let dirs = cache::candidate_dirs();
    let mut nodes: Vec<String> = Vec::new();
    for suffix in [".key", ".shares"] {
        for name in cache::names_from(&dirs, "node-", suffix) {
            let Some(label) = name.strip_prefix("node-").and_then(|rest| rest.strip_suffix(suffix)) else { continue };
            if !nodes.iter().any(|node| node == label) {
                nodes.push(label.to_string());
            }
        }
    }
    nodes.sort();
    match nodes.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(Refusal::usage(
            "no node's key is in the cache of this host: name the node with --node NAME, or its file with --shares FILE",
        )),
        many => Err(Refusal::usage(format!("this host has the nodes {}: name one with --node NAME", many.join(", ")))),
    }
}

/// How a line names the node, and how an operator reaches the share `name`.
fn reached(label: Option<&str>, name: &str) -> (String, String) {
    match label {
        Some(label) => (format!("the node {label}"), format!("node://{label}/{name}")),
        None => ("the node".to_string(), format!("node://NODE/{name}")),
    }
}

/// `add NAME=HOST:PORT`: the share, or a new target of the share of its name.
fn add(word: &str, label: Option<&str>, place: &Place, err: &mut dyn Write) -> Result<i32, Refusal> {
    let share = Share::parse(word).map_err(Refusal::usage)?;
    let (path, before) = file::edit(place, |text| {
        let (next, before) = file::with_share(text, &share);
        if before.as_ref() == Some(&share) {
            return Ok((None, before));
        }
        if before.is_none() && Shares::parse(text).list.len() >= file::MAX_SHARES {
            let why = format!("a node has {} shares at most: remove one with podssh share rm NAME", file::MAX_SHARES);
            return Err(Refusal::usage(why));
        }
        Ok((Some(next), before))
    })?;
    let (who, at) = reached(label, &share.name);
    let said = match before {
        Some(old) if old == share => format!("{who} shares {} already", share.line()),
        Some(old) => format!("{who} shares {} in place of {}", share.line(), old.target()),
        None => format!("{who} shares {}", share.line()),
    };
    let _ = writeln!(err, "podssh share: {said} ({}); its next session to {at} reaches it", path.display());
    Ok(0)
}

/// `rm NAME`: the share gone; the node refuses it from its next session.
fn rm(name: &str, label: Option<&str>, place: &Place, err: &mut dyn Write) -> Result<i32, Refusal> {
    podssh_ws::names::check_node_name(name)
        .map_err(|_| Refusal::usage(format!("{name:?} is not a share's name: letters, digits, '.', '-' and '_'")))?;
    let (who, at) = reached(label, name);
    let (path, gone) = file::edit(place, |text| match file::without(text, name) {
        (next, Some(gone)) => Ok((Some(next), gone)),
        (_, None) => Err(Refusal::usage(format!("{who} has no share {name}: podssh share ls lists its shares"))),
    })?;
    let _ = writeln!(err, "podssh share: {who} shares {name} no more ({}): {at} was {}", path.display(), gone.target());
    Ok(0)
}

/// `ls`: one line for each share, its name and its target apart by a tab,
/// as the node reads them for its next session.
fn ls(label: Option<&str>, place: &Place, out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    let (who, at) = reached(label, "NAME");
    let Some((path, text)) = file::read(place).map_err(Refusal::config)? else {
        let _ = writeln!(err, "podssh share: {who} has no shares: {} holds none", place.shown());
        return Ok(0);
    };
    let shares = Shares::parse(&text);
    for share in &shares.list {
        let _ = writeln!(out, "{}\t{}", share.name, share.target());
    }
    let count = shares.list.len();
    let _ = writeln!(err, "podssh share: {who}: {count} shares in {}, each reached as {at}", path.display());
    if !shares.bad.is_empty() {
        let _ = writeln!(err, "podssh share: lines {:?} of {} are no share NAME=HOST:PORT", shares.bad, path.display());
    }
    Ok(0)
}

/// `ls --net`: one line for each share that the net held here lists, the
/// member, the name and the address, apart by tabs.
fn ls_net(out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    if !crate::net::store::on() {
        let why = crate::net::store::place().err();
        return Err(Refusal::config(why.unwrap_or_else(|| format!("{}=no: the net is off", crate::net::store::ENV))));
    }
    let held = crate::net::held()?;
    let _ = writeln!(err, "podssh share: {}", crate::net::summary(&held));
    let mut count = 0;
    for member in &held.signed.doc.members {
        for name in &member.shares {
            let _ = writeln!(out, "{}\t{name}\tnode://{}/{name}", member.name, member.name);
            count += 1;
        }
    }
    if count == 0 {
        let _ = writeln!(
            err,
            "podssh share: the net lists no share: its owner lists a node's with podssh net add NAME KEY --roles \
             node,share --shares NAMES"
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests;
