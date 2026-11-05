//! The shares at a node (T-433): where its share file is, decided once as
//! the node starts, and the routes that the file names, read again for each
//! session that names a route of no target of the command line, on each road
//! whose routes the node serves (`crate::node_target::routes_of`). A file
//! that cannot be read serves no share, and the node says why once, until
//! what it reads changes, so that a fault is not said for each session.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use podssh_relay::cache;
use podssh_relay::reverse::routes::{Route, Shared};

use super::file::{self, Place, Share, Shares};
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The shares of this process's node.
struct Installed {
    label: String,
    /// None: no file can hold them, as the cache keeps none and `--shares`
    /// names none.
    place: Option<Place>,
    /// The start's line, said once, on the first road that serves routes.
    started: AtomicBool,
    /// The fault said last, so that each session does not say it again.
    said: Mutex<Option<String>>,
}

static INSTALLED: OnceLock<Installed> = OnceLock::new();

/// Before a node's roads start: where its shares are, the file of
/// `--shares FILE`, else `node-NAME.shares` in the cache. A node whose
/// sessions carry no route has none, and `--shares` is refused for it.
pub fn install(args: &NodeArgs) -> Result<(), Refusal> {
    let Some(label) = args.name.as_deref() else { return Ok(()) };
    if let Some(why) = no_routes(args) {
        return match args.shares {
            Some(_) => Err(Refusal::usage(format!("--shares is not for a node of {why}"))),
            None => Ok(()),
        };
    }
    let place = match &args.shares {
        Some(path) => Some(Place::File(PathBuf::from(path))),
        None if cache::candidate_dirs().is_empty() => None,
        None => Some(Place::Cache(file::file_name(label))),
    };
    let installed =
        Installed { label: label.to_string(), place, started: AtomicBool::new(false), said: Mutex::default() };
    // A node that serves again after an upgrade that did not start keeps
    // the first: the same arguments give the same place.
    let _ = INSTALLED.set(installed);
    Ok(())
}

/// Why the sessions of the node of `args` carry no route, so no share.
fn no_routes(args: &NodeArgs) -> Option<&'static str> {
    let udp = args.targets.iter().any(|t| t.starts_with("udp:") || t.contains("=udp:"));
    let each = [
        (args.no_e2e, "--no-e2e, as a share's name travels in the end-to-end channel, as a route's does"),
        (args.temporary.is_some(), "--temporary, which lets one client key reach its sshd alone"),
        (args.quick_tunnel, "--quick-tunnel, which serves one TARGET with no route"),
        (udp, "a udp: TARGET, its only one, with no route"),
    ];
    each.iter().find(|(on, _)| *on).map(|(_, why)| *why)
}

/// The node's shares, as its routes read them for each session, after the
/// start's line once; none where no node was installed in this process or
/// no file can hold them.
pub fn shared() -> Option<Arc<Shared>> {
    let installed: &'static Installed = INSTALLED.get()?;
    if !installed.started.swap(true, Ordering::SeqCst) {
        podssh_ssh::err_line!("podssh node: {}: {}", installed.label, installed.start_line());
    }
    installed.place.as_ref()?;
    let shared: Arc<Shared> = Arc::new(move || installed.now());
    Some(shared)
}

impl Installed {
    /// What the node says of its shares as it starts.
    fn start_line(&self) -> String {
        let Some(place) = &self.place else {
            return format!("no shares: {}=none keeps no file, and --shares FILE names none", cache::DIR_ENV);
        };
        let how = match place {
            Place::File(path) => format!("--shares {}", path.display()),
            Place::Cache(_) => format!("--node {}", self.label),
        };
        let (at, names) = match file::read(place) {
            Ok(Some((path, text))) => (path.display().to_string(), Shares::parse(&text).names()),
            Ok(None) => (place.shown(), String::new()),
            Err(why) => return format!("its shares cannot be read, so it serves none until they can: {why}"),
        };
        let now = if names.is_empty() { "none now".to_string() } else { names };
        let add = format!("podssh share add NAME=HOST:PORT {how} adds one");
        format!("its shares by name in {at}, read again for each session: {now}; {add}")
    }

    /// The routes of the file now, and a fault said once.
    fn now(&self) -> Vec<Route> {
        let Some(place) = &self.place else { return Vec::new() };
        let (routes, fault) = match file::read(place) {
            Ok(None) => (Vec::new(), None),
            Ok(Some((path, text))) => {
                let shares = Shares::parse(&text);
                let (bad, at) = (&shares.bad, path.display());
                let fault = (!bad.is_empty())
                    .then(|| format!("lines {bad:?} of {at} are no share NAME=HOST:PORT, and serve nothing"));
                (shares.list.iter().map(Share::route).collect(), fault)
            }
            Err(why) => (Vec::new(), Some(format!("its shares cannot be read, so it serves none: {why}"))),
        };
        self.tell(fault);
        routes
    }

    /// Say `fault` when it is new; a fault gone is said by nothing.
    fn tell(&self, fault: Option<String>) {
        let mut said = self.said.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if fault != *said {
            if let Some(line) = &fault {
                podssh_ssh::err_line!("podssh node: {}: {line}", self.label);
            }
            *said = fault;
        }
    }
}
