//! What `podssh node` was asked to do, as the command line gives it: the
//! fields of `crate::node::NodeArgs`, and their reading from clap's matches.

use clap::ArgMatches;

/// What `podssh node` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeArgs {
    /// The label of a stored pair.
    pub name: Option<String>,
    /// Each TARGET: `HOST:PORT` or `[IPV6]:PORT`, and `ROUTE=TARGET` for a
    /// route (T-089).
    pub targets: Vec<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    /// A pair file to use in place of the store.
    pub pair_file: Option<String>,
    /// Each session's bytes as they are, with no resumable layer.
    pub plain: bool,
    /// Serve the iroh road, with no pair.
    pub iroh: bool,
    /// The node's key file, by its earlier name (T-163).
    pub iroh_key: Option<String>,
    /// The allowlist, by its earlier name (T-163).
    pub iroh_allow: Option<String>,
    /// A key for this run only, by its earlier name (T-163).
    pub iroh_ephemeral: bool,
    /// The node's key file, on each road (T-087).
    pub key: Option<String>,
    /// The operator keys that may come in, on each road (T-087).
    pub allow: Option<String>,
    /// A key for this run only.
    pub ephemeral_key: bool,
    /// No end-to-end channel (T-088).
    pub no_e2e: bool,
    /// The iroh relays, in place of the variable and the table.
    pub iroh_relay: Option<String>,
    /// A roost (T-166): each TARGET is a standard sshd.
    pub sshd: bool,
    /// The temporary node of `podssh ssh --upgrade`, for this client key
    /// (T-167).
    pub temporary: Option<String>,
    /// `--install`: the node as a service of this user (T-121).
    pub install: bool,
    /// `--uninstall`: remove the service that `--install` made.
    pub uninstall: bool,
    /// `--env-file FILE`: the variables of the node, read before anything
    /// else; what `--install` writes for the service.
    pub env_file: Option<String>,
    /// How long a lost session is kept, unparsed (T-306).
    pub resume_deadline: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl NodeArgs {
    /// The arguments of `node` in `matches`.
    pub fn from_matches(matches: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> NodeArgs {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        NodeArgs {
            name: get("name"),
            targets: matches.get_many::<String>("target").map(|v| v.cloned().collect()).unwrap_or_default(),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
            pair_file: get("pair-file"),
            plain: matches.get_flag("plain"),
            iroh: matches.get_flag("iroh"),
            iroh_key: get("iroh-key"),
            iroh_allow: get("iroh-allow"),
            iroh_ephemeral: matches.get_flag("iroh-ephemeral"),
            key: get("key"),
            allow: get("allow"),
            ephemeral_key: matches.get_flag("ephemeral-key"),
            no_e2e: matches.get_flag("no-e2e"),
            iroh_relay: get("iroh-relay"),
            sshd: matches.get_flag("sshd"),
            temporary: get("temporary"),
            install: matches.get_flag("install"),
            uninstall: matches.get_flag("uninstall"),
            env_file: get("env-file"),
            resume_deadline: get("resume-deadline"),
            refused,
        }
    }
}
