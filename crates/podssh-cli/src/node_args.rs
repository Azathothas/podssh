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
    /// Serve the DERP road (T-379), beside the pair's road when there is one.
    pub derp: bool,
    /// The DERP servers, in place of the variable and the fleet, unparsed.
    pub derp_server: Option<String>,
    /// Serve the OpenTunnel road (T-531), beside the pair's road when there
    /// is one.
    pub opentunnel: bool,
    /// Serve a quick tunnel of Cloudflare's, with no pair (T-300).
    pub quick_tunnel: bool,
    /// Reach the quick tunnel's edge inside WARP's tunnel first (T-374).
    pub warp: bool,
    /// The relay role behind the quick tunnel too (T-428).
    pub relay: bool,
    /// Whom the role mints for, unparsed: `relay serve`'s words.
    pub mint: Option<String>,
    /// The file that keeps the role's pairs across a restart.
    pub pairs: Option<String>,
    /// The role dials non-public targets too.
    pub allow_private: bool,
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
    /// `--detach`: into the background once online (T-380).
    pub detach: bool,
    /// `--restart`: the detached node started again whenever it ends (T-390).
    pub restart: bool,
    /// `--detach-name NAME`: the detached node's name (T-392).
    pub detach_name: Option<String>,
    /// `--install`: the node as a service of this user (T-121).
    pub install: bool,
    /// `--uninstall`: remove the service that `--install` made.
    pub uninstall: bool,
    /// `--env-file FILE`: the variables of the node, read before anything
    /// else; what `--install` writes for the service.
    pub env_file: Option<String>,
    /// How long a lost session is kept, unparsed (T-306).
    pub resume_deadline: Option<String>,
    /// `--exit`: lend this host's egress to the net's members (T-431).
    pub exit: bool,
    /// `--routes RANGES`: the private ranges that the exit, or the relay role
    /// of `--relay` (T-635), dials too, unparsed.
    pub routes: Option<String>,
    /// `--carrier ADDR`: the node's one road, a stream that exists already
    /// (T-595), unparsed.
    pub carrier: Option<String>,
    /// `--grant-to KEY`: print a grant used once for KEY, signed by the
    /// node's key, and serve nothing (T-226); its route and its life.
    pub grant_to: Option<String>,
    pub grant_route: Option<String>,
    pub grant_for: Option<String>,
    /// `--revoked FILE`: the serials of grants that the node refuses.
    pub revoked: Option<String>,
    /// `--ask`: a person at the node's terminal lets each key in, after the
    /// door (T-638).
    pub ask: bool,
    /// `--publish-tls TARGET`: the pair's sessions are a site that podssh's
    /// relay role routes here by its name (T-649), unparsed; with `--acme
    /// NAME` the node ends their TLS itself, with a certificate of a CA's
    /// (`--acme-directory URL`, else Let's Encrypt's).
    pub publish_tls: Option<String>,
    pub acme: Option<String>,
    pub acme_directory: Option<String>,
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
            derp: matches.get_flag("derp"),
            derp_server: get("derp-server"),
            opentunnel: matches.get_flag("opentunnel"),
            quick_tunnel: matches.get_flag("quick-tunnel"),
            warp: matches.get_flag("warp"),
            relay: matches.get_flag("relay"),
            mint: get("mint"),
            pairs: get("pairs"),
            allow_private: matches.get_flag("allow-private"),
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
            detach: matches.get_flag("detach"),
            restart: matches.get_flag("restart"),
            detach_name: get("detach-name"),
            install: matches.get_flag("install"),
            uninstall: matches.get_flag("uninstall"),
            env_file: get("env-file"),
            resume_deadline: get("resume-deadline"),
            exit: matches.get_flag("exit"),
            routes: get("routes"),
            carrier: get("carrier"),
            grant_to: get("grant-to"),
            grant_route: get("grant-route"),
            grant_for: get("grant-for"),
            revoked: get("revoked"),
            ask: matches.get_flag("ask"),
            publish_tls: get("publish-tls"),
            acme: get("acme"),
            acme_directory: get("acme-directory"),
            refused,
        }
    }
}
