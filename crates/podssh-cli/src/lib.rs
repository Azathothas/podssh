//! podssh's command line: one tree, two renderers, and refusals that name a
//! real flag.
//!
//! **The seam is argv in, a typed command out**, and it is one seam:
//! [`tree::parse`] is the only way a command is selected, and [`dispatch`]
//! turns the result into an exit code. Everything else in this crate is a
//! renderer or a table, so there is exactly one place where a wrong command
//! line can be mistaken for a right one.
//!
//! **`podssh` with no subcommand never connects.** `docs/cli.md` makes it
//! an error that explains itself ("A word with no subcommand"): the two-stage handler in
//! [`refuse`] is why `podssh example.org` says `Try: podssh ssh example.org` and never says
//! `doctor`.
//!
//! `podssh man` ([`man`]) renders the same tables as `--help`, with the
//! facts, notes and examples beside them, as text or as roff. The flags of
//! `chat`, `cp`, `mv` and `relay` are defined so they parse and are refused
//! correctly; those commands are not implemented yet.

// A dependency that no code uses fails the build (the tests have their own).
#![cfg_attr(not(test), deny(unused_crate_dependencies))]

// The ACME client of `podssh relay serve --acme NAME` (T-447).
pub mod acme;
pub mod agent;
// `--carrier ADDR`: the node's road over a stream that exists already, and
// the relay role's side of it in its client (T-595).
pub mod carrier;
pub mod channel;
pub mod chat;
pub mod clap_error;
pub mod config_import;
// `--ConnectTimeout` of operator, proxy and pipe: one bound on the open (T-589).
pub mod connect_bound;
// `podssh containers`: the containers of a host, and --exec (T-190).
pub mod containers;
pub mod cp;
pub mod detach;
pub mod dispatch;
pub mod doctor;
// `podssh each`: one command on many hosts at once (T-183).
pub mod each;
// `podssh edit`: one far file, changed in an editor here (T-149).
pub mod edit;
// The report of a failure, to the program of `PODSSH_ERROR_PROGRAM` (T-195).
pub mod error_program;
pub mod exit_codes;
// **The fault table of the exit codes, as code.** `exit_codes.rs` holds the two
// candidate usage constants and names the fork; `exitmap.rs` holds the whole
// table, the collision guard, and the tests that decide `2` versus `64`.
// Two modules because they answer different questions: `exit_codes.rs` is
// "what does this crate emit today", `exitmap.rs` is "what the contract says".
pub mod exitmap;
// `podssh exit NAME --listen ADDR:PORT`, and the client's side of an exit of
// the net: `--exit NAME` of proxy and pipe (T-431).
pub mod exit;
// The first thread, which runs on itself what the command's thread asks: the
// capabilities that `relay serve` drops after its bind (T-629).
pub mod first_thread;
// Tables, one flag to a row: rustfmt would spread each row over many lines.
#[rustfmt::skip]
pub mod flags;
// `--forwarder`: other products' WebSocket forwarders, in place of the
// relay (T-369).
pub mod forwarder;
// Grants used once (T-226): a client's --grant, a node's door and its mint.
pub mod grants;
// The signals that end a client of a node's layer with a `CLOSE` (T-586).
pub mod hangup;
pub mod help;
// `podssh health`: the facts of the far host, over one exec (T-189).
pub mod health;
// The hosts of a word: braces and groups (T-184).
pub mod hosts;
// The HTTP road of proxy and ssh, where the way refused the upgrade (T-319).
pub mod http_road;
// The command that installs a missing program, named and never run (T-590).
pub mod install_hint;
// `podssh job`: jobs on a far host, each in its tmux (T-193).
pub mod job;
pub mod keygen;
pub mod keygen_cert;
pub mod keygen_change;
pub mod keygen_convert;
pub mod keygen_hosts;
pub mod keygen_sign;
pub mod keygen_sk;
pub mod layered;
// Whether this host has an sshd, for a roost and for doctor (T-590).
pub mod local_sshd;
// The manual (`man/`) and the pager that shows it on a terminal.
pub mod man;
// `podssh mcp`: the commands as tools for an agent (T-055).
pub mod mcp;
// `podssh net`: a user's own nodes as one net, signed by its owner (T-429).
pub mod net;
pub mod node;
pub mod node_args;
// `podssh node --carrier ADDR`: the node's socket on a stream (T-595).
pub mod node_carrier;
// A pair's expiry said before it comes, and the next pair taken at it (T-395).
pub mod node_expiry;
// A node's stop token, rotated where its relay rotates one (T-615).
pub mod node_rotate;
// `podssh node --install`: the node as a service of this user (T-121).
pub mod node_install;
// The flags of `podssh node` that each road reads: the keys, the resume
// deadline (T-306).
pub mod node_flags;
// `podssh node --exit`: the node lends its egress to its net (T-431).
pub mod node_exit;
pub(crate) mod node_exit_own;
// `podssh node NAME udp:HOST:PORT`: a UDP target, one flow for each session.
pub mod node_udp;
// `podssh node --derp`: the DERP road, and its fallback of a node with no
// pair (T-379).
pub mod node_derp;
// `podssh node --opentunnel`: the OpenTunnel road, and its fallback of a node
// with no other road (T-531, Q76).
pub mod node_opentunnel;
// The transit relay of Q65 beside a pair's road, for a node and its
// operators (T-436).
pub mod node_transit;
// `podssh node --iroh`: the iroh road, with the feature `iroh` only.
#[cfg(feature = "iroh")]
pub mod node_iroh;
// A node's record of pkarr with each of its roads (T-445); in a build with
// no iroh road, no record.
pub mod node_record;
// The Piping Server road of a node of a pair (T-437): asked by PODSSH_PIPING,
// or unasked where the WebSocket upgrade is refused on the way (Q65).
pub mod node_piping;
// `podssh node --quick-tunnel`: a quick tunnel of Cloudflare's, which podssh
// makes itself (T-300).
pub mod node_quick;
// `podssh node --quick-tunnel --relay`: the relay role behind the node's
// quick tunnel, with no listener (T-428).
pub mod node_quick_relay;
// The quick tunnel's edge inside WARP's tunnel (T-374), with the feature
// `warp`; without it, the road says what such a build does.
pub mod node_warp;
// `podssh node --temporary`: the far end of `podssh ssh --upgrade` (T-167).
pub mod node_target;
pub mod node_temp;
// The soft limit of open files, raised at start within the hard one (T-564).
pub mod nofile;
// `--no-resume` of a client of a node (T-612).
pub mod no_resume;
pub mod non_interactive;
pub mod operator;
pub mod pager;
mod pairs;
pub mod parsed;
pub mod ping;
pub mod pins;
pub mod pipe;
// PODSSH_PIPING, and the Piping Server road's dialer of `podssh ssh node://`
// (T-437).
pub mod piping_road;
pub mod play;
pub mod positionals;
pub mod proxy;
// `podssh proxy node://NAME`: the pipe of `podssh operator NAME` (T-587).
pub mod proxy_node;
pub mod refuse;
// `podssh relay pair --code` and `podssh relay join`: pairing by a short code (T-086).
pub mod relay_cmd;
mod relay_code;
// The signed list of deployments: the keys trusted, and its words (T-346).
mod relay_deployments;
pub mod relay_diag;
mod relay_diag_text;
// How a session that a relay host carried ended, for the record of the
// hosts (T-563).
pub mod relay_ends;
// `podssh proxy` in the resumable layer at podssh's relay role, where it is
// asked for and offered (T-173).
pub mod relay_layer;
// `podssh relay pair --renew NAME`: a pair renewed at podssh's relay role (T-592).
mod relay_renew;
// `podssh relay rank`: each relay host measured from this host, the rank kept (T-606).
mod relay_rank;
// The rank of a session's background, with RelayRank auto alone (T-608).
mod relay_rank_auto;
pub mod relay_serve;
pub mod relay_settings;
pub mod relay_spec;
// `podssh relay status NAME` and `--pair-file`: a pair's state and expiry (T-591).
mod relay_status;
// `podssh session`: a session that outlives each call of an agent (T-186).
pub mod session;
// `podssh run`: copy a project, then run a command in it (T-192).
pub mod run_cmd;
pub mod session_log;
pub mod settings;
pub mod sftp;
// `--shadowsocks FILE`: Shadowsocks servers in place of the relay (T-373).
pub mod shadowsocks;
// Commands of the settings file, shown and asked before they run (T-187).
pub mod snippets;
pub mod ssh;
pub mod status;
pub mod suggest;
pub mod tree;
// `podssh update` (T-375).
pub mod update;
// `podssh ts` links the vendored tailscale-rs fork, which needs a C toolchain,
// so it is compiled only with the `ts` feature (see Cargo.toml).
#[cfg(feature = "ts")]
pub mod ts;
// The line of a temporary node to `podssh ssh --upgrade` (T-167).
mod upgrade_line;
// The commit that a release build names in `--version` (T-210).
pub mod version;
// `--via URL`: a forward proxy over TLS in place of the relay (T-439).
pub mod via;
// `--vless FILE`: VLESS servers in place of the relay (T-440).
pub mod vless;
// `--wstunnel URL`: a wstunnel server in place of the relay (T-441).
pub mod wstunnel;

pub use flags::{FlagKind, FlagRow, Verb, VERBS};
pub use tree::{parse, Parsed};
