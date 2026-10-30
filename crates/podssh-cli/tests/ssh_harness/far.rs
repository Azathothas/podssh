//! The handler's state for one connection of the test's server: what each
//! command of the server keeps between its messages. Apart from the handler
//! (`mod.rs`), so that each file stays short.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use russh::ChannelId;

use super::sudo::Elevated;

/// One connection's handler: the bytes that `sink` has read on each of its
/// channels, and the channels of `echo` and of `hold`.
#[derive(Default)]
pub(super) struct Far {
    pub(super) sinks: HashMap<ChannelId, u64>,
    pub(super) echoes: Vec<ChannelId>,
    pub(super) holds: Vec<ChannelId>,
    pub(super) quits: Vec<ChannelId>,
    /// The channels of `spew` and `spew-mute`: their writers stop at the
    /// client's end of input, and `spew` then gives the status 7.
    pub(super) spews: HashMap<ChannelId, (Arc<std::sync::atomic::AtomicBool>, bool)>,
    /// The user `kick`: the server ends the connection after the login.
    pub(super) kick: bool,
    /// The channels of `cat > /dev/null`: read to the end, say nothing.
    pub(super) drains: Vec<ChannelId>,
    /// The user `bare-...`: a host with no `cat` and no `head`; and
    /// `bare-early-...`, whose server ends their channels before its reply.
    pub(super) bare: bool,
    pub(super) early: bool,
    /// The user `late-...`, and the channels of `cat` that have not echoed yet.
    pub(super) late: bool,
    pub(super) late_echoes: Vec<ChannelId>,
    /// The users `su-...` and `sudo-nopass-...`, and the commands of sudo
    /// and su that wait for their password.
    pub(super) su: bool,
    pub(super) nopass: bool,
    pub(super) elevated: HashMap<ChannelId, Elevated>,
    /// The cookie of the client's `x11-req`, in hexadecimal.
    pub(super) x11_cookie: Option<String>,
    /// The user `pty-...`: a pty is granted; its size, and the channels of
    /// `watch` (T-132).
    pub(super) pty: bool,
    pub(super) pty_size: (u32, u32),
    pub(super) watches: Vec<ChannelId>,
    /// Where `sftp-server` runs, and the stdin of each that runs (T-140).
    pub(super) sftp_root: Option<PathBuf>,
    /// The user `evil-...`: each listing of its `sftp-server` names
    /// `../escape` too (T-143).
    pub(super) evil: bool,
    /// A server of `watch::start_watched` (T-297): what it counts, and the
    /// bytes of SFTP input left before this connection's cut (`cut-N-...`).
    pub(super) watch: Option<Arc<super::watch::Watch>>,
    pub(super) cut: Option<u64>,
    pub(super) sftps: HashMap<ChannelId, tokio::process::ChildStdin>,
    /// A server of `start_podssh`: what its podssh gets (T-167).
    pub(super) podssh: Option<Arc<super::podssh::Podssh>>,
    /// The user `containers-...`: a host with docker and kubectl (T-190).
    pub(super) containers: Option<String>,
    /// The channels of `prompt`, each with the keys of its line (T-191).
    pub(super) prompts: HashMap<ChannelId, Vec<u8>>,
    /// The commands of `wait-signal` (T-293).
    pub(super) waits: HashMap<ChannelId, super::interrupt::Wait>,
    /// A server of `start_shell`: each command runs in sh (T-193).
    pub(super) shell: Option<super::shell::Shell>,
}
