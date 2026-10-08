//! podssh-ssh — the native SSH client behind `podssh ssh`.
//!
//! The SSH protocol itself is `russh` (aws-lc-rs backend; strict key exchange
//! and the post-quantum hybrid key exchange are in its default lists). What
//! this crate adds is what a constrained host needs around it:
//!
//! - a byte stream from the relay ([`relay_stream`]), or any stream the caller
//!   opened (a TCP connection, or a channel of a previous hop for `-J`);
//! - host-key checking against OpenSSH `known_hosts` files ([`known_hosts`],
//!   [`hostkey`]);
//! - the authentication chain, with prompts that work through the controlling
//!   terminal or `SSH_ASKPASS`, and refuse with a remedy when neither exists
//!   ([`auth`], [`prompt`]);
//! - the local terminal: raw mode, window size, `~` escapes ([`terminal`],
//!   [`escape`], [`session`]);
//! - exit codes that follow OpenSSH: the remote status, 128 + a signal, and 255
//!   for podssh's own failures ([`run`]).

pub mod auth;
pub mod escape;
pub mod forward;
pub mod handler;
pub mod hostkey;
pub mod io;
pub mod keys;
pub mod known_hosts;
pub mod log;
pub mod options;
pub mod prompt;
pub mod relay_stream;
pub mod run;
pub mod session;
pub mod signals;
pub mod terminal;

pub use log::Log;
pub use options::{Agent, Hop, LogLevel, Method, Options, Request, RequestTty, StrictHostKeyChecking};
pub use relay_stream::{RelayEnd, RelayStatus};
pub use run::{run, EXIT_FAILURE};
