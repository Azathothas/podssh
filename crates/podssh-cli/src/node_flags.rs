//! The flags of `podssh node` that each road reads: the node's key and
//! allowlist, each by its two names (T-087, T-163), and the resume deadline
//! (T-306). Apart from `node.rs` for the length of that file.

use std::path::PathBuf;

use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The node's key and allowlist, by their names of T-087 or of T-163.
pub(crate) struct KeyFlags {
    pub key: Option<String>,
    pub ephemeral: bool,
    pub allow: Option<PathBuf>,
}

/// The flags of the node's key and allowlist; each by one of its two names.
pub(crate) fn key_flags(args: &NodeArgs) -> Result<KeyFlags, Refusal> {
    let both = |a: &str, b: &str| Refusal::usage(format!("{a} and {b} are one flag by two names: give one"));
    if args.key.is_some() && args.iroh_key.is_some() {
        return Err(both("--key", "--iroh-key"));
    }
    if args.allow.is_some() && args.iroh_allow.is_some() {
        return Err(both("--allow", "--iroh-allow"));
    }
    Ok(KeyFlags {
        key: args.key.clone().or_else(|| args.iroh_key.clone()),
        ephemeral: args.ephemeral_key || args.iroh_ephemeral,
        allow: args.allow.as_ref().or(args.iroh_allow.as_ref()).map(PathBuf::from),
    })
}

/// `--resume-deadline TIME` (T-306): how long the node keeps a session whose
/// link is lost, and names to its clients, on each road; 10 minutes with
/// none. A node with no layer, or the temporary node, keeps no session so.
pub(crate) fn deadline(args: &NodeArgs) -> Result<(), Refusal> {
    let Some(text) = args.resume_deadline.as_deref() else { return Ok(()) };
    if args.temporary.is_some() {
        return Err(Refusal::usage("--resume-deadline does not go with --temporary, which keeps the defaults"));
    }
    if args.plain {
        return Err(Refusal::usage("--resume-deadline is a time of the resumable layer, which --plain turns off"));
    }
    crate::layered::set_far_deadline(crate::layered::parse_deadline(text).map_err(Refusal::usage)?);
    Ok(())
}

/// The mode of a node with the layer, as its first line says it: with the
/// time for which it keeps a lost session.
pub(crate) fn layer_mode() -> String {
    let kept = podssh_relay::session::deadline::span(crate::layered::settings().resume_deadline);
    format!("with the resumable layer, which keeps a lost session {kept}")
}
