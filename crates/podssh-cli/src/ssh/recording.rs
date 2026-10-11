//! `--record FILE` (T-033): the output of a session, with its timing, in an
//! asciicast v2 file. The file is made as the run starts, never over one
//! that exists, and `-G` makes none. A session is needed, and `--persist`,
//! whose sessions follow one another, cannot go with it. Such a run makes a
//! connection of its own: a master's session would not be recorded.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use podssh_ssh::record::Target;
use podssh_ssh::Request;

use super::args::SshArgs;
use super::resolve::Resolved;
use crate::relay_settings::Refusal;

/// Check `--record`, and keep its file in `resolved`.
pub fn check(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    let Some(file) = args.record.as_deref() else { return Ok(()) };
    if matches!(resolved.options.request, Request::StdioForward(_) | Request::Nothing) {
        return Err("--record keeps the output of a session, and -W and -N open none".into());
    }
    if resolved.persist.is_some() {
        return Err("--record cannot go with --persist, whose sessions follow one another".into());
    }
    if resolved.control.path.take().is_some() {
        resolved.notes.push("--record makes a connection of its own: ControlPath has no effect".into());
    }
    resolved.record = Some(PathBuf::from(file));
    Ok(())
}

/// Make the file of `--record`: closed to others (mode 0600, or on Windows
/// an access list of its own), and never over a file that exists.
pub fn create(path: &Path) -> Result<Target, String> {
    podssh_relay::cache::create_new_private(path).map(Target::new).map_err(|e| match e.kind() {
        ErrorKind::AlreadyExists => {
            format!("--record {}: the file exists, and podssh records over none", path.display())
        }
        _ => format!("--record {}: {e}", path.display()),
    })
}
