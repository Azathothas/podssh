//! `--sudo` and `--su` (T-032): the remote command runs as root, with the
//! password asked here, never taken from the command line. A remote command
//! is needed. `--sudo` runs it with no pty, as `sudo -S` reads the password
//! from the channel, which a pty would echo; `--su` asks for one, as su reads
//! a terminal alone. Such a run makes a connection of its own: the session of
//! a master would run the command with no filter for the password.

use podssh_ssh::{Elevate, Request, RequestTty};

use super::args::SshArgs;
use super::resolve::Resolved;
use crate::relay_settings::Refusal;

/// Check `--sudo` and `--su`, and set them in `resolved`.
pub fn check(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    let (how, flag) = match (args.sudo, args.su) {
        (false, false) => return Ok(()),
        (true, true) => return Err("--sudo and --su each run the command as root: give one".into()),
        (true, false) => (Elevate::Sudo, "--sudo"),
        (false, true) => (Elevate::Su, "--su"),
    };
    let options = &mut resolved.options;
    if !matches!(options.request, Request::Exec(_)) {
        return Err(format!("{flag} runs a remote command as root: give the command").into());
    }
    match how {
        Elevate::Sudo if args.tty > 0 => {
            return Err("--sudo runs the command with no pseudo-terminal: sudo -S reads the password from the \
                        channel, which a pseudo-terminal would echo; drop -t"
                .into())
        }
        Elevate::Su if args.no_tty => {
            return Err("--su needs a pseudo-terminal, as su reads a terminal alone; drop -T".into())
        }
        Elevate::Sudo => options.request_tty = RequestTty::No,
        Elevate::Su => options.request_tty = RequestTty::Force,
    }
    options.elevate = Some(how);
    if resolved.control.path.take().is_some() {
        resolved.notes.push(format!("{flag} makes a connection of its own: ControlPath has no effect"));
    }
    Ok(())
}
