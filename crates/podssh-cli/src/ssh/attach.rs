//! `--attach` and `--take` (T-158): join a shell that the far end keeps
//! after `~d`, or list the kept shells. Only a far end that names `keep.v1`
//! in the resumable layer keeps shells, and only the road of a node
//! (`node://NAME`) reads it, so each other destination is refused before
//! anything connects. The far end decides who may join a shell, and says
//! why it refuses (`podssh_ssh::keep`).

use podssh_ssh::keep::{self, Ask};
use podssh_ssh::{Request, RequestTty};

use super::args::SshArgs;
use super::resolve::{Resolved, Transport};
use crate::relay_settings::Refusal;

/// `--attach DEST` with no destination after it: DEST is the destination,
/// and the run lists the kept shells there. `None` for each other command
/// line.
pub fn listing(args: &SshArgs) -> Option<SshArgs> {
    match (&args.attach, &args.destination) {
        (Some(destination), None) => {
            Some(SshArgs { destination: Some(destination.clone()), attach: None, attach_list: true, ..args.clone() })
        }
        _ => None,
    }
}

/// Check `--attach` and `--take` against the rest of the command line,
/// before anything connects (64), and set what they ask of the session: a
/// pty for the shell to join, or the subsystem that lists the kept shells.
pub fn check(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    let ask = match (&args.attach, args.attach_list) {
        (Some(name), _) => Ask::Attach { name: name.clone(), take: args.take },
        (None, true) if args.take => {
            return Err("--take takes a kept shell from its client: give --attach NAME DEST".into());
        }
        (None, true) => Ask::List,
        (None, false) if args.take => return Err("--take is for --attach NAME: give --attach too".into()),
        (None, false) => return Ok(()),
    };
    if !matches!(resolved.transport, Transport::Node { .. }) {
        return Err("--attach is for a node://NAME destination, whose far end can keep shells; a standard sshd \
                    keeps none, and --persist keeps the shell in its tmux"
            .into());
    }
    if let Ask::Attach { name, .. } = &ask {
        keep::check_name(name).map_err(|why| format!("--attach {why}; --attach DEST alone lists the kept shells"))?;
    }
    let with = if args.stdio_forward.is_some() {
        Some("-W")
    } else if args.no_command {
        Some("-N")
    } else if args.subsystem {
        Some("-s")
    } else if !args.command.is_empty() {
        Some("a remote command")
    } else if resolved.options.request != Request::Shell {
        Some("RemoteCommand or SessionType")
    } else if matches!(ask, Ask::Attach { .. }) && resolved.options.request_tty == RequestTty::No {
        Some("-T or RequestTTY=no: a kept shell runs in a pseudo-terminal")
    } else {
        None
    };
    if let Some(with) = with {
        return Err(format!("--attach joins a kept shell, or lists them; it cannot be combined with {with}").into());
    }
    match ask {
        // A kept shell has a pty, also with no local terminal, as -tt asks.
        Ask::Attach { .. } => resolved.options.request_tty = RequestTty::Force,
        Ask::List => {
            resolved.options.request = Request::Subsystem(keep::LIST.to_string());
            resolved.options.request_tty = RequestTty::No;
            resolved.options.stdin_null = true;
        }
    }
    // A control master would carry the session without the far end's
    // offer (T-039): this run makes a connection of its own.
    if resolved.control.path.take().is_some() {
        resolved.notes.push("--attach makes a connection of its own: ControlPath has no effect".into());
    }
    resolved.options.keep.ask = Some(ask);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_with_one_word_lists_the_kept_shells_there() {
        let args = SshArgs { attach: Some("node://lab".into()), ..SshArgs::default() };
        let listed = listing(&args).expect("a listing");
        assert_eq!(listed.destination.as_deref(), Some("node://lab"));
        assert_eq!((listed.attach, listed.attach_list), (None, true));
        let named = SshArgs { destination: Some("node://lab".into()), ..args };
        assert_eq!(listing(&named), None);
        assert_eq!(listing(&SshArgs::default()), None);
    }
}
