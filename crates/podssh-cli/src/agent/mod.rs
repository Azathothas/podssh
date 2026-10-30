//! `podssh agent` (T-034): an SSH agent inside podssh, for a host with no
//! `ssh-agent` and no OpenSSH program that runs. With no subcommand it
//! serves the agent protocol on a socket that only this user can open, and
//! says `SSH_AUTH_SOCK` as `ssh-agent -s` does; it stays in the foreground,
//! and the user starts it with `&`. `add`, `list`, `remove`, `lock` and
//! `unlock` talk to the agent of `SSH_AUTH_SOCK`, as `ssh-add` does, so they
//! work with OpenSSH's agent too. Keys stay in memory only, and so do the
//! passwords and passphrases of `add-password` and `add-passphrase`
//! (T-228), which only podssh's agent keeps.

mod credentials;
mod keys;
pub(crate) mod serve;

use std::io::Write;

use crate::exit_codes::EXIT_USAGE;

/// The command line of `podssh agent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentArgs {
    pub subcommand: Option<String>,
    /// The key files of `add`, `add-passphrase` and `remove`; the target of
    /// `add-password`.
    pub args: Vec<String>,
    /// `--socket`: where the agent serves.
    pub socket: Option<String>,
    /// `--lifetime` / `-t`: seconds, for `add`, `add-password` and
    /// `add-passphrase`.
    pub lifetime: Option<String>,
    /// `--all`, for `remove`.
    pub all: bool,
    /// The flags that this verb refuses: the flag, its row's kind, and what
    /// to use instead.
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// What a subcommand takes, for its usage error.
const SUBCOMMANDS: &str =
    "add, add-password, add-passphrase, list, remove, lock or unlock; with none, the agent serves";

/// Run `podssh agent`: its exit code.
pub fn run(args: &AgentArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Err(why) = check(args) {
        let _ = writeln!(err, "podssh agent: {why}");
        return EXIT_USAGE;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = writeln!(err, "podssh agent: no runtime: {e}");
            return crate::exitmap::sysexits::EX_SOFTWARE;
        }
    };
    let code = match args.subcommand.as_deref() {
        None => runtime.block_on(serve::serve(args, out, err)),
        Some("add") => runtime.block_on(keys::add(args, out, err)),
        Some("add-password") => runtime.block_on(credentials::add_password(args, err)),
        Some("add-passphrase") => runtime.block_on(credentials::add_passphrase(args, err)),
        Some("list") => runtime.block_on(keys::list(out, err)),
        Some("remove") => runtime.block_on(keys::remove(args, out, err)),
        Some("lock") => runtime.block_on(keys::lock(true, out, err)),
        Some("unlock") => runtime.block_on(keys::lock(false, out, err)),
        Some(_) => unreachable!("checked"),
    };
    // A prompt's helper thread may still wait on stdin.
    runtime.shutdown_background();
    code
}

/// The usage errors of `podssh agent`, before anything runs.
fn check(args: &AgentArgs) -> Result<(), String> {
    let sub = args.subcommand.as_deref();
    match sub {
        None | Some("add" | "add-password" | "add-passphrase" | "list" | "remove" | "lock" | "unlock") => {}
        Some(other) => return Err(format!("no subcommand '{other}': {SUBCOMMANDS}")),
    }
    if args.socket.is_some() && sub.is_some() {
        return Err("--socket is for the agent that serves; the subcommands use SSH_AUTH_SOCK".into());
    }
    if args.lifetime.is_some() && !matches!(sub, Some("add" | "add-password" | "add-passphrase")) {
        return Err("--lifetime is for add, add-password and add-passphrase".into());
    }
    if let Some(seconds) = &args.lifetime {
        if !matches!(seconds.parse::<u32>(), Ok(n) if n > 0) {
            return Err(format!("--lifetime {seconds}: a number of seconds, 1 or more"));
        }
    }
    if args.all && sub != Some("remove") {
        return Err("--all is for remove".into());
    }
    match (sub, args.args.len(), args.all) {
        (Some("add"), 0, _) => Err("add needs a key file: podssh agent add FILE".into()),
        (Some("add-password"), n, _) if n != 1 => {
            Err("add-password takes one server, [USER@]HOST[:PORT]; the password comes from stdin, the terminal or \
                 SSH_ASKPASS, never from the command line"
                .into())
        }
        (Some("add-passphrase"), n, _) if n != 1 => Err("add-passphrase takes one key file".into()),
        (Some("remove"), 0, false) => Err("remove needs a key file, or --all".into()),
        (Some("remove"), _, true) if !args.args.is_empty() => Err("remove takes a key file or --all, not both".into()),
        (None | Some("list" | "lock" | "unlock"), n, _) if n > 0 => {
            Err(format!("{} takes no file", sub.unwrap_or("the agent that serves")))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(sub: Option<&str>, files: &[&str]) -> AgentArgs {
        AgentArgs {
            subcommand: sub.map(str::to_string),
            args: files.iter().map(|f| f.to_string()).collect(),
            ..AgentArgs::default()
        }
    }

    #[test]
    fn agent_usage_is_checked_before_anything_runs() {
        assert!(check(&args(None, &[])).is_ok());
        assert!(check(&args(Some("add"), &["k"])).is_ok());
        assert!(check(&args(Some("list"), &[])).is_ok());
        assert!(check(&args(Some("frob"), &[])).unwrap_err().contains("no subcommand 'frob'"));
        assert!(check(&args(Some("add"), &[])).unwrap_err().contains("needs a key file"));
        assert!(check(&args(Some("list"), &["k"])).unwrap_err().contains("takes no file"));
        assert!(check(&args(Some("add-password"), &["u@h"])).is_ok());
        assert!(check(&args(Some("add-password"), &[])).unwrap_err().contains("never from the command line"));
        assert!(check(&args(Some("add-password"), &["u@h", "pw"])).unwrap_err().contains("takes one server"));
        assert!(check(&args(Some("add-passphrase"), &["k"])).is_ok());
        assert!(check(&args(Some("add-passphrase"), &[])).unwrap_err().contains("one key file"));
        let mut a = args(Some("add"), &["k"]);
        a.lifetime = Some("0".into());
        assert!(check(&a).unwrap_err().contains("1 or more"));
        a.lifetime = Some("600".into());
        assert!(check(&a).is_ok());
        let mut r = args(Some("remove"), &[]);
        assert!(check(&r).unwrap_err().contains("or --all"));
        r.all = true;
        assert!(check(&r).is_ok());
        let mut s = args(Some("list"), &[]);
        s.socket = Some("/tmp/x".into());
        assert!(check(&s).unwrap_err().contains("--socket is for the agent that serves"));
    }
}
