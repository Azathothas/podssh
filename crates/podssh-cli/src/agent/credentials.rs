//! The passwords and passphrases that `podssh agent` keeps (T-228):
//! `add-password [USER@]HOST[:PORT]` and `add-passphrase FILE`, to the agent
//! of `SSH_AUTH_SOCK`. The secret comes from stdin when stdin is no
//! terminal, else from the terminal or `SSH_ASKPASS`; never from the command
//! line. It lives in the agent's memory only, for its life or `--lifetime`
//! seconds, and `podssh ssh` asks for it before each prompt.

use std::io::{BufRead, Write};
use std::path::Path;

use podssh_ssh::credential_store::{StoreClient, StoreError, Target};
use podssh_ssh::prompt;
use zeroize::Zeroizing;

use super::AgentArgs;
use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::{EX_DATAERR, EX_NOINPUT, EX_SOFTWARE, EX_UNAVAILABLE};
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env};

/// `add-password [USER@]HOST[:PORT]`: the password of a server, under the
/// user, the host and the port that `podssh ssh` logs in with, its
/// ssh_config read.
pub async fn add_password(args: &AgentArgs, err: &mut dyn Write) -> i32 {
    let destination = &args.args[0];
    let ssh = SshArgs { destination: Some(destination.clone()), ..SshArgs::default() };
    let target = match resolve::resolve(&ssh, &Env::from_process()) {
        Ok(resolved) => {
            let hop = &resolved.options.destination;
            let user = hop.user.clone().unwrap_or_else(|| resolved.options.user.clone());
            Target::password(&user, &hop.host, hop.port)
        }
        Err(why) => {
            let _ = writeln!(err, "podssh agent: {destination}: {why}");
            return EXIT_USAGE;
        }
    };
    let question = format!("{}'s password: ", target.name);
    let secret = match read_secret(&question, err) {
        Ok(secret) => secret,
        Err(code) => return code,
    };
    keep(args, &target, &secret, err).await
}

/// `add-passphrase FILE`: the passphrase of a key file that the agent does
/// not hold, once it opens the file.
pub async fn add_passphrase(args: &AgentArgs, err: &mut dyn Write) -> i32 {
    let file = &args.args[0];
    let path = Path::new(file);
    if !path.is_file() {
        let _ = writeln!(err, "podssh agent: {file}: no such key file");
        return EX_NOINPUT;
    }
    if podssh_ssh::key_file::load(path, None).is_ok() {
        let _ = writeln!(err, "podssh agent: {file} needs no passphrase: nothing to keep");
        return EX_DATAERR;
    }
    let secret = match read_secret(&format!("Enter passphrase for key '{file}': "), err) {
        Ok(secret) => secret,
        Err(code) => return code,
    };
    if podssh_ssh::key_file::load(path, Some(secret.as_str())).is_err() {
        let _ = writeln!(err, "podssh agent: the passphrase does not open {file}; it is not kept");
        return EX_DATAERR;
    }
    keep(args, &Target::passphrase(path), &secret, err).await
}

/// The secret: the first line of stdin when stdin is no terminal, else asked
/// on the terminal or through `SSH_ASKPASS`. An empty one is refused.
fn read_secret(question: &str, err: &mut dyn Write) -> Result<Zeroizing<String>, i32> {
    let secret = if podssh_ssh::terminal::stdin_is_terminal() {
        prompt::ask(question, false).map_err(|e| {
            let _ = writeln!(err, "podssh agent: {e}");
            EX_NOINPUT
        })?
    } else {
        let mut line = Zeroizing::new(String::new());
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(_) => {
                while line.ends_with(['\n', '\r']) {
                    line.pop();
                }
                line
            }
            Err(e) => {
                let _ = writeln!(err, "podssh agent: stdin could not be read: {e}");
                return Err(EX_NOINPUT);
            }
        }
    };
    if secret.is_empty() {
        let _ = writeln!(err, "podssh agent: an empty secret is not kept");
        return Err(EX_NOINPUT);
    }
    Ok(secret)
}

/// Keep `secret` for `target` in the agent of `SSH_AUTH_SOCK`.
async fn keep(args: &AgentArgs, target: &Target, secret: &str, err: &mut dyn Write) -> i32 {
    let agent = match super::keys::connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    let lifetime: Option<u32> = args.lifetime.as_deref().and_then(|s| s.parse().ok());
    match StoreClient::new(agent.into_inner()).store(target, secret, lifetime).await {
        Ok(()) => {
            let _ = writeln!(err, "Added {}", target.shown());
            0
        }
        Err(StoreError::NoStore) => {
            let _ = writeln!(
                err,
                "podssh agent: the agent of SSH_AUTH_SOCK keeps no passwords: it is not podssh agent, or it is locked"
            );
            EX_UNAVAILABLE
        }
        Err(e) => {
            let _ = writeln!(err, "podssh agent: {e}");
            EX_SOFTWARE
        }
    }
}
