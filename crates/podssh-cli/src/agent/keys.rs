//! The commands that talk to an agent (T-034): `add`, `list`, `remove`,
//! `lock` and `unlock`, to the agent of `SSH_AUTH_SOCK`, podssh's or
//! OpenSSH's, with the words of `ssh-add`. A passphrase or a lock password
//! is asked on the terminal or through `SSH_ASKPASS`, and lives in memory
//! that is wiped.

use std::io::Write;
use std::path::Path;

use podssh_ssh::prompt::{self, PromptError};
use podssh_ssh::russh::keys::agent::client::{AgentClient, AgentStream};
use podssh_ssh::russh::keys::agent::Constraint;
use podssh_ssh::russh::keys::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use super::AgentArgs;
use crate::exitmap::sysexits::{EX_NOINPUT, EX_NOPERM, EX_SOFTWARE, EX_UNAVAILABLE};

type Agent = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

/// The agent of `SSH_AUTH_SOCK`; on Windows, else OpenSSH's named pipe.
pub(super) async fn connect(err: &mut dyn Write) -> Result<Agent, i32> {
    let named = std::env::var("SSH_AUTH_SOCK").ok().filter(|v| !v.is_empty());
    #[cfg(unix)]
    let Some(place) = named
    else {
        let _ = writeln!(err, "podssh agent: SSH_AUTH_SOCK is not set: start podssh agent, and set it as it says");
        return Err(EX_UNAVAILABLE);
    };
    #[cfg(unix)]
    let reached = AgentClient::connect_uds(&place).await.map(|agent| agent.dynamic());
    #[cfg(windows)]
    let place = named.unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".to_string());
    #[cfg(windows)]
    let reached = AgentClient::connect_named_pipe(&place).await.map(|agent| agent.dynamic());
    reached.map_err(|e| {
        let _ = writeln!(err, "podssh agent: no agent answers at {place}: {e}");
        EX_UNAVAILABLE
    })
}

/// `add FILE...`: each key to the agent, for `--lifetime` seconds when given.
pub async fn add(args: &AgentArgs, _out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut agent = match connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    let lifetime: Option<u32> = args.lifetime.as_deref().and_then(|s| s.parse().ok());
    let constraints: Vec<Constraint> =
        lifetime.map(|seconds| vec![Constraint::KeyLifetime { seconds }]).unwrap_or_default();
    for file in &args.args {
        let key = match load(Path::new(file), err).await {
            Ok(key) => key,
            Err(code) => return code,
        };
        if let Err(e) = agent.add_identity(&key, &constraints).await {
            // podssh agent keeps no RSA key (T-257); another agent may.
            let why = if key.algorithm().is_rsa() {
                "; podssh agent keeps no RSA key, as russh's agent server would sign with it through the rsa \
                 crate, which is not constant-time: use an Ed25519 key, or OpenSSH's ssh-agent"
            } else {
                ""
            };
            let _ = writeln!(err, "podssh agent: the agent refused {file}: {e}{why}");
            return EX_SOFTWARE;
        }
        let _ = writeln!(err, "Identity added: {file} ({})", key.comment());
        if let Some(seconds) = lifetime {
            let _ = writeln!(err, "Lifetime set to {seconds} seconds");
        }
    }
    0
}

/// `list`: a line for each key, as `ssh-add -l` writes it; 1, as there,
/// when the agent holds none.
pub async fn list(out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut agent = match connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    let identities = match agent.request_identities().await {
        Ok(identities) => identities,
        Err(e) => {
            let _ = writeln!(err, "podssh agent: the agent did not list its keys: {e}");
            return EX_SOFTWARE;
        }
    };
    if identities.is_empty() {
        let _ = writeln!(out, "The agent has no identities.");
        return 1;
    }
    for identity in &identities {
        let key = identity.public_key();
        let _ = writeln!(
            out,
            "{} {} {} ({})",
            bits(&key),
            key.fingerprint(HashAlg::Sha256),
            identity.comment(),
            podssh_ssh::known_hosts::key_type(&key)
        );
    }
    0
}

/// `remove FILE...` or `remove --all`.
pub async fn remove(args: &AgentArgs, _out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut agent = match connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    if args.all {
        // Each key in turn: russh 0.64.1's own request for all of them goes
        // out with no length, and no agent understands it.
        let identities = match agent.request_identities().await {
            Ok(identities) => identities,
            Err(e) => {
                let _ = writeln!(err, "podssh agent: the agent did not list its keys: {e}");
                return EX_SOFTWARE;
            }
        };
        for identity in &identities {
            if let Err(e) = agent.remove_identity(&identity.public_key()).await {
                let _ = writeln!(err, "podssh agent: the agent did not remove a key: {e}");
                return EX_SOFTWARE;
            }
        }
        let _ = writeln!(err, "All identities removed.");
        return 0;
    }
    for file in &args.args {
        let public = match public_of(Path::new(file), err).await {
            Ok(public) => public,
            Err(code) => return code,
        };
        if let Err(e) = agent.remove_identity(&public).await {
            let _ = writeln!(err, "podssh agent: the agent did not remove {file}: {e}");
            return EX_SOFTWARE;
        }
        let _ = writeln!(err, "Identity removed: {file}");
    }
    0
}

/// `lock` (the password asked twice) or `unlock`.
pub async fn lock(locking: bool, _out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut agent = match connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    let password = match ask("Enter lock password: ".into()).await {
        Ok(password) => password,
        Err(e) => {
            let _ = writeln!(err, "podssh agent: no password: {e}");
            return EX_NOPERM;
        }
    };
    if locking {
        match ask("Again: ".into()).await {
            Ok(again) if again.as_str() == password.as_str() => {}
            Ok(_) => {
                let _ = writeln!(err, "podssh agent: the passwords do not match");
                return EX_NOPERM;
            }
            Err(e) => {
                let _ = writeln!(err, "podssh agent: no password: {e}");
                return EX_NOPERM;
            }
        }
    }
    let done = if locking { agent.lock(password.as_bytes()).await } else { agent.unlock(password.as_bytes()).await };
    match (done, locking) {
        (Ok(()), true) => {
            let _ = writeln!(err, "Agent locked.");
            0
        }
        (Ok(()), false) => {
            let _ = writeln!(err, "Agent unlocked.");
            0
        }
        (Err(e), _) => {
            let _ = writeln!(err, "podssh agent: the agent refused: {e}");
            EX_NOPERM
        }
    }
}

/// A key file, opened with its passphrase when it asks for one.
async fn load(path: &Path, err: &mut dyn Write) -> Result<PrivateKey, i32> {
    match podssh_ssh::key_file::load(path, None) {
        Ok(key) => Ok(key),
        Err(podssh_ssh::russh::keys::Error::KeyIsEncrypted) => {
            let passphrase = match ask(format!("Enter passphrase for {}: ", path.display())).await {
                Ok(passphrase) => passphrase,
                Err(e) => {
                    let _ = writeln!(err, "podssh agent: {} is encrypted, and no passphrase came: {e}", path.display());
                    return Err(EX_NOPERM);
                }
            };
            podssh_ssh::key_file::load(path, Some(passphrase.as_str())).map_err(|_| {
                let _ = writeln!(err, "podssh agent: bad passphrase for {}", path.display());
                EX_NOPERM
            })
        }
        Err(e) => {
            let _ = writeln!(err, "podssh agent: {}: {e}", path.display());
            Err(EX_NOINPUT)
        }
    }
}

/// The public key of a key file: the file itself, or `FILE.pub`, else the
/// private key's half.
async fn public_of(path: &Path, err: &mut dyn Write) -> Result<PublicKey, i32> {
    if let Ok(public) = podssh_ssh::russh::keys::load_public_key(path) {
        return Ok(public);
    }
    let mut pub_file = path.as_os_str().to_owned();
    pub_file.push(".pub");
    if let Ok(public) = podssh_ssh::russh::keys::load_public_key(&pub_file) {
        return Ok(public);
    }
    load(path, err).await.map(|key| key.public_key().clone())
}

/// A prompt on its own thread, as it may block on the terminal.
async fn ask(text: String) -> Result<Zeroizing<String>, PromptError> {
    tokio::task::spawn_blocking(move || prompt::ask(&text, false))
        .await
        .unwrap_or(Err(PromptError::Failed("the prompt's thread failed".into())))
}

/// The size of a key, as `ssh-add -l` shows it.
fn bits(key: &PublicKey) -> usize {
    use podssh_ssh::russh::keys::ssh_key::public::KeyData;
    match key.key_data() {
        KeyData::Ed25519(_) => 256,
        KeyData::Ecdsa(ecdsa) => match ecdsa.curve().as_str() {
            "nistp384" => 384,
            "nistp521" => 521,
            _ => 256,
        },
        KeyData::Rsa(rsa) => rsa.n().as_positive_bytes().map_or(0, |n| n.len() * 8),
        _ => 0,
    }
}
