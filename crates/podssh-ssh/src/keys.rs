//! Public keys to offer, one per attempt: an agent's keys first, then key
//! files, each key at most once (a key both in the agent and on disk is
//! offered once). With `IdentitiesOnly`, agent keys are offered only when they
//! match a configured key file.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::Handle;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::agent::AgentIdentity;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};

use crate::answer::{within, within_signing, AgentTime, Timed};
use crate::auth::Step;
use crate::handler::Client;
use crate::log::Log;
use crate::options::{Agent, Options};
use crate::prompt::{self, PromptError};

type DynAgent = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

enum AgentState {
    NotTried,
    Ready(DynAgent, VecDeque<PublicKey>),
    Done,
}

pub(crate) struct PublicKeys {
    files: VecDeque<PathBuf>,
    all_files: Vec<PathBuf>,
    identities_only: bool,
    agent_choice: Agent,
    agent: AgentState,
    can_prompt: bool,
    passphrase_tries: u32,
    log: Arc<Log>,
    offered: Vec<PublicKey>,
    rsa_hash: Option<Option<HashAlg>>,
    skipped_encrypted: Vec<PathBuf>,
    /// The limit on each answer of the server (`ConnectTimeout`), and the
    /// host's name for its message.
    limit: Duration,
    host: String,
}

impl PublicKeys {
    pub fn new(opts: &Options, host: &str, log: Arc<Log>) -> Self {
        PublicKeys {
            files: opts.identity_files.iter().cloned().collect(),
            all_files: opts.identity_files.clone(),
            identities_only: opts.identities_only,
            agent_choice: opts.agent.clone(),
            agent: AgentState::NotTried,
            can_prompt: !opts.batch_mode,
            passphrase_tries: opts.password_prompts.max(1),
            log,
            offered: Vec::new(),
            rsa_hash: None,
            skipped_encrypted: Vec::new(),
            limit: opts.connect_timeout,
            host: host.to_string(),
        }
    }

    /// Offer the next key; `Exhausted` when none is left.
    pub async fn try_next(&mut self, handle: &mut Handle<Client>, user: &str) -> Result<Step, String> {
        if let Some(step) = self.try_agent(handle, user).await? {
            return Ok(step);
        }
        while let Some(path) = self.files.pop_front() {
            let Some(key) = self.load(&path).await else { continue };
            let public = key.public_key().clone();
            if self.offered.iter().any(|k| k.key_data() == public.key_data()) {
                continue;
            }
            let hash = self.hash_for(handle, &public).await;
            self.log.debug(&format!("offering {} key {}", crate::known_hosts::key_type(&public), path.display()));
            let call = handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash));
            let result = within(self.limit, &self.host, "the publickey request", call)
                .await?
                .map_err(|e| format!("public key authentication failed: {e}"))?;
            self.offered.push(public);
            return Ok(Step::from(result));
        }
        Ok(Step::Exhausted)
    }

    /// What to add to a final "Permission denied" message.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.offered.is_empty() {
            let files: Vec<String> = self.all_files.iter().map(|p| p.display().to_string()).collect();
            notes.push(if files.is_empty() {
                "no key was offered: no key file is configured and no agent answered; use -i FILE".to_string()
            } else {
                format!(
                    "no key was offered: no agent answered and none of these could be used: {}; use -i FILE",
                    files.join(", ")
                )
            });
        }
        if !self.skipped_encrypted.is_empty() {
            let files: Vec<String> = self.skipped_encrypted.iter().map(|p| p.display().to_string()).collect();
            notes.push(format!(
                "skipped encrypted key(s) {}: there is no terminal or SSH_ASKPASS for the passphrase",
                files.join(", ")
            ));
        }
        notes
    }

    async fn try_agent(&mut self, handle: &mut Handle<Client>, user: &str) -> Result<Option<Step>, String> {
        if let AgentState::NotTried = self.agent {
            self.agent = match connect_agent(&self.agent_choice).await {
                Ok(Some(mut agent)) => match agent.request_identities().await {
                    Ok(ids) => {
                        let wanted = if self.identities_only { self.file_public_keys() } else { Vec::new() };
                        let keys: VecDeque<PublicKey> = ids
                            .into_iter()
                            .filter_map(|id| match id {
                                AgentIdentity::PublicKey { key, .. } => Some(key),
                                AgentIdentity::Certificate { .. } => None,
                            })
                            .filter(|k| !self.identities_only || wanted.iter().any(|w| w.key_data() == k.key_data()))
                            .collect();
                        self.log.debug(&format!("the agent offers {} usable key(s)", keys.len()));
                        AgentState::Ready(agent, keys)
                    }
                    Err(e) => {
                        self.log.verbose(&format!("the agent did not list its keys: {e}"));
                        AgentState::Done
                    }
                },
                Ok(None) => AgentState::Done,
                Err(why) => {
                    self.log.verbose(&format!("no agent: {why}"));
                    AgentState::Done
                }
            };
        }
        loop {
            let AgentState::Ready(_, keys) = &mut self.agent else { return Ok(None) };
            let Some(key) = keys.pop_front() else {
                self.agent = AgentState::Done;
                return Ok(None);
            };
            if self.offered.iter().any(|k| k.key_data() == key.key_data()) {
                continue;
            }
            let hash = self.hash_for(handle, &key).await;
            let AgentState::Ready(agent, _) = &mut self.agent else { return Ok(None) };
            self.log.debug(&format!("offering agent key {}", crate::known_hosts::fingerprint(&key)));
            let time = Arc::new(Mutex::new(AgentTime::default()));
            let mut timed = Timed { inner: agent, time: time.clone() };
            let call = handle.authenticate_publickey_with(user, key.clone(), hash, &mut timed);
            match within_signing(self.limit, &self.host, "the publickey request", &time, call).await? {
                Ok(result) => {
                    self.offered.push(key);
                    return Ok(Some(Step::from(result)));
                }
                Err(e) => self.log.verbose(&format!("the agent could not sign: {e}")),
            }
        }
    }

    /// The hash for an RSA signature: the best the server lists, else
    /// SHA-512 (no RSA key is ever signed with SHA-1 unless the server asks).
    async fn hash_for(&mut self, handle: &Handle<Client>, key: &PublicKey) -> Option<HashAlg> {
        if !key.algorithm().is_rsa() {
            return None;
        }
        if self.rsa_hash.is_none() {
            self.rsa_hash = Some(match handle.best_supported_rsa_hash().await {
                Ok(Some(best)) => best,
                _ => Some(HashAlg::Sha512),
            });
        }
        self.rsa_hash.flatten()
    }

    async fn load(&mut self, path: &Path) -> Option<PrivateKey> {
        if !path.exists() {
            self.log.debug(&format!("no key file at {}", path.display()));
            return None;
        }
        warn_if_readable_by_others(path, &self.log);
        match russh::keys::load_secret_key(path, None) {
            Ok(key) => Some(key),
            Err(russh::keys::Error::KeyIsEncrypted) => self.decrypt(path).await,
            Err(e) => {
                self.log.info(&format!("could not use the key file {}: {e}", path.display()));
                None
            }
        }
    }

    async fn decrypt(&mut self, path: &Path) -> Option<PrivateKey> {
        if !self.can_prompt || !prompt::can_ask() {
            self.skipped_encrypted.push(path.to_path_buf());
            return None;
        }
        for _ in 0..self.passphrase_tries {
            let text = format!("Enter passphrase for key '{}': ", path.display());
            let answer = tokio::task::spawn_blocking(move || prompt::ask(&text, false))
                .await
                .unwrap_or(Err(PromptError::Failed("the prompt thread failed".into())));
            match answer {
                Ok(p) if p.is_empty() => return None,
                Ok(p) => match russh::keys::load_secret_key(path, Some(p.as_str())) {
                    Ok(key) => return Some(key),
                    Err(_) => self.log.info(&format!("Bad passphrase for {}.", path.display())),
                },
                Err(_) => return None,
            }
        }
        None
    }

    /// The public halves of the key files, for matching agent keys under
    /// `IdentitiesOnly`: from `FILE.pub`, else from an unencrypted `FILE`.
    fn file_public_keys(&self) -> Vec<PublicKey> {
        let mut out = Vec::new();
        for path in &self.all_files {
            let mut public_path = path.clone().into_os_string();
            public_path.push(".pub");
            if let Ok(k) = russh::keys::load_public_key(PathBuf::from(public_path)) {
                out.push(k);
            } else if let Ok(k) = russh::keys::load_secret_key(path, None) {
                out.push(k.public_key().clone());
            }
        }
        out
    }
}

/// OpenSSH refuses a key file others can read; podssh uses it and says so,
/// because on the hosts it targets `chmod` may not work at all.
fn warn_if_readable_by_others(path: &Path, log: &Log) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                log.info(&format!(
                    "warning: the key file {} can be read by others (mode {mode:04o}); using it anyway",
                    path.display()
                ));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, log);
}

async fn connect_agent(choice: &Agent) -> Result<Option<DynAgent>, String> {
    match choice {
        Agent::Off => Ok(None),
        #[cfg(unix)]
        Agent::FromEnvironment => {
            if std::env::var_os("SSH_AUTH_SOCK").is_none_or(|v| v.is_empty()) {
                return Ok(None);
            }
            AgentClient::connect_env().await.map(|a| Some(a.dynamic())).map_err(|e| e.to_string())
        }
        #[cfg(unix)]
        Agent::Path(path) => AgentClient::connect_uds(path).await.map(|a| Some(a.dynamic())).map_err(|e| e.to_string()),
        #[cfg(windows)]
        Agent::FromEnvironment => {
            let pipe = std::env::var_os("SSH_AUTH_SOCK")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".into());
            if let Ok(a) = AgentClient::connect_named_pipe(&pipe).await {
                return Ok(Some(a.dynamic()));
            }
            match AgentClient::connect_pageant().await {
                Ok(a) => Ok(Some(a.dynamic())),
                Err(_) => Ok(None),
            }
        }
        #[cfg(windows)]
        Agent::Path(path) => {
            AgentClient::connect_named_pipe(path).await.map(|a| Some(a.dynamic())).map_err(|e| e.to_string())
        }
    }
}
