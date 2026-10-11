//! The hops of `-J` and `ProxyJump` (T-290), each as OpenSSH's jump host
//! resolves itself: the blocks of `ssh_config` for its own name give it its
//! `HostName`, `Port`, `User`, keys and the rest. A `ProxyJump` there puts a
//! chain before the first hop of a list alone: OpenSSH gives each later hop
//! the hops before it as its `-J`, which beats its file. The command line's
//! settings of host keys, authentication, keys and time hold for each hop
//! too (T-030); `-l`, `-p` and the destination's settings are the
//! destination's alone, as OpenSSH's jump process gets none of them.

use std::time::Duration;

use podssh_ssh::{Hop, Options};

use super::args::SshArgs;
use super::hop::{host_rule, jump_hop};
use super::options::Settings;
use super::resolve::Env;
use super::tokens::{jump_token, lower_host, Tokens, USER_REFUSES};
use crate::relay_settings::Refusal;

/// A chain longer than this is refused: a loop through names that differ,
/// or a mistake.
const MOST_HOPS: usize = 16;

/// The hops of `list`, a value of `-J` or `ProxyJump`, in order, each with
/// its options; `cli` holds the settings of the command line's `-o`.
pub(super) fn hops(list: &str, args: &SshArgs, cli: &Settings, env: &Env) -> Result<(Vec<Hop>, Vec<Options>), Refusal> {
    let mut chain = Chain { args, cli: for_hop(cli), env, hops: Vec::new(), options: Vec::new(), path: Vec::new() };
    chain.list(list)?;
    Ok((chain.hops, chain.options))
}

/// The settings of the command line that hold for each hop too (T-030):
/// host keys, authentication, keys and time.
fn for_hop(cli: &Settings) -> Settings {
    Settings {
        identity_files: cli.identity_files.clone(),
        identities_only: cli.identities_only,
        identity_agent: cli.identity_agent.clone(),
        strict: cli.strict,
        user_known_hosts: cli.user_known_hosts.clone(),
        global_known_hosts: cli.global_known_hosts.clone(),
        batch_mode: cli.batch_mode,
        preferred_auth: cli.preferred_auth.clone(),
        pubkey: cli.pubkey,
        password: cli.password,
        kbd_interactive: cli.kbd_interactive,
        password_prompts: cli.password_prompts,
        alive_interval: cli.alive_interval,
        alive_count: cli.alive_count,
        connect_timeout: cli.connect_timeout,
        log_level: cli.log_level,
        ignore_unknown: cli.ignore_unknown.clone(),
        ..Settings::default()
    }
}

struct Chain<'a> {
    args: &'a SshArgs,
    cli: Settings,
    env: &'a Env,
    hops: Vec<Hop>,
    options: Vec<Options>,
    /// The hops whose own chain is being read: one met again is a loop.
    path: Vec<String>,
}

/// A hop's settings: the command line's, then those of its blocks; and the
/// `User` and `Port` of its blocks, which its `user@` and `:PORT` beat.
struct Filed {
    settings: Settings,
    user: Option<String>,
    port: Option<u16>,
}

impl Chain<'_> {
    /// Each hop of `list`; before the first, the chain of its own
    /// `ProxyJump`.
    fn list(&mut self, list: &str) -> Result<(), Refusal> {
        for (i, text) in list.split(',').map(str::trim).enumerate() {
            let target = jump_hop(text)?;
            let filed = self.filed(&target)?;
            let own = filed.settings.proxy_jump.clone().filter(|j| i == 0 && j != "none");
            if let Some(own) = own {
                if self.path.iter().any(|t| t == text) {
                    return Err(format!("ProxyJump {own} of {text}: a jump host loop, through {text} again").into());
                }
                self.path.push(text.to_string());
                self.list(&own)?;
                self.path.pop();
            }
            if self.hops.len() >= MOST_HOPS {
                return Err(format!("-J {text}: a chain of more than {MOST_HOPS} jump hosts").into());
            }
            let (hop, options) = self.hop(&target, filed)?;
            self.hops.push(hop);
            self.options.push(options);
        }
        Ok(())
    }

    /// The blocks of `ssh_config` for the hop's own name, under the command
    /// line, as for the destination (T-043).
    fn filed(&self, target: &Hop) -> Result<Filed, Refusal> {
        let env = self.env;
        let source = super::config::file(self.args.config.as_deref(), env.ssh_config.as_deref(), env.home.as_deref());
        let so_far = |file: &Settings| include_tokens(target, env, file);
        let ctx = super::config::Context {
            host: &target.host,
            home: env.home.as_deref(),
            system: env.system_config.as_deref(),
            tokens: &so_far,
        };
        let file = super::config::read(&source, &ctx, self.cli.ignore_unknown.clone()).map_err(Refusal::config)?;
        let (user, port) = (file.user.clone(), file.port);
        Ok(Filed { settings: self.cli.clone().then_file(file), user, port })
    }

    /// The hop's address, user and options.
    fn hop(&self, target: &Hop, filed: Filed) -> Result<(Hop, Options), Refusal> {
        let (env, settings) = (self.env, filed.settings);
        let host = match settings.host_name.as_deref() {
            Some(name) => {
                let name = super::tokens::host_name(name, &target.host)?;
                host_rule(&format!("HostName={name}"), &name)?;
                name
            }
            None => target.host.clone(),
        };
        let port = Some(target.port).filter(|p| *p != 22).or(filed.port).unwrap_or(22);
        let mut tokens = Tokens {
            home: env.home.clone(),
            host: lower_host(&host),
            original: target.host.clone(),
            port,
            remote_user: String::new(),
            local_user: env.user.clone(),
            local_host: env.local_host.clone(),
            uid: env.uid,
            alias: settings
                .host_key_alias
                .as_deref()
                .map(str::to_ascii_lowercase)
                .unwrap_or_else(|| target.host.clone()),
            jump: jump_token(settings.proxy_jump.as_deref()),
        };
        // `user@` as it is, else its `User` expanded, else the local user:
        // never the destination's.
        let user = match (&target.user, &filed.user) {
            (Some(user), _) => user.clone(),
            (None, Some(user)) => tokens.text("User ", user, USER_REFUSES)?,
            (None, None) => env.user.clone().ok_or_else(|| {
                format!("no user name for the jump host {}: give one as user@host, or User in ssh_config", target.host)
            })?,
        };
        tokens.remote_user = user.clone();
        let login = super::login::login(&self.args.identity_files, &settings, &tokens, env)?;
        let hop = Hop { user: Some(user.clone()), host, port };
        let mut options = Options::new(hop.clone(), user);
        options.host_key_alias = settings.host_key_alias.as_deref().map(str::to_ascii_lowercase);
        login.apply(&mut options, &settings);
        let expand = |setting: &str, p: &str| tokens.expand(setting, p);
        options.agent = super::agents::choose(Some(false), &settings, &expand)?.identity;
        options.keepalive_interval = match settings.alive_interval {
            Some(0) => None,
            Some(s) => Some(Duration::from_secs(s)),
            None => Some(Duration::from_secs(60)),
        };
        options.compression = settings.compression.unwrap_or(false);
        Ok((hop, options))
    }
}

/// The `%` tokens of an `Include` in a hop's blocks, with the values of the
/// moment, as `tokens::include_tokens` gives the destination's, with none of
/// the destination's flags.
fn include_tokens(target: &Hop, env: &Env, file: &Settings) -> Tokens {
    Tokens {
        home: env.home.clone(),
        host: file.host_name.clone().unwrap_or_else(|| target.host.clone()),
        original: target.host.clone(),
        port: Some(target.port).filter(|p| *p != 22).or(file.port).unwrap_or(22),
        remote_user: target.user.clone().or_else(|| file.user.clone()).or_else(|| env.user.clone()).unwrap_or_default(),
        local_user: env.user.clone(),
        local_host: env.local_host.clone(),
        uid: env.uid,
        alias: file.host_key_alias.clone().unwrap_or_else(|| target.host.clone()),
        jump: jump_token(file.proxy_jump.as_deref()),
    }
}
