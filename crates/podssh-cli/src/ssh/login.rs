//! The settings of one login, the destination's or a hop's of `-J` alike
//! (T-290): its key files, its `known_hosts` files and its methods, from `-i`
//! and its settings, with the `%` tokens of its own connection.

use std::path::PathBuf;
use std::time::Duration;

use podssh_ssh::options::{default_global_known_hosts, default_identity_files, default_user_known_hosts};
use podssh_ssh::{Method, Options, StrictHostKeyChecking};

use super::options::Settings;
use super::resolve::Env;
use super::tokens::Tokens;

/// The lists of a login, made from its settings.
pub(super) struct Login {
    identity_files: Vec<PathBuf>,
    user_known_hosts: Vec<PathBuf>,
    no_user_known_hosts: Option<&'static str>,
    global_known_hosts: Vec<PathBuf>,
    methods: Vec<Method>,
    publickey_off: Option<String>,
}

/// The login of one connection: `cli_files` are the key files of `-i`, tried
/// before those of `IdentityFile`; with neither, the defaults of the home.
pub(super) fn login(cli_files: &[String], settings: &Settings, tokens: &Tokens, env: &Env) -> Result<Login, String> {
    let expand = |setting: &str, p: &str| tokens.expand(setting, p);
    let mut identity_files: Vec<PathBuf> = cli_files
        .iter()
        .map(|p| expand("-i ", p))
        .chain(settings.identity_files.iter().map(|p| expand("-o IdentityFile=", p)))
        .collect::<Result<_, _>>()?;
    if identity_files.is_empty() {
        identity_files = env.home.as_deref().map(default_identity_files).unwrap_or_default();
    }
    let known = |setting: &str, list: &Option<Vec<String>>, default: Vec<PathBuf>| -> Result<Vec<PathBuf>, String> {
        Ok(match list {
            Some(files) if files.iter().any(|f| f.eq_ignore_ascii_case("none")) => Vec::new(),
            Some(files) => files.iter().map(|f| expand(setting, f)).collect::<Result<_, _>>()?,
            None => default,
        })
    };
    let user_known_hosts = known(
        "-o UserKnownHostsFile=",
        &settings.user_known_hosts,
        env.home.as_deref().map(default_user_known_hosts).unwrap_or_default(),
    )?;
    let global_known_hosts =
        known("-o GlobalKnownHostsFile=", &settings.global_known_hosts, default_global_known_hosts())?;
    // Why no user file is read: a key accepted then is not recorded (T-028).
    let no_user_known_hosts = match &settings.user_known_hosts {
        Some(files) if files.iter().any(|f| f.eq_ignore_ascii_case("none")) => Some("UserKnownHostsFile is none"),
        None if env.home.is_none() && cfg!(windows) => Some("neither HOME nor USERPROFILE is set"),
        None if env.home.is_none() => Some("HOME is not set"),
        _ => None,
    };

    let mut methods = settings
        .preferred_auth
        .clone()
        .unwrap_or_else(|| vec![Method::PublicKey, Method::KeyboardInteractive, Method::Password]);
    methods.retain(|m| match m {
        Method::PublicKey => settings.pubkey != Some(false),
        Method::Password => settings.password != Some(false),
        Method::KeyboardInteractive => settings.kbd_interactive != Some(false),
    });
    let publickey_off = match (methods.contains(&Method::PublicKey), settings.pubkey) {
        (true, _) => None,
        (false, Some(false)) => Some("-o PubkeyAuthentication=no".to_string()),
        (false, _) => Some("PreferredAuthentications does not list publickey".to_string()),
    };
    Ok(Login { identity_files, user_known_hosts, no_user_known_hosts, global_known_hosts, methods, publickey_off })
}

impl Login {
    /// Into `options`, with the single values of `settings` that each login
    /// takes: its host keys, its prompts and its times.
    pub(super) fn apply(self, options: &mut Options, settings: &Settings) {
        options.identity_files = self.identity_files;
        options.identities_only = settings.identities_only.unwrap_or(false);
        options.strict_host_key_checking = settings.strict.unwrap_or(StrictHostKeyChecking::Ask);
        options.user_known_hosts = self.user_known_hosts;
        options.no_user_known_hosts = self.no_user_known_hosts;
        options.global_known_hosts = self.global_known_hosts;
        options.batch_mode = settings.batch_mode.unwrap_or(false);
        options.methods = self.methods;
        options.publickey_off = self.publickey_off;
        options.password_prompts = settings.password_prompts.unwrap_or(3);
        options.keepalive_max = settings.alive_count.unwrap_or(3);
        options.connect_timeout = Duration::from_secs(settings.connect_timeout.unwrap_or(60));
    }
}
