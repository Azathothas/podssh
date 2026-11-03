//! `-o NAME=VALUE`: the OpenSSH keywords podssh honours, those it accepts and
//! ignores, and those it refuses by name. The lists are in `keywords.rs`,
//! which the manual also reads. An unknown keyword is an error before anything
//! connects, as in OpenSSH: a silently dropped `-o StrictHostKeyChecking=…`
//! would be a security bug.

use podssh_ssh::{LogLevel, Method, RequestTty, StrictHostKeyChecking};

use super::given::{Given, Place};
use super::keywords;

// The values of the keywords, apart for the length of this file.
#[path = "options_values.rs"]
mod values;
pub(super) use values::words;
pub use values::{parse_port, yes_no};
use values::{parse_seconds, unknown, unquote};

/// What `-o` set, before defaults. For single values the first one given
/// wins, as in OpenSSH; lists accumulate.
#[derive(Debug, Default, Clone)]
pub struct Settings {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub host_name: Option<String>,
    pub host_key_alias: Option<String>,
    pub identity_files: Vec<String>,
    pub identities_only: Option<bool>,
    pub identity_agent: Option<String>,
    /// `ForwardAgent`: whether to forward the agent (the first value; a path
    /// is yes), and the first path or `$NAME` given, which OpenSSH keeps
    /// apart from it (T-036).
    pub forward_agent: Option<bool>,
    pub forward_agent_path: Option<String>,
    /// `ForwardX11`, `ForwardX11Trusted`, `ForwardX11Timeout` (seconds) and
    /// `XAuthLocation` (T-037).
    pub forward_x11: Option<bool>,
    pub forward_x11_trusted: Option<bool>,
    pub forward_x11_timeout: Option<u64>,
    pub xauth_location: Option<String>,
    pub strict: Option<StrictHostKeyChecking>,
    pub user_known_hosts: Option<Vec<String>>,
    pub global_known_hosts: Option<Vec<String>>,
    pub batch_mode: Option<bool>,
    pub preferred_auth: Option<Vec<Method>>,
    pub pubkey: Option<bool>,
    pub password: Option<bool>,
    pub kbd_interactive: Option<bool>,
    pub password_prompts: Option<u32>,
    pub alive_interval: Option<u64>,
    pub alive_count: Option<usize>,
    pub connect_timeout: Option<u64>,
    /// `ConnectionAttempts`: rounds over the relay hosts (or dials, direct).
    pub connection_attempts: Option<u32>,
    pub request_tty: Option<RequestTty>,
    pub escape_char: Option<Option<u8>>,
    pub set_env: Vec<(String, String)>,
    pub send_env: Vec<String>,
    pub compression: Option<bool>,
    pub log_level: Option<LogLevel>,
    pub remote_command: Option<String>,
    /// `LocalCommand` as given, and `PermitLocalCommand` (T-191).
    pub local_command: Option<String>,
    pub permit_local_command: Option<bool>,
    pub proxy_jump: Option<String>,
    /// `ProxyCommand` (T-502): the first value given, `none` or podssh's own
    /// proxy, which podssh takes as its own road; a later one is not read,
    /// nor a later `ProxyJump`, as in OpenSSH.
    pub proxy_command: Option<Given>,
    /// 4 or 6 from `AddressFamily`; `Some(0)` for `any`.
    pub address_family: Option<u8>,
    pub stdin_null: Option<bool>,
    /// `SessionType`: `none`, `subsystem` or `default`.
    pub session_type: Option<String>,
    /// `Tag`, which `Match tagged` reads (T-045).
    pub tag: Option<String>,
    /// `RemoteForward`: each one given, as for `-R`.
    pub remote_forwards: Vec<podssh_ssh::RemoteForward>,
    /// `LocalForward` and `DynamicForward` (T-038): each one given.
    pub local_forwards: Vec<super::local_spec::LocalSpec>,
    /// `GatewayPorts`: `-L` and `-D` with no address listen on each address.
    pub gateway_ports: Option<bool>,
    /// `ClearAllForwardings`: no `-L`, `-D` or `-R`, from any place.
    pub clear_all_forwardings: Option<bool>,
    pub exit_on_forward_failure: Option<bool>,
    /// `ForkAfterAuthentication`: `-f` (T-380).
    pub fork_after_authentication: Option<bool>,
    /// `ControlMaster`, `ControlPath` and `ControlPersist` (T-039).
    pub control_master: Option<super::control::Mode>,
    pub control_path: Option<String>,
    pub control_persist: Option<super::control::Persist>,
    /// `IgnoreUnknown`: a pattern list of unknown keywords to accept without
    /// effect, when they come after it.
    pub ignore_unknown: Option<String>,
    /// Keywords accepted without effect, for a verbose note.
    pub ignored: Vec<String>,
}

impl Settings {
    /// Apply one `-o` argument: `Name=Value`, `Name Value` or `Name = Value`.
    pub fn apply(&mut self, raw: &str) -> Result<(), String> {
        self.apply_at(raw, &Place::CommandLine)
    }

    /// Apply one keyword and its value, given at `place`, which a note and a
    /// refusal name: a line of a file is applied as `-o` is.
    pub fn apply_at(&mut self, raw: &str, place: &Place) -> Result<(), String> {
        let raw = raw.trim();
        let split = raw.find(|c: char| c == '=' || c.is_whitespace()).unwrap_or(raw.len());
        let (name, rest) = raw.split_at(split);
        let value = rest.trim_start().trim_start_matches('=').trim();
        if name.is_empty() {
            return Err(format!("-o {raw:?}: expected NAME=VALUE"));
        }
        let key = name.to_ascii_lowercase();
        if value.is_empty() && !keywords::is_ignored(&key) {
            return Err(format!("-o {name}: missing value"));
        }
        let bad = |what: &str| format!("-o {name}={value}: {what}");
        match key.as_str() {
            "user" => set(&mut self.user, value.to_string()),
            "port" => set(&mut self.port, parse_port(value).ok_or_else(|| bad("not a port"))?),
            "hostname" => set(&mut self.host_name, value.to_string()),
            "hostkeyalias" => set(&mut self.host_key_alias, value.to_string()),
            "identityfile" => add(&mut self.identity_files, unquote(value)),
            "identitiesonly" => set(&mut self.identities_only, yes_no(value).ok_or_else(|| bad("expected yes or no"))?),
            "identityagent" => set(&mut self.identity_agent, unquote(value)),
            "forwardagent" => match (yes_no(value), unquote(value)) {
                (Some(on), _) => set(&mut self.forward_agent, on),
                (None, path) if path.is_empty() => return Err(bad("expected yes, no, a path or $NAME")),
                (None, path) => {
                    set(&mut self.forward_agent, true);
                    set(&mut self.forward_agent_path, path);
                }
            },
            "forwardx11" => set(&mut self.forward_x11, yes_no(value).ok_or_else(|| bad("expected yes or no"))?),
            "forwardx11trusted" => {
                set(&mut self.forward_x11_trusted, yes_no(value).ok_or_else(|| bad("expected yes or no"))?)
            }
            "forwardx11timeout" => set(
                &mut self.forward_x11_timeout,
                super::control::seconds(&value.to_ascii_lowercase()).ok_or_else(|| bad("not a time"))?,
            ),
            "xauthlocation" => set(&mut self.xauth_location, unquote(value)),
            "stricthostkeychecking" => set(
                &mut self.strict,
                StrictHostKeyChecking::parse(value).ok_or_else(|| bad("expected yes, accept-new, no or ask"))?,
            ),
            "userknownhostsfile" => set(&mut self.user_known_hosts, words(value)),
            "globalknownhostsfile" => set(&mut self.global_known_hosts, words(value)),
            "batchmode" => set(&mut self.batch_mode, yes_no(value).ok_or_else(|| bad("expected yes or no"))?),
            "preferredauthentications" => {
                let methods: Vec<Method> = value.split(',').filter_map(Method::parse).collect();
                if methods.is_empty() {
                    return Err(bad("podssh supports publickey, keyboard-interactive and password"));
                }
                set(&mut self.preferred_auth, methods)
            }
            "pubkeyauthentication" => set(
                &mut self.pubkey,
                yes_no(value).or((value == "unbound").then_some(true)).ok_or_else(|| bad("expected yes or no"))?,
            ),
            "passwordauthentication" => {
                set(&mut self.password, yes_no(value).ok_or_else(|| bad("expected yes or no"))?)
            }
            "kbdinteractiveauthentication" | "challengeresponseauthentication" => {
                set(&mut self.kbd_interactive, yes_no(value).ok_or_else(|| bad("expected yes or no"))?)
            }
            "numberofpasswordprompts" => {
                set(&mut self.password_prompts, value.parse().map_err(|_| bad("not a number"))?)
            }
            "serveraliveinterval" => {
                set(&mut self.alive_interval, parse_seconds(value).ok_or_else(|| bad("not a number of seconds"))?)
            }
            "serveralivecountmax" => set(&mut self.alive_count, value.parse().map_err(|_| bad("not a number"))?),
            "connecttimeout" => set(
                &mut self.connect_timeout,
                parse_seconds(value).filter(|s| *s > 0).ok_or_else(|| bad("not a number of seconds"))?,
            ),
            "connectionattempts" => set(
                &mut self.connection_attempts,
                value.parse().ok().filter(|n| (1..=100).contains(n)).ok_or_else(|| bad("a number from 1 to 100"))?,
            ),
            "requesttty" => set(
                &mut self.request_tty,
                RequestTty::parse(value).ok_or_else(|| bad("expected auto, yes, force or no"))?,
            ),
            "escapechar" => set(
                &mut self.escape_char,
                podssh_ssh::escape::parse_escape_char(value).ok_or_else(|| bad("expected none, a character or ^X"))?,
            ),
            "setenv" => {
                let mut pairs: Vec<(String, String)> = Vec::new();
                for pair in words(value) {
                    let (n, v) = pair.split_once('=').ok_or_else(|| bad("expected NAME=VALUE"))?;
                    if !pairs.iter().any(|(k, _)| k == n) {
                        pairs.push((n.to_string(), v.to_string()));
                    }
                }
                // The first SetEnv holds whole, as in OpenSSH (T-045).
                if self.set_env.is_empty() {
                    self.set_env = pairs;
                }
            }
            "sendenv" => self.send_env.extend(words(value)),
            "compression" => set(&mut self.compression, yes_no(value).ok_or_else(|| bad("expected yes or no"))?),
            "loglevel" => set(&mut self.log_level, LogLevel::parse(value).ok_or_else(|| bad("not a log level"))?),
            "remotecommand" => set(&mut self.remote_command, value.to_string()),
            "localcommand" => set(&mut self.local_command, value.to_string()),
            "permitlocalcommand" => {
                set(&mut self.permit_local_command, yes_no(value).ok_or_else(|| bad("expected yes or no"))?)
            }
            // A ProxyCommand that holds goes before a later ProxyJump, which
            // OpenSSH 10.3p1 does not read then (readconf.c, parse_jump).
            "proxyjump" if self.proxy_command.is_some() => {}
            "proxyjump" => set(&mut self.proxy_jump, value.to_string()),
            "addressfamily" => set(
                &mut self.address_family,
                match value.to_ascii_lowercase().as_str() {
                    "any" => 0,
                    "inet" => 4,
                    "inet6" => 6,
                    _ => return Err(bad("expected any, inet or inet6")),
                },
            ),
            "stdinnull" => set(&mut self.stdin_null, yes_no(value).ok_or_else(|| bad("expected yes or no"))?),
            "tag" => set(&mut self.tag, value.to_string()),
            "sessiontype" => match value.to_ascii_lowercase().as_str() {
                v @ ("none" | "subsystem" | "default") => set(&mut self.session_type, v.to_string()),
                _ => return Err(bad("expected none, subsystem or default")),
            },
            // The first ProxyCommand holds, as OpenSSH reads the first alone:
            // a later one, as of a `Host *` block, is not read (T-502).
            "proxycommand" if self.proxy_command.is_some() => {}
            // `none`, and the ssh_config of OpenSSH users that names podssh
            // itself: podssh ssh takes that road anyway, so neither stops it.
            "proxycommand" if value.eq_ignore_ascii_case("none") || runs_podssh_proxy(value) == Some(true) => {
                self.proxy_command = Some(Given::new(name, value, place))
            }
            "proxycommand" => return Err(proxy_refused(name, value, runs_podssh_proxy(value).is_some(), place)),
            "localforward" => self.local_forwards.push(super::local_spec::local_keyword(value)?),
            "dynamicforward" => self.local_forwards.push(super::local_spec::dynamic_keyword(value)?),
            "gatewayports" => set(&mut self.gateway_ports, yes_no(value).ok_or_else(|| bad("expected yes or no"))?),
            "clearallforwardings" => {
                set(&mut self.clear_all_forwardings, yes_no(value).ok_or_else(|| bad("expected yes or no"))?)
            }
            "remoteforward" => self.remote_forwards.push(super::forward::parse_remote_keyword(value)?),
            "controlmaster" => set(
                &mut self.control_master,
                super::control::Mode::parse(value).ok_or_else(|| bad("expected yes, no, ask, auto or autoask"))?,
            ),
            "controlpath" => set(&mut self.control_path, unquote(value)),
            "controlpersist" => set(
                &mut self.control_persist,
                super::control::Persist::parse(value).ok_or_else(|| bad("expected yes, no or a time"))?,
            ),
            "exitonforwardfailure" => {
                set(&mut self.exit_on_forward_failure, yes_no(value).ok_or_else(|| bad("expected yes or no"))?)
            }
            "forkafterauthentication" => {
                set(&mut self.fork_after_authentication, yes_no(value).ok_or_else(|| bad("expected yes or no"))?)
            }
            "revokedhostkeys" | "knownhostscommand" => {
                return Err(format!(
                    "-o {name}: not supported; mark keys @revoked, or list them, in a known_hosts file instead"
                ))
            }
            "include" | "match" | "host" => {
                return Err(format!("-o {name}: an ssh_config block keyword, not an option"))
            }
            "ignoreunknown" => set(&mut self.ignore_unknown, value.to_string()),
            k if keywords::is_ignored(k) => add(&mut self.ignored, name.to_string()),
            k if self.ignores_unknown(k) => add(&mut self.ignored, name.to_string()),
            _ => return Err(unknown(name)),
        }
        Ok(())
    }

    /// Whether `IgnoreUnknown` names `key`, a lowercase keyword: OpenSSH's
    /// pattern list, without case, where a negated pattern that matches
    /// excludes it.
    fn ignores_unknown(&self, key: &str) -> bool {
        let Some(list) = &self.ignore_unknown else { return false };
        let mut matched = false;
        for pattern in list.split(',').map(str::trim) {
            let (negated, pattern) = pattern.strip_prefix('!').map_or((false, pattern), |rest| (true, rest));
            if podssh_ssh::known_hosts::wildcard(pattern.to_ascii_lowercase().as_bytes(), key.as_bytes()) {
                if negated {
                    return false;
                }
                matched = true;
            }
        }
        matched
    }
}

/// The refusal of a `ProxyCommand` that runs another program, or podssh's
/// proxy with flags that podssh ssh would not see (T-043). A file's names
/// the flag that goes past it and keeps the file's other settings (Q70).
fn proxy_refused(name: &str, value: &str, podssh: bool, place: &Place) -> String {
    let why = if podssh {
        format!(
            "-o {name}={value}: podssh ssh reaches the host through the relay itself; it accepts \
             `podssh proxy %h %p` alone here, so give podssh ssh the other flags"
        )
    } else {
        format!("-o {name}: podssh ssh reaches the host through the relay itself and runs no ProxyCommand")
    };
    match place {
        Place::CommandLine if podssh => why,
        Place::CommandLine => {
            format!("{why}; to use OpenSSH with a relay, give ssh `-o ProxyCommand='podssh proxy %h %p'`")
        }
        Place::Line { .. } => format!(
            "{why}; -o ProxyCommand=none makes podssh ssh take its own road for this run, with the file's other \
             settings"
        ),
    }
}

/// Whether a `ProxyCommand` runs podssh's own proxy: `Some(true)` for
/// `[exec] podssh proxy %h %p`, with podssh by any path; `Some(false)` for
/// podssh's proxy with other words, whose flags podssh ssh would not see;
/// `None` for another program.
fn runs_podssh_proxy(value: &str) -> Option<bool> {
    let mut words: Vec<String> = words(value);
    if words.first().is_some_and(|w| w == "exec") {
        words.remove(0);
    }
    let program = words.first()?.rsplit(['/', '\\']).next()?.to_ascii_lowercase();
    if !matches!(program.as_str(), "podssh" | "podssh.exe") || words.get(1).map(String::as_str) != Some("proxy") {
        return None;
    }
    Some(words[2..] == ["%h", "%p"])
}

impl Settings {
    /// The command line's settings, then a file's for each that the command
    /// line left unset: the first value obtained wins, as in OpenSSH, and the
    /// lists add up, the command line's first (`IdentityFile` adds to `-i`).
    /// `User` and `Port` are taken apart by `resolve`, as `user@host` and
    /// `host:PORT` come between the command line's and the file's.
    pub fn then_file(self, file: Settings) -> Settings {
        let mut identity_files = self.identity_files;
        file.identity_files.into_iter().for_each(|f| add(&mut identity_files, f));
        // The first SetEnv holds whole: the command line's, else the file's.
        let set_env = if self.set_env.is_empty() { file.set_env } else { self.set_env };
        let mut send_env = self.send_env;
        send_env.extend(file.send_env);
        let mut remote_forwards = self.remote_forwards;
        remote_forwards.extend(file.remote_forwards);
        let mut local_forwards = self.local_forwards;
        local_forwards.extend(file.local_forwards);
        let mut ignored = self.ignored;
        file.ignored.into_iter().for_each(|k| add(&mut ignored, k));
        Settings {
            user: self.user,
            port: self.port,
            host_name: self.host_name.or(file.host_name),
            host_key_alias: self.host_key_alias.or(file.host_key_alias),
            identity_files,
            identities_only: self.identities_only.or(file.identities_only),
            identity_agent: self.identity_agent.or(file.identity_agent),
            forward_agent: self.forward_agent.or(file.forward_agent),
            forward_agent_path: self.forward_agent_path.or(file.forward_agent_path),
            forward_x11: self.forward_x11.or(file.forward_x11),
            forward_x11_trusted: self.forward_x11_trusted.or(file.forward_x11_trusted),
            forward_x11_timeout: self.forward_x11_timeout.or(file.forward_x11_timeout),
            xauth_location: self.xauth_location.or(file.xauth_location),
            strict: self.strict.or(file.strict),
            user_known_hosts: self.user_known_hosts.or(file.user_known_hosts),
            global_known_hosts: self.global_known_hosts.or(file.global_known_hosts),
            batch_mode: self.batch_mode.or(file.batch_mode),
            preferred_auth: self.preferred_auth.or(file.preferred_auth),
            pubkey: self.pubkey.or(file.pubkey),
            password: self.password.or(file.password),
            kbd_interactive: self.kbd_interactive.or(file.kbd_interactive),
            password_prompts: self.password_prompts.or(file.password_prompts),
            alive_interval: self.alive_interval.or(file.alive_interval),
            alive_count: self.alive_count.or(file.alive_count),
            connect_timeout: self.connect_timeout.or(file.connect_timeout),
            connection_attempts: self.connection_attempts.or(file.connection_attempts),
            request_tty: self.request_tty.or(file.request_tty),
            escape_char: self.escape_char.or(file.escape_char),
            set_env,
            send_env,
            compression: self.compression.or(file.compression),
            log_level: self.log_level.or(file.log_level),
            remote_command: self.remote_command.or(file.remote_command),
            local_command: self.local_command.or(file.local_command),
            permit_local_command: self.permit_local_command.or(file.permit_local_command),
            proxy_jump: self.proxy_jump.or(file.proxy_jump),
            proxy_command: self.proxy_command.or(file.proxy_command),
            address_family: self.address_family.or(file.address_family),
            stdin_null: self.stdin_null.or(file.stdin_null),
            session_type: self.session_type.or(file.session_type),
            tag: self.tag.or(file.tag),
            remote_forwards,
            local_forwards,
            gateway_ports: self.gateway_ports.or(file.gateway_ports),
            clear_all_forwardings: self.clear_all_forwardings.or(file.clear_all_forwardings),
            exit_on_forward_failure: self.exit_on_forward_failure.or(file.exit_on_forward_failure),
            fork_after_authentication: self.fork_after_authentication.or(file.fork_after_authentication),
            control_master: self.control_master.or(file.control_master),
            control_path: self.control_path.or(file.control_path),
            control_persist: self.control_persist.or(file.control_persist),
            ignore_unknown: self.ignore_unknown.or(file.ignore_unknown),
            ignored,
        }
    }
}

impl Settings {
    /// What the command line gives the reading of a file before its first
    /// line: its `IgnoreUnknown`, which holds for the files too, and its
    /// `ProxyCommand`, which holds, so that a file's is not read (T-502).
    pub fn for_files(&self) -> Settings {
        Settings {
            ignore_unknown: self.ignore_unknown.clone(),
            proxy_command: self.proxy_command.clone(),
            ..Settings::default()
        }
    }
}

fn set<T>(slot: &mut Option<T>, value: T) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

/// Add to a list what it lacks, as OpenSSH adds a key file once (T-045).
fn add<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
