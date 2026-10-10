//! `-o NAME=VALUE`: the OpenSSH keywords podssh honours, those it accepts and
//! ignores, and those it refuses by name. The lists are in `keywords.rs`,
//! which the manual also reads. An unknown keyword is an error before anything
//! connects, as in OpenSSH: a silently dropped `-o StrictHostKeyChecking=…`
//! would be a security bug.

use podssh_ssh::{LogLevel, Method, RequestTty, StrictHostKeyChecking};

use super::keywords;

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
    pub proxy_jump: Option<String>,
    /// 4 or 6 from `AddressFamily`; `Some(0)` for `any`.
    pub address_family: Option<u8>,
    pub stdin_null: Option<bool>,
    /// `SessionType`: `none`, `subsystem` or `default`.
    pub session_type: Option<String>,
    /// `RemoteForward`: each one given, as for `-R`.
    pub remote_forwards: Vec<podssh_ssh::RemoteForward>,
    pub exit_on_forward_failure: Option<bool>,
    /// `IgnoreUnknown`: a pattern list of unknown keywords to accept without
    /// effect, when they come after it.
    pub ignore_unknown: Option<String>,
    /// Keywords accepted without effect, for a verbose note.
    pub ignored: Vec<String>,
}

impl Settings {
    /// Apply one `-o` argument: `Name=Value`, `Name Value` or `Name = Value`.
    pub fn apply(&mut self, raw: &str) -> Result<(), String> {
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
            "identityfile" => self.identity_files.push(unquote(value)),
            "identitiesonly" => set(&mut self.identities_only, yes_no(value).ok_or_else(|| bad("expected yes or no"))?),
            "identityagent" => set(&mut self.identity_agent, unquote(value)),
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
                for pair in words(value) {
                    let (n, v) = pair.split_once('=').ok_or_else(|| bad("expected NAME=VALUE"))?;
                    if !self.set_env.iter().any(|(k, _)| k == n) {
                        self.set_env.push((n.to_string(), v.to_string()));
                    }
                }
            }
            "sendenv" => self.send_env.extend(words(value)),
            "compression" => set(&mut self.compression, yes_no(value).ok_or_else(|| bad("expected yes or no"))?),
            "loglevel" => set(&mut self.log_level, LogLevel::parse(value).ok_or_else(|| bad("not a log level"))?),
            "remotecommand" => set(&mut self.remote_command, value.to_string()),
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
            "sessiontype" => match value.to_ascii_lowercase().as_str() {
                v @ ("none" | "subsystem" | "default") => set(&mut self.session_type, v.to_string()),
                _ => return Err(bad("expected none, subsystem or default")),
            },
            "proxycommand" if value.eq_ignore_ascii_case("none") => {}
            // The ssh_config of OpenSSH users names podssh itself; podssh ssh
            // takes that road anyway, so the line must not stop it.
            "proxycommand" if runs_podssh_proxy(value) == Some(true) => self.ignored.push(name.to_string()),
            "proxycommand" if runs_podssh_proxy(value) == Some(false) => {
                return Err(format!(
                    "-o {name}={value}: podssh ssh reaches the host through the relay itself; it accepts \
                     `podssh proxy %h %p` alone here, so give podssh ssh the other flags"
                ))
            }
            "proxycommand" => {
                return Err(format!(
                    "-o {name}: podssh ssh reaches the host through the relay itself and runs no ProxyCommand; \
                     to use OpenSSH with a relay, give ssh `-o ProxyCommand='podssh proxy %h %p'`"
                ))
            }
            "localforward" | "dynamicforward" => {
                return Err(format!(
                    "-o {name}: needs a local listener, which podssh ssh does not open yet; use -W HOST:PORT, or podssh pipe tcp-listen:"
                ))
            }
            "remoteforward" => self.remote_forwards.push(super::forward::parse_remote_keyword(value)?),
            "exitonforwardfailure" => {
                set(&mut self.exit_on_forward_failure, yes_no(value).ok_or_else(|| bad("expected yes or no"))?)
            }
            "forkafterauthentication" if yes_no(value) == Some(true) => {
                return Err(format!("-o {name}: going to the background is not supported; run podssh with `&`"))
            }
            "forkafterauthentication" => {}
            "revokedhostkeys" | "knownhostscommand" => {
                return Err(format!(
                    "-o {name}: not supported; mark keys @revoked, or list them, in a known_hosts file instead"
                ))
            }
            "include" | "match" | "host" => {
                return Err(format!("-o {name}: an ssh_config block keyword, not an option"))
            }
            "ignoreunknown" => set(&mut self.ignore_unknown, value.to_string()),
            k if keywords::is_ignored(k) => self.ignored.push(name.to_string()),
            k if self.ignores_unknown(k) => self.ignored.push(name.to_string()),
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
        identity_files.extend(file.identity_files);
        let mut set_env = self.set_env;
        set_env.extend(file.set_env);
        let mut send_env = self.send_env;
        send_env.extend(file.send_env);
        let mut remote_forwards = self.remote_forwards;
        remote_forwards.extend(file.remote_forwards);
        let mut ignored = self.ignored;
        ignored.extend(file.ignored);
        Settings {
            user: self.user,
            port: self.port,
            host_name: self.host_name.or(file.host_name),
            host_key_alias: self.host_key_alias.or(file.host_key_alias),
            identity_files,
            identities_only: self.identities_only.or(file.identities_only),
            identity_agent: self.identity_agent.or(file.identity_agent),
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
            proxy_jump: self.proxy_jump.or(file.proxy_jump),
            address_family: self.address_family.or(file.address_family),
            stdin_null: self.stdin_null.or(file.stdin_null),
            session_type: self.session_type.or(file.session_type),
            remote_forwards,
            exit_on_forward_failure: self.exit_on_forward_failure.or(file.exit_on_forward_failure),
            ignore_unknown: self.ignore_unknown.or(file.ignore_unknown),
            ignored,
        }
    }
}

fn set<T>(slot: &mut Option<T>, value: T) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

pub fn yes_no(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

pub fn parse_port(value: &str) -> Option<u16> {
    value.trim().parse::<u16>().ok().filter(|p| *p != 0)
}

/// Whole seconds; the whole string must be a number (no `30x`).
fn parse_seconds(value: &str) -> Option<u64> {
    let v = value.trim();
    let v = v.strip_suffix('s').unwrap_or(v);
    v.parse::<u64>().ok()
}

/// Space-separated values, as OpenSSH splits them: a space inside double
/// quotes belongs to its value, and the quotes go.
fn words(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word: Option<String> = None;
    let mut quoted = false;
    for c in value.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                word.get_or_insert_with(String::new);
            }
            c if c.is_whitespace() && !quoted => out.extend(word.take()),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    out.extend(word);
    out
}

fn unquote(value: &str) -> String {
    let v = value.trim();
    v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(v).to_string()
}

/// "unknown option", naming the nearest known keyword when one is close.
fn unknown(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let best = keywords::known_names()
        .map(|k| (distance(&lower, &k.to_ascii_lowercase()), k))
        .min_by_key(|(d, _)| *d)
        .filter(|(d, _)| *d <= 3);
    match best {
        Some((_, k)) => format!("-o {name}: unknown option; did you mean {k}?"),
        None => format!("-o {name}: unknown option"),
    }
}

/// Levenshtein distance, for suggestions only.
fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = (prev + usize::from(ca != *cb)).min(row[j] + 1).min(cur + 1);
            prev = cur;
        }
    }
    row[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_spellings_and_first_value_wins() {
        let mut s = Settings::default();
        s.apply("StrictHostKeyChecking=accept-new").unwrap();
        s.apply("StrictHostKeyChecking yes").unwrap();
        assert_eq!(s.strict, Some(StrictHostKeyChecking::AcceptNew));
        s.apply("Port = 2222").unwrap();
        assert_eq!(s.port, Some(2222));
        s.apply("identityfile=a").unwrap();
        s.apply("IdentityFile b").unwrap();
        assert_eq!(s.identity_files, vec!["a", "b"]);
    }

    #[test]
    fn a_typo_is_an_error_that_names_the_real_option() {
        let err = Settings::default().apply("StrictHostKeyChekcing=no").unwrap_err();
        assert!(err.contains("unknown option"), "{err}");
        assert!(err.contains("StrictHostKeyChecking"), "{err}");
        assert!(Settings::default().apply("NoSuchThing=1").unwrap_err().contains("unknown option"));
    }

    #[test]
    fn bad_values_and_refused_keywords_are_errors() {
        assert!(Settings::default().apply("StrictHostKeyChecking=maybe").is_err());
        assert!(Settings::default().apply("ConnectTimeout=30x").is_err());
        assert!(Settings::default().apply("LocalForward=8080 db:5432").unwrap_err().contains("-W"));
        assert!(Settings::default().apply("ProxyCommand=nc %h %p").unwrap_err().contains("podssh proxy"));
        Settings::default().apply("ProxyCommand=none").unwrap();
    }

    #[test]
    fn ignored_keywords_are_accepted_and_remembered() {
        let mut s = Settings::default();
        s.apply("UpdateHostKeys=yes").unwrap();
        s.apply("ControlMaster=auto").unwrap();
        assert_eq!(s.ignored, vec!["UpdateHostKeys", "ControlMaster"]);
    }

    #[test]
    fn set_env_takes_several_pairs() {
        let mut s = Settings::default();
        s.apply("SetEnv=A=1 B=two").unwrap();
        assert_eq!(s.set_env, vec![("A".into(), "1".into()), ("B".into(), "two".into())]);
    }
}
