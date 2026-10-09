//! The `-o NAME=VALUE` keywords of `podssh ssh`, written down once. The
//! parser (`options.rs`) and the manual (`podssh man`) both read this table.
//! The tests below apply each keyword through the parser, so the table cannot
//! claim a keyword that the parser handles differently.

/// A keyword that podssh applies.
#[derive(Clone, Copy, Debug)]
pub struct Keyword {
    pub name: &'static str,
    /// The value, as the manual shows it.
    pub value: &'static str,
    pub help: &'static str,
    /// A value the parser accepts, for the tests.
    pub sample: &'static str,
}

const fn kw(name: &'static str, value: &'static str, help: &'static str, sample: &'static str) -> Keyword {
    Keyword { name, value, help, sample }
}

/// The keywords podssh applies. A default given here is checked against what
/// `resolve` really uses, by `the_documented_defaults_are_the_real_ones`.
// One keyword to a row, in each of these tables.
#[rustfmt::skip]
pub const HONOURED: &[Keyword] = &[
    kw("AddressFamily", "any|inet|inet6", "inet is -4 and inet6 is -6", "inet"),
    kw("BatchMode", "yes|no", "yes: never prompt; a prompt becomes an error", "yes"),
    kw("ChallengeResponseAuthentication", "yes|no", "the old name of KbdInteractiveAuthentication", "no"),
    kw("Compression", "yes|no", "the same as -C", "yes"),
    kw("ConnectTimeout", "SECONDS", "the limit on the SSH handshake, and on each answer of the server while \
        podssh logs in (default 60)", "30"),
    kw("ConnectionAttempts", "1-100", "rounds over the relay hosts, or dials with --direct (default 1)", "3"),
    kw("EscapeChar", "CHAR|^X|none", "the same as -e", "~"),
    kw("GlobalKnownHostsFile", "FILE...|none", "the system known_hosts files", "/dev/null"),
    kw("HostKeyAlias", "NAME", "look up and record the host key under this name", "alias"),
    kw("HostName", "HOST", "the host to connect to, in place of the destination", "example.org"),
    kw("IdentitiesOnly", "yes|no", "yes: use only the identity files, not the other keys of the agent", "yes"),
    kw("IdentityAgent", "PATH|SSH_AUTH_SOCK|none", "the agent socket (a named pipe on Windows); none: no agent", "none"),
    kw("IdentityFile", "FILE", "the same as -i; repeatable", "~/.ssh/id_ed25519"),
    kw("KbdInteractiveAuthentication", "yes|no", "allow keyboard-interactive authentication", "yes"),
    kw("LogLevel", "QUIET|FATAL|ERROR|INFO|VERBOSE|DEBUG|DEBUG2|DEBUG3", "how much podssh says on stderr (default INFO)", "VERBOSE"),
    kw("NumberOfPasswordPrompts", "N", "password attempts (default 3)", "2"),
    kw("PasswordAuthentication", "yes|no", "allow password authentication", "no"),
    kw("Port", "PORT", "the same as -p", "2222"),
    kw("PreferredAuthentications", "LIST", "publickey, keyboard-interactive and password, in the order to try them", "publickey,password"),
    kw("ProxyJump", "HOSTS|none", "the same as -J", "none"),
    kw("PubkeyAuthentication", "yes|no", "allow key authentication", "yes"),
    kw("RemoteCommand", "COMMAND", "the command to run when the command line gives none", "uptime"),
    kw("RequestTTY", "auto|yes|force|no", "yes is -t, force is -tt, no is -T", "force"),
    kw("SendEnv", "NAME...", "send these local variables; the server decides which to accept", "LANG"),
    kw("ServerAliveCountMax", "N", "keepalives with no answer before podssh ends the session (default 3)", "5"),
    kw("ServerAliveInterval", "SECONDS", "seconds between keepalives (default 60; 0 turns them off)", "30"),
    kw("SessionType", "none|subsystem|default", "none is -N and subsystem is -s", "none"),
    kw("SetEnv", "NAME=VALUE...", "set these variables on the server", "A=1"),
    kw("StdinNull", "yes|no", "the same as -n", "yes"),
    kw("StrictHostKeyChecking", "yes|accept-new|no|ask", "what to do with an unknown host key (default ask); a changed key is refused with each value", "accept-new"),
    kw("User", "USER", "the same as -l", "user"),
    kw("UserKnownHostsFile", "FILE...|none", "the user's known_hosts files; a new host key goes to the first", "/dev/null"),
];

/// Keywords accepted with no effect: they ask for nothing podssh does
/// differently, or limit algorithm lists that podssh keeps modern itself.
#[rustfmt::skip]
pub const IGNORED: &[&str] = &[
    "AddKeysToAgent", "BindAddress", "BindInterface", "CanonicalDomains", "CanonicalizeFallbackLocal",
    "CanonicalizeHostname", "CanonicalizeMaxDots", "CanonicalizePermittedCNAMEs", "CASignatureAlgorithms",
    "CertificateFile", "ChannelTimeout", "CheckHostIP", "Ciphers", "ClearAllForwardings",
    "ControlMaster", "ControlPath", "ControlPersist", "EnableEscapeCommandline", "EnableSSHKeysign",
    "ExitOnForwardFailure", "FingerprintHash", "ForwardAgent", "ForwardX11", "ForwardX11Timeout",
    "ForwardX11Trusted", "GatewayPorts", "GSSAPIAuthentication", "GSSAPIDelegateCredentials", "HashKnownHosts",
    "HostbasedAcceptedAlgorithms", "HostbasedAuthentication", "HostKeyAlgorithms", "IPQoS", "KexAlgorithms",
    "LocalCommand", "LogVerbose", "MACs", "NoHostAuthenticationForLocalhost", "ObscureKeystrokeTiming",
    "PermitLocalCommand", "PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes", "RekeyLimit",
    "RequiredRSASize", "SecurityKeyProvider", "StreamLocalBindMask", "StreamLocalBindUnlink",
    "SyslogFacility", "Tag", "TCPKeepAlive", "Tunnel", "TunnelDevice", "UpdateHostKeys", "VerifyHostKeyDNS",
    "VersionAddendum", "VisualHostKey", "WarnWeakCrypto", "XAuthLocation",
];

/// Keywords refused by name, and why. `options.rs` gives the same reasons.
#[rustfmt::skip]
pub const REFUSED: &[(&str, &str)] = &[
    ("ProxyCommand", "podssh ssh reaches the host through the relay itself (ProxyCommand=none is accepted); to use OpenSSH, give it ProxyCommand='podssh proxy %h %p'"),
    ("LocalForward", "needs a local listener, and podssh never listens; use -W HOST:PORT"),
    ("DynamicForward", "needs a local listener, and podssh never listens; use -W HOST:PORT"),
    ("RemoteForward", "remote forwarding is not implemented yet"),
    ("ForkAfterAuthentication", "going to the background is not supported (=no is accepted); start podssh with &"),
    ("RevokedHostKeys", "mark the keys @revoked in a known_hosts file"),
    ("KnownHostsCommand", "list the keys in a known_hosts file"),
    ("Include", "a keyword of ssh_config files, not an option"),
    ("Match", "a keyword of ssh_config files, not an option"),
    ("Host", "a keyword of ssh_config files, not an option"),
];

/// Whether `-o` accepts `name` (any case) without effect.
pub fn is_ignored(name: &str) -> bool {
    IGNORED.iter().any(|k| k.eq_ignore_ascii_case(name))
}

/// Every keyword name podssh knows, for "did you mean" suggestions.
pub fn known_names() -> impl Iterator<Item = &'static str> {
    HONOURED.iter().map(|k| k.name).chain(REFUSED.iter().map(|(n, _)| *n))
}

/// The `default X` that a keyword's help states, if it states one.
pub fn documented_default(name: &str) -> Option<&'static str> {
    let help = HONOURED.iter().find(|k| k.name == name)?.help;
    let rest = &help[help.find("(default ")? + "(default ".len()..];
    rest.split([')', ';']).next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::options::Settings;

    #[test]
    fn each_honoured_keyword_is_applied_and_not_ignored() {
        for k in HONOURED {
            let mut s = Settings::default();
            s.apply(&format!("{}={}", k.name, k.sample)).unwrap_or_else(|e| panic!("{}={}: {e}", k.name, k.sample));
            assert!(s.ignored.is_empty(), "{} is in HONOURED but the parser ignores it", k.name);
        }
    }

    #[test]
    fn each_ignored_keyword_is_accepted_and_noted() {
        for name in IGNORED {
            let mut s = Settings::default();
            s.apply(&format!("{name}=yes")).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(s.ignored, vec![name.to_string()], "{name}");
        }
    }

    #[test]
    fn each_refused_keyword_is_refused() {
        for (name, _) in REFUSED {
            assert!(Settings::default().apply(&format!("{name}=yes")).is_err(), "{name}=yes was accepted");
        }
        // The two values that are accepted, as the table says.
        Settings::default().apply("ProxyCommand=none").unwrap();
        Settings::default().apply("ForkAfterAuthentication=no").unwrap();
    }

    /// A planted defect for the three tests above: a keyword the parser does
    /// not know is refused, so a misspelt row fails instead of passing.
    #[test]
    fn an_unknown_keyword_is_refused() {
        assert!(Settings::default().apply("NoSuchKeyword=yes").is_err());
    }

    #[test]
    fn no_keyword_is_in_two_lists() {
        let mut all: Vec<String> = known_names().chain(IGNORED.iter().copied()).map(str::to_ascii_lowercase).collect();
        let count = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), count, "a keyword is listed twice");
    }

    /// The defaults the manual states are the ones `resolve` uses.
    #[test]
    fn the_documented_defaults_are_the_real_ones() {
        let parsed = crate::tree::parse(["ssh", "-l", "user", "example.org"]);
        let crate::tree::Parsed::Command { ssh: Some(args), .. } = parsed else { panic!("not an ssh command") };
        let env = crate::ssh::resolve::Env { user: Some("user".into()), ..Default::default() };
        let r = crate::ssh::resolve::resolve(&args, &env).expect("resolves");
        let o = &r.options;
        let d = |name| documented_default(name).unwrap_or_else(|| panic!("{name} states no default"));
        assert_eq!(d("ConnectTimeout"), o.connect_timeout.as_secs().to_string());
        assert_eq!(d("ConnectionAttempts"), r.connection_attempts.to_string());
        assert_eq!(d("NumberOfPasswordPrompts"), o.password_prompts.to_string());
        assert_eq!(d("ServerAliveCountMax"), o.keepalive_max.to_string());
        let interval = o.keepalive_interval.map(|i| i.as_secs()).unwrap_or(0);
        assert_eq!(d("ServerAliveInterval"), interval.to_string());
        assert_eq!(d("StrictHostKeyChecking"), "ask");
        assert_eq!(o.strict_host_key_checking, podssh_ssh::StrictHostKeyChecking::Ask);
        assert_eq!(d("LogLevel"), "INFO");
        assert_eq!(o.log_level, podssh_ssh::LogLevel::Info);
    }
}
