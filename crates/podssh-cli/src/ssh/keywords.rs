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
    kw("CASignatureAlgorithms", "LIST", "the signatures with which a CA that a @cert-authority line names may sign a \
        host certificate; another refuses it with 255", "-ssh-rsa"),
    kw("ChallengeResponseAuthentication", "yes|no", "the old name of KbdInteractiveAuthentication", "no"),
    kw("Ciphers", "LIST", "the ciphers to offer, in order", "aes256-gcm@openssh.com,aes128-ctr"),
    kw("ClearAllForwardings", "yes|no", "yes: no -L, -D or -R, from the command line or a file (default no)", "yes"),
    kw("Compression", "yes|no", "the same as -C", "yes"),
    kw("ControlMaster", "yes|no|ask|auto|autoask", "be the master of ControlPath (yes is -M, ask is -MM; auto: when \
        none answers); Unix only (default no)", "auto"),
    kw("ControlPath", "PATH|none", "the control socket: a run goes through its master when one answers (the same \
        as -S); it takes the tokens", "/tmp/cm-%C"),
    kw("ControlPersist", "yes|no|TIME", "how long a -N master stays with no client (default no)", "10m"),
    kw("ConnectTimeout", "SECONDS", "the limit on the SSH handshake, and on each answer of the server while \
        podssh logs in, a question's time left out (default 60)", "30"),
    kw("ConnectionAttempts", "1-100", "rounds over the relay hosts, or dials with --direct (default 1)", "3"),
    kw("DynamicForward", "[BIND:]PORT|PATH", "the same as -D; repeatable", "1080"),
    kw("EscapeChar", "CHAR|^X|none", "the same as -e", "~"),
    kw("ExitOnForwardFailure", "yes|no", "yes: a forward of -R that the server refuses ends the run with 255", "yes"),
    kw("ForkAfterAuthentication", "yes|no", "yes is -f: the run goes to the background once its request went, with a \
        command or -N (T-380)", "yes"),
    kw("ForwardAgent", "yes|no|PATH|$NAME", "yes is -A: while the session lasts, the server may use the agent that \
        podssh logs in with; PATH, or the variable NAME, names another agent (default no)", "yes"),
    kw("ForwardX11", "yes|no", "yes is -X: the server may open X11 channels to DISPLAY (default no)", "yes"),
    kw("ForwardX11Timeout", "TIME", "-X: no new X11 channel after this time; 0 for none (default 20m)", "20m"),
    kw("ForwardX11Trusted", "yes|no", "yes: -X gives the X server's own cookie, as -Y does (default no)", "yes"),
    kw("GatewayPorts", "yes|no", "the same as -g (default no)", "yes"),
    kw("GlobalKnownHostsFile", "FILE...|none", "the system known_hosts files", "/dev/null"),
    kw("HostKeyAlgorithms", "LIST", "the host key algorithms to ask for; those that known_hosts records for the host \
        go first within it", "ssh-ed25519,rsa-sha2-512"),
    kw("HostKeyAlias", "NAME", "look up and record the host key under this name, in lowercase", "alias"),
    kw("HostName", "HOST", "the host to connect to, in place of the destination; %h is the host as typed", "%h.example.org"),
    kw("IdentitiesOnly", "yes|no", "yes: use only the identity files, not the other keys of the agent", "yes"),
    kw("IdentityAgent", "PATH|$NAME|SSH_AUTH_SOCK|none", "the agent socket (a named pipe on Windows), or the variable \
        NAME that holds its path; none: no agent", "none"),
    kw("IdentityFile", "FILE", "the same as -i; repeatable", "~/.ssh/id_ed25519"),
    kw("IgnoreUnknown", "PATTERN,...", "unknown keywords to accept with no effect, when they come after it", "UseKeychain"),
    kw("KbdInteractiveAuthentication", "yes|no", "allow keyboard-interactive authentication", "yes"),
    kw("KexAlgorithms", "LIST", "the key exchanges to offer, in order", "-diffie-hellman*"),
    kw("LocalCommand", "COMMAND", "with PermitLocalCommand yes: run COMMAND here after the login, as SHELL -c COMMAND; it \
        takes the % tokens, and %T", "touch /tmp/lc-%h"),
    kw("LocalForward", "[BIND:]PORT HOST:HOSTPORT", "the same as -L, with a space between the two sides; repeatable", "8080 db:5432"),
    kw("LogLevel", "QUIET|FATAL|ERROR|INFO|VERBOSE|DEBUG|DEBUG2|DEBUG3", "how much podssh says on stderr (default INFO)", "VERBOSE"),
    kw("MACs", "LIST", "the MACs to offer, in order; a cipher with its own, such as AES-GCM, uses none", "hmac-sha2-256-etm@openssh.com"),
    kw("NumberOfPasswordPrompts", "N", "password attempts (default 3)", "2"),
    kw("PasswordAuthentication", "yes|no", "allow password authentication", "no"),
    kw("PermitLocalCommand", "yes|no", "yes: run LocalCommand (default no)", "yes"),
    kw("Port", "PORT", "the same as -p", "2222"),
    kw("PreferredAuthentications", "LIST", "publickey, keyboard-interactive and password, in the order to try them", "publickey,password"),
    kw("ProxyJump", "HOSTS|none", "the same as -J", "none"),
    kw("PubkeyAcceptedAlgorithms", "LIST", "the algorithms that podssh signs a login with: a key of another is not \
        offered, and an RSA key signs with the list's first of RSA when the server's best is not in it", "ssh-ed25519,rsa-sha2-512"),
    kw("PubkeyAcceptedKeyTypes", "LIST", "the old name of PubkeyAcceptedAlgorithms", "+ssh-rsa"),
    kw("PubkeyAuthentication", "yes|no", "allow key authentication", "yes"),
    kw("RemoteCommand", "COMMAND", "the command to run when the command line gives none; it takes the % tokens", "uptime"),
    kw("RemoteForward", "LISTEN [TARGET]", "the same as -R: a port or a socket path, then HOST:PORT or a socket here, or none for SOCKS; repeatable", "8080 localhost:80"),
    kw("RequestTTY", "auto|yes|force|no", "yes is -t, force is -tt, no is -T", "force"),
    kw("RequiredRSASize", "BITS", "the least RSA key: a smaller key of the user is not offered, and a smaller host \
        key, or key of the CA of a host certificate, ends the connection with 255; under 1024 it changes nothing \
        (default 1024)", "2048"),
    kw("SendEnv", "NAME...", "send these local variables; the server decides which to accept", "LANG"),
    kw("ServerAliveCountMax", "N", "keepalives with no answer before podssh ends the session (default 3)", "5"),
    kw("ServerAliveInterval", "SECONDS", "seconds between keepalives (default 60; 0 turns them off)", "30"),
    kw("SessionType", "none|subsystem|default", "none is -N and subsystem is -s", "none"),
    kw("SetEnv", "NAME=VALUE...", "set these variables on the server", "A=1"),
    kw("StdinNull", "yes|no", "the same as -n", "yes"),
    kw("Tag", "NAME", "the tag that Match tagged reads; the same as -P", "work"),
    kw("StrictHostKeyChecking", "yes|accept-new|no|ask", "what to do with an unknown host key (default ask); a changed key is refused with each value", "accept-new"),
    kw("User", "USER", "the same as -l, but it takes the % tokens, not %C or %r", "user"),
    kw("UserKnownHostsFile", "FILE...|none", "the user's known_hosts files; a new host key goes to the first", "/dev/null"),
    kw("XAuthLocation", "PATH", "the xauth that makes the untrusted cookie of -X (default: xauth in PATH)", "/usr/bin/xauth"),
];

/// Keywords of a restriction that podssh accepts and does not apply, and
/// why (T-505): a value that the user gave gets one note at the default
/// level; a line of the system's file, at -v alone.
#[rustfmt::skip]
pub const NOTED: &[(&str, &str)] = &[
    ("BindAddress", "podssh binds no socket of its own: the relay dials, or the system chooses the address with --direct"),
    ("BindInterface", "podssh binds no socket of its own: the relay dials, or the system chooses the interface with --direct"),
    ("CertificateFile", "podssh offers no certificate of the user, only keys"),
    ("ChannelTimeout", "podssh closes no channel for being idle"),
    ("IPQoS", "podssh leaves the type of service of its connection to the system"),
    ("RekeyLimit", "podssh rekeys at russh's limits, after 1 GiB each way or an hour"),
    ("SecurityKeyProvider", "podssh speaks to a security key itself, with no provider library"),
    ("TCPKeepAlive", "podssh leaves TCP keepalives to the system; ServerAliveInterval finds a dead link"),
    ("Tunnel", "podssh opens no tun device; -W and -D carry a stream"),
    ("TunnelDevice", "podssh opens no tun device"),
    ("UpdateHostKeys", "podssh records no host key that the server sends after the login"),
    ("VerifyHostKeyDNS", "podssh checks host keys against known_hosts alone"),
    ("WarnWeakCrypto", "podssh says nothing of the algorithms that it negotiated"),
];

/// Keywords accepted with no effect: they ask for nothing podssh does
/// differently. A note at -v names the place of each.
#[rustfmt::skip]
pub const IGNORED: &[&str] = &[
    "AddKeysToAgent", "CanonicalDomains", "CanonicalizeFallbackLocal",
    "CanonicalizeHostname", "CanonicalizeMaxDots", "CanonicalizePermittedCNAMEs",
    "CheckHostIP", "EnableEscapeCommandline", "EnableSSHKeysign",
    "FingerprintHash", "GSSAPIAuthentication", "GSSAPIClientIdentity", "GSSAPIDelegateCredentials",
    "GSSAPIKeyExchange", "GSSAPIKexAlgorithms", "GSSAPIRenewalForcesRekey", "GSSAPIServerIdentity", "GSSAPITrustDns",
    "HashKnownHosts", "HostbasedAcceptedAlgorithms", "HostbasedAuthentication",
    "LogVerbose", "NoHostAuthenticationForLocalhost", "ObscureKeystrokeTiming",
    "StreamLocalBindMask", "StreamLocalBindUnlink", "SyslogFacility",
    "VersionAddendum", "VisualHostKey",
];

/// Keywords refused by name, and why. `options.rs` gives the same reasons.
#[rustfmt::skip]
pub const REFUSED: &[(&str, &str)] = &[
    ("ProxyCommand", "podssh ssh reaches the host through the relay itself: none, and podssh proxy %h %p, are accepted, and the first value holds, as in OpenSSH, so -o ProxyCommand=none goes past a file's; a command of a file is refused (exit 78), and its line names that flag; to use OpenSSH, give it ProxyCommand='podssh proxy %h %p'"),
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

/// Why podssh does not apply `name` (any case), a keyword of a restriction
/// that it accepts with a note; `None` for another keyword.
pub fn noted(name: &str) -> Option<&'static str> {
    NOTED.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, why)| *why)
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
            assert_eq!(s.ignored.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(), [*name], "{name}");
            assert!(s.noted.is_empty(), "{name}");
        }
    }

    /// Each keyword of a restriction that podssh does not apply is kept for
    /// its note at the default level, not with the inert ones (T-505).
    #[test]
    fn each_noted_keyword_is_accepted_and_kept_for_its_note() {
        for (name, why) in NOTED {
            let mut s = Settings::default();
            s.apply(&format!("{name}=yes")).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(s.noted.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(), [*name], "{name}");
            assert!(s.ignored.is_empty(), "{name}");
            assert!(why.starts_with("podssh "), "{name}: the reason says what podssh does: {why}");
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
        let noted = NOTED.iter().map(|(n, _)| *n);
        let mut all: Vec<String> =
            known_names().chain(IGNORED.iter().copied()).chain(noted).map(str::to_ascii_lowercase).collect();
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
        assert_eq!(d("ForwardAgent"), "no");
        assert_eq!(d("GatewayPorts"), "no");
        assert_eq!(d("ClearAllForwardings"), "no");
        assert_eq!(d("ControlMaster"), "no");
        assert_eq!(d("ControlPersist"), "no");
        assert_eq!(r.control, crate::ssh::control::Plan::default());
        assert_eq!(o.forward_agent, podssh_ssh::Agent::Off);
        assert_eq!(d("PermitLocalCommand"), "no");
        assert!(o.local_command.is_none());
        assert_eq!(d("RequiredRSASize"), o.algorithms.rsa_floor().to_string());
        assert_eq!(o.algorithms, podssh_ssh::algorithms::Algorithms::default(), "each list is podssh's own");
    }
}
