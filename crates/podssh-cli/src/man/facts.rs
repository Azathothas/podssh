//! The manual's ENVIRONMENT, FILES, THE RELAY and EXIT STATUS sections. Each
//! number, name and path is read from the constant the code uses. The tests
//! check the variables against the source, and the exit codes against the
//! constants that the commands return.

use std::path::Path;

use super::model::{Block, Section, Span};
use crate::exitmap::sysexits;

fn lit(t: impl Into<String>) -> Span {
    Span::Lit(t.into())
}

fn item(term: Vec<Span>, text: impl Into<String>) -> Block {
    Block::Item { term, text: text.into() }
}

/// Terms for a list of names: `A, B`.
fn names(list: &[&str]) -> Vec<Span> {
    let mut t = Vec::new();
    for (i, n) in list.iter().enumerate() {
        if i > 0 {
            t.push(Span::Plain(", ".into()));
        }
        t.push(lit(*n));
    }
    t
}

fn topic(key: &'static str, aliases: Vec<&'static str>, heading: &str, blocks: Vec<Block>) -> Section {
    Section { key, aliases, heading: heading.into(), command: false, blocks }
}

pub fn sections() -> Vec<Section> {
    vec![
        topic("environment", vec!["env"], "ENVIRONMENT", environment()),
        topic("files", vec![], "FILES", files()),
        topic("relay", vec![], "THE RELAY", relay()),
        topic("exit-status", vec!["exit"], "EXIT STATUS", exit_status()),
    ]
}

/// Every variable podssh reads, as `(names, what it does)`. The tests check
/// this list against the source in both directions.
pub const VARIABLES: &[(&[&str], &str)] = &[
    (&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"],
     "The HTTP CONNECT proxy for each connection, as http://[USER:PASSWORD@]HOST:PORT. The first one \
      that is set is used, in this order. podssh sends host names to the proxy, so it needs no DNS, and \
      it never shows the proxy's credentials."),
    (&["http_proxy", "HTTP_PROXY"],
     "Not used: they are for http:// URLs. podssh doctor says so when one of them is set and no \
      variable above is."),
    (&["no_proxy", "NO_PROXY"],
     "Hosts to reach without the proxy, separated by commas: example.com also matches its subdomains, \
      and * matches each host. A loopback address never goes through a proxy."),
    (&["PODSSH_RELAY"], "The relay hosts, as --relay-host. The flag wins."),
    (&["PODSSH_RELAY_ADDR"], "Addresses to use in place of DNS, as --relay-addr, after the flag's addresses."),
    (&["PODSSH_RELAY_TOKEN"], "A relay token to use in place of one podssh mints. podssh never prints it."),
    (&["SSL_CERT_FILE"], "Trust only the CA certificates in this file, as --ca-file. The flag wins."),
    (&["SSH_AUTH_SOCK"],
     "The SSH agent's socket. On Windows, a named pipe; with none set, podssh tries the pipe of the \
      OpenSSH agent, then Pageant."),
    (&["SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY", "WAYLAND_DISPLAY"],
     "A program that asks for passwords and passphrases, chosen as OpenSSH chooses: \
      SSH_ASKPASS_REQUIRE=force always uses it; prefer uses it when DISPLAY or WAYLAND_DISPLAY is set; \
      never does not use it. When SSH_ASKPASS_REQUIRE is not set, podssh asks on the terminal, and uses \
      the program only when there is no terminal and DISPLAY or WAYLAND_DISPLAY is set."),
    (&["HOME", "USERPROFILE"],
     "The home directory, for ~ in file names (USERPROFILE on Windows when HOME is not set)."),
    (&["USER", "LOGNAME", "USERNAME"],
     "The login name when none is given. With none of them set, uid 0 is root. podssh never reads \
      the user database."),
    (&["XDG_CACHE_HOME", "LOCALAPPDATA", "TMPDIR"], "Where podssh keeps its cache (see FILES)."),
    (&["TERM"], "Sent to the server with a pty request; xterm-256color when it is not set."),
    (&["COLUMNS", "LINES"],
     "The window size sent with a pty request when there is no terminal to measure (80 and 24 when \
      they are not set)."),
    (&["COMPUTERNAME"], "On Windows, the host name in the default comment of podssh keygen."),
    (&["ProgramData"], "On Windows, the directory of the system known_hosts file."),
    (&["PAGER"],
     "The pager of podssh man on a terminal. Empty, or cat, writes the manual with no pager."),
    (&["LESS"], "Options for less. podssh man sets FRX when it starts less and LESS is not set."),
    (&["PATH"], "Where podssh man looks for less, and where podssh doctor looks for directories that run programs."),
    (&["PODSSH_OFFLINE"],
     "Forbid each network connection. Test suites set it. podssh doctor then shows the network \
      checks as one ???? line."),
];

fn environment() -> Vec<Block> {
    VARIABLES.iter().map(|(n, what)| item(names(n), *what)).collect()
}

fn path_text(p: &Path) -> String {
    p.display().to_string()
}

fn files() -> Vec<Block> {
    let home = Path::new("~");
    let ids: Vec<String> = podssh_ssh::options::default_identity_files(home).iter().map(|p| path_text(p)).collect();
    let user_kh: Vec<String> = podssh_ssh::options::default_user_known_hosts(home).iter().map(|p| path_text(p)).collect();
    let global_kh: Vec<String> = if cfg!(windows) {
        vec![r"%ProgramData%\ssh\ssh_known_hosts".to_string()]
    } else {
        podssh_ssh::options::default_global_known_hosts().iter().map(|p| path_text(p)).collect()
    };
    let as_refs = |v: &[String]| -> Vec<Span> { names(&v.iter().map(String::as_str).collect::<Vec<_>>()) };
    let cache = if cfg!(windows) {
        r"%LOCALAPPDATA%\podssh, else podssh-USER in the temporary directory, else .podssh in the working directory"
    } else {
        "$XDG_CACHE_HOME/podssh (else ~/.cache/podssh), else $TMPDIR/podssh-UID (else /tmp), else \
         /dev/shm/podssh-UID, else ./.podssh"
    };
    vec![
        item(as_refs(&ids), "The identity files tried, in this order, when no -i or IdentityFile is given."),
        item(
            as_refs(&user_kh),
            "The user's known hosts. podssh records a new host key in the first file (mode 0600, in a \
             directory of mode 0700). With no home directory, a new key is accepted but not recorded.",
        ),
        item(as_refs(&global_kh), "The system's known hosts. podssh only reads them."),
        item(
            vec![lit(cache)],
            format!(
                "The cache: the first of these directories that podssh can use. It holds one relay token for \
                 each relay deployment, with the host that minted it ({} for the default relay), and the \
                 relay's list of hosts ({}). Each file has mode 0600. \
                 podssh ignores a cache file that is a symbolic link, that belongs to another user, or that \
                 others can read.",
                podssh_relay::cache::file_name(podssh_relay::DEFAULT_RELAY_HOST),
                podssh_relay::pool::file_name(podssh_relay::DEFAULT_RELAY_HOST)
            ),
        ),
        item(
            vec![lit(podssh_ws::bundle::BUNDLE_FILE_NAME)],
            "CA certificates in the directory of the podssh binary, added to the trust store.",
        ),
        item(
            names(podssh_ws::tls::SYSTEM_BUNDLES),
            "The system CA bundles. The first one that podssh can read is added to the trust store.",
        ),
    ]
}

fn relay() -> Vec<Block> {
    use podssh_relay::{open, pool, relay};
    let secs = |d: std::time::Duration| d.as_secs();
    let doh: Vec<&str> = podssh_ws::resolve::DOH_RESOLVERS.iter().map(|(ip, _)| *ip).collect();
    let every = secs(podssh_ws::client::LIVENESS_EVERY);
    let allowed = podssh_ws::client::LIVENESS_ALLOWED;
    let keepalive = crate::ssh::keywords::documented_default("ServerAliveInterval").unwrap_or("60");
    vec![
        Block::Para(format!(
            "podssh opens a TLS connection to a relay host on port 443, and a WebSocket session for each \
             connection. The relay opens the TCP connection to the target. Thus a host needs only one kind \
             of egress: HTTPS to the relay hosts, directly or through the proxy. The default relay is {}.",
            relay::DEFAULT_RELAY_HOST
        )),
        item(
            vec![lit("Hosts")],
            format!(
                "With no --relay-host and no PODSSH_RELAY, podssh tries {} first, then up to {} hosts of its \
                 pool. The relay publishes the pool; podssh caches it, and fetches it again at the next token \
                 mint once it is {} days old. Until a pool is cached, these hosts are the pool: {}.",
                relay::DEFAULT_RELAY_HOST,
                relay::MAX_ALTERNATES,
                pool::STALE_AFTER_MS / (24 * 3600 * 1000),
                pool::SEED.join(", ")
            ),
        ),
        item(
            vec![lit("Failover")],
            format!(
                "Each host gets one attempt of {} s or less, and each step (TCP, the proxy, TLS, the \
                 WebSocket upgrade) {} s or less. An error that another host can repair goes to the next \
                 host. An error that each host would give (such as a refused target) stops at once. \
                 ConnectionAttempts repeats the whole round, after a random wait that starts near {} s and \
                 doubles to near {} s.",
                secs(open::HOST_DEADLINE),
                secs(open::CONNECT_TIMEOUT),
                secs(open::BACKOFF_FIRST),
                secs(open::BACKOFF_MAX)
            ),
        ),
        item(
            vec![lit("Tokens")],
            "podssh mints a token from the relay (no account is needed), caches it, and mints a new one when \
             the relay refuses a cached token. PODSSH_RELAY_TOKEN replaces the mint. A token goes only into \
             a request header to a relay host: never into output, a URL or a command line.",
        ),
        item(
            vec![lit("Liveness")],
            format!(
                "podssh pings the relay every {every} s. After {allowed} checks in a row with no frame from \
                 the relay, the link is dead and the session ends, so a silent relay is found in {} to {} s.",
                every * u64::from(allowed),
                every * u64::from(allowed + 1),
                every = every,
                allowed = allowed,
            ),
        ),
        item(
            vec![lit("DNS")],
            format!(
                "Through a proxy, podssh sends host names and needs no DNS. With no proxy, it finds a relay's \
                 address in this order: an IP address in place of the name, --relay-addr and \
                 PODSSH_RELAY_ADDR, the system resolver, then DNS over HTTPS to {} (by address).",
                doh.join(", ")
            ),
        ),
        item(
            vec![lit("Trust")],
            format!(
                "TLS is always verified, and no option turns the check off. With --ca-file or SSL_CERT_FILE, \
                 only that file is trusted. Else the trust store is the Mozilla roots in the binary, {} next \
                 to the binary, and the first system bundle.",
                podssh_ws::bundle::BUNDLE_FILE_NAME
            ),
        ),
        item(
            vec![lit("Idle limit")],
            format!(
                "The relay closes a session after {idle} s with no traffic. podssh ssh sends a keepalive \
                 every {keepalive} s. With OpenSSH, set ServerAliveInterval below {idle}.",
                idle = relay::RELAY_IDLE_SECS
            ),
        ),
    ]
}

/// The exit codes, from the constants that the commands return.
fn exit_status() -> Vec<Block> {
    let code = |n: i32| vec![lit(n.to_string())];
    vec![
        item(code(0), "Success. For podssh ssh: the remote command exited 0."),
        item(
            code(crate::doctor::EXIT_FAILED),
            "podssh doctor: a check failed. podssh keygen: a key could not be made or read.",
        ),
        item(
            code(crate::exit_codes::EXIT_USAGE),
            "A usage error: an unknown command or flag, a bad value, a missing argument. podssh did nothing.",
        ),
        item(
            code(sysexits::EX_UNAVAILABLE),
            "podssh proxy: no relay host could be reached, or the relay ended the session abnormally.",
        ),
        item(
            code(crate::exit_codes::EXIT_NOT_IMPLEMENTED),
            "The command is not implemented yet, or podssh failed inside.",
        ),
        item(
            code(sysexits::EX_NOPERM),
            "podssh proxy: the relay or the proxy refused (a token, a blocked address, a proxy's 403 or 407).",
        ),
        item(
            code(sysexits::EX_CONFIG),
            "A setting of the environment cannot be used: PODSSH_RELAY or PODSSH_RELAY_ADDR (podssh ssh, \
             proxy and doctor). For podssh proxy also a proxy URL that is not http://, or a \
             PODSSH_RELAY_TOKEN that is not a token. The same value as a flag is a usage error (64).",
        ),
        item(
            code(podssh_ssh::EXIT_FAILURE),
            "podssh ssh: the connection, the host key or the authentication failed, or the session ended \
             with no exit status. OpenSSH uses the same code.",
        ),
        item(
            vec![Span::Var("N".into())],
            "podssh ssh: the exit status of the remote command, unchanged. When signal N stopped the \
             command, 128 + N.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn crate_dir(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(name).join("src")
    }

    /// The non-test source of the crates in the binary's path, without the
    /// manual itself (which names each variable).
    fn sources() -> Vec<(PathBuf, String)> {
        let mut out = Vec::new();
        let mut dirs: Vec<PathBuf> = ["podssh-cli", "podssh-ssh", "podssh-relay", "podssh-ws"].iter().map(|c| crate_dir(c)).collect();
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|n| n == "man") {
                        continue;
                    }
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    let code = text.split("#[cfg(test)]").next().unwrap_or("").to_string();
                    out.push((path, code));
                }
            }
        }
        out
    }

    fn documented() -> Vec<&'static str> {
        VARIABLES.iter().flat_map(|(n, _)| n.iter().copied()).collect()
    }

    /// Each documented variable is read somewhere: a removed variable fails.
    #[test]
    fn each_documented_variable_is_in_the_source() {
        let src = sources();
        for name in documented() {
            let quoted = format!("\"{name}\"");
            let indirect = name == "TMPDIR"; // std::env::temp_dir reads it too
            assert!(
                indirect || src.iter().any(|(_, code)| code.contains(&quoted)),
                "{name} is documented, but no source reads it"
            );
        }
    }

    /// Each variable that the source reads by name is documented.
    #[test]
    fn each_variable_in_the_source_is_documented() {
        let documented = documented();
        let mut missing = Vec::new();
        for (path, code) in sources() {
            for name in variables_read(&code) {
                if !documented.contains(&name.as_str()) {
                    missing.push(format!("{name} ({})", path.display()));
                }
            }
        }
        assert!(missing.is_empty(), "read but not in ENVIRONMENT: {missing:?}");
    }

    /// The names that `code` reads: arguments of `var("..")` and
    /// `var_os("..")`, and quoted names shaped like variables.
    fn variables_read(code: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (i, _) in code.match_indices('"') {
            let rest = &code[i + 1..];
            let Some(end) = rest.find('"') else { continue };
            let word = &rest[..end];
            let shaped = word.contains('_')
                && word.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                && word.starts_with(|c: char| c.is_ascii_uppercase())
                || word.ends_with("_proxy") && word.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            let called = code[..i].ends_with("var(") || code[..i].ends_with("var_os(");
            if (shaped || called) && !word.starts_with("CARGO_") && !out.iter().any(|w| w == word) {
                out.push(word.to_string());
            }
        }
        out
    }

    /// The control for the test above: the reader finds a planted variable.
    #[test]
    fn the_reader_finds_a_planted_variable() {
        let code = r#"let a = std::env::var("PLANTED_NAME"); let b = var_os("Plain"); let c = "not a var";"#;
        assert_eq!(variables_read(code), vec!["PLANTED_NAME", "Plain"]);
    }

    /// The cache directories are the ones FILES describes: the user's cache
    /// directory when there is one, the temporary directory, /dev/shm on Unix,
    /// and the working directory, last.
    #[test]
    fn the_cache_directories_are_the_ones_described() {
        let dirs = podssh_relay::cache::candidate_dirs();
        let last: Vec<String> =
            dirs.iter().map(|d| d.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(last.last().map(String::as_str), Some(".podssh"), "{last:?}");
        let tagged = last.iter().filter(|n| n.starts_with("podssh-")).count();
        assert_eq!(tagged, if cfg!(unix) { 2 } else { 1 }, "{last:?}");
        assert!(last.len() <= tagged + 2, "{last:?}");
    }

    #[test]
    fn the_exit_codes_are_the_constants() {
        let blocks = exit_status();
        let codes: Vec<String> = blocks
            .iter()
            .filter_map(|b| match b {
                Block::Item { term, .. } => Some(super::super::model::plain(term)),
                _ => None,
            })
            .collect();
        for c in [0, 1, 64, 69, 70, 77, 78, 255] {
            assert!(codes.contains(&c.to_string()), "exit {c} is not documented: {codes:?}");
        }
        assert_eq!(crate::keygen::EXIT_FAILED, crate::doctor::EXIT_FAILED, "one row documents both");
    }
}
