//! The manual's ENVIRONMENT, FILES, THE RELAY and EXIT STATUS sections. Each
//! number, name and path is read from the constant the code uses. The tests
//! check the variables against the source, and the exit codes against the
//! constants that the commands return.

use super::model::{Block, Section, Span};

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
        // Not "relay": that is the command's name, and a name selects one
        // section.
        topic("relay-facts", vec![], "THE RELAY", relay()),
        topic("exit-status", vec!["exit"], "EXIT STATUS", exit_status()),
    ]
}

/// Every variable podssh reads, as `(names, what it does)`. The tests check
/// this list against the source in both directions.
pub const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"],
        "The proxy for each connection: an HTTP CONNECT proxy, as http://[USER:PASSWORD@]HOST:PORT (port \
      80 when none is given), or a SOCKS5 proxy, as socks5:// or socks5h://[USER:PASSWORD@]HOST:PORT \
      (port 1080), with the user and password of RFC 1929. The first one that is set is used, in this \
      order. podssh sends host names to the proxy, for SOCKS5 too, so it needs no DNS; a SOCKS5 proxy \
      that takes no names gets one more try with an address. It never shows the proxy's credentials. \
      SOCKS4 is refused. The iroh road and podssh ts take either kind, and send the host names to \
      both.",
    ),
    (
        &["http_proxy", "HTTP_PROXY"],
        "Not used: they are for http:// URLs. podssh doctor says so when one of them is set and no \
      variable above is.",
    ),
    (
        &["no_proxy", "NO_PROXY"],
        "Hosts to reach without the proxy, separated by commas: example.com also matches its subdomains, \
      * matches each host, and a block ADDR/BITS (10.0.0.0/8, fd7a::/16) matches each address inside \
      it, never a name. A loopback address never goes through a proxy.",
    ),
    (&["PODSSH_RELAY"], "The relay hosts, as --relay-host. The flag wins."),
    (
        &["PODSSH_RELAY_FAILOVER"],
        "How the relay hosts are tried, as --relay-failover: staggered (the default), parallel or serial. \
      The flag wins; another word is a configuration error (78).",
    ),
    (
        &["PODSSH_SSH_CONFIG"],
        "The ssh_config file of podssh ssh, as -F: none reads no file. The flag wins. A process manager \
      sets it once, also where the home cannot be written.",
    ),
    (&["PODSSH_RELAY_ADDR"], "Addresses to use in place of DNS, as --relay-addr, after the flag's addresses."),
    (
        &["SSH_CONNECTION"],
        "Set by sshd in a session: podssh node --temporary, which podssh ssh --upgrade starts there, stands \
      in front of the server's address and port that it names, tried on the loopback first.",
    ),
    (
        &["PODSSH_SESSION_LOG"],
        "A line for each session of podssh ssh and podssh proxy, at its end (see FILES): 1 or yes in the cache, \
      an absolute path in that file, 0 or no for none; over SessionLog of the settings file; off by default. \
      Another value is refused (78).",
    ),
    (
        &["PODSSH_ERROR_PROGRAM"],
        "A program that gets a report when podssh itself fails, run as SSH_ASKPASS is: by its name, with no \
      shell and no argument. Its stdin is one JSON object: schema (1), podssh, os, arch, verb, exit, messages \
      (the last 64 lines of podssh's own messages, 16 KiB at most) and relay (host, close code and reason, \
      or null). A report never holds a token, a proxy URL or its password, a key, the environment, the \
      command line or a byte of a session. An exit 0, the status of a remote command or of a child that \
      podssh passes on, and a stop by SIGINT or SIGTERM start no program. Its stdout and stderr go to \
      stderr; after 30 s podssh stops it. Its status is ignored, and the exit code stays the run's. podssh \
      calls no AI service and no address for the report: the program decides.",
    ),
    (
        &["PODSSH_SETTINGS"],
        "The file of podssh's own settings (see FILES), an absolute path that must exist; none reads none. \
      The flags and the other variables beat the file.",
    ),
    (
        &["PODSSH_TIMEOUT"],
        "The default of --timeout for each command that has the flag, as a whole duration such as 30s; the \
      flag wins, and an empty value is no value. A bad value is a configuration error (78).",
    ),
    (&["PODSSH_RELAY_TOKEN"], "A relay token to use in place of one podssh mints. podssh never prints it."),
    (
        &["PODSSH_CF_ACCESS_CLIENT_ID", "PODSSH_CF_ACCESS_CLIENT_SECRET"],
        "A service token of Cloudflare Access, both or neither, for a cf://HOST destination behind Access: \
      podssh sends them in the headers that cloudflared sends, never in a URL, and never prints them.",
    ),
    (
        &["PODSSH_CF_ACCESS_TOKEN", "PODSSH_CF_ACCESS_TOKEN_FILE"],
        "A token of Cloudflare Access for a cf://HOST destination, or the file that holds one: what \
      cloudflared access token -app=https://HOST prints on a host where its login can run. The variable \
      wins over the file; podssh never prints the token.",
    ),
    (&["PODSSH_NICK"], "The nick of podssh chat, as --nick: the name that the peer sees. The flag wins."),
    (
        &["PODSSH_REPLAY_BUFFER"],
        "With a node that offers the resumable layer, the bytes that podssh keeps in each direction until \
      the node acknowledges them, so that a new link can send them again: a whole number of bytes, from \
      4194304 (the default) to 16777216. When they are kept in full, podssh sends nothing more until an \
      acknowledgement comes. Another value is ignored.",
    ),
    (
        &["PODSSH_PROGRESS"],
        "line or off: the progress line of podssh cp, mv, scp and sftp on stderr, on or off whatever \
      stderr is. With neither, the line shows when stderr is a terminal and -q is not given; --jsonl \
      gives progress objects instead.",
    ),
    (
        &["PODSSH_ZMODEM"],
        "off: podssh ssh does not watch a session's output for ZMODEM (sz and rz of lrzsz), and the bytes \
      go to stdout as they come. Else it watches in each session with a pty and a local terminal (see \
      podssh ssh).",
    ),
    (
        &["PODSSH_SPARE_LINKS"],
        "no: with a node that offers the resumable layer, podssh opens no spare link beside a link that \
      went silent, and finds such a link dead after 30 s only (see podssh ssh). Else a spare link opens \
      once the node has not answered for 3 s, one each 10 s at most, but on the iroh road, whose QUIC \
      carries a session across a new address by itself.",
    ),
    (
        &["PODSSH_TITLE_STACK"],
        "yes or no: whether the terminal keeps a stack of window titles (XTWINOPS 22 and 23), where the \
      notice of a silent node shows (see podssh ssh). With neither, podssh knows xterm and VTE by \
      XTERM_VERSION and VTE_VERSION, and no other terminal.",
    ),
    (
        &["XTERM_VERSION", "VTE_VERSION"],
        "Set by xterm and by VTE: podssh ssh shows the notice of a silent node in the window's title of \
      such a terminal, saved first on its stack of titles, but inside tmux or screen.",
    ),
    (
        &["PODSSH_SESSION_BUDGET"],
        "Lowers the bytes that podssh cp and mv carry in one relay session before they open a new one, \
      for a relay with smaller limits: a whole number of bytes, 1048576 at least. It never raises the \
      budget of THE RELAY's session limits; another value is ignored.",
    ),
    (
        &["PODSSH_SHELL_ID"],
        "Set by a far end that keeps shells in each shell that it starts: the shell's id there. podssh ssh \
      --attach sends it, so that the far end refuses to join a shell to a client that runs inside it.",
    ),
    (&["SSL_CERT_FILE"], "Trust only the CA certificates in this file, as --ca-file. The flag wins."),
    (
        &["SSH_AUTH_SOCK"],
        "The SSH agent's socket. On Windows, a named pipe; with none set, podssh tries the pipe of the \
      OpenSSH agent, then Pageant when its window is there.",
    ),
    (
        &["SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY", "WAYLAND_DISPLAY"],
        "A program that asks for passwords and passphrases, chosen as OpenSSH chooses: \
      SSH_ASKPASS_REQUIRE=force always uses it; prefer uses it when DISPLAY or WAYLAND_DISPLAY is set; \
      never does not use it. When SSH_ASKPASS_REQUIRE is not set, podssh asks on the terminal, and uses \
      the program only when there is no terminal and DISPLAY or WAYLAND_DISPLAY is set.",
    ),
    (&["XAUTHORITY"], "The authority file of the X server of DISPLAY, whose cookie -Y forwards (else ~/.Xauthority)."),
    (
        &["HOME", "USERPROFILE"],
        "The home directory, for ~ in file names (USERPROFILE on Windows when HOME is not set).",
    ),
    (
        &["USER", "LOGNAME", "USERNAME"],
        "The login name when none is given, and the nick of podssh chat when neither --nick nor \
      PODSSH_NICK gives one. With none of them set, uid 0 is root. podssh never reads the user \
      database.",
    ),
    (
        &["USERDOMAIN"],
        "On Windows, with USERNAME, the user DOMAIN\\USER whose logon starts the task of podssh node \
      --install.",
    ),
    (
        &["PODSSH_CACHE_DIR"],
        "The directory of podssh's cache, tried before the others; none keeps no file, and a token is \
      then minted on each run. A relative path is not used, and podssh says so. A directory that refuses \
      a write is skipped, and podssh says why (see FILES).",
    ),
    (
        &["XDG_CACHE_HOME", "LOCALAPPDATA", "XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"],
        "Where podssh keeps its cache (see FILES).",
    ),
    (&["XDG_CONFIG_HOME", "APPDATA"], "Where podssh looks for its settings file, APPDATA on Windows (see FILES)."),
    (&["TERM"], "Sent to the server with a pty request; xterm-256color when it is not set."),
    (
        &["COLUMNS", "LINES"],
        "The window size sent with a pty request when there is no terminal to measure (80 and 24 when \
      they are not set).",
    ),
    (&["COMPUTERNAME"], "On Windows, the host name in the default comment of podssh keygen."),
    (&["ProgramData"], "On Windows, the directory of the system known_hosts file."),
    (&["PAGER"], "The pager of podssh man on a terminal. Empty, or cat, writes the manual with no pager."),
    (
        &["SHELL"],
        "The shell of LocalCommand with PermitLocalCommand=yes: SHELL -c COMMAND; empty or not set, /bin/sh \
      when it is there, else podssh ssh exits 78.",
    ),
    (&["LESS"], "Options for less. podssh man sets FRX when it starts less and LESS is not set."),
    (
        &["VISUAL", "EDITOR"],
        "The editor of podssh edit: VISUAL, else EDITOR, else vi on PATH. A program and its words, split at \
      blanks with no shell, or one program whose path has a blank; an empty value is no value.",
    ),
    (
        &["PATH"],
        "Where podssh man looks for less, podssh edit for vi, and podssh doctor for directories that run programs.",
    ),
    (
        &["PODSSH_LISTEN"],
        "no: podssh pipe listens on nothing, and unix-listen: and tcp-listen: exit 78 before any bind; so do \
      podssh session start and serve. Else they listen where the bind works.",
    ),
    (
        &["PODSSH_MPTCP"],
        "yes: with --direct and no proxy, ask Linux for Multipath TCP, which can carry a connection on \
      after one of two networks of this host goes, where the server speaks it too. Where the kernel \
      offers none, a proxy carries the connection or the server does not speak it, the connection is \
      plain TCP; -v says which. no, or unset, asks for nothing; another value is refused before the \
      connection, as a configuration error (78; podssh ssh exits 255).",
    ),
    (
        &["PODSSH_SK_DEVICE"],
        "The security key (FIDO2) that podssh keygen, podssh ssh and podssh agent use: a path of /dev/hidraw* \
      on Linux. none: podssh uses no security key, and each use says so. Unset: on Linux each FIDO device \
      of /dev/hidraw* that this user may open, on Windows the one that the person chooses in Windows' dialog.",
    ),
    (
        &["PODSSH_OFFLINE"],
        "Forbid each network connection. Test suites set it. podssh doctor then shows the network \
      checks as one ???? line.",
    ),
];

/// The variables of the iroh road (T-165), which only a build with the
/// feature `iroh` reads.
#[cfg(feature = "iroh")]
const FEATURE_VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_IROH_RELAY"],
        "The iroh relays, as --iroh-relay: https://HOST[:PORT], separated by commas, in order. The flag \
          wins; an empty value is no value, and a bad one is a configuration error (78).",
    ),
    (
        &["PODSSH_IROH_UDP"],
        "off: the iroh road takes no direct path, and its relay carries each byte, as where UDP is refused. on: \
          UDP is used once a socket binds, with nothing sent, for a relay that runs no QUIC address discovery. \
          Else UDP is used once a datagram came back: a QUIC address discovery to the home relay within 6 s of \
          the start, before anything is dialled or served; with none, the relay carries each byte. -v says \
          which answer the road took, and at a session's end which path carried it; podssh doctor's line iroh \
          UDP out gives the answer.",
    ),
];

#[cfg(not(feature = "iroh"))]
const FEATURE_VARIABLES: &[(&[&str], &str)] = &[];

/// Each variable that this build reads: [`VARIABLES`], those of the cloud
/// roads (T-351), and those of its features.
pub fn variables() -> impl Iterator<Item = &'static (&'static [&'static str], &'static str)> {
    VARIABLES.iter().chain(cloud::VARIABLES).chain(FEATURE_VARIABLES)
}

fn environment() -> Vec<Block> {
    variables().map(|(n, what)| item(names(n), *what)).collect()
}

fn files() -> Vec<Block> {
    super::data::files()
        .into_iter()
        .map(|(list, what)| item(names(&list.iter().map(String::as_str).collect::<Vec<_>>()), what))
        .collect()
}

fn relay() -> Vec<Block> {
    use podssh_relay::{failover, open, pool, relay};
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
                "With no --relay-host, no PODSSH_RELAY and no RelayHost in the settings file, podssh tries {} first, \
                 then up to {} hosts of its \
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
                 host. An error that each host would give (such as a refused target) stops each attempt at \
                 once. ConnectionAttempts repeats the whole round, after a random wait that starts near {} s \
                 and doubles to near {} s.",
                secs(open::HOST_DEADLINE),
                secs(open::CONNECT_TIMEOUT),
                secs(open::BACKOFF_FIRST),
                secs(open::BACKOFF_MAX)
            ),
        ),
        item(
            vec![lit("--relay-failover MODE")],
            format!(
                "How the hosts are tried; also PODSSH_RELAY_FAILOVER, and the flag wins. staggered, the \
                 default: the next host starts when the one before it has not opened within {} s, or at \
                 once when it failed; the first that opens is kept, and of two that opened together the \
                 earlier in the list. parallel: each host starts at once, and one that opened waits up to {} \
                 s for the hosts before it. serial: one host at a time, each step of a host with a successor \
                 {} s or less. A session that opened and is not kept is closed at once. One token is minted \
                 at a time for each deployment: an attempt waits up to {} s for a mint in flight, then reads \
                 its token, or mints at its own host.",
                secs(failover::STAGGER),
                secs(failover::STAGGER),
                secs(failover::SERIAL_STEP),
                secs(failover::STAGGER)
            ),
        ),
        item(
            vec![lit("A host that failed")],
            format!(
                "A relay host that failed with an error that another host can repair, or that said nothing \
                 while a host after it opened, is tried last for {} min, in each run and each mode, also in \
                 a list that you named; a note says so, and no host is left out. The record is {} in the \
                 cache; a host that opens leaves it. podssh status and podssh doctor show it.",
                podssh_relay::failures::WINDOW.as_secs() / 60,
                podssh_relay::failures::FILE
            ),
        ),
        item(
            vec![lit("A dropped session")],
            "podssh ssh tries a session again when the relay dropped it before any request reached the \
             destination: during the SSH handshake or the login, before the command, the shell, the \
             subsystem, -W's connection, -R's forwards or -N's wait. A drop of the link to the relay goes \
             to the next relay host; a drop of the relay's link to the target tries once more. A close at \
             the relay's limits (1001, 1009) or for a backlog (1013), and each drop after a request, end \
             the run with 255. Each try says why on stderr; a try after the first asks nothing, so a login \
             that needs a prompt then stops. The tries are at most ConnectionAttempts times the relay hosts.",
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
                 the relay, the link is dead and the session ends, so a silent relay is found in {} to {} s. \
                 To a node, the resumable layer also sends a record when it sent nothing for {beat} s, and the \
                 node does the same; a link that carries nothing from the node for {dead} s is dead, and the \
                 session goes on over a new one.",
                every * u64::from(allowed),
                every * u64::from(allowed + 1),
                every = every,
                allowed = allowed,
                beat = podssh_relay::session::pump::PING_EVERY.as_secs(),
                dead = podssh_relay::session::pump::DEAD_AFTER.as_secs(),
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
        trust::block(),
        item(
            vec![lit("Idle limit")],
            format!(
                "The relay closes a session after {idle} s with no traffic. podssh ssh sends a keepalive \
                 every {keepalive} s. With OpenSSH, set ServerAliveInterval below {idle}. To a node, the \
                 resumable layer's records keep each link busy, and SSH sends no keepalive unless \
                 ServerAliveInterval is set.",
                idle = relay::RELAY_IDLE_SECS
            ),
        ),
        item(
            vec![lit("Session limits")],
            format!(
                "The relay ends a session after {cap} MiB, both ways together, or after {hours} hours. \
                 podssh cp and mv count each session's bytes and age, and before {budget} MiB or {minutes} \
                 minutes they open a new session and go on at the offset of the copy, with the host key and \
                 the login of the first; PODSSH_SESSION_BUDGET lowers the bytes. To a node, the resumable \
                 layer moves the session to a new link at {moved} MiB of a link or after {move_hours} hours, \
                 and -v prints a line for each move. A pair expires after 72 hours at most: podssh ssh \
                 node:// and podssh operator warn {warning} minutes before, and then the relay ends each \
                 session of the pair. --direct has no limit.",
                cap = relay::SESSION_BYTE_CAP >> 20,
                hours = relay::SESSION_TIME_CAP.as_secs() / 3600,
                budget = relay::SESSION_BYTE_BUDGET >> 20,
                minutes = relay::SESSION_TIME_BUDGET.as_secs() / 60,
                moved = podssh_relay::session::resume::MOVE_BYTES >> 20,
                move_hours = podssh_relay::session::resume::MOVE_AGE.as_secs() / 3600,
                warning = crate::layered::EXPIRY_WARNING.as_secs() / 60
            ),
        ),
    ]
    .into_iter()
    .chain(iroh_relays())
    .collect()
}

/// The relays of the iroh road, in a build that has it.
#[cfg(feature = "iroh")]
fn iroh_relays() -> Vec<Block> {
    use podssh_iroh::relays;
    vec![item(
        vec![lit("iroh relays")],
        format!(
            "The iroh road (podssh node --iroh, podssh ssh iroh:TICKET) has relays of its own: {}, or those of \
             --iroh-relay or {}, the flag first. podssh asks /ping of each, in order, through the proxy, {} s \
             at most each, and the first that answers is the home relay; a node's ticket names it. A client \
             asks the relay of the ticket first. When none answers, iroh probes them all and takes the one \
             that answers fastest.",
            relays::DEFAULT.join(", "),
            relays::ENV,
            relays::PING_LIMIT.as_secs()
        ),
    )]
}

#[cfg(not(feature = "iroh"))]
fn iroh_relays() -> Vec<Block> {
    Vec::new()
}

/// The exit codes, from the constants that the commands return.
fn exit_status() -> Vec<Block> {
    super::data::exit_codes()
        .into_iter()
        .map(|(code, what)| {
            let term = match code {
                super::data::Code::Value(n) => vec![lit(n.to_string())],
                super::data::Code::Remote => vec![Span::Var("N".into())],
            };
            item(term, what)
        })
        .collect()
}

mod cloud;
#[cfg(test)]
mod tests;
mod trust;
