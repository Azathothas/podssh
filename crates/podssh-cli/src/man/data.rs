//! The FILES and EXIT STATUS tables, as data: the text, the man page and
//! `podssh man --json` read them, so the renderers cannot differ. Each number,
//! name and path comes from the constant that the code uses.

use std::path::Path;

use crate::exitmap::sysexits;

/// An exit code: a number, or the status of the remote command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Value(i32),
    /// `N`: the remote command's status, which `podssh ssh` passes on.
    Remote,
}

/// Each exit code and what it means, from the constants that the commands
/// return.
pub fn exit_codes() -> Vec<(Code, String)> {
    let row = |code: i32, what: &str| (Code::Value(code), what.to_string());
    vec![
        row(
            0,
            "Success. For podssh ssh: the remote command exited 0. For podssh chat: each message was \
             acknowledged, and the one thing of --send or --file is done. For podssh ping: a relay host \
             gave its measures, or with a destination each measure has its number. For podssh health: the \
             facts came, or the host has no /proc and gave its system's name.",
        ),
        row(
            crate::doctor::EXIT_FAILED,
            "podssh doctor: a check failed. podssh relay spec: a fact of the relay's document disagrees. \
             podssh keygen: a key could not be made or read.",
        ),
        row(
            crate::exit_codes::EXIT_USAGE,
            "A usage error: an unknown command or flag, a bad value, a missing argument. podssh did nothing.",
        ),
        row(
            sysexits::EX_DATAERR,
            "podssh agent add-passphrase: the passphrase does not open the key file, or the file needs none; \
             nothing is kept. podssh pipe: the bytes of a udp: address are not each datagram after its \
             length. podssh containers: a tool listed a name that podssh does not take, which is left out.",
        ),
        row(
            sysexits::EX_NOINPUT,
            "podssh cp and mv: a source is missing or cannot be read. podssh mv: a source that changed \
             during the move, which stays. podssh chat: the file of --file or --sendfile cannot be read.",
        ),
        row(
            sysexits::EX_UNAVAILABLE,
            "podssh proxy: no relay host could be reached, or the relay ended the session abnormally. \
             podssh node, operator and relay: the relay or TARGET could not be reached, the node did not take \
             the session, the pair was stopped, or another node serves it; with --sshd, a TARGET that sent \
             no line within 10 s, or closed first. podssh cp and mv: no connection to \
             the server, or it has neither SFTP nor the sh and the tools of a copy by exec. podssh chat: \
             the same of the relay and the pair, or a message went with no acknowledgement; each is said. \
             podssh ping: no relay host answered, or PODSSH_OFFLINE is set. podssh relay status: no relay \
             host answered; podssh relay trace: the relay would not dial the target. podssh agent: no agent \
             answers at SSH_AUTH_SOCK, or the agent keeps no passwords. podssh containers: the host has \
             none of docker, podman and kubectl, one of them failed, or --exec names no container that a \
             list has. podssh session: no session of that name answers, or its session ended (and the \
             status that it ended with is said).",
        ),
        row(
            crate::exit_codes::EXIT_NOT_IMPLEMENTED,
            "The command is not implemented yet, or podssh failed inside. podssh node and operator: the \
             relay closed the node or the session for a fault (1003, 1008 or 1009), or the end-to-end \
             channel failed (a peer with no channel, a message that failed its check). podssh cp and mv: the \
             digests of a copy differ, or the session broke; the destination was not changed. podssh mv: \
             the copy is verified and its source could not be removed; the data is in both places. podssh \
             chat: the peer broke the protocol, the channel failed, or the file of --file arrived with \
             another SHA-256.",
        ),
        row(
            sysexits::EX_CANTCREAT,
            "podssh cp and mv: the destination cannot be written. podssh edit: the far file changed since \
             it was fetched, so nothing was sent and the copy here stays, or no cache directory takes the copy. \
             podssh chat: the directory of --accept-dir is not there. podssh each: a file of --output-dir \
             cannot be made; no host has run.",
        ),
        row(
            sysexits::EX_TEMPFAIL,
            "podssh cp and mv: the --timeout passed before the copy ended; a later try can work. podssh \
             chat: the --timeout passed, or the peer talks with another peer; a later try can work. podssh \
             session start and wait: the --timeout passed first. podssh job wait: the --timeout passed \
             before the job ended, which runs on; podssh job fetch: the job is queued or running, so its \
             output is not whole yet. podssh node --quick-tunnel: api.trycloudflare.com refused for now \
             (429 or a 5xx) and asked for a wait past 5 minutes, which the line names, or refused for 5 \
             minutes; a later run can work.",
        ),
        row(
            sysexits::EX_NOPERM,
            "podssh proxy: the relay or the proxy refused (a token, a blocked address, a proxy's 403 or 407). \
             podssh node, operator and relay: the relay refused the pair, or the pair expired; for relay \
             trace, the token. podssh operator and pipe node:: the node's key is not the one pinned in known-nodes or named by \
             --node-key, or the node's allowlist refused this client's key. podssh cp and mv: the server \
             refused the login, or podssh did not accept its host key. podssh chat: the same of the pair \
             and of the keys, or the peer declined the file of --file. podssh session start: this host refuses \
             the bind of the session's socket.",
        ),
        row(
            sysexits::EX_CONFIG,
            "A setting of the environment cannot be used: PODSSH_RELAY or PODSSH_RELAY_ADDR (podssh ssh, \
             cp, proxy and doctor). For podssh proxy also a proxy URL that is not http://, or a \
             PODSSH_RELAY_TOKEN that is not a token. The same value as a flag is a usage error (64). \
             podssh node, operator, relay and chat: no pair is stored under the label, the pair cannot be \
             read or stored, or a node cannot connect as it is set up. podssh edit: VISUAL, EDITOR and PATH \
             give no editor, the editor does not start, or PODSSH_CACHE_DIR is none. podssh node --sshd: a \
             TARGET whose first line is not an SSH version line, which is another service. podssh node: this host \
             refuses UDP for a udp: TARGET. podssh each --interactive: the emergency stop cannot be armed. \
             podssh session start and serve: PODSSH_LISTEN is no, or no directory takes the session's \
             socket.",
        ),
        row(
            podssh_ssh::EXIT_FAILURE,
            "podssh ssh: the connection, the host key, a node's key or the authentication failed, the \
             session ended with no exit status (also when stdout closed and none came within 5 s), or the \
             server ended a run of -N. OpenSSH uses the same code. podssh ping: the destination could \
             not be reached or logged in to, or a measure broke. podssh each: a host could not be reached \
             or logged in to, or its session ended with no exit status. podssh health: the host could not \
             be reached or logged in to, it has no sh, or its answer had none of the lines of the script. \
             podssh containers: the host could not be reached or logged in to, or its list did not end \
             within 60 s. podssh session start: the connection or the login failed. podssh job: the host \
             could not be reached or logged in to, has no tmux, has no such job, or gave no answer; for \
             wait, also a job that is lost. podssh run: the copy failed, and the command did not run.",
        ),
        (
            Code::Remote,
            "podssh ssh: the exit status of the remote command, unchanged. When signal N stopped the \
             command, 128 + N. podssh ping: the status of the remote program of a measure that failed, \
             127 when the host lacks it. podssh edit: the status of an editor that failed; nothing was sent. \
             podssh each: the largest status of the hosts, 0 only when each gave 0; with --interactive, of their \
             shells, and 130 for a host whose shell Ctrl-C cut after the end of the input. podssh containers \
             --exec: the status of the session in the container. podssh job wait: the exit status of the job. \
             podssh run: the status of the command, as podssh ssh gives it."
                .to_string(),
        ),
    ]
}

fn paths(list: Vec<std::path::PathBuf>) -> Vec<String> {
    list.iter().map(|p| p.display().to_string()).collect()
}

/// Each file that podssh reads or writes: its names, and what podssh does
/// with it. The home directory is written `~`, so the table is the same for
/// each user.
pub fn files() -> Vec<(Vec<String>, String)> {
    let home = Path::new("~");
    let global_kh: Vec<String> = if cfg!(windows) {
        vec![r"%ProgramData%\ssh\ssh_known_hosts".to_string()]
    } else {
        paths(podssh_ssh::options::default_global_known_hosts())
    };
    let cache = if cfg!(windows) {
        "%PODSSH_CACHE_DIR%, else %LOCALAPPDATA%\\podssh, else podssh-USER in the temporary directory (%TMP%, \
         %TEMP%, else the one Windows gives), else .podssh in the working directory"
    } else {
        "$PODSSH_CACHE_DIR, else $XDG_CACHE_HOME/podssh (else ~/.cache/podssh), else \
         $XDG_RUNTIME_DIR/podssh, else podssh-UID in $TMPDIR (else $TMP, $TEMP, and only then /tmp and \
         /dev/shm), else ./.podssh"
    };
    let rows = vec![
        (
            paths(podssh_ssh::options::default_identity_files(home)),
            "The identity files tried, in this order, when no -i or IdentityFile is given.".to_string(),
        ),
        (
            paths(podssh_ssh::options::default_user_known_hosts(home)),
            "The user's known hosts. podssh records a new host key in the first file (mode 0600, in a \
             directory of mode 0700). With no home directory, a new key is accepted but not recorded."
                .to_string(),
        ),
        (global_kh, "The system's known hosts. podssh only reads them.".to_string()),
        (
            vec!["~/.ssh/config".to_string()],
            "The user's ssh_config, read by podssh ssh, cp, mv, scp and sftp unless -F or PODSSH_SSH_CONFIG \
             names another file, or none. A missing file is no error. A file that another user than you or \
             root owns (on Windows, than you, SYSTEM or the Administrators), or that others can change (on \
             Windows, as its access list says), is refused, and so is each file that an Include reads. Match \
             is read as OpenSSH 10.3p1 reads it, but Match exec and Match localnetwork, which are refused by \
             name, with the file and the line, where they would decide, and run nothing. Each hop of \
             -J reads the blocks of its own name, as OpenSSH's jump host does, and logs in as its user@, its \
             User, else the local user."
                .to_string(),
        ),
        (
            vec![if cfg!(windows) { r"%ProgramData%\ssh\ssh_config" } else { "/etc/ssh/ssh_config" }.to_string()],
            "The system's ssh_config, read after the user's, and not when -F or PODSSH_SSH_CONFIG names a \
             file. A relative Include in it starts from its directory."
                .to_string(),
        ),
        (
            vec![cache.to_string()],
            format!(
                "The cache: the first of these directories that podssh can use. It holds one relay token for \
                 each relay deployment, with the host that minted it ({} for the default relay), the \
                 relay's list of hosts ({}), and the last addresses that carried a session to each relay host \
                 ({}), which a run whose resolver fails asks before DNS over HTTPS. It holds each pair of the \
                 reverse road under its label ({}), \
                 as podssh relay pair writes it, and, until a copy that broke is done, its side file \
                 (podssh-cp-*.resume: the offset, the temporary file's name and the source's state, never a \
                 byte of the file). While podssh edit runs, a directory edit-RANDOM of mode 0700 holds the \
                 copy of the far file; it goes after the edit, and stays, named, after a failure when the copy \
                 holds a change. Each file has mode 0600; on Windows, an access list that lets in only \
                 you, SYSTEM and the Administrators. podssh ignores a cache file that is a symbolic link, \
                 that belongs to another user, or that others can read.",
                podssh_relay::cache::file_name(podssh_relay::DEFAULT_RELAY_HOST),
                podssh_relay::pool::file_name(podssh_relay::DEFAULT_RELAY_HOST),
                podssh_relay::addresses::FILE,
                podssh_relay::pair::file_name("LABEL").unwrap_or_default()
            ),
        ),
        (
            vec![
                podssh_relay::identity::file::node_file("NAME"),
                podssh_relay::identity::file::CLIENT_FILE.to_string(),
            ],
            "The keys of the ends of a road between two podssh ends (T-087), in the cache, the same on each \
             road: a node's under its NAME, and this user's as a client; --key and --client-key name other \
             files. Each holds the secret key in hex, has mode 0600, and is made when it is missing. podssh \
             refuses one that is a symbolic link, another user's, or that others can read, and never \
             replaces it: a new key would change the node's identity, which operators pinned, and its \
             ticket. The names of an earlier podssh, iroh-node-NAME.key and iroh-client.key, are still read."
                .to_string(),
        ),
        (
            vec![crate::ssh::cloud::warp::DEVICE_FILE.to_string()],
            "The device of WARP's road (warp://, in a build with the feature warp), in the cache, as JSON: its id \
             and its token at WARP's API, its P-256 key, the endpoint's key that the road pins, and its \
             addresses inside the tunnel. Written once, as the device registers, with mode 0600, and read at \
             each run; a record that cannot be read is a configuration error (78), never a new registration: \
             remove it to register again."
                .to_string(),
        ),
        (
            vec!["detached/".to_string()],
            "The logs of the runs that --detach and -f sent into the background (T-380), in the cache, mode \
             0700: VERB-PID.log, mode 0600, which takes the run's stdout and stderr once it is ready; past 1 \
             MiB its earlier part goes to VERB-PID.log.1. podssh removes none: a log tells what a run in the \
             background did."
                .to_string(),
        ),
        (
            vec![format!("{}/", crate::ssh::cloud::tor::DIR_NAME)],
            "The Tor road's directory (tor://, in a build with the feature tor), in the cache, mode 0700: \
             Arti's state (its guards, which Tor asks a client to keep) in state/, and its copy of Tor's \
             directory in cache/, which a later run reads to start sooner. Arti checks that no other user \
             can write them; where a sandbox's mounts fail that check on a directory above, podssh made \
             these private itself and tries once more without it. The same pair for another network of \
             PODSSH_TOR_NETWORK goes in networks/, by a digest of its file. Removing it costs the next run a \
             new bootstrap."
                .to_string(),
        ),
        (
            vec![podssh_relay::identity::pins::FILE.to_string()],
            "The node keys that an operator has met, in the cache: one line for each key of a label, LABEL \
             KEY, the key as its fingerprint (SHA256:...) or itself. The first sight of a label's node \
             writes its line; a node whose key matches no line of its label is refused, and no line is ever \
             replaced: remove one, or add one for a new key. A file of the user that others cannot change."
                .to_string(),
        ),
        (
            vec!["the file of --shadowsocks".to_string()],
            "The Shadowsocks servers of --shadowsocks: ss:// lines and subscription https://URL lines (see podssh \
             ssh). Its keys hold passwords, so podssh reads it only as a regular file of yours that others cannot \
             read (on Windows, as its access list says), as a pair file; else, and for a line that cannot be \
             read, the run is refused (78). podssh never writes it."
                .to_string(),
        ),
        (
            vec!["shadowsocks-HASH.json".to_string()],
            "The list of each subscription of --shadowsocks, in the cache, under a hash of its URL, which it \
             does not show: the time it came and its ss:// lines, which hold passwords; mode 0600. Read for a \
             day, then fetched again, and fetched again too when each of its servers failed."
                .to_string(),
        ),
        (
            vec!["the file of --allow".to_string()],
            "The operator keys that may come in to podssh node, on each road: one key on each line, as its \
             fingerprint (SHA256:...) or in iroh's hex or base32, then routes=ROUTE,... for the routes that \
             it may use (routes=* for each), then a comment if any; # starts a comment line. Read again for \
             each session. A file of the user that others cannot change; others may read it."
                .to_string(),
        ),
        (
            vec![podssh_ws::bundle::BUNDLE_FILE_NAME.to_string()],
            "CA certificates in the directory of the podssh binary, added to the trust store.".to_string(),
        ),
        (
            if cfg!(windows) {
                vec![r"%APPDATA%\podssh\settings".to_string(), crate::settings::BESIDE_BINARY.to_string()]
            } else {
                vec!["$XDG_CONFIG_HOME/podssh/settings".to_string(), crate::settings::BESIDE_BINARY.to_string()]
            },
            "podssh's own settings: RelayHost, RelayAddr (each line adds), RelayFailover, CaFile, SessionLog, \
             Forwarder and ForwarderFallback, as Keyword value lines, below the flags and the variables. The file of PODSSH_SETTINGS, else the first of these \
             that exists (~/.config/podssh/settings with no XDG_CONFIG_HOME; the second beside the podssh \
             binary); never one of the working directory. A symbolic link, a file of another user than you or \
             root, one that others can change, and a bad line are refused (78) by each command that reaches the \
             relay. podssh never writes it, and no keyword holds a token. After a line [groups], each line \
             is NAME HOSTS: a group of hosts, which podssh each takes as @NAME. After a line [snippets], each \
             line is NAME COMMAND: a command that podssh ssh --snippet NAME and podssh each run, with its \
             placeholders (see podssh ssh). A COMMAND in double quotes, with none inside, loses them, and a # \
             in it is no comment."
                .to_string(),
        ),
        (
            vec![crate::session_log::FILE.to_string(), crate::session_log::OLD_FILE.to_string()],
            "The log of the sessions of this host, in the cache, when PODSSH_SESSION_LOG or SessionLog asks for \
             it: a JSON line for each run of podssh ssh and podssh proxy that named a destination, at its end, \
             with its start, duration, verb, host, port, relay host or road, end, exit code, bytes and the \
             relay's close code; never a command, an environment value, a token or a password. Mode 0600, \
             opened to append with no symbolic link followed, a line in one write; at 1 MiB it becomes the \
             second name, and a new file starts. podssh status shows the last line."
                .to_string(),
        ),
        (
            vec![format!("sessions{}NAME.sock", std::path::MAIN_SEPARATOR)],
            "The socket of each session of podssh session, in the cache: the directory sessions has mode 0700, \
             and each socket mode 0600 (on Windows, the access list of the cache); it goes when its session's \
             podssh ends. A socket that nobody serves is replaced by the next start of its name."
                .to_string(),
        ),
        (
            podssh_ws::tls::SYSTEM_BUNDLES.iter().map(|s| s.to_string()).collect(),
            "The system CA bundles. The first one that podssh can read is added to the trust store.".to_string(),
        ),
        (
            vec![".podssh.update-RANDOM".to_string(), "podssh.exe.old".to_string()],
            "In the directory of the podssh binary, while podssh update runs: the new binary, written beside \
             the old one with its mode, then renamed over it, or removed when a step fails. On Windows the \
             running binary is renamed to podssh.exe.old first, and the next run of podssh removes it."
                .to_string(),
        ),
    ];
    rows
}
