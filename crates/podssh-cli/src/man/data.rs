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
             acknowledged, and the one thing of --send or --file is done.",
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
            sysexits::EX_NOINPUT,
            "podssh cp and mv: a source is missing or cannot be read. podssh mv: a source that changed \
             during the move, which stays. podssh chat: the file of --file or --sendfile cannot be read.",
        ),
        row(
            sysexits::EX_UNAVAILABLE,
            "podssh proxy: no relay host could be reached, or the relay ended the session abnormally. \
             podssh node, operator and relay: the relay or TARGET could not be reached, the node did not take \
             the session, the pair was stopped, or another node serves it. podssh cp and mv: no connection to \
             the server, or it has neither SFTP nor the sh and the tools of a copy by exec. podssh chat: \
             the same of the relay and the pair, or a message went with no acknowledgement; each is said.",
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
            "podssh cp and mv: the destination cannot be written. podssh chat: the directory of \
             --accept-dir is not there.",
        ),
        row(
            sysexits::EX_TEMPFAIL,
            "podssh cp and mv: the --timeout passed before the copy ended; a later try can work. podssh \
             chat: the --timeout passed, or the peer talks with another peer; a later try can work.",
        ),
        row(
            sysexits::EX_NOPERM,
            "podssh proxy: the relay or the proxy refused (a token, a blocked address, a proxy's 403 or 407). \
             podssh node, operator and relay: the relay refused the pair, or the pair expired. podssh \
             operator and pipe node:: the node's key is not the one pinned in known-nodes or named by \
             --node-key, or the node's allowlist refused this client's key. podssh cp and mv: the server \
             refused the login, or podssh did not accept its host key. podssh chat: the same of the pair \
             and of the keys, or the peer declined the file of --file.",
        ),
        row(
            sysexits::EX_CONFIG,
            "A setting of the environment cannot be used: PODSSH_RELAY or PODSSH_RELAY_ADDR (podssh ssh, \
             cp, proxy and doctor). For podssh proxy also a proxy URL that is not http://, or a \
             PODSSH_RELAY_TOKEN that is not a token. The same value as a flag is a usage error (64). \
             podssh node, operator, relay and chat: no pair is stored under the label, the pair cannot be \
             read or stored, or a node cannot connect as it is set up.",
        ),
        row(
            podssh_ssh::EXIT_FAILURE,
            "podssh ssh: the connection, the host key, a node's key or the authentication failed, the \
             session ended with no exit status (also when stdout closed and none came within 5 s), or the \
             server ended a run of -N. OpenSSH uses the same code.",
        ),
        (
            Code::Remote,
            "podssh ssh: the exit status of the remote command, unchanged. When signal N stopped the \
             command, 128 + N."
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
        r"%LOCALAPPDATA%\podssh, else podssh-USER in the temporary directory, else .podssh in the working directory"
    } else {
        "$XDG_CACHE_HOME/podssh (else ~/.cache/podssh), else $TMPDIR/podssh-UID (else /tmp), else \
         /dev/shm/podssh-UID, else ./.podssh"
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
             names another file, or none. A missing file is no error. On Unix, a file that another user than \
             you or root owns, or that others can change, is refused, and so is each file that an Include \
             reads. Match is refused by name, with the file and the line, but for Match all and Match final \
             all."
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
                 each relay deployment, with the host that minted it ({} for the default relay), and the \
                 relay's list of hosts ({}). It holds each pair of the reverse road under its label ({}), \
                 as podssh relay pair writes it, and, until a copy that broke is done, its side file \
                 (podssh-cp-*.resume: the offset, the temporary file's name and the source's state, never a \
                 byte of the file). Each file has mode 0600. \
                 podssh ignores a cache file that is a symbolic link, that belongs to another user, or that \
                 others can read.",
                podssh_relay::cache::file_name(podssh_relay::DEFAULT_RELAY_HOST),
                podssh_relay::pool::file_name(podssh_relay::DEFAULT_RELAY_HOST),
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
            vec![podssh_relay::identity::pins::FILE.to_string()],
            "The node keys that an operator has met, in the cache: one line for each key of a label, LABEL \
             KEY, the key as its fingerprint (SHA256:...) or itself. The first sight of a label's node \
             writes its line; a node whose key matches no line of its label is refused, and no line is ever \
             replaced: remove one, or add one for a new key. A file of the user that others cannot change."
                .to_string(),
        ),
        (
            vec!["the file of --allow".to_string()],
            "The operator keys that may come in to podssh node, on each road: one key on each line, as its \
             fingerprint (SHA256:...) or in iroh's hex or base32, then a comment if any; # starts a comment \
             line. Read again for each session. A file of the user that others cannot change; others may \
             read it."
                .to_string(),
        ),
        (
            vec![podssh_ws::bundle::BUNDLE_FILE_NAME.to_string()],
            "CA certificates in the directory of the podssh binary, added to the trust store.".to_string(),
        ),
        (
            podssh_ws::tls::SYSTEM_BUNDLES.iter().map(|s| s.to_string()).collect(),
            "The system CA bundles. The first one that podssh can read is added to the trust store.".to_string(),
        ),
    ];
    rows
}
