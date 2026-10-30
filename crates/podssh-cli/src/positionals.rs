//! The positional arguments of each verb: what follows its options. The
//! value names and the help are what `podssh man` shows under "Arguments";
//! podssh never prints clap's own help or usage.

use clap::{Arg, Command};

/// Add the positional arguments of the verb `name` to its parser.
pub fn add(cmd: Command, name: &str) -> Command {
    // `ssh` is `[user@]host [command...]`; `cp`/`mv` are `SRC... DST`.
    match name {
        // As OpenSSH: options may follow the destination, and the first word
        // after it starts the command, which takes everything after it
        // (`podssh ssh host ls -la` runs `ls -la`). A repeated switch is
        // allowed; for a repeated value, `ssh::args` follows OpenSSH.
        "ssh" => cmd
            .args_override_self(true)
            .arg(
                Arg::new("destination")
                    .value_name("[user@]host")
                    .help("the host to log in to: [user@]host, host:PORT, [user@][IPV6]:PORT or ssh://[user@]host[:PORT]"),
            )
            .arg(
                Arg::new("remote-command")
                    .value_name("COMMAND")
                    .num_args(1..)
                    .trailing_var_arg(true)
                    .allow_hyphen_values(true)
                    .help("the command to run on the host, its words joined with spaces as OpenSSH joins them; without one, the host starts a shell"),
            ),
        // The hosts, then the command, which takes everything after its
        // first word, as `ssh`'s does; `--` before it is the usual form.
        "each" => cmd
            .arg(
                Arg::new("hosts")
                    .value_name("HOSTS")
                    .help("the hosts, a comma list of [user@]host[:port], each named as it is written here; braces as in bash, web{01..12} and {a,b}, and @GROUP of the settings file"),
            )
            .arg(
                Arg::new("remote-command")
                    .value_name("COMMAND")
                    .num_args(1..)
                    .trailing_var_arg(true)
                    .allow_hyphen_values(true)
                    .help("the command to run on each host, its words joined with spaces as OpenSSH joins them; none with --interactive"),
            ),
        // One host; a second word is clap's refusal (T-190).
        "containers" => cmd.arg(
            Arg::new("destination")
                .value_name("[user@]host")
                .help("the host whose containers are listed: [user@]host, host:PORT, [user@][IPV6]:PORT or ssh://[user@]host[:PORT]"),
        ),
        // What to do and the host, then an ID or the command. The command
        // comes after `--`, which `job` checks: a word of it that looks like
        // a flag is then never one of podssh's.
        "job" => cmd
            .arg(Arg::new("subcommand").value_name("SUBCOMMAND").help("start, list, log or stop"))
            .arg(
                Arg::new("host")
                    .value_name("HOST")
                    .help("the host, [user@]host[:port], as podssh ssh takes it, with its Host blocks of ssh_config"),
            )
            .arg(
                Arg::new("words")
                    .value_name("ID|COMMAND")
                    .num_args(0..)
                    .help("log and stop: the job's ID; start: the command after --, its words joined with spaces as OpenSSH joins them, for sh on the host"),
            ),
        // Any count parses for `cp`, `mv` and `scp`: each says itself what a
        // short list lacks, in words clap's count error does not have.
        "cp" | "mv" | "scp" => cmd.arg(Arg::new("paths").value_name("PATH").num_args(1..).help("SRC... DST")),
        // One file, optional, so that `edit` with none says itself what it
        // needs; a second word is clap's refusal.
        "edit" => cmd.arg(
            Arg::new("file")
                .value_name("[user@]host:PATH")
                .help("the file to edit, on a server: [user@]host:path, [user@][IPV6]:path or scp://[user@]host[:port]/path"),
        ),
        // Optional, so that `sftp` with none says itself what it needs.
        "sftp" => cmd.arg(
            Arg::new("destination")
                .value_name("DESTINATION")
                .help("[user@]host[:path], sftp://[user@]host[:port][/path], or node://[user@]NAME[/ROUTE][:path], the node of a pair"),
        ),
        "chat" => cmd.arg(
            Arg::new("peer")
                .value_name("PEER")
                .help("the peer: NAME, node:NAME or node://NAME, the node of a pair; iroh:TICKET; with --listen, the label of the pair that this side serves"),
        ),
        "man" => cmd.arg(
            Arg::new("section")
                .value_name("SECTION")
                .help("one section only: a command, or environment, files, relay-facts, exit-status, examples or see-also"),
        ),
        "agent" => cmd
            .arg(
                Arg::new("subcommand")
                    .value_name("SUBCOMMAND")
                    .help("add, add-password, add-passphrase, list, remove, lock or unlock; with none, the agent serves"),
            )
            .arg(
                Arg::new("args")
                    .value_name("FILE")
                    .num_args(0..)
                    .help("the key files of add, add-passphrase and remove; [USER@]HOST[:PORT] for add-password"),
            ),
        // `session SUBCOMMAND NAME`, then the host and its command (start,
        // serve) or the text (send); the ids of the last two are ssh's, so
        // that `SshArgs` reads them for start.
        "session" => cmd
            .arg(
                Arg::new("subcommand")
                    .value_name("SUBCOMMAND")
                    .help("start, send, wait, capture, stop or list; serve is what start runs in the background"),
            )
            .arg(Arg::new("name").value_name("NAME").help("the session's name: letters, digits, _ and -, 32 at most"))
            .arg(
                Arg::new("destination")
                    .value_name("HOST")
                    .help("start and serve: the host, as podssh ssh takes it; send: the text to type, with \\r, \\n, \\t, \\e, \\xNN and \\\\; with none, send reads it from stdin"),
            )
            .arg(
                Arg::new("remote-command")
                    .value_name("COMMAND")
                    .num_args(1..)
                    .trailing_var_arg(true)
                    .allow_hyphen_values(true)
                    .help("start and serve: the command to run on the host with a pty, in place of the login shell; send: more words of the text, joined with spaces"),
            ),
        "relay" => cmd
            .arg(
                Arg::new("subcommand")
                    .value_name("SUBCOMMAND")
                    .help("pair, revoke, status, info, trace or spec"),
            )
            .arg(
                Arg::new("args")
                    .value_name("NAME")
                    .num_args(0..)
                    .help("the label of a pair, which you choose; for info and trace, HOST PORT"),
            ),
        "node" => cmd
            .arg(
                Arg::new("name")
                    .value_name("NAME")
                    .help("the label of a stored pair (podssh relay pair NAME); with --iroh, the node's name, which labels its key; with --temporary, the label of its lines (default upgrade)"),
            )
            .arg(
                Arg::new("target")
                    .value_name("TARGET")
                    .num_args(0..)
                    .help("the TCP service that each session reaches: HOST:PORT, or [IPV6]:PORT; ROUTE=HOST:PORT offers one more under ROUTE, which an operator names as NAME/ROUTE; udp:HOST:PORT, alone, a UDP service; with --sshd and none, 127.0.0.1:22"),
            ),
        "pipe" => cmd
            .arg(
                Arg::new("a")
                    .value_name("A")
                    .help("the first address: - or stdio, fd:N (Unix), or exec:CMD (a program, its words in one argument)"),
            )
            .arg(Arg::new("b").value_name("B").help("the second address, of the same kinds")),
        "operator" => cmd.arg(
            Arg::new("name")
                .value_name("NAME")
                .help("the label of a pair: stored here, or named for the --pair-file; NAME/ROUTE names a route of its node"),
        ),
        "proxy" => cmd
            .arg(
                Arg::new("target")
                    .value_name("HOST")
                    .help("the host that the relay connects to, or an IPv6 address; HOST:PORT or [IPV6]:PORT in one word also works"),
            )
            .arg(Arg::new("port").value_name("PORT").help("the TCP port on that host")),
        "ping" => cmd.arg(
            Arg::new("destination")
                .value_name("[user@]host")
                .help("a host to log in to for the echo and the throughput; with none, the relay leg alone"),
        ),
        "health" => cmd.arg(
            Arg::new("destination")
                .value_name("[user@]host")
                .help("the host to read: [user@]host, host:PORT, [user@][IPV6]:PORT or ssh://[user@]host[:PORT]"),
        ),
        "play" => cmd.arg(Arg::new("file").value_name("FILE").help("the recording: an asciicast v2 file")),
        "config" => cmd.arg(Arg::new("subcommand").value_name("SUBCOMMAND").help("import")).arg(
            Arg::new("args")
                .value_name("FORMAT FILE")
                .num_args(0..)
                .help("import: the format, ansible (an INI inventory), and the file, - for stdin"),
        ),
        "status" => cmd.arg(
            Arg::new("destination")
                .value_name("[user@]host")
                .help("a host whose host key is looked up: [user@]host, host:PORT or [IPV6]:PORT"),
        ),
        // `-Y sign` signs each file (T-020); with none, standard input.
        "keygen" => cmd.arg(
            Arg::new("files")
                .value_name("FILE")
                .num_args(1..)
                .help("with -Y sign: the files to sign, each to FILE.sig; with none, standard input to standard output"),
        ),
        "doctor" => cmd,
        // `mcp` reads its messages on stdin, and takes no word.
        "mcp" => cmd,
        // `ts` takes its three forms: bare (status), `[user@]host` (a session)
        // and `-W` (a byte pipe).
        "ts" => cmd
            .arg(Arg::new("destination").value_name("[user@]host").help("the tailnet host to log in to"))
            .arg(
                Arg::new("args")
                    .value_name("COMMAND")
                    .num_args(0..)
                    .last(true)
                    .help("command to run on the remote host"),
            ),
        _ => cmd.arg(Arg::new("args").num_args(0..)),
    }
}
