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
        "cp" | "mv" => cmd.arg(Arg::new("paths").value_name("PATH").num_args(2..).help("SRC... DST")),
        "chat" => cmd
            .arg(Arg::new("channel").value_name("CHANNEL").help("channel to join"))
            .arg(Arg::new("message").value_name("MESSAGE").num_args(0..).help("message to send")),
        "man" => cmd.arg(
            Arg::new("section")
                .value_name("SECTION")
                .help("one section only: a command, or environment, files, relay, exit-status, examples or see-also"),
        ),
        "relay" => cmd
            .arg(Arg::new("subcommand").value_name("SUBCOMMAND").help("status, info, spec, trace, pair, revoke"))
            .arg(Arg::new("args").value_name("ARGS").num_args(0..).help("arguments for the subcommand")),
        "node" | "operator" => cmd.arg(Arg::new("name").value_name("NAME").help("node name")),
        "proxy" => cmd
            .arg(
                Arg::new("target")
                    .value_name("HOST")
                    .help("the host that the relay connects to, or an IPv6 address; HOST:PORT or [IPV6]:PORT in one word also works"),
            )
            .arg(Arg::new("port").value_name("PORT").help("the TCP port on that host")),
        "status" | "doctor" | "keygen" => cmd,
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
