//! `podssh exit NAME --listen ADDR:PORT` (T-431): a local proxy for other
//! programs, whose each connection starts at NAME, a node of the user's net
//! that lends its egress (`podssh node NAME --exit`), as a Tailscale exit
//! node carries a device's traffic. One port takes SOCKS5, SOCKS4a and
//! HTTP CONNECT (`listen`), and each client's target goes in the end-to-end
//! channel to the node, which resolves it, checks it and dials it (`open`;
//! `crate::node_exit` at the node).
//!
//! The listener is one that the user asks for, on a loopback address, once
//! the bind passed (rule 2 of `AGENTS.md`, Q1): `PODSSH_LISTEN=no` refuses
//! it before anything binds, as for `podssh pipe tcp-listen:`. An address
//! of another host is refused: SOCKS here takes no credentials, and each
//! host that found the port would spend the exit's egress.

pub mod listen;
pub mod open;

use std::io::Write;

use clap::ArgMatches;

use crate::pipe::address::Address;
use crate::relay_settings::Refusal;

/// `--exit NAME` and `--client-key FILE` of `podssh proxy`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub name: Option<String>,
    pub client_key: Option<String>,
}

/// What `podssh exit` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExitArgs {
    /// The exit node: a member of the net, and the label of a pair here.
    pub name: Option<String>,
    /// `--listen ADDR:PORT`.
    pub listen: Option<String>,
    pub pair_file: Option<String>,
    pub client_key: Option<String>,
    pub node_key: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    /// `-q`: no line for each connection.
    pub quiet: bool,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl ExitArgs {
    /// The arguments of `exit` in `matches`.
    pub fn from_matches(matches: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> ExitArgs {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        ExitArgs {
            name: get("name"),
            listen: get("listen"),
            pair_file: get("pair-file"),
            client_key: get("client-key"),
            node_key: get("node-key"),
            relay_addr: get("relay-addr"),
            ca_file: get("ca-file"),
            quiet: matches.get_count("quiet") > 0,
            refused,
        }
    }
}

/// Run the verb; returns the process exit code: 0 at Ctrl-C or SIGTERM.
pub fn run_exit(args: &ExitArgs, err: &mut dyn Write) -> i32 {
    let (to, at) = match prepare(args) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("exit", err),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh exit: could not start the async runtime: {e}");
            return crate::exit_codes::EXIT_NOT_IMPLEMENTED;
        }
    };
    let code = runtime.block_on(Box::pin(listen::serve(to, at)));
    // A client's session may still be closing; the proxy has ended.
    runtime.shutdown_background();
    code
}

/// Each check that needs no network, in order: the exit's name, the
/// listener's address, the pins; then that listening is allowed here.
fn prepare(args: &ExitArgs) -> Result<(open::To, Address), Refusal> {
    let name = args.name.clone().ok_or("missing NAME: the exit node of your net (podssh node NAME --exit)")?;
    crate::pairs::check_label(&name)?;
    let text = args.listen.as_deref().ok_or("--listen ADDR:PORT is where the proxy listens, as 127.0.0.1:1080")?;
    let at = crate::pipe::address::parse(&format!("tcp-listen:{text}"))
        .map_err(|refusal| Refusal::usage(format!("--listen {text}: {}", refusal.message)))?;
    let Address::TcpListen { host, .. } = &at else {
        return Err(Refusal::usage(format!("--listen {text}: a TCP address, ADDR:PORT")));
    };
    if !host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return Err(Refusal::usage(format!(
            "--listen {text}: the proxy listens on a loopback address alone: SOCKS here takes no credentials, and \
             each host that found the port would spend the exit's egress"
        )));
    }
    crate::pins::apply(args.relay_addr.as_deref())?;
    crate::pipe::listen::allowed()?;
    let to = open::To {
        name,
        pair_file: args.pair_file.clone(),
        client_key: args.client_key.clone(),
        node_key: args.node_key.clone(),
        ca_file: args.ca_file.clone(),
        quiet: args.quiet,
    };
    Ok((to, at))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(name: Option<&str>, listen: Option<&str>) -> ExitArgs {
        ExitArgs { name: name.map(String::from), listen: listen.map(String::from), ..ExitArgs::default() }
    }

    #[test]
    fn the_proxy_listens_on_a_loopback_address_that_the_user_names() {
        let (to, at) = prepare(&args(Some("lab"), Some("1080"))).unwrap();
        assert_eq!((to.name.as_str(), at), ("lab", Address::TcpListen { host: "127.0.0.1".into(), port: 1080 }));
        assert!(prepare(&args(Some("lab"), Some("[::1]:0"))).is_ok());
        for (name, listen, words) in [
            (None, Some("1080"), "missing NAME"),
            (Some("lab"), None, "--listen ADDR:PORT"),
            (Some("lab"), Some("0.0.0.0:1080"), "a loopback address alone"),
            (Some("lab"), Some("192.168.1.2:1080"), "a loopback address alone"),
            (Some("lab"), Some("example.org:80"), "--listen example.org:80"),
            (Some("lab"), Some("70000"), "--listen 70000"),
            (Some("a/b"), Some("1080"), ""),
        ] {
            let refusal = prepare(&args(name, listen)).unwrap_err();
            assert!(refusal.code == 64 && refusal.message.contains(words), "{name:?} {listen:?}: {}", refusal.message);
        }
    }
}
