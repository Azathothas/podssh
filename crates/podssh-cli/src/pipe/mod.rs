//! `podssh pipe A B` (T-174, T-175): join two byte streams, as socat does,
//! with no listener unless one side asks for one (T-177). Each address is
//! `KIND:REST` (`address`); both are checked before anything starts. The
//! pump (`pump`) copies both ways; the local ends are stdin and stdout, an
//! inherited descriptor, and a child (`local`); the remote ends open a road
//! (`remote`, `relay`); a listening side (`listen`, `serve`) joins each
//! client to the other side; `udp:node:NAME` carries datagrams through a
//! node, and gives a program beside it a datagram socket (`datagram`); a
//! serial line (`serial`) is a local end whose settings go back at each end,
//! a signal's too; `http-listen:` is an HTTP CONNECT proxy whose other side
//! is a road that each request names (`web`, `http_listen`, `gateway`,
//! T-367). A road that failed gives the pipe's exit code, as
//! `podssh proxy` gives it; else a child's status, B's when both are
//! children, as a shell gives it; with neither, a clean end gives 0.

use std::io::Write;

pub mod address;
pub mod credentials;
pub mod datagram;
pub mod gateway;
pub mod http_listen;
pub mod iroh;
pub mod listen;
#[cfg(windows)]
pub mod listen_win;
pub mod local;
pub mod node;
pub mod pump;
pub mod relay;
pub mod remote;
pub mod serial;
pub mod serve;
pub mod ssh;
pub mod unix;
pub mod web;

use crate::exit_codes::EXIT_SOFTWARE;

/// What `podssh pipe` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipeArgs {
    pub a: Option<String>,
    pub b: Option<String>,
    /// The settings of the remote roads, by the ids of `ssh`'s flags: the
    /// relay, the trust, `--direct`, the keys and the options of an SSH
    /// hop, a pair's file and the iroh road's key and relays.
    pub ssh: crate::ssh::args::SshArgs,
    /// `--keep-listening`: each client in turn, not only the first.
    pub keep_listening: bool,
    /// `--proxy-auth-file`: the credentials of the clients of `http-listen:`.
    pub proxy_auth_file: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Run the verb; returns the process exit code.
pub fn run_pipe(args: &PipeArgs, err: &mut dyn Write) -> i32 {
    let (a, b) = match address::both(args.a.as_deref(), args.b.as_deref()) {
        Ok(both) => both,
        Err(refusal) => return refusal.report("pipe", err),
    };
    let listening = a.listens() || b.listens();
    if args.keep_listening && !listening {
        let refusal = crate::relay_settings::Refusal::usage(
            "--keep-listening is for a listening side: unix-listen:PATH, tcp-listen:[ADDR:]PORT or http-listen:",
        );
        return refusal.report("pipe", err);
    }
    let credentials = match http_listen::credentials([&a, &b], args.proxy_auth_file.as_deref()) {
        Ok(credentials) => credentials,
        Err(refusal) => return refusal.report("pipe", err),
    };
    if listening {
        if let Err(refusal) = listen::allowed() {
            return refusal.report("pipe", err);
        }
    }
    let settings = match remote::settings(args, [&a, &b]) {
        Ok(settings) => settings,
        Err(refusal) => return refusal.report("pipe", err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh pipe: could not start the async runtime: {e}");
            return EXIT_SOFTWARE;
        }
    };
    let code = if listening {
        let (listening, other, listener_is_a) = if a.listens() { (&a, &b, true) } else { (&b, &a, false) };
        let quiet = args.ssh.quiet > 0;
        // A proxy takes each client: a program opens a tunnel for each host.
        let keep = args.keep_listening || matches!(listening, address::Address::HttpListen(_));
        let serve = serve::Serve { listening, other, listener_is_a, keep, quiet, credentials };
        // A client's road through a node's layer ends with its CLOSE, the
        // last one's before the exit (T-331).
        runtime.block_on(crate::ssh::transport::settled(serve::run(serve, &settings, err)))
    } else {
        runtime.block_on(crate::ssh::transport::settled(run(a, b, &settings, err)))
    };
    // A read of stdin may still wait in its thread; the pipe has ended.
    runtime.shutdown_background();
    code
}

async fn run(a: address::Address, b: address::Address, settings: &remote::Settings, err: &mut dyn Write) -> i32 {
    // With a serial line, SIGINT and SIGTERM drop the ends, so that its
    // settings go back, and podssh exits with 128 and the signal's number.
    let serial = |x: &address::Address| matches!(x, address::Address::Serial { .. });
    let mut stop = (serial(&a) || serial(&b)).then(serve::Interrupt::new);
    tokio::select! {
        code = joined(a, b, settings, err) => code,
        code = interrupted(&mut stop) => code,
    }
}

/// The exit code of a signal, when `stop` listens for them; else never.
async fn interrupted(stop: &mut Option<serve::Interrupt>) -> i32 {
    match stop {
        Some(stop) => stop.next().await,
        None => std::future::pending().await,
    }
}

/// Open both ends, pump, and report.
async fn joined(a: address::Address, b: address::Address, settings: &remote::Settings, err: &mut dyn Write) -> i32 {
    use address::Address::UdpNode;
    // The node's session first, beside a program of datagrams: a datagram
    // socket has no end of input, so a program started first would not
    // learn that the session failed.
    let opened = if matches!(b, UdpNode(_)) && !matches!(a, UdpNode(_)) {
        in_turn(&b, &a, settings, err).await.map(|(b, a)| (a, b))
    } else {
        in_turn(&a, &b, settings, err).await
    };
    let (a, b) = match opened {
        Ok(ends) => ends,
        Err(code) => return code,
    };
    let pumped = pump::pump(a, b).await;
    report(pumped, "podssh pipe", err).await
}

/// `first`, then `second`; when `second` cannot open, `first` is closed as
/// at any end.
async fn in_turn(
    first: &address::Address,
    second: &address::Address,
    settings: &remote::Settings,
    err: &mut dyn Write,
) -> Result<(pump::End, pump::End), i32> {
    let opened = beside(first, second, settings, err).await?;
    match beside(second, first, settings, err).await {
        Ok(other) => Ok((opened, other)),
        Err(code) => {
            let pump::End { read, write, child, ending, .. } = opened;
            drop((read, write));
            // A child would wait for input that never comes.
            if let Some(mut child) = child {
                let _ = child.kill().await;
            }
            if let Some(ending) = ending {
                let _ = ending.finish().await;
            }
            Err(code)
        }
    }
}

/// Open `address`, whose other side is `other`: a program beside
/// `udp:node:` gets datagrams.
async fn beside(
    address: &address::Address,
    other: &address::Address,
    settings: &remote::Settings,
    err: &mut dyn Write,
) -> Result<pump::End, i32> {
    if let (address::Address::Exec(words), address::Address::UdpNode(_)) = (address, other) {
        let mut say = |line: &str| {
            let _ = writeln!(err, "podssh pipe: {line}");
        };
        let opened = datagram::exec(words, &mut say);
        return opened.map_err(|unopened| {
            let _ = writeln!(err, "podssh pipe: {}", unopened.why);
            unopened.code
        });
    }
    open(address, settings, err).await
}

/// Open one end: the end, or the exit code once its lines are written.
async fn open(address: &address::Address, settings: &remote::Settings, err: &mut dyn Write) -> Result<pump::End, i32> {
    if remote::is_remote(address) {
        return remote::open(address, settings, err).await;
    }
    if let address::Address::Unix(path) = address {
        let mut say = |line: &str| {
            let _ = writeln!(err, "podssh pipe: {line}");
        };
        return unix::open(path, &mut say).await;
    }
    local::open(address).map_err(|unopened| {
        let _ = writeln!(err, "podssh pipe: {}", unopened.why);
        unopened.code
    })
}

/// After the pump: each road closed and judged, each child waited for, as
/// a shell waits; the exit code, and each road's lines on `err` after
/// `prefix`. A road that failed is the pipe's failure; else a child's
/// status, B's first.
pub async fn report(pumped: pump::Pumped, prefix: &str, err: &mut dyn Write) -> i32 {
    let a_road = finished(pumped.a.ending).await;
    let b_road = finished(pumped.b.ending).await;
    let a_child = waited(pumped.a.child).await;
    let b_child = waited(pumped.b.child).await;
    for (_, lines) in [&b_road, &a_road].into_iter().flatten() {
        for line in lines {
            let _ = writeln!(err, "{prefix}: {line}");
        }
    }
    if let Some((code, _)) = b_road.as_ref().or(a_road.as_ref()) {
        return *code;
    }
    let child = b_child.or(a_child);
    // A child's status is the child's, no failure of podssh (T-195).
    if child.is_some() {
        crate::error_program::not_a_failure();
    }
    child.unwrap_or(0)
}

async fn finished(ending: Option<Box<dyn pump::Ending>>) -> pump::Verdict {
    match ending {
        Some(ending) => ending.finish().await,
        None => None,
    }
}

/// The child's exit code, when there is a child.
async fn waited(child: Option<tokio::process::Child>) -> Option<i32> {
    let mut child = child?;
    Some(match child.wait().await {
        Ok(status) => local::code_of(status),
        Err(_) => EXIT_SOFTWARE,
    })
}
