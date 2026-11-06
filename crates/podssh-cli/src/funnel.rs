//! `podssh funnel TARGET` (T-180): a local HTTP service at a public
//! `https://` name, as Tailscale's funnel publishes one, through a quick
//! tunnel that podssh makes itself (T-300), with no relay and no listener.
//! The name is a random `NAME.trycloudflare.com` with no account, or with
//! `--tunnel-token-file FILE` the names that the user's own account routes to
//! a named tunnel. Each visitor's request goes to TARGET as HTTP/1.1, and a
//! WebSocket passes through (`podssh_relay::quick::funnel`). TARGET is
//! `HOST:PORT` or `tcp:HOST:PORT`, `unix-connect:PATH` or `exec:CMD`, as
//! `podssh pipe` names them (T-174 to T-176), so that a node in a cage where
//! loopback is refused serves a socket or a program. The URL is public, so
//! there is no `--allow`; TLS ends at Cloudflare's edge, and the first lines
//! say so. stdout holds the URL alone.

use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use clap::ArgMatches;
use podssh_relay::quick::funnel::{Dial, Dialed, Funnel, Stream, TLS_LINE};
use podssh_relay::quick::keep::{self, Gone, Keep, Say};
use podssh_relay::quick::origin::{Origin, Visitors};
use podssh_relay::quick::register::Connector;
use podssh_relay::quick::{api, token};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::watch;

use crate::exitmap::{sysexits, Fault};
use crate::node_warp::WarpRoad;
use crate::pipe::address::{self, Address};
use crate::pipe::pump::End;
use crate::relay_settings::Refusal;

/// What `podssh funnel` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunnelArgs {
    pub target: Option<String>,
    /// `--tunnel-token-file FILE`: a named tunnel of the user's account.
    pub tunnel_token_file: Option<String>,
    /// `--warp`: the edge inside WARP's tunnel first.
    pub warp: bool,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl FunnelArgs {
    /// The arguments of `funnel` in `matches`.
    pub fn from_matches(matches: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> FunnelArgs {
        FunnelArgs {
            target: matches.get_one::<String>("target").cloned(),
            tunnel_token_file: matches.get_one::<String>("tunnel-token-file").cloned(),
            warp: matches.get_flag("warp"),
            refused,
        }
    }
}

/// The kinds of TARGET, as a refusal names them.
const KINDS: &str = "HOST:PORT, tcp:HOST:PORT, unix-connect:PATH or exec:CMD";

/// TARGET as `podssh pipe` reads an address, a bare `HOST:PORT` as TCP.
pub fn target_of(text: &str) -> Result<Address, Refusal> {
    let parsed = address::parse(text).or_else(|first| address::parse(&format!("tcp:{text}")).map_err(|_| first));
    match parsed? {
        target @ (Address::Tcp { .. } | Address::Unix(_) | Address::Exec(_)) => Ok(target),
        _ => Err(Refusal::usage(format!("{text}: a funnel's TARGET is {KINDS}"))),
    }
}

/// Run the verb; returns the process exit code.
pub fn run(args: &FunnelArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(text) = args.target.as_deref() else {
        return Refusal::usage(format!("missing TARGET: the HTTP service, {KINDS}")).report("funnel", err);
    };
    let target = match target_of(text).and_then(|t| crate::pairs::online().map(|()| t)) {
        Ok(target) => target,
        Err(refusal) => return refusal.report("funnel", err),
    };
    if args.warp && !cfg!(feature = "warp") {
        let message = crate::ssh::cloud::warp::not_built("--warp");
        return Refusal { message, code: crate::exit_codes::EXIT_NOT_IMPLEMENTED }.report("funnel", err);
    }
    // The token is read before anything connects; it goes in no line.
    let named = match args.tunnel_token_file.as_deref().map(read_token).transpose() {
        Ok(named) => named,
        Err(refusal) => return refusal.report("funnel", err),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh funnel: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    let code = runtime.block_on(Box::pin(serve(text.to_string(), target, named, args.warp, out, err)));
    runtime.shutdown_background();
    code
}

/// The tunnel of a token file: its own user's file, as a key is.
fn read_token(path: &str) -> Result<api::Tunnel, Refusal> {
    let text =
        std::fs::read_to_string(path).map_err(|e| Refusal::config(format!("--tunnel-token-file {path}: {e}")))?;
    token::read(&text).map_err(|why| Refusal::config(format!("--tunnel-token-file {path}: {why}")))
}

async fn serve(
    shown: String,
    target: Address,
    named: Option<api::Tunnel>,
    warp: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let say: Say = Arc::new(|line: String| podssh_ssh::err_line!("podssh funnel: {line}"));
    let (proxy, trust) = (ProxyChoice::FromEnvironment, crate::pairs::trust(None));
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(async move {
        crate::node_upgrade::stop_signal().await;
        let _ = stop.send(true);
    });
    let tunnel = match named {
        Some(tunnel) => tunnel,
        None => match api::request(&trust, &proxy, &*say).await {
            Ok(tunnel) => tunnel,
            Err(api::Failed::ForNow(why)) => {
                return Refusal { message: why, code: sysexits::EX_TEMPFAIL }.report("funnel", err)
            }
            Err(api::Failed::Refused(why)) => {
                return Refusal { message: why, code: Fault::RelayUnreachable.code() }.report("funnel", err)
            }
        },
    };
    let at = match tunnel.hostname.is_empty() {
        true => format!("the names that its account routes to the tunnel {}", token::shown_id(&tunnel.id)),
        false => format!("https://{}", tunnel.hostname),
    };
    let _ = writeln!(err, "podssh funnel: serving {shown} at {at} until Ctrl-C");
    let _ = writeln!(err, "podssh funnel: {TLS_LINE}");
    if !tunnel.hostname.is_empty() {
        let _ = writeln!(out, "https://{}", tunnel.hostname);
        let _ = out.flush();
    }
    let origin: Arc<dyn Origin> = Arc::new(Funnel::new(dial_of(target), say.clone()));
    // Each path is TARGET's: no visitor's WebSocket comes to this closure.
    let visit = Visitors { visit: |_: DuplexStream| async {}, origin: Some(origin) };
    let connector = Arc::new(Connector {
        account_tag: tunnel.account_tag.clone(),
        secret: tunnel.secret.clone(),
        tunnel_id: tunnel.id,
        client_id: rand::random::<[u8; 16]>(),
        version: format!("podssh {}", env!("CARGO_PKG_VERSION")),
        arch: crate::node_quick::arch(),
    });
    let roads = crate::node_quick::edge_roads(proxy, WarpRoad::new(warp), say.clone());
    let ready = Box::new(|| crate::detach::ready("funnel"));
    let connections = crate::node_quick::CONNECTIONS;
    let keep = Keep { connector, visit, roads, say: say.clone(), ready, connections };
    let message = match keep::keep(keep, stopped).await {
        Ok(()) => {
            say("stopped".into());
            return 0;
        }
        Err(Gone::Refused(message)) => return Refusal { message, code: Fault::Auth.code() }.report("funnel", err),
        Err(Gone::Unreached(why)) => format!(
            "{why}; a funnel needs port 7844 of Cloudflare's edge: UDP for QUIC, TCP directly or through a proxy \
             that allows it, or TCP inside WARP's tunnel"
        ),
    };
    Refusal { message, code: Fault::RelayUnreachable.code() }.report("funnel", err)
}

/// A new connection to `target` for each request.
fn dial_of(target: Address) -> Dial {
    Arc::new(move || {
        let target = target.clone();
        Box::pin(async move { open(&target).await }) as Dialed
    })
}

async fn open(target: &Address) -> Result<Box<dyn Stream>, String> {
    let end = match target {
        Address::Tcp { host, port } => crate::pipe::remote::tcp_dial(host, *port)
            .await
            .map_err(|e| crate::pipe::remote::tcp_failure(host, *port, e.as_ref()))?,
        Address::Unix(path) => {
            crate::pipe::unix::connect(path).await.map_err(|e| format!("unix-connect:{path}: {e}"))?
        }
        Address::Exec(words) => {
            crate::pipe::local::exec(words, &crate::pipe::local::socketpair).map_err(|unopened| unopened.why)?
        }
        _ => return Err(format!("{target:?} is no funnel's TARGET")),
    };
    Ok(Box::new(Joined::of(end)))
}

/// An end of `podssh pipe` as one stream; a program's child is waited for
/// once the stream goes, so that none stays a zombie.
struct Joined {
    io: tokio::io::Join<crate::pipe::pump::Reader, crate::pipe::pump::Writer>,
    child: Option<tokio::process::Child>,
}

impl Joined {
    fn of(end: End) -> Joined {
        Joined { io: tokio::io::join(end.read, end.write), child: end.child }
    }
}

impl Drop for Joined {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = child.wait().await;
                });
            }
        }
    }
}

impl AsyncRead for Joined {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Joined {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_tcp_a_unix_socket_or_a_program() {
        assert_eq!(target_of("127.0.0.1:8080").unwrap(), Address::Tcp { host: "127.0.0.1".into(), port: 8080 });
        assert!(matches!(target_of("tcp:example.org:80").unwrap(), Address::Tcp { .. }));
        assert!(matches!(target_of("unix-connect:/run/app.sock").unwrap(), Address::Unix(_)));
        assert!(matches!(target_of("exec:python3 -m http.server").unwrap(), Address::Exec(_)));
        for refused in ["stdio", "node:lab", "tcp-listen:8080", "no-port-here"] {
            assert!(target_of(refused).is_err(), "{refused}");
        }
    }
}
