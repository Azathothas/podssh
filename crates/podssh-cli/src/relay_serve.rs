//! `podssh relay serve` (T-169, the operator's ruling Q63): the relay's
//! forward road and its reverse road (T-427), served by this binary on a
//! listener that the user asks for (Q1), with TLS from a certificate and a
//! P-256 key in PEM files. The routes are `podssh_relay::serve`'s; this file
//! owns the listener, TLS, the port file of a harness, the file of the pairs,
//! and the end on Ctrl-C or SIGTERM, which closes each reverse socket with
//! `1012` first (T-255).

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::serve::{self, Config, Limits, Mint};

use crate::exitmap::sysexits::{EX_CONFIG, EX_UNAVAILABLE};
use crate::relay_cmd::RelayArgs;
use crate::relay_settings::Refusal;

/// How long a client has to finish TLS.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(30);
/// How long a planned stop waits for each reverse socket's Close to go out.
const STOP_WAIT: Duration = Duration::from_secs(3);

/// The flags of `serve`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeArgs {
    pub listen: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub port_file: Option<String>,
    pub mint: Option<String>,
    pub allow_private: bool,
    pub keepalive: Option<String>,
    /// The file that keeps the pairs of the reverse road across a restart.
    pub pairs: Option<String>,
}

impl ServeArgs {
    pub fn from_matches(matches: &clap::ArgMatches) -> ServeArgs {
        let get = |id: &str| matches.try_get_one::<String>(id).ok().flatten().cloned();
        ServeArgs {
            listen: get("listen"),
            cert: get("cert"),
            key: get("key"),
            port_file: get("port-file"),
            mint: get("mint"),
            allow_private: matches.try_get_one::<bool>("allow-private").ok().flatten().copied().unwrap_or(false),
            keepalive: get("keepalive"),
            pairs: get("pairs"),
        }
    }

    /// Whether a flag of `serve` was given, which another subcommand refuses.
    pub fn any(&self) -> bool {
        self != &ServeArgs::default()
    }
}

/// Run `podssh relay serve`; returns the exit code.
pub fn run(args: &RelayArgs, err: &mut dyn Write) -> i32 {
    match prepare(&args.serve) {
        Ok((listener, acceptor, cfg, shown)) => {
            let _ = writeln!(err, "podssh relay serve: {shown}");
            serve_until_stopped(listener, acceptor, cfg, err)
        }
        Err(refusal) => refusal.report("relay serve", err),
    }
}

type Prepared = (std::net::TcpListener, podssh_ws::tls_server::TlsAcceptor, Arc<Config>, String);

fn prepare(s: &ServeArgs) -> Result<Prepared, Refusal> {
    let listen = s.listen.as_deref().ok_or_else(|| {
        Refusal::usage("serve needs --listen ADDR:PORT, the address to serve on (127.0.0.1:0 takes a free port)")
    })?;
    let (Some(cert), Some(key)) = (s.cert.as_deref(), s.key.as_deref()) else {
        return Err(Refusal::usage(
            "serve needs --cert FILE and --key FILE: a certificate chain and its P-256 key, in PEM",
        ));
    };
    let mint = match s.mint.as_deref().unwrap_or("nobody") {
        "anyone" => Mint::Anyone,
        "nobody" | "none" => Mint::Nobody,
        word => match word.strip_prefix("keys:").filter(|file| !file.is_empty()) {
            Some(file) => Mint::Keys(file.into()),
            None => return Err(Refusal::usage(format!("--mint {word:?}: anyone, nobody or keys:FILE"))),
        },
    };
    // The list is read again for each request; here, so that a list that
    // cannot be read stops the start, and the keys that it holds are said.
    let who = match &mint {
        Mint::Anyone => "anyone".to_string(),
        Mint::Nobody => "no one".to_string(),
        Mint::Keys(file) => {
            let list = podssh_relay::identity::allow::Allowlist::read(file).map_err(Refusal::config)?;
            let bad = match list.bad_lines() {
                [] => String::new(),
                lines => format!("; lines {lines:?} hold no key, and let nobody in"),
            };
            format!("the {} keys of {}{bad}", list.len(), file.display())
        }
    };
    let keepalive = match s.keepalive.as_deref() {
        None => Limits::default().keepalive,
        Some(text) => match text.parse::<u64>() {
            Ok(secs @ 1..=3600) => Duration::from_secs(secs),
            _ => return Err(Refusal::usage(format!("--keepalive {text:?}: seconds, from 1 to 3600"))),
        },
    };
    if podssh_relay::open::offline() {
        let env = podssh_relay::open::OFFLINE_ENV;
        return Err(Refusal {
            message: format!("{env} is set, so podssh does not connect anywhere"),
            code: EX_UNAVAILABLE,
        });
    }
    crate::pipe::listen::allowed()?;
    let read = |path: &str| std::fs::read(path).map_err(|e| Refusal::config(format!("{path}: {e}")));
    let acceptor = podssh_ws::tls_server::acceptor(&read(cert)?, &read(key)?, &[podssh_ws::tls_server::HTTP1])
        .map_err(|e| Refusal::config(format!("{cert} and {key}: {e}")))?;
    let tokens = serve::tokens::Tokens::random().map_err(Refusal::config)?;
    let pairs = serve::reverse::Pairs::open(s.pairs.as_deref().map(Into::into)).map_err(Refusal::config)?;
    let kept = match (s.pairs.as_deref(), pairs.len()) {
        (Some(file), n) => format!(", its pairs kept in {file} ({n} now)"),
        (None, _) => String::new(),
    };
    let listener = std::net::TcpListener::bind(listen)
        .map_err(|e| Refusal { message: format!("cannot listen on {listen}: {e}"), code: EX_UNAVAILABLE })?;
    let bound = listener.local_addr().map_err(|e| Refusal::config(e.to_string()))?;
    if let Some(path) = s.port_file.as_deref() {
        std::fs::write(path, bound.port().to_string()).map_err(|e| Refusal::config(format!("{path}: {e}")))?;
    }
    let events: serve::Events = Box::new(|line: &str| {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    });
    let cfg = Config {
        version: format!("podssh {}", env!("CARGO_PKG_VERSION")),
        mint,
        tokens,
        policy: serve::policy::Policy { private: s.allow_private, ..Default::default() },
        limits: Limits { keepalive, ..Limits::default() },
        pairs,
        answered: Default::default(),
        events: Some(events),
    };
    let inside = if s.allow_private { ", private targets too" } else { "" };
    let shown = format!(
        "the relay's forward and reverse roads (contract {}) at {bound}, minting for {who}{inside}{kept}",
        serve::CONTRACT
    );
    Ok((listener, acceptor, Arc::new(cfg), shown))
}

fn serve_until_stopped(
    listener: std::net::TcpListener,
    acceptor: podssh_ws::tls_server::TlsAcceptor,
    cfg: Arc<Config>,
    err: &mut dyn Write,
) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh relay serve: could not start the async runtime: {e}");
            return EX_CONFIG;
        }
    };
    let code = runtime.block_on(async move {
        if listener.set_nonblocking(true).is_err() {
            return Err("the listener cannot be made non-blocking".to_string());
        }
        let listener = tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())?;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { continue };
                    let (acceptor, cfg) = (acceptor.clone(), cfg.clone());
                    tokio::spawn(async move {
                        if let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_WAIT, acceptor.accept(tcp)).await {
                            // The name that the client asked for, which a
                            // key's signed mint must name (T-448).
                            let sni = tls.get_ref().1.server_name().map(str::to_string);
                            serve::serve_named(tls, cfg, sni).await;
                        }
                    });
                }
                _ = stopped() => {
                    // A planned stop: each reverse socket hears 1012, which
                    // its client tells apart from a lost link (T-255).
                    cfg.pairs.restart(STOP_WAIT).await;
                    return Ok(());
                }
            }
        }
    });
    runtime.shutdown_background();
    match code {
        Ok(()) => 0,
        Err(why) => {
            let _ = writeln!(err, "podssh relay serve: {why}");
            EX_UNAVAILABLE
        }
    }
}

/// Ctrl-C, or SIGTERM on Unix.
async fn stopped() {
    #[cfg(unix)]
    {
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(term) => term,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
