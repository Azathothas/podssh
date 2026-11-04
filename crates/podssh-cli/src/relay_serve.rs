//! `podssh relay serve` (T-169, the operator's ruling Q63): the relay's
//! forward road and its reverse road (T-427), served by this binary on a
//! listener that the user asks for (Q1), with TLS from a certificate and a
//! P-256 key in PEM files, or from ACME, read again on SIGHUP (T-447,
//! `relay_serve/certs.rs`). The routes are `podssh_relay::serve`'s; this
//! file owns the listener, TLS, the port file of a harness, the file of the
//! pairs, whom it mints for (a list's keys, T-448; the net's members, T-455,
//! `crate::net::mint`), and the end on Ctrl-C or SIGTERM, which closes each
//! reverse socket with `1012` first (T-255).

mod certs;
mod list;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::PublicKey;
use podssh_relay::serve::egress::Egress;
use podssh_relay::serve::listener::Door;
use podssh_relay::serve::{self, Config, Limits, Mint};

use crate::exitmap::sysexits::{EX_CONFIG, EX_UNAVAILABLE};
use crate::relay_cmd::RelayArgs;
use crate::relay_settings::Refusal;

/// How long a planned stop waits for each reverse socket's Close to go out.
pub(crate) const STOP_WAIT: Duration = Duration::from_secs(3);

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
    /// The name of a certificate from ACME, in place of `cert` and `key`.
    pub acme: Option<String>,
    /// The CA's directory, else Let's Encrypt's.
    pub acme_directory: Option<String>,
    /// yes or no: the cleartext road beside TLS on the listener (T-326).
    pub cleartext: Option<String>,
    /// The deployments of the list that `/relays.json` signs, and its key
    /// file (T-346).
    pub deployment: Vec<String>,
    pub list_key: Option<String>,
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
            acme: get("acme"),
            acme_directory: get("acme-directory"),
            cleartext: get("cleartext"),
            deployment: matches
                .try_get_many::<String>("deployment")
                .ok()
                .flatten()
                .map(|v| v.cloned().collect())
                .unwrap_or_default(),
            list_key: get("list-key"),
        }
    }

    /// Whether a flag of `serve` was given, which another subcommand refuses.
    pub fn any(&self) -> bool {
        self != &ServeArgs::default()
    }
}

/// Run `podssh relay serve`; returns the exit code.
pub fn run(args: &RelayArgs, err: &mut dyn Write) -> i32 {
    match prepare(&args.serve, args.ca_file.as_deref()) {
        Ok(prepared) => {
            let _ = writeln!(err, "podssh relay serve: {}", prepared.shown);
            serve_until_stopped(prepared, err)
        }
        Err(refusal) => refusal.report("relay serve", err),
    }
}

/// The role, ready to serve.
struct Prepared {
    listener: std::net::TcpListener,
    /// TLS, and the cleartext road beside it unless --cleartext no.
    door: Door,
    cfg: Arc<Config>,
    certs: certs::Certs,
    shown: String,
    /// The file of `--port-file`, and the port that it gets.
    port_file: Option<(String, u16)>,
}

fn prepare(s: &ServeArgs, ca_file: Option<&str>) -> Result<Prepared, Refusal> {
    let listen = s.listen.as_deref().ok_or_else(|| {
        Refusal::usage("serve needs --listen ADDR:PORT, the address to serve on (127.0.0.1:0 takes a free port)")
    })?;
    let source = certs::Source::of(s, ca_file)?;
    // No key of its own: the net's `relay:*` names this role (T-455).
    let mint = mint_of(s.mint.as_deref().unwrap_or("nobody"), None)?;
    let who = minting_for(&mint)?;
    let egress = egress_of()?;
    // The cleartext road beside TLS, with tokens of one session (T-326).
    let cleartext = match s.cleartext.as_deref() {
        None => true,
        Some(word) => crate::forwarder::fallback::word(word)
            .ok_or_else(|| Refusal::usage(format!("--cleartext {word:?}: yes or no")))?,
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
    let certs = certs::Certs::open(source)?;
    // The list of deployments that its /relays.json signs (T-346).
    let listed = list::install(s)?;
    let acceptor = podssh_ws::tls_server::acceptor_for(certs.served.clone(), certs.alpn()).map_err(Refusal::config)?;
    let tokens = serve::tokens::Tokens::random().map_err(Refusal::config)?;
    let pairs = serve::reverse::Pairs::open(s.pairs.as_deref().map(Into::into)).map_err(Refusal::config)?;
    let kept = match (s.pairs.as_deref(), pairs.len()) {
        (Some(file), n) => format!(", its pairs kept in {file} ({n} now)"),
        (None, _) => String::new(),
    };
    let listener = std::net::TcpListener::bind(listen)
        .map_err(|e| Refusal { message: format!("cannot listen on {listen}: {e}"), code: EX_UNAVAILABLE })?;
    let bound = listener.local_addr().map_err(|e| Refusal::config(e.to_string()))?;
    let events: serve::Events = Box::new(|line: &str| {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    });
    let through = egress_shown(&egress);
    let cfg = Config {
        version: format!("podssh {}", env!("CARGO_PKG_VERSION")),
        mint,
        tokens,
        policy: serve::policy::Policy { private: s.allow_private, ..Default::default() },
        egress,
        limits: Limits { keepalive, ..Limits::default() },
        pairs,
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        events: Some(events),
    };
    let inside = if s.allow_private { ", private targets too" } else { "" };
    let clear = if cleartext { ", the cleartext road beside TLS" } else { ", TLS alone" };
    let shown = format!(
        "the relay's forward and reverse roads (contract {}) at {bound}, minting for \
         {who}{inside}{kept}{through}{clear}{listed}; {}",
        serve::CONTRACT,
        certs.shown
    );
    let port_file = s.port_file.clone().map(|path| (path, bound.port()));
    let door = Door { acceptor, cleartext };
    Ok(Prepared { listener, door, cfg: Arc::new(cfg), certs, shown, port_file })
}

/// The words of `--mint`, as a refusal names them.
const MINT_WORDS: &str = "anyone, nobody, keys:FILE, net or net,keys:FILE";

/// Who `--mint WORD` mints for: anyone, nobody, the keys of a list (T-448),
/// the members of the net that this host holds (T-455), or both of those
/// (`net,keys:FILE`: FILE is the rest of the word, commas and all); the node
/// behind a quick tunnel reads the same words (T-428), and names its key
/// `me`, which the net's `relay:NODE` names.
pub(crate) fn mint_of(word: &str, me: Option<PublicKey>) -> Result<Mint, Refusal> {
    let list = |text: &str| text.strip_prefix("keys:").filter(|file| !file.is_empty()).map(PathBuf::from);
    let net = |list: Option<PathBuf>| Mint::Net(Arc::new(crate::net::mint::Members::new(me)), list);
    match word {
        "anyone" => Ok(Mint::Anyone),
        "nobody" | "none" => Ok(Mint::Nobody),
        "net" => Ok(net(None)),
        word => match (word.strip_prefix("net,").map(list), list(word)) {
            (Some(Some(file)), _) => Ok(net(Some(file))),
            (None, Some(file)) => Ok(Mint::Keys(file)),
            _ => Err(Refusal::usage(format!("--mint {word:?}: {MINT_WORDS}"))),
        },
    }
}

/// Whom `mint` mints for, in the words of the first line. The list and the
/// net's document are read again for each request; here, so that a list
/// that cannot be read, or a net that this host does not hold or that
/// ended, stops the start (78), and whom they hold is said.
pub(crate) fn minting_for(mint: &Mint) -> Result<String, Refusal> {
    Ok(match mint {
        Mint::Anyone => "anyone".to_string(),
        Mint::Nobody => "no one".to_string(),
        Mint::Keys(file) => list_shown(file)?,
        Mint::Net(net, list) => {
            let members = net.shown().map_err(|why| Refusal::config(format!("--mint net: {why}")))?;
            match list {
                Some(file) => format!("{members}; and {}", list_shown(file)?),
                None => members,
            }
        }
    })
}

/// How the role dials its targets (T-457): through the proxy that this
/// host's variables name, as each client of podssh does, else directly. A
/// proxy that cannot be read stops the start (78), as a client refuses it.
pub(crate) fn egress_of() -> Result<Egress, Refusal> {
    Egress::from_env().map_err(|why| Refusal::config(format!("the proxy of this host: {why}")))
}

/// The egress in the words of the first line, after a comma; nothing when
/// the role dials directly.
pub(crate) fn egress_shown(egress: &Egress) -> String {
    egress.shown().map(|words| format!(", {words}")).unwrap_or_default()
}

/// The keys of the list in `file`, in the words of the first line.
fn list_shown(file: &Path) -> Result<String, Refusal> {
    let list = podssh_relay::identity::allow::Allowlist::read(file).map_err(Refusal::config)?;
    let bad = match list.bad_lines() {
        [] => String::new(),
        lines => format!("; lines {lines:?} hold no key, and let nobody in"),
    };
    Ok(format!("the {} keys of {}{bad}", list.len(), file.display()))
}

fn serve_until_stopped(prepared: Prepared, err: &mut dyn Write) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh relay serve: could not start the async runtime: {e}");
            return EX_CONFIG;
        }
    };
    let Prepared { listener, door, cfg, certs: kept, port_file, .. } = prepared;
    // SIGHUP is taken before a harness learns the port, so that none sent
    // after it ends the role.
    let mut hangups = {
        let _inside = runtime.enter();
        certs::Hangups::take()
    };
    if let Some((path, port)) = port_file {
        if let Err(e) = std::fs::write(&path, port.to_string()) {
            let _ = writeln!(err, "podssh relay serve: {path}: {e}");
            return EX_CONFIG;
        }
    }
    let said: &mut dyn Write = &mut *err;
    let code = runtime.block_on(async move {
        if listener.set_nonblocking(true).is_err() {
            return Err("the listener cannot be made non-blocking".to_string());
        }
        let listener = tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())?;
        // The lines of ACME's work, said here, as each other line of the role.
        let (say, mut lines) = tokio::sync::mpsc::unbounded_channel();
        let mut keeper = tokio::spawn(kept.keeper(say));
        let mut watch = tokio::time::interval_at(tokio::time::Instant::now() + certs::WATCH, certs::WATCH);
        watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((tcp, peer)) = accepted else { continue };
                    // What a slow client leaves unsent, bounded (T-336).
                    serve::sockets::bound_unsent(&tcp);
                    // TLS, with ACME's handshake alone, or the cleartext road
                    // by the first byte (T-326).
                    tokio::spawn(serve::listener::connection(tcp, peer.ip(), door.clone(), cfg.clone()));
                }
                () = hangups.next() => {
                    let _ = writeln!(said, "podssh relay serve: {}", kept.reload("SIGHUP"));
                }
                _ = watch.tick() => {
                    if let Some(line) = kept.reload_if_changed() {
                        let _ = writeln!(said, "podssh relay serve: {line}");
                    }
                }
                Some(line) = lines.recv() => {
                    let _ = writeln!(said, "podssh relay serve: {line}");
                }
                ended = &mut keeper => {
                    // No certificate to serve: the first order failed.
                    return Err(ended.unwrap_or_else(|e| format!("the certificate's keeper stopped: {e}")));
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
