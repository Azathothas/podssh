//! `podssh relay serve` (T-169, the operator's ruling Q63): the relay's
//! forward road and its reverse road (T-427), served by this binary on a
//! listener that the user asks for (Q1), with TLS from a certificate and a
//! P-256 key in PEM files, or from ACME, read again on SIGHUP (T-447,
//! `relay_serve/certs.rs`). The routes are `podssh_relay::serve`'s; this
//! file owns the listener, TLS, the port file of a harness, the file of the
//! pairs, whom it mints for (a list's keys, T-448; the net's members, T-455,
//! `crate::net::mint`), and the end on Ctrl-C or SIGTERM, which closes each
//! reverse socket with `1012` first (T-255). The sessions of its forward
//! road in the resumable layer take their budget, their deadline and this
//! process's name from flags of their own (T-173, `relay_serve/resumes.rs`).
//! Once its listener is bound, before the runtime starts a thread, it gives
//! up the capabilities of its start (T-629, `relay_serve/harden.rs`). With
//! `--quic yes` it serves QUIC on the listener's port of UDP too (T-667,
//! `relay_serve/quic.rs`). What each key carried, its budget for a day and
//! the file that keeps the counts are `relay_serve/quota.rs`'s (T-636); a
//! list of keys at an `https://` URL, `relay_serve/keys_url.rs`'s (T-646).

mod certs;
mod harden;
#[cfg(target_os = "linux")]
mod harden_sys;
pub(crate) mod keys_url;
mod list;
mod quic;
mod quota;
mod resumes;
mod stopped;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::PublicKey;
use podssh_relay::serve::egress::Egress;
use podssh_relay::serve::keys::List;
use podssh_relay::serve::listener::Door;
use podssh_relay::serve::ranges::Range;
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
    /// The private ranges that it dials too, unparsed (T-635).
    pub routes: Option<String>,
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
    /// The resumable sessions of the forward road (T-173): how long one
    /// whose link is lost is kept, the MiB of their replay buffers in all,
    /// and this process's own name for each link of one.
    pub resume_deadline: Option<String>,
    pub resume_budget: Option<String>,
    pub resume_host: Option<String>,
    /// yes or no: HTTP/2 with extended CONNECT on the listener (T-321).
    pub http2: Option<String>,
    /// yes or no: QUIC on the listener's port of UDP (T-667).
    pub quic: Option<String>,
    /// A key's MiB for a day, and the file of each key's counts (T-636).
    pub quota: Option<String>,
    pub usage: Option<String>,
    /// How often a list of keys at a URL is fetched, and how long past
    /// that its copy is read while its server fails (T-646).
    pub list_ttl: Option<String>,
    pub list_stale: Option<String>,
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
            routes: get("routes"),
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
            resume_deadline: get("resume-deadline"),
            resume_budget: get("resume-budget"),
            resume_host: get("resume-host"),
            http2: get("http2"),
            quic: get("quic"),
            quota: get("quota"),
            usage: get("usage"),
            list_ttl: get("list-ttl"),
            list_stale: get("list-stale"),
        }
    }

    /// Whether a flag of `serve` was given, which another subcommand refuses.
    pub fn any(&self) -> bool {
        self != &ServeArgs::default()
    }
}

/// Run `podssh relay serve`; returns the exit code.
pub fn run(args: &RelayArgs, err: &mut dyn Write) -> i32 {
    // The host of a list of keys at a URL by --relay-addr too, as each host
    // that podssh reaches (T-646).
    let pinned = match keys_url::named(args.serve.mint.as_deref()) {
        true => crate::pins::apply(args.relay_addr.as_deref()),
        false => Ok(()),
    };
    match pinned.and_then(|()| prepare(&args.serve, args.ca_file.as_deref())) {
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
    /// QUIC's socket, with --quic yes (T-667).
    quic: Option<std::net::UdpSocket>,
}

fn prepare(s: &ServeArgs, ca_file: Option<&str>) -> Result<Prepared, Refusal> {
    let listen = s.listen.as_deref().ok_or_else(|| {
        Refusal::usage("serve needs --listen ADDR:PORT, the address to serve on (127.0.0.1:0 takes a free port)")
    })?;
    // The private ranges that it dials too (T-635), read before anything.
    let routes = routes_of(s.routes.as_deref(), s.allow_private)?;
    let source = certs::Source::of(s, ca_file)?;
    // No key of its own: the net's `relay:*` names this role (T-455); a
    // list of a URL is fetched with the trust of --ca-file (T-646).
    let lists = keys_url::Lists::of(s, ca_file)?;
    let mint = mint_of(s.mint.as_deref().unwrap_or("nobody"), None, &lists)?;
    let who = minting_for(&mint)?;
    // What each key carried, and its budget (T-636).
    let (usage, metered) = quota::of(s, &mint)?;
    let egress = egress_of()?;
    // The cleartext road beside TLS, with tokens of one session (T-326).
    let cleartext = match s.cleartext.as_deref() {
        None => true,
        Some(word) => crate::forwarder::fallback::word(word)
            .ok_or_else(|| Refusal::usage(format!("--cleartext {word:?}: yes or no")))?,
    };
    // HTTP/2 with extended CONNECT, by ALPN (T-321).
    let http2 = match s.http2.as_deref() {
        None => true,
        Some(word) => crate::forwarder::fallback::word(word)
            .ok_or_else(|| Refusal::usage(format!("--http2 {word:?}: yes or no")))?,
    };
    // QUIC on the listener's port of UDP, when asked (T-667).
    let asked_quic = quic::asked(s.quic.as_deref())?;
    let keepalive = match s.keepalive.as_deref() {
        None => Limits::default().keepalive,
        Some(text) => match text.parse::<u64>() {
            Ok(secs @ 1..=3600) => Duration::from_secs(secs),
            _ => return Err(Refusal::usage(format!("--keepalive {text:?}: seconds, from 1 to 3600"))),
        },
    };
    // The resumable sessions of the forward road (T-173).
    let (sessions, resumable) = resumes::of(s)?;
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
    let acceptor =
        podssh_ws::tls_server::acceptor_for(certs.served.clone(), certs.alpn(http2)).map_err(Refusal::config)?;
    let tokens = serve::tokens::Tokens::random().map_err(Refusal::config)?;
    let pairs = serve::reverse::Pairs::open(s.pairs.as_deref().map(Into::into)).map_err(Refusal::config)?;
    let kept = match (s.pairs.as_deref(), pairs.len()) {
        (Some(file), n) => format!(", its pairs kept in {file} ({n} now)"),
        (None, _) => String::new(),
    };
    // The one call that may need a privilege, then none kept (T-629):
    // QUIC's socket with it.
    let mut udp = None;
    let (listener, dropped) = bind_then_drop(listen, |tcp| {
        udp = quic::bind(asked_quic, tcp)?;
        harden::give_up()
    })?;
    let sessions = quic::offered(sessions, &udp);
    let bound = listener.local_addr().map_err(|e| Refusal::config(e.to_string()))?;
    let events: serve::Events = Box::new(|line: &str| {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    });
    // A list of a URL, fetched with no privilege of the start (T-646).
    let came = keys_url::first(&mint)?;
    let through = egress_shown(&egress);
    let cfg = Config {
        version: format!("podssh {}", env!("CARGO_PKG_VERSION")),
        mint,
        tokens,
        policy: serve::policy::Policy {
            private: s.allow_private,
            ranges: routes.iter().map(|(_, range)| *range).collect(),
            ..Default::default()
        },
        egress,
        limits: Limits { keepalive, ..Limits::default() },
        pairs,
        resumes: sessions,
        answered: Default::default(),
        brake: Default::default(),
        usage,
        events: Some(events),
    };
    let inside = inside_shown(s.allow_private, &routes);
    let clear = if cleartext { ", the cleartext road beside TLS" } else { ", TLS alone" };
    let h2 = if http2 { ", HTTP/2 with extended CONNECT" } else { ", no HTTP/2" };
    let over_udp = quic::shown(&udp);
    let dropped = dropped.unwrap_or_default();
    let shown = format!(
        "the relay's forward and reverse roads (contract {}) at {bound}, minting for \
         {who}{came}{metered}{inside}{kept}{through}{clear}{listed}{resumable}{h2}{over_udp}{dropped}; {}",
        serve::CONTRACT,
        certs.shown
    );
    let port_file = s.port_file.clone().map(|path| (path, bound.port()));
    let door = Door { acceptor, cleartext };
    Ok(Prepared { listener, door, cfg: Arc::new(cfg), certs, shown, port_file, quic: udp })
}

/// The listener of `listen`, then `give_up` once it is bound: the
/// capabilities of the start go after the one call that needs them, and
/// before the runtime makes a thread, which would keep the sets that it was
/// made with.
fn bind_then_drop(
    listen: &str,
    give_up: impl FnOnce(&std::net::TcpListener) -> Result<Option<String>, Refusal>,
) -> Result<(std::net::TcpListener, Option<String>), Refusal> {
    let listener = std::net::TcpListener::bind(listen)
        .map_err(|e| Refusal { message: format!("cannot listen on {listen}: {e}"), code: EX_UNAVAILABLE })?;
    let dropped = give_up(&listener)?;
    Ok((listener, dropped))
}

/// The words of `--mint`, as a refusal names them.
const MINT_WORDS: &str = "anyone, nobody, keys:FILE, net or net,keys:FILE, where FILE may be an https:// URL";

/// Who `--mint WORD` mints for: anyone, nobody, the keys of a list (T-448),
/// the members of the net that this host holds (T-455), or both of those
/// (`net,keys:FILE`: FILE is the rest of the word, commas and all), a list
/// of an `https://` URL fetched as `lists` says (T-646); the node behind a
/// quick tunnel reads the same words (T-428), and names its key `me`, which
/// the net's `relay:NODE` names.
pub(crate) fn mint_of(word: &str, me: Option<PublicKey>, lists: &keys_url::Lists) -> Result<Mint, Refusal> {
    let list = |text: &str| {
        let rest = text.strip_prefix("keys:").filter(|rest| !rest.is_empty())?;
        Some(keys_url::list_of(rest, lists))
    };
    let net = |list: Option<List>| Mint::Net(Arc::new(crate::net::mint::Members::new(me)), list);
    match word {
        "anyone" => Ok(Mint::Anyone),
        "nobody" | "none" => Ok(Mint::Nobody),
        "net" => Ok(net(None)),
        word => match (word.strip_prefix("net,").map(list), list(word)) {
            (Some(Some(listed)), _) => Ok(net(Some(listed?))),
            (None, Some(listed)) => Ok(Mint::Keys(listed?)),
            _ => Err(Refusal::usage(format!("--mint {word:?}: {MINT_WORDS}"))),
        },
    }
}

/// Whom `mint` mints for, in the words of the first line. The list and the
/// net's document are read again for each request; here, so that a list
/// that cannot be read, or a net that this host does not hold or that
/// ended, stops the start (78), and whom they hold is said. A list of a URL
/// is read by its first fetch (`keys_url::first`), whose words follow.
pub(crate) fn minting_for(mint: &Mint) -> Result<String, Refusal> {
    Ok(match mint {
        Mint::Anyone => "anyone".to_string(),
        Mint::Nobody => "no one".to_string(),
        Mint::Keys(list) => list_shown(list)?,
        Mint::Net(net, list) => {
            let members = net.shown().map_err(|why| Refusal::config(format!("--mint net: {why}")))?;
            match list {
                Some(list) => format!("{members}; and {}", list_shown(list)?),
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

/// The private ranges of `--routes` (T-635), each read strictly, as an
/// exit's: none without the flag; with `--allow-private`, which dials each
/// address, a refusal (64), as the two say opposite things. The node behind
/// a quick tunnel reads the same.
pub(crate) fn routes_of(text: Option<&str>, private: bool) -> Result<Vec<(String, Range)>, Refusal> {
    let Some(text) = text else { return Ok(Vec::new()) };
    if private {
        return Err(Refusal::usage(
            "--routes names the private ranges that the relay dials, and --allow-private dials each address: give \
             one of them",
        ));
    }
    podssh_relay::serve::ranges::list(text).map_err(|why| Refusal::usage(format!("--routes {text}: {why}")))
}

/// The private targets of the first line, after a comma: each, those of
/// the ranges, or none.
pub(crate) fn inside_shown(private: bool, routes: &[(String, Range)]) -> String {
    match (private, routes) {
        (true, _) => ", private targets too".to_string(),
        (false, []) => String::new(),
        (false, routes) => {
            let words: Vec<&str> = routes.iter().map(|(word, _)| word.as_str()).collect();
            format!(", the private targets in {} too", words.join(", "))
        }
    }
}

/// The keys of `list`, in the words of the first line: a file's, read now;
/// a URL's by its host, whose copy has not come.
fn list_shown(list: &List) -> Result<String, Refusal> {
    let List::File(file) = list else { return Ok(format!("the keys of the list at {}", list.shown())) };
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
    let Prepared { listener, door, cfg, certs: kept, port_file, quic: udp, .. } = prepared;
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
        // QUIC beside the listener, with the certificate that it presents.
        if let Some(socket) = udp {
            quic::spawn(socket, kept.served.clone(), cfg.clone())?;
        }
        // The lines of ACME's work, said here, as each other line of the role.
        let (say, mut lines) = tokio::sync::mpsc::unbounded_channel();
        // A list of keys at a URL, fetched again each TTL; its lines too (T-646).
        let listed = say.clone();
        keys_url::start(
            &cfg.mint,
            Arc::new(move |line: &str| {
                let _ = listed.send(line.to_string());
            }),
        );
        let mut keeper = tokio::spawn(kept.keeper(say));
        // Each key's counts into their file, each 2 s while one moved (T-636).
        tokio::spawn(cfg.usage.clone().keep());
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
                    // Each key's totals, beside the reload (T-636).
                    for line in cfg.usage.lines() {
                        let _ = writeln!(said, "podssh relay serve: {line}");
                    }
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
                _ = stopped::stopped() => {
                    // A planned stop: each reverse socket hears 1012, which
                    // its client tells apart from a lost link (T-255).
                    cfg.pairs.restart(STOP_WAIT).await;
                    // The counts of the last 2 s, which no later write takes.
                    if let Err(why) = cfg.usage.save() {
                        let _ = writeln!(said, "podssh relay serve: usage: the counts were not written: {why}");
                    }
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

// Its steps' tests, apart so that this file stays within 500 lines.
#[cfg(test)]
mod tests;
