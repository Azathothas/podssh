//! `podssh ping` (T-053): a short check of the path. With no destination,
//! the relay leg of each relay host: the time of each step to it, then
//! WebSocket pings, each with its time in its payload and matched to its
//! pong. With a destination, the SSH login too, the echo of single bytes
//! through `cat`, and the throughput down and up, each remote command named.
//! Each step has a limit, and so has the whole run.

mod far;
mod relay;
mod stats;

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::relay::RelayList;
use podssh_ssh::Log;
use podssh_ws::Trust;

use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Transport};
use stats::Summary;

/// The default and the largest `--count`.
const COUNT: usize = 10;
const MAX_COUNT: usize = 100;
/// The limit on the whole run.
const RUN_LIMIT: Duration = Duration::from_secs(600);

/// What `podssh ping` was given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PingArgs {
    pub ssh: SshArgs,
    pub size: Option<String>,
    pub count: Option<String>,
    /// Where the relay leg goes, `HOST:PORT`.
    pub target: Option<String>,
    pub json: bool,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// The relay legs of a run: the hosts, their trust, the target, and the
/// family that the relay dials.
struct Legs {
    relays: RelayList,
    trust: Trust,
    target: (String, u16),
    family: Option<u8>,
}

/// What a run measured, for the lines and the JSON.
#[derive(Default)]
struct Report {
    relays: Vec<relay::Leg>,
    far: Option<Far>,
    code: i32,
}

/// The measures through the destination.
#[derive(Default)]
struct Far {
    destination: String,
    login: Option<Duration>,
    /// The exit code when the destination was not reached.
    unreached: Option<i32>,
    echo: Option<Summary>,
    echoes: usize,
    down: Option<(String, Result<Duration, String>)>,
    up: Option<(String, Result<Duration, String>)>,
    /// The status of the first remote program that failed.
    status: Option<i32>,
    failed: Option<String>,
}

/// Run `podssh ping`: 0 when the path works (a relay host gave its
/// measures, or with a destination each measure has its number); 64 for a
/// bad flag, before anything connects; 69 when no relay host answers, or
/// with `PODSSH_OFFLINE`; with a destination, `podssh ssh`'s code when it
/// cannot be reached or logged in to, a remote program's status when one
/// fails (127 when the host lacks it), and 255 when a measure breaks.
pub fn run(args: &PingArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let size = match args.size.as_deref().map(stats::size).transpose() {
        Ok(size) => size.unwrap_or(stats::DEFAULT_SIZE),
        Err(why) => return Refusal::usage(why).report("ping", err),
    };
    let count = match args.count.as_deref().map(|c| c.parse::<usize>()) {
        None => COUNT,
        Some(Ok(n)) if (1..=MAX_COUNT).contains(&n) => n,
        Some(_) => {
            let why = format!("--count {}: from 1 to {MAX_COUNT}", args.count.as_deref().unwrap_or_default());
            return Refusal::usage(why).report("ping", err);
        }
    };
    let target = match args.target.as_deref() {
        Some(text) => match crate::proxy::parse_target(Some(text), None) {
            Ok(target) => target,
            Err(why) => return Refusal::usage(format!("--target {text}: {why}")).report("ping", err),
        },
        None => (relay::REFERENCE.0.to_string(), relay::REFERENCE.1),
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("ping", err);
    }
    // With a destination, the run is resolved as `podssh ssh` resolves it.
    let resolved = match &args.ssh.destination {
        Some(_) => match resolve::resolve_or_refuse(&args.ssh, &Env::from_process()) {
            Ok(resolved) => Some(resolved),
            Err(refusal) => return refusal.report("ping", err),
        },
        None => None,
    };
    let legs = match &resolved {
        Some(r) => match &r.transport {
            Transport::Relay { relays, trust, family, .. } => {
                Some(Legs { relays: relays.clone(), trust: trust.clone(), target, family: *family })
            }
            _ => None,
        },
        None => match crate::relay_settings::relays(
            args.ssh.relay_host.as_deref(),
            std::env::var(podssh_relay::relay::RELAY_ENV).ok(),
        ) {
            Ok(relays) => {
                let family = if args.ssh.ipv4 { Some(4) } else { args.ssh.ipv6.then_some(6) };
                Some(Legs { relays, trust: relay::trust(args.ssh.ca_file.as_deref()), target, family })
            }
            Err(refusal) => return refusal.report("ping", err),
        },
    };
    if legs.is_none() && args.target.is_some() {
        let why = "--target aims the relay leg, and this run does not go through the relay".to_string();
        return Refusal::usage(why).report("ping", err);
    }
    if podssh_relay::open::offline() {
        let _ = writeln!(
            err,
            "podssh ping: {} is set, so podssh does not connect anywhere",
            podssh_relay::open::OFFLINE_ENV
        );
        return EX_UNAVAILABLE;
    }
    let level = resolved.as_ref().map_or(podssh_ssh::LogLevel::Info, |r| r.options.log_level);
    let log = Arc::new(Log::new(level));
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh ping: could not start the async runtime: {e}");
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    let work = async {
        let mut report = Report::default();
        if let Some(legs) = &legs {
            for host in &legs.relays.hosts {
                let leg = relay::leg(host, &legs.trust, (&legs.target.0, legs.target.1), legs.family, count).await;
                say_leg(&leg, args.json, out);
                report.relays.push(leg);
            }
            if resolved.is_none() && report.relays.iter().all(|leg| leg.failed.is_some()) {
                report.code = EX_UNAVAILABLE;
            }
        }
        if let Some(resolved) = &resolved {
            let far = destination(resolved, size, count, &log).await;
            report.code = far_code(&far);
            say_far(&far, size, args.json, out);
            report.far = Some(far);
        }
        report
    };
    let report = match runtime.block_on(async { tokio::time::timeout(RUN_LIMIT, work).await }) {
        Ok(report) => report,
        Err(_) => {
            let _ = writeln!(err, "podssh ping: the run passed its limit of {} s", RUN_LIMIT.as_secs());
            runtime.shutdown_background();
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    runtime.shutdown_background();
    if args.json {
        let _ = writeln!(out, "{}", json(&report, size, count));
    }
    // A remote program's status is the host's, no failure of podssh (T-195).
    if report.far.as_ref().is_some_and(|far| far.login.is_some() && far.status.is_some_and(|s| s != 0)) {
        crate::error_program::not_a_failure();
    }
    report.code
}

/// The exit code of the destination's measures.
fn far_code(far: &Far) -> i32 {
    if far.login.is_none() {
        return far.unreached.unwrap_or(podssh_ssh::EXIT_FAILURE);
    }
    if let Some(status) = far.status.filter(|s| *s != 0) {
        return status;
    }
    let broke = |m: &Option<(String, Result<Duration, String>)>| matches!(m, Some((_, Err(_))));
    if far.failed.is_some() || broke(&far.down) || broke(&far.up) {
        podssh_ssh::EXIT_FAILURE
    } else {
        0
    }
}

/// Log in, then the echo and the throughput.
async fn destination(resolved: &resolve::Resolved, size: u64, count: usize, log: &Arc<Log>) -> Far {
    let opts = &resolved.options;
    let mut far = Far { destination: format!("{}@{}", opts.user, opts.destination.host), ..Far::default() };
    let started = Instant::now();
    let reached = match crate::ssh::transport::reach(resolved, log).await {
        Ok(reached) => reached,
        Err(not) => {
            far.unreached = Some(not.code);
            far.failed = Some(not.lines.join("; "));
            return far;
        }
    };
    let handles = match podssh_ssh::run::connect_hops(reached.stream, opts, log).await {
        Ok(handles) => handles,
        Err(e) => {
            far.failed = Some(e.to_string());
            return far;
        }
    };
    far.login = Some(started.elapsed());
    let handle = handles.last().expect("the destination");
    match far::echo(handle, count).await {
        Ok(samples) => {
            far.echoes = samples.len();
            far.echo = Summary::of(&samples);
        }
        Err(why) => {
            far.status = why.status();
            far.failed = Some(format!("echo: {why}"));
        }
    }
    if far.failed.is_none() {
        let (command, result) = far::down(handle, size).await;
        far.status = far.status.or(result.as_ref().err().and_then(far::Failed::status));
        far.down = Some((command, result.map_err(|e| e.to_string())));
        let (command, result) = far::up(handle, size).await;
        far.status = far.status.or(result.as_ref().err().and_then(far::Failed::status));
        far.up = Some((command, result.map_err(|e| e.to_string())));
    }
    podssh_ssh::run::disconnect_all(&handles).await;
    drop(handles);
    crate::ssh::transport::settle(reached.layer).await;
    far
}

fn say_leg(leg: &relay::Leg, json: bool, out: &mut dyn Write) {
    if !json {
        let _ = writeln!(out, "{}", leg.line());
    }
}

fn say_far(far: &Far, size: u64, json: bool, out: &mut dyn Write) {
    if json {
        return;
    }
    let mut lines = Vec::new();
    match (&far.login, &far.failed) {
        (Some(login), _) => {
            lines.push(format!("ssh {}: login {:.0} ms", far.destination, login.as_secs_f64() * 1000.0))
        }
        (None, Some(why)) => lines.push(format!("ssh {}: {why}", far.destination)),
        (None, None) => {}
    }
    if let Some(echo) = &far.echo {
        lines.push(format!("echo (cat), {} bytes: {}", far.echoes, echo.shown()));
    }
    for (way, measure) in [("down", &far.down), ("up", &far.up)] {
        if let Some((command, result)) = measure {
            lines.push(match result {
                Ok(took) => format!(
                    "{way} ({command}): {} in {:.2} s, {:.1} MiB/s",
                    stats::mib(size),
                    took.as_secs_f64(),
                    size as f64 / 1_048_576.0 / took.as_secs_f64().max(1e-6)
                ),
                Err(why) => format!("{way} ({command}): {why}"),
            });
        }
    }
    if let (Some(_), Some(why)) = (&far.login, &far.failed) {
        lines.push(why.clone());
    }
    for line in lines {
        let _ = writeln!(out, "{line}");
    }
}

/// One JSON document, in the shape of `doctor --json` (T-049).
fn json(report: &Report, size: u64, count: usize) -> serde_json::Value {
    let ms = |d: &Duration| (d.as_secs_f64() * 1_000_000.0).round() / 1000.0;
    let far = report.far.as_ref().map(|f| {
        let measure = |m: &Option<(String, Result<Duration, String>)>| match m {
            Some((command, Ok(took))) => {
                serde_json::json!({ "command": command, "seconds": took.as_secs_f64(), "bytes": size })
            }
            Some((command, Err(why))) => serde_json::json!({ "command": command, "error": why }),
            None => serde_json::Value::Null,
        };
        serde_json::json!({
            "destination": f.destination,
            "login_ms": f.login.as_ref().map(ms),
            "echo": f.echo.map(|e| e.json()),
            "down": measure(&f.down),
            "up": measure(&f.up),
            "error": f.failed,
        })
    });
    serde_json::json!({
        "schema": 1,
        "podssh": crate::help::version(),
        "count": count,
        "size": size,
        "relays": report.relays.iter().map(relay::Leg::json).collect::<Vec<_>>(),
        "destination": far,
        "exit": report.code,
    })
}
