//! `podssh pipe A B` (T-174, T-175): join two byte streams, as socat does,
//! with no listener. Each address is `KIND:REST` (`address`); both are
//! checked before anything starts. The pump (`pump`) copies both ways; the
//! local ends are stdin and stdout, an inherited descriptor, and a child
//! (`local`); the remote ends open a road (`remote`, `relay`). A road that
//! failed gives the pipe's exit code, as `podssh proxy` gives it; else a
//! child's status, B's when both are children, as a shell gives it; with
//! neither, a clean end gives 0.

use std::io::Write;

pub mod address;
pub mod iroh;
pub mod local;
pub mod node;
pub mod pump;
pub mod relay;
pub mod remote;
pub mod ssh;
pub mod unix;

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
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Run the verb; returns the process exit code.
pub fn run_pipe(args: &PipeArgs, err: &mut dyn Write) -> i32 {
    let (a, b) = match address::both(args.a.as_deref(), args.b.as_deref()) {
        Ok(both) => both,
        Err(refusal) => return refusal.report("pipe", err),
    };
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
    let code = runtime.block_on(run(a, b, &settings, err));
    // A read of stdin may still wait in its thread; the pipe has ended.
    runtime.shutdown_background();
    code
}

async fn run(a: address::Address, b: address::Address, settings: &remote::Settings, err: &mut dyn Write) -> i32 {
    let a = match open(&a, settings, err).await {
        Ok(end) => end,
        Err(code) => return code,
    };
    let b = match open(&b, settings, err).await {
        Ok(end) => end,
        Err(code) => {
            // A's child, if any, would wait for input that never comes; its
            // road is closed as at any end.
            if let Some(mut child) = a.child {
                let _ = child.kill().await;
            }
            if let Some(ending) = a.ending {
                let _ = ending.finish().await;
            }
            return code;
        }
    };
    let pumped = pump::pump(a, b).await;
    report(pumped, "podssh pipe", err).await
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
    b_child.or(a_child).unwrap_or(0)
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
