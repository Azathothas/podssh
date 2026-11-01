//! The Tor road, in a build with the feature `tor` (T-353): whether Arti
//! bootstraps here, as `tor://` makes it (through the proxy, its first
//! hops held to the ports that the proxy allows, or the bridges of
//! `PODSSH_TOR_BRIDGES` and their transports, T-385), and in how long. A
//! first bootstrap fetches Tor's directory, a few MiB, so it runs with
//! `--full` alone; no stream is opened.

use std::sync::Mutex;
use std::time::Instant;

use podssh_ws::Trust;

use super::Report;

/// The line of a run without `--full`.
const NOT_TRIED: &str =
    "not tried: a first bootstrap fetches Tor's directory, a few MiB; podssh doctor --full tries it";

pub(super) async fn check(report: &mut Report<'_>, trust: &Trust, full: bool) {
    if !full {
        return report.unknown("tor", NOT_TRIED.to_string());
    }
    let started = Instant::now();
    // The road's own lines would go to stderr; the report says the result.
    let retried = Mutex::new(false);
    let say = |_: &str| {};
    let verbose = |_: &str| {
        if let Ok(mut retried) = retried.lock() {
            *retried = true;
        }
    };
    // The line names the bridges and their transports when there are any.
    match crate::ssh::cloud::tor::road::bootstrap("tor", trust, &say, &verbose).await {
        Ok((_tor, how)) => {
            let again = match retried.lock().map(|r| *r) {
                Ok(true) => "; Arti refused the directories' modes, and its check was left out",
                _ => "",
            };
            let took = started.elapsed().as_secs_f32();
            report.ok("tor", format!("Arti bootstrapped in {took:.1} s, {how}{again}"));
        }
        Err((line, _)) => report.fail("tor", line),
    }
}
