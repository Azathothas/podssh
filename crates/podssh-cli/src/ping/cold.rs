//! `podssh ping --connect-runs N` (T-660): N cold connects, one after the
//! other, each a connection of its own as a new `podssh ssh` would open, the
//! login, and `true` run to its exit status: the wait for a first command.
//! Each run is timed from the start of its own connection to `true`'s
//! status; the destination was resolved once before, as each `ssh` resolves
//! it in a few milliseconds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_ssh::handler::Client;
use podssh_ssh::russh::client::Handle;
use podssh_ssh::russh::ChannelMsg;
use podssh_ssh::{Log, EXIT_FAILURE};
use serde_json::{json, Value};

use super::far::STEP;
use super::stats::{self, Summary};
use crate::ssh::resolve::Resolved;

/// The most runs: each is a login, which a server and the relay count.
pub const MAX_RUNS: usize = 20;
const COMMAND: &str = "true";

/// The runs that ended with `true`'s status 0.
#[derive(Debug, Default)]
pub struct Cold {
    pub runs: usize,
    pub samples: Vec<Duration>,
}

/// Why a run gave no time: the code of the run (`podssh ssh`'s when the
/// destination was not reached, `true`'s status, else 255), and the words.
#[derive(Debug)]
pub struct ColdFailed {
    pub code: i32,
    pub why: String,
}

/// `runs` cold connects; the first that fails ends them.
pub async fn runs(resolved: &Resolved, runs: usize, log: &Arc<Log>) -> Result<Cold, ColdFailed> {
    let mut cold = Cold { runs, samples: Vec::with_capacity(runs) };
    for run in 1..=runs {
        match one(resolved, log).await {
            Ok(took) => cold.samples.push(took),
            Err((code, why)) => return Err(ColdFailed { code, why: format!("connect run {run} of {runs}: {why}") }),
        }
    }
    Ok(cold)
}

/// One run: its own connection, the login, `true`; then it ends, before the
/// next starts, so a run never meets the one before it.
async fn one(resolved: &Resolved, log: &Arc<Log>) -> Result<Duration, (i32, String)> {
    let started = Instant::now();
    let reached = super::feel::reach(resolved, log).await.map_err(|not| (not.code, not.lines.join("; ")))?;
    let handles = match podssh_ssh::run::connect_hops(reached.stream, &resolved.options, log).await {
        Ok(handles) => handles,
        Err(e) => return Err((EXIT_FAILURE, e.to_string())),
    };
    let answered = match handles.last() {
        Some(handle) => first_command(handle).await,
        None => Err((EXIT_FAILURE, "no connection to the destination".into())),
    };
    podssh_ssh::run::disconnect_all(&handles).await;
    drop(handles);
    crate::ssh::transport::settle(reached.layer).await;
    answered.map(|at| at.duration_since(started))
}

/// `true` on a channel of its own: when its exit status came. The status
/// and the server's reply to the command can come in either order.
async fn first_command(handle: &Handle<Client>) -> Result<Instant, (i32, String)> {
    let broke = |why: String| (EXIT_FAILURE, format!("{COMMAND}: {why}"));
    let channel = match handle.channel_open_session().await {
        Ok(channel) => channel,
        Err(e) => {
            let read = podssh_ssh::unopened::read(&e, handle).await;
            return Err(broke(read.words("a session", false)));
        }
    };
    channel.exec(true, COMMAND.as_bytes()).await.map_err(|e| broke(format!("not sent: {e}")))?;
    let (mut reader, _writer) = channel.split();
    let mut answered = None;
    loop {
        match tokio::time::timeout(STEP, reader.wait()).await {
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => answered = Some((Instant::now(), exit_status)),
            Ok(Some(ChannelMsg::Failure)) => return Err(broke("the server refused to run it".into())),
            Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
            Ok(Some(_)) => {}
            Err(_) => return Err(broke(format!("no answer within {} s", STEP.as_secs()))),
        }
    }
    match answered {
        Some((at, 0)) => Ok(at),
        Some((_, status)) => Err((i32::try_from(status).unwrap_or(255), format!("{COMMAND}: exit {status}"))),
        None => Err(broke("the channel closed with no exit status".into())),
    }
}

impl Cold {
    /// `connect and true, 5 runs: min 310.2, p50 ..., max ... ms`.
    pub fn line(&self) -> Option<String> {
        let summary = Summary::of(&self.samples)?;
        Some(format!("connect and {COMMAND}, {} runs: {}", self.samples.len(), summary.shown()))
    }

    /// The runs in the JSON of `--json`, each run's time in order.
    pub fn json(&self) -> Value {
        let mut value = Summary::of(&self.samples).map_or_else(|| json!({}), |s| s.json());
        value["runs"] = self.runs.into();
        value["command"] = COMMAND.into();
        value["samples_ms"] = stats::samples_json(&self.samples);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runs_give_a_line_and_each_raw_time() {
        let ms = |v: u64| Duration::from_millis(v);
        let cold = Cold { runs: 3, samples: vec![ms(400), ms(380), ms(390)] };
        assert_eq!(
            cold.line().as_deref(),
            Some("connect and true, 3 runs: min 380.0, p50 390.0, p95 400.0, max 400.0 ms")
        );
        let doc = cold.json();
        assert_eq!(doc["samples_ms"], json!([400.0, 380.0, 390.0]));
        assert_eq!((doc["runs"].as_u64(), doc["command"].as_str()), (Some(3), Some("true")));
        assert_eq!(doc["p50_ms"], 390.0);
        assert_eq!(Cold::default().line(), None);
    }
}
