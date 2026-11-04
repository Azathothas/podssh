//! `podssh ping --under-load` (T-660): what a user feels while a download
//! runs on the same connection. The keys of [`super::keys`] through `cat`,
//! idle; then `head -c` on a second channel of the connection, and after a
//! warm-up that lets it fill the path's queue, the same keys beside it, as
//! osewa measures. The download stops once the last key came back, and its
//! bytes while the keys ran are the rate of a bulk copy while one types.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use podssh_ssh::handler::Client;
use podssh_ssh::russh::client::Handle;
use podssh_ssh::russh::{ChannelMsg, ChannelReadHalf};
use serde_json::{json, Value};

use super::far::{self, Failed, STEP};
use super::keys::{self, Key, GAP, KEYS};
use super::stats::{self, Summary};

/// How long the download runs before the first key: the queue of a path
/// fills in its first seconds, and a key before then is not under load.
pub const WARMUP: Duration = Duration::from_secs(3);
/// The download's bytes: under the relay's 64 MiB for one session with the
/// keys beside them, and more than each of osewa's links carries while the
/// keys run, so on those links it is stopped, never spent.
pub const LOAD: u64 = 60 * 1024 * 1024;
const ECHO: &str = "cat";

/// What a run under load measured.
#[derive(Debug, Default)]
pub struct UnderLoad {
    pub idle: Vec<Key>,
    /// The keys after the warm-up, each sent from the download's start.
    pub loaded: Vec<Key>,
    pub command: String,
    /// When the download ended by itself, from its start; `None` when it
    /// still ran as the last key came back.
    pub ended: Option<Duration>,
    /// Its bytes in all.
    pub bytes: u64,
    /// Its bytes while the keys ran, and that time.
    pub typing: (u64, Duration),
}

/// The keys idle, then beside the download, on the connection of `handle`.
pub async fn measure(handle: &Handle<Client>) -> Result<UnderLoad, Failed> {
    let (mut reader, writer) = far::open(handle, ECHO).await?.split();
    // One key that is not counted: the first can wait for the shell to start cat.
    keys::typed(&writer, &mut reader, 1, Instant::now()).await?;
    let idle = keys::typed(&writer, &mut reader, KEYS, Instant::now()).await?;
    let command = format!("head -c {LOAD} /dev/zero");
    let (load_reader, load_writer) = far::open(handle, &command).await?.split();
    let started = Instant::now();
    let mut download = Download::start(load_reader);
    tokio::time::sleep_until((started + WARMUP).into()).await;
    let mut under = UnderLoad { idle, command, ..UnderLoad::default() };
    if download.ended().is_none() {
        let (before, from) = (download.bytes(), Instant::now());
        under.loaded = keys::typed(&writer, &mut reader, KEYS, started).await?;
        let to = download.ended().map_or_else(Instant::now, |end| end.min(Instant::now()));
        under.typing = (download.bytes() - before, to.saturating_duration_since(from));
    }
    under.ended = download.ended().map(|end| end.duration_since(started));
    // Stopped: what is in flight still comes, and goes with the channel.
    let _ = load_writer.close().await;
    let status = download.end().await;
    under.bytes = download.bytes();
    // A download that ended by itself ended whole, or the host's head failed.
    if under.ended.is_some() {
        match status {
            Some(0) if under.bytes == LOAD => {}
            Some(0) | None => {
                let why = format!("{}: {} of {LOAD} bytes came", under.command, under.bytes);
                return Err(Failed::Broke(why));
            }
            Some(other) => return Err(Failed::Status(under.command.clone(), other)),
        }
    }
    let _ = writer.eof().await;
    let _ = far::status_of(&mut reader).await;
    Ok(under)
}

/// The download beside the keys, read by a task of its own so that its bytes
/// never wait for a key: its count so far, and when it ended.
struct Download {
    got: Arc<AtomicU64>,
    ended: Arc<Mutex<Option<Instant>>>,
    task: tokio::task::JoinHandle<Option<i32>>,
}

impl Download {
    fn start(mut reader: ChannelReadHalf) -> Download {
        let got = Arc::new(AtomicU64::new(0));
        let ended: Arc<Mutex<Option<Instant>>> = Arc::default();
        let (count, end) = (got.clone(), ended.clone());
        let task = tokio::spawn(async move {
            let mut status = None;
            while let Ok(Some(msg)) = tokio::time::timeout(STEP, reader.wait()).await {
                match msg {
                    ChannelMsg::Data { data } => {
                        count.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    ChannelMsg::ExitStatus { exit_status } => status = Some(i32::try_from(exit_status).unwrap_or(255)),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            *end.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
            status
        });
        Download { got, ended, task }
    }

    fn bytes(&self) -> u64 {
        self.got.load(Ordering::Relaxed)
    }

    fn ended(&self) -> Option<Instant> {
        *self.ended.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The download's exit status, once its task ended within [`STEP`].
    async fn end(&mut self) -> Option<i32> {
        match tokio::time::timeout(STEP, &mut self.task).await {
            Ok(Ok(status)) => status,
            _ => {
                self.task.abort();
                None
            }
        }
    }
}

impl UnderLoad {
    /// Whether a key's echo came while the download still ran.
    fn beside(&self, key: &Key) -> bool {
        self.ended.is_none_or(|end| key.back() <= end)
    }

    /// The echoes of the keys beside the download: a key whose echo came
    /// after it ended was typed on an idle path.
    pub fn loaded_echoes(&self) -> Vec<Duration> {
        self.loaded.iter().filter(|k| self.beside(k)).map(|k| k.echo).collect()
    }

    /// The lines of the measure.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(idle) = Summary::of(&keys::echoes(&self.idle)) {
            let (n, gap) = (self.idle.len(), GAP.as_millis());
            lines.push(format!("echo idle ({ECHO}), {n} keys {gap} ms apart: {}", idle.shown()));
        }
        let beside = self.loaded_echoes();
        let after = WARMUP.as_secs();
        match (Summary::of(&beside), self.ended) {
            (Some(loaded), _) => {
                let keys = if beside.len() == self.loaded.len() {
                    format!("{} keys", beside.len())
                } else {
                    format!("{} of {} keys, the rest after it ended", beside.len(), self.loaded.len())
                };
                let (command, shown) = (&self.command, loaded.shown());
                lines.push(format!("echo under load ({ECHO} beside {command}, after {after} s), {keys}: {shown}"));
            }
            (None, Some(end)) => lines.push(format!(
                "echo under load: {} ended {:.1} s after it started, before a key went beside it: this path is \
                 faster than {} can load",
                self.command,
                end.as_secs_f64(),
                stats::mib(LOAD)
            )),
            (None, None) => {}
        }
        let (bytes, took) = self.typing;
        if !took.is_zero() {
            let rate = bytes as f64 / 1_048_576.0 / took.as_secs_f64();
            let (command, size, secs) = (&self.command, stats::mib(bytes), took.as_secs_f64());
            lines.push(format!("down while typing ({command}): {size} in {secs:.2} s, {rate:.1} MiB/s"));
        }
        lines
    }

    /// The measure in the JSON of `--json`, with each key's raw times.
    pub fn json(&self) -> Value {
        let key = |k: &Key| json!({ "sent_ms": stats::ms(k.sent), "echo_ms": stats::ms(k.echo) });
        let loaded = self
            .loaded
            .iter()
            .map(|k| {
                let mut value = key(k);
                value["beside"] = self.beside(k).into();
                value
            })
            .collect();
        json!({
            "keys": KEYS,
            "gap_ms": GAP.as_millis() as u64,
            "warmup_ms": WARMUP.as_millis() as u64,
            "idle": summarized(Summary::of(&keys::echoes(&self.idle)), self.idle.iter().map(key).collect()),
            "loaded": summarized(Summary::of(&self.loaded_echoes()), loaded),
            "load": {
                "command": self.command,
                "bytes": self.bytes,
                "typing_bytes": self.typing.0,
                "typing_seconds": self.typing.1.as_secs_f64(),
                "ended_ms": self.ended.map(stats::ms),
            },
        })
    }
}

/// A summary's fields, when it has one, beside the raw samples it was made of.
fn summarized(summary: Option<Summary>, samples: Vec<Value>) -> Value {
    let mut value = summary.map_or_else(|| json!({}), |s| s.json());
    value["samples"] = Value::Array(samples);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(sent: u64, echo: u64) -> Key {
        Key { sent: Duration::from_millis(sent), echo: Duration::from_millis(echo) }
    }

    fn run(ended: Option<u64>, loaded: Vec<Key>) -> UnderLoad {
        UnderLoad {
            idle: vec![key(0, 60), key(150, 62)],
            loaded,
            command: format!("head -c {LOAD} /dev/zero"),
            ended: ended.map(Duration::from_millis),
            bytes: LOAD,
            typing: (2 * 1_048_576, Duration::from_secs(2)),
        }
    }

    #[test]
    fn each_key_counts_beside_a_download_that_still_runs() {
        let under = run(None, vec![key(3_000, 480), key(3_150, 470)]);
        assert_eq!(under.loaded_echoes(), vec![Duration::from_millis(480), Duration::from_millis(470)]);
        let lines = under.lines();
        assert!(lines[0].starts_with("echo idle (cat), 2 keys 150 ms apart: min 60.0, p50 60.0"), "{lines:?}");
        let loaded = format!("echo under load (cat beside head -c {LOAD} /dev/zero, after 3 s), 2 keys: ");
        assert!(lines[1].starts_with(&loaded), "{lines:?}");
        assert!(lines[2].ends_with("2.0 MiB in 2.00 s, 1.0 MiB/s"), "{lines:?}");
        let doc = under.json();
        assert_eq!(doc["loaded"]["samples"][1], json!({ "sent_ms": 3150.0, "echo_ms": 470.0, "beside": true }));
        assert_eq!(doc["loaded"]["p50_ms"], 470.0);
        assert_eq!(doc["idle"]["samples"].as_array().map(Vec::len), Some(2));
        assert_eq!(doc["warmup_ms"], 3000);
    }

    #[test]
    fn a_key_back_after_the_download_ended_is_no_key_under_load() {
        // Ended at 3.4 s: the first key came back at 3.35 s, the second at 3.6 s.
        let under = run(Some(3_400), vec![key(3_000, 350), key(3_150, 450)]);
        assert_eq!(under.loaded_echoes(), vec![Duration::from_millis(350)]);
        assert!(under.lines()[1].contains("1 of 2 keys, the rest after it ended: "), "{:?}", under.lines());
        assert_eq!(under.json()["loaded"]["samples"][1]["beside"], false);
    }

    #[test]
    fn a_download_spent_within_the_warm_up_is_said_with_no_figure() {
        let mut under = run(Some(800), Vec::new());
        under.typing = (0, Duration::ZERO);
        let lines = under.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains("ended 0.8 s after it started, before a key went beside it"), "{lines:?}");
        let doc = under.json();
        assert!(doc["loaded"]["p50_ms"].is_null(), "{doc}");
        assert_eq!(doc["loaded"]["samples"], json!([]));
        assert_eq!(doc["load"]["ended_ms"], 800.0);
    }
}
