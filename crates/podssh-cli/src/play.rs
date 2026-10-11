//! `podssh play FILE` (T-033): a recording of `podssh ssh --record`, or
//! another asciicast v2 file, played again on stdout with its timing. The
//! output of a session reaches the terminal again, its control sequences
//! too: play only a file that you trust.

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::exit_codes::EXIT_USAGE;

/// The exit when the file cannot be played: missing, or not asciicast v2.
pub const EXIT_FAILED: i32 = 1;

/// Every value `podssh play` accepts, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayArgs {
    pub file: Option<String>,
    pub speed: Option<String>,
    pub idle_limit: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

pub fn run(args: &PlayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(path) = args.file.as_deref() else {
        let _ = writeln!(err, "podssh play: give the recording: podssh play FILE");
        return EXIT_USAGE;
    };
    let number = |flag: &str, value: &Option<String>| match value.as_deref() {
        None => Ok(None),
        Some(text) => positive(text).map(Some).ok_or(format!("{flag} {text}: a number above 0")),
    };
    let (speed, idle) = match (number("--speed", &args.speed), number("--idle-limit", &args.idle_limit)) {
        (Ok(speed), Ok(idle)) => (speed.unwrap_or(1.0), idle),
        (Err(why), _) | (_, Err(why)) => {
            let _ = writeln!(err, "podssh play: {why}");
            return EXIT_USAGE;
        }
    };
    match play(path, speed, idle, out) {
        Ok(()) => 0,
        Err(why) => {
            let _ = writeln!(err, "podssh play: {path}{why}");
            EXIT_FAILED
        }
    }
}

/// Each output event of the file at its time, each wait cut to `idle` and
/// divided by `speed`; an event of another kind is passed over. `Err` is
/// the end of a message after the file's name.
fn play(path: &str, speed: f64, idle: Option<f64>, out: &mut dyn Write) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!(": {e}"))?;
    let mut lines = std::io::BufReader::new(file).lines();
    let header: Option<Value> = lines.next().and_then(Result::ok).and_then(|line| serde_json::from_str(&line).ok());
    let header = header.filter(|h| h.get("version").and_then(Value::as_u64) == Some(2));
    let Some(header) = header else { return Err(": not an asciicast v2 recording".into()) };
    let idle = idle.or_else(|| header.get("idle_time_limit").and_then(Value::as_f64).filter(|v| *v > 0.0));
    let (start, mut last, mut clock) = (Instant::now(), 0.0_f64, 0.0_f64);
    for (n, line) in lines.enumerate() {
        let line = line.map_err(|e| format!(": {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let event: Option<Value> = serde_json::from_str(&line).ok();
        let event = event.as_ref().and_then(|e| Some((e.get(0)?.as_f64()?, e.get(1)?.as_str()?, e.get(2)?.as_str()?)));
        let Some((at, kind, data)) = event else { return Err(format!(":{}: not an event", n + 2)) };
        let gap = (at - last).max(0.0);
        last = at;
        clock += idle.map_or(gap, |limit| gap.min(limit)) / speed;
        if kind != "o" {
            continue;
        }
        std::thread::sleep((start + Duration::from_secs_f64(clock)).saturating_duration_since(Instant::now()));
        // Whoever read the output went: nothing more to play.
        if out.write_all(data.as_bytes()).and_then(|()| out.flush()).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

fn positive(text: &str) -> Option<f64> {
    text.parse::<f64>().ok().filter(|v| v.is_finite() && *v > 0.0)
}
