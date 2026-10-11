//! One call of a tool: this binary once more, as a child with three pipes.
//! Its stdin gets the call's input and then its end; its stdout and stderr
//! are kept up to a cap each, and read to their end past it, so that the
//! child never waits on a full pipe. A call past its limit, or one that the
//! client cancels, ends with its child.

use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

/// How long the output may take to end once the child has: a program that
/// the child started, a `ProxyCommand`, can hold its pipes open.
const DRAIN: Duration = Duration::from_secs(5);

/// What a call runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The arguments after the binary.
    pub argv: Vec<OsString>,
    /// The bytes of the child's stdin.
    pub stdin: Vec<u8>,
    /// The longest that the call may take.
    pub limit: Duration,
    /// The most bytes kept of stdout, and of stderr.
    pub cap: usize,
}

/// The bytes of one stream: those kept, and whether more came.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captured {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// How a call ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// The child's exit code; none when a signal ended it, as at the limit.
    pub exit: Option<i32>,
    pub stdout: Captured,
    pub stderr: Captured,
    /// The limit passed, and the child was stopped.
    pub timed_out: bool,
    pub duration: Duration,
}

/// The end of a call.
#[derive(Debug)]
pub enum Outcome {
    Ran(Ran),
    /// The client cancelled the call: no answer is sent.
    Stopped,
    /// The child could not start.
    NotStarted(String),
}

/// Run `plan` with `binary`, until it ends, its limit passes or `stop` fires.
pub async fn run(binary: &Path, plan: &Plan, mut stop: oneshot::Receiver<()>) -> Outcome {
    let started = Instant::now();
    let mut command = tokio::process::Command::new(binary);
    command.args(&plan.argv).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    // No console window of its own for a child of a server with none.
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return Outcome::NotStarted(format!("{}: {e}", binary.display())),
    };
    let (out, err) = (Arc::new(Mutex::new(Captured::default())), Arc::new(Mutex::new(Captured::default())));
    let mut readers = Vec::new();
    if let Some(pipe) = child.stdout.take() {
        readers.push(tokio::spawn(keep(pipe, plan.cap, out.clone())));
    }
    if let Some(pipe) = child.stderr.take() {
        readers.push(tokio::spawn(keep(pipe, plan.cap, err.clone())));
    }
    let feed = child.stdin.take().map(|mut pipe| {
        let input = plan.stdin.clone();
        tokio::spawn(async move {
            let _ = pipe.write_all(&input).await;
            let _ = pipe.shutdown().await;
        })
    });
    let mut timed_out = false;
    let status = tokio::select! {
        status = child.wait() => status.ok(),
        () = tokio::time::sleep(plan.limit) => {
            timed_out = true;
            let _ = child.kill().await;
            child.wait().await.ok()
        }
        _ = &mut stop => {
            let _ = child.kill().await;
            return Outcome::Stopped;
        }
    };
    if let Some(feed) = feed {
        feed.abort();
    }
    let drained = tokio::time::timeout(DRAIN, async {
        for reader in readers.iter_mut() {
            let _ = reader.await;
        }
    })
    .await;
    if drained.is_err() {
        readers.iter().for_each(|reader| reader.abort());
    }
    let take = |c: &Arc<Mutex<Captured>>| std::mem::take(&mut *c.lock().unwrap_or_else(|e| e.into_inner()));
    Outcome::Ran(Ran {
        exit: status.and_then(|s| s.code()),
        stdout: take(&out),
        stderr: take(&err),
        timed_out,
        duration: started.elapsed(),
    })
}

/// Read `pipe` to its end, keeping its first `cap` bytes in `into`.
async fn keep(mut pipe: impl AsyncRead + Unpin, cap: usize, into: Arc<Mutex<Captured>>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let mut kept = into.lock().unwrap_or_else(|e| e.into_inner());
        let room = cap.saturating_sub(kept.bytes.len());
        kept.bytes.extend_from_slice(&buf[..n.min(room)]);
        if n > room {
            kept.truncated = true;
        }
    }
}

/// The bytes as text: UTF-8 when they are, base64 else. A cut at the cap
/// that split a character keeps the text up to it, as the cap is a bound
/// and not a promise of a size.
pub fn text(captured: &Captured) -> (String, &'static str) {
    let bytes = &captured.bytes;
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), "utf-8"),
        // A character cut at the end, by the cap: the text before it.
        Err(e) if captured.truncated && e.error_len().is_none() => {
            (String::from_utf8_lossy(&bytes[..e.valid_up_to()]).into_owned(), "utf-8")
        }
        Err(_) => {
            use base64::Engine as _;
            (base64::engine::general_purpose::STANDARD.encode(bytes), "base64")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_utf8_when_it_can_be_and_base64_else() {
        let c = |bytes: &[u8], truncated| Captured { bytes: bytes.to_vec(), truncated };
        assert_eq!(text(&c(b"hi\n", false)), ("hi\n".to_string(), "utf-8"));
        assert_eq!(text(&c(&[0xff, 0x00, 0x41], false)), ("/wBB".to_string(), "base64"));
        // "é" cut in half by the cap.
        assert_eq!(text(&c(&[b'a', 0xc3], true)), ("a".to_string(), "utf-8"));
        // The same bytes with nothing cut are not text.
        assert_eq!(text(&c(&[b'a', 0xc3], false)).1, "base64");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keep_holds_the_cap_and_reads_on() {
        let into = Arc::new(Mutex::new(Captured::default()));
        let data = vec![7u8; 200_000];
        keep(&data[..], 100_000, into.clone()).await;
        let kept = into.lock().unwrap().clone();
        assert_eq!((kept.bytes.len(), kept.truncated), (100_000, true));
        let into = Arc::new(Mutex::new(Captured::default()));
        keep(&b"short"[..], 100_000, into.clone()).await;
        assert_eq!(*into.lock().unwrap(), Captured { bytes: b"short".to_vec(), truncated: false });
    }
}
