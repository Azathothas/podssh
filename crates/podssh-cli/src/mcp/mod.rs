//! `podssh mcp` (T-055): the commands of podssh as tools for an agent that
//! speaks the Model Context Protocol, over stdin and stdout. Each line of
//! stdin is one JSON-RPC message, each line of stdout one answer, and
//! nothing else is written there: podssh's own words go to stderr.
//!
//! Each call of a tool runs this binary once more, as a child with pipes:
//! `podssh ssh` for `ssh_exec`, and `status`, `doctor --json` and
//! `man --json`. A session's output reaches the call's buffers and never
//! the protocol's stdout; a call that runs too long, or that the client
//! cancels, ends with its child; and calls run at once, which one process
//! could not do, as the records of `podssh-ssh` are the process's (T-054).
//! At the end of stdin, the calls in flight have 2 s to end; at a signal to
//! end, none: each ends with its child.

mod allow;
mod child;
mod protocol;
mod tools;

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::exitmap::sysexits::{EX_CONFIG, EX_SOFTWARE, EX_USAGE};
use allow::Allow;
use child::Outcome;
use protocol::{Action, Era};
use tools::Settings;

/// The longest line that the server reads: the input of a call rides in it.
const MAX_LINE: usize = 16 << 20;
/// The calls that run at once; the others wait for one to end.
const SESSIONS: usize = 4;
/// How long the calls in flight may take to end once stdin has: a client
/// that closes stdin waits a short while before it ends the server.
const GRACE: Duration = Duration::from_secs(2);

/// `podssh mcp`'s command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpArgs {
    /// `--allow-host PATTERN`, each one.
    pub allow_host: Vec<String>,
    /// `-F FILE`: the `ssh_config` of each session.
    pub config: Option<String>,
    /// `--direct`: each session over TCP.
    pub direct: bool,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Serve stdin and stdout until the end of stdin: 0, or 64 for a pattern
/// that is not one, 78 for a `-F` file that is not one.
pub fn run(args: &McpArgs, err: &mut dyn Write) -> i32 {
    let allow = match Allow::new(&args.allow_host) {
        Ok(allow) => allow,
        Err(why) => {
            let _ = writeln!(err, "podssh mcp: {why}");
            return EX_USAGE;
        }
    };
    if let Some(file) = args.config.as_deref().filter(|f| !Path::new(f).is_file()) {
        let _ = writeln!(err, "podssh mcp: -F {file}: no such file");
        return EX_CONFIG;
    }
    let binary = match std::env::current_exe() {
        Ok(binary) => binary,
        Err(e) => {
            let _ = writeln!(err, "podssh mcp: the path of this program: {e}");
            return EX_SOFTWARE;
        }
    };
    let scratch = std::env::temp_dir().join(format!("podssh-mcp-{}", std::process::id()));
    if let Err(e) = podssh_relay::cache::private_dir(&scratch) {
        let _ = writeln!(err, "podssh mcp: {}: {e}", scratch.display());
        return EX_CONFIG;
    }
    let settings = Settings { allow, config: args.config.clone(), direct: args.direct, scratch: scratch.clone() };
    let _ = match settings.allow.is_empty() {
        true => writeln!(err, "podssh mcp: no --allow-host: ssh_exec is not offered; status, doctor and man are"),
        false => writeln!(err, "podssh mcp: ssh_exec may reach {}", settings.allow.shown()),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = writeln!(err, "podssh mcp: {e}");
            return EX_SOFTWARE;
        }
    };
    runtime.block_on(serve(settings, binary, tokio::io::stdin(), tokio::io::stdout()));
    // A read of stdin that waits on a blocking thread holds no one up.
    runtime.shutdown_timeout(Duration::from_millis(200));
    let _ = std::fs::remove_dir_all(&scratch);
    0
}

/// The calls in flight, by the text of their id: what stops each.
type Calls = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

/// Answer each line of `input` on `output`, until the end of `input`; then
/// each call in flight ends with its child.
pub(crate) async fn serve<R, W>(settings: Settings, binary: PathBuf, input: R, output: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let tools = tools::list(&settings);
    let settings = Arc::new(settings);
    let (tx, rx) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(write_lines(output, rx));
    let calls: Calls = Arc::default();
    let sessions = Arc::new(Semaphore::new(SESSIONS));
    let mut tasks = tokio::task::JoinSet::new();
    let mut era = Era::default();
    let mut input = BufReader::new(input);
    let ended = signalled();
    tokio::pin!(ended);
    let mut grace = GRACE;
    loop {
        let line = tokio::select! {
            line = read_line(&mut input) => line,
            () = &mut ended => {
                grace = Duration::ZERO;
                break;
            }
        };
        let line = match line {
            Line::End => break,
            Line::TooLong => {
                let _ = tx.send(protocol::error(&Value::Null, -32600, "Invalid Request: a line longer than 16 MiB"));
                continue;
            }
            Line::Text(line) if line.iter().all(u8::is_ascii_whitespace) => continue,
            Line::Text(line) => line,
        };
        match protocol::handle(&line, &mut era, &tools) {
            Action::Reply(message) => {
                let _ = tx.send(message);
            }
            Action::Nothing => {}
            Action::Cancel(id) => {
                if let Some(stop) = lock(&calls).remove(&id.to_string()) {
                    let _ = stop.send(());
                }
            }
            Action::Call { id, kind, name, arguments } => {
                let key = id.to_string();
                let (stop, stopped) = oneshot::channel();
                if lock(&calls).contains_key(&key) {
                    let _ = tx.send(protocol::error(&id, -32600, "Invalid Request: the id of a request in flight"));
                    continue;
                }
                lock(&calls).insert(key.clone(), stop);
                let (settings, binary, tx) = (settings.clone(), binary.clone(), tx.clone());
                let (calls, sessions) = (calls.clone(), sessions.clone());
                tasks.spawn(async move {
                    let result = call(&settings, &binary, &sessions, &name, &arguments, stopped).await;
                    // A call that the client cancelled is no longer in the
                    // map, and gets no answer.
                    let ours = lock(&calls).remove(&key).is_some();
                    if let (true, Some(result)) = (ours, result) {
                        let _ = tx.send(protocol::answer(&id, kind, result));
                    }
                });
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    // The calls in flight end in the grace, or with their children: none
    // outlives the server.
    let _ = tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
    for (_, stop) in lock(&calls).drain() {
        let _ = stop.send(());
    }
    while tasks.join_next().await.is_some() {}
    drop(tx);
    let _ = writer.await;
}

/// A signal to end: SIGTERM, SIGINT or SIGHUP; Ctrl-C, Ctrl-Break or the
/// close of the console on Windows.
async fn signalled() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let kinds = [SignalKind::terminate(), SignalKind::interrupt(), SignalKind::hangup()];
        let [Ok(mut a), Ok(mut b), Ok(mut c)] = kinds.map(signal) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = a.recv() => {}
            _ = b.recv() => {}
            _ = c.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
        let (Ok(mut a), Ok(mut b), Ok(mut c)) = (ctrl_c(), ctrl_break(), ctrl_close()) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = a.recv() => {}
            _ = b.recv() => {}
            _ = c.recv() => {}
        }
    }
}

/// One call of `name`: its result, or none when the client cancelled it.
async fn call(
    settings: &Settings,
    binary: &Path,
    sessions: &Semaphore,
    name: &str,
    arguments: &Map<String, Value>,
    mut stopped: oneshot::Receiver<()>,
) -> Option<Value> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let file = settings.scratch.join(format!("result-{}.json", NEXT.fetch_add(1, Ordering::Relaxed)));
    let plan = match tools::plan(settings, name, arguments, &file.to_string_lossy()) {
        Ok(plan) => plan,
        Err(why) => return Some(tools::refusal(&why)),
    };
    let _permit = tokio::select! {
        permit = sessions.acquire() => permit.ok()?,
        _ = &mut stopped => return None,
    };
    let outcome = child::run(binary, &plan, stopped).await;
    let written = std::fs::read(&file).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let _ = std::fs::remove_file(&file);
    match outcome {
        Outcome::Stopped => None,
        Outcome::NotStarted(why) => Some(tools::refusal(&format!("podssh could not start: {why}"))),
        Outcome::Ran(ran) => {
            let (structured, failed) = tools::shape(name, &ran, written);
            Some(tools::result(structured, failed))
        }
    }
}

/// Each message as one line, in the order sent.
async fn write_lines<W: AsyncWrite + Unpin>(mut output: W, mut messages: mpsc::UnboundedReceiver<Value>) {
    while let Some(message) = messages.recv().await {
        let mut line = message.to_string();
        line.push('\n');
        if output.write_all(line.as_bytes()).await.is_err() || output.flush().await.is_err() {
            return;
        }
    }
}

enum Line {
    Text(Vec<u8>),
    TooLong,
    End,
}

/// The next line of `input`, without its newline; a line past `MAX_LINE` is
/// read to its end and not kept.
async fn read_line(input: &mut (impl AsyncBufRead + Unpin)) -> Line {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buf = match input.fill_buf().await {
            Ok(buf) => buf,
            Err(_) => return Line::End,
        };
        if buf.is_empty() {
            // The end of input; a last line with no newline is a line.
            return match (too_long, line.is_empty()) {
                (true, _) => Line::TooLong,
                (false, true) => Line::End,
                (false, false) => Line::Text(line),
            };
        }
        let newline = buf.iter().position(|&b| b == b'\n');
        let chunk = &buf[..newline.unwrap_or(buf.len())];
        if line.len() + chunk.len() > MAX_LINE {
            too_long = true;
            line = Vec::new();
        } else if !too_long {
            line.extend_from_slice(chunk);
        }
        let used = newline.map_or(buf.len(), |at| at + 1);
        input.consume(used);
        if newline.is_some() {
            return if too_long { Line::TooLong } else { Line::Text(line) };
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
