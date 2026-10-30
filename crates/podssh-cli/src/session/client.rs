//! The clients of a session's daemon (T-186): `send`, `wait`, `capture`,
//! `stop` and `list`. Each makes one request on the socket and reads its
//! answer: a connect, which is no listener. A daemon that closes the
//! connection with no answer took the client for another user's.

use std::io::{IsTerminal, Read, Write};
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::wire::{self, Failure, Op};
use super::{place, SessionArgs, SEND_MAX};
use crate::exitmap::sysexits::{EX_NOPERM, EX_TEMPFAIL, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;

/// How long an answer may take, past the wait that a request asks for.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// How long `list` waits for each session.
const LIST_WAIT: Duration = Duration::from_secs(2);

/// Run a request of `args`'s session, and give its answer: the screen of a
/// capture on stdout, as is; what ended a wait. The exit code.
pub fn request(args: &SessionArgs, op: Op, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let name = args.name();
    let Some(path) = place::find(name, args.socket.as_deref()) else {
        let _ = writeln!(err, "podssh session: no session {name}: podssh session list names each one");
        return EX_UNAVAILABLE;
    };
    let Some(runtime) = super::runtime(err) else { return super::NO_RUNTIME };
    let limit = match &op {
        Op::Wait(wait) => wait.timeout + ANSWER_WAIT,
        _ => ANSWER_WAIT,
    };
    let answer = runtime.block_on(ask(&path, &wire::request(name, &op), limit));
    runtime.shutdown_background();
    let fields = match answer {
        Ok(fields) => fields,
        Err((code, why)) => {
            let _ = writeln!(err, "podssh session: {name}: {why}");
            return code;
        }
    };
    let shown = match op {
        Op::Capture { raw: true } => wire::raw_bytes(&fields).map(|bytes| out.write_all(&bytes)),
        Op::Capture { raw: false } => Ok(out.write_all(text(&fields, "screen").as_bytes())),
        Op::Wait(_) => Ok(writeln!(out, "{}", text(&fields, "by"))),
        Op::Info | Op::Send(_) | Op::Stop => Ok(Ok(())),
    };
    match shown {
        Ok(_) => 0,
        Err(why) => {
            let _ = writeln!(err, "podssh session: {name}: {why}");
            crate::exitmap::sysexits::EX_SOFTWARE
        }
    }
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> &'a str {
    fields.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// One request on the socket at `path`, and its answer, within `limit`.
pub(super) async fn ask(path: &str, line: &str, limit: Duration) -> Result<Map<String, Value>, Failure> {
    let end = crate::pipe::unix::connect(path).await.map_err(|e| (code_of(&e), format!("{path}: {e}")))?;
    let mut writer = end.write;
    let mut reader = BufReader::new(end.read);
    let exchange = async {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        let mut answer = Vec::new();
        (&mut reader).take(wire::MAX_LINE as u64 + 1).read_until(b'\n', &mut answer).await?;
        Ok::<_, std::io::Error>(answer)
    };
    let answer = match tokio::time::timeout(limit, exchange).await {
        Err(_) => return Err((EX_TEMPFAIL, format!("no answer within {} s", limit.as_secs()))),
        Ok(Err(e)) => return Err((EX_UNAVAILABLE, format!("{path}: {e}"))),
        Ok(Ok(answer)) => answer,
    };
    if answer.is_empty() {
        let why = "the session's podssh closed the connection with no answer: it answers its own user only";
        return Err((EX_UNAVAILABLE, why.to_string()));
    }
    wire::parse_answer(&answer)
}

/// A socket that is not there, or that nobody serves, is no session (69);
/// one that this user may not open is a refusal (77).
fn code_of(e: &std::io::Error) -> i32 {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

/// `podssh session list`: a line for each session that answers, its name,
/// its state and its host, with tabs between them. A socket that nobody
/// serves is left out; the next `start` of its name takes its place.
pub fn list(out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let sessions = place::all();
    if sessions.is_empty() {
        return 0;
    }
    let Some(runtime) = super::runtime(err) else { return super::NO_RUNTIME };
    for (name, path) in sessions {
        let line = wire::request(&name, &Op::Info);
        let Ok(fields) = runtime.block_on(ask(&path, &line, LIST_WAIT)) else { continue };
        let state = match fields.get("status").and_then(Value::as_i64) {
            Some(status) => format!("ended {status}"),
            None => text(&fields, "state").to_string(),
        };
        let _ = writeln!(out, "{name}\t{state}\t{}", text(&fields, "host"));
    }
    runtime.shutdown_background();
    0
}

/// The text of `send` with no TEXT: stdin to its end, as it is, with no
/// Enter after it, so that a password never stands in a command line.
pub fn stdin_text() -> Result<Vec<u8>, Refusal> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        let why = "give the text, or send it on stdin: printf '%s\\r' TEXT | podssh session send NAME";
        return Err(Refusal::usage(why));
    }
    let mut text = Vec::new();
    let read = stdin.lock().take(SEND_MAX as u64 + 1).read_to_end(&mut text);
    match read {
        Ok(_) if text.len() > SEND_MAX => Err(Refusal::usage(format!("send types {SEND_MAX} bytes at most at once"))),
        Ok(_) => Ok(text),
        Err(e) => Err(Refusal::usage(format!("stdin: {e}"))),
    }
}
