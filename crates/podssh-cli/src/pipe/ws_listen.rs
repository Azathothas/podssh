//! `ws-listen:` (T-368): a WebSocket server on a port, as `tcp-listen:`
//! takes it, or on a socket, as `unix-listen:` takes it; each client is
//! joined to the other side as given, which takes no target from the
//! request. A client's request is read as `http-listen:` reads one (16 KiB,
//! 30 s) and checked as RFC 6455 section 4.2.1 asks (`podssh_ws::server`);
//! a refused one gets its status and its connection closes. Then the other
//! side opens, and only once it is open does the client hear 101, else 502.
//! Frames are then a server's: unmasked, and a client's unmasked frame
//! closes the session with 1002. One client by default, the first whose
//! upgrade is good, as a refused request is no session; with
//! `--keep-listening`, each in turn. With `--cover DIR`, a request that asks
//! for no upgrade gets a page of DIR (`cover`, T-639), and is no session
//! either.

use std::io::Write;
use std::rc::Rc;

use podssh_ws::http::request;
use tokio::io::AsyncWriteExt;

use super::address::Address;
use super::cover::{self, Cover};
use super::http_listen::{abandon, close_after, read_head, Refused};
use super::listen::Listener;
use super::pump::{self, End};
use super::remote::Settings;
use super::serve::{Interrupt, Serve};
use super::ws::{carry, Joined};
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay_settings::Refusal;

/// The client's WebSocket, in its session's lines.
const SHOWN: &str = "the client's WebSocket";

/// The answer to a client whose other side did not open.
fn unopened() -> Vec<u8> {
    request::refusal(502, "the other side of this pipe did not open", &[])
}

/// What a `ws-listen:` answers besides a good upgrade: the pages of
/// `--cover` (T-639).
#[derive(Debug, Default)]
pub struct Answers {
    pub cover: Option<Cover>,
    /// `-q`: no line for a page, which is no failure.
    pub quiet: bool,
}

/// The answers of `ws-listen:`'s flags, read before anything binds: each is
/// for a pipe with a `ws-listen:` side (64), and the DIR of `--cover` must
/// be a directory (64).
pub fn answers(addresses: [&Address; 2], dir: Option<&str>, quiet: bool) -> Result<Answers, Refusal> {
    let listens = addresses.iter().any(|a| matches!(a, Address::WsListen(_)));
    if dir.is_some() && !listens {
        let why = format!("{} is for ws-listen:, the side that a browser visits", cover::FLAG);
        return Err(Refusal::usage(why));
    }
    let cover = dir.map(Cover::open).transpose()?;
    Ok(Answers { cover, quiet })
}

/// A client's request, read and checked as an upgrade: its key, and the
/// bytes that came after it. A visit to a listener with a cover gets its
/// page here, as a refusal does: an answer, and no session.
async fn asked(client: &mut End, answers: &Answers) -> Result<(String, Vec<u8>), Refused> {
    let (head, rest) = read_head(client).await?;
    let visited = answers.cover.as_ref().filter(|_| !podssh_ws::server::asks_upgrade(&head));
    if let Some(dir) = visited {
        let (status, answer) = dir.visit(&head).await;
        let line = format!("{}: the cover answered {status}", cover::shown(&head));
        let line = if answers.quiet { String::new() } else { line };
        return Err(Refused { answer: Some(answer), line });
    }
    match podssh_ws::server::check_upgrade(&head) {
        Ok(key) => Ok((key, rest)),
        Err(refused) => {
            let line = format!("{}: answered {}", refused.why, refused.status);
            Err(Refused { answer: Some(refused.answer()), line })
        }
    }
}

/// Answer a refused request, close its connection, and say why, unless it
/// has nothing to say.
async fn refused_away(client: &mut End, refused: Refused, prefix: &str, err: &mut dyn Write) {
    if let Some(answer) = &refused.answer {
        close_after(client, answer).await;
    }
    if !refused.line.is_empty() {
        let _ = writeln!(err, "{prefix}: {}", refused.line);
    }
}

/// Answer the upgrade, then the client's end: a session of a server's frames.
async fn answered(mut client: End, key: &str, pending: Vec<u8>) -> std::io::Result<End> {
    client.write.write_all(&podssh_ws::server::switching(key)).await?;
    client.write.flush().await?;
    let End { read, write, .. } = client;
    let session = podssh_ws::server::session(Joined { read, write }, pending, Some(podssh_ws::DEFAULT_IDLE_TIMEOUT));
    Ok(carry(session, SHOWN.to_string()))
}

/// One client of `--keep-listening`: its upgrade, then its session with a
/// new instance of `other`; its lines on stderr after `client N`.
pub async fn client(
    n: u64,
    mut client: End,
    other: Rc<Address>,
    settings: Rc<Settings>,
    answers: Rc<Answers>,
    listener_is_a: bool,
) {
    let prefix = format!("podssh pipe: client {n}");
    let mut err = std::io::stderr();
    let (key, pending) = match asked(&mut client, &answers).await {
        Ok(asked) => asked,
        Err(refused) => return refused_away(&mut client, refused, &prefix, &mut err).await,
    };
    let mut lines = Vec::new();
    let opened = super::open(&other, &settings, &mut lines).await;
    let _ = err.write_all(&lines);
    let other = match opened {
        Ok(end) => end,
        Err(code) => {
            close_after(&mut client, &unopened()).await;
            let _ = writeln!(err, "{prefix}: ended with {code}, and the client heard 502");
            return;
        }
    };
    let ws = match answered(client, &key, pending).await {
        Ok(ws) => ws,
        Err(e) => {
            abandon(other).await;
            let _ = writeln!(err, "{prefix}: the client left before its session opened: {e}");
            return;
        }
    };
    let (a, b) = if listener_is_a { (ws, other) } else { (other, ws) };
    let code = super::report(pump::pump(a, b).await, &prefix, &mut err).await;
    if code != 0 {
        let _ = writeln!(err, "{prefix}: ended with {code}");
    }
}

/// The pipe of one client, the first whose upgrade is good: the listener
/// closes, and its file goes, once it is there. A signal ends the wait as in
/// each pipe that listens.
pub(super) async fn first(
    mut listener: Listener,
    serve: &Serve<'_>,
    settings: &Settings,
    err: &mut dyn Write,
    stop: &mut Interrupt,
) -> i32 {
    let quiet = serve.quiet;
    let (mut client, key, pending) = loop {
        let accepted = {
            let mut say = |line: &str| {
                if !quiet {
                    let _ = writeln!(err, "podssh pipe: {line}");
                }
            };
            tokio::select! {
                accepted = listener.accept(&mut say) => accepted,
                signal = stop.next() => return signal,
            }
        };
        let mut client = match accepted {
            Ok(client) => client,
            Err(e) => {
                let _ = writeln!(err, "podssh pipe: the listener failed: {e}");
                return EX_UNAVAILABLE;
            }
        };
        let got = tokio::select! {
            got = asked(&mut client, &serve.ws) => got,
            signal = stop.next() => return signal,
        };
        match got {
            Ok((key, pending)) => break (client, key, pending),
            Err(refused) => refused_away(&mut client, refused, "podssh pipe", err).await,
        }
    };
    // One client: nobody else connects, and the file goes now.
    drop(listener);
    let opened = tokio::select! {
        opened = super::open(serve.other, settings, err) => opened,
        signal = stop.next() => return signal,
    };
    let other = match opened {
        Ok(end) => end,
        Err(code) => {
            close_after(&mut client, &unopened()).await;
            return code;
        }
    };
    let ws = match answered(client, &key, pending).await {
        Ok(ws) => ws,
        Err(e) => {
            abandon(other).await;
            let _ = writeln!(err, "podssh pipe: the client left before its session opened: {e}");
            return EX_UNAVAILABLE;
        }
    };
    let (a, b) = if serve.listener_is_a { (ws, other) } else { (other, ws) };
    let pumped = tokio::select! {
        pumped = pump::pump(a, b) => pumped,
        signal = stop.next() => return signal,
    };
    super::report(pumped, "podssh pipe", err).await
}
