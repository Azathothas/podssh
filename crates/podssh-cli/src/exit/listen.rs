//! The local proxy of `podssh exit` (T-431): one port for SOCKS5, SOCKS4a
//! and HTTP CONNECT, told apart by the client's first byte (4 or 5 is
//! SOCKS, as each request of HTTP starts with a letter). SOCKS is read as
//! `-D` reads it (`podssh_ssh::socks`), CONNECT as `podssh pipe
//! http-listen:` reads it (`podssh_ws::http::request`); then the exit's
//! session opens with the client's target, and only once the node reached
//! it does the client hear its success: else the refusal of its protocol,
//! by the kind of the node's refusal. A refused client is closed.

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::socks;
use podssh_ws::http::request::{self, RequestError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use super::open::{open, Kind, To};
use crate::exitmap::sysexits;
use crate::pipe::address::Address;
use crate::pipe::listen::Listener;
use crate::pipe::pump::End;

/// The time that a client has to send its request.
const REQUEST_LIMIT: Duration = Duration::from_secs(30);
/// The clients at once, as `http-listen:` takes them: a program opens
/// several connections at a time.
const AT_ONCE: usize = 32;

/// Listen on `at`, and serve each client until Ctrl-C or SIGTERM (0), or
/// until the listener fails; over a carrier, the node hears the end.
pub async fn serve(to: To, at: Address) -> i32 {
    let code = Box::pin(proxy(to, at)).await;
    // The carrier's node hears a Close 1000, and its program ends (T-596).
    crate::carrier::end_shared().await;
    code
}

/// The proxy of [`serve`], until its end.
async fn proxy(to: To, at: Address) -> i32 {
    let mut say = |line: &str| podssh_ssh::err_line!("podssh exit: {line}");
    let mut listener = match Listener::bind(&at, &mut say).await {
        Ok(listener) => listener,
        Err((code, line)) => {
            say(&line);
            return code;
        }
    };
    // The carrier's role at once (T-596): the node's first frame waits for
    // it, and a node that hears nothing for 30 s drops the stream.
    let carrier = match to.carrier.as_deref().map(crate::carrier::shared).transpose() {
        Ok(carrier) => carrier,
        Err(refusal) => {
            say(&refusal.message);
            return refusal.code;
        }
    };
    if let Some(addr) = listener.local_addr() {
        let over = to.carrier.as_deref().map(|text| format!(" over the carrier {text}")).unwrap_or_default();
        let exit = match super::auto::is_auto(&to.name) {
            true => "the exit whose route of the net holds each target's address (--exit auto)".to_string(),
            false => format!("the exit {}", to.name),
        };
        say(&format!(
            "a SOCKS5 and HTTP CONNECT proxy on {addr}, whose connections start at {exit}{over}: a program reaches \
             it with ALL_PROXY=socks5h://{addr} or HTTPS_PROXY=http://{addr}, until Ctrl-C"
        ));
    }
    let (to, room) = (Arc::new(to), Arc::new(Semaphore::new(AT_ONCE)));
    let mut n: u64 = 0;
    loop {
        let Ok(permit) = room.clone().acquire_owned().await else { return crate::exit_codes::EXIT_SOFTWARE };
        let accepted = tokio::select! {
            accepted = listener.accept(&mut say) => Some(accepted),
            () = crate::node::stop_signal() => return 0,
            // A stream of stdio or fd:N has one life: its node left, so no
            // connection could start at the exit again.
            () = left(carrier.as_deref()) => None,
        };
        let Some(accepted) = accepted else {
            say("the carrier's stream ended: its node left, so this proxy ends with it");
            return 0;
        };
        match accepted {
            Ok(end) => {
                n += 1;
                let to = to.clone();
                tokio::spawn(async move {
                    client(n, end, &to).await;
                    drop(permit);
                });
            }
            Err(e) => {
                say(&format!("the listener failed: {e}"));
                return sysexits::EX_UNAVAILABLE;
            }
        }
    }
}

/// Until the node of a carrier with one life left it; never with no
/// carrier.
async fn left(carrier: Option<&crate::carrier::Client>) {
    match carrier {
        Some(client) => client.left().await,
        None => std::future::pending().await,
    }
}

/// One client: its request, the exit's session, then the bytes both ways.
async fn client(n: u64, mut end: End, to: &To) {
    let prefix = format!("podssh exit: client {n}");
    let mut first = [0u8; 1];
    match tokio::time::timeout(REQUEST_LIMIT, end.read.read(&mut first)).await {
        Ok(Ok(1)) => {}
        _ => return podssh_ssh::err_line!("{prefix}: left with no request"),
    }
    let opened = match first[0] {
        4 | 5 => from_socks(&mut end, first[0], to, &prefix).await,
        _ => from_connect(&mut end, first[0], to, &prefix).await,
    };
    let Some((target, exit)) = opened else { return };
    if !to.quiet {
        match super::auto::is_auto(&to.name) {
            true => podssh_ssh::err_line!("{prefix}: {target} through the exit that its address picked"),
            false => podssh_ssh::err_line!("{prefix}: {target} through the exit {}", to.name),
        }
    }
    let pumped = crate::pipe::pump::pump(end, exit).await;
    // The exit's end says why a session ended badly; a clean end, nothing.
    if let Some(ending) = pumped.b.ending {
        for line in ending.finish().await.map(|(_, lines)| lines).unwrap_or_default() {
            podssh_ssh::err_line!("{prefix}: {target}: {line}");
        }
    }
}

/// A SOCKS client: its request, the exit's session, then its answer.
async fn from_socks(client: &mut End, first: u8, to: &To, prefix: &str) -> Option<(String, End)> {
    let head = [first];
    let asked = {
        let mut read = (&head[..]).chain(&mut client.read);
        tokio::time::timeout(REQUEST_LIMIT, socks::read_request(&mut read, &mut client.write)).await
    };
    let asked = match asked {
        Ok(Ok(asked)) => asked,
        Ok(Err(why)) => return said(prefix, &format!("not a SOCKS request that the exit carries: {why}")),
        Err(_) => return said(prefix, "no whole SOCKS request came within 30 s"),
    };
    let target = podssh_ws::dial::authority(&asked.host, asked.port);
    match open(to, &asked.host, asked.port).await {
        Ok(exit) => {
            socks::answer(&mut client.write, asked.version, Ok(())).await.ok()?;
            Some((target, exit))
        }
        Err(refused) => {
            let why = match refused.kind {
                Kind::NotAllowed => socks::Refusal::NotAllowed,
                Kind::Unreachable => socks::Refusal::Refused,
                Kind::Failed => socks::Refusal::General,
            };
            let _ = socks::answer(&mut client.write, asked.version, Err(why)).await;
            said(prefix, &format!("{target}: {}", refused.line))
        }
    }
}

/// An HTTP client: its CONNECT, the exit's session, then its answer; the
/// bytes that came after the request go first to the exit.
async fn from_connect(client: &mut End, first: u8, to: &To, prefix: &str) -> Option<(String, End)> {
    let read = tokio::time::timeout(REQUEST_LIMIT, request::read_request(&mut client.read, vec![first])).await;
    let (head, rest) = match read {
        Err(_) => return refuse(client, 408, "no request came within 30 s", prefix).await,
        Ok(Err(RequestError::Gone(why))) => return said(prefix, &format!("left before its request ended: {why}")),
        Ok(Err(e)) => return refuse(client, e.status().unwrap_or(400), &e.to_string(), prefix).await,
        Ok(Ok(read)) => read,
    };
    if !head.method.eq_ignore_ascii_case("CONNECT") {
        let words = format!("{} is not CONNECT: this proxy carries tunnels alone", head.method);
        return refuse(client, 405, &words, prefix).await;
    }
    let (host, port) = match request::connect_target(&head.target) {
        Ok(target) => target,
        Err(why) => return refuse(client, 400, &why, prefix).await,
    };
    let target = podssh_ws::dial::authority(&host, port);
    match open(to, &host, port).await {
        Ok(mut exit) => {
            client.write.write_all(&request::established()).await.ok()?;
            if !rest.is_empty() {
                exit.write.write_all(&rest).await.ok()?;
            }
            Some((target, exit))
        }
        Err(refused) => {
            let status = if refused.kind == Kind::NotAllowed { 403 } else { 502 };
            refuse(client, status, &format!("{target}: {}", refused.line), prefix).await
        }
    }
}

/// Answer `status` with `words`, close the client, and say why.
async fn refuse(client: &mut End, status: u16, words: &str, prefix: &str) -> Option<(String, End)> {
    let allow: &[(&str, &str)] = if status == 405 { &[("Allow", "CONNECT")] } else { &[] };
    let _ = client.write.write_all(&request::refusal(status, words, allow)).await;
    let _ = client.write.shutdown().await;
    said(prefix, &format!("{words}: answered {status}"))
}

/// The client's line, and no session.
fn said(prefix: &str, line: &str) -> Option<(String, End)> {
    podssh_ssh::err_line!("{prefix}: {line}");
    None
}
