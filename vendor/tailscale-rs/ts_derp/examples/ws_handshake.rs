//! M3 — live DERP-over-WebSocket handshake probe.
//!
//! Proves the WebSocket transport against a real relay without a tailnet and
//! without admission. A fresh, unallowlisted node key is sent; the relay
//! parses the ClientInfo JSON, fails admission and refuses the connection
//! with WebSocket close code 1008, reason "not authorized". Reaching that
//! refusal proves the upgrade, the `Sec-WebSocket-Protocol: derp`
//! negotiation, the DERP framing and the ClientInfo JSON all worked — the
//! relay reads that JSON before it decides. Admission stays the only gate.
//!
//! With `--no-subprotocol` the upgrade omits the subprotocol and the relay
//! must answer HTTP 426; that is the negative control proving the subprotocol
//! is what gets the first probe past the edge.
//!
//! Exit codes: 0 the expected outcome was observed; 1 a different outcome
//! (a failure of the thing this proves); 3 `????` inconclusive — the relay is
//! paused (503), rate limiting (429), or no outcome arrived in time; 64 bad
//! usage.

use std::pin::Pin;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite;
use ts_derp::ws;
use ts_derp::{Client, Error};
use ts_keys::NodeKeyPair;

const DEFAULT_HOST: &str = "tcp.ts.relay.ajam.dev";
const DEFAULT_PORT: u16 = 443;
const TIMEOUT: Duration = Duration::from_secs(30);

/// The ServerKey magic: "DERP" followed by U+1F511 (4 UTF-8 bytes), 8 in all.
const MAGIC: &[u8] = b"DERP\xf0\x9f\x94\x91";

#[tokio::main]
async fn main() -> ExitCode {
    let mut host = DEFAULT_HOST.to_owned();
    let mut port = DEFAULT_PORT;
    let mut subprotocol: Option<&str> = Some(ws::SUBPROTOCOL);

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => match args.next() {
                Some(value) => host = value,
                None => return usage("--host needs a value"),
            },
            "--port" => match args.next().map(|value| value.parse::<u16>()) {
                Some(Ok(value)) => port = value,
                Some(Err(e)) => return usage(&format!("--port: {e}")),
                None => return usage("--port needs a value"),
            },
            "--no-subprotocol" => subprotocol = None,
            "--help" | "-h" => {
                println!("usage: ws_handshake [--host HOST] [--port PORT] [--no-subprotocol]");
                return ExitCode::SUCCESS;
            }
            other => return usage(&format!("unknown argument {other:?}")),
        }
    }

    println!("== M3: DERP over WebSocket handshake ==");
    println!("host: {host}:{port}");
    match subprotocol {
        Some(sp) => println!("subprotocol: {sp}"),
        None => println!("subprotocol: (none; negative control)"),
    }

    let keypair = NodeKeyPair::random();
    println!("node key (fresh, unallowlisted): {}", keypair.public);

    // The probe reads through this tap so the ServerKey frame can be reported
    // from the bytes that actually crossed the wire.
    let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

    let started = tokio::time::Instant::now();
    let attempt = tokio::time::timeout(TIMEOUT, async {
        let conn = ws::connect_with_subprotocol(&host, port, subprotocol).await?;
        println!("websocket: upgrade complete (HTTP 101)");
        let conn = TapIo::new(conn, Arc::clone(&seen));
        Client::handshake(conn, &keypair).await
    })
    .await;
    let elapsed = started.elapsed();

    let observed = seen.lock().expect("tap lock").clone();
    let server_key_ok = report_server_key(&observed);

    match attempt {
        Err(_) => {
            println!("???? no outcome within {TIMEOUT:?}");
            ExitCode::from(3)
        }
        Ok(Ok(_client)) => {
            println!("UNEXPECTED: the handshake succeeded; a fresh key cannot be allowlisted");
            ExitCode::FAILURE
        }
        Ok(Err(err)) => match (subprotocol, err) {
            (None, Error::WebSocket(tungstenite::Error::Http(response))) => {
                let status = response.status().as_u16();
                println!("websocket handshake refused: HTTP {status}");
                if status == 426 {
                    println!("PASS: without the derp subprotocol the relay refuses the upgrade with 426");
                    ExitCode::SUCCESS
                } else if status == 429 || status == 503 {
                    println!("???? relay returned {status}; inconclusive, not a result");
                    ExitCode::from(3)
                } else {
                    println!("FAIL: expected 426 without the subprotocol, got {status}");
                    ExitCode::FAILURE
                }
            }
            (None, err) => {
                println!("FAIL: expected HTTP 426 without the subprotocol, got: {err}");
                ExitCode::FAILURE
            }
            (Some(_), Error::WebSocket(tungstenite::Error::Http(response))) => {
                let status = response.status().as_u16();
                println!("websocket handshake refused: HTTP {status}");
                if status == 429 || status == 503 {
                    println!("???? relay returned {status}; inconclusive, not a result");
                    ExitCode::from(3)
                } else {
                    println!("FAIL: the upgrade with the derp subprotocol was refused with HTTP {status}");
                    ExitCode::FAILURE
                }
            }
            (Some(_), err) => {
                let text = err.to_string();
                println!("handshake outcome: {text}");

                if !server_key_ok {
                    println!("FAIL: the ServerKey frame was not observed");
                    return ExitCode::FAILURE;
                }
                let refused = text.contains("code=1008") && text.contains("not authorized");
                if refused {
                    println!("PASS: the relay parsed ClientInfo and refused an unallowlisted key with 1008 \"not authorized\"");
                    println!("      the transport, the framing and the JSON compatibility are proven");
                    ExitCode::SUCCESS
                } else if text.contains("code=1008") {
                    println!("FAIL: refused with a 1008 other than \"not authorized\"; the JSON or the sealed box is wrong");
                    println!("      ({} elapsed)", elapsed.as_secs_f32());
                    ExitCode::FAILURE
                } else {
                    println!("FAIL: no 1008 \"not authorized\" refusal");
                    ExitCode::FAILURE
                }
            }
        },
    }
}

/// Check and report the raw ServerKey frame among the bytes the client read.
fn report_server_key(bytes: &[u8]) -> bool {
    if bytes.len() < 45
        || bytes[0] != 0x01
        || bytes[1..5] != [0, 0, 0, 40]
        || &bytes[5..13] != MAGIC
    {
        println!(
            "ServerKey: NOT OBSERVED ({} bytes read before the outcome)",
            bytes.len()
        );
        return false;
    }

    let key = &bytes[13..45];
    println!("ServerKey: magic OK (0x01, len=40, \"DERP\"+U+1F511)");
    println!("ServerKey: relay pubkey prefix {}", hex::encode(&key[..8]));
    println!("ServerKey: relay pubkey {}", hex::encode(key));
    true
}

fn usage(message: &str) -> ExitCode {
    eprintln!("ws_handshake: {message}");
    eprintln!("usage: ws_handshake [--host HOST] [--port PORT] [--no-subprotocol]");
    ExitCode::from(64)
}

/// Passes reads and writes through to a [`ws::WsIo`] and records the bytes read.
struct TapIo {
    inner: ws::WsIo,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl TapIo {
    fn new(inner: ws::WsIo, seen: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, seen }
    }
}

impl AsyncRead for TapIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                if filled.len() > before {
                    this.seen
                        .lock()
                        .expect("tap lock")
                        .extend_from_slice(&filled[before..]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for TapIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
