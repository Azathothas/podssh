//! ⛔ **C4 live proof: a real forward session against the live relay.**
//!
//! Mint, use, discard in one shell — the token arrives by environment
//! (`PODSSH_RELAY_TOKEN`), never by argv, and is never printed. The bundle
//! is a `--bundle` file argument because the target host's trust store is
//! E05's unprobed `UNKNOWN`; this example names its file rather than
//! assuming one.
//!
//! What it proves: the upgrade completes with a self-minted token, and the
//! first bytes off `github.com:22` are the SSH banner — the forward path
//! carries bytes end to end with no SSH state machine on this side.
//!
//! ```sh
//! # one shell: mint, use, discard. The command holds no secret; only the
//! # response does, and it is never displayed.
//! export PODSSH_RELAY_TOKEN="$(curl -sS -X POST https://tcp.ssh.relay.ajam.dev/v1/mint -H 'Content-Type: application/json' -d '{}' | python -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
//! cargo run -p podssh-transport --example live_forward -- --bundle /path/to/ca-bundle.crt
//! unset PODSSH_RELAY_TOKEN
//! ```

use std::time::Duration;

use podssh_transport::forward::ForwardRunner;
use podssh_transport::socket::WsSocket;
use podssh_transport::transport::Limits;
use podssh_ws::client::{Endpoint, WsClientConfig};
use podssh_ws::{ProxyChoice, Trust};

const RELAY_HOST: &str = "tcp.ssh.relay.ajam.dev";
const RELAY_PORT: u16 = 443;
const TIMEOUT: Duration = Duration::from_secs(20);

fn usage() -> ! {
    eprintln!("usage: live_forward [--bundle <ca-pem>] [--target <host> --port <n>]");
    eprintln!("  token arrives by env PODSSH_RELAY_TOKEN, never by argv.");
    std::process::exit(64);
}

#[tokio::main]
async fn main() {
    let mut bundle: Option<String> = None;
    let mut target = "github.com".to_string();
    let mut port: u16 = 22;
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--bundle" => bundle = argv.next(),
            "--target" => {
                target = argv.next().unwrap_or_else(|| usage());
            }
            "--port" => {
                port = argv
                    .next()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            _ => usage(),
        }
    }
    // Without --bundle the default trust store is used (system bundle plus
    // the compiled-in roots); HTTPS_PROXY is honoured either way.
    let trust = match bundle {
        Some(path) => Trust::File(std::path::PathBuf::from(path)),
        None => Trust::Default,
    };

    // ⛔ The token is read, never displayed: mint, use, discard in one shell.
    let token = std::env::var("PODSSH_RELAY_TOKEN").unwrap_or_else(|_| {
        eprintln!("podssh: live_forward needs PODSSH_RELAY_TOKEN in the environment.");
        std::process::exit(64);
    });
    if token.is_empty() {
        eprintln!("podssh: PODSSH_RELAY_TOKEN is empty.");
        std::process::exit(64);
    }

    let config = WsClientConfig {
        endpoint: Endpoint {
            host: RELAY_HOST.to_string(),
            port: RELAY_PORT,
            path: format!("/connect/{target}/{port}"),
        },
        trust,
        server_name: RELAY_HOST.to_string(),
        timeout: TIMEOUT,
        idle_timeout: Some(podssh_ws::DEFAULT_IDLE_TIMEOUT),
        proxy: ProxyChoice::FromEnvironment,
    };
    let session = podssh_ws::client::connect(&config, &token)
        .await
        .unwrap_or_else(|e| {
            eprintln!("podssh: forward upgrade failed: {e}");
            std::process::exit(69);
        });

    let socket = WsSocket::new(session, Limits::forward(262144));
    let mut runner = ForwardRunner::new(socket, Limits::forward(262144));
    let banner = tokio::time::timeout(TIMEOUT, runner.recv_bytes())
        .await
        .unwrap_or_else(|_| {
            eprintln!("podssh: no banner within {TIMEOUT:?}.");
            std::process::exit(70);
        })
        .unwrap_or_else(|e| {
            eprintln!("podssh: forward read failed: {e:?}");
            std::process::exit(70);
        });

    // ⛔ Only the first line is printed, and a banner is the server's version
    // string — public, not a credential. Anything else is a length.
    let first = banner.split(|b| *b == b'\n').next().unwrap_or(&[]);
    let text = String::from_utf8_lossy(first);
    println!("banner-bytes={} first-line={text}", banner.len());
    if text.starts_with("SSH-2.0-") {
        println!("BANNER-OK");
    } else {
        eprintln!("podssh: first bytes are not an SSH banner.");
        std::process::exit(70);
    }
}
