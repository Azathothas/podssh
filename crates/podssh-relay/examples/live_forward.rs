//! A forward session against the live relay, opened as `podssh ssh` opens
//! one (`podssh_relay::open`): the token comes from the environment, the
//! cache or a mint, and is never printed. The first bytes of `github.com:22`
//! are its SSH banner, carried end to end with no SSH on this side.
//!
//! ```sh
//! cargo run -p podssh-relay --example live_forward -- [--ca-file FILE] [--target HOST --port N]
//! ```

use std::time::Duration;

use podssh_relay::open::Request;
use podssh_relay::relay::{self, forward_path};
use podssh_ws::frame;
use podssh_ws::Trust;

const TIMEOUT: Duration = Duration::from_secs(20);

fn usage() -> ! {
    eprintln!("usage: live_forward [--ca-file FILE] [--target HOST --port N]");
    std::process::exit(64);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut ca_file: Option<String> = None;
    let mut target = "github.com".to_string();
    let mut port: u16 = 22;
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--ca-file" => ca_file = Some(argv.next().unwrap_or_else(|| usage())),
            "--target" => target = argv.next().unwrap_or_else(|| usage()),
            "--port" => port = argv.next().and_then(|p| p.parse().ok()).unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }
    let trust = match ca_file {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    let pool = podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST);
    let relays = relay::select_relays(None, std::env::var(relay::RELAY_ENV).ok(), &pool).unwrap_or_else(|why| {
        eprintln!("podssh: {}: {why}", relay::RELAY_ENV);
        std::process::exit(64);
    });
    let path = forward_path(&target, port).unwrap_or_else(|why| {
        eprintln!("podssh: {why}");
        std::process::exit(64);
    });
    let shown = podssh_ws::dial::authority(&target, port);
    let request = Request { relays: &relays, path: &path, trust: &trust, target: &shown, rounds: 1 };
    let opened = podssh_relay::open(&request, &mut |note: &str| eprintln!("podssh: {note}")).await.unwrap_or_else(|failure| {
        for line in failure.lines(&shown) {
            eprintln!("podssh: {line}");
        }
        std::process::exit(69);
    });

    // The first bytes; the relay's empty keepalive frames carry none.
    let banner = loop {
        let read = tokio::time::timeout(TIMEOUT, opened.session.read_frame()).await;
        match read {
            Ok(Ok(f)) if f.opcode == frame::OPCODE_BINARY && !f.payload.is_empty() => break f.payload,
            Ok(Ok(f)) if f.opcode == frame::OPCODE_CLOSE => {
                let (code, reason) = podssh_ws::session::close_code_and_reason(&f.payload);
                eprintln!("podssh: the relay closed the session: {} {reason}", code.unwrap_or(1005));
                std::process::exit(69);
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                eprintln!("podssh: the session failed: {e}");
                std::process::exit(70);
            }
            Err(_) => {
                eprintln!("podssh: no bytes within {} s", TIMEOUT.as_secs());
                std::process::exit(70);
            }
        }
    };
    // The first line only: a server's version string is public.
    let first = banner.split(|b| *b == b'\n').next().unwrap_or(&[]);
    let text = String::from_utf8_lossy(first);
    println!("from {}: banner-bytes={} first-line={}", opened.relay.host, banner.len(), text.trim_end());
    let _ = opened.session.send_close(1000, "").await;
    if !text.starts_with("SSH-2.0-") {
        eprintln!("podssh: the first bytes are not an SSH banner");
        std::process::exit(70);
    }
    println!("BANNER-OK");
}
