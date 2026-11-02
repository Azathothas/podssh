//! The stream to the first hop through the second proxy of `--via`
//! (T-439), with `ConnectionAttempts` as `--direct` takes them: each try
//! says why it failed as it comes, and a refusal of the proxy's (403, 407)
//! or a setting that cannot work ends the tries.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::via::{Opened, Version};
use podssh_ws::DialError;

use super::Road;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::ssh::transport::{NotReached, Reached};

/// The stream to `host:port` through `road`, in at most `rounds` tries.
pub async fn reach(road: &Road, host: &str, port: u16, rounds: u32, log: &Arc<Log>) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: EX_UNAVAILABLE });
    }
    let target = podssh_ws::dial::authority(host, port);
    let (client, shown) = (super::client(road), road.shown());
    let rounds = rounds.max(1);
    let mut code = EX_UNAVAILABLE;
    for round in 1..=rounds {
        if round > 1 {
            let wait = podssh_relay::open::backoff(round - 1);
            log.info(&format!("retrying in {:.1} s (attempt {round} of {rounds})", wait.as_secs_f32()));
            tokio::time::sleep(wait).await;
        }
        log.verbose(&format!("connecting to {target} through the second proxy {shown}"));
        match client.open(host, port).await {
            Ok(opened) => {
                log.verbose(&carried(&opened, &shown, &target));
                // A write that makes no progress fails as on the relay leg,
                // never a wait for ever (T-227).
                let stream = podssh_ws::write_limit::WriteLimit::new(opened.stream, podssh_ws::client::WRITE_TIMEOUT);
                return Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: None });
            }
            Err(e) => {
                log.error(&format!("could not connect to {target}: {e}"));
                code = exit_code(&e);
                // The proxy's answer, or a setting, is the same at each try.
                if code != EX_UNAVAILABLE {
                    break;
                }
            }
        }
    }
    Err(NotReached { lines: Vec::new(), code })
}

/// The line of a tunnel: the proxy, the target, and how HTTP carries it.
pub fn carried(opened: &Opened, shown: &str, target: &str) -> String {
    let how = match (opened.version, opened.shared, &opened.fell_back) {
        (Version::Http2, true, _) => "HTTP/2, a new stream on the connection that an earlier tunnel opened".to_string(),
        (Version::Http2, false, _) => "HTTP/2, on a connection that later tunnels share".to_string(),
        (Version::Http1, _, Some(why)) => format!("HTTP/1.1, as {why}"),
        (Version::Http1, _, None) => "HTTP/1.1".to_string(),
    };
    format!("the second proxy {shown} carries the session to {target} over {how}")
}

/// The exit code of a tunnel that did not open, as `proxy` exits: 78 for
/// a setting, 77 for the proxy's refusal (403, 407), else 69.
pub fn exit_code(e: &DialError) -> i32 {
    match e {
        DialError::BadProxy(_) | DialError::InvalidTarget(_) => EX_CONFIG,
        DialError::ProxyRefused { status: 403 | 407, .. } => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_of_the_proxy_is_77_and_a_setting_78() {
        let refused = |status| DialError::ProxyRefused {
            proxy: "https://p.example:443".into(),
            target: "h:22".into(),
            status,
            reason: "no".into(),
        };
        assert_eq!(exit_code(&refused(407)), EX_NOPERM);
        assert_eq!(exit_code(&refused(403)), EX_NOPERM);
        assert_eq!(exit_code(&refused(502)), EX_UNAVAILABLE);
        assert_eq!(exit_code(&DialError::BadProxy("x".into())), EX_CONFIG);
    }

    #[test]
    fn the_line_names_the_proxy_the_target_and_the_version() {
        let opened = |version, shared, fell_back| Opened {
            stream: Box::new(tokio::io::duplex(8).0),
            version,
            shared,
            fell_back,
        };
        let line = carried(&opened(Version::Http2, true, None), "https://p.example:443", "h:22");
        assert_eq!(
            line,
            "the second proxy https://p.example:443 carries the session to h:22 over HTTP/2, a new stream on the \
             connection that an earlier tunnel opened"
        );
        let back = carried(&opened(Version::Http1, false, Some("HTTP/2 did not carry the CONNECT".into())), "p", "h");
        assert!(back.ends_with("over HTTP/1.1, as HTTP/2 did not carry the CONNECT"), "{back}");
    }
}
