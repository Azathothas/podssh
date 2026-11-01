//! The stream to the first hop through the servers of `--shadowsocks`
//! (T-373), each in turn until one carries it. Each server waits for the
//! answer of its first chunk: an SSH server speaks first, so a server that
//! stays silent has refused the key, or a proxy between carries nothing,
//! and the next is tried. Each failure is said as it comes, so the last
//! line is the one that the run ends with.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::shadowsocks::{self, Dial, Ended, OpenError};
use podssh_ws::{DialError, ProxyChoice, Trust};

use super::order::Order;
use super::Servers;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use crate::ssh::cloud::told::Told;
use crate::ssh::transport::{NotReached, Reached};

/// The stream to `host:port` through the first server that carries it.
pub async fn reach(
    servers: &Servers,
    trust: &Trust,
    host: &str,
    port: u16,
    log: &Arc<Log>,
) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: EX_UNAVAILABLE });
    }
    let target = podssh_ws::dial::authority(host, port);
    if let Err(why) = shadowsocks::address(host, port) {
        return Err(NotReached { lines: vec![OpenError::Target(why).line("", &target)], code: EX_USAGE });
    }
    let dial = Dial {
        proxy: &ProxyChoice::FromEnvironment,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        answer: Some(shadowsocks::ANSWER_WAIT),
        silence_is_ready: false,
    };
    let mut order = Order::new(servers, trust);
    let mut code = EX_UNAVAILABLE;
    let said = log.clone();
    let mut say = move |line: &str| said.info(line);
    while let Some(node) = order.next(&mut say).await {
        let shown = node.shown();
        log.verbose(&format!("connecting to {target} through the Shadowsocks server {shown}"));
        match shadowsocks::open(&node, host, port, &dial).await {
            Ok(opened) => {
                log.verbose(&format!("the Shadowsocks server {shown} carries the session to {target}"));
                let status = opened.carried.status.clone();
                let why = move || status.get().map(|end| ended(&shown, &end));
                let stream = Box::new(Told::new(opened.carried.stream, why, log.clone()));
                return Ok(Reached { stream, relay: None, direct_proxy: None, layer: None });
            }
            Err(e) => {
                log.error(&e.line(&shown, &target));
                code = exit_code(&e);
            }
        }
    }
    Err(NotReached { lines: Vec::new(), code })
}

/// The line of a stream that the server ended out of order. Its ordinary
/// end, the target's, says nothing.
pub fn ended(shown: &str, end: &Ended) -> String {
    match end {
        Ended::Chunk(why) | Ended::Failed(why) => format!("the Shadowsocks server {shown}: {why}"),
    }
}

/// The exit code of a server that carried nothing, as `proxy` exits: 78
/// for a setting, 77 for a refusal of the proxy, else 69.
pub fn exit_code(e: &OpenError) -> i32 {
    match e {
        OpenError::Target(_) => EX_USAGE,
        OpenError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) => EX_CONFIG,
        OpenError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_has_the_code_of_proxy_and_an_end_names_the_server() {
        assert_eq!(exit_code(&OpenError::Target("x".into())), EX_USAGE);
        let (proxy, target, reason) = ("p:3128".to_string(), "h:443".to_string(), "no".to_string());
        let refused = DialError::ProxyRefused { proxy, target, status: 403, reason };
        assert_eq!(exit_code(&OpenError::Dial(refused)), EX_NOPERM);
        let silent = OpenError::Silent { ended: None, after: shadowsocks::ANSWER_WAIT, proxy: None };
        assert_eq!(exit_code(&silent), EX_UNAVAILABLE);
        let line = ended("ss://h.example:443", &Ended::Chunk("a chunk of the server's did not open".into()));
        assert_eq!(line, "the Shadowsocks server ss://h.example:443: a chunk of the server's did not open");
    }
}
