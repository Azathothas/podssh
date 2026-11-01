//! `doctor --hop [USER@]HOST[:PORT]` (T-371): whether a first hop of `-J`
//! is reachable from here as `--direct` reaches it, through `HTTPS_PROXY`
//! when it is set. Three probes: the connection with the server's banner,
//! as T-317 reads it, sampled as the other probes are; the server's host
//! key; and a login with a key made for the check and never written,
//! whose refusal names the methods that the server still offers. An
//! `ssh+tls://` hop (T-372) gets each probe inside TLS checked for its host,
//! with doctor's trust.

use std::time::Duration;

use podssh_ssh::probe::Login;
use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::{Trust, Verdict};
use tokio::net::TcpStream;

use super::net::{no_ssh_banner, PROBE};
use super::samples::{sample, Tried};
use super::Report;

/// The user of the login when the hop names none: a name that no account
/// is likely to have, as the login only asks which methods are offered.
const PROBE_USER: &str = "podssh-doctor";

/// The road to `host`: the proxy of the environment, or none.
fn road(host: &str) -> Result<(ProxyChoice, String), String> {
    match dial::proxy_from_env(host).map_err(|why| format!("the proxy setting cannot be used: {why}"))? {
        Some(proxy) => {
            let shown = proxy.to_string();
            Ok((ProxyChoice::Via(proxy), format!("through {shown}")))
        }
        None => Ok((ProxyChoice::Direct, "with no proxy".to_string())),
    }
}

/// `--hop`: the hop's section alone, after this host's, so that a user who
/// asks about a hop waits for no probe of the relay.
pub(super) fn only(mut report: Report<'_>, text: &str, trust: &Trust) -> i32 {
    report.section("hop");
    if podssh_relay::open::offline() {
        report.unknown("hop", "not attempted: PODSSH_OFFLINE is set");
        return report.finish();
    }
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            runtime.block_on(check(&mut report, text, trust));
            runtime.shutdown_background();
        }
        Err(e) => report.fail("hop", format!("could not start the async runtime: {e}")),
    }
    report.finish()
}

/// Each line of the hop: `hop`, then `hop key` and `hop login` once a
/// server's banner came.
pub(super) async fn check(report: &mut Report<'_>, text: &str, trust: &Trust) {
    let hop = match crate::ssh::hop::parse_hop(text) {
        Ok(hop) => hop,
        Err(why) => return report.fail("hop", format!("--hop {why}")),
    };
    let (host, port) = (hop.host.clone(), hop.port);
    let target = dial::authority(&host, port);
    let (choice, via) = match road(&host) {
        Ok(road) => road,
        Err(why) => return report.fail("hop", format!("{target}: {why}")),
    };
    let choice = &choice;
    let tls = hop.tls.then_some(trust);
    let target = if hop.tls { format!("{}{target}", crate::ssh::hop::TLS_SCHEME) } else { target };
    let Tried { samples, first, error } = sample(PROBE, |bound| dial::dial(&host, port, choice, bound)).await;
    let summary = samples.summary();
    let Some(stream) = first else {
        let why = error.map(|e| e.to_string()).unwrap_or_default();
        let detail = format!("{target} {via}: {why}; {summary}; -J cannot reach this hop from here with --direct");
        return report.sampled("hop", Verdict::Failed { detail }, &samples);
    };
    let stream = match wrapped(stream, &host, tls).await {
        Ok(stream) => stream,
        Err(why) => {
            let detail = format!("{target} {via}: the connection opened, then TLS: {why}; {summary}");
            return report.sampled("hop", Verdict::Failed { detail }, &samples);
        }
    };
    if let Some(why) = no_ssh_banner(stream).await {
        let instead = if hop.tls {
            " inside TLS; a hop of plain SSH is written without ssh+tls://"
        } else {
            ". A proxy that waits for TLS carries no SSH: a hop whose SSH is inside TLS, as stunnel serves it, is \
             written ssh+tls://HOST (T-372), and without --direct the relay carries SSH over HTTPS"
        };
        let detail =
            format!("{target} {via}: the connection opened, then {why}: no SSH server answered{instead}; {summary}");
        return report.sampled("hop", Verdict::Failed { detail }, &samples);
    }
    let detail = format!("{target} {via}: an SSH server answered with its banner; {summary}");
    report.sampled("hop", Verdict::Ok { detail }, &samples);
    let fingerprint = match key(&host, port, choice, tls).await {
        Ok(fingerprint) => {
            report.ok("hop key", format!("{target} presents the host key {fingerprint}"));
            fingerprint
        }
        Err(why) => return report.fail("hop key", format!("{target}: {why}")),
    };
    let user = hop.user.as_deref().unwrap_or(PROBE_USER);
    report.line("hop login", login(&host, port, choice, tls, user, &fingerprint).await);
}

/// A probe's stream: the TCP connection, inside TLS for `host` with
/// `tls`'s trust when the hop is an `ssh+tls://` one.
async fn wrapped(stream: TcpStream, host: &str, tls: Option<&Trust>) -> Result<Probe, String> {
    match tls {
        None => Ok(Box::new(stream)),
        Some(trust) => match podssh_ws::tls_over(stream, host, trust, PROBE).await {
            Ok(tls) => Ok(Box::new(tls)),
            Err(e) => Err(e.to_string()),
        },
    }
}

/// The stream of a probe, TCP or TLS.
type Probe = Box<dyn crate::ssh::transport::Duplex>;

/// The fingerprint of the host key that the hop presents.
async fn key(host: &str, port: u16, choice: &ProxyChoice, tls: Option<&Trust>) -> Result<String, String> {
    let stream = dial::dial(host, port, choice, PROBE).await.map_err(|e| e.to_string())?;
    let stream = wrapped(stream, host, tls).await?;
    let key = podssh_ssh::probe::host_key(stream, PROBE).await?;
    Ok(podssh_ssh::known_hosts::fingerprint(&key))
}

/// A login as `user` with a key made for the check, which the hop is
/// expected to refuse, naming the methods that it still offers.
async fn login(
    host: &str,
    port: u16,
    choice: &ProxyChoice,
    tls: Option<&Trust>,
    user: &str,
    fingerprint: &str,
) -> Verdict {
    let stream = match dial::dial(host, port, choice, PROBE).await {
        Ok(stream) => stream,
        Err(e) => return Verdict::Failed { detail: format!("a second connection failed: {e}") },
    };
    let stream = match wrapped(stream, host, tls).await {
        Ok(stream) => stream,
        Err(why) => return Verdict::Failed { detail: format!("a second connection's TLS: {why}") },
    };
    let outcome =
        podssh_ssh::probe::login(stream, user, &[fingerprint.to_string()], PROBE * 2 + Duration::from_secs(1)).await;
    judge(user, outcome)
}

/// The verdict on the login: a refusal is the expected answer, and names
/// what a user of `-J` can log in with.
fn judge(user: &str, outcome: Result<Login, String>) -> Verdict {
    match outcome {
        Ok(Login::Refused { methods, .. }) if methods.is_empty() => Verdict::Ok {
            detail: format!("as {user}: the server refused a key made for this check, and offers no other method"),
        },
        Ok(Login::Refused { methods, .. }) => Verdict::Ok {
            detail: format!(
                "as {user}: the server refused a key made for this check, and offers {}; a password comes from \
                 SSH_ASKPASS or the terminal, never from the command line",
                methods.join(", ")
            ),
        },
        Ok(Login::Accepted { .. }) => Verdict::Ok {
            detail: format!("as {user}: the server let in a key made for this check, which takes any key"),
        },
        Ok(Login::WrongHostKey { key }) => Verdict::Failed {
            detail: format!(
                "the second connection presented the host key {}, not the first's: something in between answered",
                podssh_ssh::known_hosts::fingerprint(&key)
            ),
        },
        Err(why) => Verdict::Failed { detail: format!("as {user}: {why}") },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_the_methods_and_where_a_password_comes_from() {
        let refused = |methods: &[&str]| {
            judge(
                "tester",
                Ok(Login::Refused { key: test_key(), methods: methods.iter().map(|m| m.to_string()).collect() }),
            )
        };
        match refused(&["publickey", "password"]) {
            Verdict::Ok { detail } => {
                assert!(detail.contains("offers publickey, password"), "{detail}");
                assert!(detail.contains("SSH_ASKPASS"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(refused(&[]), Verdict::Ok { detail } if detail.contains("no other method")));
        assert!(matches!(judge("t", Err("reset".into())), Verdict::Failed { .. }));
    }

    fn test_key() -> russh::keys::PublicKey {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        russh::keys::PublicKey::from_openssh(line).unwrap()
    }
}
