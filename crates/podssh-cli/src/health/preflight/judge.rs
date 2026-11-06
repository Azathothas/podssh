//! The verdicts of the preflight (T-482) on what each probe found, as
//! `doctor` gives its own: a fact that podssh is built for is `ok` with the
//! fact, `FAIL` is kept for what stops a command of podssh, which the line
//! names with the way round where there is one, and `????` for what could
//! not be read. Each is a function of its answer alone, so that a test
//! gives it each answer.

use podssh_relay::pool::Limits;
use podssh_relay::relay;
use podssh_ssh::preflight::{Answer, Forward, Jump, SftpFacts, JUMP_PORT, KEEPALIVE, LOOPBACK};
use podssh_ssh::russh::ChannelOpenFailure;
use podssh_ssh::sftp::SftpError;
use podssh_ws::Verdict;

use super::super::cgroup;
use super::super::parse::Facts;
use super::super::show;
use super::Road;

/// The extensions of SFTP that `cp` uses, and what it does without each.
#[rustfmt::skip]
pub const EXTENSIONS: &[(&str, &str)] = &[
    ("copy-data", "cp --delta makes its file with a command of sh, and a copy from the host to itself comes through this host"),
    ("posix-rename@openssh.com", "cp removes an old file before its rename, which is then not atomic"),
    ("hardlink@openssh.com", "cp -r copies each name of a linked file as a file"),
    ("limits@openssh.com", "cp reads and writes 32 KiB at a time"),
];

/// What `-J`, `-L`, `-D` and `-W` through this host need.
const JUMPS: &str = "-J, -L, -D and -W through this host";

pub(super) fn ok(detail: impl Into<String>) -> Verdict {
    Verdict::Ok { detail: detail.into() }
}

pub(super) fn fail(detail: impl Into<String>) -> Verdict {
    Verdict::Failed { detail: detail.into() }
}

pub(super) fn unknown(why: impl Into<String>) -> Verdict {
    Verdict::Unknown { why: why.into() }
}

/// The login: who, through which hops, by which method, and the server's
/// version line.
pub fn login(destination: &str, hops: &[String], version: Option<&str>, method: Option<&str>) -> Verdict {
    let by = match method {
        Some("none") => " with no method: the server asked for none".to_string(),
        Some(method) => format!(" by {method}"),
        None => String::new(),
    };
    let through = if hops.is_empty() { String::new() } else { format!(", through -J {}", hops.join(",")) };
    let server = match version {
        Some(version) => format!("; the server's version: {version}"),
        None => "; the server's version line was not kept".to_string(),
    };
    ok(format!("{destination}{by}{through}{server}"))
}

/// Seconds as a person reads a limit: 180 s, 12 h.
fn seconds(s: u64) -> String {
    if s >= 3600 && s.is_multiple_of(3600) {
        format!("{} h", s / 3600)
    } else {
        format!("{s} s")
    }
}

/// The road and the limits on its session: the relay's, from its
/// `/relays.json` where one was read (T-342), else the built-in ones.
pub fn road(road: &Road, relay_host: Option<&str>, limits: &Limits) -> Verdict {
    if !road.relay {
        let through = if road.proxy { ", through HTTPS_PROXY" } else { "" };
        return ok(format!("{}{through}: not the relay, so none of its limits on a session", road.name));
    }
    let bytes = limits.max_session_bytes.unwrap_or(relay::session_byte_cap());
    let idle = limits.idle_timeout_ms.map_or(relay::relay_idle_secs(), |ms| ms / 1000);
    let most = limits.max_session_ms.map_or(relay::session_time_cap().as_secs(), |ms| ms / 1000);
    let read = limits.max_session_bytes.or(limits.idle_timeout_ms).or(limits.max_session_ms).is_some();
    let from = if read { "its /relays.json" } else { "podssh's own: no /relays.json was read" };
    let host = relay_host.map(|h| format!(" {h}")).unwrap_or_default();
    ok(format!(
        "the relay{host} ends a session at {} both ways, after {} with no payload, and at {} ({from}): podssh cp \
         copies more on new sessions, and a session of podssh ssh ends there",
        show::size(bytes as f64),
        seconds(idle),
        seconds(most)
    ))
}

/// The SFTP subsystem: its sizes and extensions, and what `cp` does
/// without each that it uses. No subsystem is `ok`, as `cp` then copies by
/// exec; a subsystem that does not answer fails `cp` as it failed here.
pub fn sftp(got: &Result<SftpFacts, SftpError>) -> Verdict {
    match got {
        Ok(facts) => {
            let named: Vec<&str> = facts.extensions.keys().map(String::as_str).collect();
            let named = if named.is_empty() { "none".to_string() } else { named.join(", ") };
            let (read, write) = (show::size(f64::from(facts.read_len)), show::size(f64::from(facts.write_len)));
            let mut detail = format!("version 3, reads of {read} and writes of {write}; extensions: {named}");
            for (name, without) in EXTENSIONS.iter().filter(|(name, _)| !facts.extensions.contains_key(*name)) {
                detail.push_str(&format!("; no {name}: {without}"));
            }
            ok(detail)
        }
        Err(SftpError::NoSftp) => ok("no SFTP subsystem: podssh cp copies by exec, with the tools of exec tools"),
        Err(e) => fail(format!("{e}: podssh cp, mv, sftp and edit fail on this host as the probe did")),
    }
}

/// The remote forward: a refusal, or no answer, is what `-R` gets.
pub fn forward(got: &Answer<Forward>) -> Verdict {
    match got {
        Answer::Came(Forward::Listened { port, cancel }) => {
            let at = if *port == 0 { "a port that it did not name".to_string() } else { format!("port {port}") };
            let stopped = match cancel {
                Answer::Came(true) => "and stopped at the cancel".to_string(),
                Answer::Came(false) => "and refused the cancel: it listens until this connection ends".to_string(),
                Answer::Silent(limit) => format!("and gave no answer to the cancel in {} s", limit.as_secs()),
                Answer::Lost(why) => format!("then, at the cancel: {why}"),
            };
            ok(format!("the server listened on its {LOOPBACK}, {at}, {stopped}: -R works on this host"))
        }
        Answer::Came(Forward::Refused) => fail("the server refused tcpip-forward: -R cannot work on this host"),
        Answer::Silent(limit) => {
            fail(format!("no answer to tcpip-forward in {} s: -R cannot work on this host", limit.as_secs()))
        }
        Answer::Lost(why) => fail(format!("at tcpip-forward: {why}: -R cannot work on this host")),
    }
}

/// The jump: a channel that opened, or one refused as `connect failed`
/// (RFC 4254, section 5.1, tells it from `administratively prohibited`),
/// shows a server that opens such channels, as the target was a guess.
pub fn jump(got: &Answer<Jump>) -> Verdict {
    let target = format!("{LOOPBACK}:{JUMP_PORT}");
    match got {
        Answer::Came(Jump::Opened) => {
            ok(format!("the server opened a direct-tcpip channel to its own {target}: {JUMPS} work"))
        }
        Answer::Came(Jump::Refused(ChannelOpenFailure::ConnectFailed)) => ok(format!(
            "the server opens direct-tcpip channels, and its own {target} refused the connection: {JUMPS} work"
        )),
        Answer::Came(Jump::Refused(
            reason @ (ChannelOpenFailure::AdministrativelyProhibited | ChannelOpenFailure::UnknownChannelType),
        )) => {
            let words = podssh_ssh::unopened::reason_text(reason);
            fail(format!("the server refused a direct-tcpip channel: open failed: {words}: {JUMPS} cannot work"))
        }
        Answer::Came(Jump::Refused(reason)) => {
            let words = podssh_ssh::unopened::reason_text(reason);
            unknown(format!("the server refused a direct-tcpip channel: open failed: {words}; it may open one later"))
        }
        Answer::Silent(limit) => fail(format!(
            "no answer to the open of a direct-tcpip channel in {} s: {JUMPS} cannot work",
            limit.as_secs()
        )),
        Answer::Lost(why) => fail(format!("at the open of a direct-tcpip channel: {why}: {JUMPS} cannot work")),
    }
}

/// The keepalive: a reply, a success or a failure, is `ok` (OpenSSH's
/// sshd answers with a failure); no reply, or a connection that ended at
/// it, is what each idle session of `ssh` meets, with the way round it.
pub fn keepalive(got: &Answer<bool>) -> Verdict {
    let round = "-o ServerAliveInterval=0 turns them off";
    match got {
        Answer::Came(success) => {
            let how = if *success { "a success" } else { "a failure, as OpenSSH's sshd does" };
            ok(format!("the server answered {KEEPALIVE} with {how}: an idle session stays up"))
        }
        Answer::Silent(limit) => fail(format!(
            "no answer to {KEEPALIVE} in {} s: an idle session of podssh ssh ends when its keepalives go \
             unanswered; {round}",
            limit.as_secs()
        )),
        Answer::Lost(why) => {
            fail(format!("at the reply to {KEEPALIVE}: {why}: an idle session of podssh ssh ends so; {round}"))
        }
    }
}

/// The CPUs and the memory to plan from (T-480): a cgroup's where it
/// limits them, else the host's; `????` with no facts.
pub fn cgroup(facts: Result<&Facts, &str>) -> Verdict {
    let facts = match facts {
        Err(why) => return unknown(format!("no facts: {why}")),
        Ok(facts) => facts,
    };
    let Some(e) = cgroup::effective(facts) else {
        let system = facts.system.as_deref().unwrap_or("this system");
        return unknown(format!("no /proc on {system}: no cgroup to read"));
    };
    let cpus = e.cpus.map(|n| format!("{} CPUs ({})", show::count(n), e.cpus_from));
    let kib = |n: u64| show::size(n as f64 * 1024.0);
    let memory = match (e.memory_available_kib, e.memory_total_kib) {
        (Some(room), Some(total)) => Some(format!("{} available of {} ({})", kib(room), kib(total), e.memory_from)),
        (None, Some(total)) => Some(format!("{} at most ({})", kib(total), e.memory_from)),
        _ => None,
    };
    let both = [cpus, memory].into_iter().flatten().collect::<Vec<_>>().join(", ");
    if both.is_empty() {
        return unknown("the facts name no CPUs and no memory");
    }
    if e.cpus_limited() || e.memory_limited() {
        ok(format!("the cgroup leaves {both}: plan a build or podssh cp --parallel to these"))
    } else {
        ok(format!("no cgroup limits this shell: the host's {both}"))
    }
}
