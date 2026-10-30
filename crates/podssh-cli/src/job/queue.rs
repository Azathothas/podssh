//! The queue of `podssh job` (T-197): `submit` queues a command on the far
//! host, where a runner in tmux starts the oldest queued job while fewer
//! jobs run than the slots; `wait` reads the job's state until it ends. The
//! queue lives on the far host, so that the client can stop at any time and
//! needs no listener to wait: each read is a call of its own. No GPU logic
//! and no list of devices: a count of slots is the only limit
//! (`docs/decisions.md`, Q7).

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::{Connection, Log, EXIT_FAILURE};

use super::{far, first_line, list, new_id, now_ms, unexpected};
use crate::ssh::resolve::Resolved;

/// How often `wait` reads the job's state.
pub const POLL: Duration = Duration::from_secs(5);
/// New connections in a row with no answer, after a connection broke,
/// before `wait` gives up.
pub const TRIES: u32 = 5;

/// The host to submit to: the one with the fewest jobs queued or running,
/// the first of the list on a tie. A host that gave no list (`None`) is
/// left out; `None` when none gave one.
pub fn choose(counts: &[Option<usize>]) -> Option<usize> {
    counts.iter().enumerate().filter_map(|(i, c)| c.map(|c| (c, i))).min().map(|(_, i)| i)
}

/// The jobs of a list that hold a place in the queue: queued or running.
pub fn busy(jobs: &[list::Job]) -> usize {
    jobs.iter().filter(|j| j.state == "queued" || j.state == "running").count()
}

/// A line `state STATE STATUS` of the far script: the state, and the
/// status once there is one.
pub fn parse_state(line: &str) -> Option<(String, Option<i32>)> {
    let mut words = line.split_whitespace();
    if words.next()? != "state" {
        return None;
    }
    let state = words.next()?.to_string();
    let status = match words.next()? {
        "-" => None,
        text => Some(text.parse().ok()?),
    };
    Some((state, status))
}

/// Queue `command` on the host of `handle`, with the slots of `--slots`
/// when given: its ID.
pub(crate) async fn submit(
    handle: &Connection,
    host: &str,
    command: &str,
    slots: Option<u32>,
) -> Result<String, String> {
    let id = new_id();
    let name = list::dir_name(now_ms(), &id);
    let slots = slots.map_or_else(|| "-".to_string(), |n| n.to_string());
    let lines = far::lines(handle, host, &["submit", name.as_str(), slots.as_str(), command]).await?;
    let first = first_line(host, &lines)?;
    if first != format!("queued {id}") {
        return Err(unexpected(host, first));
    }
    Ok(id)
}

/// The jobs of the host of `handle` that hold a place in its queue.
pub(crate) async fn count(handle: &Connection, host: &str) -> Result<usize, String> {
    let lines = far::lines(handle, host, &["list"]).await?;
    first_line(host, &lines)?;
    let jobs = list::parse(&lines).ok_or_else(|| format!("{host}: the list of its jobs came cut"))?;
    Ok(busy(&jobs))
}

/// Wait for the job `id`: its state each [`POLL`], over one connection;
/// after a connection broke, a new one, [`TRIES`] in a row at most with no
/// answer. The exit code: the job's status, or 255 for a job that is lost
/// or not there, or a host that does not answer.
pub(crate) async fn wait(resolved: &Resolved, host: &str, id: &str, log: &Arc<Log>) -> i32 {
    let mut tries = 0u32;
    let mut reached = false;
    let mut said = String::new();
    loop {
        if let Some(handles) = far::connect(resolved, log).await {
            reached = true;
            let handle = handles.last().expect("the destination's connection");
            let end = watch(handle, host, id, log, &mut said, &mut tries).await;
            podssh_ssh::run::disconnect_all(&handles).await;
            if let Some(code) = end {
                return code;
            }
        }
        // The first connection decides: a host that never answered is a
        // failure at once, as for each call of podssh job; its words are
        // said already.
        if !reached {
            return EXIT_FAILURE;
        }
        tries += 1;
        if tries > TRIES {
            log.error(&format!("job {id} on {host}: no answer after {TRIES} new connections; the job may still run"));
            return EXIT_FAILURE;
        }
        let pause = podssh_relay::open::backoff(tries);
        log.info(&format!("a new connection to {host} in {:.1} s ({tries} of {TRIES})", pause.as_secs_f64()));
        tokio::time::sleep(pause).await;
    }
}

/// Read the state over `handle` until the job ends: `Some(exit code)`;
/// `None` when the call broke, for a new connection.
async fn watch(
    handle: &Connection,
    host: &str,
    id: &str,
    log: &Log,
    said: &mut String,
    tries: &mut u32,
) -> Option<i32> {
    loop {
        let lines = match far::lines(handle, host, &["state", id]).await {
            Ok(lines) => lines,
            Err(why) => {
                log.info(&why);
                return None;
            }
        };
        *tries = 0;
        let first = match first_line(host, &lines) {
            Ok(first) => first,
            Err(why) => {
                log.error(&why);
                return Some(EXIT_FAILURE);
            }
        };
        let Some((state, status)) = parse_state(first) else {
            log.error(&unexpected(host, first));
            return Some(EXIT_FAILURE);
        };
        match (state.as_str(), status) {
            ("done", Some(code)) => return Some(code.clamp(0, 255)),
            ("lost", _) => {
                log.error(&format!(
                    "job {id} on {host} is lost: neither its tmux session nor its status is there, as after a \
                     restart of the host"
                ));
                return Some(EXIT_FAILURE);
            }
            _ => {}
        }
        if *said != state {
            log.verbose(&format!("job {id} on {host} is {state}"));
            *said = state;
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str, state: &str) -> list::Job {
        list::Job { id: id.into(), started_ms: 1, state: state.into(), status: None, command: "x".into() }
    }

    /// The choice of the host from the counts of each host: the fewest
    /// queued and running, the first on a tie, and none that gave no list.
    #[test]
    fn the_host_with_the_fewest_jobs_in_its_queue_is_chosen() {
        assert_eq!(choose(&[Some(3), Some(1), Some(2)]), Some(1));
        assert_eq!(choose(&[Some(2), Some(2)]), Some(0), "the first on a tie");
        assert_eq!(choose(&[None, Some(5)]), Some(1), "a host that gave no list is left out");
        assert_eq!(choose(&[None, None]), None);
        assert_eq!(choose(&[]), None);
        let jobs = [job("a", "queued"), job("b", "running"), job("c", "done"), job("d", "lost")];
        assert_eq!(busy(&jobs), 2, "done and lost hold no place");
    }

    #[test]
    fn a_state_line_gives_the_state_and_the_status() {
        assert_eq!(parse_state("state done 5"), Some(("done".into(), Some(5))));
        assert_eq!(parse_state("state queued -"), Some(("queued".into(), None)));
        assert_eq!(parse_state("state done x"), None);
        assert_eq!(parse_state("no-job abcd1234"), None);
    }
}
