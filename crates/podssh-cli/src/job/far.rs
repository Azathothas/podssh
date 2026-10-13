//! The calls of `podssh job` on the far host (T-193). Each call is one
//! command on a channel with no pty: `sh -c 'INSTALL' sh MARKER ACTION
//! ARG...`, with the far script (`far.sh`) on its stdin. The login shell,
//! POSIX or not, only starts `sh`, and each word is one quoted word, as for
//! the copy by exec of `cp`. [`INSTALL`] keeps the script as
//! `~/.podssh/jobs/jobs.sh`, which tmux runs for each job, and runs it
//! there. The answer comes after a random marker, so that text which a login
//! prints first is never read as an answer.

use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::exec::{self, Captured, ExecError};
use podssh_ssh::{Connection, Log};

use crate::cp::byexec::{self, Strip};
use crate::ssh::resolve::Resolved;

/// The far script.
pub const SCRIPT: &str = include_str!("far.sh");

/// What the login shell starts: the script from stdin into a new name, then
/// a rename onto `jobs.sh`, so that a runner of tmux that reads the old file
/// reads it whole; then the script, in its directory. `umask 077` gives the
/// directories mode 0700 and the files 0600.
pub const INSTALL: &str = "umask 077; d=\"$HOME/.podssh/jobs\"; mkdir -p \"$d\" && cd \"$d\" && \
                           cat >\".jobs.$$\" && mv -f \".jobs.$$\" jobs.sh && exec sh ./jobs.sh \"$@\" </dev/null";

/// The longest wait for each step of a call: the channel, the script, each
/// piece of the answer.
pub const STEP_WAIT: Duration = Duration::from_secs(30);

/// What a call keeps of the far stderr, for the message of a failure.
const ERR_CAP: usize = 16 * 1024;
/// The most of an answer that is read, but the output of `log`, which
/// streams.
const MOST: usize = 4 << 20;

/// The command line of a call: ACTION and its words, after a marker.
pub fn command(marker: &str, words: &[&str]) -> Result<String, String> {
    let mut args = vec![marker];
    args.extend_from_slice(words);
    byexec::command(INSTALL, &args)
}

/// A new marker for one call.
fn marker() -> String {
    format!("podssh-{:016x}", rand::random::<u64>())
}

/// The lines of the answer after `marker` in `stdout`; `None` when no
/// marker came, so no POSIX sh ran the script.
pub fn answer_lines(stdout: &[u8], marker: &str) -> Option<Vec<String>> {
    let at = byexec::after_marker(stdout, marker)?;
    Some(String::from_utf8_lossy(&stdout[at..]).lines().map(str::to_string).collect())
}

/// The connection to the host of `resolved`, each hop logged in: the
/// destination's connection is the last. Each failure is said on `log`.
pub(crate) async fn connect(resolved: &Resolved, log: &Arc<Log>) -> Option<Vec<Connection>> {
    let reached = match crate::ssh::transport::reach(resolved, log).await {
        Ok(reached) => reached,
        Err(not) => {
            for line in &not.lines {
                log.error(line);
            }
            return None;
        }
    };
    match podssh_ssh::run::connect_hops(reached.stream, &resolved.options, log).await {
        Ok(handles) => Some(handles),
        Err(e) => {
            log.error(&e.to_string());
            None
        }
    }
}

/// Run ACTION with its words on `handle`, each byte of stdout to `sink`.
async fn run(
    handle: &Connection,
    command: &str,
    sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<Captured, ExecError> {
    let mut sent = false;
    let mut fill = |piece: &mut Vec<u8>| -> std::io::Result<()> {
        if !sent {
            piece.extend_from_slice(SCRIPT.as_bytes());
            sent = true;
        }
        Ok(())
    };
    exec::send(handle, command, STEP_WAIT, ERR_CAP, &mut fill, sink).await
}

/// One call whose answer is a few lines: those lines, or why there are none.
pub(crate) async fn lines(handle: &Connection, host: &str, words: &[&str]) -> Result<Vec<String>, String> {
    let marker = marker();
    let command = command(&marker, words)?;
    let mut stdout = Vec::new();
    let mut keep = |data: &[u8]| -> std::io::Result<()> {
        let room = MOST.saturating_sub(stdout.len());
        stdout.extend_from_slice(&data[..data.len().min(room)]);
        Ok(())
    };
    let got = run(handle, &command, &mut keep).await.map_err(|e| failed(host, &e))?;
    answer_lines(&stdout, &marker).ok_or_else(|| no_answer(host, &got))
}

/// How a call that streams ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Streamed {
    /// Its head came, and the bytes after it went out.
    Out,
    /// Another first line came, which says why there are no bytes.
    Other(String),
}

/// One call whose answer is a line `head`, then bytes, which go to `out` as
/// they come: the output of `log`. Another first line is given back.
pub(crate) async fn stream(
    handle: &Connection,
    host: &str,
    words: &[&str],
    head: &str,
    out: &mut dyn std::io::Write,
) -> Result<Streamed, String> {
    let marker = marker();
    let command = command(&marker, words)?;
    let mut strip = Strip::new(&marker);
    let mut line: Option<Vec<u8>> = Some(Vec::new());
    let mut other: Option<String> = None;
    let mut sink = |data: &[u8]| -> std::io::Result<()> {
        let data = strip.feed(data).map_err(std::io::Error::other)?;
        let rest = match line.as_mut() {
            None => data,
            Some(first) => {
                first.extend_from_slice(&data);
                let Some(end) = first.iter().position(|b| *b == b'\n') else { return Ok(()) };
                let rest = first.split_off(end + 1);
                let said = String::from_utf8_lossy(first).trim_end().to_string();
                line = None;
                if said != head {
                    other = Some(said);
                }
                rest
            }
        };
        // A reader that went away (`podssh job log ... | head`) is not a
        // failure: the rest is read and dropped.
        if other.is_none() {
            let _ = out.write_all(&rest);
        }
        Ok(())
    };
    let got = run(handle, &command, &mut sink).await.map_err(|e| failed(host, &e))?;
    let _ = out.flush();
    if !strip.opened() {
        return Err(no_answer(host, &got));
    }
    match (line, other) {
        // The marker, and no whole line after it.
        (Some(first), _) => Ok(Streamed::Other(String::from_utf8_lossy(&first).trim_end().to_string())),
        (None, Some(said)) => Ok(Streamed::Other(said)),
        (None, None) => Ok(Streamed::Out),
    }
}

/// A call that did not run to its end.
fn failed(host: &str, e: &ExecError) -> String {
    match e {
        ExecError::Refused(_) => format!("{host} runs no command for podssh job ({e}): it needs a shell"),
        _ => format!("{host}: {e}"),
    }
}

/// No marker came: no POSIX sh ran the script, or it could not be kept.
fn no_answer(host: &str, got: &Captured) -> String {
    let said = String::from_utf8_lossy(&got.stderr);
    let first = said.lines().map(str::trim).find(|l| !l.is_empty());
    let mut why = format!(
        "{host} gave no answer to podssh job: it needs a POSIX sh, mkdir, cat and mv, and a home directory that \
         takes ~/.podssh/jobs"
    );
    if let Some(first) = first {
        why.push_str(&format!(" (the host said: {first})"));
    }
    why
}

/// The message of a first line of an answer that says why the call did
/// nothing; `None` for any other line.
pub fn refusal(host: &str, line: &str) -> Option<String> {
    let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
    Some(match word {
        "missing" if rest == "tmux" => format!(
            "{host} has no tmux on PATH; podssh job runs each job in the host's tmux, and starts none without it"
        ),
        "missing" => format!("{host} has no {rest} on PATH, which podssh job needs"),
        "odd-path" => format!(
            "the jobs' directory of {host}, {rest}, holds a ' or a !, which no command line of tmux can carry"
        ),
        "no-job" => format!("{host} has no job {rest}; podssh job list {host} gives each"),
        "failed" => format!("{host}: {rest}"),
        "unknown" => format!("{host} runs another version of the far script of podssh job: it has no {rest}"),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_goes_on_stdin_and_each_word_is_one_quoted_word() {
        let cmd = command("podssh-00", &["start", "0001-abcd1234", "echo 'hi' && sleep 1"]).unwrap();
        assert!(cmd.starts_with("sh -c 'umask 077; "), "{cmd}");
        assert!(cmd.ends_with(r#"sh 'podssh-00' 'start' '0001-abcd1234' 'echo '\''hi'\'' && sleep 1'"#), "{cmd}");
        assert!(command("m", &["start", "x", "a\nb"]).is_err(), "a newline has no word");
        assert!(!INSTALL.contains('\''), "the install goes in single quotes");
    }

    #[test]
    fn an_answer_is_read_after_its_marker_only() {
        let out = b"motd: started\nmissing tmux\npodssh-01\nstarted abcd1234\n";
        assert_eq!(answer_lines(out, "podssh-01"), Some(vec!["started abcd1234".to_string()]));
        assert_eq!(answer_lines(b"started abcd1234\n", "podssh-01"), None);
    }

    #[test]
    fn a_refusal_names_the_host_and_tmux() {
        let why = refusal("web1", "missing tmux").unwrap();
        assert!(why.starts_with("web1 has no tmux on PATH") && why.contains("starts none"), "{why}");
        assert!(refusal("web1", "no-job abcd1234").unwrap().contains("podssh job list web1"));
        assert_eq!(refusal("web1", "started abcd1234"), None);
        assert_eq!(refusal("web1", "end"), None);
    }

    /// The script that the binary holds is the file of the repository: the
    /// shell's syntax of each line is read by the tests that run it.
    #[test]
    fn the_script_names_each_action_of_the_client() {
        for action in ["start | submit)", "job)", "runner)", "list)", "state)", "log)", "files)", "stop)"] {
            assert!(SCRIPT.contains(&format!("\n{action}\n")), "{action}");
        }
        assert!(!SCRIPT.contains('\r'), "a CR breaks dash");
    }
}
