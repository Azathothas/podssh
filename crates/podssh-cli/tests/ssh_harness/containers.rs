//! The commands of `podssh containers` (T-190) on the test's server, for a
//! user named `containers-...`: the list's script, answered as `sh` with
//! docker and kubectl on its `PATH` answers it, from their committed lists
//! (`tests/fixtures/containers/`), after a line of the login's own; and each
//! `docker exec`, `podman exec` and `kubectl exec`, answered with the line
//! that it got. The user's name says what the host has:
//! `containers-none-...` no tool, `containers-denied-...` a docker whose
//! socket is refused, `containers-bad-...` a docker that lists `a;b`.

use podssh_cli::containers::list::MARK;
use russh::server::Session;
use russh::ChannelId;

const DOCKER: &str = include_str!("../fixtures/containers/docker-ps.txt");
const KUBECTL: &str = include_str!("../fixtures/containers/kubectl-pods.txt");
const DENIED: &str = include_str!("../fixtures/containers/docker-denied.txt");
const BAD: &str = include_str!("../fixtures/containers/docker-bad.txt");

/// The answer to `command` for the user `user`, when it is one of these;
/// `None` else.
pub(super) fn run(
    user: Option<&str>,
    command: &str,
    channel: ChannelId,
    session: &mut Session,
) -> Option<Result<(), russh::Error>> {
    let user = user?;
    let (out, err) = if command.starts_with("sh -c 'for t in ") && command.contains(MARK) {
        list(user, command)
    } else if ["docker exec ", "podman exec ", "kubectl exec "].iter().any(|p| command.starts_with(p)) {
        (format!("entered: {command}\n"), String::new())
    } else {
        return None;
    };
    let mut sent = session.data(channel, out.into_bytes());
    if !err.is_empty() {
        sent = sent.and_then(|()| session.extended_data(channel, 1, err.into_bytes()));
    }
    let ended = sent
        .and_then(|()| session.exit_status_request(channel, 0))
        .and_then(|()| session.eof(channel))
        .and_then(|()| session.close(channel));
    Some(ended)
}

/// What the script prints on a host of `user`: stdout and stderr. podman is
/// on no host.
fn list(user: &str, command: &str) -> (String, String) {
    let mut out = String::from("Welcome to the test's server\n");
    let mut err = String::new();
    let docker = if user.starts_with("containers-denied-") {
        ("", DENIED, 1)
    } else if user.starts_with("containers-bad-") {
        (BAD, "", 0)
    } else {
        (DOCKER, "", 0)
    };
    if !user.starts_with("containers-none-") {
        for (tool, (names, errors, status)) in [("docker", docker), ("kubectl", (KUBECTL, "", 0))] {
            if !asks(command, tool) {
                continue;
            }
            out.push_str(&format!("{MARK} {tool}\n{names}{MARK} end {tool} {status}\n"));
            err.push_str(&format!("{MARK} {tool}\n{errors}"));
        }
    }
    out.push_str(&format!("{MARK} done\n"));
    (out, err)
}

/// Whether the script's loop names `tool`: `--tool` leaves the others out.
fn asks(command: &str, tool: &str) -> bool {
    command.split("; do ").next().is_some_and(|head| head.split_whitespace().any(|w| w == tool))
}
