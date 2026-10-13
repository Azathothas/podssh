//! The list's script, its parse on the output of docker, podman and kubectl
//! (`tests/fixtures/containers/`, in the formats that `docker ps --format`
//! and `kubectl get pods -o name` give), the check of each name, and the
//! command that enters a container.

use super::*;

const DOCKER: &str = include_str!("../../tests/fixtures/containers/docker-ps.txt");
const PODMAN: &str = include_str!("../../tests/fixtures/containers/podman-ps.txt");
const KUBECTL: &str = include_str!("../../tests/fixtures/containers/kubectl-pods.txt");
const DENIED: &str = include_str!("../../tests/fixtures/containers/docker-denied.txt");
const BAD: &str = include_str!("../../tests/fixtures/containers/docker-bad.txt");

/// What the script prints for each `(tool, list, status)`, after a login's
/// own line.
fn printed(tools: &[(&str, &str, i32)]) -> String {
    let mut out = String::from("Last login: Tue Oct 13 09:00:00 2026\n");
    for (tool, list, status) in tools {
        out.push_str(&format!("{MARK} {tool}\n{list}{MARK} end {tool} {status}\n"));
    }
    out.push_str(&format!("{MARK} done\n"));
    out
}

#[test]
fn the_script_probes_each_tool_and_ends_with_its_mark() {
    let script = script(&Tool::ALL);
    assert!(script.starts_with("for t in docker podman kubectl; do command -v \"$t\""), "{script}");
    assert!(script.contains("kubectl get pods -o name --request-timeout=20s </dev/null"), "{script}");
    assert!(script.contains("\"$t\" ps --format \"{{.Names}}\" </dev/null"), "{script}");
    assert!(script.contains("printf \"%s end %s %s\\n\" podssh-containers \"$t\" \"$?\""), "{script}");
    assert!(script.ends_with("done; printf \"%s done\\n\" podssh-containers"), "{script}");
    assert!(!script.contains(['\'', '\n']), "{script}");
    let one = command(&[Tool::Kubectl]);
    assert!(one.starts_with("sh -c 'for t in kubectl; do ") && one.ends_with('\''), "{one}");
}

#[test]
fn the_parser_reads_the_committed_lists() {
    let stdout = printed(&[("docker", DOCKER, 0), ("podman", PODMAN, 0), ("kubectl", KUBECTL, 0)]);
    let listing = parse(stdout.as_bytes(), b"");
    assert!(listing.whole);
    let names: Vec<(Tool, Vec<&str>)> =
        listing.tools.iter().map(|t| (t.tool, t.names.iter().map(String::as_str).collect())).collect();
    assert_eq!(
        names,
        [
            (Tool::Docker, vec!["web", "db-primary", "cache_1"]),
            (Tool::Podman, vec!["toolbox-41"]),
            (Tool::Kubectl, vec!["pod/api-7d9f8c6b5-x2x9k", "pod/worker-0"]),
        ]
    );
    assert!(listing.tools.iter().all(|t| t.ok() && t.refused.is_empty() && t.errors.is_empty()));
}

#[test]
fn a_tool_that_failed_keeps_its_status_and_its_lines() {
    let stdout = printed(&[("docker", "", 1), ("kubectl", KUBECTL, 0)]);
    let stderr = format!("{MARK} docker\n{DENIED}{MARK} kubectl\n");
    let listing = parse(stdout.as_bytes(), stderr.as_bytes());
    let docker = &listing.tools[0];
    assert_eq!((docker.tool, docker.status, docker.names.len()), (Tool::Docker, Some(1), 0));
    assert_eq!(docker.errors.len(), 1, "{:?}", docker.errors);
    assert!(docker.errors[0].contains("connect: permission denied"), "{:?}", docker.errors);
    assert!(listing.tools[1].ok() && listing.tools[1].errors.is_empty());
}

/// The plant of the entry: with no check of the names, `a;b` would reach a
/// far shell in the command of its line.
#[test]
fn a_name_that_a_shell_would_read_is_left_out() {
    let listing = parse(printed(&[("docker", BAD, 0)]).as_bytes(), b"");
    assert_eq!(listing.tools[0].names, ["web"]);
    assert_eq!(listing.tools[0].refused, ["a;b"]);
    for bad in ["a;b", "$(id)", "`id`", "-rm", ".hidden", "a b", "", "pod/web", "a\u{1b}[2J"] {
        assert!(!valid_name(Tool::Docker, bad), "{bad:?}");
    }
    for bad in ["web", "pod/", "pod/a;b", "pod/-x"] {
        assert!(!valid_name(Tool::Kubectl, bad), "{bad:?}");
    }
    for good in ["web", "db-1.2_x", "0abc"] {
        assert!(valid_name(Tool::Podman, good), "{good:?}");
    }
    assert!(valid_name(Tool::Kubectl, "pod/api-7d9f8c6b5-x2x9k"));
    assert!(!valid_name(Tool::Docker, &"a".repeat(254)));
}

#[test]
fn a_list_that_was_cut_is_not_whole() {
    let stdout = format!("{MARK} docker\nweb\n");
    let listing = parse(stdout.as_bytes(), b"");
    assert!(!listing.whole);
    assert_eq!(listing.tools[0].status, None);
    assert!(!listing.tools[0].ok());
    // No sh ran the script: no mark at all.
    let listing = parse(b"This account is not available.\n", b"");
    assert_eq!(listing, Listing::default());
}

#[test]
fn the_values_of_exec_and_shell_are_checked() {
    for good in ["web", "pod/api-1", "cache_1"] {
        assert!(check_name(good).is_ok(), "{good}");
    }
    for bad in ["a;b", "-x", "pod/", "", "a b", "$(id)"] {
        assert!(check_name(bad).is_err(), "{bad:?}");
    }
    for good in ["sh", "bash", "/bin/ash", "/usr/local/bin/fish-3"] {
        assert!(check_shell(good).is_ok(), "{good}");
    }
    for bad in ["sh -x", "-c", "", "sh;id", "$SHELL"] {
        assert!(check_shell(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_name_is_found_in_each_whole_list_and_entered_with_its_tool() {
    let stdout = printed(&[("docker", "web\n", 0), ("podman", "web\n", 1), ("kubectl", "pod/web\n", 0)]);
    let listing = parse(stdout.as_bytes(), b"");
    let found: Vec<(Tool, String)> = holders(&listing, "web").into_iter().map(|(t, n)| (t.tool, n)).collect();
    // podman failed: its list is not believed.
    assert_eq!(found, [(Tool::Docker, "web".to_string()), (Tool::Kubectl, "pod/web".to_string())]);
    let found: Vec<Tool> = holders(&listing, "pod/web").into_iter().map(|(t, _)| t.tool).collect();
    assert_eq!(found, [Tool::Kubectl]);
    assert!(holders(&listing, "nope").is_empty());
    assert_eq!(enter(Tool::Docker, "web", "sh", true), ["docker", "exec", "-it", "web", "sh"]);
    assert_eq!(enter(Tool::Podman, "web", "/bin/bash", false), ["podman", "exec", "-i", "web", "/bin/bash"]);
    assert_eq!(enter(Tool::Kubectl, "pod/web", "sh", true), ["kubectl", "exec", "-it", "pod/web", "--", "sh"]);
}

#[test]
fn a_word_is_quoted_when_it_is_not_plain() {
    assert_eq!(word("user@example.org:2222"), "user@example.org:2222");
    assert_eq!(word("StrictHostKeyChecking=accept-new"), "StrictHostKeyChecking=accept-new");
    assert_eq!(word("a b"), "'a b'");
    assert_eq!(word(r"C:\keys\id"), r"'C:\keys\id'");
    assert_eq!(word("it's"), r"'it'\''s'");
    assert_eq!(word("~/.ssh/id"), "'~/.ssh/id'");
    assert_eq!(word(""), "''");
    assert_eq!(word("a\nb"), "\"a\\nb\"");
}

#[test]
fn the_shown_command_keeps_the_connection_flags() {
    let ssh = SshArgs {
        port: Some("2222".into()),
        login: Some("me".into()),
        identity_files: vec!["k 1".into()],
        options: vec!["StrictHostKeyChecking=accept-new".into()],
        jump: Some("bastion".into()),
        direct: true,
        ..SshArgs::default()
    };
    let shown = flags(&ssh).join(" ");
    assert_eq!(shown, "-p 2222 -l me -i 'k 1' -o StrictHostKeyChecking=accept-new -J bastion --direct");
    assert!(flags(&SshArgs::default()).is_empty());
    assert_eq!(line(Tool::Docker, "web", 6, "cmd"), "docker   web     cmd");
    assert_eq!(line(Tool::Kubectl, "pod/x", 5, "cmd"), "kubectl  pod/x  cmd");
}
