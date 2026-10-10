//! `-A`, `-a` and `ForwardAgent` (T-036), and the variables of the agent
//! keywords, resolved as OpenSSH 10.3p1 reads them (measured with its
//! `ssh -G`), without touching the network.

use std::path::PathBuf;

use podssh_cli::ssh::args::SshArgs;
use podssh_cli::ssh::dump;
use podssh_cli::ssh::resolve::{resolve, resolve_or_refuse, Env, Resolved};
use podssh_cli::tree::{parse, Parsed};
use podssh_ssh::Agent;

/// A variable that no machine sets.
const UNSET: &str = "PODSSH_TEST_NEVER_SET_036";

fn ssh(words: &[&str]) -> SshArgs {
    let argv: Vec<std::ffi::OsString> = std::iter::once("ssh").chain(words.iter().copied()).map(Into::into).collect();
    match parse(argv) {
        Parsed::Command { verb: "ssh", ssh: Some(args), refused, .. } => {
            assert!(refused.is_empty(), "{words:?} was refused: {refused:?}");
            *args
        }
        other => panic!("{words:?} did not parse as ssh: {other:?}"),
    }
}

fn env() -> Env {
    Env {
        home: Some(PathBuf::from("/home/u")),
        user: Some("envuser".into()),
        local_host: Some("box.example.org".into()),
        uid: Some(1000),
        ssh_config: Some("none".into()),
        ..Env::default()
    }
}

fn resolved(words: &[&str]) -> Resolved {
    let mut all = words.to_vec();
    all.push("host");
    resolve(&ssh(&all), &env()).unwrap_or_else(|e| panic!("{words:?}: {e}"))
}

fn forwarded(words: &[&str]) -> Agent {
    resolved(words).options.forward_agent
}

/// The line of `-G` for `keyword`.
fn shown(words: &[&str], keyword: &str) -> Option<String> {
    dump::lines(&resolved(words)).into_iter().find(|l| l.split(' ').next() == Some(keyword))
}

fn refused(words: &[&str]) -> String {
    let mut all = words.to_vec();
    all.push("host");
    let refusal = resolve_or_refuse(&ssh(&all), &env()).expect_err("refused");
    assert_eq!(refusal.code, 64, "{words:?}: {}", refusal.message);
    refusal.message
}

#[test]
fn agent_forwarding_is_off_by_default_and_the_last_of_a_and_a_wins() {
    assert_eq!(forwarded(&[]), Agent::Off);
    assert_eq!(shown(&[], "forwardagent").as_deref(), Some("forwardagent no"));
    assert_eq!(forwarded(&["-A"]), Agent::FromEnvironment);
    assert_eq!(shown(&["-A"], "forwardagent").as_deref(), Some("forwardagent yes"));
    assert_eq!(forwarded(&["-A", "-a"]), Agent::Off);
    assert_eq!(forwarded(&["-a", "-A"]), Agent::FromEnvironment);
    assert_eq!(forwarded(&["-A", "-A"]), Agent::FromEnvironment);
    assert_eq!(forwarded(&["-aA", "-a"]), Agent::Off);
}

#[test]
fn the_flags_win_over_forward_agent_whose_first_value_wins() {
    assert_eq!(forwarded(&["-o", "ForwardAgent=yes"]), Agent::FromEnvironment);
    assert_eq!(forwarded(&["-o", "ForwardAgent=true"]), Agent::FromEnvironment);
    assert_eq!(forwarded(&["-o", "ForwardAgent=no", "-A"]), Agent::FromEnvironment);
    assert_eq!(forwarded(&["-A", "-o", "ForwardAgent=no"]), Agent::FromEnvironment);
    assert_eq!(forwarded(&["-a", "-o", "ForwardAgent=yes"]), Agent::Off);
    assert_eq!(forwarded(&["-o", "ForwardAgent=no", "-o", "ForwardAgent=yes"]), Agent::Off);
}

#[test]
fn forward_agent_names_a_path_with_its_tokens() {
    let r = resolved(&["-o", "ForwardAgent=/s/%h-%p"]);
    assert_eq!(r.options.forward_agent, Agent::Path(PathBuf::from("/s/host-22")));
    // As OpenSSH's -G prints it: expanded.
    let path = PathBuf::from("/s/host-22").display().to_string();
    assert_eq!(shown(&["-o", "ForwardAgent=/s/%h-%p"], "forwardagent"), Some(format!("forwardagent {path}")));
    // There is no agent there: said, and the run goes on.
    assert!(
        r.warnings.iter().any(|w| w.contains("there is no agent at /s/host-22")) || cfg!(windows),
        "{:?}",
        r.warnings
    );
    // OpenSSH keeps the path apart from yes and no: -A takes it, -a not.
    assert_eq!(forwarded(&["-A", "-o", "ForwardAgent=/s/a"]), Agent::Path(PathBuf::from("/s/a")));
    assert_eq!(forwarded(&["-a", "-o", "ForwardAgent=/s/a"]), Agent::Off);
    assert_eq!(forwarded(&["-o", "ForwardAgent=~/a"]), Agent::Path(PathBuf::from("/home/u").join("a")));
}

#[test]
fn forward_agent_names_a_variable_that_holds_the_path() {
    let path = std::env::var_os("PATH").expect("PATH is set");
    assert_eq!(forwarded(&["-o", "ForwardAgent=$PATH"]), Agent::Path(PathBuf::from(path)));
    let name = format!("ForwardAgent=${UNSET}");
    let r = resolved(&["-o", &name]);
    assert_eq!(r.options.forward_agent, Agent::Off);
    assert!(r.warnings.iter().any(|w| w.contains(&format!("{UNSET} is not set"))), "{:?}", r.warnings);
    assert_eq!(shown(&["-o", &name], "forwardagent"), Some(format!("forwardagent ${UNSET}")));
    assert!(refused(&["-o", "ForwardAgent=$1-x"]).contains("not the name of a variable"));
}

#[test]
fn yes_forwards_the_agent_that_podssh_logs_in_with() {
    assert_eq!(forwarded(&["-A", "-o", "IdentityAgent=/a/s"]), Agent::Path(PathBuf::from("/a/s")));
    let r = resolved(&["-A", "-o", "IdentityAgent=none"]);
    assert_eq!(r.options.forward_agent, Agent::Off);
    assert!(r.warnings.iter().any(|w| w.contains("IdentityAgent is none")), "{:?}", r.warnings);
    // OpenSSH's -G still says yes.
    assert_eq!(shown(&["-A", "-o", "IdentityAgent=none"], "forwardagent").as_deref(), Some("forwardagent yes"));
}

#[test]
fn identity_agent_takes_a_variable_as_openssh_does() {
    let name = format!("IdentityAgent=${UNSET}");
    assert_eq!(resolved(&["-o", &name]).options.agent, Agent::Off);
    assert_eq!(shown(&["-o", &name], "identityagent"), Some(format!("identityagent ${UNSET}")));
    let path = std::env::var_os("PATH").expect("PATH is set");
    assert_eq!(resolved(&["-o", "IdentityAgent=${PATH}"]).options.agent, Agent::Path(PathBuf::from(&path)));
    assert_eq!(
        shown(&["-o", "IdentityAgent=${PATH}"], "identityagent"),
        Some(format!("identityagent {}", PathBuf::from(&path).display()))
    );
}

#[test]
fn a_variable_in_braces_is_expanded_in_a_file_name_or_refused() {
    let path = std::env::var("PATH").expect("PATH is set");
    let r = resolved(&["-o", "IdentityFile=${PATH}"]);
    assert_eq!(r.options.identity_files, vec![PathBuf::from(&path)]);
    let r = resolved(&["-o", "UserKnownHostsFile=${PATH}"]);
    assert_eq!(r.options.user_known_hosts, vec![PathBuf::from(&path)]);
    let message = refused(&["-i", &format!("/k/${{{UNSET}}}/id")]);
    assert!(message.contains(&format!("${{{UNSET}}} is not set")), "{message}");
    assert!(refused(&["-o", "IdentityFile=/k/${HOME"]).contains("a ${ with no }"));
    assert!(refused(&["-o", "IdentityFile=/k/${}"]).contains("names no variable"));
    // $NAME with no braces is a file name, as OpenSSH reads it there.
    let r = resolved(&["-o", "IdentityFile=/k/$HOME"]);
    assert_eq!(r.options.identity_files, vec![PathBuf::from("/k/$HOME")]);
}
