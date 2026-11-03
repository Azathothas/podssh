use std::time::Duration;

use serde_json::{json, Map, Value};

use super::super::child::Captured;
use super::*;

fn settings(allow_session: bool) -> Settings {
    Settings { allow: Allow::new(&["web*".to_string()]).unwrap(), allow_session, ..Settings::default() }
}

fn args(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn words(plan: &Plan) -> Vec<String> {
    plan.argv.iter().map(|a| a.to_string_lossy().into_owned()).collect()
}

fn ran(exit: Option<i32>, stdout: &[u8]) -> Ran {
    Ran {
        exit,
        stdout: Captured { bytes: stdout.to_vec(), truncated: false },
        stderr: Captured::default(),
        timed_out: false,
        duration: Duration::from_millis(4),
    }
}

/// A start carries the gate of ssh_exec; the text to type goes on stdin.
#[test]
fn a_start_has_the_gate_of_ssh_exec_and_the_text_goes_on_stdin() {
    let s = settings(true);
    let start = plan(&s, "session_start", &args(json!({ "name": "w", "destination": "u@web1", "command": "cat" })));
    let start = words(&start.unwrap().unwrap());
    assert_eq!(start[..3], ["session", "start", "w"]);
    assert!(start.contains(&"BatchMode=yes".to_string()) && start.contains(&"ForwardAgent=no".to_string()));
    assert_eq!(start[start.len() - 3..], ["--", "u@web1", "cat"]);
    let send = plan(&s, "session_send", &args(json!({ "name": "w", "text": "echo $HOME" }))).unwrap().unwrap();
    assert_eq!(words(&send), ["session", "send", "w"]);
    assert_eq!(send.stdin, b"echo $HOME\r");
    let send = plan(&s, "session_send", &args(json!({ "name": "w", "text": "pw", "enter": false }))).unwrap().unwrap();
    assert_eq!(send.stdin, b"pw");
    let wait = plan(&s, "session_wait", &args(json!({ "name": "w", "match": "-x y", "wait_seconds": 5 })));
    let wait = wait.unwrap().unwrap();
    assert_eq!(words(&wait), ["session", "wait", "w", "--match=-x y", "--timeout", "5s"]);
    assert_eq!(wait.limit, Duration::from_secs(5 + WAIT_MARGIN));
}

/// The server drives only the sessions that it started, and only with
/// --allow-session; a name is held once.
#[test]
fn only_a_session_that_this_server_started_is_driven() {
    let off = settings(false);
    let refused = plan(&off, "session_start", &args(json!({ "name": "w", "destination": "web1" }))).unwrap();
    assert!(refused.unwrap_err().contains("--allow-session"));
    let s = settings(true);
    for tool in ["session_send", "session_wait", "session_capture", "session_stop"] {
        let a = if tool == "session_send" { json!({ "name": "mine", "text": "x" }) } else { json!({ "name": "mine" }) };
        let why = plan(&s, tool, &args(a)).unwrap().unwrap_err();
        assert!(why.contains("not one that this server started"), "{tool}: {why}");
    }
    let host = plan(&s, "session_start", &args(json!({ "name": "w", "destination": "db1" }))).unwrap();
    assert!(host.unwrap_err().contains("not allowed"));
    assert!(s.started.names().is_empty(), "a refused start holds no name");
    for bad in ["", "-x", "a/b", "a b"] {
        let start = plan(&s, "session_start", &args(json!({ "name": bad, "destination": "web1" }))).unwrap();
        assert!(start.is_err(), "{bad:?}");
    }
    assert!(plan(&s, "session_start", &args(json!({ "name": "w", "destination": "web1" }))).unwrap().is_ok());
    let again = plan(&s, "session_start", &args(json!({ "name": "w", "destination": "web1" }))).unwrap();
    assert!(again.unwrap_err().contains("started one of that name"));
    assert!(plan(&s, "session_capture", &args(json!({ "name": "w" }))).unwrap().is_ok());
}

/// A start that failed frees its name; one that passed its limit stays, to
/// be stopped at the end, as does each started session.
#[test]
fn a_failed_start_frees_its_name_and_the_end_stops_the_others() {
    let s = settings(true);
    for name in ["a", "b", "c"] {
        plan(&s, "session_start", &args(json!({ "name": name, "destination": "web1" }))).unwrap().unwrap();
    }
    settle(&s, "session_start", &args(json!({ "name": "a" })), &Outcome::Ran(ran(Some(69), b"")));
    let limit_passed = Ran { timed_out: true, ..ran(None, b"") };
    settle(&s, "session_start", &args(json!({ "name": "b" })), &Outcome::Ran(limit_passed));
    settle(&s, "session_start", &args(json!({ "name": "c" })), &Outcome::Ran(ran(Some(0), b"/s/c.sock\n")));
    assert_eq!(s.started.names(), ["b", "c"]);
    let stops: Vec<Vec<String>> = stops(&s).iter().map(words).collect();
    assert_eq!(stops, [["session", "stop", "b"], ["session", "stop", "c"]]);
    settle(&s, "session_stop", &args(json!({ "name": "c" })), &Outcome::Ran(ran(Some(0), b"")));
    assert_eq!(s.started.names(), ["b"]);
}

#[test]
fn a_wait_that_passed_its_limit_is_a_result() {
    let (value, failed) = shape("session_wait", &ran(Some(NOT_YET), b"")).unwrap();
    assert_eq!((value["ended_by"].clone(), failed), (json!("limit"), false));
    let (value, failed) = shape("session_wait", &ran(Some(0), b"match\n")).unwrap();
    assert_eq!((value["ended_by"].clone(), failed), (json!("match"), false));
    assert!(shape("session_wait", &ran(Some(NO_SESSION), b"")).unwrap().1);
    let (value, _) = shape("session_start", &ran(Some(0), b"/c/w.sock\n")).unwrap();
    assert_eq!(value["socket"], "/c/w.sock");
    assert!(shape("cp_put", &ran(Some(0), b"")).is_none());
}
