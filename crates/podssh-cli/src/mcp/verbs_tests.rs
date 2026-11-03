use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::*;

fn settings() -> Settings {
    Settings {
        allow: Allow::new(&["web*".to_string()]).unwrap(),
        config: Some("cfg".into()),
        direct: true,
        scratch: PathBuf::from("scratch"),
        ..Settings::default()
    }
}

fn args(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn argv(name: &str, arguments: Value) -> Result<Vec<String>, String> {
    let plan = plan(&settings(), name, &args(arguments)).expect("a tool of verbs")?;
    Ok(plan.argv.iter().map(|a| a.to_string_lossy().into_owned()).collect())
}

/// Each child carries the options that ssh_exec forces, before the user's
/// file, and its words after them.
#[test]
fn each_child_has_the_gate_of_ssh_exec() {
    let words = argv("job_start", json!({ "destination": "u@web1", "command": "make -j4" })).unwrap();
    let at = |w: &str| words.iter().position(|x| x == w).unwrap_or_else(|| panic!("{w} in {words:?}"));
    for forced in ["BatchMode=yes", "StrictHostKeyChecking=yes", "ClearAllForwardings=yes", "ForwardAgent=no"] {
        assert!(at(forced) < at("-F"), "{forced}: {words:?}");
    }
    assert_eq!(words[0], "job");
    assert!(words.contains(&"--direct".to_string()));
    assert_eq!(words[words.len() - 4..], ["start", "u@web1", "--", "make -j4"]);
    let health = argv("health", json!({ "destination": "web2" })).unwrap();
    assert_eq!(health[0], "health");
    assert_eq!(health[health.len() - 3..], ["--json", "--", "web2"]);
    let list = argv("job_list", json!({ "destination": "web2" })).unwrap();
    assert_eq!(list[list.len() - 3..], ["list", "--json", "web2"]);
    let wait = argv("job_wait", json!({ "destination": "web2", "id": "0123abcd", "wait_seconds": 5 })).unwrap();
    assert_eq!(wait[wait.len() - 5..], ["wait", "--timeout", "5s", "web2", "0123abcd"]);
}

#[test]
fn a_host_outside_the_list_and_a_bad_argument_are_the_call_s_error() {
    for name in ["health", "job_start", "job_list", "job_log", "job_wait", "job_stop"] {
        let refused = argv(name, json!({ "destination": "db1", "command": "x", "id": "0123abcd" }));
        let why = refused.expect_err(name);
        assert!(why.contains("not allowed") || why.contains("not an argument"), "{name}: {why}");
        let refused = argv(name, json!({ "destination": "db1" })).expect_err(name);
        assert!(refused.contains("not allowed") || refused.contains("required"), "{name}: {refused}");
    }
    for id in ["", "0123", "0123abcz", "--json00", "../../x"] {
        assert!(argv("job_stop", json!({ "destination": "web1", "id": id })).unwrap_err().contains("hex digits"), "{id}");
    }
    assert!(argv("job_start", json!({ "destination": "web1", "command": "" })).is_err());
    assert!(argv("job_log", json!({ "destination": "web1", "id": "0123abcd", "max_bytes": 0 })).is_err());
    assert!(argv("job_wait", json!({ "destination": "web1", "id": "0123abcd", "timeout_seconds": 5 })).is_err());
    assert!(plan(&settings(), "ssh_exec", &Map::new()).is_none(), "not a tool of verbs");
}

#[test]
fn the_limits_of_a_wait_and_of_a_log() {
    let s = settings();
    let wait = plan(&s, "job_wait", &args(json!({ "destination": "web1", "id": "0123abcd", "wait_seconds": 100 })));
    assert_eq!(wait.unwrap().unwrap().limit, Duration::from_secs(100 + WAIT_MARGIN));
    let log = plan(&s, "job_log", &args(json!({ "destination": "web1", "id": "0123abcd", "offset": 10, "max_bytes": 5 })));
    assert_eq!(log.unwrap().unwrap().cap, 15, "the child keeps the bytes up to the window's end");
}

fn ran(stdout: &[u8], exit: Option<i32>) -> Ran {
    Ran {
        exit,
        stdout: Captured { bytes: stdout.to_vec(), truncated: false },
        stderr: Captured::default(),
        timed_out: false,
        duration: Duration::from_millis(5),
    }
}

/// A job that runs on is a result; a job's status is its exit; the log comes
/// in windows.
#[test]
fn a_job_s_state_is_a_result_and_its_log_comes_in_windows() {
    let none = Map::new();
    let (value, failed) = shape("job_wait", &none, &ran(b"", Some(NOT_ENDED))).unwrap();
    assert_eq!((value["ended"].clone(), failed), (json!(false), false));
    let (value, failed) = shape("job_wait", &none, &ran(b"", Some(5))).unwrap();
    assert_eq!((value["ended"].clone(), value["exit"].clone(), failed), (json!(true), json!(5), false));
    let (value, failed) = shape("job_start", &none, &ran(b"0123abcd\n", Some(0))).unwrap();
    assert_eq!((value["id"].clone(), failed), (json!("0123abcd"), false));
    assert!(shape("job_start", &none, &ran(b"", Some(255))).unwrap().1);
    let window = args(json!({ "offset": 2, "max_bytes": 3 }));
    let (value, failed) = shape("job_log", &window, &ran(b"abcdefgh", Some(0))).unwrap();
    assert!(!failed);
    assert_eq!(
        (value["stdout"].clone(), value["next_offset"].clone(), value["more"].clone()),
        (json!("cde"), json!(5), json!(true))
    );
    let tail = args(json!({ "offset": 6 }));
    let (value, _) = shape("job_log", &tail, &ran(b"abcdefgh", Some(0))).unwrap();
    assert_eq!((value["stdout"].clone(), value["more"].clone()), (json!("gh"), json!(false)));
    assert!(shape("health", &none, &ran(b"{}", Some(0))).is_none(), "health's own JSON is its result");
}
