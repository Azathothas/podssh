use std::time::Duration;

use serde_json::{json, Map, Value};

use super::*;

fn settings(patterns: &[&str]) -> Settings {
    let values: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
    Settings {
        allow: Allow::new(&values).unwrap(),
        config: Some("cfg".into()),
        direct: true,
        scratch: PathBuf::from("scratch"),
    }
}

fn args(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn argv(plan: &Plan) -> Vec<String> {
    plan.argv.iter().map(|a| a.to_string_lossy().into_owned()).collect()
}

#[test]
fn ssh_exec_is_offered_only_with_a_host_allowed() {
    let names = |s: &Settings| list(s).iter().map(|t| t["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(names(&settings(&["web*"])), ["ssh_exec", "status", "doctor", "man"]);
    assert_eq!(names(&settings(&[])), ["status", "doctor", "man"]);
    let tools = list(&settings(&["web*", "!web9"]));
    assert!(tools[0]["description"].as_str().unwrap().contains("web*, !web9"));
    assert_eq!(tools[0]["inputSchema"]["required"], json!(["destination", "command"]));
    for tool in &tools {
        assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{tool}");
        let name = tool["name"].as_str().unwrap();
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'), "{name}");
    }
}

#[test]
fn a_session_has_no_prompt_no_unknown_key_and_no_forwarding() {
    let plan = plan(
        &settings(&["web*"]),
        "ssh_exec",
        &args(json!({ "destination": "u@web1", "command": "echo hi; exit 3",
        "stdin": "in", "timeout_seconds": 5, "host_key_fingerprint": "SHA256:abc" })),
        "r.json",
    )
    .unwrap();
    let words = argv(&plan);
    let at = |w: &str| words.iter().position(|x| x == w).unwrap_or_else(|| panic!("{w} in {words:?}"));
    for forced in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ClearAllForwardings=yes",
        "ControlMaster=no",
        "ForwardAgent=no",
        "ForwardX11=no",
    ] {
        assert!(at(forced) < at("-F"), "{forced} before the user's file: {words:?}");
    }
    assert_eq!(words[words.len() - 5..], ["--result-file", "r.json", "--", "u@web1", "echo hi; exit 3"]);
    assert!(
        words.contains(&"--direct".to_string()) && words.contains(&"--host-key-fingerprint=SHA256:abc".to_string())
    );
    assert_eq!((plan.stdin.as_slice(), plan.limit, plan.cap), (&b"in"[..], Duration::from_secs(5), SSH_CAP));
}

#[test]
fn a_wrong_argument_is_the_calls_error() {
    let s = settings(&["web*"]);
    let refused = |a: Value| plan(&s, "ssh_exec", &args(a), "r").unwrap_err();
    assert!(refused(json!({ "destination": "db1", "command": "true" })).contains("not allowed"));
    assert!(refused(json!({ "command": "true" })).contains("destination"));
    assert!(refused(json!({ "destination": "web1" })).contains("command"));
    assert!(refused(json!({ "destination": "web1", "command": "" })).contains("command"));
    assert!(refused(json!({ "destination": "web1", "command": 7 })).contains("expected a string"));
    assert!(refused(json!({ "destination": "web1", "command": "x", "timeout_seconds": 0 })).contains("1 to 3600"));
    assert!(refused(json!({ "destination": "web1", "command": "x", "timeout_seconds": 1.5 })).contains("1 to 3600"));
    assert!(refused(json!({ "destination": "web1", "command": "x", "port": 22 })).contains("port: not an argument"));
    assert!(refused(json!({ "destination": "-oProxyCommand=x", "command": "x" })).contains("destination"));
    let other = |name: &str, a: Value| plan(&s, name, &args(a), "r");
    assert!(other("status", json!({ "destination": "db1" })).unwrap_err().contains("not allowed"));
    assert_eq!(argv(&other("status", json!({ "destination": "web1" })).unwrap()), ["status", "--", "web1"]);
    assert_eq!(argv(&other("doctor", json!({ "full": true })).unwrap()), ["doctor", "--json", "--full"]);
    assert!(other("doctor", json!({ "full": "yes" })).is_err());
    assert_eq!(argv(&other("man", json!({ "section": "exit-status" })).unwrap()), ["man", "--json", "exit-status"]);
    assert!(other("man", json!({ "section": "--roff" })).is_err());
}

fn ran(stdout: &[u8], exit: Option<i32>, timed_out: bool) -> Ran {
    Ran {
        exit,
        stdout: Captured { bytes: stdout.to_vec(), truncated: false },
        stderr: Captured { bytes: b"err!\n".to_vec(), truncated: false },
        timed_out,
        duration: Duration::from_millis(12),
    }
}

#[test]
fn a_session_result_has_the_status_and_the_streams() {
    let file = json!({ "exit": 3, "status": 3, "signal": null, "end": "status", "failure": null });
    let (value, failed) = shape("ssh_exec", &ran(b"hi\n", Some(3), false), Some(file));
    assert!(!failed, "a status that is not 0 is the command's, not the tool's");
    assert_eq!(
        (value["exit"].clone(), value["status"].clone(), value["stdout"].clone()),
        (json!(3), json!(3), json!("hi\n"))
    );
    assert_eq!((value["stderr"].clone(), value["truncated"].clone()), (json!("err!\n"), json!(false)));
    let file = json!({ "exit": 255, "status": null, "end": "failed", "failure": "auth" });
    assert!(shape("ssh_exec", &ran(b"", Some(255), false), Some(file)).1);
    let (value, failed) = shape("ssh_exec", &ran(b"part", None, true), None);
    assert!(failed);
    assert_eq!(
        (value["timed_out"].clone(), value["exit"].clone(), value["status"].clone()),
        (json!(true), Value::Null, Value::Null)
    );
    let wrapped = result(value.clone(), true);
    assert_eq!(wrapped["structuredContent"], value);
    assert_eq!(serde_json::from_str::<Value>(wrapped["content"][0]["text"].as_str().unwrap()).unwrap(), value);
}

#[test]
fn podssh_own_json_is_the_result_of_the_other_tools() {
    let (value, failed) = shape("doctor", &ran(b"{\"ok\":false}\n", Some(1), false), None);
    assert_eq!((value, failed), (json!({ "ok": false }), false));
    let (value, failed) = shape("status", &ran(b"no json", Some(64), false), None);
    assert!(failed);
    assert_eq!(value["stderr"], "err!\n");
}
