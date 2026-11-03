use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::super::allow::Allow;
use super::super::child::Captured;
use super::super::dirs::Dirs;
use super::*;

/// A directory of this test alone, gone at its end.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("podssh-mcp-copy-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("allowed")).unwrap();
        std::fs::create_dir_all(dir.join("other")).unwrap();
        Scratch(std::fs::canonicalize(&dir).unwrap())
    }

    fn settings(&self) -> Settings {
        let allowed = self.0.join("allowed").display().to_string();
        Settings {
            allow: Allow::new(&["web*".to_string()]).unwrap(),
            dirs: Dirs::new(&[allowed], &[]).unwrap(),
            scratch: self.0.clone(),
            ..Settings::default()
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn args(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn argv(s: &Settings, name: &str, arguments: Value, file: &str) -> Result<Vec<String>, String> {
    let plan = plan(s, name, &args(arguments), file).expect("a copy")?;
    Ok(plan.argv.iter().map(|a| a.to_string_lossy().into_owned()).collect())
}

#[test]
fn a_file_of_the_directory_goes_up_with_the_gate_of_ssh_exec() {
    let s = Scratch::new("put");
    std::fs::write(s.0.join("allowed/up.txt"), b"up").unwrap();
    let file = s.0.join("r1.json").display().to_string();
    let words = argv(
        &s.settings(),
        "cp_put",
        json!({ "destination": "u@web1", "path": "x/up.txt",
        "local_path": "up.txt" }),
        &file,
    )
    .unwrap();
    assert_eq!(words[..4], ["cp", "--jsonl", "--timeout", "300s"]);
    assert!(words.contains(&"BatchMode=yes".to_string()) && words.contains(&"StrictHostKeyChecking=yes".to_string()));
    let local = s.0.join("allowed/up.txt").display().to_string();
    assert_eq!(words[words.len() - 3..], ["--", local.as_str(), "u@web1:x/up.txt"]);
    let down = argv(
        &s.settings(),
        "cp_get",
        json!({ "destination": "web2", "path": "/var/log/a.log",
        "local_path": "a.log", "recursive": false }),
        &file,
    )
    .unwrap();
    let local = s.0.join("allowed/a.log").display().to_string();
    assert_eq!(down[down.len() - 3..], ["--", "web2:/var/log/a.log", local.as_str()]);
}

#[test]
fn a_path_outside_the_directory_a_host_outside_the_list_and_no_directory_are_refused() {
    let s = Scratch::new("refused");
    std::fs::write(s.0.join("other/secret"), b"s").unwrap();
    std::fs::write(s.0.join("allowed/ok"), b"o").unwrap();
    let file = s.0.join("r2.json").display().to_string();
    let outside = s.0.join("other/secret").display().to_string();
    let put = |local: &str, dest: &str| {
        argv(&s.settings(), "cp_put", json!({ "destination": dest, "path": "p", "local_path": local }), &file)
    };
    assert!(put(&outside, "web1").unwrap_err().contains("outside the directories of --allow-dir"));
    assert!(put("../other/secret", "web1").unwrap_err().contains("outside"));
    assert!(put("ok", "db1").unwrap_err().contains("not allowed"));
    let get = json!({ "destination": "web1", "path": "p", "local_path": outside });
    assert!(argv(&s.settings(), "cp_get", get, &file).unwrap_err().contains("outside"));
    // A tree goes into a path that is not there.
    let tree = json!({ "destination": "web1", "path": "d", "local_path": "ok", "recursive": true });
    assert!(argv(&s.settings(), "cp_get", tree, &file).unwrap_err().contains("new path"));
    let none = Settings { dirs: Dirs::default(), ..s.settings() };
    let refused = argv(&none, "cp_put", json!({ "destination": "web1", "path": "p", "local_path": "ok" }), &file);
    assert!(refused.unwrap_err().contains("no --allow-dir"));
    let neither = json!({ "destination": "web1", "path": "p" });
    let two_lines = json!({ "destination": "web1", "path": "a\nb", "local_path": "ok" });
    for bad in [neither, two_lines] {
        assert!(argv(&s.settings(), "cp_put", bad.clone(), &file).is_err(), "{bad}");
    }
}

#[test]
fn content_goes_through_a_private_file_of_the_far_name() {
    use base64::Engine as _;
    let s = Scratch::new("content");
    let file = s.0.join("r3.json").display().to_string();
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello\n");
    let words = argv(
        &s.settings(),
        "cp_put",
        json!({ "destination": "web1", "path": "conf/app.ini",
        "content": encoded }),
        &file,
    )
    .unwrap();
    let written = content_dir(&file).join("app.ini");
    assert_eq!(std::fs::read(&written).unwrap(), b"hello\n");
    assert_eq!(words[words.len() - 2], written.display().to_string());
    let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; CONTENT_MAX + 1]);
    let file = s.0.join("r4.json").display().to_string();
    let refused = argv(&s.settings(), "cp_put", json!({ "destination": "web1", "path": "big", "content": big }), &file);
    assert!(refused.unwrap_err().contains("at most"));
    let to_dir = json!({ "destination": "web1", "path": "conf/", "content": encoded });
    assert!(argv(&s.settings(), "cp_put", to_dir, &file).unwrap_err().contains("name the file"));
    let both = json!({ "destination": "web1", "path": "x", "content": encoded, "local_path": "y" });
    assert!(argv(&s.settings(), "cp_put", both, &file).unwrap_err().contains("give one"));
}

#[test]
fn the_result_has_cp_s_exit_and_its_events() {
    let ran = Ran {
        exit: Some(0),
        stdout: Captured { bytes: b"{\"event\":\"copied\",\"bytes\":2}\nnot json\n".to_vec(), truncated: false },
        stderr: Captured::default(),
        timed_out: false,
        duration: Duration::from_millis(3),
    };
    let (value, failed) = shape("cp_put", &ran).unwrap();
    assert!(!failed);
    assert_eq!(value["events"], json!([{ "event": "copied", "bytes": 2 }]));
    assert!(shape("cp_get", &Ran { exit: Some(66), ..ran.clone() }).unwrap().1);
    assert!(shape("job_log", &ran).is_none());
}
