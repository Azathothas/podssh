use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;
use crate::settings::{Defaults, Value as Setting};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-session-log-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).unwrap();
    dir
}

#[test]
fn a_value_is_yes_no_or_an_absolute_path() {
    for on in ["1", "yes", "YES", "on"] {
        assert_eq!(parse(on, None), Ok(Place::Cache), "{on}");
    }
    for off in ["0", "no", "Off"] {
        assert_eq!(parse(off, None), Ok(Place::Off), "{off}");
    }
    let home = std::env::temp_dir();
    let file = home.join("log.jsonl");
    assert_eq!(parse(&file.display().to_string(), None), Ok(Place::File(file.clone())));
    assert_eq!(parse("~/log.jsonl", Some(&home)), Ok(Place::File(file)));
    for bad in ["relative.jsonl", "maybe", "~/x"] {
        assert!(parse(bad, None).is_err(), "{bad}");
    }
}

#[test]
fn the_variable_beats_the_settings_file() {
    let setting = |text: &str| Setting { text: text.into(), at: "settings:3".into() };
    let file = Defaults { session_log: Some(setting("yes")), ..Defaults::default() };
    assert_eq!(place_from(None, &file, None).unwrap(), Place::Cache);
    assert_eq!(place_from(Some("0".into()), &file, None).unwrap(), Place::Off);
    assert_eq!(place_from(Some(" ".into()), &file, None).unwrap(), Place::Cache, "an empty variable is unset");
    assert_eq!(place_from(None, &Defaults::default(), None).unwrap(), Place::Off, "off by default");
    let refusal = place_from(Some("maybe".into()), &file, None).unwrap_err();
    assert_eq!(refusal.code, 78);
    assert!(refusal.message.starts_with("PODSSH_SESSION_LOG \"maybe\""), "{}", refusal.message);
    let bad = Defaults { session_log: Some(setting("rel")), ..Defaults::default() };
    assert!(place_from(None, &bad, None).unwrap_err().message.starts_with("settings:3: SessionLog"));
}

#[test]
fn lines_are_appended_privately_and_a_full_log_is_moved_aside() {
    let dir = scratch("append");
    let path = dir.join(FILE);
    let place = Place::File(path.clone());
    for n in 0..3 {
        assert_eq!(append(&place, &json!({ "n": n })).unwrap(), path);
    }
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text, "{\"n\":0}\n{\"n\":1}\n{\"n\":2}\n");
    assert_eq!(last(&path), Some(json!({ "n": 2 })));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // A log at its limit becomes sessions.1.jsonl, and a new one starts.
    let full = "x".repeat(LIMIT as usize - 1) + "\n";
    std::fs::write(&path, &full).unwrap();
    append(&place, &json!({ "n": 3 })).unwrap();
    assert_eq!(std::fs::read_to_string(dir.join(OLD_FILE)).unwrap(), full);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"n\":3}\n");
    assert_eq!(aside(Path::new("/l/log")), Path::new("/l/log.1"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_or_a_file_that_others_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("refused");
    let target = dir.join("elsewhere");
    std::fs::write(&target, "").unwrap();
    let link = dir.join("link.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(append(&Place::File(link), &json!({})).is_err());
    let open = dir.join("open.jsonl");
    std::fs::write(&open, "").unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
    let why = append(&Place::File(open.clone()), &json!({})).unwrap_err();
    assert!(why.contains("chmod 600"), "{why}");
    assert_eq!(std::fs::read_to_string(&open).unwrap(), "");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The lines of the two verbs. One test: the facts of a run are the
/// process's.
#[test]
fn a_line_names_the_run_and_never_its_command() {
    let result = json!({ "exit": 3, "status": 3, "end": "status", "failure": null, "duration_ms": 12,
        "bytes": { "stdin": 0, "stdout": 4, "stderr": 5 }, "relay": { "host": "r1.example", "close_code": 1000 } });
    *RUN.lock().unwrap() = None;
    assert_eq!(ssh_line(0, &result), None, "no destination, no line");
    target("db.example", Some(22), "relay");
    let line = ssh_line(1_760_000_000_000, &result).unwrap();
    assert_eq!(
        line,
        json!({ "start": "2025-10-09T08:53:20Z", "duration_ms": 12, "verb": "ssh",
        "host": "db.example", "port": 22, "via": "r1.example", "end": "status", "exit": 3, "failure": null,
        "bytes": { "stdin": 0, "stdout": 4, "stderr": 5 }, "close_code": 1000 })
    );
    let direct = json!({ "exit": 0, "end": "status", "duration_ms": 1, "bytes": {}, "relay": null });
    target("10.0.0.5", Some(2222), "direct");
    assert_eq!(ssh_line(0, &direct).unwrap()["via"], "direct");
    // proxy: what opened, the bytes, and the relay's close.
    target("db.example", Some(5432), "relay");
    let failed = proxy_line(0, 5, 69).unwrap();
    assert_eq!(
        (failed["end"].clone(), failed["failure"].clone(), failed["via"].clone()),
        (json!("failed"), json!("relay"), json!("relay"))
    );
    opened(Some("r2.example"));
    carried(10, 20);
    closed(Some(1000));
    let line = proxy_line(0, 5, 0).unwrap();
    assert_eq!(
        (line["verb"].clone(), line["via"].clone(), line["end"].clone()),
        (json!("proxy"), json!("r2.example"), json!("closed"))
    );
    assert_eq!(
        (line["bytes"].clone(), line["close_code"].clone(), line["failure"].clone()),
        (json!({ "stdin": 10, "stdout": 20, "stderr": 0 }), json!(1000), json!(null))
    );
    *RUN.lock().unwrap() = None;
}
