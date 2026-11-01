use super::*;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-detach-lock-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A name names files: letters, digits, `_` and `-`, and nothing that
/// could reach another file or another name's run lock.
#[test]
fn a_name_takes_letters_digits_underscores_and_hyphens() {
    for good in ["web", "ssh-1234", "a_b-C9", &"x".repeat(NAME_MAX)] {
        assert!(check_name(good).is_ok(), "{good}");
    }
    for bad in ["", "-x", "a.run", "../x", "a/b", "a b", "é", &"x".repeat(NAME_MAX + 1)] {
        assert!(check_name(bad).is_err(), "{bad}");
    }
}

/// A held lock reads as held, by a try that writes nothing, with the pid
/// where the system lets it be read; once let go, as free; a missing file
/// as free.
#[test]
fn a_held_lock_is_seen_without_taking_it_and_free_once_let_go() {
    let dir = scratch("held");
    let path = lock_path(&dir, "web");
    assert_eq!(holder(&path), Holder::Free);
    let file = match hold(&path) {
        Ok(Tried::Held(file)) => file,
        other => panic!("{other:?}"),
    };
    match holder(&path) {
        Holder::Held(pid) => assert!(pid.is_none() || pid == Some(std::process::id()), "{pid:?}"),
        other => panic!("held, not {other:?}"),
    }
    // A second holder waits its patience, then is refused.
    let began = Instant::now();
    assert!(matches!(hold(&path), Ok(Tried::Taken(_))));
    assert!(began.elapsed() >= PATIENCE);
    drop(file);
    assert_eq!(holder(&path), Holder::Free);
    assert!(matches!(hold(&path), Ok(Tried::Held(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A record is written in one rename and read back, with its pids.
#[test]
fn a_record_is_written_whole_and_read_back() {
    let dir = scratch("record");
    let path = record_path(&dir, "web");
    write_record(&path, &json!({"name": "web", "pid": 41, "run": 42, "words": ["ssh", "-f"]}));
    let record = read_record(&dir, "web").expect("a record");
    assert_eq!(pid_field(&record, "pid"), Some(41));
    assert_eq!(pid_field(&record, "run"), Some(42));
    assert_eq!(pid_field(&record, "log"), None);
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(left, vec![std::ffi::OsString::from("web.json")], "no part is left");
    let _ = std::fs::remove_dir_all(&dir);
}
