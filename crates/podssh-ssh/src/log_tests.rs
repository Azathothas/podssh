//! The copy of a log's lines for the binary's journal (T-674): which lines
//! reach the copy, at which priority, and in which words. The copy of the
//! tests keeps what it got; each test reads only the lines of its own mark,
//! as the tests run at once and each log of the crate's tests copies too.

use super::*;

/// Each copy that the tests' copy got, from any thread.
static COPIED: Mutex<Vec<(u8, String)>> = Mutex::new(Vec::new());

fn keep(priority: u8, text: &str) {
    COPIED.lock().unwrap_or_else(|e| e.into_inner()).push((priority, text.to_string()));
}

/// The tests' copy, given before a test's first line: the first call holds,
/// and each test gives the same.
fn copied_from_here() {
    copy_lines(keep);
}

/// The copies whose text holds `mark`, in their order.
fn copies(mark: &str) -> Vec<(u8, String)> {
    let copied = COPIED.lock().unwrap_or_else(|e| e.into_inner());
    copied.iter().filter(|(_, text)| text.contains(mark)).cloned().collect()
}

#[test]
fn each_level_has_its_priority_in_syslog_s_numbers() {
    let cases = [
        (LogLevel::Fatal, 2),
        (LogLevel::Error, 3),
        (LogLevel::Quiet, 6),
        (LogLevel::Info, 6),
        (LogLevel::Verbose, 7),
        (LogLevel::Debug1, 7),
        (LogLevel::Debug2, 7),
        (LogLevel::Debug3, 7),
    ];
    for (level, number) in cases {
        assert_eq!(priority(level), number, "{level:?}");
    }
    // A warning is between an error and the lines of INFO.
    assert!(priority(LogLevel::Error) < WARNING && WARNING < priority(LogLevel::Info));
}

/// An error, a warning and a line of INFO reach the copy at 3, 4 and 6, in
/// stderr's words with no line break at the end; a line at `-v` that the
/// log does not show is not copied.
#[test]
fn each_line_on_stderr_is_copied_at_its_priority() {
    copied_from_here();
    let log = Log::new(LogLevel::Info);
    log.error("t674-a: connect to the relay failed: timed out");
    log.warning("Warning: t674-a: remote port forwarding failed for listen port 2222");
    log.info("t674-a: Forwarding port.");
    log.verbose("t674-a: a line of -v");
    let want = vec![
        (3, "podssh: t674-a: connect to the relay failed: timed out".to_string()),
        (4, "podssh: Warning: t674-a: remote port forwarding failed for listen port 2222".to_string()),
        (6, "podssh: t674-a: Forwarding port.".to_string()),
    ];
    assert_eq!(copies("t674-a"), want);
}

/// A log in a file (`-E`) copies nothing: the stream has none of its lines.
#[test]
fn a_log_in_a_file_copies_nothing() {
    copied_from_here();
    let path = std::env::temp_dir().join(format!("podssh-log-copy-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let log = Log::to_file(LogLevel::Info, &path).expect("a log file");
    log.error("t674-b: an error in the file");
    log.warning("Warning: t674-b: a warning in the file");
    let written = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    assert!(written.contains("t674-b: an error in the file"), "{written}");
    assert!(written.contains("t674-b: a warning in the file"), "{written}");
    let copied = copies("t674-b");
    assert!(copied.is_empty(), "{copied:?}");
}

/// What a log does not show is not copied: `-q` hides each line, and
/// `-o LogLevel=ERROR` a warning, as OpenSSH hides its "Warning:" lines.
#[test]
fn a_line_that_the_log_hides_is_not_copied() {
    copied_from_here();
    let quiet = Log::new(LogLevel::Quiet);
    quiet.error("t674-c: hidden by -q");
    quiet.warning("Warning: t674-c: hidden by -q");
    let errors = Log::new(LogLevel::Error);
    errors.warning("Warning: t674-c: hidden at ERROR");
    errors.error("t674-c: shown at ERROR");
    assert_eq!(copies("t674-c"), vec![(3, "podssh: t674-c: shown at ERROR".to_string())]);
}

/// A host's prefix (`podssh each`) is in the copy, as on stderr, on each of
/// its lines.
#[test]
fn a_host_s_prefix_is_in_the_copy() {
    copied_from_here();
    let log = Log::new(LogLevel::Info).with_prefix("web1: ");
    log.warning("Warning: t674-d: the server tried X11 forwarding\nrefused.");
    let text = "podssh: web1: Warning: t674-d: the server tried X11 forwarding\npodssh: web1: refused.";
    assert_eq!(copies("t674-d"), vec![(4, text.to_string())]);
}

/// The binary's remedy after an error goes with it, at the error's
/// priority. The hint of the tests answers only its own mark, as no other
/// test of the crate gives one (the first call holds).
#[test]
fn a_hint_is_copied_after_its_error() {
    fn hint(message: &str) -> Option<String> {
        message.contains("t674-e").then(|| "t674-e: the remedy".to_string())
    }
    copied_from_here();
    hint_errors(hint);
    Log::new(LogLevel::Info).error("t674-e: Too many open files");
    let want =
        vec![(3, "podssh: t674-e: Too many open files".to_string()), (3, "podssh: t674-e: the remedy".to_string())];
    assert_eq!(copies("t674-e"), want);
}
