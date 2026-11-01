use super::*;

fn words(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

/// The child's flag counts first only: a word of the run that happens to
/// read the same stays the run's.
#[test]
fn the_child_s_flag_is_its_first_word_alone() {
    let (child, rest) = split_child_flag(words(&[CHILD_FLAG, "ssh", "-f", "-N", "host"]));
    assert!(child);
    assert_eq!(rest, words(&["ssh", "-f", "-N", "host"]));
    let (child, rest) = split_child_flag(words(&["ssh", CHILD_FLAG]));
    assert!(!child);
    assert_eq!(rest, words(&["ssh", CHILD_FLAG]));
    assert_eq!(split_child_flag(Vec::new()), (false, Vec::new()));
}

/// A child's code is the parent's; a signal is 128 and its number.
#[cfg(unix)]
#[test]
fn the_child_s_code_or_signal_is_the_parent_s() {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(code_of(std::process::ExitStatus::from_raw(255 << 8)), 255);
    assert_eq!(code_of(std::process::ExitStatus::from_raw(0)), 0);
    assert_eq!(code_of(std::process::ExitStatus::from_raw(libc::SIGKILL)), 128 + libc::SIGKILL);
}

/// This binary can be started again: one way at least is found here.
#[test]
fn a_way_to_start_this_binary_again_is_found() {
    let found = binaries();
    assert!(!found.is_empty());
    assert!(found.iter().all(|p| p.exists()), "{found:?}");
}

/// Outside a child, the line of ready is never sent, whatever is said.
#[test]
fn a_process_that_is_no_child_sends_no_ready() {
    assert!(!is_child());
    on_line("node", "online: the relay takes this pair's sessions");
    ready("ssh");
    assert!(!is_child());
}
