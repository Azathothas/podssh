//! The command line of `podssh job` (T-193), with no host: each action that
//! it reads, and each refusal (64) before anything connects.

use super::*;

fn args(words: &[&str], dashed: bool) -> JobArgs {
    let mut it = words.iter().map(|w| w.to_string());
    JobArgs { subcommand: it.next(), host: it.next(), words: it.collect(), dashed, ..JobArgs::default() }
}

#[test]
fn each_action_is_read_from_its_words() {
    let start = action(&args(&["start", "web1", "sleep", "300"], true)).unwrap();
    assert_eq!(start, Action::Start("sleep 300".into()), "the words joined, as OpenSSH joins them");
    assert_eq!(action(&args(&["list", "web1"], false)), Ok(Action::List));
    assert_eq!(action(&args(&["log", "web1", "ABCD1234"], false)), Ok(Action::Log("abcd1234".into())));
    assert_eq!(action(&args(&["stop", "web1", "0123abcd"], false)), Ok(Action::Stop("0123abcd".into())));
}

#[test]
fn a_command_line_that_names_no_job_is_refused() {
    for (words, dashed, says) in [
        (&[][..], false, "give what to do"),
        (&["run"][..], false, "not a command of podssh job"),
        (&["start"][..], false, "give the host"),
        (&["start", "web1"][..], true, "give the command after --"),
        // Without --, a word such as -l would be a flag of podssh.
        (&["start", "web1", "ls"][..], false, "so that no word of it is read as a flag"),
        (&["list", "web1", "x"][..], false, "list takes no word"),
        (&["log", "web1"][..], false, "give one ID"),
        (&["stop", "web1", "a", "b"][..], false, "give one ID"),
        (&["stop", "web1", "abcd123"][..], false, "8 hex digits"),
        (&["stop", "web1", "podssh-j"][..], false, "8 hex digits"),
    ] {
        let why = action(&args(words, dashed)).expect_err("a refusal");
        assert!(why.contains(says), "{words:?}: {why}");
    }
    let newline = action(&args(&["start", "web1", "echo a\nb"], true)).expect_err("a refusal");
    assert!(newline.contains("newline"), "{newline}");
}

#[test]
fn an_id_is_eight_hex_digits_and_new_ones_differ() {
    let a = new_id();
    assert_eq!(id(&a), Ok(a.clone()));
    assert_ne!(a, new_id(), "two IDs in a row are one in 2^32");
    assert!(now_ms() > 1_700_000_000_000, "milliseconds since 1970");
}
