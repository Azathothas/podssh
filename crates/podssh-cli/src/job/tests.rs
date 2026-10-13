//! The command line of `podssh job` (T-193, T-197), with no host: each
//! action that it reads, and each refusal (64) before anything connects.

use std::time::Duration;

use super::*;

fn args(words: &[&str], dashed: bool) -> JobArgs {
    let mut it = words.iter().map(|w| w.to_string());
    JobArgs { subcommand: it.next(), host: it.next(), words: it.collect(), dashed, ..JobArgs::default() }
}

#[test]
fn each_action_is_read_from_its_words() {
    let start = action(&args(&["start", "web1", "sleep", "300"], true)).unwrap();
    assert_eq!(start, Action::Start("sleep 300".into()), "the words joined, as OpenSSH joins them");
    assert_eq!(action(&args(&["list", "web1"], false)), Ok(Action::List { json: false }));
    assert_eq!(action(&args(&["log", "web1", "ABCD1234"], false)), Ok(Action::Log("abcd1234".into())));
    assert_eq!(action(&args(&["stop", "web1", "0123abcd"], false)), Ok(Action::Stop("0123abcd".into())));
}

#[test]
fn the_queue_reads_its_flags() {
    let mut submit = args(&["submit", "web1,web2", "make"], true);
    submit.slots = Some("2".into());
    assert_eq!(action(&submit), Ok(Action::Submit { command: "make".into(), slots: Some(2) }));
    let mut wait = args(&["wait", "web1", "abcd1234"], false);
    wait.timeout = Some("30s".into());
    assert_eq!(action(&wait), Ok(Action::Wait { id: "abcd1234".into(), timeout: Some(Duration::from_secs(30)) }));
    let mut fetch = args(&["fetch", "web1", "abcd1234", "here"], false);
    fetch.files = Some("build/*.log".into());
    let want = Action::Fetch { id: "abcd1234".into(), dir: Some("here".into()), files: Some("build/*.log".into()) };
    assert_eq!(action(&fetch), Ok(want));
    let mut list = args(&["list", "web1"], false);
    list.json = true;
    assert_eq!(action(&list), Ok(Action::List { json: true }));
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
        (&["submit", "web1", "ls"][..], false, "so that no word of it is read as a flag"),
        (&["list", "web1", "x"][..], false, "list takes no word"),
        (&["log", "web1"][..], false, "give one ID"),
        (&["stop", "web1", "a", "b"][..], false, "give one ID"),
        (&["stop", "web1", "abcd123"][..], false, "8 hex digits"),
        (&["stop", "web1", "podssh-j"][..], false, "8 hex digits"),
        (&["wait", "web1"][..], false, "give one ID"),
        (&["fetch", "web1", "abcd1234", "a", "b"][..], false, "a directory or none"),
    ] {
        let why = action(&args(words, dashed)).expect_err("a refusal");
        assert!(why.contains(says), "{words:?}: {why}");
    }
    let newline = action(&args(&["start", "web1", "echo a\nb"], true)).expect_err("a refusal");
    assert!(newline.contains("newline"), "{newline}");
}

#[test]
fn a_flag_of_the_queue_is_refused_with_another_subcommand_or_a_bad_value() {
    let with = |words: &[&str], set: &dyn Fn(&mut JobArgs)| {
        let mut a = args(words, true);
        set(&mut a);
        action(&a).expect_err("a refusal")
    };
    let why = with(&["list", "web1"], &|a| a.slots = Some("2".into()));
    assert!(why.contains("--slots goes with podssh job submit"), "{why}");
    let why = with(&["stop", "web1", "abcd1234"], &|a| a.json = true);
    assert!(why.contains("--json goes with podssh job list"), "{why}");
    for bad in ["0", "65", "x"] {
        let why = with(&["submit", "web1", "make"], &|a| a.slots = Some(bad.into()));
        assert!(why.contains("1 to 64"), "{bad}: {why}");
    }
    let why = with(&["wait", "web1", "abcd1234"], &|a| a.timeout = Some("soon".into()));
    assert!(why.starts_with("bad --timeout"), "{why}");
    for bad in ["/etc/*", "../x", "a/../../b", " "] {
        let why = with(&["fetch", "web1", "abcd1234"], &|a| a.files = Some(bad.into()));
        assert!(why.contains("under the home directory"), "{bad}: {why}");
    }
}

#[test]
fn an_id_is_eight_hex_digits_and_new_ones_differ() {
    let a = new_id();
    assert_eq!(id(&a), Ok(a.clone()));
    assert_ne!(a, new_id(), "two IDs in a row are one in 2^32");
    assert!(now_ms() > 1_700_000_000_000, "milliseconds since 1970");
}
