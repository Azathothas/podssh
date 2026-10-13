//! The rules of `--expect`: a text cut between two pieces, the order of the
//! rules, the window, the keys, and the end of a rule's time.

use super::*;

fn rules(pairs: &[(&str, &str)], wait: Duration) -> Rules {
    let rules =
        pairs.iter().map(|(e, s)| Rule { expect: e.as_bytes().to_vec(), send: s.as_bytes().to_vec() }).collect();
    Rules { rules, wait }
}

#[tokio::test]
async fn a_text_cut_between_two_pieces_matches() {
    let mut x = Expect::new(&rules(&[("$ ", "echo EXP\r")], Duration::from_secs(30)));
    x.feed(b"Last login: today\r\n~ $");
    assert!(x.take().is_empty() && !x.done());
    x.feed(b" ");
    assert_eq!(x.take(), b"echo EXP\r");
    assert!(x.done());
    // Nothing more is looked at, and nothing more is sent.
    x.feed(b"$ $ ");
    assert!(x.take().is_empty());
}

#[tokio::test]
async fn each_rule_looks_only_after_the_match_before_it() {
    let mut x = Expect::new(&rules(&[("$ ", "echo EXP\r"), ("EXP", "exit 4\r")], Duration::from_secs(30)));
    // EXP before the first match is not the second rule's.
    x.feed(b"EXP motd\r\n$ ");
    assert_eq!(x.take(), b"echo EXP\r");
    assert!(!x.done());
    x.feed(b"echo E");
    assert!(x.take().is_empty());
    x.feed(b"XP\r\nEXP\r\n$ ");
    assert_eq!(x.take(), b"exit 4\r");
    assert!(x.done());
}

#[tokio::test]
async fn rules_that_one_piece_completes_send_in_their_order() {
    let mut x = Expect::new(&rules(&[("a", "1"), ("b", "2"), ("c", "3")], Duration::from_secs(30)));
    x.feed(b"xaxbxc");
    assert_eq!(x.take(), b"123");
    assert!(x.done());
    // The order of the rules holds: c before b is not b's match.
    let mut x = Expect::new(&rules(&[("a", "1"), ("b", "2"), ("c", "3")], Duration::from_secs(30)));
    x.feed(b"acb");
    assert_eq!(x.take(), b"12");
    assert!(!x.done());
}

#[tokio::test]
async fn output_past_the_window_is_dropped_and_a_later_match_still_counts() {
    let mut x = Expect::new(&rules(&[("READY", "go\n")], Duration::from_secs(30)));
    x.feed(".".repeat(WINDOW + 1000).as_bytes());
    assert!(x.seen.len() <= WINDOW);
    x.feed(b"READY");
    assert_eq!(x.take(), b"go\n");
}

#[tokio::test]
async fn a_rule_that_sees_no_match_in_its_time_is_named() {
    let x = Expect::new(&rules(&[("NEVER", "x")], Duration::from_millis(50)));
    let said = tokio::time::timeout(Duration::from_secs(10), x.missed()).await.expect("the rule's time ends");
    assert_eq!(said, "--expect 1 (\"NEVER\") saw no match within 50 ms; the session ends");
    // The second rule's time starts at the first one's match.
    let mut x = Expect::new(&rules(&[("a", ""), ("b", "")], Duration::from_secs(2)));
    x.feed(b"a");
    let said = tokio::time::timeout(Duration::from_secs(10), x.missed()).await.expect("the rule's time ends");
    assert!(said.starts_with("--expect 2 (\"b\") saw no match within 2 s"), "{said}");
    // With each rule matched, nothing ends the session.
    x.feed(b"b");
    assert!(tokio::time::timeout(Duration::from_millis(100), x.missed()).await.is_err());
}
