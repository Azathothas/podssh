//! The hub of the broadcast (T-185), with no network and no terminal: each
//! host's feed holds what the hub gave it, and a test takes it back.

use podssh_ssh::io::Feed;

use super::{names_host, Hub, QUEUE};
use crate::each::fan::Ended;
use crate::hosts::Groups;

const A: &str = "a@127.0.0.1:2201";
const B: &str = "b@127.0.0.1:2203";

/// A hub of the hosts `labels`, and the feed of each.
fn fed(labels: &[&str], confirm: bool) -> (Hub, Vec<Feed>) {
    let feeds: Vec<Feed> = labels.iter().map(|_| Feed::new()).collect();
    let hub = Hub::new(labels.iter().map(|l| l.to_string()).collect(), feeds.clone(), Groups::new(), confirm);
    (hub, feeds)
}

/// What each feed holds, taken back.
fn got(feeds: &[Feed]) -> Vec<String> {
    feeds.iter().map(|f| String::from_utf8(f.take()).unwrap()).collect()
}

#[test]
fn each_whole_line_goes_to_each_host_and_a_console_s_cr_goes() {
    let (mut hub, feeds) = fed(&[A, B], false);
    assert!(hub.typed(b"uptime\nhost").is_empty());
    assert_eq!(got(&feeds), ["uptime\n", "uptime\n"], "the start of a line waits for its end");
    assert!(hub.typed(b"name\r\n\n").is_empty());
    assert_eq!(got(&feeds), ["hostname\n\n", "hostname\n\n"]);
}

#[test]
fn only_names_hosts_by_label_without_user_and_with_braces() {
    let (mut hub, feeds) = fed(&[A, B], false);
    assert_eq!(hub.typed(b":only 127.0.0.1:2203\n"), ["1 of 2 hosts take the lines"]);
    hub.typed(b"echo only\n");
    assert_eq!(got(&feeds), ["", "echo only\n"]);
    hub.typed(format!(":only {A}\n").as_bytes());
    hub.typed(b"echo a\n");
    assert_eq!(got(&feeds), ["echo a\n", ""]);
    hub.typed(b":only 127.0.0.1:{2201,2203}\n");
    hub.typed(b"echo both\n");
    assert_eq!(got(&feeds), ["echo both\n", "echo both\n"]);
    // A name of no host changes nothing.
    let said = hub.typed(b":only 127.0.0.1:9\n");
    assert!(said[0].starts_with("127.0.0.1:9 is not a host of this broadcast"), "{said:?}");
    hub.typed(b"echo still\n");
    assert_eq!(got(&feeds), ["echo still\n", "echo still\n"]);
    assert_eq!(hub.typed(b":only\n"), ["give the hosts: :only HOST..."]);
    assert!(names_host(A, A) && names_host(A, "127.0.0.1:2201"));
    assert!(!names_host(A, "a@127.0.0.1") && !names_host(A, "127.0.0.1") && !names_host(A, "2201"));
}

#[test]
fn none_all_list_and_a_host_that_ended() {
    let (mut hub, feeds) = fed(&[A, B], false);
    assert_eq!(hub.typed(b":none\n"), ["0 of 2 hosts take the lines"]);
    let said = hub.typed(b"rm -rf /tmp/x\n");
    assert!(said[0].starts_with("no host is selected: the line goes to no host"), "{said:?}");
    assert_eq!(got(&feeds), ["", ""]);
    hub.typed(b":all\nsleep 9\n");
    let said = hub.ended(1, &Ended::Status(0));
    assert_eq!(said.len(), 2, "{said:?}");
    assert_eq!(said[0], format!("{B}: its shell ended with 0; it takes no more lines"));
    assert_eq!(said[1], format!("{B}: 8 bytes that waited for it were not sent"));
    assert_eq!(hub.typed(b":all\n"), ["1 of 2 hosts take the lines"], "a host that ended is not selected");
    hub.typed(b"echo all\n");
    assert_eq!(got(&feeds), ["sleep 9\necho all\n", ""]);
    let list = hub.typed(b":list\n");
    assert_eq!(list.len(), 2, "{list:?}");
    assert!(list[0].contains(A) && list[0].contains("selected") && list[0].ends_with("connecting"), "{list:?}");
    assert!(list[1].contains(B) && !list[1].contains("selected") && list[1].ends_with("ended with 0"), "{list:?}");
    let said = hub.typed(format!(":only {B}\n").as_bytes());
    assert_eq!(said, [format!("{B}: it has ended, and takes no line"), "0 of 2 hosts take the lines".to_string()]);
    let said = hub.ended(0, &Ended::Failed("no route".into()));
    assert_eq!(said, [format!("{A}: no session; the broadcast goes on without it")]);
}

#[test]
fn a_colon_line_is_for_podssh_and_two_colons_send_one() {
    let (mut hub, feeds) = fed(&[A], false);
    let said = hub.typed(b":rm -rf /\n");
    assert!(said[0].starts_with(":rm -rf / is not a command"), "{said:?}");
    assert!(hub.typed(b"::rm -rf x\n").is_empty());
    assert_eq!(got(&feeds), [":rm -rf x\n"]);
    assert_eq!(hub.typed(b":all now\n"), [":all takes no other word"]);
    assert!(hub.typed(b":help\n").iter().any(|l| l.contains(":only HOST...")));
    assert!(hub.typed(b":\n").iter().any(|l| l.contains("the emergency stop")), ": alone is :help");
    assert_eq!(hub.typed(b":intr\n"), ["signal INT to 1 hosts; a server may ignore it"]);
    assert_eq!(got(&feeds), [""], "no command sent a byte");
}

#[test]
fn with_confirm_a_line_for_two_hosts_waits_for_a_second_enter() {
    let (mut hub, feeds) = fed(&[A, B], true);
    assert_eq!(hub.typed(b"touch one\n"), ["this line goes to 2 hosts: Enter sends it, another line drops it"]);
    assert_eq!(got(&feeds), ["", ""]);
    let said = hub.typed(b"touch two\n");
    assert_eq!(said[0], "the line that waited for a second Enter is not sent");
    assert!(hub.typed(b"\n").is_empty());
    assert_eq!(got(&feeds), ["touch two\n", "touch two\n"]);
    // For one host, no wait.
    hub.typed(format!(":only {A}\n").as_bytes());
    assert!(hub.typed(b"touch solo\n").is_empty());
    assert_eq!(got(&feeds), ["touch solo\n", ""]);
}

#[test]
fn a_host_whose_queue_is_full_leaves_the_selection_with_a_word() {
    let (mut hub, feeds) = fed(&[A, B], false);
    // 1024 bytes with the newline; A reads as they come, B reads nothing.
    let line = format!("# {}\n", "x".repeat(1021));
    for _ in 0..QUEUE / line.len() {
        assert!(hub.typed(line.as_bytes()).is_empty());
        feeds[0].take();
    }
    assert_eq!(feeds[1].held(), QUEUE);
    let said = hub.typed(line.as_bytes());
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].starts_with(&format!("{B}: its queue is full ({QUEUE} bytes wait for it)")), "{said:?}");
    assert_eq!(feeds[1].held(), QUEUE, "the line did not go to it");
    assert_eq!(String::from_utf8(feeds[0].take()).unwrap(), line, "the other host took it");
    assert!(hub.typed(b"echo next\n").is_empty(), "B left the selection: no word again");
    assert_eq!((String::from_utf8(feeds[0].take()).unwrap(), feeds[1].held()), ("echo next\n".to_string(), QUEUE));
    hub.typed(b":all\n");
    assert_eq!(hub.typed(b"echo again\n").len(), 1, "taken back while full, it leaves again");
    assert_eq!(hub.missed(), [format!("{B}: lines that did not reach it because its queue was full: 2")]);
}

#[test]
fn the_stop_clears_the_selection_what_waits_and_a_half_line_at_once() {
    let (mut hub, feeds) = fed(&[A, B], false);
    hub.typed(b"touch queued\ntouch ha");
    let dropped = 2 * "touch queued\n".len() + "touch ha".len() + 3;
    let said = hub.stop(3);
    assert_eq!(said.len(), 2, "{said:?}");
    assert_eq!(said[0], "broadcast stopped; :all starts it again");
    assert_eq!(said[1], format!("{dropped} bytes that waited were dropped"));
    assert_eq!(got(&feeds), ["", ""]);
    // The rest of the half line is a line of its own, and goes to no host.
    let said = hub.typed(b"lf\n");
    assert!(said[0].starts_with("no host is selected"), "{said:?}");
    hub.typed(b":all\ntouch after\n");
    assert_eq!(got(&feeds), ["touch after\n", "touch after\n"]);
    assert_eq!(hub.stop(0), ["broadcast stopped; :all starts it again"], "nothing waited");
    // A line that waits for its second Enter goes too.
    let (mut hub, feeds) = fed(&[A, B], true);
    hub.typed(b"reboot\n");
    assert_eq!(hub.stop(0).len(), 2);
    assert!(hub.typed(b"\n")[0].starts_with("no host is selected"));
    assert_eq!(got(&feeds), ["", ""]);
}

#[test]
fn the_end_sends_a_last_line_and_drops_one_that_waits() {
    let (mut hub, feeds) = fed(&[A], false);
    hub.typed(b"exit 3");
    assert!(hub.end().is_empty());
    assert_eq!(got(&feeds), ["exit 3\n"]);
    assert_eq!(feeds[0].put(b"late\n"), 0, "the feed has ended");
    let (mut hub, feeds) = fed(&[A, B], true);
    hub.typed(b"touch x\n");
    assert_eq!(hub.end(), ["the line that waited for a second Enter is not sent"]);
    assert_eq!(got(&feeds), ["", ""]);
    assert!(hub.ended(0, &Ended::Status(0)).is_empty(), "after the end of the input, an end says nothing");
}

#[test]
fn a_line_longer_than_the_queue_goes_to_no_host() {
    let (mut hub, feeds) = fed(&[A], false);
    let said = hub.typed(&vec![b'y'; QUEUE + 1]);
    assert!(said[0].starts_with("a line of more than 64 KiB goes to no host"), "{said:?}");
    assert!(hub.typed(b"yyy\necho ok\n").is_empty());
    assert_eq!(got(&feeds), ["echo ok\n"], "the rest of the long line went with it");
    let mut line = vec![b'z'; QUEUE];
    line.push(b'\n');
    assert_eq!(hub.typed(&line), ["a line of more than 64 KiB goes to no host"]);
    assert_eq!(got(&feeds), [""]);
}
