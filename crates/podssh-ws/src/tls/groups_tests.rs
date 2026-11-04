use std::sync::{Arc, Mutex};

use super::*;

const NOW: i64 = 1_790_000_000_000;
/// P-256's number in TLS's registry of groups, and X25519's.
const P256: u16 = 23;
const X25519: u16 = 29;

/// A file of the test's memory, as the cache would keep it.
#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Option<String>>>);

impl GroupFile for Memory {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }

    fn store(&self, text: &[u8]) {
        *self.0.lock().unwrap() = Some(String::from_utf8_lossy(text).into_owned());
    }
}

/// The text that one group gives is read back to the same groups; a name
/// is kept as DNS compares it.
#[test]
fn the_file_reads_back_what_it_kept() {
    let mut groups = Groups::default();
    assert!(groups.took("Relay.Example.", P256, NOW));
    assert!(groups.took("2001:db8::1", X25519, NOW - 5));
    let text = groups.text();
    assert!(text.starts_with("podssh tls groups 1\n"), "{text}");
    assert!(text.contains("relay.example 23 1790000000000\n"), "{text}");
    assert_eq!(Groups::read(&text, NOW), Ok(groups.clone()));
    assert_eq!(groups.group("RELAY.example"), Some(P256));
    assert_eq!(groups.group("other.example"), None);
}

/// The same group within a day is not written again; another group is, and
/// so is the same one a day later.
#[test]
fn a_group_is_written_when_it_changed_or_aged() {
    let mut groups = Groups::default();
    assert!(groups.took("relay.example", P256, NOW));
    assert!(!groups.took("relay.example", P256, NOW + 1000), "the same group within the day");
    assert!(groups.took("relay.example", X25519, NOW + 2000), "another group");
    assert!(groups.took("relay.example", X25519, NOW + 2000 + REFRESH_MS), "a day later");
    assert!(!groups.took("a name with spaces", P256, NOW), "a name that no line could hold");
}

/// Past [`MOST`], the server that took its group longest ago goes, also from
/// a file that holds more.
#[test]
fn the_servers_are_bounded() {
    let mut groups = Groups::default();
    for i in 0..=MOST as i64 {
        groups.took(&format!("h{i}.example"), P256, NOW + i);
    }
    assert_eq!(groups.servers.len(), MOST);
    assert_eq!(groups.group("h0.example"), None, "the oldest went");
    let mut text = groups.text();
    text.push_str("h0.example 23 1790000000001\nlate.example 23 1790000009999\n");
    let read = Groups::read(&text, NOW + 10_000).expect("the file reads");
    assert_eq!(read.servers.len(), MOST);
    assert_eq!(read.group("late.example"), Some(P256));
}

/// A group older than [`MAX_AGE_MS`] is not read.
#[test]
fn an_old_group_is_forgotten() {
    let text = format!("{HEADER}\nold.example 23 {}\nnew.example 23 {}\n", NOW - MAX_AGE_MS - 1, NOW - 1);
    let groups = Groups::read(&text, NOW).expect("the file reads");
    assert_eq!(groups.group("old.example"), None);
    assert_eq!(groups.group("new.example"), Some(P256));
}

/// A file that does not read is refused whole, with why.
#[test]
fn a_file_that_does_not_read_is_refused_whole() {
    for (text, why) in [
        ("", "first line"),
        ("not the format\n", "first line"),
        ("podssh tls groups 1\nrelay.example 23\n", "line 2"),
        ("podssh tls groups 1\nok.example 23 1\nrelay.example x 1\n", "line 3"),
        ("podssh tls groups 1\nrelay.example 23 soon\n", "line 2"),
        ("podssh tls groups 1\nrelay/example 23 1\n", "line 2"),
        ("podssh tls groups 1\nrelay.example 65536 1\n", "line 2"),
    ] {
        let refused = Groups::read(text, NOW).expect_err(text);
        assert!(refused.contains(why), "{text:?}: {refused}");
    }
}

/// A run's groups come from its file, and go to it when a server took
/// another; a later run with the same file reads them.
#[test]
fn a_later_run_reads_the_group_that_a_run_kept() {
    let file = Memory::default();
    let first = Kept::new();
    assert_eq!(first.group("relay.example"), None, "no file, no group");
    assert!(first.keep_in(Box::new(file.clone())));
    assert!(!first.keep_in(Box::new(Memory::default())), "the first file stays");
    first.took("relay.example", P256);
    assert!(file.load().is_some_and(|text| text.contains("relay.example 23 ")));
    let later = Kept::new();
    later.keep_in(Box::new(file.clone()));
    assert_eq!(later.group("relay.example"), Some(P256));
    assert_eq!(later.take_note(), None);
}

/// A file that does not read gives no group and a note, once; the next
/// group taken writes the file again in the format.
#[test]
fn a_file_set_aside_is_said_once_and_made_again() {
    let file = Memory(Arc::new(Mutex::new(Some("garbage".into()))));
    let kept = Kept::new();
    kept.keep_in(Box::new(file.clone()));
    assert_eq!(kept.group("relay.example"), None);
    let note = kept.take_note().expect("a note");
    assert!(note.contains("set aside") && note.contains("first line"), "{note}");
    assert_eq!(kept.take_note(), None, "said once");
    kept.took("relay.example", P256);
    assert!(file.load().is_some_and(|text| text.starts_with(HEADER)));
}

/// A group taken before the file was given is kept over the file's.
#[test]
fn a_group_of_this_process_wins_over_the_file() {
    let file = Memory(Arc::new(Mutex::new(Some(format!("{HEADER}\nrelay.example {X25519} {}\n", now_ms())))));
    let kept = Kept::new();
    kept.took("relay.example", P256);
    kept.keep_in(Box::new(file));
    assert_eq!(kept.group("relay.example"), Some(P256));
    let shown = format!("{kept:?}");
    assert!(shown.contains("servers: 1") && !shown.contains("relay.example"), "{shown}");
}
