use super::*;

const NOW: i64 = 1_790_000_000_000;
/// A fingerprint as `ssh-keygen -l` prints one.
const KEY: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
const OTHER: &str = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s";

fn host(n: u8) -> String {
    host_id(&format!("user{n}"), b"host key")
}

/// The text that a record gives is read back to the same record.
#[test]
fn the_file_reads_back_what_it_kept() {
    let mut record = Accepted::default();
    assert!(record.took(&host(1), KEY, NOW));
    assert!(record.took(&host(2), OTHER, NOW - 5));
    let text = record.text();
    assert!(text.starts_with("podssh accepted keys 1\n"), "{text}");
    assert!(text.contains(&format!("{} {KEY} {NOW}\n", host(1))), "{text}");
    assert_eq!(Accepted::read(&text, NOW), Ok(record.clone()));
    assert_eq!(record.key(&host(1)), Some(KEY));
    assert_eq!(record.key(&host(3)), None);
}

/// A host's id is the hash of its user and its host key, and names neither;
/// each pair has its own, whatever bytes they hold.
#[test]
fn a_host_s_id_names_no_host_and_no_user() {
    let id = host_id("alice", b"key of the host");
    assert_eq!(id.len(), 64);
    assert!(!id.contains("alice"));
    assert_eq!(id, host_id("alice", b"key of the host"), "the same pair, the same id");
    assert_ne!(id, host_id("bob", b"key of the host"));
    assert_ne!(id, host_id("alice", b"another key"));
    assert_ne!(host_id("ab", b"c"), host_id("a", b"bc"), "the framing keeps the parts apart");
}

/// The same key within a day is not written again; another key is, and so
/// is the same one a day later; a refusal forgets the host.
#[test]
fn a_key_is_written_when_it_changed_aged_or_was_refused() {
    let mut record = Accepted::default();
    assert!(record.took(&host(1), KEY, NOW));
    assert!(!record.took(&host(1), KEY, NOW + 1000), "the same key within the day");
    assert!(record.took(&host(1), OTHER, NOW + 2000), "another key");
    assert!(record.took(&host(1), OTHER, NOW + 2000 + REFRESH_MS), "a day later");
    assert!(record.forget(&host(1)));
    assert!(!record.forget(&host(1)), "nothing left to forget");
    assert!(!record.took("not an id", KEY, NOW));
    assert!(!record.took(&host(1), "MD5:aa:bb", NOW), "only a fingerprint of SHA-256");
}

/// Past [`MOST`], the host that took its key longest ago goes.
#[test]
fn the_hosts_are_bounded() {
    let mut record = Accepted::default();
    for i in 0..=MOST as i64 {
        record.took(&host_id(&format!("u{i}"), b"k"), KEY, NOW + i);
    }
    assert_eq!(record.hosts.len(), MOST);
    assert_eq!(record.key(&host_id("u0", b"k")), None, "the oldest went");
    assert_eq!(Accepted::read(&record.text(), NOW + 1000).map(|r| r.hosts.len()), Ok(MOST));
}

/// A key older than [`MAX_AGE_MS`] is not read.
#[test]
fn an_old_key_is_forgotten() {
    let text = format!("{HEADER}\n{} {KEY} {}\n{} {OTHER} {}\n", host(1), NOW - MAX_AGE_MS - 1, host(2), NOW - 1);
    let record = Accepted::read(&text, NOW).expect("the file reads");
    assert_eq!(record.key(&host(1)), None);
    assert_eq!(record.key(&host(2)), Some(OTHER));
}

/// A file that does not read is refused whole, with why.
#[test]
fn a_file_that_does_not_read_is_refused_whole() {
    let id = host(1);
    for (text, why) in [
        (String::new(), "first line"),
        ("podssh tls groups 1\n".to_string(), "first line"),
        (format!("{HEADER}\n{id} {KEY}\n"), "line 2"),
        (format!("{HEADER}\n{id} {KEY} 1\n{id} {KEY} soon\n"), "line 3"),
        (format!("{HEADER}\nNOTHEX {KEY} 1\n"), "line 2"),
        (format!("{HEADER}\n{id} SHA256:has space 1\n"), "line 2"),
    ] {
        let refused = Accepted::read(&text, NOW).expect_err(&text);
        assert!(refused.contains(why), "{text:?}: {refused}");
    }
}

/// A file that takes its time to read, as a slow disk does: each change that
/// starts while another reads would read the old text.
struct Slow(std::sync::Mutex<Option<String>>);

impl KeptFile for Slow {
    fn load(&self) -> Option<String> {
        let text = self.0.lock().unwrap().clone();
        std::thread::sleep(std::time::Duration::from_millis(30));
        text
    }

    fn store(&self, text: &[u8]) {
        *self.0.lock().unwrap() = Some(String::from_utf8_lossy(text).into_owned());
    }
}

/// Logins at once in one process (the hosts of `podssh each`) each keep
/// their host's key: no change is lost to another's write. The only test
/// of this binary that gives the run its file.
#[test]
fn changes_at_once_in_one_process_each_stay() {
    assert!(keep_in(Box::new(Slow(std::sync::Mutex::new(None)))), "no other test gives the run a file");
    let threads: Vec<_> =
        (1..=6).map(|n| std::thread::spawn(move || took(&host(n), if n % 2 == 0 { KEY } else { OTHER }))).collect();
    for thread in threads {
        thread.join().unwrap();
    }
    refused(&host(6));
    for n in 1..=5 {
        assert_eq!(last(&host(n)), Ok(Some((if n % 2 == 0 { KEY } else { OTHER }).to_string())), "host {n}");
    }
    assert_eq!(last(&host(6)), Ok(None), "the refusal is kept too");
}
