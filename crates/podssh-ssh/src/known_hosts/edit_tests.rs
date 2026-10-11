use std::path::PathBuf;

use russh::keys::ssh_key::PrivateKey;
use russh::keys::{Algorithm, PublicKey};

use super::*;

fn key() -> PublicKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap().public_key().clone()
}

fn line(key: &PublicKey) -> String {
    PublicKey::new(key.key_data().clone(), "").to_openssh().unwrap()
}

/// The file of the measurement of OpenSSH for Windows 10.0p2's `ssh-keygen`
/// (2026-10-11), with a CRLF line, spacing that a rewrite must keep, a line
/// that is not UTF-8 and a last line with no line end.
fn sample() -> (Vec<u8>, [PublicKey; 6]) {
    let keys = [key(), key(), key(), key(), key(), key()];
    let k: Vec<String> = keys.iter().map(line).collect();
    let mut text = Vec::new();
    text.extend_from_slice(b"# a comment line\n");
    text.extend_from_slice(format!("one.example {}\n", k[0]).as_bytes());
    text.extend_from_slice(format!("two.example,2.example,192.0.2.2 {} a comment\n", k[1]).as_bytes());
    text.extend_from_slice(format!("[three.example]:2222 {}\r\n", k[2]).as_bytes());
    text.extend_from_slice(format!("*.wild.example {}\n", k[3]).as_bytes());
    text.extend_from_slice(b"\n");
    text.extend_from_slice(format!("@cert-authority *.ca.example {}\n", k[4]).as_bytes());
    text.extend_from_slice(format!("@revoked one.example {}\n", k[5]).as_bytes());
    text.extend_from_slice(b"not a key line \xff\n");
    text.extend_from_slice(format!("one.example {}\n", k[4]).as_bytes());
    text.extend_from_slice(format!("!neg.wild.example,*.neg.example {}\n", k[2]).as_bytes());
    text.extend_from_slice(format!("  Indented.Example   {}   spaced comment  ", k[2]).as_bytes());
    (text, keys)
}

fn counter() -> impl FnMut() -> [u8; 20] {
    let mut n = 0u8;
    move || {
        n += 1;
        [n; 20]
    }
}

/// The lines that `ssh-keygen -F` printed for each host, by number and
/// marker; the line itself as the file has it.
#[test]
fn find_finds_what_openssh_found() {
    let (text, _) = sample();
    let found = |host: &str| -> Vec<(usize, Option<Marker>)> {
        find(&text, host, &mut counter()).iter().map(|f| (f.line, f.marker)).collect()
    };
    assert_eq!(found("one.example"), [(2, None), (8, Some(Marker::Revoked)), (10, None)]);
    assert_eq!(found("ONE.EXAMPLE"), [(2, None), (8, Some(Marker::Revoked)), (10, None)]);
    assert_eq!(found("192.0.2.2"), [(3, None)]);
    assert_eq!(found("[three.example]:2222"), [(4, None)]);
    assert_eq!(found("three.example"), []);
    assert_eq!(found("x.wild.example"), [(5, None)]);
    assert_eq!(found("a.ca.example"), [(7, Some(Marker::CertAuthority))]);
    assert_eq!(found("neg.wild.example"), [(5, None)], "a negated pattern rejects its line");
    assert_eq!(found("a.neg.example"), [(11, None)]);
    assert_eq!(found("indented.example"), [(12, None)]);
    let two = find(&text, "2.example", &mut counter());
    assert!(
        two[0].text.starts_with("two.example,2.example,192.0.2.2 ssh-ed25519 ") && two[0].text.ends_with(" a comment")
    );
    // -F -H: each name of the line on a line of its own; a wildcard line as
    // it is.
    assert_eq!(two[0].hashed.len(), 3);
    assert!(two[0].hashed.iter().all(|l| l.starts_with("|1|") && l.ends_with(" a comment")));
    assert!(matches(two[0].hashed[1].split(' ').next().unwrap(), "2.example"));
    let wild = find(&text, "x.wild.example", &mut counter());
    assert_eq!(wild[0].hashed, [wild[0].text.clone()]);
}

/// `-R` removes the plain lines of the host and keeps every other line byte
/// for byte: comments, a blank line, a CRLF line, spacing, a line that is
/// not UTF-8, the marked lines, and the last line with no line end.
#[test]
fn remove_keeps_every_other_line_byte_for_byte() {
    let (text, _) = sample();
    let removed = remove(&text, "one.example");
    assert_eq!(removed.removed, [2, 10]);
    assert_eq!(removed.other, [9]);
    let want: Vec<u8> = lines(&text)
        .iter()
        .filter(|l| l.number != 2 && l.number != 10)
        .flat_map(|l| l.text.iter().chain(l.end.iter()).copied())
        .collect();
    assert_eq!(removed.text.unwrap(), want);
    let removed = remove(&text, "Indented.Example");
    assert_eq!(removed.removed, [12]);
    let left = removed.text.unwrap();
    assert!(
        left.ends_with(
            b"
"
        ) && !left.windows(8).any(|w| w == b"Indented"),
        "the last line, with no line end"
    );
    // A wildcard line is kept, and said; a missing host changes nothing.
    let wild = remove(&text, "x.wild.example");
    assert_eq!((wild.removed.len(), wild.kept.len(), wild.text.is_none()), (0, 1, true));
    assert_eq!(wild.kept[0], (5, "*.wild.example".to_string()));
    assert!(remove(&text, "missing.example").text.is_none());
    assert!(remove(&text, "a.ca.example").text.is_none(), "a @cert-authority line stays");
}

/// `-H` hashes each name on a line of its own, and keeps the rest; podssh's
/// lookup finds each name hashed, in any case.
#[test]
fn hash_hashes_each_name_and_lookups_find_it() {
    let (text, keys) = sample();
    let hashed = hash(&text, &mut counter());
    assert_eq!(hashed.names, 7, "one, two, 2, 192.0.2.2, [three]:2222, one again, Indented");
    assert_eq!(
        hashed.wildcard,
        [
            (5, "*.wild.example".to_string()),
            (7, "*.ca.example".to_string()),
            (11, "!neg.wild.example,*.neg.example".to_string())
        ]
    );
    assert_eq!(hashed.other, [9]);
    let new = hashed.text.unwrap();
    let new_text = String::from_utf8_lossy(&new);
    assert!(new_text.starts_with("# a comment line\n|1|"));
    let other: &[u8] = b"not a key line \xff\n";
    assert!(new.windows(other.len()).any(|w| w == other), "the line that is not UTF-8 stays");
    assert!(new_text.contains(&format!("@revoked one.example {}\n", line(&keys[5]))), "a marked line stays");
    assert!(new_text.contains("\r\n"), "a CRLF line keeps its line end");
    assert!(new_text.ends_with("   spaced comment  \n"), "the comment keeps its spacing");
    for host in ["one.example", "two.example", "2.example", "192.0.2.2", "[three.example]:2222", "indented.example"] {
        assert!(!find(&new, host, &mut counter()).is_empty(), "{host} is not found once hashed");
    }
    let lookup = |host: &str, k: &PublicKey| {
        let raw = new.clone();
        let entries = super::super::parse_entries(std::path::Path::new("kh"), &raw, host);
        entries.iter().any(|e| e.key == *k)
    };
    assert!(lookup("one.example", &keys[0]) && lookup("192.0.2.2", &keys[1]) && lookup("INDENTED.example", &keys[2]));
    // Hashed again: nothing left to hash.
    assert!(hash(&new, &mut counter()).text.is_none());
}

/// The hash of OpenSSH for Windows 10.0p2's `ssh-keygen -H` for the name
/// "Two.Example" (2026-10-11): HMAC-SHA1 of the name in lower case.
#[test]
fn a_name_hashes_as_openssh_hashes_it() {
    let engine = base64::engine::general_purpose::STANDARD;
    let salt: [u8; 20] = engine.decode("K5QM+M4kagFCR2wK/XH4Q8oWotk=").unwrap().try_into().unwrap();
    let want = "|1|K5QM+M4kagFCR2wK/XH4Q8oWotk=|4Zyq5SxKlrzouYKDel2EBFCEbIw=";
    assert_eq!(hash_name("Two.Example", &salt), want);
    assert_eq!(hash_name("two.example", &salt), want);
}

fn create(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-kh-edit-{tag}-{:016x}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A rewrite keeps the old text in `FILE.old` and puts the new one in place;
/// with nothing to change, nothing is written.
#[test]
fn a_rewrite_keeps_the_old_text() {
    let dir = scratch("old");
    let path = dir.join("known_hosts");
    let (text, _) = sample();
    std::fs::write(&path, &text).unwrap();
    let (done, removed) = rewrite(&path, create, |raw| {
        let removed = remove(raw, "one.example");
        (removed.text.clone(), removed)
    })
    .unwrap();
    let done = done.unwrap();
    assert_eq!(std::fs::read(&done.old).unwrap(), text);
    assert_eq!(std::fs::read(&path).unwrap(), removed.text.unwrap());
    let (none, ()) = rewrite(&path, create, |_| (None, ())).unwrap();
    assert!(none.is_none());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2, "a file was left beside it");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A run of `podssh ssh` that waited for the lock while the file was
/// rewritten puts its line in the new file, not in the one replaced (the
/// pitfall of T-019; T-029).
#[test]
fn an_append_that_waited_reaches_the_new_file() {
    let dir = scratch("race");
    let path = dir.join("known_hosts");
    let (text, _) = sample();
    std::fs::write(&path, &text).unwrap();
    let new_key = key();
    let (done, waiter) = rewrite(&path, create, |raw| {
        let (path, new_key) = (path.clone(), new_key.clone());
        // The rewrite holds the lock: this append waits for it.
        let waiter = std::thread::spawn(move || super::super::append(&path, "late.example", &new_key));
        std::thread::sleep(std::time::Duration::from_millis(300));
        (remove(raw, "one.example").text, waiter)
    })
    .unwrap();
    assert!(done.is_some());
    let recorded = waiter.join().unwrap().unwrap();
    assert!(matches!(recorded, super::super::Recorded::Written { locked: true }), "{recorded:?}");
    let now = std::fs::read(&path).unwrap();
    assert_eq!(find(&now, "late.example", &mut counter()).len(), 1, "the line went to the file replaced");
    assert!(find(&now, "one.example", &mut counter()).iter().all(|f| f.marker.is_some()));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// On Unix a link stays a link, and its target is rewritten.
#[cfg(unix)]
#[test]
fn a_link_stays_a_link() {
    let dir = scratch("link");
    let target = dir.join("real");
    let (text, _) = sample();
    std::fs::write(&target, &text).unwrap();
    let link = dir.join("known_hosts");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    rewrite(&link, create, |raw| (remove(raw, "one.example").text, ())).unwrap();
    assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert!(find(&std::fs::read(&target).unwrap(), "one.example", &mut counter()).iter().all(|f| f.marker.is_some()));
    std::fs::remove_dir_all(&dir).unwrap();
}
