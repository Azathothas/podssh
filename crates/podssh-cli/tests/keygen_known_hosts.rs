//! `podssh keygen -F`, `-R` and `-H` as a process (T-019): the lines and
//! the messages of OpenSSH's `ssh-keygen`, and the files that `-R` and `-H`
//! leave. OpenSSH itself checks them in `scripts/interop-keygen.sh`.

mod cleanup;
mod keygen_support;

use std::path::Path;

use keygen_support::*;

/// A `known_hosts` file of the lines that OpenSSH's `ssh-keygen -F`, `-R`
/// and `-H` were measured on (T-019), and its keys.
fn known_hosts_file(dir: &Path) -> (String, String, Vec<String>) {
    let keys: Vec<String> = (0..3)
        .map(|_| {
            let key = podssh_ssh::keygen::generate(podssh_ssh::keygen::KeyKind::Ed25519, "").unwrap();
            key_part(&key.public_key().to_openssh().unwrap())
        })
        .collect();
    let text = format!(
        "# a comment line\none.example {0}\ntwo.example,2.example {1} a comment\n[three.example]:2222 {2}\n\
         *.wild.example {1}\n@revoked one.example {2}\n",
        keys[0], keys[1], keys[2]
    );
    let path = file(dir, "known_hosts");
    std::fs::write(&path, &text).unwrap();
    (path, text, keys)
}

/// `-F` prints the lines of `ssh-keygen -F`: a line that says where, with a
/// space before the marker even when there is none, then the line; `-q`
/// the lines alone, `-H` each name hashed; exit 1 when no line names it.
#[test]
fn known_hosts_find_prints_the_lines_of_openssh() {
    let dir = scratch();
    let (kh, _, keys) = known_hosts_file(&dir);
    let run = podssh(&["keygen", "-F", "one.example", "-f", &kh]);
    assert_eq!(run.code, 0, "{}", run.err);
    let want = format!(
        "# Host one.example found: line 2 \none.example {}\n# Host one.example found: line 6 REVOKED\n\
         @revoked one.example {}\n",
        keys[0], keys[2]
    );
    assert_eq!(run.out, want);
    let run = podssh(&["keygen", "-q", "-F", "2.example", "-f", &kh]);
    assert_eq!(run.out, format!("two.example,2.example {} a comment\n", keys[1]));
    let run = podssh(&["keygen", "-F", "2.example", "-H", "-f", &kh]);
    let hashed: Vec<&str> = run.out.lines().skip(1).collect();
    assert_eq!(hashed.len(), 2, "one line for each name: {}", run.out);
    assert!(hashed.iter().all(|l| l.starts_with("|1|") && l.ends_with(" a comment")), "{}", run.out);
    let run = podssh(&["keygen", "-F", "three.example", "-f", &kh]);
    assert_eq!((run.code, run.out.as_str()), (1, ""));
    let run = podssh(&["keygen", "-F", "three.example:2222", "-f", &kh]);
    assert_eq!(run.code, 1);
    assert!(run.err.contains("[three.example]:2222"), "{}", run.err);
}

/// `-R` removes the lines of the host, keeps the rest byte for byte and the
/// old text in `FILE.old`, and says what `ssh-keygen -R` says; a marked line
/// and a wildcard line stay.
#[test]
fn known_hosts_remove_keeps_the_rest_and_the_old_file() {
    let dir = scratch();
    let (kh, text, _) = known_hosts_file(&dir);
    let run = podssh(&["keygen", "-R", "one.example", "-f", &kh]);
    assert_eq!(run.code, 0, "{}", run.err);
    assert_eq!(
        run.out,
        format!("# Host one.example found: line 2\n{kh} updated.\nOriginal contents retained as {kh}.old\n")
    );
    let want: String = text.lines().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| format!("{l}\n")).collect();
    assert_eq!(std::fs::read_to_string(&kh).unwrap(), want);
    assert_eq!(std::fs::read_to_string(format!("{kh}.old")).unwrap(), text);
    let run = podssh(&["keygen", "-R", "missing.example", "-f", &kh]);
    assert_eq!((run.code, run.out.as_str()), (0, ""));
    assert_eq!(run.err, format!("Host missing.example not found in {kh}\n"));
    let run = podssh(&["keygen", "-R", "x.wild.example", "-f", &kh]);
    assert_eq!(run.code, 0);
    assert!(run.err.contains(":4: kept: x.wild.example matches its pattern *.wild.example"), "{}", run.err);
    assert_eq!(std::fs::read_to_string(&kh).unwrap(), want, "the file changed");
}

/// `-H` hashes each name, and `-F` still finds each host; the old text,
/// which holds the names, stays in `FILE.old`, as `ssh-keygen -H` warns.
#[test]
fn known_hosts_hash_hides_the_names_and_finds_them() {
    let dir = scratch();
    let (kh, text, _) = known_hosts_file(&dir);
    let run = podssh(&["keygen", "-H", "-f", &kh]);
    assert_eq!(run.code, 0, "{}", run.err);
    assert_eq!(run.out, format!("{kh} updated.\nOriginal contents retained as {kh}.old\n"));
    assert!(run.err.contains(":5: ignoring host name with wildcard: *.wild.example"), "{}", run.err);
    assert!(run.err.contains(&format!("WARNING: {kh}.old contains unhashed entries")), "{}", run.err);
    let now = std::fs::read_to_string(&kh).unwrap();
    assert!(!now.contains("two.example") && !now.contains("three.example"), "{now}");
    assert_eq!(std::fs::read_to_string(format!("{kh}.old")).unwrap(), text);
    for host in ["one.example", "two.example", "2.example", "[three.example]:2222"] {
        assert_eq!(podssh(&["keygen", "-F", host, "-f", &kh]).code, 0, "{host} is not found once hashed");
    }
    let again = podssh(&["keygen", "-H", "-f", &kh]);
    assert!(again.err.contains("no host name to hash"), "{}", again.err);
}

/// The flags that do not go together, and a missing file, are refused.
#[test]
fn known_hosts_refusals() {
    let dir = scratch();
    let (kh, _, _) = known_hosts_file(&dir);
    for args in [
        vec!["keygen", "-F", "a", "-R", "b", "-f", &kh],
        vec!["keygen", "-R", "a", "-H", "-f", &kh],
        vec!["keygen", "-F", "a", "-y", "-f", &kh],
        vec!["keygen", "-H", "-p", "-f", &kh],
    ] {
        assert_eq!(podssh(&args).code, 64, "{args:?}");
    }
    let missing = file(&dir, "none");
    let run = podssh(&["keygen", "-F", "a", "-f", &missing]);
    assert_eq!(run.code, 1);
    assert!(run.err.contains("no such file"), "{}", run.err);
}
