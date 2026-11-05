//! The share file (T-433) with no node: its lines, a change that keeps what
//! it does not touch, two changes at once that both count under the lock,
//! and a lock held too long that fails the change with 75.

use std::path::PathBuf;

use super::file::{self, Place, Share, Shares};
use crate::exitmap::sysexits;
use crate::relay_settings::Refusal;

/// A private directory of its own for a test, as the node refuses a share
/// file that others may change.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-share-{tag}-{}-{nanos}", std::process::id()));
    podssh_relay::cache::private_dir(&dir).expect("a private scratch directory");
    dir
}

/// A share as `add` makes it.
fn share(name: &str, port: u16) -> Share {
    Share { name: name.into(), host: "127.0.0.1".into(), port }
}

#[test]
fn a_share_is_a_route_s_name_and_a_tcp_target() {
    assert_eq!(Share::parse("web=127.0.0.1:8080"), Ok(share("web", 8080)));
    let v6 = Share::parse("db=[::1]:5432").unwrap();
    assert_eq!((v6.host.as_str(), v6.port, v6.line()), ("::1", 5432, "db=[::1]:5432".to_string()));
    assert_eq!(share("web", 8080).route().name.as_deref(), Some("web"));
    for (word, says) in [
        ("web", "is not NAME=HOST:PORT"),
        ("-web=127.0.0.1:80", "is not a share's name"),
        ("a/b=127.0.0.1:80", "is not a share's name"),
        ("dns=udp:127.0.0.1:53", "a share is a TCP service"),
        ("web=127.0.0.1", "missing PORT"),
        ("web=127.0.0.1:0", "is not a port"),
    ] {
        let why = Share::parse(word).expect_err(word);
        assert!(why.contains(says), "{word}: {why}");
    }
}

#[test]
fn a_file_s_comments_and_bad_lines_are_known_and_a_name_counts_once() {
    let text = "# the lab\n\nweb=127.0.0.1:8080\nnot a share\nweb=127.0.0.1:9090\n  db=127.0.0.1:5432  \n";
    let shares = Shares::parse(text);
    assert_eq!(shares.list, vec![share("web", 8080), share("db", 5432)], "the first line of a name counts");
    assert_eq!(shares.bad, vec![4, 5]);
    assert_eq!(shares.names(), "web, db");
    let many: String = (0..file::MAX_SHARES + 1).map(|n| format!("s{n}=127.0.0.1:{}\n", 1000 + n)).collect();
    let bounded = Shares::parse(&many);
    assert_eq!((bounded.list.len(), bounded.bad.len()), (file::MAX_SHARES, 1), "a share past the bound serves nothing");
}

#[test]
fn a_change_keeps_each_line_that_it_does_not_touch() {
    let (first, before) = file::with_share("", &share("web", 8080));
    assert!(before.is_none());
    assert!(first.starts_with('#') && first.ends_with("web=127.0.0.1:8080\n"), "{first}");
    let mine = "# mine\nweb=127.0.0.1:8080\nnot a share\nweb=127.0.0.1:1\n";
    let (moved, before) = file::with_share(mine, &share("web", 9090));
    assert_eq!(before, Some(share("web", 8080)));
    let later = "a later line of the name goes, as it served nothing";
    assert_eq!(moved, "# mine\nweb=127.0.0.1:9090\nnot a share\n", "{later}");
    let (added, before) = file::with_share(mine, &share("db", 5432));
    assert!(before.is_none());
    assert_eq!(added, format!("{mine}db=127.0.0.1:5432\n"));
    let (gone, was) = file::without(mine, "web");
    assert_eq!((gone.as_str(), was), ("# mine\nnot a share\n", Some(share("web", 8080))));
    let (same, was) = file::without(mine, "db");
    assert_eq!((same.as_str(), was), (mine, None));
}

#[test]
fn an_edit_keeps_the_file_whole_and_a_node_reads_it_again() {
    let dir = scratch("edit");
    let place = Place::File(dir.join("lab.shares"));
    assert_eq!(file::read(&place), Ok(None), "no file: no share");
    let add = |s: Share| file::edit(&place, move |text| Ok((Some(file::with_share(text, &s).0), ())));
    add(share("web", 8080)).unwrap();
    add(share("db", 5432)).unwrap();
    let (path, text) = file::read(&place).unwrap().expect("the file");
    assert_eq!(path, dir.join("lab.shares"));
    assert_eq!(Shares::parse(&text).list, vec![share("web", 8080), share("db", 5432)]);
    // A change that changes nothing writes nothing.
    let unchanged = file::edit(&place, |_| Ok((None, "said")));
    assert_eq!(unchanged.map(|(_, said)| said), Ok("said"));
    // A refusal of the change leaves the file as it was.
    let refused = file::edit(&place, |_| Err::<(Option<String>, ()), _>(Refusal::usage("no")));
    assert_eq!(refused.map(|_| ()), Err(Refusal::usage("no")));
    assert_eq!(file::read(&place).unwrap().map(|(_, t)| t), Some(text));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two changes at once, each of many shares: each counts, as each reads the
/// file again under the lock. Without it, one would write over the other.
#[test]
fn two_changes_at_once_both_count_under_the_lock() {
    let dir = scratch("lock");
    let place = Place::File(dir.join("lab.shares"));
    let each = |base: u16, prefix: &'static str| {
        let place = place.clone();
        std::thread::spawn(move || {
            for n in 0..40u16 {
                let s = share(&format!("{prefix}{n}"), base + n);
                file::edit(&place, move |text| Ok((Some(file::with_share(text, &s).0), ()))).expect("an edit");
            }
        })
    };
    let (a, b) = (each(2000, "a"), each(3000, "b"));
    a.join().unwrap();
    b.join().unwrap();
    let (_, text) = file::read(&place).unwrap().expect("the file");
    assert_eq!(Shares::parse(&text).list.len(), 80, "each change counts:\n{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A lock that another change keeps past the wait fails this one with 75,
/// and the file is not touched.
#[test]
fn a_lock_held_past_the_wait_fails_the_change_with_75() {
    let dir = scratch("held");
    let place = Place::File(dir.join("lab.shares"));
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("lab.shares.lock"));
    let lock = lock.expect("the lock's file");
    if lock.try_lock().is_err() {
        eprintln!("did not run: this file system takes no lock");
        return;
    }
    let start = std::time::Instant::now();
    let held = file::edit(&place, |_| Ok((Some("web=127.0.0.1:8080\n".to_string()), ())));
    match held {
        Err(refusal) => {
            assert_eq!(refusal.code, sysexits::EX_TEMPFAIL, "{}", refusal.message);
            assert!(refusal.message.contains("held its lock"), "{}", refusal.message);
        }
        Ok(_) => panic!("a change went on under another's lock"),
    }
    assert!(start.elapsed() >= file::WAIT, "it waited the whole bound first");
    assert_eq!(file::read(&place), Ok(None), "the file is not touched");
    drop(lock);
    let _ = std::fs::remove_dir_all(&dir);
}
