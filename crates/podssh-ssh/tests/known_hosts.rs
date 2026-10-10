//! `known_hosts` against files OpenSSH wrote or reads: hashed entries made by
//! `ssh-keygen -H` (OpenSSH 10.3p1, 2026-10-08), markers, bad lines, ports,
//! and appending without disturbing what is there.

mod cleanup;

use std::path::PathBuf;

use podssh_ssh::hostkey::{Offer, Policy, Verdict};
use podssh_ssh::known_hosts::{append, host_name, lookup, lookup_all, recorded_algorithms, Lookup, Recorded};
use podssh_ssh::log::Log;
use podssh_ssh::options::{LogLevel, StrictHostKeyChecking};
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::ssh_key::private::{Ed25519Keypair, PrivateKey};
use russh::keys::ssh_key::{Certificate, HashAlg, PublicKey};

const A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrY8o/Gih84gTH1Xe3+dWQIj69CTwHrBaBcbYacBdYS";
const B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFuCj635iAvbyqAVAq82WzngvdvUIT84jHdP+VKHDIxG";
const C: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIX5A9Qd4sCwGMActiYw/Zczh6DcGTiIZQ8itSiOpkRfZn5dfS8lPbzENJ1QsmzZxaRqPrm51X4QSi9WGfOUSBE=";

/// `example.org` and `[example.org]:2222`, both with key A, as `ssh-keygen -H`
/// wrote them.
const HASHED: &str = "\
|1|XM6FrlaGMCfqLfD0zsCs1B7SmNE=|lepsE8/iAQKmGYjQ/qgJbxh1Bcg= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrY8o/Gih84gTH1Xe3+dWQIj69CTwHrBaBcbYacBdYS
|1|iPOzT2ChmNBY0coDy3g0CTqlPMY=|4EdM2GBnNHVzuoWXF9JAz3LCBEs= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrY8o/Gih84gTH1Xe3+dWQIj69CTwHrBaBcbYacBdYS
";

fn key(text: &str) -> PublicKey {
    PublicKey::from_openssh(text).unwrap()
}

fn file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-kh-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    let path = dir.join("known_hosts");
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn hashed_entries_written_by_ssh_keygen_match() {
    let f = file("hashed", HASHED);
    assert!(matches!(lookup(std::slice::from_ref(&f), "example.org", &key(A)), Lookup::Known { line: 1, .. }));
    assert!(matches!(
        lookup(std::slice::from_ref(&f), &host_name("example.org", 2222), &key(A)),
        Lookup::Known { line: 2, .. }
    ));
    assert!(matches!(lookup(std::slice::from_ref(&f), "other.org", &key(A)), Lookup::Unknown));
    assert!(matches!(lookup(&[f], "example.org", &key(B)), Lookup::Changed { line: 1, .. }));
}

#[test]
fn a_revoked_key_is_refused_even_with_a_plain_entry_for_it() {
    let f = file("revoked", &format!("example.org {A}\n@revoked * {A}\n"));
    assert!(matches!(lookup(&[f], "example.org", &key(A)), Lookup::Revoked { line: 2, .. }));
}

#[test]
fn a_cert_authority_line_does_not_make_a_key_known() {
    let f = file("ca", &format!("@cert-authority example.org {A}\n"));
    assert!(matches!(lookup(&[f], "example.org", &key(A)), Lookup::Unknown));
}

#[test]
fn bad_lines_are_skipped_and_line_numbers_kept() {
    let content = format!(
        "# a comment\n\nexample.org ssh-ed25519 not-base64!!\n@unknown-marker example.org {B}\nexample.org\t  {A}  trailing comment\n"
    );
    let f = file("bad", &content);
    match lookup(&[f], "example.org", &key(A)) {
        Lookup::Known { line, .. } => assert_eq!(line, 5),
        other => panic!("{other:?}"),
    }
}

#[test]
fn other_key_types_are_reported_and_ordered_first() {
    let f = file("types", &format!("example.org {C}\n"));
    match lookup(std::slice::from_ref(&f), "example.org", &key(A)) {
        Lookup::OtherTypes(types) => assert_eq!(types, vec!["ECDSA".to_string()]),
        other => panic!("{other:?}"),
    }
    assert_eq!(recorded_algorithms(&[f], "example.org"), vec![key(C).algorithm()]);
}

#[test]
fn several_files_are_read_in_order_and_missing_ones_are_fine() {
    let missing = std::env::temp_dir().join("podssh-kh-does-not-exist").join("known_hosts");
    let f = file("second", &format!("example.org {A}\n"));
    assert!(matches!(lookup(&[missing, f], "example.org", &key(A)), Lookup::Known { .. }));
}

#[test]
fn append_keeps_what_is_there_and_adds_a_missing_newline() {
    let f = file("append", "# keep me\nnot a valid line");
    append(&f, &host_name("new.example", 2200), &key(B)).unwrap();
    let text = std::fs::read_to_string(&f).unwrap();
    assert_eq!(text, format!("# keep me\nnot a valid line\n[new.example]:2200 {B}\n"));
    assert!(matches!(lookup(&[f], "[new.example]:2200", &key(B)), Lookup::Known { line: 3, .. }));
}

#[test]
fn append_creates_the_directory_and_the_file() {
    let dir = std::env::temp_dir().join(format!("podssh-kh-{}-fresh", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    cleanup::at_test_end(&dir);
    let f = dir.join("sub").join("known_hosts");
    append(&f, "fresh.example", &key(A)).unwrap();
    assert_eq!(std::fs::read_to_string(&f).unwrap(), format!("fresh.example {A}\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

/// A new directory of its own for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-kh-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// accept-new for `example.org` with `user` as the one user file.
fn accept_new(user: &std::path::Path) -> Policy {
    Policy {
        name: "example.org".into(),
        strict: StrictHostKeyChecking::AcceptNew,
        user_files: vec![user.to_path_buf()],
        no_user_file: None,
        global_files: Vec::new(),
        batch_mode: true,
        pin: None,
        fingerprints: Vec::new(),
    }
}

/// A user file that exists and cannot be read (a directory, which fails also
/// for root): the lookup names it, and accept-new refuses an unknown key with
/// the file's name, where it once took the file as empty (T-028).
#[test]
fn an_unreadable_user_file_is_named_and_accept_new_refuses_the_key() {
    let dir = scratch("unreadable");
    let user = dir.join("known_hosts");
    std::fs::create_dir(&user).unwrap();
    let (found, unreadable) = lookup_all(std::slice::from_ref(&user), "example.org", &key(A));
    assert!(matches!(found, Lookup::Unknown), "{found:?}");
    assert_eq!(unreadable.len(), 1, "{unreadable:?}");
    assert_eq!(unreadable[0].path, user);
    let log = Log::new(LogLevel::Quiet);
    match accept_new(&user).check(&key(A), &log) {
        Verdict::Reject(why) => {
            assert!(why.contains(&user.display().to_string()), "{why}");
            assert!(why.contains("cannot be verified") && why.contains("UserKnownHostsFile"), "{why}");
        }
        Verdict::Accept => panic!("an unknown key was accepted while the user file cannot be read"),
    }
}

/// A missing user file is normal: accept-new takes the key and records it,
/// and the next lookup knows it. The null device holds nothing, and is no
/// failure: `UserKnownHostsFile /dev/null` is common.
#[test]
fn a_missing_or_null_file_is_not_unreadable() {
    let dir = scratch("missing");
    let user = dir.join(".ssh").join("known_hosts");
    let log = Log::new(LogLevel::Quiet);
    assert_eq!(accept_new(&user).check(&key(A), &log), Verdict::Accept);
    assert!(matches!(lookup(std::slice::from_ref(&user), "example.org", &key(A)), Lookup::Known { .. }));
    let null = PathBuf::from(if cfg!(windows) { "NUL" } else { "/dev/null" });
    let (found, unreadable) = lookup_all(&[null], "example.org", &key(A));
    assert!(matches!(found, Lookup::Unknown) && unreadable.is_empty(), "{found:?} {unreadable:?}");
}

/// A FIFO is not read: an open of one for reading would block for ever. It
/// is unreadable, and the lookup returns at once (T-028).
#[cfg(unix)]
#[test]
fn an_unreadable_fifo_never_blocks_the_lookup() {
    let dir = scratch("fifo");
    let fifo = dir.join("known_hosts");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|s| s.success()) {
        eprintln!("no mkfifo here; the FIFO case is not run");
        return;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(lookup_all(&[fifo], "example.org", &key(A)));
    });
    let (found, unreadable) =
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the lookup blocked on a FIFO");
    assert!(matches!(found, Lookup::Unknown), "{found:?}");
    assert_eq!(unreadable.len(), 1, "{unreadable:?}");
    assert!(unreadable[0].error.contains("not a regular file"), "{unreadable:?}");
}

/// A run records a host that another run recorded since its lookup (T-029):
/// the same key adds no line, another key of the type is refused as changed,
/// a key revoked meanwhile is refused, and a key of another type is added.
#[test]
fn recorded_meanwhile_the_same_key_adds_nothing_and_another_is_refused() {
    let f = file("meanwhile", &format!("example.org {A}\n@revoked example.org {C}\n"));
    let before = std::fs::read_to_string(&f).unwrap();
    assert!(matches!(append(&f, "example.org", &key(A)).unwrap(), Recorded::Already { line: 1 }));
    match append(&f, "example.org", &key(B)).unwrap() {
        Recorded::Changed { line, recorded } => {
            assert_eq!(line, 1);
            assert_eq!(recorded.key_data(), key(A).key_data());
        }
        other => panic!("another key of the type was not refused: {other:?}"),
    }
    assert!(matches!(append(&f, "example.org", &key(C)).unwrap(), Recorded::Revoked { line: 2 }));
    assert_eq!(std::fs::read_to_string(&f).unwrap(), before, "nothing was to be written");
    assert!(matches!(append(&f, "other.example", &key(B)).unwrap(), Recorded::Written { .. }));
    assert_eq!(std::fs::read_to_string(&f).unwrap().lines().count(), 3);
}

/// Sixteen runs record one new key at the same moment: the file gets one
/// line for it, and each other run finds it there (T-029).
#[test]
fn concurrent_append_of_one_new_key_writes_one_line() {
    let f = file("concurrent", "");
    let start = std::sync::Arc::new(std::sync::Barrier::new(16));
    let runs: Vec<_> = (0..16)
        .map(|_| {
            let (f, start) = (f.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                append(&f, "race.example", &key(A)).unwrap()
            })
        })
        .collect();
    let results: Vec<Recorded> = runs.into_iter().map(|run| run.join().unwrap()).collect();
    let written = results.iter().filter(|r| matches!(r, Recorded::Written { .. })).count();
    let already = results.iter().filter(|r| matches!(r, Recorded::Already { line: 1 })).count();
    assert_eq!((written, already), (1, 15), "{results:?}");
    let text = std::fs::read_to_string(&f).unwrap();
    assert_eq!(text.lines().filter(|l| l.starts_with("race.example ")).count(), 1, "{text}");
}

/// The lock refuses no reader: a lookup while another run holds the file's
/// lock reads it, on Windows too, where a lock of the file's bytes would
/// refuse the read (T-029).
#[test]
fn concurrent_append_never_makes_the_file_unreadable() {
    let f = file("readers", &format!("example.org {A}\n"));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let (f, stop) = (f.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut n = 0;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                append(&f, &format!("host{n}.example"), &key(B)).unwrap();
                n += 1;
            }
        })
    };
    for _ in 0..200 {
        let (found, unreadable) = lookup_all(std::slice::from_ref(&f), "example.org", &key(A));
        assert!(unreadable.is_empty(), "{unreadable:?}");
        assert!(matches!(found, Lookup::Known { line: 1, .. }), "{found:?}");
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    writer.join().unwrap();
}

/// An Ed25519 key from a seed: a test's CA or host key, the same at each run.
fn seeded(n: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[n; 32]))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// A certificate of the host key of seed `host`, signed by the CA of seed
/// `ca`, of `kind`, for `principal`, valid from `after` to `before`.
fn cert(host: u8, ca: u8, kind: CertType, principal: &str, after: u64, before: u64) -> Certificate {
    let mut builder = Builder::new([7u8; 16], seeded(host).public_key().key_data().clone(), after, before).unwrap();
    builder.cert_type(kind).unwrap();
    builder.valid_principal(principal).unwrap();
    builder.key_id("podssh-test").unwrap();
    builder.sign(&seeded(ca)).unwrap()
}

/// The `@cert-authority` line of the CA of seed `ca`, for example.org.
fn ca_line(marker: &str, ca: u8) -> String {
    format!("{marker} example.org {}\n", seeded(ca).public_key().to_openssh().unwrap())
}

/// StrictHostKeyChecking=yes for example.org with `user` as the user file.
fn strict(user: &std::path::Path) -> Policy {
    Policy {
        name: "example.org".into(),
        strict: StrictHostKeyChecking::Yes,
        user_files: vec![user.to_path_buf()],
        no_user_file: None,
        global_files: Vec::new(),
        batch_mode: true,
        pin: None,
        fingerprints: Vec::new(),
    }
}

fn offer(cert: Certificate) -> Offer {
    Offer::Certificate(Box::new(cert))
}

/// A host key that a CA of known_hosts signed is accepted under strict
/// checking, and nothing is recorded (T-027).
#[test]
fn cert_authority_signs_a_host_key_that_strict_checking_accepts() {
    let f = file("ca-good", &ca_line("@cert-authority", 1));
    let before = std::fs::read_to_string(&f).unwrap();
    let log = Log::new(LogLevel::Quiet);
    let good = cert(10, 1, CertType::Host, "example.org", now() - 60, now() + 3600);
    assert_eq!(strict(&f).check_offer(&offer(good), &log), Verdict::Accept);
    assert_eq!(std::fs::read_to_string(&f).unwrap(), before, "nothing is recorded");
}

/// A certificate whose CA no line names is checked as its plain key, which
/// strict checking refuses; the refusal has both fingerprints.
#[test]
fn cert_authority_of_another_ca_falls_back_and_names_both_keys() {
    let f = file("ca-other", &ca_line("@cert-authority", 2));
    let log = Log::new(LogLevel::Quiet);
    let theirs = cert(10, 1, CertType::Host, "example.org", now() - 60, now() + 3600);
    let host_fp = seeded(10).public_key().fingerprint(HashAlg::Sha256).to_string();
    let ca_fp = seeded(1).public_key().fingerprint(HashAlg::Sha256).to_string();
    match strict(&f).check_offer(&offer(theirs), &log) {
        Verdict::Reject(why) => assert!(why.contains(&host_fp) && why.contains(&ca_fp), "{why}"),
        Verdict::Accept => panic!("a certificate of a CA that no line names was accepted under strict checking"),
    }
}

/// From a CA of known_hosts, an expired certificate, one for another
/// principal, a user certificate and one of a revoked CA are refused, each
/// with the check that failed.
#[test]
fn cert_authority_refuses_a_certificate_that_fails_a_check() {
    let f = file("ca-checks", &ca_line("@cert-authority", 1));
    let log = Log::new(LogLevel::Quiet);
    let (t, policy) = (now(), strict(&f));
    let cases = [
        (cert(10, 1, CertType::Host, "example.org", t - 7200, t - 3600), "has expired"),
        (cert(10, 1, CertType::Host, "example.org", t + 3600, t + 7200), "is not valid yet"),
        (cert(10, 1, CertType::Host, "other.example", t - 60, t + 3600), "names other.example, not example.org"),
        (cert(10, 1, CertType::User, "example.org", t - 60, t + 3600), "is a user certificate"),
    ];
    for (offered, says) in cases {
        match policy.check_offer(&offer(offered), &log) {
            Verdict::Reject(why) => assert!(why.contains(says), "{says}: {why}"),
            Verdict::Accept => panic!("accepted a certificate that {says}"),
        }
    }
    let expired = cert(10, 1, CertType::Host, "example.org", t - 7200, t - 3600);
    let Verdict::Reject(why) = policy.check_offer(&offer(expired), &log) else { panic!("accepted") };
    assert!(why.contains("clock") && why.contains("podssh doctor"), "the expiry names the clock: {why}");
    let revoked = file("ca-revoked", &(ca_line("@cert-authority", 1) + &ca_line("@revoked", 1)));
    let good = cert(10, 1, CertType::Host, "example.org", t - 60, t + 3600);
    match strict(&revoked).check_offer(&offer(good), &log) {
        Verdict::Reject(why) => assert!(why.contains("marked @revoked"), "{why}"),
        Verdict::Accept => panic!("accepted a certificate of a revoked CA"),
    }
}
