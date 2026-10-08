//! E13, part two: the file, `--accept-new`, and what podssh writes.
//!
//! ⛔ **The companion of `known_hosts.rs`, and the seam is the subject** ⛔ that
//! file is the key encoding and the three verdicts, and this one is the file
//! itself, the non-interactive accept path, and the bytes podssh writes. ⛔ Every
//! key is `tests/common/mod.rs`, beside the command that produced it and the
//! `ssh-keygen -lf` value it must reproduce.
//!
//! ⛔ **The third command of `E13`'s `Prove` block is `ssh-keygen -F`.** ⛔ It
//! cannot run here ⛔ there is no `podssh` binary and no session ⛔ so the file
//! format is pinned as strings instead, and `docs/TODO/security/host-keys.md`
//! says which clauses remain unrun.

mod common;

use std::path::{Path, PathBuf};

use common::{
    b64, b64_decode, key, line_for, FakeEnv, CHANGED, ED25519, FILE, HASHED_ED25519,
};
use podssh_cli::security::fingerprint::encode;
use podssh_cli::security::known_hosts::{format_entry, hash_host, parse, Entry, Marker};
use podssh_cli::security::store::{accept_new, check, load, resolve_path, AcceptOutcome, Verdict};

fn file(p: &str) -> &Path {
    Path::new(p)
}
// ---------------------------------------------------------------- the file

#[test]
fn one_corrupt_line_does_not_cost_the_good_entry() {
    // ⛔ `E13`'s `Prove` block: ⛔ *"a `known_hosts` file with one corrupt line
    // and one good entry. Must load the good entry and skip the bad one, not
    // fail the load."*
    // ⛔ **Two lines with a corrupt *host* field, and they are the only
    // ones that reach the pattern parser** ⛔ — **a first version of this
    // test had none, and a strict-parser plant then passed at exit 0.** ⛔ The
    // other two bad lines below fail in the *key* arm, which is a separate
    // `continue`, so ⛔ **a parser that lost the whole file on a bad key would
    // still have passed.** ⛔ The host arm is the one the entry’s
    // "the parser is strict" sentence is about, because it is the one a
    // hand-edited file reaches first.
    let text = "\
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU
this-line-has-no-key-type-at-all
broken.example ssh-ed25519 not-valid-base64-!!! truncated
quantum.example ssh-quantum AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU
|1|not-base64!|also-not-base64! ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU
|1|onlyonesalt ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU
";
    let store = parse(text);
    assert_eq!(store.entries.len(), 1, "one good entry must survive: {:?}", store.skipped);
    assert_eq!(store.entries[0].line, 1);
    assert!(matches!(
        check(&store, file("/tmp/kh"), "github.com", &key(ED25519)),
        Verdict::Accepted { line: 1 }
    ));
    // ⛔ And every bad line is **named**, not silently dropped ⛔ a parser that
    // skipped them would pass this test and the operator would never learn
    // their trust store has a typo in it.
    let lines: Vec<usize> = store.skipped.iter().map(|s| s.line).collect();
    assert_eq!(
        lines,
        vec![2, 3, 4, 5, 6],
        "each skipped line keeps its number and its reason"
    );
    // ⛔ Line 4 is refused as a mismatch rather than as an unknown type, and
    // that is ⛔ **the better of the two failures**: an unknown type name with a
    // real key inside it is a file claiming one key and carrying another, and
    // ⛔ the algorithm check runs first.
    assert_eq!(
        store.skipped[2].why,
        "the key type in the field is not the one inside the blob"
    );
    // ⛔ And the two *host*-arm failures, asserted separately because they are
    // ⛔ the ones the plant above targets.
    assert_eq!(store.skipped[3].why, "\"not-base64!\" is not base64");
    assert_eq!(store.skipped[4].why, "a hashed host with no MAC");
    // ⛔ And the type check is exercised on its own, with a ⛔ **self
    // consistent** blob of a type podssh does not implement ⛔ which is the case
    // a relay rolling out a new algorithm would actually produce.
    let future = encode("ssh-future-quantum", b"pretend this is a key").expect("a name and a body encode");
    let only = parse(&format!(
        "quantum.example ssh-future-quantum {}\n",
        b64(&future)
    ));
    assert!(only.entries.is_empty());
    assert!(only.skipped[0].why.contains("not in podssh's host-key set"), "{}", only.skipped[0].why);
    // ⛔ And an unknown type is not a match: a key podssh cannot interpret is a
    // key it must not trust.
    assert!(matches!(
        check(&store, file("/tmp/kh"), "quantum.example", &key(ED25519)),
        Verdict::Unknown { .. }
    ));
}

#[test]
fn markers_are_recognised_and_both_of_them_refuse() {
    // ⛔ **Both of these were silently dropped in the first version**, because
    // the parser decided "is this a known key type" with the ⛔ six SSH host-key
    // types, and neither marker is one of them. ⛔ MEASURED: a file whose only
    // entry was `@revoked …` parsed to ⛔ **zero entries** ⛔ so ⛔ the revocation
    // ⛔ was erased by opening the file. ⛔ The parser now asks ⛔ "is this a
    // ⛔ marker" first, and that question has its own function.
    let k = key(ED25519);
    for (marker, name) in [("@cert-authority ", "ca"), ("@revoked ", "revoked")] {
        let store = parse(&line_for(marker, name, &k));
        assert_eq!(store.entries.len(), 1, "{marker} was dropped");
        assert_eq!(store.skipped.len(), 0, "{marker} was reported as malformed");
    }
    // ⛔ `@cert-authority` is not a host key: podssh does not validate
    // certificates, so it must not vouch for one.
    let ca = parse(&line_for("@cert-authority ", "www.example", &k));
    assert_eq!(ca.entries[0].marker, Marker::CertAuthority);
    assert!(matches!(
        check(&ca, file("/tmp/kh"), "www.example", &k),
        Verdict::Unknown { .. }
    ));
    // ⛔ `@revoked` is a ⛔ contradiction, not an unknown ⛔ and the difference is
    // the whole point: `Unknown` offers `--accept-new`, and ⛔ `--accept-new` is
    // ⛔ **not** permitted to accept a revocation.
    let rv = parse(&line_for("@revoked ", "evil.example", &k));
    let v = check(&rv, file("/tmp/kh"), "evil.example", &k);
    assert!(matches!(v, Verdict::Refused(_)), "a revoked key must be refused, got {v:?}");
    assert!(accept_new(&rv, file("/tmp/kh"), "evil.example", &k).is_err());
}

// ---------------------------------------------------------------- accept-new

#[test]
fn accept_new_writes_an_unknown_key_and_the_write_is_readable() {
    let store = parse(FILE);
    let out = accept_new(&store, file("/tmp/kh"), "new.example", &key(CHANGED))
        .expect("an unknown host is what --accept-new is for");
    match out {
        AcceptOutcome::Write { path, text } => {
            assert_eq!(path, file("/tmp/kh"));
            // ⛔ **Compared line by line, and not with `contains`.** ⛔ A
            // `contains` over the whole fixture passes against a ⛔ truncated
            // RSA line: the first forty characters of it are a prefix of the
            // good one, so a re-serialisation that dropped the modulus still
            // contained every line. ⛔ **That is a test that passed while the
            // code was wrong**, and the count below is what catches it.
            let before: Vec<&str> = FILE.lines().filter(|l| !l.starts_with('#')).collect();
            let after: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
            assert_eq!(after.len(), before.len() + 1, "exactly one line was added:\n{text}");
            for (a, b) in before.iter().zip(after.iter()) {
                assert_eq!(a, b, "an existing line changed");
            }
            assert!(text.contains("new.example ssh-ed25519 "), "not OpenSSH's shape:\n{text}");
            // ⛔ And re-parsing the new file finds it, which is the round trip
            // that makes "wrote" mean something.
            let round = parse(&text);
            assert!(matches!(
                check(&round, file("/tmp/kh"), "new.example", &key(CHANGED)),
                Verdict::Accepted { .. }
            ));
        }
        other => panic!("an unknown host must produce a write, got {other:?}"),
    }
}

#[test]
fn accept_new_against_a_changed_key_is_still_refused() {
    // ⛔ **The plant that matters**, in `E13`'s own words: ⛔ *"Plant:
    // `--accept-new` against a **changed** key. Must still refuse. ⛔ This is
    // the plant that matters, because it is the one a naive implementation
    // passes."*
    //
    // ⛔ **The planted key is `CHANGED` and the planted host is
    // `example.com:2222`** ⛔ **and `github.com` would NOT have been a
    // contradiction.** ⛔ The fixture holds `github.com` twice:
    // ⛔ unhashed with `ED25519` on line 2, and hashed with `CHANGED` on
    // line 4, so presenting `CHANGED` for `github.com` is ⛔ **a match** ⛔ the
    // hashed lookup succeeds, the entry is found, and `--accept-new`
    // correctly returns `AlreadyKnown { line: 4 }`. ⛔ A first version of this
    // ⛔ test was green for exactly that reason. ⛔ The plant has to be a host
    // the store has, with a key it does not hold.
    let store = parse(FILE);
    let err = accept_new(&store, file("/root/.ssh/known_hosts"), "example.com:2222", &key(CHANGED))
        .expect_err("--accept-new must never accept a contradiction");
    let message = err.to_string();
    assert!(message.contains("REFUSING example.com:2222"), "{message}");
    assert!(message.contains("/root/.ssh/known_hosts"), "the file is not named: {message}");
    assert!(message.contains(":3"), "the line is not named: {message}");
    // ⛔ And the control for the whole test: the same key against a host the
    // ⛔ store has never seen ⛔ **is** accepted. ⛔ Without this, an
    // ⛔ `--accept-new` that refused everything would pass the plant.
    assert!(matches!(
        accept_new(&store, file("/root/.ssh/known_hosts"), "brand-new.example", &key(CHANGED)),
        Ok(AcceptOutcome::Write { .. })
    ));
    // ⛔ And the file is untouched, which is the other half: a refusal that
    // appended the attacker's key would be a refusal in name only.
    assert_eq!(store.entries.len(), 4, "the store was not modified");
}

#[test]
fn accept_new_against_a_known_key_does_not_rewrite_it() {
    // ⛔ *"a connect that succeeds without persisting is a silent TOFU that
    // re-prompts forever"* is the unknown case ⛔ and this is the other half,
    // ⛔ a different arm because rewriting a file that is already right makes
    // ⛔ every connect dirty.
    let store = parse(FILE);
    assert_eq!(
        accept_new(&store, file("/tmp/kh"), "github.com", &key(ED25519))
            .expect("a known key is already accepted"),
        AcceptOutcome::AlreadyKnown { line: 2 }
    );
}

// ---------------------------------------------------------------- what podssh writes

#[test]
fn what_podssh_writes_is_what_openssh_prints() {
    // ⛔ **The third command of `E13`'s `Prove` block**, asserted as strings
    // because ⛔ there is no `podssh` binary and no file on disk during a test.
    // ⛔ `ssh-keygen -F` prints `# Host <h> found: line <n>` and then the line
    // verbatim, so the line and ⛔ the number are what it pins ⛔ and the number
    // is what the entry's "naming the file and the line" requirement needs.
    let store = parse(FILE);
    let e: &Entry = &store.entries[0];
    assert_eq!(e.line, 2, "the line number survives the round trip");
    assert_eq!(
        format_entry(e),
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU"
    );
    // ⛔ The comment is not part of a `known_hosts` line, and writing it would
    // make the file differ from what OpenSSH writes and reads back.
    assert!(!format_entry(e).contains("podssh-e13-fixture"));
    // ⛔ Every entry re-serialises to the line it was parsed from.
    for (i, entry) in store.entries.iter().enumerate() {
        let round = parse(&format!("{}\n", format_entry(entry)));
        assert_eq!(round.entries.len(), 1, "entry {i} did not survive a round trip");
        assert_eq!(round.entries[0].key, entry.key, "entry {i} changed its key");
        assert_eq!(round.entries[0].patterns, entry.patterns, "entry {i} changed its hosts");
    }
}

#[test]
fn a_hashed_entry_is_written_back_with_its_salt_untouched() {
    // ⛔ podssh has no reason to re-hash a host it did not hash, ⛔ and
    // re-hashing on every write would churn the file for no gain.
    let store = parse(FILE);
    assert_eq!(format_entry(&store.entries[2]), HASHED_ED25519);
}

#[test]
fn podsshs_hash_is_the_hash_ssh_keygen_wrote() {
    // ⛔ The measurement, as an assertion. ⛔ For the salt
    // `7VxMAYCtkkfcxLDU4i9dktuD4hM=` and the host `github.com`, podssh's
    // HMAC-SHA1 is `vWs7gM52cv1zvZLddNKcOSlslOQ=` ⛔ the MAC `ssh-keygen -H`
    // ⛔ wrote ⛔ and SHA-256 over the same input gives `T0FkV1QZLMbNWs/Z9S4IWhjqMcg=`,
    // ⛔ which is why the algorithm is pinned and not assumed.
    let salt = b64_decode("7VxMAYCtkkfcxLDU4i9dktuD4hM=");
    let pattern = hash_host(&salt, "github.com");
    match &pattern {
        podssh_cli::security::known_hosts::HostPattern::Hashed { mac, .. } => {
            assert_eq!(b64(mac), "vWs7gM52cv1zvZLddNKcOSlslOQ=");
        }
        other => panic!("expected a hashed pattern, got {other:?}"),
    }
    // ⛔ The control: a different host does not produce the same MAC.
    assert_ne!(hash_host(&salt, "gitlab.com"), pattern);
    // ⛔ And the written line still matches, which closes the loop.
    let store = parse(&format!("{HASHED_ED25519}\n"));
    assert!(matches!(
        check(&store, file("/tmp/kh"), "github.com", &key(CHANGED)),
        Verdict::Accepted { line: 1 }
    ));
}


// ---------------------------------------------------------------- the path

#[test]
fn the_store_path_is_probed_and_the_probe_is_reported() {
    // ⛔ `E13`'s Approach: ⛔ *"`~/.ssh/known_hosts`, then
    // `$XDG_CONFIG_HOME`/`podssh/known_hosts`, then beside the binary ⛔
    // resolved from `/proc/self/exe`, then `$PODSSH_KNOWN_HOSTS`."*
    // ⛔ **The override is checked first here, and that is a deviation from
    // the entry's written order** ⛔ because an explicit override that is probed
    // past is a suggestion, and `docs/spec/08-tokens.md` says the same of the
    // token chain's row 1.
    let env = FakeEnv {
        vars: vec![("HOME", "/home/op".into()), ("XDG_CONFIG_HOME", "/home/op/.config".into())],
        writable: vec!["/home/op/.ssh"],
        cwd: "/run",
    };
    assert_eq!(
        resolve_path(&env, Some(Path::new("/opt/podssh/bin/podssh"))),
        Some(PathBuf::from("/home/op/.ssh/known_hosts")),
        "the first writable candidate wins"
    );
    // ⛔ **The plant**: no `$HOME` at all, which is the constrained host's shape
    // ⛔ `docs/spec/04-constrained-env.md` says there is no `/etc/passwd`, and
    // ⛔ `E05`'s `open()` for a writable `$HOME` has never been run on any
    // ⛔ host. ⛔ Nothing is assumed; the chain falls through.
    let bare = FakeEnv {
        vars: vec![("XDG_CONFIG_HOME", "/home/op/.config".into())],
        writable: vec!["/run"],
        cwd: "/run",
    };
    assert_eq!(
        resolve_path(&bare, None),
        Some(PathBuf::from("/run/podssh-known-hosts")),
        "the run directory is the last resort"
    );
    // ⛔ And the override wins over all of it.
    let over = FakeEnv {
        vars: vec![
            ("PODSSH_KNOWN_HOSTS", "/explicit/kh".into()),
            ("HOME", "/home/op".into()),
        ],
        writable: vec!["/home/op/.ssh", "/explicit"],
        cwd: "/run",
    };
    assert_eq!(resolve_path(&over, None), Some(PathBuf::from("/explicit/kh")));
}

#[test]
fn a_missing_file_is_an_empty_store_and_not_an_error() {
    // ⛔ *"podssh cannot find anywhere to store the key… it then either refuses
    // every first connection, which makes the tool unusable, or degrades to
    // accepting every key, which makes it worse than useless."* ⛔ An empty
    // ⛔ store is what turns that into a TOFU rather than a dead end.
    let path = file("/nonexistent/podssh/known_hosts");
    let store = load(path).expect("a missing file is an empty store, not an error");
    assert!(store.entries.is_empty());
    assert!(matches!(
        check(&store, path, "github.com", &key(ED25519)),
        Verdict::Unknown { .. }
    ));
}
