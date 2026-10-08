//! E13: `known_hosts`, asserted against OpenSSH's own output.
//!
//! ⛔ **Every key here was produced by `ssh-keygen` on this machine** ⛔ and
//! lives in `tests/common/mod.rs` with the command that made it and the
//! `ssh-keygen -lf` value it must reproduce. ⛔ Nothing is generated, and ⛔ no
//! private key is anywhere in this tree.
//!
//! ⛔ **The companion is `known_hosts_file.rs`**, and ⛔ **the seam is
//! the subject**: ⛔ this file is the encoding and the three verdicts, and that
//! one is the file itself, the non-interactive accept path, and the bytes
//! podssh writes. ⛔ Split at the 500-line gate, not at an arbitrary point.
//!

mod common;

use std::path::Path;

// ⛔ **Only what this file uses.** ⛔ The companion takes the rest, and ⛔ an
// ⛔ import left behind by the split is a line a reader trusts to matter.
use common::{b64, key, CHANGED, CHANGED_FP, ED25519, ED25519_FP, FILE, RSA_A, RSA_A_FP};
use podssh_cli::security::fingerprint::{decode, parse_field};
use podssh_cli::security::known_hosts::parse;
use podssh_cli::security::store::{check, Verdict};

fn file(p: &str) -> &Path {
    Path::new(p)
}

#[test]
fn a_key_round_trips_through_the_rfc4253_container() {
    let k = key(ED25519);
    assert_eq!(k.algorithm, "ssh-ed25519");
    assert_eq!(
        k.to_openssh_line(" podssh-e13-fixture"),
        ED25519,
        "the key must re-serialise to the exact line ssh-keygen wrote"
    );
    // ⛔ The fingerprint is OpenSSH's, asserted **with** the prefix and
    // **without** padding, because a fingerprint that differs from
    // `ssh-keygen -lf` by a trailing `=` is one the operator cannot compare
    // against anything.
    assert_eq!(k.fingerprint().with_prefix(), ED25519_FP);
    assert!(!k.fingerprint().as_str().contains('='), "OpenSSH strips the padding");
}

#[test]
fn an_rsa_key_keeps_its_modulus() {
    // ⛔ **This is the test for a bug that shipped in the first version.** RFC
    // 4253 §6.6 is `string name` + *algorithm-specific* fields, and ⛔ **only
    // ed25519 has one string after the name.** The first decoder read a second
    // string and re-encoded, which for an RSA key took ⛔ the 3-byte public
    // exponent and discarded the 257-byte modulus.
    let k = key(RSA_A);
    assert_eq!(k.algorithm, "ssh-rsa");
    assert_eq!(k.fingerprint().with_prefix(), RSA_A_FP);
    // ⛔ And the blob is the blob `ssh-keygen` printed, byte for byte ⛔ which is
    // the property a re-encoding loses.
    assert_eq!(k.to_openssh_line(" podssh-e13-fixture"), RSA_A);
    assert_eq!(k.blob.len(), 279, "the measured blob length on this host");
}

#[test]
fn the_legacy_md5_fingerprint_matches_md5sum_on_this_host() {
    // ⛔ MEASURED 2026-10-02, this machine (Git Bash on Windows):
    //   B=$(cut -d' ' -f2 hk_ed25519.pub); printf '%s' "$B" | base64 -d | md5sum
    //   # 2745846c4c32e8eb5b1298dd91ee3096  -
    // ⛔ **This is the one hash in podssh that is hand-rolled**, so it is
    // ⛔ asserted against that reference and ⛔ **not** against its own shape.
    // ⛔ A shape assertion (`47 chars, hex and colons`) passed against a ⛔ wrong
    // ⛔ implementation during this entry: the first version rotated the wrong
    // register and printed `e0:aa:8f:…`, and every shape check was green. ⛔ A
    // ⛔ test that describes the output rather than the reference proves the
    // ⛔ description.
    let k = key(ED25519);
    assert_eq!(k.md5_fingerprint_hex(), "27:45:84:6c:4c:32:e8:eb:5b:12:98:dd:91:ee:30:96");
    // ⛔ And it decides nothing: the verdicts come from the key bytes.
    let store = parse(FILE);
    assert!(matches!(
        check(&store, file("/tmp/kh"), "github.com", &k),
        Verdict::Accepted { line: 2 }
    ));
}

#[test]
fn a_truncated_key_can_never_equal_a_whole_one() {
    // ⛔ **How much of a truncated key is structurally invisible, measured
    // rather than asserted as a rule.** ⛔ An `ssh-rsa` blob is `string name`
    // (11 bytes) + `mpint e` + `mpint n`, and ⛔ `decode` checks the length of
    // the ⛔ **first field only** — the exponent, whose declared length is
    // 3. ⛔ So a cut at 18 or later parses, and the modulus is never
    // length-checked at all: ⛔ **a per-algorithm material length is exactly
    // the thing `E01`’s algorithm set does not define yet.**
    //
    // ⛔ **A first version of this test asserted the opposite** — that a cut
    // inside the modulus is refused — and it passed, for a reason that had
    // nothing to do with truncation: ⛔ the re-encoding bug made every parsed key
    // 20 bytes long, so any cut past 20 overran the buffer. ⛔ The wire,
    // ⛔ `known_hosts`, and a fingerprint are all consistent with 20-byte keys
    // — ⛔ **a test can be green because the code is broken.**
    let rsa = key(RSA_A);
    // ⛔ `4` is the length prefix. ⛔ **The two boundaries are derived from the
    // blob rather than written down**, so a fixture with a different key cannot
    // make the expectation quietly wrong.
    let name_len = 4 + rsa.algorithm.len();
    // ⛔ **The declared body length, and `name_len + exp_len` is therefore the
    // offset of the modulus** — ⛔ the four bytes of the exponent's own length
    // ⛔ prefix are part of the boundary, not of the body. ⛔ Getting that
    // ⛔ wrong by four moved the assertion by four, and ⛔ **the diagnostic
    // ⛔ that found it printed the three cuts that were refused.**
    let exp_len = u32::from_be_bytes([
        rsa.blob[name_len],
        rsa.blob[name_len + 1],
        rsa.blob[name_len + 2],
        rsa.blob[name_len + 3],
    ]) as usize;
    let mut inside_name: Vec<usize> = Vec::new();
    let mut inside_exp: Vec<usize> = Vec::new();
    let mut inside_modulus: Vec<usize> = Vec::new();
    // ⛔ **One ordered chain, because a `match` on a tuple of three conditions
    // gets the arms in the wrong order** — ⛔ a first version routed cuts
    // ⛔ 12-14 by the *name* arm because `cut < name_len` was tested first and
    // ⛔ `name_len` had been written as the body length rather than the offset.
    for cut in 4..rsa.blob.len() {
        let ok = parse_field(&format!("ssh-rsa {}", b64(&rsa.blob[..cut]))).is_ok();
        if ok {
            inside_modulus.push(cut);
        } else if cut < name_len {
            inside_name.push(cut);
        } else {
            inside_exp.push(cut);
        }
    }
    assert_eq!(inside_name, (4..name_len).collect::<Vec<_>>(), "a cut in the name is refused");
    // ⛔ **The refused cuts are 15, 16 and 17** — ⛔ the last three bytes of
    // the four-byte length prefix. ⛔ A cut at 14 leaves all four and so reads a
    // ⛔ length of zero; ⛔ a cut at 15 leaves three and reads one; ⛔ a cut at
    // ⛔ 18 leaves the whole exponent and reads three. ⛔ The offsets are
    // ⛔ derived rather than written, so the assertion cannot drift from the
    // ⛔ fixture when the key changes length.
    assert_eq!(
        inside_exp,
        (name_len + 4..rsa.blob.len())
            .take(3)
            .collect::<Vec<_>>(),
        "a cut that leaves the exponent’s length prefix incomplete is refused"
    );
    assert_eq!(
        inside_modulus.len(),
        rsa.blob.len() - name_len - exp_len,
        "every cut from the end of the exponent onward parses: the modulus is unchecked"
    );
    // ⛔ **And the gaps are harmless, which is the property that matters and
    // the only one the entry requires.** ⛔ A short blob that parses is not a
    // ⛔ key that can be presented: it is ⛔ **not byte-equal to a whole one**,
    // ⛔ and host-key comparison is byte equality over the whole blob — ⛔ so it
    // ⛔ cannot satisfy one, and it cannot equal another host’s key either.
    for cut in inside_modulus.iter().chain(inside_name.iter()).chain(inside_exp.iter()) {
        let short = decode(&rsa.blob[..*cut]);
        assert!(
            short.is_err() || short.expect("checked").blob != rsa.blob,
            "a cut at {cut} must not be the whole key"
        );
    }
    // ⛔ **The ed25519 blob, `string name` + 32 raw bytes, carries no inner
    // length at all**, and ⛔ **a 20-byte cut is refused — by the mpint
    // heuristic, not by a rule about ed25519.** ⛔ The name is 11 bytes, so
    // ⛔ the 4 bytes at 15-18 are the start of a 32-byte key read as a
    // ⛔ `u32`, and the check correctly notices they overrun. ⛔ **That is
    // ⛔ a false positive that happens to be right**, and it is why the check
    // ⛔ is commented as conservative where it lives rather than presented as
    // ⛔ a truncation detector. ⛔ What holds for every algorithm is the
    // ⛔ property below.
    let k = key(ED25519);
    let k_name_len = 4 + k.algorithm.len();
    for cut in k_name_len..k.blob.len() {
        if let Ok(short) = decode(&k.blob[..cut]) {
            assert_ne!(
                short.fingerprint(),
                k.fingerprint(),
                "a cut at {cut} must never equal the whole ed25519 key"
            );
            assert_ne!(short.blob, k.blob);
        }
    }
    assert!(
        decode(&k.blob[..20]).is_err(),
        "MEASURED: the mpint heuristic refuses this cut, and that is why the assertion above is a loop"
    );
    // ⛔ And the control: the whole key parses.
    assert!(parse_field(ED25519).is_ok());
}

#[test]
fn a_field_whose_algorithm_disagrees_with_its_blob_is_refused() {
    // ⛔ Two different strings in the same line. ⛔ A reader that compared the
    // field's name and verified the blob's would be comparing one key and
    // verifying another, and ⛔ the file is where somebody who can write it
    // would try that.
    let lying = format!("ssh-rsa {}", b64(&key(ED25519).blob));
    assert_eq!(
        parse_field(&lying).expect_err("a mismatch must be refused").to_string(),
        "the key type in the field is not the one inside the blob"
    );
    // ⛔ A line of five fields is a damaged line, not a key with a comment.
    assert!(parse_field("a b c d e").is_err());
    // ⛔ Two key types and no body is a damaged line too, and ⛔ **not** read as
    // a comment that happens to look like a key type.
    assert!(parse_field(&format!("ssh-ed25519 {} ssh-rsa", b64(&key(ED25519).blob))).is_err());
}

// ---------------------------------------------------------------- the three verdicts

#[test]
fn an_unknown_key_is_reported_as_unknown_and_nothing_else() {
    let store = parse(FILE);
    let v = check(&store, file("/tmp/known_hosts"), "never-seen.example", &key(ED25519));
    match v {
        Verdict::Unknown { fingerprint } => {
            assert_eq!(fingerprint, ED25519_FP, "the fingerprint must be in the message");
        }
        other => panic!("an unknown host must be Unknown, got {other:?}"),
    }
}

#[test]
fn a_matching_key_is_accepted_and_says_only_which_line() {
    let store = parse(FILE);
    let v = check(&store, file("/tmp/known_hosts"), "github.com", &key(ED25519));
    assert_eq!(v, Verdict::Accepted { line: 2 });
    // ⛔ *"Must connect **silently** — no prompt, no stderr output."* ⛔ The
    // `Display` is asserted too, because a `Display` that congratulated would
    // be one the doctor prints on every connect.
    assert_eq!(v.to_string(), "host key matches the entry on line 2");
}

#[test]
fn a_matching_hashed_entry_is_accepted_on_the_line_that_matched() {
    let store = parse(FILE);
    // ⛔ **Line 4, not line 2.** ⛔ `github.com` is on line 2 unhashed with one
    // key and on line 4 hashed with a ⛔ **different** key, and a first version
    // of `check` returned the ⛔ *first candidate's* line for either ⛔ so it
    // said "matches the entry on line 2" ⛔ while the key that matched was on
    // line 4. ⛔ A refusal message that names a line holding a different key is
    // the sentence `Prove` requires to be true.
    let v = check(&store, file("/tmp/known_hosts"), "github.com", &key(CHANGED));
    assert_eq!(v, Verdict::Accepted { line: 4 });
    // ⛔ And the hash did the work, not the key: the same key on the same host
    // is refused against a store that has no hashed entry.
    let unhashed_only = parse("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX00QstqthxP3bYFY7PTQA0kpoIzXpWQbz5ddUC7NMU\n");
    assert!(matches!(
        check(&unhashed_only, file("/tmp/kh"), "github.com", &key(CHANGED)),
        Verdict::Refused(_)
    ));
}

#[test]
fn a_changed_key_is_refused_and_the_message_names_the_file_and_the_line() {
    let store = parse(FILE);
    let v = check(&store, file("/root/.ssh/known_hosts"), "example.com:2222", &key(CHANGED));
    let refusal = match v {
        Verdict::Refused(r) => r,
        other => panic!("a changed key must be refused, got {other:?}"),
    };
    let message = refusal.to_string();
    // ⛔ Every one of these is named in `E13`'s `Prove` block or its Approach.
    for want in [
        "/root/.ssh/known_hosts",
        ":3",
        "REFUSING example.com:2222",
        "ssh-keygen -R example.com:2222",
    ] {
        assert!(message.contains(want), "{want:?} is missing from:\n{message}");
    }
    // ⛔ Both fingerprints ⛔ the Approach says "refuse, and name both
    // fingerprints" ⛔ and ⛔ they are the values `ssh-keygen -lf` printed, so an
    // ⛔ operator can diff the message against their own terminal.
    assert_eq!(refusal.presented, CHANGED_FP);
    assert_eq!(refusal.stored, vec![RSA_A_FP.to_string()]);
    assert!(message.contains(&refusal.presented));
    assert!(message.contains(&refusal.stored[0]));
    assert!(message.contains("refused, not warned about"));
}

#[test]
fn a_host_with_a_port_is_matched_by_its_full_name() {
    let store = parse(FILE);
    // ⛔ The control for the line above: the same host without the port is
    // unknown, ⛔ because a match on the bare name would let an entry for
    // `example.com:2222` vouch for a connection to `example.com:22`.
    assert!(matches!(
        check(&store, file("/tmp/kh"), "example.com:22", &key(RSA_A)),
        Verdict::Unknown { .. }
    ));
    assert!(matches!(
        check(&store, file("/tmp/kh"), "example.com:2222", &key(RSA_A)),
        Verdict::Accepted { line: 3 }
    ));
}

#[test]
fn a_comma_list_covers_every_name_in_it() {
    let store = parse(FILE);
    for host in ["h1.example", "h2.example"] {
        assert!(
            matches!(check(&store, file("/tmp/kh"), host, &key(ED25519)), Verdict::Accepted { line: 5 }),
            "{host} is in the comma list on line 5"
        );
    }
    assert!(matches!(
        check(&store, file("/tmp/kh"), "h3.example", &key(ED25519)),
        Verdict::Unknown { .. }
    ));
}
