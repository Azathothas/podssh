//! The identity of each end (T-087): a key shown as OpenSSH shows one and
//! read as iroh writes one, the Noise key derived from the seed and signed by
//! it, a node's allowlist, and an operator's pins, in temporary directories.

mod cleanup;

use std::path::{Path, PathBuf};

use podssh_relay::identity::allow::{self, Allowlist};
use podssh_relay::identity::pins::{self, PinError, Seen};
use podssh_relay::identity::{Identity, KeyName, PublicKey};

/// A throwaway Ed25519 key that OpenSSH 10.3p1 made for this test, and its
/// `ssh-keygen -lf`; the secret half was deleted.
const OPENSSH_KEY: &str = "7769b4030e693169deb26e0a5e32a84d5108b6517e0dd05db0d13ca506e854af";
const OPENSSH_FINGERPRINT: &str = "SHA256:4GCq9Leo8YikY6DuOUiMStys+sW6A5GLCsemjyLisjY";
/// One key in iroh's two forms (the vector of iroh-base, as the iroh road's
/// tests have it).
const IROH_HEX: &str = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";
const IROH_BASE32: &str = "vzmp7cbteqnmqllp65qrarxnm62qoliufrmi2add5fbntj2vak3a";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-identity-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// Write a file that only its owner can change, where modes exist.
fn write_own(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

fn key(text: &str) -> PublicKey {
    PublicKey::parse(text).unwrap()
}

#[test]
fn a_key_is_shown_as_openssh_shows_it() {
    let shown = key(OPENSSH_KEY);
    assert_eq!(shown.fingerprint(), OPENSSH_FINGERPRINT, "the fingerprint of ssh-keygen -lf");
    assert_eq!(shown.to_string(), OPENSSH_FINGERPRINT);
    assert_eq!(shown.hex(), OPENSSH_KEY, "iroh's hex");
}

#[test]
fn a_key_is_read_in_each_form_that_iroh_writes() {
    let hex = key(IROH_HEX);
    assert_eq!(PublicKey::parse(IROH_BASE32), Some(hex), "iroh's base32 of the same key");
    assert_eq!(PublicKey::parse(&IROH_BASE32.to_uppercase()), Some(hex));
    assert_eq!(PublicKey::parse(&IROH_HEX.to_uppercase()), Some(hex));
    let near = [
        String::new(),
        IROH_HEX[..63].to_string(),
        format!("{}zz", &IROH_HEX[..62]),
        format!("{}1", &IROH_BASE32[..51]),
        // The last letter's four low bits are not part of the key: they must be 0.
        format!("{}b", &IROH_BASE32[..51]),
    ];
    for bad in &near {
        assert_eq!(PublicKey::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn a_key_is_named_by_its_fingerprint_or_by_itself() {
    let named = key(OPENSSH_KEY);
    let other = key(IROH_HEX);
    for word in [OPENSSH_FINGERPRINT.to_string(), format!("{OPENSSH_FINGERPRINT}="), OPENSSH_KEY.to_string()] {
        let name = KeyName::parse(&word).unwrap();
        assert!(name.matches(&named) && !name.matches(&other), "{word}");
        assert_eq!(name.fingerprint(), OPENSSH_FINGERPRINT, "{word}");
    }
    for bad in ["SHA256:", "SHA256:4GCq9Leo8YikY6DuOUiM", "MD5:4GCq9Leo8YikY6DuOUiMStys+sW6A5GLCsemjyLisjY", "laptop"] {
        assert_eq!(KeyName::parse(bad), None, "{bad}");
    }
}

#[test]
fn the_noise_key_is_derived_from_the_seed_and_signed_by_the_identity() {
    let one = Identity::from_seed(&[7; 32]);
    let again = Identity::from_seed(&[7; 32]);
    let other = Identity::from_seed(&[8; 32]);
    assert_eq!(one.public(), again.public());
    assert_eq!(one.dh_public(), again.dh_public(), "the same seed, the same Noise key");
    assert_ne!(one.dh_public(), other.dh_public());
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*one.dh_secret()));
    assert_eq!(public.as_bytes(), one.dh_public(), "X25519's public half of the derived secret");
    // Not the Ed25519 key's Montgomery form: no key does two jobs.
    let montgomery = ed25519_dalek::VerifyingKey::from_bytes(&one.public().0).unwrap().to_montgomery();
    assert_ne!(&montgomery.to_bytes(), one.dh_public());
    // The signature binds this Noise key to this identity, and nothing else.
    assert!(one.public().signed(one.dh_public(), one.binding()));
    assert!(!other.public().signed(one.dh_public(), one.binding()));
    assert!(!one.public().signed(other.dh_public(), one.binding()));
    let mut flipped = *one.binding();
    flipped[10] ^= 1;
    assert!(!one.public().signed(one.dh_public(), &flipped));
    // Shown by its fingerprint, never by its seed.
    let seed = "07".repeat(32);
    for shown in [format!("{one:?}"), one.public().to_string(), format!("{:?}", one.public())] {
        assert!(!shown.contains(&seed), "{shown}");
    }
}

#[test]
fn an_allowlist_takes_fingerprints_and_keys_and_names_its_bad_lines() {
    let stranger = Identity::from_seed(&[9; 32]).public();
    let text =
        format!("# the operator's laptop\n{OPENSSH_FINGERPRINT} laptop\n\n  not-a-key\n{IROH_BASE32} a client\n");
    let list = Allowlist::parse(&text);
    assert!(list.admits(&key(OPENSSH_KEY)), "by its fingerprint");
    assert!(list.admits(&key(IROH_HEX)), "by the key in base32");
    assert!(!list.admits(&stranger));
    assert_eq!(list.len(), 2);
    assert_eq!(list.bad_lines(), [4], "the line that is not a key is named, and admits nobody");
    assert!(Allowlist::parse("").is_empty());
}

#[test]
fn the_node_reads_its_allowlist_again_for_each_session() {
    let path = scratch("allow").join("allow");
    let operator = key(OPENSSH_KEY);
    let why = allow::admits(&path, &operator).unwrap_err();
    assert!(why.contains("no such file"), "a missing file lets nobody in: {why}");
    write_own(&path, "# nobody yet\n");
    let why = allow::admits(&path, &operator).unwrap_err();
    assert!(why.contains("is not in") && why.contains("allow"), "{why}");
    write_own(&path, &format!("{OPENSSH_FINGERPRINT} added\n"));
    assert_eq!(allow::admits(&path, &operator), Ok(()), "a key added counts at once");
    write_own(&path, "\n");
    assert!(allow::admits(&path, &operator).is_err(), "a key taken away, at the next session");
}

#[cfg(unix)]
#[test]
fn an_allowlist_that_others_can_change_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let path = scratch("allow-open").join("allow");
    write_own(&path, &format!("{OPENSSH_FINGERPRINT}\n"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let why = allow::admits(&path, &key(OPENSSH_KEY)).unwrap_err();
    assert!(why.contains("others can change it"), "{why}");
}

#[test]
fn the_first_sight_pins_and_a_changed_key_is_refused_with_both_and_kept() {
    let base = scratch("pins");
    let dirs = [base.join("a"), base.join("b")];
    let (node, other) = (key(OPENSSH_KEY), key(IROH_HEX));
    let file = dirs[0].join(pins::FILE);
    assert_eq!(pins::check_in(&dirs, "lab", &node), Ok(Seen::Pinned(file.clone())), "trust on first use");
    let pinned = format!("lab {OPENSSH_FINGERPRINT}\n");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), pinned);
    assert_eq!(pins::check_in(&dirs, "lab", &node), Ok(Seen::Known));
    let changed = pins::check_in(&dirs, "lab", &other).unwrap_err();
    assert_eq!(changed, PinError::Changed { pinned: OPENSSH_FINGERPRINT.to_string(), path: file.clone(), line: 1 });
    assert!(changed.to_string().contains(OPENSSH_FINGERPRINT), "{changed}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), pinned, "a changed key is never written over the pin");

    // Another label pins beside it, in the same file.
    assert_eq!(pins::check_in(&dirs, "far", &other), Ok(Seen::Pinned(file.clone())));
    assert_eq!(pins::check_in(&dirs, "far", &other), Ok(Seen::Known));
    // A line that the user adds for a new key lets it in too, as a rotation.
    let text = std::fs::read_to_string(&file).unwrap();
    write_own(&file, &format!("{text}lab {IROH_HEX} the new key\n"));
    assert_eq!(pins::check_in(&dirs, "lab", &other), Ok(Seen::Known));
    assert_eq!(pins::check_in(&dirs, "lab", &node), Ok(Seen::Known));
}

#[test]
fn a_pin_that_cannot_be_trusted_refuses_and_an_odd_label_is_not_pinned() {
    let base = scratch("pins-bad");
    let dirs = [base.join("a")];
    std::fs::create_dir_all(&dirs[0]).unwrap();
    let file = dirs[0].join(pins::FILE);
    write_own(&file, "lab not-a-key\n");
    let why = pins::check_in(&dirs, "lab", &key(OPENSSH_KEY)).unwrap_err();
    assert!(matches!(&why, PinError::Unreadable(text) if text.contains("line 1")), "{why:?}");
    // A line of another label that is not a key is not this label's business.
    assert!(matches!(pins::check_in(&dirs, "far", &key(OPENSSH_KEY)), Ok(Seen::Pinned(_))));
    assert!(matches!(pins::check_in(&dirs, "has space", &key(OPENSSH_KEY)), Ok(Seen::NotPinned(_))));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let why = pins::check_in(&dirs, "far", &key(OPENSSH_KEY)).unwrap_err();
        assert!(matches!(&why, PinError::Unreadable(text) if text.contains("others can change it")), "{why:?}");
    }
}
