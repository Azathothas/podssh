//! The lists as OpenSSH 10.3p1 assembles them (`kex_assemble_names`), and
//! what they do to russh's lists and to the keys that podssh offers.

use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::Preferred;

use super::*;

fn names(kind: Kind, spec: &str) -> Vec<String> {
    assemble(kind, spec).unwrap_or_else(|e| panic!("{spec}: {e}")).names
}

#[test]
fn a_list_replaces_adds_takes_away_and_goes_first_as_in_openssh() {
    let own = own(Kind::Ciphers);
    assert!(own.contains(&"chacha20-poly1305@openssh.com".to_string()), "{own:?}");
    // A list, in its order; a pattern takes each name it matches.
    assert_eq!(names(Kind::Ciphers, "aes128-ctr,aes256-ctr"), ["aes128-ctr", "aes256-ctr"]);
    assert_eq!(names(Kind::Ciphers, "aes*-ctr"), ["aes128-ctr", "aes192-ctr", "aes256-ctr"]);
    // + adds after podssh's own, once each.
    let added = names(Kind::Ciphers, "+aes128-cbc,aes128-ctr");
    assert_eq!(added[..own.len()], own[..]);
    assert_eq!(added[own.len()..], ["aes128-cbc"]);
    // - takes away, with patterns.
    let taken = names(Kind::Ciphers, "-aes*-ctr");
    assert!(taken.iter().all(|n| !n.ends_with("-ctr")) && !taken.is_empty(), "{taken:?}");
    // ^ puts first, and the rest follows in podssh's order.
    let first = names(Kind::Ciphers, "^aes128-ctr");
    let rest: Vec<&String> = own.iter().filter(|n| *n != "aes128-ctr").collect();
    assert_eq!(first[0], "aes128-ctr");
    assert_eq!(first[1..].iter().collect::<Vec<&String>>(), rest, "{first:?}");
}

#[test]
fn a_name_that_podssh_does_not_speak_is_left_out_and_a_list_of_none_is_refused() {
    let a = assemble(Kind::Ciphers, "3des-cbc,aes128-ctr").unwrap();
    assert_eq!((a.names, a.dropped), (vec!["aes128-ctr".to_string()], vec!["3des-cbc".to_string()]));
    for (kind, spec) in [
        (Kind::Ciphers, "3des-cbc"),
        (Kind::Ciphers, "-*"),
        (Kind::Ciphers, "none"),
        (Kind::Macs, "umac-128@openssh.com"),
        (Kind::Kex, "sntrup761x25519-sha512@openssh.com"),
        (Kind::Kex, "ext-info-c"),
        (Kind::Pubkey, "ssh-ed25519-cert-v01@openssh.com"),
        (Kind::Ciphers, ""),
    ] {
        let err = assemble(kind, spec).unwrap_err();
        assert!(err.contains("podssh") || err.contains("names no"), "{spec}: {err}");
    }
    let err = assemble(Kind::Ciphers, "3des-cbc").unwrap_err();
    assert!(err.contains("chacha20-poly1305@openssh.com"), "the refusal names what podssh speaks: {err}");
    // A negated name, outside a list that takes away, as OpenSSH refuses it.
    assert!(assemble(Kind::Macs, "!hmac-sha1").unwrap_err().contains("!hmac-sha1"));
    assert!(!names(Kind::Macs, "-hmac*,!hmac-sha2-256").is_empty());
}

#[test]
fn the_lists_of_keys_name_certificates_and_the_extensions_stay() {
    let host = own(Kind::HostKey);
    let cert = host.iter().position(|n| n == "ssh-ed25519-cert-v01@openssh.com").expect("a certificate");
    let plain = host.iter().position(|n| n == "ssh-ed25519").expect("a plain key");
    assert!(cert < plain, "the certificates first, as OpenSSH lists them: {host:?}");
    assert!(!host.contains(&"ssh-rsa-cert-v01@openssh.com".to_string()), "no certificate of SHA-1 RSA");
    assert!(own(Kind::Kex).iter().all(|n| !n.starts_with("ext-info") && !n.starts_with("kex-strict")));
    let mut chosen = Algorithms::default();
    chosen.set(Kind::Kex, vec!["curve25519-sha256".into()]);
    chosen.set(Kind::Ciphers, vec!["aes128-ctr".into()]);
    chosen.set(Kind::HostKey, vec!["rsa-sha2-512".into(), "ssh-ed25519-cert-v01@openssh.com".into()]);
    let mut preferred = Preferred::default();
    restrict(&mut preferred, &chosen);
    let kex: Vec<&str> = preferred.kex.iter().map(|k| k.as_ref()).collect();
    assert_eq!(kex[0], "curve25519-sha256");
    assert!(kex.contains(&"ext-info-c") && kex.contains(&"kex-strict-c-v00@openssh.com"), "{kex:?}");
    assert_eq!(preferred.cipher.iter().map(|c| c.as_ref()).collect::<Vec<&str>>(), ["aes128-ctr"]);
    assert_eq!(preferred.key.to_vec(), [Algorithm::Rsa { hash: Some(HashAlg::Sha512) }]);
    assert_eq!(apply::certificates(chosen.given(Kind::HostKey).unwrap()), [Algorithm::Ed25519]);
}

#[test]
fn a_key_of_another_algorithm_or_under_the_rsa_floor_is_not_offered() {
    let ed25519 = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a key").public_key().clone();
    let mut chosen = Algorithms::default();
    assert_eq!(UserKeys::of(&chosen).refuses(&ed25519), None, "podssh's own list takes it");
    chosen.set(Kind::Pubkey, vec!["rsa-sha2-512".into()]);
    let why = UserKeys::of(&chosen).refuses(&ed25519).expect("refused");
    assert!(why.contains("ssh-ed25519") && why.contains("PubkeyAcceptedAlgorithms"), "{why}");
    // The hash of RSA: the server's best when the list takes it, else the list's.
    let keys = UserKeys::of(&chosen);
    assert_eq!(keys.rsa_hash(Some(HashAlg::Sha512)), Some(HashAlg::Sha512));
    assert_eq!(keys.rsa_hash(Some(HashAlg::Sha256)), Some(HashAlg::Sha512));
    chosen.set(Kind::Pubkey, vec!["ssh-ed25519".into(), "rsa-sha2-256".into()]);
    assert_eq!(UserKeys::of(&chosen).rsa_hash(Some(HashAlg::Sha512)), Some(HashAlg::Sha256));
    assert_eq!(UserKeys::of(&Algorithms::default()).rsa_hash(None), None, "as before, with no list");
    // OpenSSH's floor holds under a smaller RequiredRSASize.
    chosen.required_rsa_size = Some(512);
    assert_eq!(chosen.rsa_floor(), MIN_RSA);
    chosen.required_rsa_size = Some(4096);
    assert_eq!(chosen.rsa_floor(), 4096);
}

#[test]
fn an_rsa_key_under_required_rsa_size_is_refused() {
    let rsa = crate::rsa_key::generate(2048).expect("an RSA key");
    let public = PrivateKey::from(rsa).public_key().clone();
    let mut chosen = Algorithms { required_rsa_size: Some(4096), ..Algorithms::default() };
    let why = UserKeys::of(&chosen).refuses(&public).expect("refused");
    assert!(why.contains("2048 bits") && why.contains("RequiredRSASize 4096"), "{why}");
    let offered = russh::keys::PublicKeyOrCertificate::from(public.clone());
    let why = HostLimits::of(&chosen).refuses(&offered, &[], "[127.0.0.1]:2222").expect("refused");
    assert!(why.contains("'[127.0.0.1]:2222'") && why.contains("2048 bits"), "{why}");
    chosen.required_rsa_size = Some(2048);
    assert_eq!(UserKeys::of(&chosen).refuses(&public), None);
    assert_eq!(HostLimits::of(&chosen).refuses(&offered, &[], "h"), None);
    // A list with no signature of RSA leaves an RSA key out.
    chosen.set(Kind::Pubkey, vec!["ssh-ed25519".into()]);
    assert!(UserKeys::of(&chosen).refuses(&public).is_some());
}
