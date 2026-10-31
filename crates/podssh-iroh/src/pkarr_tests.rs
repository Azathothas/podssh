//! The record of pkarr, with no network: the server's URL and the variable,
//! n0's server for n0's relays alone, and the reading of a record, whose
//! signature is checked against the node's key. The records are made by
//! iroh-dns, as iroh's own publisher makes them.

use std::time::Duration;

use iroh::endpoint_info::EndpointInfo;
use iroh::{RelayUrl, SecretKey};

use super::*;

fn relay(text: &str) -> RelayUrl {
    text.parse().expect("a relay URL")
}

/// The record of `secret`'s key that names `relays`, as a server sends it.
fn payload(secret: &SecretKey, relays: &[RelayUrl]) -> Vec<u8> {
    let info = relays.iter().fold(EndpointInfo::new(secret.public()), |info, r| info.with_relay_url(r.clone()));
    info.to_pkarr_signed_packet(secret, TTL).expect("a signed packet").to_relay_payload()
}

#[test]
fn n0_s_server_and_its_times_are_iroh_s() {
    assert_eq!(N0, iroh::address_lookup::N0_DNS_PKARR_RELAY_PROD, "n0's server in iroh changed: read it again");
    assert_eq!(TTL, iroh::address_lookup::DEFAULT_PKARR_TTL);
    assert_eq!(REPUBLISH, iroh::address_lookup::DEFAULT_REPUBLISH_INTERVAL);
}

#[test]
fn a_server_is_https_with_a_host_and_a_path_and_nothing_more() {
    let key = SecretKey::from_bytes(&[3; 32]).public();
    let n0 = Server::n0();
    assert_eq!(n0.host(), "dns.iroh.link");
    assert_eq!(n0.path_of(&key), format!("/pkarr/{}", key.to_z32()));
    for (good, path) in [
        ("https://pkarr.example", "/"),
        ("https://pkarr.example/", "/"),
        ("https://pkarr.example:8443/pkarr/", "/pkarr/"),
        ("https://192.0.2.7/relay", "/relay/"),
    ] {
        let server = Server::parse(good).unwrap_or_else(|why| panic!("{good}: {why}"));
        assert_eq!(server.path_of(&key), format!("{path}{}", key.to_z32()), "{good}");
    }
    for (bad, says) in [
        ("http://pkarr.example", "https:// only"),
        ("https://user:pass@pkarr.example", "no user name"),
        ("https://pkarr.example/?a=1", "no query"),
        ("https://pkarr.example/#top", "fragment"),
        ("https://-pkarr.example", "not a host name"),
        ("pkarr.example", "not a URL"),
    ] {
        let why = Server::parse(bad).unwrap_err();
        assert!(why.contains(says), "{bad}: {why}");
        // A password in the URL is never said back.
        assert!(!why.contains("pass@"), "{why}");
    }
}

#[test]
fn the_variable_names_a_server_or_off() {
    assert_eq!(choice(None), Ok(Choice::Default));
    assert_eq!(choice(Some("  ")), Ok(Choice::Default));
    assert_eq!(choice(Some("off")), Ok(Choice::Off));
    assert_eq!(choice(Some(" OFF ")), Ok(Choice::Off));
    let named = choice(Some("https://pkarr.example/pkarr")).unwrap();
    assert_eq!(named, Choice::At(Server::parse("https://pkarr.example/pkarr").unwrap()));
    let why = choice(Some("http://pkarr.example")).unwrap_err();
    assert!(why.starts_with(ENV), "the error names the variable: {why}");
}

#[test]
fn n0_s_server_is_the_default_for_n0_s_relays_alone() {
    let table = crate::relays::defaults();
    assert_eq!(server_for(&Choice::Default, &table), Some(Server::n0()));
    // n0's relay with no final dot is n0's still.
    let dotless = [relay("https://euc1-1.relay.n0.iroh.link")];
    assert_eq!(server_for(&Choice::Default, &dotless), Some(Server::n0()));
    // A relay of the user's own tells n0 nothing, nor does a list with one.
    let own = relay("https://relay.example");
    assert_eq!(server_for(&Choice::Default, std::slice::from_ref(&own)), None);
    assert_eq!(server_for(&Choice::Default, &[table[0].clone(), own.clone()]), None);
    assert_eq!(server_for(&Choice::Default, &[]), None);
    // The user's choice wins over the relays.
    let named = Server::parse("https://pkarr.example").unwrap();
    assert_eq!(server_for(&Choice::At(named.clone()), &[own]), Some(named));
    assert_eq!(server_for(&Choice::Off, &table), None);
}

#[test]
fn a_record_reads_back_and_one_that_another_key_signed_is_refused() {
    let node = SecretKey::from_bytes(&[0x11; 32]);
    let other = SecretKey::from_bytes(&[0x22; 32]);
    let home = relay("https://usw1-1.relay.n0.iroh.link.");
    let record = read(&node.public(), &payload(&node, &[home.clone()])).expect("the node's own record");
    assert_eq!(record.relays, vec![home.clone()]);
    assert!(record.age() < Duration::from_secs(60), "{:?}", record.age());
    // Another key's record, sent as the node's: the signature is not the
    // node's.
    let why = read(&node.public(), &payload(&other, &[home])).unwrap_err();
    assert!(why.contains("not signed by the node's key"), "{why}");
    // Bytes that are no record at all.
    let why = read(&node.public(), b"no record").unwrap_err();
    assert!(why.contains("not a signed record"), "{why}");
    // A record whose relay podssh would not dial names no relay.
    let why = read(&node.public(), &payload(&node, &[relay("http://relay.example")])).unwrap_err();
    assert!(why.contains("names no https:// relay"), "{why}");
}
