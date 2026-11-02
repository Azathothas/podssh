//! A record with each road (T-445), with no network: what podssh puts is
//! read back whole by podssh, and iroh-dns reads its iroh part alone, in
//! iroh's own words; each road that a record names is checked, and one that
//! fails its check is set aside while the others stay.

use iroh::endpoint_info::EndpointInfo;
use iroh::{RelayUrl, SecretKey};
use podssh_relay::derp::{Key, Server, Ticket};
use podssh_relay::identity::PublicKey as IdentityKey;
use simple_dns::rdata::{RData, TXT};
use simple_dns::{Name, Packet, ResourceRecord, CLASS};

use super::*;
use crate::pkarr::TTL;

const QUICK: &str = "four-words-of-a.trycloudflare.com";

fn relay() -> RelayUrl {
    "https://usw1-1.relay.n0.iroh.link.".parse().expect("a relay URL")
}

/// The DERP ticket of `secret`'s node at `host`.
fn ticket(secret: &SecretKey, host: &str) -> Ticket {
    let node = IdentityKey(*secret.public().as_bytes());
    Ticket { node, derp: Key([8; 32]), server: Server::new(host, 443).expect("a server") }
}

fn each_road(secret: &SecretKey) -> Roads {
    Roads { relay: Some(relay()), derp: Some(ticket(secret, "tc301a.ipn.dev")), quick: Some(QUICK.into()) }
}

/// The record that `packet` is, as a client reads it from a server.
fn read_back(secret: &SecretKey, packet: &SignedPacket) -> Result<Record, String> {
    crate::pkarr::read(&secret.public(), &packet.to_relay_payload())
}

/// A packet of `secret`'s node whose `_podssh` values are `values`, as a
/// node of another podssh, or a planted one, would sign it.
fn planted(secret: &SecretKey, values: &[&str]) -> SignedPacket {
    let name = format!("{PODSSH_TXT_NAME}.{}", secret.public().to_z32());
    let mut dns = Packet::new_reply(0);
    for value in values {
        let txt = TXT::try_from(*value).expect("a TXT value");
        dns.answers.push(ResourceRecord::new(Name::new_unchecked(&name), CLASS::IN, TTL, RData::TXT(txt)));
    }
    sign(secret, &dns.build_bytes_vec_compressed().expect("a DNS packet")).expect("a signed packet")
}

#[test]
fn a_record_with_each_road_reads_back_whole_and_iroh_reads_its_relay_alone() {
    let node = SecretKey::from_bytes(&[0x41; 32]);
    let roads = each_road(&node);
    let packet = packet(&node, &roads, TTL).expect("the record");
    let record = read_back(&node, &packet).expect("the node's own record");
    assert_eq!(record.relays, vec![relay()]);
    assert_eq!(record.derp, roads.derp);
    assert_eq!(record.quick.as_deref(), Some(QUICK));
    assert!(record.set_aside.is_empty(), "{:?}", record.set_aside);
    // iroh's own reading: the relay, and nothing of podssh's names.
    let info = EndpointInfo::from_pkarr_signed_packet(&packet).expect("iroh reads the record as its own");
    assert_eq!(info.relay_urls().cloned().collect::<Vec<_>>(), vec![relay()]);
    // In iroh's own words: what iroh-dns writes for the relay alone.
    let theirs = EndpointInfo::new(node.public()).with_relay_url(relay()).to_pkarr_signed_packet(&node, TTL).unwrap();
    assert_eq!(packet.txt_records(IROH_TXT_NAME), theirs.txt_records(IROH_TXT_NAME));
    assert_eq!(packet.txt_records(PODSSH_TXT_NAME).len(), 2, "the DERP home and the quick tunnel");
}

#[test]
fn a_record_of_the_derp_road_alone_reads_with_no_relay() {
    let node = SecretKey::from_bytes(&[0x42; 32]);
    let roads = Roads { derp: Some(ticket(&node, "tc302a.ipn.dev")), ..Roads::default() };
    let record = read_back(&node, &packet(&node, &roads, TTL).unwrap()).expect("a record of one road");
    assert_eq!((record.relays.len(), record.derp, record.quick), (0, roads.derp.clone(), None));
    // iroh reads it as a node with no relay, and refuses nothing of it.
    let info = EndpointInfo::from_pkarr_signed_packet(&packet(&node, &roads, TTL).unwrap()).unwrap();
    assert_eq!(info.relay_urls().count(), 0);
    assert!(Roads::default().is_empty() && !roads.is_empty());
}

#[test]
fn a_long_derp_home_goes_in_pieces_and_comes_back_whole() {
    let node = SecretKey::from_bytes(&[0x43; 32]);
    // A name of 253 characters, the longest: its ticket is past a DNS
    // string's 255 bytes, so it goes in pieces.
    let host = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
    assert_eq!(host.len(), 253);
    let roads = Roads { derp: Some(ticket(&node, &host)), ..each_road(&node) };
    assert!(roads.derp.as_ref().unwrap().to_string().len() > 255);
    let record = read_back(&node, &packet(&node, &roads, TTL).expect("within pkarr's bytes")).unwrap();
    assert_eq!(record.derp, roads.derp);
    assert_eq!(record.quick.as_deref(), Some(QUICK));
}

#[test]
fn a_road_that_fails_its_check_is_set_aside_and_the_others_stay() {
    let node = SecretKey::from_bytes(&[0x44; 32]);
    let other = SecretKey::from_bytes(&[0x45; 32]);
    let mine = format!("derp={}", ticket(&node, "tc303a.ipn.dev"));
    let theirs = format!("derp={}", ticket(&other, "tc303a.ipn.dev"));
    let quick = format!("quick={QUICK}");
    let (mine, theirs, quick) = (mine.as_str(), theirs.as_str(), quick.as_str());
    // Another node's DERP ticket: set aside; the quick tunnel stays.
    let record = read_back(&node, &planted(&node, &[theirs, quick])).unwrap();
    assert_eq!((record.derp, record.quick.as_deref()), (None, Some(QUICK)));
    assert!(record.set_aside.iter().any(|why| why.contains("another node's key")), "{:?}", record.set_aside);
    // A quick tunnel outside Cloudflare's zone, of two labels, or with a
    // bad first character: set aside, never said back; the DERP home stays.
    for bad in ["quick=evil.example.com", "quick=a.b.trycloudflare.com", "quick=-x.trycloudflare.com"] {
        let record = read_back(&node, &planted(&node, &[bad, mine])).unwrap();
        assert_eq!(record.quick, None, "{bad}");
        assert!(record.derp.is_some(), "{bad}");
        assert!(!format!("{:?}", record.set_aside).contains("evil"), "{:?}", record.set_aside);
    }
    // A road of a later podssh passes by in silence; a value with no key,
    // and a second DERP home, are set aside.
    let record = read_back(&node, &planted(&node, &["transit=wss://x.example", "novalue", mine, theirs])).unwrap();
    assert!(record.derp.is_some());
    assert_eq!(record.set_aside.len(), 2, "{:?}", record.set_aside);
    // Nothing that passes its check: no road, and the reasons.
    let why = read_back(&node, &planted(&node, &[theirs])).unwrap_err();
    assert!(why.contains("names no road") && why.contains("another node's key"), "{why}");
    // A ticket that is no ticket.
    let record = read_back(&node, &planted(&node, &["derp=derp:notaticket", quick])).unwrap();
    assert!(record.set_aside.iter().any(|why| why.contains("not a ticket")), "{:?}", record.set_aside);
}

#[test]
fn a_quick_tunnel_s_name_is_one_label_under_cloudflare_s_zone() {
    assert_eq!(quick_name("Four-Words-Of-A.TryCloudflare.com.").as_deref(), Ok(QUICK));
    let long = format!("{}.trycloudflare.com", "a".repeat(64));
    for bad in [
        "trycloudflare.com",
        ".trycloudflare.com",
        "x-.trycloudflare.com",
        "a_b.trycloudflare.com",
        "x.trycloudflare.com.evil.example",
        "xtrycloudflare.com",
        long.as_str(),
    ] {
        assert!(quick_name(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_node_says_its_roads_in_words() {
    let node = SecretKey::from_bytes(&[0x46; 32]);
    let said = each_road(&node).said();
    assert!(said.starts_with(&format!("the home relay {}", relay())), "{said}");
    assert!(said.ends_with(&format!(", the DERP home tc301a.ipn.dev and the quick tunnel {QUICK}")), "{said}");
    let alone = Roads { quick: Some(QUICK.into()), ..Roads::default() };
    assert_eq!(alone.said(), format!("the quick tunnel {QUICK}"));
}
