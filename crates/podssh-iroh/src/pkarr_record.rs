//! What a node's record of pkarr names (T-350, T-445): its iroh home relay,
//! in iroh's own `_iroh` TXT, and its other roads, in podssh's `_podssh` TXT
//! of the same signed packet: its DERP home, as the node's DERP ticket, and
//! its quick tunnel's name. iroh reads `_iroh` alone (iroh-dns 1.4.1's
//! `EndpointInfo::from_pkarr_signed_packet` asks for `txt_records("_iroh")`),
//! so its tools and n0's DNS pass podssh's names by; a key that iroh does not
//! know under `_iroh` would make iroh refuse the whole record, which is why
//! podssh's roads have a name of their own.
//!
//! A client takes of a record only what it takes of a command line: a relay
//! `https://HOST[:PORT]`, a DERP ticket that names the record's own key, and
//! one label under `trycloudflare.com`. Each other value is set aside, and
//! the record keeps its other roads. The record is signed by the node's key,
//! which the client already holds, and each road checks that key again (the
//! QUIC handshake, the end-to-end channel), so a road that a record names
//! reaches the node or nothing.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint_info::EndpointInfo;
use iroh::{PublicKey, RelayUrl, SecretKey};
use iroh_dns::pkarr::{SignedPacket, Timestamp};
use iroh_dns::IROH_TXT_NAME;
use podssh_relay::derp::Ticket;
use simple_dns::rdata::{RData, TXT};
use simple_dns::{Name, Packet, ResourceRecord, CLASS};

/// podssh's name in a node's zone, beside iroh's `_iroh`: the underscore
/// keeps it out of the names of hosts, as `_iroh` is.
pub const PODSSH_TXT_NAME: &str = "_podssh";

/// The key of the DERP home: the node's DERP ticket, as the node prints it.
pub const DERP_KEY: &str = "derp";

/// The key of the quick tunnel: its name, `NAME.trycloudflare.com`.
pub const QUICK_KEY: &str = "quick";

/// The zone of each quick tunnel's name, as Cloudflare's API gives one: the
/// fact `tunnel-zone` of `trycloudflare` (`pod-services`).
pub fn quick_zone() -> &'static str {
    let service = pod_services::get("trycloudflare").expect("pod-services holds the service trycloudflare");
    service.text("tunnel-zone").expect("trycloudflare of pod-services holds the fact tunnel-zone")
}

/// pkarr's cap on the DNS packet of a record (iroh-dns's
/// `MAX_DNS_PACKET_SIZE`), checked here to say so in words.
const MAX_DNS_PACKET: usize = 1000;

/// The longest label of a DNS name.
const MAX_LABEL: usize = 63;

/// What a node puts in its record: each road that it has now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roads {
    /// The iroh home relay.
    pub relay: Option<RelayUrl>,
    /// The DERP home, as the node's ticket there.
    pub derp: Option<Ticket>,
    /// The quick tunnel's name.
    pub quick: Option<String>,
}

impl Roads {
    /// Whether the record would name no road, and so is not put.
    pub fn is_empty(&self) -> bool {
        self.relay.is_none() && self.derp.is_none() && self.quick.is_none()
    }

    /// The roads in words, for the node's line: "the home relay URL, the
    /// DERP home HOST and the quick tunnel NAME".
    pub fn said(&self) -> String {
        let mut each = Vec::new();
        if let Some(relay) = &self.relay {
            each.push(format!("the home relay {relay}"));
        }
        if let Some(ticket) = &self.derp {
            each.push(format!("the DERP home {}", ticket.server));
        }
        if let Some(name) = &self.quick {
            each.push(format!("the quick tunnel {name}"));
        }
        match each.split_last() {
            None => "no road".to_string(),
            Some((last, [])) => last.clone(),
            Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        }
    }
}

/// A node's record, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The relays that it names, `https://` alone, in its order.
    pub relays: Vec<RelayUrl>,
    /// The node's DERP home, as its ticket; one that names another key is
    /// never here.
    pub derp: Option<Ticket>,
    /// The node's quick tunnel, `NAME.trycloudflare.com` in lower case.
    pub quick: Option<String>,
    /// When the node signed it, in microseconds since the epoch (pkarr's
    /// sequence number).
    pub signed_at: u64,
    /// What was set aside, and why, for `-v`: no value is said back.
    pub set_aside: Vec<String>,
}

impl Record {
    /// The names of `packet`, whose signature the caller checked: iroh's
    /// part by iroh's own reading, podssh's by iroh-dns's reading of TXT.
    pub fn of(packet: &SignedPacket) -> Result<Record, String> {
        let mut set_aside = Vec::new();
        // A relay that podssh would not dial is no relay of the record.
        let relays = match EndpointInfo::from_pkarr_signed_packet(packet) {
            Ok(info) => info.relay_urls().filter_map(|url| crate::relays::parse_url(url.as_str()).ok()).collect(),
            Err(e) => {
                set_aside.push(format!("its {IROH_TXT_NAME} names are not iroh's record of a node: {e}"));
                Vec::new()
            }
        };
        let node = packet.public_key();
        let (mut derp, mut quick) = (None, None);
        for value in packet.txt_records(PODSSH_TXT_NAME) {
            let Some((key, value)) = value.split_once('=') else {
                set_aside.push(format!("a {PODSSH_TXT_NAME} value that is not KEY=VALUE"));
                continue;
            };
            match key {
                DERP_KEY if derp.is_none() => match derp_home(value, &node) {
                    Ok(ticket) => derp = Some(ticket),
                    Err(why) => set_aside.push(why),
                },
                QUICK_KEY if quick.is_none() => match quick_name(value) {
                    Ok(name) => quick = Some(name),
                    Err(why) => set_aside.push(why),
                },
                DERP_KEY | QUICK_KEY => set_aside.push(format!("a second {key}= of {PODSSH_TXT_NAME}")),
                // A road of a later podssh: passed by, as iroh passes ours.
                _ => {}
            }
        }
        if relays.is_empty() && derp.is_none() && quick.is_none() {
            let why = if set_aside.is_empty() { String::new() } else { format!(" ({})", set_aside.join("; ")) };
            return Err(format!("the record names no road: no https:// relay, no DERP home and no quick tunnel{why}"));
        }
        Ok(Record { relays, derp, quick, signed_at: packet.timestamp().as_micros(), set_aside })
    }

    /// How long ago the node signed it; none for a time after this host's.
    pub fn age(&self) -> Duration {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros()).unwrap_or_default();
        Duration::from_micros(u64::try_from(now).unwrap_or(u64::MAX).saturating_sub(self.signed_at))
    }
}

/// A DERP ticket of the record of `node`: one of another node would send
/// the client to a stranger, whose channel would fail.
fn derp_home(value: &str, node: &PublicKey) -> Result<Ticket, String> {
    let ticket = Ticket::parse(value).map_err(|why| format!("its DERP home is not a ticket: {why}"))?;
    if ticket.node.0 != *node.as_bytes() {
        return Err("its DERP home is the ticket of another node's key, and is set aside".into());
    }
    Ok(ticket)
}

/// A quick tunnel's name: one label of letters, digits and '-', under
/// [`quick_zone`], as Cloudflare's API gives one; so a record never sends a
/// client to a host outside Cloudflare's edge. Not echoed: a stranger's
/// record may hold anything.
pub fn quick_name(value: &str) -> Result<String, String> {
    let name = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = name.strip_suffix(quick_zone()).and_then(|rest| rest.strip_suffix('.'));
    let good = label.is_some_and(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    match good {
        true => Ok(name),
        false => Err(format!("its quick tunnel is not one name under {}, and is set aside", quick_zone())),
    }
}

/// The signed packet of `roads`, under `secret`'s key: iroh's `_iroh`
/// values for the relay, as iroh-dns writes them, and podssh's `_podssh`
/// values for the rest, each name in the node's zone, as iroh-dns builds a
/// packet; a value longer than a DNS string goes in pieces, which a reader
/// of TXT joins again.
pub fn packet(secret: &SecretKey, roads: &Roads, ttl: u32) -> Result<SignedPacket, String> {
    let key = secret.public();
    let zone = key.to_z32();
    let mut values: Vec<(String, String)> = Vec::new();
    if let Some(relay) = &roads.relay {
        // iroh's own words for its part, so that iroh reads them as its own.
        let iroh = EndpointInfo::new(key)
            .with_relay_url(relay.clone())
            .to_pkarr_signed_packet(secret, ttl)
            .map_err(|e| format!("the record could not be made: {e}"))?;
        let name = format!("{IROH_TXT_NAME}.{zone}");
        values.extend(iroh.txt_records(IROH_TXT_NAME).into_iter().map(|value| (name.clone(), value)));
    }
    let ours = format!("{PODSSH_TXT_NAME}.{zone}");
    if let Some(ticket) = &roads.derp {
        values.push((ours.clone(), format!("{DERP_KEY}={ticket}")));
    }
    if let Some(name) = &roads.quick {
        values.push((ours.clone(), format!("{QUICK_KEY}={name}")));
    }
    let mut dns = Packet::new_reply(0);
    for (name, value) in &values {
        let txt = TXT::try_from(value.as_str()).map_err(|e| format!("the record could not be made: {e}"))?;
        dns.answers.push(ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, ttl, RData::TXT(txt)));
    }
    let encoded = dns.build_bytes_vec_compressed().map_err(|e| format!("the record could not be made: {e}"))?;
    if encoded.len() > MAX_DNS_PACKET {
        return Err(format!("the record would be {} bytes, more than pkarr's {MAX_DNS_PACKET}", encoded.len()));
    }
    sign(secret, &encoded)
}

/// `encoded`, signed as pkarr signs a packet: BEP 44's form of the sequence
/// number, a time in microseconds, and the value. iroh-dns checks it again
/// as it reads the bytes, so a fault here is never put.
fn sign(secret: &SecretKey, encoded: &[u8]) -> Result<SignedPacket, String> {
    let time = Timestamp::now();
    let mut signed = format!("3:seqi{}e1:v{}:", time.as_micros(), encoded.len()).into_bytes();
    signed.extend_from_slice(encoded);
    let signature = secret.sign(&signed);
    let mut bytes = Vec::with_capacity(32 + 64 + 8 + encoded.len());
    bytes.extend_from_slice(secret.public().as_bytes());
    bytes.extend_from_slice(&signature.to_bytes());
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes.extend_from_slice(encoded);
    SignedPacket::from_bytes(&bytes).map_err(|e| format!("the record does not read back as signed: {e}"))
}

#[cfg(test)]
#[path = "pkarr_record_tests.rs"]
mod tests;
