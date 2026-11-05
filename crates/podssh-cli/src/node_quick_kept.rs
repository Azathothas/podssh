//! The quick tunnel of a node's run, kept across its upgrade in place
//! (T-679): its id, its name, its account and its secret go to the binary
//! that takes the node's place, as a part of the run (`node_upgrade::parts`),
//! and that binary registers the same tunnel again, with no request to the
//! API, so that the name which the clients of its sessions hold reaches it.
//! The secret stays in memory that is wiped, as the API's reply keeps it.

use podssh_relay::quick::api::Tunnel;
use podssh_relay::session::handover::wire::{Get, Put, Unreadable};
use zeroize::Zeroizing;

use crate::node_upgrade::parts;

/// The longest name or account, and the most bytes of a secret, that a part
/// holds: a tunnel's are far shorter.
const MAX_TEXT: usize = 1024;
const MAX_SECRET: usize = 4096;

/// The tunnel as the part's bytes.
fn encode(tunnel: &Tunnel) -> Zeroizing<Vec<u8>> {
    let mut put = Put::new();
    put.fixed(&tunnel.id);
    put.text(&tunnel.hostname);
    put.text(&tunnel.account_tag);
    put.bytes(&tunnel.secret);
    put.into_bytes()
}

/// The tunnel of the part's bytes; bytes that do not hold together are none.
fn decode(bytes: &[u8]) -> Result<Tunnel, Unreadable> {
    let mut get = Get::new(bytes);
    let id: [u8; 16] = get.fixed("the tunnel's id")?;
    let hostname = get.text("the tunnel's name", MAX_TEXT)?;
    let account_tag = get.text("the tunnel's account", MAX_TEXT)?;
    let secret = Zeroizing::new(get.bytes("the tunnel's secret", MAX_SECRET)?.to_vec());
    get.end("the tunnel")?;
    Ok(Tunnel { id, hostname, account_tag, secret })
}

/// The tunnel of this run: the one that the binary before this one served,
/// or this binary's own when it serves again after a binary that did not
/// start.
pub(crate) fn of_the_run() -> Option<Tunnel> {
    decode(&parts::part(parts::QUICK)?).ok()
}

/// This run's tunnel, for the binary after an upgrade.
pub(crate) fn keep(tunnel: &Tunnel) {
    parts::keep(parts::QUICK, &encode(tunnel));
}

/// The tunnel no longer stands (the edge refused it): the next start asks
/// for a new one.
pub(crate) fn forget() {
    parts::forget(parts::QUICK);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tunnel kept by this run comes back whole for the binary after, its
    /// secret too; bytes cut short are no tunnel.
    #[test]
    fn a_kept_tunnel_comes_back_whole() {
        let tunnel = Tunnel {
            id: [7; 16],
            hostname: "three-words-here.trycloudflare.com".into(),
            account_tag: "0123456789abcdef".into(),
            secret: Zeroizing::new(vec![0x5a; 32]),
        };
        let bytes = encode(&tunnel);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.id, tunnel.id);
        assert_eq!(back.hostname, tunnel.hostname);
        assert_eq!(back.account_tag, tunnel.account_tag);
        assert_eq!(&back.secret[..], &tunnel.secret[..]);
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        keep(&tunnel);
        assert_eq!(of_the_run().map(|t| t.hostname), Some(tunnel.hostname.clone()));
        forget();
        assert!(of_the_run().is_none());
    }
}
