//! The note of `podssh ssh` on the public services that podssh tries when
//! the user named none, and on those that it never names (T-533), apart
//! from `notes_ssh` for its length: it follows the note of the forwarders.
//! A road that a later ruling adds says itself here (Q74, Q75, Q78).

/// The public services that podssh tries last, and the ones it never names.
pub const PUBLIC: &str =
    "The public services that podssh tries when you named no server of their kind, each after podssh's \
     own roads and by the operator's rulings: on the forward road, the four forwarders above, wisp last; \
     on the reverse road, Tailscale's DERP servers for tailcat, Least Authority's transit relay, ppng.io \
     and n0's server of pkarr (see podssh node). Each is a third party that nobody vouches for: its \
     operator sees the target or the two ends, the sizes and the times, may log them, and may stop \
     serving podssh at any time; the host key of SSH, and on the reverse road the end-to-end channel, \
     keep the bytes from it. podssh names no other public server of their kinds: no server of \
     Tailscale's main DERP fleet, which serves Tailscale's own clients; no community DERP server, no Wisp \
     server of a web proxy's list and no public proxy node of an aggregator's list, as none names an \
     operator who answers for it. A server that you name (--derp-server, --forwarder, --shadowsocks, \
     --vless, --via, --wstunnel) is yours to trust. podssh never uses, and never names, a domain that \
     looks taken over: a school's, a church's or a shop's, or a name made to look like one (the \
     operator's ruling Q79).";

#[cfg(test)]
mod tests {
    use super::super::notes::for_verb;

    /// The note follows the forwarders' in the notes of ssh, and holds each
    /// of its claims: the third party, the main fleet, and Q79 (T-533).
    #[test]
    fn the_note_of_the_public_services_follows_the_forwarders() {
        let notes = for_verb("ssh");
        let at = notes.iter().position(|n| *n == super::PUBLIC).expect("the note of the public services");
        assert!(notes[at - 1].starts_with("Four words name public forwarders"), "{}", notes[at - 1]);
        for text in [
            "Each is a third party that nobody vouches for",
            "no server of Tailscale's main DERP fleet, which serves Tailscale's own clients",
            "podssh never uses, and never names, a domain that looks taken over",
        ] {
            assert!(super::PUBLIC.contains(text), "{text}");
        }
    }
}
