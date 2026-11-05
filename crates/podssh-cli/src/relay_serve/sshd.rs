//! `podssh relay serve --sshd ADDR:PORT` (T-644, GitHub #142): the owner's
//! sshd on the listener's port, for a host that lets one port in. A
//! connection whose first four bytes are `SSH-` goes to it, untouched
//! (`podssh_relay::serve::sshd`); with no flag nothing changes. ADDR is an
//! address, never a name, so that each dial reaches the one sshd that the
//! first line named. The first line says that a shell is published on the
//! port, behind that sshd's own authentication, and whether the host's
//! proxy carries the dial.

use std::net::SocketAddr;

use podssh_relay::serve::egress::Egress;

use crate::relay_settings::Refusal;

/// The sshd of `--sshd ADDR:PORT`: none without the flag; an address and a
/// port other than 0, else a refusal (64).
pub(super) fn of(word: Option<&str>) -> Result<Option<SocketAddr>, Refusal> {
    let Some(word) = word else { return Ok(None) };
    match word.parse::<SocketAddr>() {
        Ok(at) if at.port() != 0 => Ok(Some(at)),
        _ => Err(Refusal::usage(format!(
            "--sshd {word:?}: the address and the port of an sshd, such as 127.0.0.1:22 or [::1]:22, not a name"
        ))),
    }
}

/// The words of the first line, after a comma: nothing without an sshd.
pub(super) fn shown(sshd: Option<SocketAddr>, egress: &Egress) -> String {
    let Some(at) = sshd else { return String::new() };
    // The role's way out decides, as for each of its dials (T-457).
    let through = match egress.proxy_for(&at.ip().to_string()) {
        Some(_) => " through the host's proxy",
        None => "",
    };
    format!(
        ", SSH on this port to the sshd at {at}{through} (a shell for each client that reaches the port, behind \
         that sshd's own authentication)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-644: an address and a port alone, and the words of the first line.
    #[test]
    fn the_sshd_is_an_address_and_a_port_and_the_first_line_names_it() {
        assert_eq!(of(None), Ok(None));
        assert_eq!(of(Some("127.0.0.1:22")), Ok(Some(SocketAddr::from(([127, 0, 0, 1], 22)))));
        assert_eq!(of(Some("[::1]:2222")).map(|at| at.map(|a| a.port())), Ok(Some(2222)));
        for wrong in ["localhost:22", "127.0.0.1", "127.0.0.1:0", "22", "127.0.0.1:ssh", ""] {
            let refused = of(Some(wrong)).unwrap_err();
            assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE, "{wrong}: {refused:?}");
            assert!(refused.message.starts_with("--sshd ") && refused.message.contains("not a name"), "{refused:?}");
        }
        assert_eq!(shown(None, &Egress::Direct), "");
        let direct = shown(Some(SocketAddr::from(([127, 0, 0, 1], 22))), &Egress::Direct);
        assert!(direct.starts_with(", SSH on this port to the sshd at 127.0.0.1:22 (a shell for each"), "{direct}");
        assert!(direct.contains("behind that sshd's own authentication"), "{direct}");
        // Through a proxy that the host names, the loopback stays direct and
        // another address goes through it.
        let proxied = Egress::from_vars(|name| (name == "HTTPS_PROXY").then(|| "http://127.0.0.1:3128".to_string()));
        let proxied = proxied.unwrap();
        assert!(!shown(Some(SocketAddr::from(([127, 0, 0, 1], 22))), &proxied).contains("proxy"));
        let far = shown(Some(SocketAddr::from(([10, 0, 0, 5], 22))), &proxied);
        assert!(far.contains("10.0.0.5:22 through the host's proxy"), "{far}");
    }
}
