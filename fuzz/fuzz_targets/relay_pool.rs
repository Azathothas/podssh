//! A `/relays.json` body (`podssh_relay::pool::parse_pool`), as the relay
//! sends it: each host is kept once, in lower case, and belongs to the
//! deployment of the primary host and is not the primary itself.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_relay::pool::parse_pool;

const PRIMARY: &str = "tcp.ssh.relay.ajam.dev";

fuzz_target!(|data: &[u8]| {
    let Ok(hosts) = parse_pool(data, PRIMARY) else { return };
    for (i, host) in hosts.iter().enumerate() {
        assert_eq!(host, &host.to_ascii_lowercase());
        assert!(host.ends_with(".ssh.relay.ajam.dev") && host != PRIMARY, "{host:?}");
        assert!(!hosts[..i].contains(host), "{host:?} twice");
    }
});
