//! `--relay-addr HOST=IP` and `PODSSH_RELAY_ADDR`: addresses to use instead of
//! DNS, for hosts that have none. The flag's pins come first, then the
//! environment's, then the settings file's (T-048); TLS still checks the
//! host's name, so a wrong address fails the handshake rather than
//! connecting somewhere else. Each command that reaches the relay starts
//! here, so a settings file that cannot be read is refused here (78).

use crate::relay_settings::Refusal;

/// Environment variable with pins, `HOST=IP[,HOST=IP...]`.
pub const PINS_ENV: &str = "PODSSH_RELAY_ADDR";

/// Parse the flag and the environment and install the pins for this process.
/// A bad flag is a usage error, a bad variable a configuration error.
pub fn apply(flag: Option<&str>) -> Result<(), Refusal> {
    let file = crate::settings::here();
    file.check()?;
    let mut pins = match flag {
        Some(text) => podssh_ws::resolve::parse_pins(text).map_err(|e| Refusal::usage(format!("--relay-addr: {e}")))?,
        None => Vec::new(),
    };
    if let Some(text) = std::env::var(PINS_ENV).ok().filter(|v| !v.trim().is_empty()) {
        pins.extend(podssh_ws::resolve::parse_pins(&text).map_err(|e| Refusal::config(format!("{PINS_ENV}: {e}")))?);
    }
    for value in &file.relay_addr {
        let more = podssh_ws::resolve::parse_pins(&value.text);
        pins.extend(more.map_err(|e| Refusal::config(format!("{}: RelayAddr {}: {e}", value.at, value.text)))?);
    }
    podssh_ws::resolve::set_pins(pins);
    // The addresses that carried a session, which the dialer asks after the
    // system resolver fails (T-344), and the TLS groups that servers took.
    podssh_relay::addresses::install();
    // The key that each host took last, for a login with no query (T-664).
    podssh_ssh::accepted::keep_in(Box::new(AcceptedInCache));
    Ok(())
}

/// The record of the keys that hosts took, a private file of the cache as
/// each of podssh's is: mode 0600, and one that others can read is not read.
struct AcceptedInCache;

impl podssh_ssh::accepted::KeptFile for AcceptedInCache {
    fn load(&self) -> Option<String> {
        podssh_relay::cache::load_file(podssh_ssh::accepted::FILE)
    }

    fn store(&self, text: &[u8]) {
        // A record that cannot be kept costs the next login its round trips.
        let _ = podssh_relay::cache::store_file(podssh_ssh::accepted::FILE, text);
    }
}
