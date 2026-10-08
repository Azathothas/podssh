//! `--relay-addr HOST=IP` and `PODSSH_RELAY_ADDR`: addresses to use instead of
//! DNS, for hosts that have none. The flag's pins come first, then the
//! environment's; TLS still checks the host's name, so a wrong address fails
//! the handshake rather than connecting somewhere else.

/// Environment variable with pins, `HOST=IP[,HOST=IP...]`.
pub const PINS_ENV: &str = "PODSSH_RELAY_ADDR";

/// Parse the flag and the environment and install the pins for this process.
pub fn apply(flag: Option<&str>) -> Result<(), String> {
    let mut pins = match flag {
        Some(text) => podssh_ws::resolve::parse_pins(text).map_err(|e| format!("--relay-addr: {e}"))?,
        None => Vec::new(),
    };
    if let Some(text) = std::env::var(PINS_ENV).ok().filter(|v| !v.trim().is_empty()) {
        pins.extend(podssh_ws::resolve::parse_pins(&text).map_err(|e| format!("{PINS_ENV}: {e}"))?);
    }
    podssh_ws::resolve::set_pins(pins);
    Ok(())
}
