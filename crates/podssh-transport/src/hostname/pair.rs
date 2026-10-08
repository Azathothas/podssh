//! E17 — ⛔ **the `(name, address)` pair, and why a bare address is not a type.**

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// ⛔ **Why a configured relay address could not be used.** ⛔ Named, because
/// ⛔ **each of these has a different fix** and ⛔ **"could not resolve" with no
/// further detail is the message that costs a session** ⛔ — ⛔ the whole of
/// `relay-hostname.md`'s Problem section, which lists three messages
/// ⛔ (`Temporary failure in resolution`, `403`, `Could not reach the relay`) ⛔
/// **with different fixes and the same-looking causes**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAddressError {
    /// ⛔ **A bare address, with no name.** ⛔ `relay-hostname.md`'s second plant
    /// verbatim: ⛔ *"`podssh --relay-address 104.21.39.2 connect …` must be
    /// **rejected at parse time** with a message saying the hostname is
    /// required."* ⛔ **The measured reason is the SNI certificate**: ⛔ *"A
    /// relay address on its own is not a relay. It is a Cloudflare edge address
    /// that speaks for exactly one name per certificate."*
    MissingName { address: String },
    /// ⛔ The name is not one a certificate could carry.
    BadName { name: String, why: String },
    /// ⛔ The address does not parse, and ⛔ **the name is not what is missing** —
    /// ⛔ so this is a different message and a different fix.
    BadAddress { name: String, address: String, why: String },
}

impl fmt::Display for RelayAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayAddressError::MissingName { address } => write!(
                f,
                "{address} is a bare address and a relay address on its own is not a relay: \
                 the endpoint is behind a certificate issued for a name, and a request that \
                 carries only an address fails the TLS handshake. Pass \
                 --relay-address=<hostname>=<address> — for example \
                 --relay-address=tcp-1.ssh.relay.ajam.dev=104.21.39.2 — so the name reaches \
                 SNI and the certificate is still verified. ⛔ --insecure is not the way to \
                 make this work: it trades a resolution failure for the loss of host identity"
            ),
            RelayAddressError::BadName { name, why } => {
                write!(f, "relay hostname {name:?} is not usable: {why}")
            }
            RelayAddressError::BadAddress { name, address, why } => write!(
                f,
                "relay hostname {name:?} is fine but {address:?} is not an address: {why}. \
                 ⛔ Do not pass a hostname where an address belongs — that is the resolution \
                 this entry is failing to perform"
            ),
        }
    }
}

impl std::error::Error for RelayAddressError {}

/// ⛔ **A relay address, as a name and an address.** ⛔ **Both fields are
/// private and there is no constructor that takes an address alone**, ⛔ so ⛔
/// **a value of this type cannot exist without a name** ⛔ — ⛔ which is how the
/// plant is a guard on the type rather than a check on the arguments.
///
/// ⛔ **The name is what goes to SNI and to the certificate check; the address is
/// what gets dialled.** ⛔ **Verification is unchanged by being pinned** ⛔ —
/// ⛔ a pin is a pin, not a trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAddress {
    name: String,
    address: SocketAddr,
}

impl RelayAddress {
    /// ⛔ **The only constructor.** ⛔ It takes the name first ⛔ **because the
    /// entry's own example puts it first** ⛔ — ⛔ `--relay-address
    /// 'tcp-1.ssh.relay.ajam.dev=104.21.39.2'` ⛔ — ⛔ **and because a signature
    /// that cannot be called with one argument is a signature that cannot be
    /// called wrong.**
    pub fn new(name: &str, address: &str, port: u16) -> Result<Self, RelayAddressError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(RelayAddressError::MissingName { address: address.to_string() });
        }
        if let Err(why) = check_name(trimmed) {
            return Err(RelayAddressError::BadName { name: trimmed.to_string(), why });
        }
        // ⛔ Brackets are accepted because that is how an IPv6 literal is written
        // in a URL authority, and ⛔ **rejected silently is the defect** ⛔ — so
        // they are stripped and the port supplied separately.
        let bare = address.trim().strip_prefix('[').and_then(|a| a.strip_suffix(']')).unwrap_or_else(|| address.trim());
        let ip: IpAddr = bare.parse().map_err(|e: std::net::AddrParseError| RelayAddressError::BadAddress {
            name: trimmed.to_string(),
            address: address.to_string(),
            why: e.to_string(),
        })?;
        Ok(RelayAddress { name: trimmed.to_ascii_lowercase(), address: SocketAddr::new(ip, port) })
    }

    /// ⛔ **From the `name=address` spelling**, ⛔ **and ⛔ a bare address is
    /// `MissingName` and not a bare address with an invented name.** ⛔ That is
    /// the parse-time refusal E17's second plant requires, ⛔ and ⛔ **the test
    /// drives exactly this function** ⛔ because ⛔ **that is what
    /// `podssh --relay-address <v>` will call** ⛔ — ⛔ **E31 owns the CLI that
    /// does, and this is the function it will call.**
    pub fn parse(spec: &str, port: u16) -> Result<Self, RelayAddressError> {
        let spec = spec.trim();
        match spec.split_once('=') {
            Some((name, address)) => Self::new(name, address, port),
            None => Err(RelayAddressError::MissingName { address: spec.to_string() }),
        }
    }

    /// ⛔ **The name the certificate must carry.** ⛔ Lowercased ⛔ **because DNS is
    /// case-insensitive and a certificate's SANs are matched case-insensitively**,
    /// ⛔ and ⛔ `relay-hostname.md`'s pool names are already lower.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// ⛔ **The literal to dial.**
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// ⛔ **The pair, as the `Sources` in E15's chain wants it.**
    pub fn as_pair(&self) -> (String, SocketAddr) {
        (self.name.clone(), self.address)
    }

    /// ⛔ **The owned name, for a caller handing a `ServerName<'static>` to
    /// `rustls`.**
    ///
    /// ⛔ **It returns an owned `String` and not a borrow on purpose.**
    /// `rustls::ServerName<'static>` needs a buffer that outlives the
    /// connection, ⛔ **and a `&str` borrowed from `&self` cannot promise that** ⛔
    /// — ⛔ **a `&'static str` here would have to be `unimplemented!()`, and a
    /// `unimplemented!()` in a library is a panic somebody finds in production.**
    ///
    /// ⛔ **The rule this method holds** ⛔ — ⛔ **the name goes to SNI and the
    /// address is what gets dialled** ⛔ — ⛔ is ⛔ `podssh-ws`'s: ⛔ *"a client
    /// with no name to verify is a client with no name to verify **against**"*,
    /// ⛔ and its `WsClientConfig::validate` refuses an empty `server_name` with ⛔
    /// *"a server name is required: hostname verification has no bypass"*. ⛔
    /// **There is no method here that returns a name built from the address**,
    /// ⛔ and ⛔ **there is no `--insecure`**, ⛔ because ⛔ **a pin is a pin, not
    /// a trust anchor.**
    pub fn server_name(&self) -> String {
        self.name.clone()
    }
}


/// ⛔ **What makes a string usable as a relay hostname.** ⛔ **Not a URL and not a
/// path**: ⛔ a name carrying a scheme, a slash, an `@`, or a space is either a
/// mistake or an attempt to make the name say something else ⛔ — ⛔ **and the
/// name goes into a TLS SNI extension and an HTTP `Host` header**, so ⛔ **both
/// of those must be a name and nothing else.**
fn check_name(name: &str) -> Result<(), String> {
    if name.len() > 253 {
        return Err(format!("{} bytes, over the 253-byte maximum for a DNS name", name.len()));
    }
    for ch in name.chars() {
        if ch.is_whitespace() || matches!(ch, '/' | '@' | '?' | '#' | ':' | '\\' | '"') {
            return Err(format!("it contains {ch:?}; a relay hostname is a name and not a URL"));
        }
    }
    if name.starts_with('.') {
        return Err("it starts with a dot".to_string());
    }
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            return Err("it has an empty label".to_string());
        }
        if label.len() > 63 {
            return Err(format!("the label {label:?} is over 63 bytes"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("the label {label:?} starts or ends with a hyphen"));
        }
    }
    Ok(())
}