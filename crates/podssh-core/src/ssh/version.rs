//! RFC 4253 §4.2: the version banner.
//!
//! ```text
//! SSH-protoversion-softwareversion SP comments CR LF
//! ```
//! Both sides send theirs first, before any packet. The banner is a line,
//! not a packet — a decoder pointed at it misframes, so version exchange
//! happens before `packet::Decoder` ever sees a byte.

/// What podssh announces. The version is the crate's contract with servers
/// that key behaviour off the peer string; it changes only deliberately.
pub const OUR_VERSION: &str = "SSH-2.0-podssh_0.1.0";

/// A parsed peer banner: protocol version plus the raw line (kept whole —
/// the kex hash needs the exact bytes, and a re-rendered banner is not them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// `2.0` for SSH-2.0; anything else is refused by the caller.
    pub proto: String,
    /// The full line without CR LF, exactly as received.
    pub raw: String,
}

/// Why a banner is not a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionError {
    /// No CR LF in the buffer yet: wait for more, do not guess.
    NeedMore,
    /// The line does not start with `SSH-`.
    NotSsh { line: String },
    /// `SSH-1.x`: refused — podssh negotiates nothing below 2.0, and a
    /// client that falls back to SSH-1 is a client with no security.
    UnsupportedProtocol { proto: String },
    /// Over 255 bytes (RFC 4253 §4.2: "MUST NOT send" — a longer line is a
    /// peer violating the bound, not a banner to buffer without limit).
    TooLong { bytes: usize },
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedMore => write!(f, "no banner line yet; need more bytes"),
            Self::NotSsh { line } => write!(f, "{line:?} is not an SSH banner"),
            Self::UnsupportedProtocol { proto } => {
                write!(f, "SSH protocol {proto} is not 2.0 and is refused")
            }
            Self::TooLong { bytes } => write!(f, "banner of {bytes} bytes exceeds 255"),
        }
    }
}

impl std::error::Error for VersionError {}

/// Our banner on the wire, with its terminator.
pub fn our_banner() -> Vec<u8> {
    format!("{OUR_VERSION}\r\n").into_bytes()
}

/// Parse one banner line out of a byte buffer. Returns the version and the
/// bytes consumed (banner + CR LF); `NeedMore` leaves the buffer untouched.
/// Lines before the banner that do not start with `SSH-` are skipped one at
/// a time (RFC 4253 §4.2 allows other lines first) — but a skipped line is
/// reported as exactly that, never silently eaten in bulk.
pub fn parse_version(buf: &[u8]) -> Result<(Version, usize), VersionError> {
    let end = buf.windows(2).position(|w| w == b"\r\n").ok_or(VersionError::NeedMore)?;
    let line = &buf[..end];
    if line.len() > 255 {
        return Err(VersionError::TooLong { bytes: line.len() });
    }
    let text = String::from_utf8_lossy(line);
    let Some(rest) = text.strip_prefix("SSH-") else {
        return Err(VersionError::NotSsh { line: text.into_owned() });
    };
    let proto = rest.split(['-', ' ']).next().unwrap_or("");
    // `2.x` proceeds. `1.99` is the RFC 4253 §4.2 dual-stack marker — a
    // peer that speaks 2.0 but says 1.99 — so it proceeds too. Anything else
    // below 2.0 is refused: podssh never answers SSH-1.
    if !(proto.starts_with("2.") || proto == "1.99") {
        return Err(VersionError::UnsupportedProtocol { proto: proto.to_string() });
    }
    Ok((Version { proto: proto.to_string(), raw: text.into_owned() }, end + 2))
}
