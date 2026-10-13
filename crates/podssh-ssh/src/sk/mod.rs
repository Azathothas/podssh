//! Security keys: OpenSSH's `sk-` keys, whose private key stays in a FIDO2
//! device, and each signature of which needs a touch (T-229). podssh makes
//! such a key (`podssh keygen -t ed25519-sk`), signs a login with its key
//! file, and `podssh agent` signs with one that it holds. Each use probes
//! first: with no device that podssh may reach, it refuses with the reason
//! before it writes or sends anything (AGENTS.md, section 5, rule 1).
//!
//! The way to the device: on Linux, CTAP2 over `/dev/hidraw*`, in Rust
//! (CTAPHID, CBOR and the PIN protocol one); on Windows, the WebAuthn API of
//! the system (webauthn.dll, loaded at run time), which talks to the device
//! and shows its own dialog; on each other system none, and a key that an
//! agent holds signs through the agent. A device has [`TOUCH_LIMIT`] for an
//! operation, the touch included.

// The CTAP2 parts serve Linux; the tests run them on each system.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod cbor;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod ctap;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod flow;
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
mod format;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod hid;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod pin;
#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;
#[cfg(not(any(target_os = "linux", windows)))]
#[path = "other.rs"]
mod platform;

pub mod agent;
pub(crate) mod signer;

use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

pub use format::{is_sk, private_key, public_blob, signature_blob, SkKey};

/// A device's time for an operation, the touch included.
pub const TOUCH_LIMIT: Duration = Duration::from_secs(30);

/// The variable that names the device: a path of `/dev/hidraw*` on Linux,
/// or `none`, which turns security keys off.
pub const DEVICE_VARIABLE: &str = "PODSSH_SK_DEVICE";

/// The flags of an `sk-` key (OpenSSH's sk-api.h): each signature needs a
/// touch, each needs the PIN, and the key lives in the device (resident).
pub const USER_PRESENCE_REQUIRED: u8 = 0x01;
pub const USER_VERIFICATION_REQUIRED: u8 = 0x04;
pub const RESIDENT_KEY: u8 = 0x20;

/// The two kinds of `sk-` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Ed25519,
    EcdsaP256,
}

impl Alg {
    /// The key's name in SSH.
    pub fn ssh_name(self) -> &'static str {
        match self {
            Alg::Ed25519 => "sk-ssh-ed25519@openssh.com",
            Alg::EcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    /// COSE's number of its signature (RFC 9053): EdDSA, or ES256.
    pub(crate) fn cose(self) -> i64 {
        match self {
            Alg::Ed25519 => -8,
            Alg::EcdsaP256 => -7,
        }
    }
}

/// A request to make a key in a device: the `-O` options of `ssh-keygen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enroll {
    pub alg: Alg,
    /// The application: `ssh:`, or what `-O application=` names.
    pub application: String,
    /// The user id of the key: what `-O user=` names, in 32 bytes, else 32
    /// bytes of zero, as OpenSSH gives it.
    pub user: Vec<u8>,
    /// The key lives in the device (`-O resident`).
    pub resident: bool,
    /// Each signature needs a touch; `-O no-touch-required` turns it off.
    pub touch: bool,
    /// Each signature needs the PIN (`-O verify-required`).
    pub verify: bool,
}

impl Enroll {
    /// The flags of the key file that this request makes.
    pub fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.touch {
            flags |= USER_PRESENCE_REQUIRED;
        }
        if self.verify {
            flags |= USER_VERIFICATION_REQUIRED;
        }
        if self.resident {
            flags |= RESIDENT_KEY;
        }
        flags
    }
}

/// A new key in a device: its public key (Ed25519's 32 bytes, or a P-256
/// point of 65) and the handle that the device gave for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    pub public: Vec<u8>,
    pub key_handle: Vec<u8>,
}

/// A device's signature: the flags and the counter that it signed with it,
/// and the signature (Ed25519's 64 bytes, or ECDSA's in X9.62's DER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub flags: u8,
    pub counter: u32,
    pub signature: Vec<u8>,
}

/// What an operation tells the person, and asks.
pub struct Ask<'a> {
    /// A line for the person, as the touch that the device waits for.
    pub say: &'a dyn Fn(&str),
    /// The PIN of the device, asked with this prompt, or why there is none.
    pub pin: &'a dyn Fn(&str) -> Result<Zeroizing<String>, String>,
}

/// A way to a device that the probe found.
pub struct Device(platform::Found);

impl Device {
    /// What the probe found, for `-v`.
    pub fn describe(&self) -> String {
        self.0.describe()
    }
}

/// The way to a device here, or why there is none: a message that starts
/// "no security key: ". `named` is the device that the user named (`-O
/// device=`); else [`DEVICE_VARIABLE`] names one, or turns them off.
pub fn probe(named: Option<&Path>) -> Result<Device, String> {
    let variable = std::env::var_os(DEVICE_VARIABLE).filter(|v| !v.is_empty());
    if named.is_none() && variable.as_deref().is_some_and(|v| v == "none") {
        return Err(format!("no security key: {DEVICE_VARIABLE} is none"));
    }
    let from_variable = variable.map(PathBuf::from);
    platform::probe(named.or(from_variable.as_deref())).map(Device)
}

/// Make a key in the device, as `request` asks.
pub fn enroll(device: &Device, request: &Enroll, ask: &Ask) -> Result<Enrolled, String> {
    platform::enroll(&device.0, request, ask)
}

/// Sign `data` with `key` in the device.
pub fn sign(device: &Device, key: &SkKey, data: &[u8], ask: &Ask) -> Result<Signed, String> {
    platform::sign(&device.0, key, data, ask)
}

/// Sign `data` with `key`: the probe, the device's signature, and the
/// signature as SSH carries it. `say` gets the line of the touch, and the
/// PIN is asked only when `may_ask` (not under `BatchMode`).
pub fn sign_blob(key: &SkKey, data: &[u8], say: &dyn Fn(&str), may_ask: bool) -> Result<Vec<u8>, String> {
    let device = probe(None)?;
    let pin = |prompt: &str| ask_pin(prompt, may_ask);
    let signed = sign(&device, key, data, &Ask { say, pin: &pin })?;
    signature_blob(key.alg, &signed)
}

/// The PIN, asked with podssh's prompt (the terminal or `SSH_ASKPASS`);
/// `may_ask` false (`BatchMode`) refuses it.
pub fn ask_pin(prompt: &str, may_ask: bool) -> Result<Zeroizing<String>, String> {
    if !may_ask {
        return Err("the key needs the PIN of its security key, and BatchMode forbids the question".into());
    }
    if !crate::prompt::can_ask() {
        return Err("the key needs the PIN of its security key, and there is no terminal or SSH_ASKPASS to ask".into());
    }
    crate::prompt::ask(prompt, false).map_err(|e| format!("the PIN of the security key: {e}"))
}

// A device in software, for the tests; last, as the manual's scan of the
// variables reads each file up to its first item of the tests.
#[cfg(test)]
mod soft;
