//! Security keys on a system that is not Linux or Windows: podssh has no
//! way to the device here (macOS gives one only through IOKit), so each use
//! refuses with the reason. A key that an agent holds still signs, through
//! the agent (OpenSSH's `ssh-agent` with its own helper).

use std::path::Path;

use super::format::SkKey;
use super::{Ask, Enroll, Enrolled, Signed};

/// No device is ever found here.
pub(super) enum Found {}

impl Found {
    pub fn describe(&self) -> String {
        match *self {}
    }
}

pub(super) fn probe(_named: Option<&Path>) -> Result<Found, String> {
    Err("no security key: podssh reaches a security key on Linux (/dev/hidraw) and Windows (WebAuthn) only; \
         here an agent that holds the key, such as OpenSSH's ssh-agent, signs with it"
        .into())
}

pub(super) fn enroll(found: &Found, _request: &Enroll, _ask: &Ask) -> Result<Enrolled, String> {
    match *found {}
}

pub(super) fn sign(found: &Found, _key: &SkKey, _data: &[u8], _ask: &Ask) -> Result<Signed, String> {
    match *found {}
}
