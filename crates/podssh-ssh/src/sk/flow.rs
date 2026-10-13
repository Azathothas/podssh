//! The operations of a security key over CTAP2, on any channel: make a key,
//! sign, and ask a device silently whether it holds a key. The PIN, when a
//! device needs it, goes through the PIN protocol one. Linux speaks them
//! over `/dev/hidraw*`; the tests, to a device in software.

use std::time::Duration;

use zeroize::Zeroizing;

use super::cbor::{self, Value};
use super::ctap::{self, Info};
use super::format::{self, sha256, SkKey};
use super::hid::{Channel, Reports};
use super::pin::{self, Shared};
use super::{Alg, Ask, Enroll, Enrolled, Signed};

/// The time of a device for a command that needs no touch.
const ANSWER_LIMIT: Duration = Duration::from_secs(5);

/// The answer to a command: the CBOR of a success, else the status's words.
fn command<R: Reports>(channel: &mut Channel<R>, code: u8, request: &[u8], limit: Duration) -> Result<Value, String> {
    let (status, body) = channel.cbor(code, request, limit)?;
    if status != 0 {
        return Err(ctap::status(status));
    }
    cbor::decode_all(&body).map_err(|e| format!("the device's answer: {e}"))
}

/// Make a key in the device, which waits at most `limit` for the touch.
pub(crate) fn enroll<R: Reports>(
    channel: &mut Channel<R>,
    request: &Enroll,
    ask: &Ask,
    limit: Duration,
) -> Result<Enrolled, String> {
    let info = Info::read(&command(channel, ctap::GET_INFO, &[], ANSWER_LIMIT)?);
    if info.algorithms.as_ref().is_some_and(|algs| !algs.contains(&request.alg.cose())) {
        return Err(match request.alg {
            Alg::Ed25519 => "the device makes no Ed25519 key: use -t ecdsa-sk".into(),
            Alg::EcdsaP256 => "the device makes no ECDSA key of P-256".into(),
        });
    }
    if request.verify && info.client_pin != Some(true) {
        return Err("verify-required needs a PIN, and the device has none: set one with the tool of its maker".into());
    }
    // A device with a PIN needs it for a resident key, for a key that needs
    // it, and, before CTAP 2.1, for any key.
    let needs_pin = info.client_pin == Some(true) && (request.resident || request.verify || !info.no_pin_to_make);
    let client_data_hash: [u8; 32] = rand::random();
    let pin_auth = if needs_pin {
        Some(pin::auth(&token(channel, ask, "Enter PIN for the security key: ")?, &client_data_hash))
    } else {
        None
    };
    (ask.say)("You may need to touch your security key to authorize key generation.");
    let make = ctap::make_credential(
        &client_data_hash,
        &request.application,
        &request.user,
        request.alg.cose(),
        request.resident,
        pin_auth.as_deref(),
    );
    let answer = command(channel, ctap::MAKE_CREDENTIAL, &make, limit)?;
    let data = answer.at(2).and_then(Value::as_bytes).ok_or("the device's answer holds no authenticator data")?;
    format::enrolled(request.alg, &request.application, data, None)
}

/// Sign `data` with `key`, whose device waits at most `limit` for the touch.
pub(crate) fn sign<R: Reports>(
    channel: &mut Channel<R>,
    key: &SkKey,
    data: &[u8],
    ask: &Ask,
    limit: Duration,
) -> Result<Signed, String> {
    let hash = sha256(data);
    let pin_auth = if key.verify() {
        Some(pin::auth(&token(channel, ask, "Enter PIN for the security key: ")?, &hash))
    } else {
        None
    };
    let request = ctap::get_assertion(&key.application, &hash, &key.key_handle, key.touch(), pin_auth.as_deref());
    let answer = command(channel, ctap::GET_ASSERTION, &request, limit)?;
    let auth_data = answer.at(2).and_then(Value::as_bytes).ok_or("the device's answer holds no authenticator data")?;
    let signature = answer.at(3).and_then(Value::as_bytes).ok_or("the device's answer holds no signature")?;
    format::signed(&key.application, auth_data, signature.to_vec())
}

/// Whether the device holds `key`: a signature with no touch, which a device
/// answers at once. `None` when the device cannot say (it takes no such
/// request).
pub(crate) fn holds<R: Reports>(channel: &mut Channel<R>, key: &SkKey) -> Option<bool> {
    let request = ctap::get_assertion(&key.application, &[0; 32], &key.key_handle, false, None);
    match channel.cbor(ctap::GET_ASSERTION, &request, ANSWER_LIMIT) {
        Ok((0, _)) => Some(true),
        Ok((ctap::NO_CREDENTIALS, _)) => Some(false),
        _ => None,
    }
}

/// The device's token of the PIN, which the person gives at `prompt`.
fn token<R: Reports>(channel: &mut Channel<R>, ask: &Ask, prompt: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let pin = (ask.pin)(prompt)?;
    pin::check(&pin)?;
    let answer = command(channel, ctap::CLIENT_PIN, &ctap::get_key_agreement(), ANSWER_LIMIT)?;
    let key = answer.at(1).ok_or("the device gave no key of the PIN protocol")?;
    let coordinate = |label| key.at(label).and_then(Value::as_bytes).filter(|c| c.len() == 32);
    let (Some(x), Some(y)) = (coordinate(-2), coordinate(-3)) else {
        return Err("the device's key of the PIN protocol has no x and y of 32 bytes".into());
    };
    let shared = Shared::agree(x, y)?;
    let hash = shared.encrypt(&pin::pin_hash(&pin))?;
    let (ours_x, ours_y) = shared.coordinates();
    let answer = command(channel, ctap::CLIENT_PIN, &ctap::get_pin_token(ours_x, ours_y, &hash), ANSWER_LIMIT)?;
    let sealed = answer.at(2).and_then(Value::as_bytes).ok_or("the device gave no token of the PIN")?;
    shared.decrypt(sealed)
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
