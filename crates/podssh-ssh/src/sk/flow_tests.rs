//! The operations over CTAP2, against a device in software that speaks
//! CTAPHID and CTAP2 as the specification gives them: a key made and a
//! signature that ssh-key verifies, a PIN through the PIN protocol one, a
//! wrong PIN, a device that nobody touches, a device of other algorithms.
//! A real device's run waits for the operator (T-229's Done).

use std::cell::RefCell;
use std::collections::VecDeque;

use aws_lc_rs::agreement::{self, UnparsedPublicKey, ECDH_P256};
use russh::keys::ssh_key::Signature;
use signature::Verifier;

use super::super::hid::REPORT;
use super::super::soft::{attested, auth_data as soft_auth_data, SoftKey};
use super::super::{private_key, USER_PRESENCE_REQUIRED, USER_VERIFICATION_REQUIRED};
use super::*;

const CID: u32 = 0x0102_0304;

/// A FIDO2 device in software.
struct Fake {
    /// Reports for podssh to read.
    pending: VecDeque<[u8; 64]>,
    /// A message on its way in: its channel, command, length and data.
    incoming: Option<(u32, u8, usize, Vec<u8>)>,
    keys: Vec<(Vec<u8>, SoftKey)>,
    pin: Option<String>,
    agreement: agreement::PrivateKey,
    token: [u8; 32],
    counter: u32,
    /// Whether a person touches the device.
    touched: bool,
    algorithms: Vec<i64>,
    cancelled: bool,
}

impl Fake {
    fn new() -> Fake {
        Fake {
            pending: VecDeque::new(),
            incoming: None,
            keys: Vec::new(),
            pin: None,
            agreement: agreement::PrivateKey::generate(&ECDH_P256).unwrap(),
            token: [0x55; 32],
            counter: 0,
            touched: true,
            algorithms: vec![-8, -7],
            cancelled: false,
        }
    }

    fn respond(&mut self, cid: u32, command: u8, payload: &[u8]) {
        let mut report = [0u8; 64];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = command;
        report[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let first = payload.len().min(57);
        report[7..7 + first].copy_from_slice(&payload[..first]);
        self.pending.push_back(report);
        for (seq, chunk) in payload[first..].chunks(59).enumerate() {
            let mut report = [0u8; 64];
            report[..4].copy_from_slice(&cid.to_be_bytes());
            report[4] = seq as u8;
            report[5..5 + chunk.len()].copy_from_slice(chunk);
            self.pending.push_back(report);
        }
    }

    fn message(&mut self, cid: u32, command: u8, data: Vec<u8>) {
        match command {
            0x86 => {
                let mut answer = data[..8].to_vec();
                answer.extend_from_slice(&CID.to_be_bytes());
                answer.extend_from_slice(&[2, 1, 0, 0, 0x04]);
                self.respond(cid, 0x86, &answer);
            }
            0x91 => self.cancelled = true,
            0x90 => {
                let request = cbor::decode_all(&data[1..]).unwrap_or(Value::Null);
                let touch = matches!(data[0], 0x01 | 0x02)
                    && request.at(5).and_then(|o| o.field("up")).and_then(Value::as_bool) != Some(false);
                if touch {
                    self.respond(cid, 0xbb, &[2]);
                    if !self.touched {
                        return;
                    }
                }
                let (status, body) = match self.ctap(data[0], &request) {
                    Ok(body) => (0, body.to_vec()),
                    Err(status) => (status, Vec::new()),
                };
                let mut answer = vec![status];
                answer.extend_from_slice(&body);
                self.respond(cid, 0x90, &answer);
            }
            _ => self.respond(cid, 0xbf, &[1]),
        }
    }

    /// The answer to a CTAP2 command, or its status.
    fn ctap(&mut self, command: u8, request: &Value) -> Result<Value, u8> {
        let bytes = |key: i64| request.at(key).and_then(Value::as_bytes).map(<[u8]>::to_vec);
        match command {
            0x04 => {
                let algorithms =
                    self.algorithms.iter().map(|a| Value::Map(vec![(Value::text("alg"), Value::Int(*a))])).collect();
                let options = vec![(Value::text("clientPin"), Value::Bool(self.pin.is_some()))];
                Ok(Value::Map(vec![(Value::Int(4), Value::Map(options)), (Value::Int(10), Value::Array(algorithms))]))
            }
            0x01 => {
                let hash = bytes(1).ok_or(0x14u8)?;
                let rp = request.at(2).and_then(|rp| rp.field("id")).and_then(Value::as_text).ok_or(0x14u8)?;
                let alg = request
                    .at(4)
                    .and_then(Value::as_array)
                    .and_then(|list| list[0].field("alg"))
                    .and_then(Value::as_int)
                    .ok_or(0x14u8)?;
                let flags = self.verified(&hash, bytes(8), true)?;
                let key = match alg {
                    -8 if self.algorithms.contains(&-8) => SoftKey::new(Alg::Ed25519),
                    -7 if self.algorithms.contains(&-7) => SoftKey::new(Alg::EcdsaP256),
                    _ => return Err(0x26),
                };
                let id: Vec<u8> = rand::random::<[u8; 32]>().to_vec();
                let data = attested(rp, flags, &id, &key.cose());
                self.keys.push((id, key));
                Ok(Value::Map(vec![(Value::Int(1), Value::text("none")), (Value::Int(2), Value::Bytes(data))]))
            }
            0x02 => {
                let rp = request.at(1).and_then(Value::as_text).ok_or(0x14u8)?;
                let hash = bytes(2).ok_or(0x14u8)?;
                let id = request
                    .at(3)
                    .and_then(Value::as_array)
                    .and_then(|list| list[0].field("id"))
                    .and_then(Value::as_bytes)
                    .ok_or(0x14u8)?;
                let up = request.at(5).and_then(|o| o.field("up")).and_then(Value::as_bool) != Some(false);
                let mut flags = self.verified(&hash, bytes(6), false)? & !0x01;
                if up {
                    flags |= 0x01;
                }
                let at = self.keys.iter().position(|(k, _)| k == id).ok_or(0x2eu8)?;
                self.counter += 1;
                let data = soft_auth_data(rp, flags, self.counter);
                let mut signed = data.clone();
                signed.extend_from_slice(&hash);
                let signature = self.keys[at].1.sign(&signed);
                Ok(Value::Map(vec![(Value::Int(2), Value::Bytes(data)), (Value::Int(3), Value::Bytes(signature))]))
            }
            0x06 => self.client_pin(request),
            _ => Err(0x01),
        }
    }

    /// The flags of a request: UP, and UV when its proof of the PIN holds.
    /// A device with a PIN needs the proof to make a key (`make`), as a
    /// device of CTAP 2.0 does, and not to sign.
    fn verified(&self, hash: &[u8], proof: Option<Vec<u8>>, make: bool) -> Result<u8, u8> {
        match (&self.pin, proof) {
            (Some(_), None) if make => Err(0x36),
            (_, None) => Ok(0x01),
            (_, Some(proof)) => {
                let hash: [u8; 32] = hash.try_into().map_err(|_| 0x02u8)?;
                // CTAP2's pinAuth, made here and not by the code under test:
                // the first 16 bytes of HMAC-SHA-256 of the hash with the token.
                let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &self.token[..]);
                if aws_lc_rs::hmac::sign(&key, &hash).as_ref()[..16] == proof[..] {
                    Ok(0x05)
                } else {
                    Err(0x33)
                }
            }
        }
    }

    fn client_pin(&mut self, request: &Value) -> Result<Value, u8> {
        let ours = self.agreement.compute_public_key().unwrap().as_ref().to_vec();
        match request.at(2).and_then(Value::as_int) {
            Some(0x02) => {
                let key = Value::Map(vec![
                    (Value::Int(1), Value::Int(2)),
                    (Value::Int(3), Value::Int(-25)),
                    (Value::Int(-1), Value::Int(1)),
                    (Value::Int(-2), Value::Bytes(ours[1..33].to_vec())),
                    (Value::Int(-3), Value::Bytes(ours[33..].to_vec())),
                ]);
                Ok(Value::Map(vec![(Value::Int(1), key)]))
            }
            Some(0x05) => {
                let platform = request.at(3).ok_or(0x14u8)?;
                let mut point = vec![0x04];
                point.extend_from_slice(platform.at(-2).and_then(Value::as_bytes).ok_or(0x14u8)?);
                point.extend_from_slice(platform.at(-3).and_then(Value::as_bytes).ok_or(0x14u8)?);
                let secret =
                    agreement::agree(&self.agreement, UnparsedPublicKey::new(&ECDH_P256, &point), 0x02u8, |shared| {
                        Ok(sha256(shared))
                    })?;
                let shared = Shared::of_secret(secret);
                let sent = request.at(6).and_then(Value::as_bytes).ok_or(0x14u8)?;
                let hash = shared.decrypt(sent).map_err(|_| 0x02u8)?;
                let pin = self.pin.as_deref().ok_or(0x35u8)?;
                // CTAP2's pinHash, made here and not by the code under test:
                // the first 16 bytes of the PIN's SHA-256.
                if hash[..] != sha256(pin.as_bytes())[..16] {
                    return Err(0x31);
                }
                let sealed = shared.encrypt(&self.token).map_err(|_| 0x02u8)?;
                Ok(Value::Map(vec![(Value::Int(2), Value::Bytes(sealed))]))
            }
            _ => Err(0x02),
        }
    }
}

impl Reports for &mut Fake {
    fn send(&mut self, report: &[u8; REPORT]) -> std::io::Result<()> {
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        if report[4] & 0x80 != 0 {
            let total = usize::from(u16::from_be_bytes([report[5], report[6]]));
            self.incoming = Some((cid, report[4], total, report[7..7 + total.min(57)].to_vec()));
        } else if let Some((_, _, total, data)) = self.incoming.as_mut() {
            let take = (*total - data.len()).min(59);
            data.extend_from_slice(&report[5..5 + take]);
        }
        if self.incoming.as_ref().is_some_and(|(_, _, total, data)| data.len() >= *total) {
            let (cid, command, _, data) = self.incoming.take().unwrap();
            self.message(cid, command, data);
        }
        Ok(())
    }

    fn receive(&mut self, _wait: Duration) -> std::io::Result<Option<[u8; REPORT]>> {
        Ok(self.pending.pop_front())
    }
}

const LIMIT: Duration = Duration::from_secs(1);

fn request(alg: Alg) -> Enroll {
    Enroll { alg, application: "ssh:".into(), user: vec![0; 32], resident: false, touch: true, verify: false }
}

/// A key is made, and its signature, made into SSH's, verifies with the
/// public key of the key file; the person is told to touch the device.
#[test]
fn a_key_is_made_and_signs_through_ctap2() {
    for alg in [Alg::Ed25519, Alg::EcdsaP256] {
        let mut device = Fake::new();
        let said = RefCell::new(Vec::new());
        let say = |line: &str| said.borrow_mut().push(line.to_string());
        let no_pin = |_: &str| -> Result<Zeroizing<String>, String> { Err("no PIN here".into()) };
        let ask = Ask { say: &say, pin: &no_pin };
        let mut channel = Channel::open(&mut device, [1; 8]).unwrap();
        let made = enroll(&mut channel, &request(alg), &ask, LIMIT).unwrap();
        assert!(said.borrow()[0].contains("touch your security key"), "{:?}", said.borrow());
        let file = private_key(alg, &made, "ssh:", USER_PRESENCE_REQUIRED, "").unwrap();
        let key = SkKey::of(file.key_data()).unwrap();
        assert_eq!(holds(&mut channel, &key), Some(true));
        let signed = sign(&mut channel, &key, b"a login", &ask, LIMIT).unwrap();
        assert_eq!((signed.flags, signed.counter), (0x01, 2), "{alg:?}: one silent check, then this one");
        let blob = format::signature_blob(alg, &signed).unwrap();
        let ssh = Signature::try_from(&blob[..]).unwrap();
        file.public_key().key_data().verify(b"a login", &ssh).unwrap_or_else(|e| panic!("{alg:?}: {e}"));
        let other = SkKey { key_handle: vec![9; 48], ..key };
        assert_eq!(holds(&mut channel, &other), Some(false));
    }
}

/// A device with a PIN gets it through the PIN protocol one: the key is
/// made, and a key that needs the PIN signs with UV; a wrong PIN is said.
#[test]
fn a_pin_goes_through_the_pin_protocol() {
    let mut device = Fake::new();
    device.pin = Some("4321".into());
    let say = |_: &str| {};
    let right = |_: &str| -> Result<Zeroizing<String>, String> { Ok(Zeroizing::new("4321".into())) };
    let ask = Ask { say: &say, pin: &right };
    let mut channel = Channel::open(&mut device, [2; 8]).unwrap();
    let wanted = Enroll { resident: true, verify: true, ..request(Alg::EcdsaP256) };
    let made = enroll(&mut channel, &wanted, &ask, LIMIT).unwrap();
    let flags = wanted.flags();
    assert_eq!(flags, USER_PRESENCE_REQUIRED | USER_VERIFICATION_REQUIRED | super::super::RESIDENT_KEY);
    let file = private_key(Alg::EcdsaP256, &made, "ssh:", flags, "").unwrap();
    let key = SkKey::of(file.key_data()).unwrap();
    let signed = sign(&mut channel, &key, b"data", &ask, LIMIT).unwrap();
    assert_eq!(signed.flags, 0x05, "the device verified the user");

    let wrong = |_: &str| -> Result<Zeroizing<String>, String> { Ok(Zeroizing::new("1111".into())) };
    let ask = Ask { say: &say, pin: &wrong };
    assert_eq!(sign(&mut channel, &key, b"data", &ask, LIMIT).unwrap_err(), "the PIN is wrong");
    let short = |_: &str| -> Result<Zeroizing<String>, String> { Ok(Zeroizing::new("12".into())) };
    let ask = Ask { say: &say, pin: &short };
    assert!(sign(&mut channel, &key, b"data", &ask, LIMIT).unwrap_err().contains("4 characters"));
}

/// With nobody to touch the device, the wait ends, the command is
/// cancelled, and the message says so.
#[test]
fn nobody_touches_the_device() {
    let mut device = Fake::new();
    device.touched = false;
    let say = |_: &str| {};
    let no_pin = |_: &str| -> Result<Zeroizing<String>, String> { Err("no PIN here".into()) };
    let ask = Ask { say: &say, pin: &no_pin };
    let mut channel = Channel::open(&mut device, [3; 8]).unwrap();
    let late = enroll(&mut channel, &request(Alg::Ed25519), &ask, LIMIT).unwrap_err();
    assert_eq!(late, "nobody touched the security key within 1 s");
    assert!(device.cancelled);
}

#[test]
fn a_device_of_other_algorithms_or_with_no_pin_says_so() {
    let mut device = Fake::new();
    device.algorithms = vec![-7];
    let say = |_: &str| {};
    let no_pin = |_: &str| -> Result<Zeroizing<String>, String> { Err("no PIN here".into()) };
    let ask = Ask { say: &say, pin: &no_pin };
    let mut channel = Channel::open(&mut device, [4; 8]).unwrap();
    let refused = enroll(&mut channel, &request(Alg::Ed25519), &ask, LIMIT).unwrap_err();
    assert!(refused.contains("no Ed25519 key"), "{refused}");
    let verify = Enroll { verify: true, ..request(Alg::EcdsaP256) };
    let refused = enroll(&mut channel, &verify, &ask, LIMIT).unwrap_err();
    assert!(refused.contains("verify-required needs a PIN"), "{refused}");
}
