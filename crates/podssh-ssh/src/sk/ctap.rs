//! The commands of CTAP2 that podssh sends (CTAP 2.0, section 5), in its
//! canonical CBOR: the keys of each map in the canonical order (integers
//! first, then texts, the shorter first), as a strict device wants them;
//! and the words of each status that a device answers.

use super::cbor::Value;

pub(crate) const MAKE_CREDENTIAL: u8 = 0x01;
pub(crate) const GET_ASSERTION: u8 = 0x02;
pub(crate) const GET_INFO: u8 = 0x04;
pub(crate) const CLIENT_PIN: u8 = 0x06;

/// The status of a device that does not hold the key asked for.
pub(crate) const NO_CREDENTIALS: u8 = 0x2e;

/// The PIN protocol one, and its subcommands.
const PIN_PROTOCOL: i64 = 1;
const GET_KEY_AGREEMENT: i64 = 0x02;
const GET_PIN_TOKEN: i64 = 0x05;
/// COSE's ECDH-ES with HKDF-256, the algorithm of the key agreement.
const ECDH_ES_HKDF_256: i64 = -25;

fn int(n: i64) -> Value {
    Value::Int(n)
}

/// `{"id": ID, "type": "public-key"}`: a key that a device holds.
fn credential(id: &[u8]) -> Value {
    Value::Map(vec![(Value::text("id"), Value::Bytes(id.to_vec())), (Value::text("type"), Value::text("public-key"))])
}

/// authenticatorMakeCredential: a new key of the COSE algorithm `alg` for
/// `rp_id`, of the user `user_id` (OpenSSH's user and display names are
/// "openssh"), resident when asked, and with the proof of the PIN when the
/// device needs it.
pub(crate) fn make_credential(
    client_data_hash: &[u8; 32],
    rp_id: &str,
    user_id: &[u8],
    alg: i64,
    resident: bool,
    pin_auth: Option<&[u8]>,
) -> Vec<u8> {
    let mut map = vec![
        (int(1), Value::Bytes(client_data_hash.to_vec())),
        (int(2), Value::Map(vec![(Value::text("id"), Value::text(rp_id))])),
        (
            int(3),
            Value::Map(vec![
                (Value::text("id"), Value::Bytes(user_id.to_vec())),
                (Value::text("name"), Value::text("openssh")),
                (Value::text("displayName"), Value::text("openssh")),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![Value::Map(vec![
                (Value::text("alg"), int(alg)),
                (Value::text("type"), Value::text("public-key")),
            ])]),
        ),
    ];
    if resident {
        map.push((int(7), Value::Map(vec![(Value::text("rk"), Value::Bool(true))])));
    }
    if let Some(auth) = pin_auth {
        map.push((int(8), Value::Bytes(auth.to_vec())));
        map.push((int(9), int(PIN_PROTOCOL)));
    }
    Value::Map(map).to_vec()
}

/// authenticatorGetAssertion: a signature of the key `credential_id` for
/// `rp_id`, of the client data whose hash is `client_data_hash`. With `up`
/// false the device signs with no touch: for a key made with
/// `no-touch-required`, and to ask a device silently whether it holds a key.
pub(crate) fn get_assertion(
    rp_id: &str,
    client_data_hash: &[u8; 32],
    credential_id: &[u8],
    up: bool,
    pin_auth: Option<&[u8]>,
) -> Vec<u8> {
    let mut map = vec![
        (int(1), Value::text(rp_id)),
        (int(2), Value::Bytes(client_data_hash.to_vec())),
        (int(3), Value::Array(vec![credential(credential_id)])),
    ];
    if !up {
        map.push((int(5), Value::Map(vec![(Value::text("up"), Value::Bool(false))])));
    }
    if let Some(auth) = pin_auth {
        map.push((int(6), Value::Bytes(auth.to_vec())));
        map.push((int(7), int(PIN_PROTOCOL)));
    }
    Value::Map(map).to_vec()
}

/// authenticatorClientPIN getKeyAgreement: the device's key of the PIN
/// protocol one.
pub(crate) fn get_key_agreement() -> Vec<u8> {
    Value::Map(vec![(int(1), int(PIN_PROTOCOL)), (int(2), int(GET_KEY_AGREEMENT))]).to_vec()
}

/// authenticatorClientPIN getPINToken: podssh's key of the agreement (the
/// x and y of a P-256 point), and the PIN's hash, encrypted.
pub(crate) fn get_pin_token(x: &[u8], y: &[u8], pin_hash_enc: &[u8]) -> Vec<u8> {
    let key = Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(ECDH_ES_HKDF_256)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(x.to_vec())),
        (int(-3), Value::Bytes(y.to_vec())),
    ]);
    Value::Map(vec![
        (int(1), int(PIN_PROTOCOL)),
        (int(2), int(GET_PIN_TOKEN)),
        (int(3), key),
        (int(6), Value::Bytes(pin_hash_enc.to_vec())),
    ])
    .to_vec()
}

/// What podssh reads of authenticatorGetInfo.
#[derive(Debug, Default)]
pub(crate) struct Info {
    /// The option `clientPin`: `Some(true)` when the device has a PIN,
    /// `Some(false)` when it has none yet, `None` when it takes none.
    pub client_pin: Option<bool>,
    /// The option `makeCredUvNotRqd` of CTAP 2.1: a key that is not
    /// resident needs no PIN.
    pub no_pin_to_make: bool,
    /// The COSE algorithms of the device's keys, when it lists them.
    pub algorithms: Option<Vec<i64>>,
}

impl Info {
    pub fn read(answer: &Value) -> Info {
        let options = answer.at(4);
        let option = |name: &str| options.and_then(|o| o.field(name)).and_then(Value::as_bool);
        let algorithms = answer
            .at(10)
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(|entry| entry.field("alg").and_then(Value::as_int)).collect());
        Info { client_pin: option("clientPin"), no_pin_to_make: option("makeCredUvNotRqd") == Some(true), algorithms }
    }
}

/// The words of a status of CTAP2.
pub(crate) fn status(code: u8) -> String {
    let words = match code {
        0x01 => "the device does not know the command",
        0x02 | 0x11 | 0x12 | 0x14 => "the device could not read podssh's request",
        0x19 => "the device holds this key already",
        0x26 => "the device makes no key of this type",
        0x27 => "the device refused the operation",
        0x28 => "the device has no room for another resident key",
        0x2b | 0x2c => "the device does not take an option of the request",
        0x2d => "the operation was cancelled",
        NO_CREDENTIALS => "the device does not hold this key",
        0x2f | 0x3a => "the device's own time for a touch ran out",
        0x31 => "the PIN is wrong",
        0x32 => "the device's PIN is blocked: only a reset of the device opens it again",
        0x33 => "the device refused the proof of the PIN",
        0x34 => "the device takes no PIN until it is plugged in again",
        0x35 => "the device has no PIN: set one with the tool of its maker",
        0x36 => "the device needs its PIN",
        0x37 => "the PIN breaks the device's rules (4 to 63 bytes)",
        0x39 => "the request is too large for the device",
        0x3b => "the device needs a touch",
        _ => return format!("the device refused (CTAP2 status {code:#04x})"),
    };
    words.to_string()
}

#[cfg(test)]
mod tests {
    use super::super::cbor::decode_all;
    use super::*;

    /// A request reads back as CTAP2 keys it, and each map's keys are in
    /// the canonical order.
    #[test]
    fn requests_have_the_fields_of_ctap2() {
        let request = decode_all(&make_credential(&[1; 32], "ssh:", &[0; 32], -8, true, Some(&[9; 16]))).unwrap();
        assert_eq!(request.at(1).and_then(Value::as_bytes), Some(&[1u8; 32][..]));
        assert_eq!(request.at(2).and_then(|rp| rp.field("id")).and_then(Value::as_text), Some("ssh:"));
        assert_eq!(request.at(3).and_then(|u| u.field("name")).and_then(Value::as_text), Some("openssh"));
        let alg = request.at(4).and_then(Value::as_array).and_then(|a| a[0].field("alg")).and_then(Value::as_int);
        assert_eq!(alg, Some(-8));
        assert_eq!(request.at(7).and_then(|o| o.field("rk")).and_then(Value::as_bool), Some(true));
        assert_eq!(request.at(9).and_then(Value::as_int), Some(1));
        let Value::Map(pairs) = &request else { panic!("a map") };
        let keys: Vec<i64> = pairs.iter().filter_map(|(k, _)| k.as_int()).collect();
        assert_eq!(keys, [1, 2, 3, 4, 7, 8, 9]);

        let plain = decode_all(&make_credential(&[1; 32], "ssh:", &[0; 32], -7, false, None)).unwrap();
        assert!(plain.at(7).is_none() && plain.at(8).is_none());

        let silent = decode_all(&get_assertion("ssh:", &[2; 32], b"handle", false, None)).unwrap();
        assert_eq!(silent.at(1).and_then(Value::as_text), Some("ssh:"));
        let allowed = silent.at(3).and_then(Value::as_array).unwrap();
        assert_eq!(allowed[0].field("id").and_then(Value::as_bytes), Some(&b"handle"[..]));
        assert_eq!(silent.at(5).and_then(|o| o.field("up")).and_then(Value::as_bool), Some(false));
        let touched = decode_all(&get_assertion("ssh:", &[2; 32], b"handle", true, None)).unwrap();
        assert!(touched.at(5).is_none(), "a touch is the default");
    }

    #[test]
    fn get_info_is_read() {
        let answer = Value::Map(vec![
            (int(1), Value::Array(vec![Value::text("FIDO_2_0")])),
            (
                int(4),
                Value::Map(vec![
                    (Value::text("clientPin"), Value::Bool(true)),
                    (Value::text("makeCredUvNotRqd"), Value::Bool(true)),
                ]),
            ),
            (int(10), Value::Array(vec![Value::Map(vec![(Value::text("alg"), int(-7))])])),
        ]);
        let info = Info::read(&answer);
        assert_eq!(info.client_pin, Some(true));
        assert!(info.no_pin_to_make);
        assert_eq!(info.algorithms, Some(vec![-7]));
        let bare = Info::read(&Value::Map(vec![]));
        assert_eq!((bare.client_pin, bare.no_pin_to_make, bare.algorithms), (None, false, None));
        assert_eq!(status(0x31), "the PIN is wrong");
        assert_eq!(status(0x7f), "the device refused (CTAP2 status 0x7f)");
    }
}
