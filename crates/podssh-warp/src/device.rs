//! A device of WARP, as it is kept between runs: a registration at each
//! start would spend a device each time (GitHub #63's first comment), so
//! the caller keeps this record in a private file of its cache directory
//! (T-243) and reads it again. The record holds the device's token and its
//! key: it is a credential, and no `Debug` or error shows either.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::key::DeviceKey;

/// The name of the record in the cache directory.
pub const FILE: &str = "warp-device.json";
/// The version of the record's form; another is refused, not guessed.
pub const VERSION: u32 = 1;

/// The record as its file holds it.
#[derive(Serialize, Deserialize)]
struct Record {
    version: u32,
    /// The device's id at the API.
    id: String,
    /// The API's token of the device (Bearer), for a later change of it.
    token: String,
    /// The 32 bytes of the device's P-256 key, base64.
    key: String,
    /// The endpoint's public key, PEM, as the API gave it.
    endpoint_key: String,
    /// The endpoint of HTTP/2, `ADDRESS:443`.
    endpoint: String,
    /// The device's addresses inside the tunnel.
    #[serde(default)]
    address_v4: Option<String>,
    #[serde(default)]
    address_v6: Option<String>,
    /// When it was registered, RFC 3339.
    registered: String,
    /// Whether a team's token enrolled it (a Cloudflare One organization).
    #[serde(default)]
    team: bool,
}

/// A registered device.
#[derive(Clone)]
pub struct Device {
    pub id: String,
    token: Zeroizing<String>,
    pub key: DeviceKey,
    /// The endpoint's key, the SEC1 point that the TLS handshake pins.
    pub endpoint_point: Vec<u8>,
    /// The endpoint's key as the API gave it, PEM.
    pub endpoint_pem: String,
    /// Where the edge serves HTTP/2.
    pub endpoint: SocketAddr,
    pub address_v4: Option<Ipv4Addr>,
    pub address_v6: Option<Ipv6Addr>,
    pub registered: String,
    pub team: bool,
}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .field("address_v4", &self.address_v4)
            .field("address_v6", &self.address_v6)
            .field("registered", &self.registered)
            .field("team", &self.team)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// A device of its parts: the endpoint's key as PEM, which the handshake
    /// pins once it reads as a P-256 key.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        token: String,
        key: DeviceKey,
        endpoint_pem: &str,
        endpoint: SocketAddr,
        address_v4: Option<Ipv4Addr>,
        address_v6: Option<Ipv6Addr>,
        registered: String,
        team: bool,
    ) -> Result<Device, String> {
        let endpoint_point = endpoint_point(endpoint_pem)?;
        if address_v4.is_none() && address_v6.is_none() {
            return Err("the device has no address inside the tunnel".into());
        }
        Ok(Device {
            id,
            token: Zeroizing::new(token),
            key,
            endpoint_point,
            endpoint_pem: endpoint_pem.to_string(),
            endpoint,
            address_v4,
            address_v6,
            registered,
            team,
        })
    }

    /// The API's token of the device.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The device's addresses inside the tunnel.
    pub fn addresses(&self) -> Vec<IpAddr> {
        let v4 = self.address_v4.map(IpAddr::V4);
        let v6 = self.address_v6.map(IpAddr::V6);
        v4.into_iter().chain(v6).collect()
    }

    /// The record of the device, for its private file.
    pub fn to_json(&self) -> Zeroizing<String> {
        let record = Record {
            version: VERSION,
            id: self.id.clone(),
            token: self.token.to_string(),
            key: base64::engine::general_purpose::STANDARD.encode(&*self.key.scalar()),
            endpoint_key: self.endpoint_pem.clone(),
            endpoint: self.endpoint.to_string(),
            address_v4: self.address_v4.map(|a| a.to_string()),
            address_v6: self.address_v6.map(|a| a.to_string()),
            registered: self.registered.clone(),
            team: self.team,
        };
        let text = serde_json::to_string_pretty(&record).unwrap_or_default();
        let Record { mut token, mut key, .. } = record;
        zeroize::Zeroize::zeroize(&mut token);
        zeroize::Zeroize::zeroize(&mut key);
        Zeroizing::new(text)
    }

    /// The device of a record. An error names the field, never its value.
    pub fn from_json(text: &str) -> Result<Device, String> {
        // serde_json's words can quote a value, so only its place is said.
        let record: Record = serde_json::from_str(text)
            .map_err(|e| format!("not a record of a device (line {}, column {})", e.line(), e.column()))?;
        let Record { version, id, token, key, endpoint_key, endpoint, address_v4, address_v6, registered, team } =
            record;
        let (token, key_text) = (Zeroizing::new(token), Zeroizing::new(key));
        if version != VERSION {
            return Err(format!("a record of version {version}, where podssh reads {VERSION}"));
        }
        let scalar = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(key_text.as_bytes())
                .map_err(|_| "its key is not base64".to_string())?,
        );
        let key = DeviceKey::from_scalar(&scalar).map_err(|why| format!("its key: {why}"))?;
        let endpoint: SocketAddr =
            endpoint.parse().map_err(|_| format!("its endpoint {endpoint:?} is not ADDRESS:PORT"))?;
        let v4 = parse_opt::<Ipv4Addr>(address_v4.as_deref(), "address_v4")?;
        let v6 = parse_opt::<Ipv6Addr>(address_v6.as_deref(), "address_v6")?;
        Device::new(id, token.to_string(), key, &endpoint_key, endpoint, v4, v6, registered, team)
    }

    /// The same device at another endpoint (`PODSSH_WARP_ENDPOINT`, or a
    /// stand-in).
    pub fn at(mut self, endpoint: SocketAddr) -> Device {
        self.endpoint = endpoint;
        self
    }

    /// The endpoint's key that WARP's API gives now, PEM, in place of the
    /// one that the handshake pinned (T-399). A key that does not read
    /// leaves the device as it was; its file is the caller's to write.
    pub fn rekey(&mut self, endpoint_pem: &str) -> Result<(), String> {
        self.endpoint_point = endpoint_point(endpoint_pem)?;
        self.endpoint_pem = endpoint_pem.to_string();
        Ok(())
    }
}

fn parse_opt<T: std::str::FromStr>(text: Option<&str>, field: &str) -> Result<Option<T>, String> {
    match text.filter(|t| !t.is_empty()) {
        None => Ok(None),
        Some(t) => t.parse().map(Some).map_err(|_| format!("its {field} {t:?} is not an address")),
    }
}

/// The SEC1 point of the endpoint's key, PEM, as the API gives it: a
/// SubjectPublicKeyInfo of P-256 (usque reads it with Go's
/// `x509.ParsePKIXPublicKey` and keeps an ECDSA key alone).
pub fn endpoint_point(pem: &str) -> Result<Vec<u8>, String> {
    let der = crate::der::from_pem(pem, "PUBLIC KEY").ok_or("the endpoint's key is not a PEM PUBLIC KEY")?;
    let point = crate::der::p256_point(&der).ok_or("the endpoint's key is not a P-256 key")?;
    // The form that the handshake compares: uncompressed, as SEC1 allows two.
    let key = p256::PublicKey::from_sec1_bytes(point).map_err(|_| "the endpoint's key is no point of P-256")?;
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    Ok(key.to_sec1_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> Device {
        let endpoint = DeviceKey::generate().unwrap();
        let pem = crate::der::pem(&endpoint.spki(), "PUBLIC KEY");
        Device::new(
            "id-1".into(),
            "a-token".into(),
            DeviceKey::generate().unwrap(),
            &pem,
            crate::ENDPOINT_H2.parse().unwrap(),
            Some("172.16.0.2".parse().unwrap()),
            Some("2606:4700:110:8a36::1".parse().unwrap()),
            "2026-10-31T12:00:00.000+00:00".into(),
            false,
        )
        .unwrap()
    }

    /// A record reads back as the device that wrote it.
    #[test]
    fn a_record_reads_back() {
        let first = device();
        let again = Device::from_json(&first.to_json()).unwrap();
        assert_eq!(again.id, first.id);
        assert_eq!(again.token(), "a-token");
        assert_eq!(again.key.point(), first.key.point());
        assert_eq!(again.endpoint_point, first.endpoint_point);
        assert_eq!(again.endpoint, first.endpoint);
        assert_eq!(again.addresses(), first.addresses());
    }

    /// Neither the token nor the key shows in `Debug`, nor in an error of a
    /// record that cannot be read.
    #[test]
    fn no_credential_is_shown() {
        let first = device();
        let shown = format!("{first:?}");
        let json = first.to_json().to_string();
        let record: serde_json::Value = serde_json::from_str(&json).unwrap();
        let key = record["key"].as_str().unwrap();
        assert!(!shown.contains("a-token") && !shown.contains(key), "{shown}");
        let bad = json.replace(key, "!!!not base64!!!");
        let why = Device::from_json(&bad).unwrap_err();
        assert!(!why.contains("a-token") && !why.contains("!!!"), "{why}");
    }

    /// A new key of the endpoint replaces the pinned one, and its record
    /// keeps it; a key that does not read changes nothing.
    #[test]
    fn a_new_key_of_the_endpoint_is_pinned_and_kept() {
        let mut device = device();
        let next = DeviceKey::generate().unwrap();
        device.rekey(&crate::der::pem(&next.spki(), "PUBLIC KEY")).unwrap();
        assert_eq!(device.endpoint_point, next.point());
        assert_eq!(Device::from_json(&device.to_json()).unwrap().endpoint_point, next.point());
        assert!(device.rekey("not a key").is_err());
        assert_eq!(device.endpoint_point, next.point());
    }

    /// Another version, a key of another curve and no address are refused.
    #[test]
    fn a_record_of_another_shape_is_refused() {
        let json = device().to_json().to_string();
        let later = json.replace("\"version\": 1", "\"version\": 2");
        assert!(Device::from_json(&later).unwrap_err().contains("version 2"));
        let mut record: serde_json::Value = serde_json::from_str(&json).unwrap();
        record["address_v4"] = serde_json::Value::Null;
        record["address_v6"] = serde_json::Value::Null;
        assert!(Device::from_json(&record.to_string()).unwrap_err().contains("no address"));
        assert!(endpoint_point("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").is_err());
    }
}
