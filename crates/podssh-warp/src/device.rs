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
use crate::routes::Route;

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
    /// The endpoints of the API's peers, each `ADDRESS:443`, tried after
    /// `endpoint` (T-561); a record of before has none.
    #[serde(default)]
    peers: Vec<String>,
    /// The endpoint that last opened the tunnel, tried first (T-561).
    #[serde(default)]
    reached: Option<String>,
    /// The route to WARP's API that last answered for the device,
    /// `HOST[:PORT]`, tried first (T-562).
    #[serde(default)]
    api: Option<String>,
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
    /// Where the edge serves HTTP/2: the record's endpoint, 162.159.198.2:443
    /// since the registration.
    pub endpoint: SocketAddr,
    pub address_v4: Option<Ipv4Addr>,
    pub address_v6: Option<Ipv6Addr>,
    pub registered: String,
    pub team: bool,
    /// Where the probe of a tunnel that has just opened goes (T-560): a
    /// setting of the run, which the record never holds. Cloudflare's
    /// resolver of a family that the device has; none skips the probe.
    pub probe: Option<SocketAddr>,
    /// The endpoints of the API's peers, on port 443, tried after
    /// `endpoint` (T-561).
    pub peers: Vec<SocketAddr>,
    /// The endpoint that last opened the tunnel, tried first; a run that
    /// opens none forgets it (T-561).
    pub reached: Option<SocketAddr>,
    /// The one endpoint of the run (`PODSSH_WARP_ENDPOINT`, a stand-in),
    /// tried alone: a setting of the run, never of the record.
    pub only: Option<SocketAddr>,
    /// The route to WARP's API that registered the device, or answered its
    /// last read, which the caller tries first (T-562).
    pub api: Option<Route>,
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
            .field("probe", &self.probe)
            .field("peers", &self.peers)
            .field("reached", &self.reached)
            .field("only", &self.only)
            .field("api", &self.api)
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
        let mut device = Device {
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
            probe: None,
            peers: Vec::new(),
            reached: None,
            only: None,
            api: None,
        };
        device.probe = crate::probe::target(&device.addresses());
        Ok(device)
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
            peers: self.peers.iter().map(SocketAddr::to_string).collect(),
            reached: self.reached.map(|at| at.to_string()),
            api: self.api.as_ref().map(Route::to_string),
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
        let Record {
            version,
            id,
            token,
            key,
            endpoint_key,
            endpoint,
            address_v4,
            address_v6,
            registered,
            team,
            peers,
            reached,
            api,
        } = record;
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
        let peers = peers
            .iter()
            .map(|peer| peer.parse::<SocketAddr>().map_err(|_| format!("its peer {peer:?} is not ADDRESS:PORT")))
            .collect::<Result<Vec<_>, _>>()?;
        let reached = reached
            .filter(|at| !at.is_empty())
            .map(|at| at.parse::<SocketAddr>().map_err(|_| format!("its reached {at:?} is not ADDRESS:PORT")))
            .transpose()?;
        let api = api
            .filter(|route| !route.is_empty())
            .map(|route| Route::parse_authority(&route).map_err(|why| format!("its api {route:?}: {why}")))
            .transpose()?;
        let mut device = Device::new(id, token.to_string(), key, &endpoint_key, endpoint, v4, v6, registered, team)?
            .with_peers(peers);
        device.reached = reached;
        device.api = api;
        Ok(device)
    }

    /// The same device with the route to WARP's API that answered for it
    /// (T-562).
    pub fn by(mut self, route: Route) -> Device {
        self.api = Some(route);
        self
    }

    /// The same device with one endpoint for the run (`PODSSH_WARP_ENDPOINT`,
    /// or a stand-in), tried alone (T-561); the record's endpoint, its peers
    /// and the one that last opened stay as they are.
    pub fn at(mut self, endpoint: SocketAddr) -> Device {
        self.only = Some(endpoint);
        self
    }

    /// The same device with the endpoints of the API's `peers` (T-561).
    pub fn with_peers(mut self, peers: Vec<SocketAddr>) -> Device {
        self.peers = peers;
        self
    }

    /// The endpoints that a run tries, in turn (T-561): the run's one
    /// endpoint alone when it has one; else the one that last opened, the
    /// record's endpoint of HTTP/2, then the API's peers, each once.
    pub fn endpoints(&self) -> Vec<SocketAddr> {
        if let Some(only) = self.only {
            return vec![only];
        }
        let mut out: Vec<SocketAddr> = Vec::new();
        for at in self.reached.into_iter().chain([self.endpoint]).chain(self.peers.iter().copied()) {
            if !out.contains(&at) {
                out.push(at);
            }
        }
        out
    }

    /// The same device with the probe of its tunnel at `probe`, or with none
    /// (`PODSSH_WARP_PROBE=no`, T-560); a setting of the run, never of the
    /// record.
    pub fn probing(mut self, probe: Option<SocketAddr>) -> Device {
        self.probe = probe;
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
            crate::endpoint_h2(),
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

    /// The record keeps the API's peers and the endpoint that last opened;
    /// a record of before T-561 reads with neither. The endpoints go in turn:
    /// the one that opened, the record's, then the peers, each once; the
    /// run's one endpoint alone, which the record does not keep.
    #[test]
    fn the_endpoints_go_in_turn_and_the_record_keeps_them() {
        let texts = ["162.159.198.1:443", "[2606:4700:103::]:443"];
        let peers: Vec<SocketAddr> = texts.iter().map(|p| p.parse().unwrap()).collect();
        let mut first = device().with_peers(peers.clone());
        first.reached = Some(peers[1]);
        let again = Device::from_json(&first.to_json()).unwrap();
        assert_eq!((again.peers.clone(), again.reached), (peers.clone(), Some(peers[1])));
        let h2: SocketAddr = crate::endpoint_h2();
        assert_eq!(again.endpoints(), vec![peers[1], h2, peers[0]]);
        let only: SocketAddr = "127.0.0.1:4443".parse().unwrap();
        let run = again.clone().at(only);
        assert_eq!(run.endpoints(), vec![only]);
        let kept = Device::from_json(&run.to_json()).unwrap();
        assert_eq!((kept.endpoint, kept.only, kept.reached), (h2, None, Some(peers[1])));
        let mut record: serde_json::Value = serde_json::from_str(&device().to_json()).unwrap();
        let fields = record.as_object_mut().unwrap();
        fields.remove("peers");
        fields.remove("reached");
        let before = Device::from_json(&record.to_string()).unwrap();
        assert_eq!((before.peers.len(), before.reached, before.endpoints()), (0, None, vec![h2]));
        record["peers"] = serde_json::json!(["not an address"]);
        assert!(Device::from_json(&record.to_string()).unwrap_err().contains("its peer"));
    }

    /// The record keeps the route to WARP's API that answered (T-562); a
    /// record of before has none, and a route that does not read is refused
    /// by its field.
    #[test]
    fn the_record_keeps_the_route_of_the_api() {
        let route = Route { host: "api.devices.example".into(), port: 8443 };
        let first = device().by(route.clone());
        let again = Device::from_json(&first.to_json()).unwrap();
        assert_eq!(again.api, Some(route));
        assert_eq!(Device::from_json(&device().to_json()).unwrap().api, None);
        let mut record: serde_json::Value = serde_json::from_str(&first.to_json()).unwrap();
        record["api"] = serde_json::json!("bad host/");
        assert!(Device::from_json(&record.to_string()).unwrap_err().contains("its api"));
    }

    /// The probe goes to the resolver of the device's IPv4 by default; its
    /// setting is the run's, and the record holds none (T-560).
    #[test]
    fn the_probe_is_a_setting_of_the_run() {
        let first = device();
        assert_eq!(first.probe, Some(crate::probe::target_v4()));
        let json = first.clone().probing(None).to_json().to_string();
        assert!(!json.contains("probe") && !json.contains("1.1.1.1"), "{json}");
        assert_eq!(Device::from_json(&json).unwrap().probe, Some(crate::probe::target_v4()));
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
