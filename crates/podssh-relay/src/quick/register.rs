//! The registration of a quick tunnel's connection (T-300): the parameters
//! of `registerConnection` and its answer, as cloudflared's schema at
//! 2026.10.6 lays them out (`tunnelrpc/proto/tunnelrpc.capnp`, the interface
//! `RegistrationServer`; the sizes and places are those of its generated
//! code, `tunnelrpc.capnp.go`).

use std::time::Duration;

use podssh_ws::text::one_line;

use super::capnp::{At, Builder, Malformed, Struct};

/// `RegistrationServer`, and its methods.
pub const REGISTRATION_SERVER: u64 = 0xf716_95ec_7fe8_5497;
pub const REGISTER_CONNECTION: u16 = 0;
pub const UNREGISTER_CONNECTION: u16 = 1;
pub const UPDATE_LOCAL_CONFIGURATION: u16 = 2;

/// The sizes of the parameters of each method: data words and pointers.
pub const REGISTER_PARAMS: (u16, u16) = (1, 3);
pub const UNREGISTER_PARAMS: (u16, u16) = (0, 0);
pub const CONFIGURATION_PARAMS: (u16, u16) = (0, 1);

/// The features that cloudflared 2026.10.6 names when it registers: those of
/// the registration that T-299 measured, over HTTP/2, at the edge. Since
/// cloudflared's commit 77a79bf the edge treats each of them as given, and
/// 2026.10.7 names none of them; podssh names those of the pin's release,
/// which the edge takes from each release that it supports (T-404).
pub const FEATURES: &[&str] =
    &["allow_remote_config", "serialized_headers", "support_datagram_v2", "support_quic_eof", "management_logs"];

/// What a connector names when it registers a connection.
pub struct Registration<'a> {
    /// The tunnel's credentials, from the reply to the request for a tunnel.
    pub account_tag: &'a str,
    pub secret: &'a [u8],
    pub tunnel_id: [u8; 16],
    /// Which connection of the tunnel this is: 0, as a quick tunnel has one.
    pub conn_index: u8,
    /// This connector's own id, new each run.
    pub client_id: [u8; 16],
    pub features: &'a [&'a str],
    pub version: &'a str,
    /// The system and the machine, as cloudflared writes them: `linux_amd64`.
    pub arch: &'a str,
}

impl Registration<'_> {
    /// Write the parameters into `params`, a struct of [`REGISTER_PARAMS`],
    /// field by field in the schema's order. `originLocalIp`,
    /// `replaceExisting`, `compressionQuality` and `numPreviousAttempts`
    /// stay unset: none, false, 0 and 0.
    pub fn write(&self, b: &mut Builder, params: At) {
        let auth = b.init_struct(params, 0, 0, 2);
        b.set_text(auth, 0, self.account_tag);
        b.set_data(auth, 1, self.secret);
        b.set_data(params, 1, &self.tunnel_id);
        b.set_u8(params, 0, self.conn_index);
        let options = b.init_struct(params, 2, 1, 2);
        let client = b.init_struct(options, 0, 0, 4);
        b.set_data(client, 0, &self.client_id);
        b.set_text_list(client, 1, self.features);
        b.set_text(client, 2, self.version);
        b.set_text(client, 3, self.arch);
    }
}

/// Write the parameters of `updateLocalConfiguration`, the ingress rules as
/// JSON, into `params`, a struct of [`CONFIGURATION_PARAMS`].
pub fn write_configuration(b: &mut Builder, params: At, config: &[u8]) {
    b.set_data(params, 0, config);
}

/// The answer of `registerConnection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registered {
    /// The connection is registered: its id, the data center where it
    /// landed, and whether the tunnel's configuration is managed remotely.
    Details { uuid: Vec<u8>, location: String, remotely_managed: bool },
    /// The edge refused it: why, and whether to try again after `after`.
    Refused { cause: String, retry: bool, after: Duration },
}

/// The answer in `results`, the results of `registerConnection`: one
/// pointer, to a `ConnectionResponse`, whose union is at its first bytes.
/// The edge's texts, the cause and the place, reach a line, so they are
/// made one line with no control character here, where they are read.
pub fn read_results(results: Struct<'_>) -> Result<Registered, Malformed> {
    let response = results.get_struct(0)?.ok_or(Malformed("a registration's answer with no result"))?;
    match response.u16(0) {
        0 => {
            let error = response.get_struct(0)?.ok_or(Malformed("a refusal with no error"))?;
            let nanos = error.u64(0) as i64;
            Ok(Registered::Refused {
                cause: one_line(error.get_text(0)?.unwrap_or_default()),
                retry: error.bit(64),
                after: Duration::from_nanos(nanos.max(0) as u64),
            })
        }
        1 => {
            let details = response.get_struct(0)?.ok_or(Malformed("a registration with no details"))?;
            Ok(Registered::Details {
                uuid: details.get_data(0)?.unwrap_or_default().to_vec(),
                location: one_line(details.get_text(1)?.unwrap_or_default()),
                remotely_managed: details.bit(0),
            })
        }
        _ => Err(Malformed("a registration's answer of a kind that is not known")),
    }
}
