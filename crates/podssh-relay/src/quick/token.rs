//! The token of a named tunnel of the user's own Cloudflare account (T-180,
//! `podssh funnel --tunnel-token-file FILE`), as cloudflared reads one
//! (`cmd/cloudflared/tunnel/subcommands.go` at 2026.10.6, `TunnelToken`):
//! base64 of a JSON object with the account's tag `a`, the tunnel's id `t`
//! and its secret `s` in base64. It registers the node as a quick tunnel's
//! credentials do, at the names that the account routes to the tunnel,
//! which podssh does not know: no name is asked of the API. The token is a
//! credential: no error quotes it.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use zeroize::Zeroizing;

use super::api::{uuid_bytes, Tunnel};

/// The tunnel of `text`, a token as Cloudflare's dashboard gives it, with
/// white space around it; `Err` says why, never with the token's bytes.
pub fn read(text: &str) -> Result<Tunnel, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("the file holds no token".into());
    }
    let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(text).ok())
        .map(Zeroizing::new)
        .ok_or("the token is not base64, as Cloudflare's dashboard gives one")?;
    let value: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|_| "the token is not a tunnel's token: no JSON in it")?;
    let field = |name: &str| value.get(name).and_then(|v| v.as_str());
    let (Some(account), Some(id), Some(secret)) = (field("a"), field("t"), field("s")) else {
        return Err("the token names no account (a), tunnel (t) or secret (s)".into());
    };
    let id = uuid_bytes(id).ok_or("the token's tunnel id is not a UUID")?;
    let secret = STANDARD.decode(secret).map_err(|_| "the token's secret is not base64")?;
    if secret.len() < 32 {
        return Err("the token's secret is shorter than a tunnel's".into());
    }
    let hostname = String::new();
    Ok(Tunnel { id, hostname, account_tag: account.to_string(), secret: Zeroizing::new(secret) })
}

/// The id of a tunnel as its account shows it.
pub fn shown_id(id: &[u8; 16]) -> String {
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token of the form that cloudflared reads, made here: the fields
    /// come back, and a broken one says why with none of its bytes.
    #[test]
    fn a_token_reads_its_account_its_tunnel_and_its_secret() {
        let secret = STANDARD.encode([9u8; 32]);
        let json = format!(r#"{{"a":"0123abcd","t":"11111111-2222-3333-4444-555555555555","s":"{secret}"}}"#);
        let token = STANDARD.encode(json);
        let tunnel = read(&format!("  {token}\n")).unwrap();
        assert_eq!(tunnel.account_tag, "0123abcd");
        assert_eq!(shown_id(&tunnel.id), "11111111-2222-3333-4444-555555555555");
        assert_eq!(tunnel.secret.as_slice(), &[9u8; 32]);
        assert!(tunnel.hostname.is_empty(), "the account routes the names");
        for bad in ["", "not base64 !!", &STANDARD.encode("{}"), &STANDARD.encode("plain text")] {
            let why = read(bad).unwrap_err();
            assert!(bad.is_empty() || !why.contains(bad), "{why}");
        }
    }
}
