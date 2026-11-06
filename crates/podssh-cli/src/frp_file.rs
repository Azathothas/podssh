//! The file of the frp road (T-498), which the node (`podssh node NAME
//! TARGET --frp FILE`) and its clients (`PODSSH_FRP=FILE podssh ssh
//! node://NAME`) share: frps, its token, and the secret of the node's STCP
//! service, a line each. The token and the secret are credentials, so the
//! file is the user's own and no one else may read it, as a key's; neither
//! goes on argv, in a line or in a URL.
//!
//! ```text
//! # frps behind the user's TLS front end, or frp's own TCP with TLS
//! server wss://frps.example
//! token the-frps-token
//! secret the-stcp-secret-of-this-node
//! ```
//!
//! `name NAME` names the service, where it is not the node's label.

use std::path::Path;
use std::sync::Arc;

use podssh_ws::frp::node::Road;
use podssh_ws::frp::Server;
use podssh_ws::Trust;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;

/// The variable that names the file for a client, or for a node with no
/// `--frp`.
pub const ENV: &str = "PODSSH_FRP";

/// The road of the file, and the service's name in it.
pub struct Frp {
    pub road: Road,
    pub name: Option<String>,
}

/// The words of one file: each line `KEY VALUE`; `#` starts a comment.
pub fn parse(text: &str, trust: Trust) -> Result<Frp, String> {
    let (mut server, mut token, mut secret, mut name) = (None, None, None, None);
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = n + 1;
        let (key, value) = line.split_once(char::is_whitespace).map(|(k, v)| (k, v.trim())).unwrap_or((line, ""));
        let slot = match key {
            "server" => &mut server,
            "token" => &mut token,
            "secret" => &mut secret,
            "name" => &mut name,
            // The line's number, never its text, which may hold a secret.
            _ => return Err(format!("line {at}: a key that the file does not have (server, token, secret, name)")),
        };
        if value.is_empty() {
            return Err(format!("line {at}: {key} names nothing"));
        }
        if slot.is_some() {
            return Err(format!("line {at}: {key} is given twice"));
        }
        *slot = Some(value.to_string());
    }
    let server = server.ok_or("no server line: frp://HOST[:PORT] or wss://HOST[:PORT][/PATH]")?;
    let server = Server::parse(&server)?;
    let token = token.ok_or("no token line: frps's auth.token")?;
    let secret = secret.ok_or("no secret line: the secret of the node's STCP service")?;
    if let Some(name) = &name {
        crate::pairs::check_label(name).map_err(|r| format!("name: {}", r.message))?;
    }
    let road = Road { server, token: Arc::new(Zeroizing::new(token)), secret: Arc::new(Zeroizing::new(secret)), trust };
    Ok(Frp { road, name })
}

/// The file at `path`, read as a private file of the user's.
pub fn read(path: &str, trust: Trust, at: &str) -> Result<Frp, Refusal> {
    let text =
        podssh_relay::cache::read_private(Path::new(path)).map_err(|why| Refusal::config(format!("{at}: {why}")))?;
    let text = Zeroizing::new(text);
    parse(&text, trust).map_err(|why| Refusal::config(format!("{at}: {why}")))
}

/// The file that `PODSSH_FRP` names, if it names one.
pub fn from_env(trust: Trust) -> Result<Option<Frp>, Refusal> {
    match std::env::var(ENV).ok().filter(|v| !v.trim().is_empty()) {
        Some(path) => read(path.trim(), trust, &format!("{ENV}={path}")).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_names_frps_its_token_and_the_secret_and_never_says_them() {
        let text = "# the road\nserver frp://frps.example\ntoken T0KEN-of-the-test\nsecret s3cret-of-the-test\n";
        let frp = parse(text, Trust::Default).unwrap();
        assert_eq!(frp.road.server.shown(), "frp://frps.example:7000");
        assert_eq!((frp.road.token.as_str(), frp.road.secret.as_str()), ("T0KEN-of-the-test", "s3cret-of-the-test"));
        assert_eq!(frp.name, None);
        for (bad, why) in [
            ("server frp://f.example\ntoken t\n", "no secret"),
            ("server ws://f.example\ntoken t\nsecret s\n", "ws://"),
            ("server frp://f.example\ntoken t\ntoken u\nsecret s\n", "twice"),
            ("server frp://f.example\npassword hunter2\n", "line 2"),
        ] {
            let e = parse(bad, Trust::Default).err().unwrap();
            assert!(e.contains(why), "{bad}: {e}");
            assert!(!e.contains("hunter2"), "{e}");
        }
    }
}
