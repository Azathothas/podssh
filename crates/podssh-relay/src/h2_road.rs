//! Which sessions of the forward road take the WebSocket over HTTP/2 (T-321,
//! [`podssh_ws::h2_road`]), by `PODSSH_H2`: unset, empty or `auto`, a
//! session to a relay host that the user named, as podssh's own relay role
//! is named, and none to a host of the default relay, whose edge chose `h2`
//! with no extended CONNECT (measured 2026-10-30), so that a run there pays
//! no second connection; `yes`, each session; `no`, none, the upgrade of
//! HTTP/1.1 alone, as before. Another word takes the upgrade alone, and
//! `podssh doctor`'s line `http2` says so.

use podssh_ws::{ConnectError, RelaySession, WsClientConfig};

use crate::open::Opened;

/// The variable that says which sessions take the road.
pub const H2_ENV: &str = "PODSSH_H2";

/// The words of [`H2_ENV`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// A relay host that the user named.
    Auto,
    /// Each relay host.
    Yes,
    /// None.
    No,
}

impl Choice {
    /// The choice of `value`; another word is refused, with why.
    pub fn parse(value: Option<&str>) -> Result<Choice, String> {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            None | Some("" | "auto") => Ok(Choice::Auto),
            Some("yes" | "on" | "true" | "1") => Ok(Choice::Yes),
            Some("no" | "off" | "false" | "0") => Ok(Choice::No),
            Some(_) => Err(format!("{H2_ENV}: auto, yes or no")),
        }
    }

    /// [`Choice::parse`] of this process's variable.
    pub fn from_env() -> Result<Choice, String> {
        Choice::parse(std::env::var(H2_ENV).ok().as_deref())
    }

    /// Whether a session to a host of a list that the user named
    /// (`explicit`), or of the default relay, takes the road.
    pub fn offers(self, explicit: bool) -> bool {
        match self {
            Choice::Auto => explicit,
            Choice::Yes => true,
            Choice::No => false,
        }
    }
}

/// The session of `config` with `token` to a host of a list that the user
/// named when `explicit`: on the road where [`Choice`] offers it, its words
/// kept in the session for `-v`; else the upgrade of HTTP/1.1, as
/// [`podssh_ws::connect`] makes it.
pub async fn connect(config: &WsClientConfig, token: &str, explicit: bool) -> Result<RelaySession, ConnectError> {
    if !Choice::from_env().is_ok_and(|choice| choice.offers(explicit)) {
        return podssh_ws::connect(config, token).await;
    }
    let (session, road) = podssh_ws::h2_road::connect(config, token).await?;
    Ok(match road.words() {
        Some(words) => session.with_road(words),
        None => session,
    })
}

impl Opened {
    /// How the session is carried, after the relay host's name in a line:
    /// in cleartext (T-326), over HTTP/2 or HTTP/1.1 after it (T-321), over
    /// QUIC (T-667), or nothing more to say.
    pub fn road(&self) -> String {
        if self.cleartext {
            return " in cleartext".to_string();
        }
        self.session.road().map(|how| format!(", {how}")).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unset is auto: the hosts that the user named; another word is
    /// refused, and offers nothing.
    #[test]
    fn the_variable_says_which_hosts_take_the_road() {
        for (value, choice) in [(None, Choice::Auto), (Some(" "), Choice::Auto), (Some("AUTO"), Choice::Auto)] {
            assert_eq!(Choice::parse(value), Ok(choice), "{value:?}");
        }
        assert_eq!(Choice::parse(Some("yes")), Ok(Choice::Yes));
        assert_eq!(Choice::parse(Some("off")), Ok(Choice::No));
        assert_eq!(Choice::parse(Some("maybe")), Err("PODSSH_H2: auto, yes or no".into()));
        assert!(Choice::Auto.offers(true) && !Choice::Auto.offers(false), "named hosts alone");
        assert!(Choice::Yes.offers(false) && !Choice::No.offers(true));
    }
}
