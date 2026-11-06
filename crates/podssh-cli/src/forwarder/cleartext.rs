//! The forwarders that the binary names, in their `ws://` form (T-326,
//! GitHub #56): tried last in the fallback, once the `wss://` form of each
//! failed, and only for a forwarder whose host passed a probe with no TLS
//! on the port of that form (`podssh_ws::cleartext::probe`), the probes one
//! at a time. No relay token goes to a forwarder, so the operator's ruling
//! Q45 asks nothing more of this road; each hop reads the target, which the
//! form carries in its URL or its first frame, and SSH inside stays end to
//! end. `PODSSH_CLEARTEXT=no` turns it off, as it turns off the relay's.

use std::time::Duration;

use podssh_ws::forwarder::builtin::{self, Builtin};
use podssh_ws::forwarder::{Template, WISP};
use podssh_ws::url::WsUrl;
use podssh_ws::ProxyChoice;

use super::Forwarder;

/// The bound on each probe.
pub const PROBE_WAIT: Duration = Duration::from_secs(5);

/// The `ws://` text of a template of the binary's: its `wss://`, Wisp's
/// too, with no TLS.
fn ws_text(b: &Builtin) -> String {
    b.template.replacen("wss://", "ws://", 1)
}

/// The `ws://` form of a forwarder that the binary names, named by its word
/// and its URL.
pub fn ws_form(b: &Builtin) -> Option<Forwarder> {
    let template = Template::parse(&ws_text(b)).ok()?;
    let name = format!("{} ({})", b.word, template.shown());
    Some(Forwarder { template, name })
}

/// The host and the port of a template's URL, Wisp's prefix aside.
fn host_of(text: &str) -> Option<(String, u16)> {
    let url = text.strip_prefix(WISP).unwrap_or(text);
    WsUrl::parse(url).ok().map(|u| (u.host, u.port))
}

/// The `ws://` forms whose hosts passed the probe, in the order of the
/// fallback; none when `PODSSH_CLEARTEXT` turns the road off. Each probe's
/// words go to `say`.
pub async fn passed(say: &mut dyn FnMut(&str)) -> Vec<Forwarder> {
    match podssh_relay::cleartext::on() {
        Ok(true) => {}
        Ok(false) => return Vec::new(),
        Err(why) => {
            say(&format!("{why}; the ws:// forms of the forwarders are not tried"));
            return Vec::new();
        }
    }
    let mut out = Vec::new();
    for b in builtin::BUILTIN.iter() {
        let (Some(form), Some((host, port))) = (ws_form(b), host_of(&ws_text(b))) else { continue };
        let heard = podssh_ws::cleartext::probe(&host, port, &ProxyChoice::FromEnvironment, PROBE_WAIT).await;
        say(&format!("{} in cleartext: {}", podssh_ws::dial::authority(&host, port), heard.words()));
        if heard.passed() {
            out.push(form);
        }
    }
    out
}

/// The line before the `ws://` forms: what goes to whom, with no TLS.
pub fn announce(target: &str, forms: &[Forwarder]) -> String {
    let names: Vec<&str> = forms.iter().map(|f| f.name.as_str()).collect();
    format!(
        "each forwarder's wss:// failed: podssh sends {target} to {}, with no TLS, where a probe in \
         cleartext passed; each hop reads the target, and SSH inside stays end to end; {}=no turns this off",
        names.join(", "),
        podssh_relay::cleartext::CLEARTEXT_ENV
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each forwarder of the binary has a `ws://` form of its own form, on
    /// port 80 of its host.
    #[test]
    fn each_built_in_forwarder_has_a_ws_form() {
        for b in builtin::BUILTIN.iter() {
            let form = ws_form(b).unwrap_or_else(|| panic!("{}", b.word));
            let ws = form.name.starts_with(&format!("{} (ws://", b.word)) || form.name.contains("wisp+ws://");
            assert!(ws, "{}", form.name);
            assert_eq!(form.template.form(), Template::parse(b.template).unwrap().form(), "{}", b.word);
            let (host, port) = host_of(&ws_text(b)).unwrap();
            assert_eq!(port, 80, "{}", b.word);
            assert!(b.template.contains(&host), "{}", b.word);
        }
        let line = announce("192.0.2.1:22", &[ws_form(&builtin::BUILTIN[0]).unwrap()]);
        let said = "podssh sends 192.0.2.1:22 to mudlet (ws://web-proxy.mudlet.org/), with no TLS";
        assert!(line.contains(said), "{line}");
        assert!(line.ends_with("PODSSH_CLEARTEXT=no turns this off"), "{line}");
    }
}
