//! The templates of other products' public forwarders that the binary
//! carries (T-370), each selected by a word, by the operator's ruling Q56:
//! the three that GitHub #59 measured on 2026-10-31. They serve their own
//! products' users, publish no limit and give no notice, so the order puts
//! a second provider before a second copy of the first: when Cloudflare's
//! runtime refuses a target, the copy on the same runtime refuses it too.
//! After them, and never first, by the operator's ruling Q65: the demo
//! server of the Wisp protocol (T-438), whose operator says it is "primarily
//! for demo and testing".

use std::sync::LazyLock;

/// A forwarder that the binary names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Builtin {
    /// The word that selects it, as `--forwarder mudlet`.
    pub word: &'static str,
    pub template: &'static str,
    /// What it is, for the manual and `doctor`.
    pub note: &'static str,
}

/// The built-in forwarders, in the order of the fallback: the services of
/// the kind `forwarder` of `pod-services`, by their rank, each with its
/// facts `word`, `template` and `note`.
pub static BUILTIN: LazyLock<Vec<Builtin>> = LazyLock::new(|| {
    let fact = |s: &'static pod_services::Service, name: &str| s.text(name).unwrap_or_default();
    let each = |s| Builtin { word: fact(s, "word"), template: fact(s, "template"), note: fact(s, "note") };
    pod_services::of_kind("forwarder").map(each).collect()
});

/// The built-in forwarder of `word`, in any case.
pub fn lookup(word: &str) -> Option<&'static Builtin> {
    BUILTIN.iter().find(|b| b.word.eq_ignore_ascii_case(word.trim()))
}

/// The words, as a refusal lists them: `mudlet, ssheasy, mudix, wisp`.
pub fn words() -> String {
    BUILTIN.iter().map(|b| b.word).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::super::{Form, Template};
    use super::*;

    /// Each template parses in the form that its forwarder takes, and no
    /// two share a word or a host.
    #[test]
    fn each_built_in_template_is_one_of_its_form() {
        let forms: Vec<(&str, Form)> =
            BUILTIN.iter().map(|b| (b.word, Template::parse(b.template).unwrap().form())).collect();
        let want = [("mudlet", Form::Query), ("ssheasy", Form::Frame), ("mudix", Form::Query), ("wisp", Form::Wisp)];
        assert_eq!(forms, want);
        let shown = |b: &Builtin| Template::parse(b.template).unwrap().shown().to_string();
        let shown: Vec<String> = BUILTIN.iter().map(shown).collect();
        let want = [
            "wss://web-proxy.mudlet.org/",
            "wss://ssheasy.com/p",
            "wss://mudix.delwing.workers.dev/",
            "wisp+wss://wisp.mercurywork.shop/",
        ];
        assert_eq!(shown, want);
        assert_eq!(lookup(" MudLet ").map(|b| b.word), Some("mudlet"));
        assert_eq!(lookup("WISP").map(|b| b.word), Some("wisp"));
        assert_eq!(lookup("mudlett"), None);
        assert_eq!(words(), "mudlet, ssheasy, mudix, wisp");
    }
}
