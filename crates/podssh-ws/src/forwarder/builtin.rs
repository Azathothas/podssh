//! The templates of other products' public forwarders that the binary
//! carries (T-370), each selected by a word, by the operator's ruling Q56:
//! the three that GitHub #59 measured on 2026-10-31. They serve their own
//! products' users, publish no limit and give no notice, so the order puts
//! a second provider before a second copy of the first: when Cloudflare's
//! runtime refuses a target, the copy on the same runtime refuses it too.

/// A forwarder that the binary names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Builtin {
    /// The word that selects it, as `--forwarder mudlet`.
    pub word: &'static str,
    pub template: &'static str,
    /// What it is, for the manual and `doctor`.
    pub note: &'static str,
}

/// The built-in forwarders, in the order of the fallback.
pub const BUILTIN: &[Builtin] = &[
    Builtin {
        word: "mudlet",
        template: "wss://web-proxy.mudlet.org/?host={host}&port={port}",
        note: "the Worker of Mudlet's web client, on Cloudflare, whose runtime refuses port 25, private addresses \
               and Cloudflare's own; each of its users shares the requests of its plan",
    },
    Builtin {
        word: "ssheasy",
        template: "wss://ssheasy.com/p",
        note: "the proxy of ssheasy's SSH client in a browser, which takes the target in a first frame; its code \
               slows a connection to 100 KiB/s after 1 GiB, and takes one connection a second from each address",
    },
    Builtin {
        word: "mudix",
        template: "wss://mudix.delwing.workers.dev/?host={host}&port={port}",
        note: "an older copy of Mudlet's Worker, on one person's name under workers.dev",
    },
];

/// The built-in forwarder of `word`, in any case.
pub fn lookup(word: &str) -> Option<&'static Builtin> {
    BUILTIN.iter().find(|b| b.word.eq_ignore_ascii_case(word.trim()))
}

/// The words, as a refusal lists them: `mudlet, ssheasy, mudix`.
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
        assert_eq!(forms, [("mudlet", Form::Query), ("ssheasy", Form::Frame), ("mudix", Form::Query)]);
        let shown = |b: &Builtin| Template::parse(b.template).unwrap().shown().to_string();
        let shown: Vec<String> = BUILTIN.iter().map(shown).collect();
        assert_eq!(shown, ["wss://web-proxy.mudlet.org/", "wss://ssheasy.com/p", "wss://mudix.delwing.workers.dev/"]);
        assert_eq!(lookup(" MudLet ").map(|b| b.word), Some("mudlet"));
        assert_eq!(lookup("mudlett"), None);
        assert_eq!(words(), "mudlet, ssheasy, mudix");
    }
}
