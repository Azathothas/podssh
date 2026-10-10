//! `005` — ISUPPORT — and the vocabulary it carries.
//!
//! **A server's `005` is the only place it states its own limits, and podssh
//! reads rather than assumes every one of them.** `NICKLEN`, `CHANNELLEN` and
//! `CHANLIMIT` decide whether an offer fits; `PREFIX` decides who is a voice
//! and who is an operator; `CHANMODES` decides which flags a `MODE` on a
//! channel may carry; `CASEMAPPING` decides whether `#Foo` and `#foo` are the
//! same channel. **A client that hardcodes any of them is wrong on some
//! network**, and this repository's own rule is that a capability is `MEASURED`
//! or the client does not depend on it.
//!
//! **Absent means absent.** [`Isupport::get`] returns `None` and the
//! [`Isupport::get_or`] default is the RFC's own value where RFC 1459 states
//! one. **An unknown token is kept, not dropped**: `005` carries vendor
//! extensions and a client that discards them cannot tell a network's
//! capability from its absence.

use std::collections::BTreeMap;

/// **RFC 1459 §2.6 default**, used when a server sends no `NICKLEN`.
pub const DEFAULT_NICKLEN: usize = 9;
/// **RFC 1459 §2.6 default**, used when a server sends no `CHANNELLEN`.
pub const DEFAULT_CHANNELLEN: usize = 64;

/// The parsed contents of `005`.
///
/// **A `BTreeMap`, so iteration is ordered and two parses of the same reply
/// compare equal.** A `HashMap` would make [`PartialEq`] on this type a coin
/// toss, and a structure whose equality is a coin toss cannot be asserted on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Isupport {
    entries: BTreeMap<String, Option<String>>,
}

impl Isupport {
    /// Parse the parameter list of a `005`, **skipping the first
    /// parameter**, which is the recipient's own nick and is not a token.
    ///
    /// `005 nick CHANTYPES=# PREFIX=(ov)@+ NETWORK=Example :are supported
    /// by this server`. A token with no `=` — `CHANTYPES` on a broken peer —
    /// is stored with no value rather than rejected, because dropping it would
    /// silently disable the feature it describes.
    pub fn parse(params: &[String]) -> Self {
        let mut entries = BTreeMap::new();
        for token in params.iter().skip(1) {
            match token.split_once('=') {
                Some((key, value)) => {
                    entries.insert(key.to_ascii_uppercase(), Some(value.to_string()));
                }
                None => {
                    entries.insert(token.to_ascii_uppercase(), None);
                }
            }
        }
        Isupport { entries }
    }

    /// **Add one `005` line to the lines before it** (T-095): each server
    /// measured sends several (ngircd 27 two, InspIRCd 4.11.0 and ergo 2.18.0
    /// three), with `CASEMAPPING` in the first and `NICKLEN` in a later one,
    /// so a line that replaced the ones before would lose half of them. A
    /// `-TOKEN` takes a token away.
    pub fn merge(&mut self, params: &[String]) {
        for token in params.iter().skip(1) {
            if let Some(gone) = token.strip_prefix('-') {
                self.entries.remove(&gone.to_ascii_uppercase());
                continue;
            }
            match token.split_once('=') {
                Some((key, value)) => self.entries.insert(key.to_ascii_uppercase(), Some(value.to_string())),
                None => self.entries.insert(token.to_ascii_uppercase(), None),
            };
        }
    }

    /// **`a` and `b` name the same nick or channel on this network**, by its
    /// `CASEMAPPING`: `ascii` folds `A-Z`; `rfc1459`, the default, also folds
    /// `[]\~` to `{}|^`; `strict-rfc1459` folds `[]\` but not `~`.
    pub fn same(&self, a: &str, b: &str) -> bool {
        let mapping = self.casemapping().to_ascii_lowercase();
        let fold = |c: char| -> char {
            match (c, mapping.as_str()) {
                (c, _) if c.is_ascii_uppercase() => c.to_ascii_lowercase(),
                ('[', "rfc1459" | "strict-rfc1459") => '{',
                (']', "rfc1459" | "strict-rfc1459") => '}',
                ('\\', "rfc1459" | "strict-rfc1459") => '|',
                ('~', "rfc1459") => '^',
                (c, _) => c,
            }
        };
        a.chars().map(fold).eq(b.chars().map(fold))
    }

    /// An empty `005`, for a server that sent none. Every accessor then
    /// returns its RFC default, **which is a working client**, not a broken
    /// one — an `Isupport` that panicked here would make `005` mandatory, and
    /// `005` is not.
    pub fn empty() -> Self {
        Isupport::default()
    }

    /// The raw value, or `None` if the token was absent or valueless.
    pub fn get(&self, token: &str) -> Option<&str> {
        self.entries.get(&token.to_ascii_uppercase()).and_then(|v| v.as_deref())
    }

    pub fn get_or<'a>(&'a self, token: &str, default: &'a str) -> &'a str {
        self.get(token).unwrap_or(default)
    }

    pub fn contains(&self, token: &str) -> bool {
        self.entries.contains_key(&token.to_ascii_uppercase())
    }

    /// Every token the server sent, uppercase and ordered.
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|k| k.as_str())
    }

    /// **How many characters one nick may have**, `NICKLEN`.
    ///
    /// RFC 1459 §2.6 says 9, and the default is that 9 rather than a guess:
    /// **every network that matters sends `NICKLEN`**, so the default is only
    /// ever reached against a server too old to send it, and 9 is what such a
    /// server enforces.
    pub fn nicklen(&self) -> usize {
        self.number("NICKLEN").unwrap_or(DEFAULT_NICKLEN)
    }

    /// How many characters one channel name may have, `CHANNELLEN`.
    pub fn channellen(&self) -> usize {
        self.number("CHANNELLEN").unwrap_or(DEFAULT_CHANNELLEN)
    }

    /// How many users one channel may hold, `MAXTARGETS`. **`None` when
    /// the server sent no `MAXTARGETS`, which means no limit** — and a client
    /// that turned the absence into zero would refuse every transfer to every
    /// channel.
    pub fn maxtargets(&self) -> Option<usize> {
        self.number("MAXTARGETS")
    }

    /// **The mode characters that take a parameter**, as `(flags, needs_arg)`,
    /// from `CHANMODES=A,B,C`. **Empty means "unknown", not "none"**, which
    /// is why this is `Option`: a client that treated an absent `CHANMODES` as
    /// "modes take no arguments" would strip the argument from every `MODE` it
    /// forwards and produce a mode change the user did not ask for.
    pub fn chanmodes(&self) -> Option<ChanModes> {
        let raw = self.get("CHANMODES")?;
        let mut parts = raw.split(',');
        let list = |part: Option<&str>| -> Vec<char> {
            part.unwrap_or("").chars().filter(|c| !c.is_ascii_whitespace()).collect()
        };
        Some(ChanModes {
            address: list(parts.next()),
            parameter: list(parts.next()),
            set: list(parts.next()),
            remove: list(parts.next()),
        })
    }

    /// **Who is a voice and who is an operator**, from `PREFIX=(ov)@+`.
    ///
    /// **The two halves are independent lists and must be read in step.** A
    /// parser that took the first half of the flags and the second half of the
    /// prefixes would report `@` as an operator and `+` as a voice on every
    /// server, and `ov` and `@+` are the only spelling most servers use — so
    /// the bug would survive every smoke test and only misbehave on a network
    /// with three prefix modes.
    pub fn prefix(&self) -> PrefixModes {
        PrefixModes::parse(self.get("PREFIX"))
    }

    /// `CASEMAPPING`, e.g. `ascii`, `rfc1459`, `strict-rfc1459`. The
    /// default is `rfc1459`: RFC 2812 §5.2 changed the mapping and nearly no
    /// server implements it, so `strict-rfc1459` would be the wrong assumption
    /// rather than the safe one.
    pub fn casemapping(&self) -> &str {
        self.get_or("CASEMAPPING", "rfc1459")
    }

    /// Is this network's case folding plain ASCII?
    ///
    /// **A server may send an unknown `CASEMAPPING` value**, and the only
    /// safe answer is then "not plain ASCII" — because assuming ASCII is the
    /// one assumption that makes a client treat two different channels as the
    /// same one, which is how a message goes to the wrong room.
    pub fn is_ascii_casemapping(&self) -> bool {
        self.casemapping().eq_ignore_ascii_case("ascii")
    }

    fn number(&self, token: &str) -> Option<usize> {
        self.get(token)?.parse().ok()
    }
}

/// `CHANMODES`, split into the four lists its value carries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChanModes {
    /// Modes that always take an argument: `o`, `k`.
    pub address: Vec<char>,
    /// Modes that take an argument when *set*: `l`.
    pub parameter: Vec<char>,
    /// Modes that take an argument only when set *with a value*: `b`, `e`, `I`.
    pub set: Vec<char>,
    /// Same, when cleared: `k`, `l`.
    pub remove: Vec<char>,
}

impl ChanModes {
    /// **Does this mode take a parameter, given the sign?**
    ///
    /// The sign matters and that is the whole reason the lists are separate:
    /// `+l` takes `50` and `-l` does not, and a client that asked for the
    /// argument on both would emit a `MODE` line the server rejects.
    pub fn takes_parameter(&self, mode: char, adding: bool) -> bool {
        if self.address.contains(&mode) {
            return true;
        }
        if adding {
            self.parameter.contains(&mode) || self.set.contains(&mode)
        } else {
            self.parameter.contains(&mode) || self.remove.contains(&mode)
        }
    }
}

/// `PREFIX`, the two halves of a server's prefix vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrefixModes {
    /// Rank first is highest. **A mode's index is its rank**: the flags and
    /// the prefixes are read in step, so `@` is `o` because `o` is first in
    /// `(ov)` and `+` is `v` because `v` is second.
    pub modes: Vec<char>,
    /// In step with [`PrefixModes::modes`], the same length by construction.
    pub prefixes: Vec<char>,
}

impl PrefixModes {
    pub fn parse(raw: Option<&str>) -> Self {
        let raw = match raw {
            Some(r) => r,
            // A server with no `PREFIX` has no prefix modes at all, which is
            // legal: `PREFIX=(ov)@+` is an `005` token, not part of the
            // protocol. Empty here is "no prefixes exist", not "unknown".
            None => return PrefixModes::default(),
        };
        let mut modes = Vec::new();
        let mut prefixes = Vec::new();
        if let (Some(open), Some(close)) = (raw.find('('), raw.rfind(')')) {
            if open < close {
                modes = raw[open + 1..close].chars().collect();
            }
            prefixes = raw[close + 1..].chars().collect();
        }
        PrefixModes { modes, prefixes }
    }

    /// **The prefix character for a mode letter.** `None` when the mode is
    /// not a prefix mode, which is the case a client that assumed otherwise
    /// would turn into a mislabelled user.
    pub fn prefix_for(&self, mode: char) -> Option<char> {
        let rank = self.modes.iter().position(|m| *m == mode)?;
        self.prefixes.get(rank).copied()
    }

    /// The mode letter for a prefix character.
    pub fn mode_for(&self, prefix: char) -> Option<char> {
        let rank = self.prefixes.iter().position(|p| *p == prefix)?;
        self.modes.get(rank).copied()
    }

    /// Does this string begin with a prefix character? **A `+` or `@` in
    /// the middle of a nick is not a prefix**, so only the first character is
    /// examined — `bo+b` is a nick, not an op.
    pub fn split_prefix<'a>(&self, entry: &'a str) -> (Option<char>, &'a str) {
        match entry.chars().next() {
            Some(c) if self.prefixes.contains(&c) => (Some(c), &entry[c.len_utf8()..]),
            _ => (None, entry),
        }
    }
}
