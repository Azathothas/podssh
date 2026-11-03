//! The algorithm lists of a connection (T-505): `Ciphers`, `MACs`,
//! `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms` and
//! `CASignatureAlgorithms`, assembled as OpenSSH 10.3p1 assembles them
//! (`kex_assemble_names` of its `kex-names.c`): a list replaces podssh's
//! own, one that starts with `+` adds to it, with `-` takes from it, and
//! with `^` puts its names first. A name may be a pattern of `*` and `?`;
//! one that podssh does not speak is left out, as OpenSSH filters a list
//! by what it speaks, and a list that leaves nothing is refused before
//! anything connects. `RequiredRSASize` is the least RSA key that podssh
//! takes. What each list does to a connection is in `apply`.

mod apply;
mod names;

pub(crate) use apply::{certificates, restrict, HostLimits, UserKeys};

/// The least RSA key that OpenSSH takes, whatever `RequiredRSASize` says
/// (`SSH_RSA_MINIMUM_MODULUS_SIZE` of its `sshkey.h`), and the default.
pub const MIN_RSA: u32 = 1024;

/// One of the lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ciphers,
    Macs,
    Kex,
    HostKey,
    Pubkey,
    CaSignature,
}

impl Kind {
    /// Each kind, in the order of the manual.
    pub const ALL: [Kind; 6] = [Kind::Ciphers, Kind::Macs, Kind::Kex, Kind::HostKey, Kind::Pubkey, Kind::CaSignature];

    /// The kind of a keyword, in any case; `PubkeyAcceptedKeyTypes` is the
    /// old name of `PubkeyAcceptedAlgorithms`.
    pub fn of_keyword(keyword: &str) -> Option<Kind> {
        match keyword.to_ascii_lowercase().as_str() {
            "ciphers" => Some(Kind::Ciphers),
            "macs" => Some(Kind::Macs),
            "kexalgorithms" => Some(Kind::Kex),
            "hostkeyalgorithms" => Some(Kind::HostKey),
            "pubkeyacceptedalgorithms" | "pubkeyacceptedkeytypes" => Some(Kind::Pubkey),
            "casignaturealgorithms" => Some(Kind::CaSignature),
            _ => None,
        }
    }

    /// The keyword, as ssh_config(5) spells it.
    pub fn keyword(self) -> &'static str {
        match self {
            Kind::Ciphers => "Ciphers",
            Kind::Macs => "MACs",
            Kind::Kex => "KexAlgorithms",
            Kind::HostKey => "HostKeyAlgorithms",
            Kind::Pubkey => "PubkeyAcceptedAlgorithms",
            Kind::CaSignature => "CASignatureAlgorithms",
        }
    }

    /// The keyword of its line of `ssh -G`, as OpenSSH prints it.
    pub fn dumped(self) -> &'static str {
        match self {
            Kind::Ciphers => "ciphers",
            Kind::Macs => "macs",
            Kind::Kex => "kexalgorithms",
            Kind::HostKey => "hostkeyalgorithms",
            Kind::Pubkey => "pubkeyacceptedalgorithms",
            Kind::CaSignature => "casignaturealgorithms",
        }
    }

    /// What one name of the list is, for a refusal.
    fn what(self) -> &'static str {
        match self {
            Kind::Ciphers => "cipher",
            Kind::Macs => "MAC",
            Kind::Kex => "key exchange",
            Kind::HostKey => "host key algorithm",
            Kind::Pubkey => "key algorithm of a login",
            Kind::CaSignature => "signature algorithm of a CA",
        }
    }
}

/// podssh's own list of `kind`, in its order: what it offers when no
/// keyword gives one.
pub fn own(kind: Kind) -> Vec<String> {
    names::own(kind)
}

/// Each name of `kind` that podssh speaks, which a list may name.
pub fn spoken(kind: Kind) -> Vec<String> {
    names::spoken(kind)
}

/// A list as given, assembled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assembled {
    /// The names that podssh offers, in order.
    pub names: Vec<String>,
    /// The names and patterns of the list that matched nothing that podssh
    /// speaks, left out; `-v` says so.
    pub dropped: Vec<String>,
}

/// The list `spec` of `kind`, as OpenSSH 10.3p1's `kex_assemble_names`
/// makes it over podssh's own list and what podssh speaks. `Err` is why it
/// is refused, with what podssh speaks.
pub fn assemble(kind: Kind, spec: &str) -> Result<Assembled, String> {
    let spec = spec.trim();
    let (form, list) = match spec.chars().next() {
        Some(c @ ('+' | '-' | '^')) => (c, &spec[1..]),
        _ => ('=', spec),
    };
    let patterns: Vec<&str> = list.split(',').map(str::trim).filter(|p| !p.is_empty()).collect();
    if patterns.is_empty() {
        return Err(format!("names no {}", kind.what()));
    }
    // OpenSSH takes a negated pattern only where it takes names away.
    if let Some(negated) = patterns.iter().find(|p| p.starts_with('!')).filter(|_| form != '-') {
        return Err(format!("{negated}: a name with ! is for a list that starts with -, as in OpenSSH"));
    }
    let own = names::own(kind);
    let spoken = names::spoken(kind);
    let mut out = Assembled::default();
    if form == '-' {
        out.names = own.into_iter().filter(|name| matched(name, &patterns) != 1).collect();
    } else {
        let wanted: Vec<&str> = match form {
            '+' => own.iter().map(String::as_str).chain(patterns.iter().copied()).collect(),
            '^' => patterns.iter().copied().chain(own.iter().map(String::as_str)).collect(),
            _ => patterns.clone(),
        };
        for pattern in wanted {
            let found: Vec<&String> = spoken.iter().filter(|name| wildcard(pattern, name)).collect();
            if found.is_empty() && !out.dropped.iter().any(|d| d == pattern) {
                out.dropped.push(pattern.to_string());
            }
            for name in found {
                if !out.names.contains(name) {
                    out.names.push(name.clone());
                }
            }
        }
    }
    if out.names.is_empty() {
        return Err(format!("leaves no {} that podssh speaks; it speaks {}", kind.what(), spoken.join(",")));
    }
    Ok(out)
}

/// The lists of one connection: `None` is podssh's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Algorithms {
    pub ciphers: Option<Vec<String>>,
    pub macs: Option<Vec<String>>,
    pub kex: Option<Vec<String>>,
    pub host_key: Option<Vec<String>>,
    pub pubkey: Option<Vec<String>>,
    pub ca_signature: Option<Vec<String>>,
    /// `RequiredRSASize` as given; below [`MIN_RSA`] it changes nothing.
    pub required_rsa_size: Option<u32>,
}

impl Algorithms {
    /// The list of `kind` that was given, if one was.
    pub fn given(&self, kind: Kind) -> Option<&Vec<String>> {
        match kind {
            Kind::Ciphers => self.ciphers.as_ref(),
            Kind::Macs => self.macs.as_ref(),
            Kind::Kex => self.kex.as_ref(),
            Kind::HostKey => self.host_key.as_ref(),
            Kind::Pubkey => self.pubkey.as_ref(),
            Kind::CaSignature => self.ca_signature.as_ref(),
        }
    }

    /// Give the list of `kind`.
    pub fn set(&mut self, kind: Kind, names: Vec<String>) {
        let slot = match kind {
            Kind::Ciphers => &mut self.ciphers,
            Kind::Macs => &mut self.macs,
            Kind::Kex => &mut self.kex,
            Kind::HostKey => &mut self.host_key,
            Kind::Pubkey => &mut self.pubkey,
            Kind::CaSignature => &mut self.ca_signature,
        };
        *slot = Some(names);
    }

    /// The list of `kind` in effect: the one given, else podssh's own.
    pub fn list(&self, kind: Kind) -> Vec<String> {
        self.given(kind).cloned().unwrap_or_else(|| names::own(kind))
    }

    /// The least RSA key that podssh takes: `RequiredRSASize`, and never
    /// less than OpenSSH's floor.
    pub fn rsa_floor(&self) -> u32 {
        self.required_rsa_size.unwrap_or(MIN_RSA).max(MIN_RSA)
    }
}

/// OpenSSH's `match_pattern_list`, with case: 1 when a pattern matches and
/// no negated one does, -1 when a negated one matches, 0 when none does.
fn matched(name: &str, patterns: &[&str]) -> i8 {
    let mut got = 0;
    for pattern in patterns {
        let (negated, pattern) = pattern.strip_prefix('!').map_or((false, *pattern), |rest| (true, rest));
        if wildcard(pattern, name) {
            if negated {
                return -1;
            }
            got = 1;
        }
    }
    got
}

/// A pattern of `*` and `?` against a name, with case, as OpenSSH matches
/// the names of a list.
fn wildcard(pattern: &str, name: &str) -> bool {
    crate::known_hosts::wildcard(pattern.as_bytes(), name.as_bytes())
}

#[cfg(test)]
mod tests;
