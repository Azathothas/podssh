//! E17 — ⛔ **the resolution of the relay's own name, and the failure message
//! that names every source it tried.**

use std::fmt;
use std::net::SocketAddr;

use crate::dns::{How, ResolveError, Stage};

/// ⛔ **Which source answered.** ⛔ **It is reported and never inferred** ⛔ —
/// ⛔ the sibling records the same three values ⛔ — **READ**,
/// `dropssh` `src/dns.c:310` `*how = "cache"`, `:321` `"literal"`, `:354`
/// `"getaddrinfo"`, `:364` `"hosts"`, `:371` `"doh"` ⛔ — ⛔ and ⛔ **prints
/// them**, ⛔ because ⛔ **"Cannot resolve" and "relay down" look identical
/// from the outside.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Literal,
    Cache,
    System,
    Hosts,
    Doh,
    /// ⛔ E17's fourth source: an operator-configured `(name, address)` pair.
    /// ⛔ **Consulted only after the first three fail**, ⛔ and ⛔ **there is
    /// no value of this variant that podssh can produce on its own** ⛔ — ⛔ it
    /// exists only when an operator named the pair.
    Configured,
}

impl Route {
    pub const fn as_str(self) -> &'static str {
        match self {
            Route::Literal => "Literal",
            Route::Cache => "Cache",
            Route::System => "System",
            Route::Hosts => "Hosts",
            Route::Doh => "Doh",
            Route::Configured => "Configured",
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<How> for Route {
    fn from(how: How) -> Self {
        match how {
            How::Literal => Route::Literal,
            How::Cache => Route::Cache,
            How::System => Route::System,
            How::Hosts => Route::Hosts,
            How::Doh => Route::Doh,
            How::Configured => Route::Configured,
        }
    }
}

/// ⛔ **A relay that resolved, and how.** ⛔ **`address` and `name` are both
/// kept, and both are needed**: ⛔ the address is dialled ⛔ **and the name is
/// what the certificate must carry** ⛔ — ⛔ **a value that carried only an
/// address would be the defect `relay-hostname.md` measured**, ⛔ exit **35**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayResolution {
    pub name: String,
    pub address: SocketAddr,
    pub route: Route,
    /// ⛔ **Every address the chain produced**, ⛔ so a caller can try the next
    /// one without resolving again ⛔ — ⛔ **and so a test can assert there was
    /// more than one**, ⛔ because ⛔ **the pool is anycast and every name in it
    /// resolves to the same two addresses** ⛔ (`relay-hostname.md` §"The
    /// addresses are anycast").
    pub addresses: Vec<SocketAddr>,
}

impl RelayResolution {
    pub fn line(&self) -> String {
        format!(
            "relay {} resolved by {} -> {}",
            self.name, self.route, self.address
        )
    }
}

/// ⛔ **Why the relay could not be resolved.** ⛔ **Every variant names the
/// host**, ⛔ because ⛔ **the whole of E17's Problem is that three different
/// failures print three messages the operator cannot tell apart**, ⛔ and ⛔ **a
/// fourth that names nothing would be the same defect wearing a new hat.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayResolutionError {
    /// ⛔ **No relay name was given at all.** ⛔ **podssh ships no default** ⛔ —
    /// ⛔ E06's entry is about a compiled-in `/connect/railway` ⛔ **that no
    /// longer exists**, ⛔ and ⛔ **a stock client aimed at a gateway the relay
    /// no longer has is a client that fails in a way nobody can read.**
    NoRelayConfigured,
    /// ⛔ **Every source failed, and the chain's own list is carried through
    /// whole.** ⛔ **All four sources are named** ⛔ — ⛔ System, `/etc/hosts`,
    /// DoH and the configured pair ⛔ — ⛔ because ⛔ *"a bare `cannot resolve` is
    /// the message that costs a session"* ⛔ and ⛔ **each has a different fix.**
    AllSourcesFailed { host: String, cause: ResolveError },
    /// ⛔ **A configured pair exists and does not apply to this name.**
    ConfiguredPairMisses { host: String, configured: Vec<String> },
    /// ⛔ **A configured pair is malformed.** ⛔ **Reported, never repaired**, and
    /// ⛔ **never replaced with a guess**: ⛔ **a pinned address is a pin, not a
    /// trust anchor**, ⛔ and ⛔ a repaired pair is a pin podssh chose.
    ConfiguredPairInvalid { host: String, detail: String },
}

impl fmt::Display for RelayResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayResolutionError::NoRelayConfigured => write!(
                f,
                "no relay name is configured. ⛔ podssh ships no default relay path: the relay \
                 currently publishes none, and a client that falls back to a name that no longer \
                 exists dials a gateway that is gone. Set one explicitly, or configure a \
                 (name, address) pair"
            ),
            RelayResolutionError::ConfiguredPairMisses { host, configured } => write!(
                f,
                "cannot resolve the relay {host}: the configured (name, address) pair does not \
                 name it. {} pair(s) configured: {}. ⛔ A configured address is not a wildcard — \
                 a pair for one name does not resolve another",
                configured.len(),
                configured.join(", ")
            ),
            RelayResolutionError::ConfiguredPairInvalid { host, detail } => write!(
                f,
                "cannot resolve the relay {host}: the configured (name, address) pair is \
                 malformed. {detail} ⛔ podssh does not repair it and does not substitute an \
                 address of its own: a wrong host that looks like a working connection is worse \
                 than a named failure"
            ),
            RelayResolutionError::AllSourcesFailed { host, cause } => {
                write!(f, "cannot resolve the relay {host}. ")?;
                write!(f, "{cause}")?;
                // ⛔ **The four sources, named whatever happened.** ⛔ The chain may
                // have stopped before reaching some of them, ⛔ and ⛔ **a message
                // that names only the ones that ran is not the message the entry
                // requires** ⛔ — ⛔ **an operator needs to know the remedies, not the
                // itinerary.**
                let reached: Vec<Stage> = cause.tried().iter().map(|r| r.stage).collect();
                for stage in [Stage::System, Stage::Hosts, Stage::Doh, Stage::Configured] {
                    if !reached.contains(&stage) {
                        write!(
                            f,
                            "\n  {stage} was not reached: the chain stopped earlier. If you \
                             need it, name it explicitly — for --relay-address \
                             '<hostname>=<address>'"
                        )?;
                    }
                }
                write!(
                    f,
                    "\n  Remedies, in order: a working local resolver, an /etc/hosts line, \
                     egress on 443 to a DoH endpoint, or an explicitly configured \
                     (name, address) pair. ⛔ The three causes look identical from outside — \
                     `Temporary failure in resolution`, a 403, and an unreachable relay — and \
                     ⛔ the first is this one, so neither of the other two was reached."
                )
            }
        }
    }
}

impl std::error::Error for RelayResolutionError {}

/// ⛔ **The remedies, as a value, for `podssh --doctor --verbose`.**
///
/// ⛔ **The sibling reports a failed resolution as ⛔ *a condition with a remedy*,
/// not a failure** ⛔ — **READ**, `dropssh` `src/doctor.c:181-189` ⛔ — ⛔ and ⛔
/// **this is that shape**, ⛔ **with the exit code kept separate from the
/// severity** ⛔ because ⛔ **a doctor that exits 0 because a probe could not
/// run is the exact defect `????` exists to prevent.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remedies {
    /// ⛔ **Something on this machine resolves the name.**
    NothingNeeded,
    /// ⛔ **Add a line to `/etc/hosts`.** ⛔ A curated entry outranks DoH ⛔ and ⛔
    /// **a DoH answer must not quietly overrule it.**
    AddHostsEntry { path: String },
    /// ⛔ **Egress on 443 to a DoH endpoint.** ⛔ **`UNKNOWN` on the target
    /// host** ⛔ — ⛔ `relay-hostname.md` §"The state of the target host" ⛔ and
    /// E05's probe are what would settle it.
    AllowHttpsEgress { endpoint: String },
    /// ⛔ **Configure the pair.** ⛔ **Both halves**, ⛔ because ⛔ **a bare
    /// address is a TLS failure**.
    ConfigurePair { example: String },
}

impl fmt::Display for Remedies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Remedies::NothingNeeded => write!(f, "nothing: a local resolver answered"),
            Remedies::AddHostsEntry { path } => {
                write!(f, "add a line to {path}: '<address>  <hostname>'")
            }
            Remedies::AllowHttpsEgress { endpoint } => write!(
                f,
                "allow egress on 443 to a DoH endpoint ({endpoint}), or configure the address \
                 directly"
            ),
            Remedies::ConfigurePair { example } => write!(
                f,
                "configure the address: --relay-address '<hostname>=<address>' — for example \
                 {example}. ⛔ The hostname is required: it is what the certificate is issued \
                 for and what goes into SNI"
            ),
        }
    }
}

impl RelayResolutionError {
    /// ⛔ **What the operator can do about it.** ⛔ **Ordered**, ⛔ and ⛔ **the
    /// first entry is the cheapest thing that fixes it.**
    pub fn remedies(&self) -> Vec<Remedies> {
        let example = "tcp-1.ssh.relay.ajam.dev=104.21.39.2".to_string();
        match self {
            RelayResolutionError::NoRelayConfigured => {
                vec![Remedies::ConfigurePair { example }]
            }
            RelayResolutionError::ConfiguredPairMisses { configured, .. } => {
                let mut out = vec![Remedies::AddHostsEntry { path: "/etc/hosts".to_string() }];
                out.push(Remedies::AllowHttpsEgress {
                    endpoint: "1.1.1.1/dns-query".to_string(),
                });
                if !configured.is_empty() {
                    out.push(Remedies::ConfigurePair { example });
                }
                out
            }
            RelayResolutionError::ConfiguredPairInvalid { .. } => {
                vec![Remedies::ConfigurePair { example }]
            }
            RelayResolutionError::AllSourcesFailed { cause, .. } => {
                let reached: Vec<Stage> = cause.tried().iter().map(|r| r.stage).collect();
                let mut out = Vec::new();
                if reached.contains(&Stage::Hosts) || reached.is_empty() {
                    out.push(Remedies::AddHostsEntry { path: "/etc/hosts".to_string() });
                }
                if !reached.contains(&Stage::Configured) {
                    out.push(Remedies::ConfigurePair { example });
                }
                if reached.contains(&Stage::Doh) {
                    out.push(Remedies::AllowHttpsEgress {
                        endpoint: "1.1.1.1/dns-query".to_string(),
                    });
                }
                out
            }
        }
    }

    /// ⛔ **Whether this is a resolution failure and not a network failure.** ⛔
    /// E17's Problem names three messages ⛔ — ⛔ `Temporary failure in
    /// resolution`, `403`, `Could not reach the relay` ⛔ — ⛔ and ⛔ **the third
    /// is not this one.** ⛔ A caller that could not tell them apart is the defect
    /// this whole entry exists to remove ⛔ — ⛔ so ⛔ **the classification is a
    /// method and not a comment.**
    pub fn is_resolution_failure(&self) -> bool {
        !matches!(self, RelayResolutionError::NoRelayConfigured)
    }

    /// ⛔ **The exit code podssh uses.** ⛔ **`NoRelayConfigured` and a failed
    /// resolution are both non-zero**, ⛔ because ⛔ **a zero exit on the
    /// entry's acceptance command ⛔ *"is a failure of this entry"*, because it
    /// means something resolved the relay that should not have.**
    pub fn exit_code(&self) -> i32 {
        3
    }
}