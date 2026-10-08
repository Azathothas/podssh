//! E17 — ⛔ **the relay's own name, resolved without DNS and never guessed.**
//!
//! ⛔ **This is a different problem from `?family=4`.** `?family=4` ⛔ *"`resolve
//! the target over DoH`"* ⛔ — **READ**, live spec line 199, verified 2026-10-02
//! with `sed -n '164p'` — ⛔ **resolves the TARGET, server-side, and does nothing
//! for podssh resolving anything locally.** ⛔ **Two separate problems share one
//! confusing word**, and ⛔ **"a client that reads `?family=4` as covering its own
//! lookup has read the column heading and not the cell."**
//!
//! ⛔ **A `Host:` header is not a solution, and the entry measured it.** ⛔
//! `relay-hostname.md`: ⛔ *"wrong: pin the address, drop the hostname"* ⛔
//! `curl -sS -H 'Host: tcp-1.ssh.relay.ajam.dev' https://104.21.39.2/health`
//! ⛔ → ⛔ `curl: (35) schannel: next InitializeSecurityContext failed:
//! SEC_E_ILLEGAL_MESSAGE`, ⛔ exit **35**, for tcp-1, tcp-2 and tcp-3 alike. ⛔
//! *"right: pin the address, KEEP the hostname for SNI and Host"* ⛔
//! `--resolve 'tcp-1.ssh.relay.ajam.dev:443:104.21.39.2'` ⛔ → ⛔ **200**. ⛔ **A
//! relay address on its own is not a relay** ⛔ — ⛔ it is a Cloudflare edge
//! address that speaks for exactly one name per certificate.
//!
//! ⛔ **The remedy is a `(name, address)` pair, and that is the type.** ⛔ **A bare
//! address is not representable**, ⛔ **which is how E17's second plant is made
//! structural instead of a convention** ⛔ — ⛔ the entry's requirement is that
//! `podssh --relay-address 104.21.39.2` ⛔ *"must be **rejected at parse time**"*.
//!
//! ⛔ **No default relay path is compiled in.** `endpoint.rs` already refuses one
//! (`TransportError::NoRelayConfigured`) ⛔ **and this module ships no constant
//! that could become one**: ⛔ E06's entry exists about `DROPSSH_DEFAULT_FORWARD
//! "/connect/railway"` ⛔ **and that target no longer exists**, ⛔ so ⛔ **a silent
//! fallback is indistinguishable from a working connection until the day it is
//! not.**
//!
//! ⛔ **The route that answered is reported, never inferred.** ⛔ **"Cannot
//! resolve" and "relay down" look identical from the outside**, ⛔ and ⛔ a
//! doctor that cannot say which it measured is worse than no doctor.

mod pair;
mod report;

pub use pair::{RelayAddress, RelayAddressError};
pub use report::{RelayResolution, RelayResolutionError, Route, Remedies};