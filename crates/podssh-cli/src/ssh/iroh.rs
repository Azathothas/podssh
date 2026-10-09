//! `podssh ssh iroh:TICKET`: a podssh far end over the iroh road (T-162).
//! The road is in a build with the feature `iroh` only: without it, an iroh
//! destination is refused before anything connects, and the refusal names
//! the feature. Dialling a ticket comes with T-163.

/// The form of an iroh destination: `iroh:TICKET`, or `USER@iroh:TICKET`.
pub const SCHEME: &str = "iroh:";

/// Whether `destination` names a far end over the iroh road.
pub fn is_iroh(destination: &str) -> bool {
    let host = destination.rsplit_once('@').map_or(destination, |(_, host)| host);
    host.starts_with(SCHEME)
}

/// Why `destination` cannot be reached by this build.
pub fn refusal(destination: &str) -> String {
    if cfg!(feature = "iroh") {
        format!("{destination}: dialling an iroh ticket is not implemented yet")
    } else {
        format!(
            "{destination}: the iroh road is not in this build; build podssh with --features iroh \
             (cargo build -p podssh-cli --features iroh)"
        )
    }
}
