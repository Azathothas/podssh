//! The variables of the roads that a library crate reads, before a command
//! takes them: the DERP road of podssh-relay (T-349), whose command line is
//! T-379.

/// Each one: its names, and what it does.
pub(super) const VARIABLES: &[(&[&str], &str)] = &[(
    &["PODSSH_DERP_SERVER"],
    "The DERP servers of the DERP road in place of Tailscale's tailcat fleet: HOST[:PORT], separated by \
      commas, in order; the port is 443 when none is named. No command takes the DERP road before T-379.",
)];
