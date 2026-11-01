//! The variables of the roads that are read apart from `facts.rs`, for the
//! length of that file: the DERP road (T-349, T-379), and the direct road
//! after the relay hosts (T-363).

/// Each one: its names, and what it does.
pub(super) const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_DERP_SERVER"],
        "The DERP servers of the DERP road in place of Tailscale's tailcat fleet, as --derp-server: \
          HOST[:PORT], separated by commas, in order; the port is 443 when none is named. The flag wins; a bad \
          value is a configuration error (78). podssh node --derp calls the first whose /derp/probe answers \
          home, and podssh ssh tries the rest after a ticket's server when the list holds that server.",
    ),
    (
        &["PODSSH_DERP"],
        "no: no DERP road that the user did not ask for, which the operator's ruling Q50 allows: podssh node \
          with no pair refuses as before, and podssh ssh node://NAME dials no ticket that it kept under NAME. \
          --derp, --derp-ticket and derp:TICKET still take the road. Unset, empty or yes: the fallback is on; \
          another word is a configuration error (78).",
    ),
    (
        &["PODSSH_DIRECT"],
        "no: when each relay host failed, podssh ssh and each command that reaches a server as it does (cp, \
          each, job, health, containers, ping, pipe ssh:) end with the relay's failure, as with --relay-host, \
          and do not try the direct road. Unset, empty or yes: with no relay named (no --relay-host, \
          PODSSH_RELAY or RelayHost) and no -4 or -6, the direct road is tried once, as --direct dials it, \
          through HTTPS_PROXY when one is set, and the server's version line must come within 10 s. The \
          settings file's Direct says the same, below the variable; another word is a configuration error (78).",
    ),
];
