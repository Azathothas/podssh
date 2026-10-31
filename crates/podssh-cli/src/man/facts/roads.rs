//! The variables of the roads that are read apart from `facts.rs`, for the
//! length of that file: the DERP road (T-349, T-379).

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
];
