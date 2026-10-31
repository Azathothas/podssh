//! The variables of the roads beside the relay's, out of `facts.rs` at its
//! 500 lines: the DERP road of podssh-relay (T-349), which a library crate
//! reads before a command takes it (its command line is T-379), and the
//! forwarders of other products (T-369).

/// Each one: its names, and what it does.
pub(super) const VARIABLES: &[(&[&str], &str)] = &[
    (
        &["PODSSH_DERP_SERVER"],
        "The DERP servers of the DERP road in place of Tailscale's tailcat fleet: HOST[:PORT], separated by \
      commas, in order; the port is 443 when none is named. No command takes the DERP road before T-379.",
    ),
    (
        &["PODSSH_FORWARDER"],
        "The forwarders of podssh ssh, of each command that reaches its server as podssh ssh does, and of podssh \
      proxy, as --forwarder: other products' WebSocket forwarders, in order, in place of the relay. The flag \
      wins, and so do --relay-host and --relay-failover; beside PODSSH_RELAY, or with a bad template, it is a \
      configuration error (78). An empty value is no value.",
    ),
];
