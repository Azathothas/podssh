//! The variables of the roads beside the relay's, out of `facts.rs` at its
//! 500 lines: the DERP road of podssh-relay (T-349), which a library crate
//! reads before a command takes it (its command line is T-379), and the
//! forwarders of other products (T-369) and their fallback (T-370).

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
      proxy, as --forwarder: other products' WebSocket forwarders, templates or the words mudlet, ssheasy and \
      mudix, in order, in place of the relay. The flag wins, and so do --relay-host and --relay-failover; \
      beside PODSSH_RELAY, or with a bad template, it is a configuration error (78). An empty value is no \
      value.",
    ),
    (
        &["PODSSH_FORWARDER_FALLBACK"],
        "no: when each relay host failed, podssh does not try the forwarders that it names (mudlet, ssheasy, \
      mudix); yes, the default, tries them, where the relay was podssh's own choice. Over ForwarderFallback \
      of the settings file; another word is a configuration error (78).",
    ),
];
