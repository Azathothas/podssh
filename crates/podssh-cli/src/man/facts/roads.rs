//! The variables of the roads that are read apart from `facts.rs`, for the
//! length of that file: the DERP road (T-349, T-379), the Piping Server road
//! (T-437), the direct road after the relay hosts (T-363), the forwarders of
//! other products (T-369), Wisp's among them (T-438), and their fallback
//! (T-370), and the forward proxy over TLS of --via (T-439).

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
        &["PODSSH_TRANSIT"],
        "The transit road of a pair (T-436), which the operator's ruling Q65 lets podssh take unasked: a \
          magic-wormhole transit relay, Least Authority's wss://relay.mw.leastauthority.com by default, where a \
          node of the resumable layer and the end-to-end channel waits for the pair's operators beside the pair's \
          road, and where podssh ssh node://NAME meets it when each other road failed. Its token and the proof of \
          the pair come from the pair's connect token; the relay sees ciphertext. no: no transit road; a ws:// or \
          wss:// URL: that relay in place of Least Authority's; unset, empty or yes: the default; another word \
          is a configuration error (78), which does not echo the value.",
    ),
    (
        &["PODSSH_PIPING"],
        "The Piping Server road of a pair (podssh node NAME, podssh ssh node://NAME), for a proxy that refuses \
          the WebSocket upgrade: a POST and a GET of plain HTTPS for each way of a link, on paths that the pair's \
          secret gives, under the resumable layer and the end-to-end channel. Unset or empty: the fallback that \
          the operator's ruling Q65 allows, through https://ppng.io: a node serves it alone once a probe at its \
          start finds the upgrade to the relay refused on the way, and a client tries it once the pair's road \
          found the same. no: no such road. yes, or https://HOST[:PORT][/PREFIX] of another Piping Server: the \
          road as asked, which a node serves beside the pair's road and a client races 250 ms after it; with \
          --plain, --no-e2e or a udp: TARGET the node refuses it (64). Another word is a configuration error \
          (78).",
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
    (
        &["PODSSH_FORWARDER"],
        "The forwarders of podssh ssh, of each command that reaches its server as podssh ssh does, and of podssh \
      proxy, as --forwarder: other products' WebSocket forwarders, templates, Wisp servers (wisp+wss://) or the \
      words mudlet, ssheasy, mudix and wisp, in order, in place of the relay. The flag wins, and so do \
      --relay-host and --relay-failover; \
      beside PODSSH_RELAY, or with a bad template, it is a configuration error (78). An empty value is no \
      value.",
    ),
    (
        &["PODSSH_FORWARDER_FALLBACK"],
        "no: when each relay host failed, podssh does not try the forwarders that it names (mudlet, ssheasy, \
      mudix, then the Wisp demo server, wisp); yes, the default, tries them, where the relay was podssh's own \
      choice. Over ForwarderFallback \
      of the settings file; another word is a configuration error (78).",
    ),
    (
        &["PODSSH_VIA"],
        "The forward proxy over TLS of podssh ssh, of each command that reaches its server as podssh ssh does, \
      and of podssh proxy and podssh doctor, as --via: https://[USER@]HOST[:PORT], in place of the relay. The \
      flag wins, and so do --relay-host, --relay-failover, --forwarder and --shadowsocks; beside PODSSH_RELAY or \
      PODSSH_FORWARDER, or with a URL that cannot be read, it is a configuration error (78). An empty value is \
      no value.",
    ),
    (
        &["PODSSH_VIA_AUTH_FILE"],
        "The credentials file of the proxy of --via or PODSSH_VIA, as --via-auth-file, which wins: a private \
      file, one line, USER:PASSWORD, or the password alone when the URL names USER (see FILES).",
    ),
    (
        &["PODSSH_VIA_HTTP"],
        "1.1 or 2: the one version of HTTP that podssh offers the proxy of --via by ALPN; a proxy that does not \
      take it is refused. Unset, empty or auto offers h2, then http/1.1, and the proxy chooses. Another word is \
      a configuration error (78).",
    ),
    (
        &["INVOCATION_ID", "WSL_DISTRO_NAME", "TERMUX_VERSION"],
        "Read, never set, by --detach and -f (T-380), each to say before the run goes to the background what may \
      end it there: a unit of systemd that started it, whose stop ends it too; WSL, whose machine may stop when no \
      terminal of it is open; Termux, whose processes in the background Android may end.",
    ),
];
