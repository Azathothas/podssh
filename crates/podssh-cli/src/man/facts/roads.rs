//! The variables of the roads that are read apart from `facts.rs`, for the
//! length of that file: the DERP road (T-349, T-379), the Piping Server road
//! (T-437), the direct road after the relay hosts (T-363), the forwarders of
//! other products (T-369), Wisp's among them (T-438), and their fallback
//! (T-370), the forward proxy over TLS of --via (T-439), the wstunnel
//! server of --wstunnel (T-441), the OpenTunnel road (T-531), and the
//! resumable layer at podssh's relay role (T-173).

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
        &["PODSSH_OPENTUNNEL"],
        "The OpenTunnel road (T-531), which the operator's ruling Q76 lets podssh take unasked for a node with no \
          other road: a blind TLS tunnel with no account, https://opentunnel.xyz by default, of podssh node \
          --opentunnel and podssh ssh node://NAME --opentunnel-name. no: no such road, and the flags are refused \
          (64); an https://HOST[:PORT] URL: that service in place of OpenTunnel's, whose certificates the trust of \
          --ca-file checks; unset, empty or yes: the default. Another word is a configuration error (78), which \
          does not echo the value.",
    ),
    (
        &["PODSSH_RELAY_LAYER"],
        "yes: podssh proxy reads the /relays.json of the first relay host, and where it offers the resumable \
          layer (forward.layer, which podssh relay serve gives), carries the session in it to that host alone: \
          the relay keeps the connection to the target while this host's link is lost, for 10 minutes, and a new \
          link resumes the session, which a line on stderr says (T-173). A host that offers none, or whose first \
          link fails for a reason that another host may not share, takes the contract's road, with one line. \
          Unset, empty or no: the contract's road, with no request more; another word is a configuration error \
          (78).",
    ),
    (
        &["PODSSH_RELAY_RANK"],
        "no (or off, 0): the default relay hosts go in the order of /relays.json, as before T-607. Unset or \
          another word: when a rank of podssh relay rank holds for this egress (24 h), the default list is the \
          default host and the best three other hosts of the pool in the rank's order, the default host at its \
          place among them; where none holds, the times of each run's own race, the last 8 of each host, order \
          the pool. A list that the user named keeps its order, and a host that failed lately goes last over \
          its rank. auto: the same, and a session of podssh ssh on the default list ranks the hosts in its \
          background when no rank holds for this egress, once a day, 8 hosts, one probe each 10 s at most, \
          each with ?dial=lazy (Q89, T-608); never unless asked. The settings file's RelayRank yes, no or auto \
          says the same, below the variable: a variable that is set, and not empty, wins.",
    ),
    (
        &["PODSSH_RELAY_RANK_PACE"],
        "For tests only, and read only by a build with debug assertions, never by a release binary: \
          DELAY_MS,GAP_MS, the wait of a rank in a session's background (T-608) after the session opened and \
          between the starts of two of its probes, in place of 60 s and 10 s, so that a test of the bounds \
          runs in seconds.",
    ),
    (
        &["PODSSH_DIRECT"],
        "no: when each relay host failed, podssh ssh and each command that reaches a server as it does (cp, \
          each, job, health, containers, ping, pipe ssh:) end with the relay's failure, as with --relay-host, \
          and do not try the direct road. Unset, empty or yes: with no relay named (no --relay-host, \
          PODSSH_RELAY or RelayHost), the direct road is tried once, as --direct dials it, of the family of \
          -4 or -6 when one is given, also after a relay that closed a session to an IPv6 target before any \
          byte, through HTTPS_PROXY when one is set, and the server's version line must come within 10 s. The \
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
      mudix, then the Wisp demo server, wisp); yes, the default, tries them, 10 s at most each, where the relay \
      was podssh's own choice and no relay host answered about the target (its 502, or its refusal of the \
      target by policy, ends the run). Over ForwarderFallback of the settings file; another word is a \
      configuration error (78).",
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
        &["PODSSH_WSTUNNEL"],
        "The wstunnel server of podssh ssh, of each command that reaches its server as podssh ssh does, and of \
      podssh proxy, as --wstunnel: wss://HOST[:PORT] or ws://HOST[:PORT], in place of the relay. The flag wins, \
      and so do --relay-host, --relay-failover, --forwarder, --shadowsocks and --via; beside PODSSH_RELAY, \
      PODSSH_FORWARDER or PODSSH_VIA, or with a URL that cannot be read, it is a configuration error (78). An \
      empty value is no value.",
    ),
    (
        &["PODSSH_WSTUNNEL_SECRET_FILE"],
        "The secret file of the server of --wstunnel or PODSSH_WSTUNNEL, as --wstunnel-secret-file, which wins: a \
      private file of path-prefix PREFIX, credentials USER[:PASSWORD] or authorization VALUE (see FILES).",
    ),
    (
        &["INVOCATION_ID", "WSL_DISTRO_NAME", "TERMUX_VERSION"],
        "Read, never set, by --detach and -f (T-380), each to say before the run goes to the background what may \
      end it there: a unit of systemd that started it, whose stop ends it too; WSL, whose machine may stop when no \
      terminal of it is open; Termux, whose processes in the background Android may end.",
    ),
];
