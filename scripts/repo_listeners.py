"""The allowance of the listener scan of scripts/check-repo.py (check 6): each
pattern that makes or names a listening socket, and the files outside a
crate's tests/ where it may stand. Apart from check-repo.py so that each file
stays within 500 lines (T-400).
"""

# Each pattern that makes or names a listening socket, and the files outside
# a crate's tests/ where it may stand. A listener that the user asks for, and
# that a probe allows, joins its row in the commit that adds it, with the
# flag that asks for it and the probe that allows it.
LISTENER_RULE = "no listener unless the user asks for it and a probe at run time allows the bind"
LISTENERS = {
    # The listening side of `podssh pipe`, which the user asks for with
    # unix-listen:, tcp-listen:, http-listen: or ws-listen: (T-177, T-367,
    # T-368): the bind itself is the probe, and PODSSH_LISTEN turns it off;
    # pipe/serve.rs binds each.
    # And the target of the tests of -R (T-035), on the loopback, and the
    # stand-in agent of the tests of -A (T-036), on a socket in a scratch
    # directory: test modules of src/ that reach the crate's own login. And
    # -L and -D of `podssh ssh` (T-038), which the user asks for: the bind and
    # the listen, before anything connects, are the probe, and PODSSH_LISTEN
    # turns them off. And the stand-in server of pkarr on the loopback
    # (T-350), beside iroh's test relay: the tests' own, behind the feature
    # test-relay, which no release builds.
    # And the stand-in of WARP's edge (T-352), for the tests of this crate
    # and of podssh-relay (T-374), on the loopback: podssh-warp's feature
    # `stand-in`, which no binary enables.
    "TcpListener": [
        "crates/podssh-cli/src/pipe/listen.rs",
        "crates/podssh-ssh/src/remote_tests.rs",
        "crates/podssh-cli/src/ssh/local_bind.rs",
        "crates/podssh-iroh/src/test_pkarr.rs",
        "crates/podssh-warp/src/stand_in.rs",
    ],
    # The control socket of `podssh ssh -M` (T-039), which the user asks for:
    # pipe/listen.rs makes it before anything connects (the probe), and the
    # master serves it; its tests make one in a scratch directory. And the
    # target of the tests of -R to a socket on this host (T-365), in one.
    "UnixListener": [
        "crates/podssh-cli/src/pipe/listen.rs",
        "crates/podssh-ssh/src/agent_forward_tests.rs",
        "crates/podssh-ssh/src/remote_tests.rs",
        "crates/podssh-ssh/src/mux/master.rs",
        "crates/podssh-ssh/src/mux/tests.rs",
    ],
    # The iroh road (feature `iroh`, T-162), which the user selects: its probe
    # binds a UDP socket to port 0 and closes it, and only when the probe
    # allowed it does the endpoint bind UDP for direct paths. And a node's
    # UDP TARGET (T-168), which the user names (`podssh node NAME
    # udp:HOST:PORT`): each flow is a socket of port 0, connected to the
    # target, made only after the node's probe made and closed one. And the
    # quick tunnel over QUIC (T-301), which the user asks for with `podssh
    # node --quick-tunnel`: one socket of port 0 for its one connection to
    # the edge, only with no proxy set; a bind that fails is the probe's
    # answer, and the node takes HTTP/2. And the tests of the iroh road's
    # probe (T-359): a UDP port on the loopback that reads and never answers,
    # as a network that drops UDP further on. And the quick tunnel's probe of
    # UDP before QUIC (T-400), with the same flag and only with no proxy set:
    # a socket of port 0 for each address probed, connected to it, which
    # sends one packet and closes within 300 ms; doctor's --full sends it too.
    "UdpSocket": [
        "crates/podssh-iroh/src/probe.rs",
        "crates/podssh-iroh/src/endpoint_udp_tests.rs",
        "crates/podssh-relay/src/udp/flow.rs",
        "crates/podssh-relay/src/quick/quic.rs",
        "crates/podssh-relay/src/quick/probe.rs",
    ],
    # The bind probes of `podssh doctor`, which close at once and never listen;
    # and the iroh road's probe and endpoint, as above, with the commands that
    # make the endpoint: `podssh node --iroh`, `podssh ssh iroh:` (T-163) and
    # the race of `podssh ssh --iroh-ticket` (T-164). And `podssh agent`
    # (T-034), which the user starts: it binds through `podssh pipe`'s
    # listener, after PODSSH_LISTEN, and the bind is its probe. And the
    # flows of a node's UDP TARGET (T-168), as above. And the daemon of
    # `podssh session start` and `serve` (T-186), which the user asks for:
    # it binds through the same listener, after PODSSH_LISTEN, before it
    # connects, and the bind is its probe. And the quick tunnel over QUIC
    # (T-301) and its probe of UDP (T-400), the tests of the iroh road's
    # probe (T-359), and the stand-in server of pkarr (T-350), as above.
    "bind(": [
        "crates/podssh-iroh/src/test_pkarr.rs",
        "crates/podssh-iroh/src/endpoint_udp_tests.rs",
        "crates/podssh-relay/src/udp/flow.rs",
        "crates/podssh-relay/src/quick/quic.rs",
        "crates/podssh-relay/src/quick/probe.rs",
        "crates/podssh-cli/src/agent/serve.rs",
        "crates/podssh-cli/src/session/daemon.rs",
        "crates/podssh-cli/src/doctor/unix.rs",
        "crates/podssh-cli/src/pipe/listen.rs",
        "crates/podssh-cli/src/pipe/listen_win.rs",
        "crates/podssh-cli/src/pipe/serve.rs",
        "crates/podssh-iroh/src/probe.rs",
        "crates/podssh-iroh/src/endpoint.rs",
        "crates/podssh-cli/src/node_iroh.rs",
        "crates/podssh-cli/src/ssh/iroh/dial.rs",
        "crates/podssh-cli/src/ssh/iroh/race.rs",
        "crates/podssh-ssh/src/remote_tests.rs",
        "crates/podssh-ssh/src/agent_forward_tests.rs",
        "crates/podssh-cli/src/ssh/local_bind.rs",
        "crates/podssh-ssh/src/mux/tests.rs",
        "crates/podssh-warp/src/stand_in.rs",
    ],
    # And the stand-in of WARP's edge, as above, whose far end waits for
    # connections inside its tunnel: sockets of smoltcp in the process, no
    # socket of the system (T-352).
    # And the Tor road's TCP provider (T-353): Arti's trait asks each
    # provider for a listen method, and podssh's refuses each call with an
    # error, binding nothing.
    "listen(": [
        "crates/podssh-cli/src/pipe/listen_win.rs",
        "crates/podssh-cli/src/doctor/unix.rs",
        "crates/podssh-warp/src/stand_in.rs",
        "crates/podssh-warp/src/inside.rs",
        "crates/podssh-tor/src/runtime.rs",
    ],
    "socket2": [],
}
