# Tailscale (milestone M8)

`podssh ts` (cargo feature `ts`) joins a tailnet through a fork of
tailscale-rs (`vendor/tailscale-rs`, with local patches in `vendor/patches/`).
DERP goes over a WebSocket relay, so it works on hosts whose only egress is
HTTPS. Build it only with `--features ts`; see [development.md](development.md).

## State (measured 2026-10-07)

- Probe nodes registered with the tailnet (the control login works), but no
  network map arrived within 60 s.
- The fork does not give the relay's `1008 "not authorized"` to its `Device`
  API. Thus a node key that is not in the relay's allowlist looks like a
  network map that has not arrived yet. Repair this first.
- The operator adds node keys to the allowlist. This needs a Tailscale admin
  token and a deployment credential for the relay.
- The live test with two nodes has never passed.
- More open defects: T-100 (formerly C2) in [TODO/ts.md](../TODO/ts.md).

## The choice of a mode, and the end of a run (T-102, 2026-10-10)

- Before the node starts, `podssh ts` checks each mode through the proxy:
  `tcp` by a TLS handshake with a stock DERP server (one of each of the first
  three regions of Tailscale's default map, read from
  `login.tailscale.com/derpmap/default`), and `relay` by one with the relay
  host. Each step has 8 s, as in `podssh doctor`. `--ts-mode auto` takes the
  first of `tcp` and `relay` whose check passed; a forced mode is checked
  alone. With none ready, the exit is 78, with each reason. Measured from
  this machine (direct): the `tcp` check passed in 1.5 s, the `relay` check
  in 0.4 s.
- The proxy of the node and of its checks is `--ts-proxy`, else the
  environment's (`https_proxy`, `HTTPS_PROXY`, `all_proxy`, `ALL_PROXY`, with
  `no_proxy`), as for each other podssh command; a URL with no port means
  port 80, and the fork gets the port written (T-103, 2026-10-10). Each
  connection of the node goes through it: to the control server, and to DERP,
  over WebSocket to the relay too, by name and within 20 s (patch 0017).
  Credentials in `--ts-proxy` can be read in the list of processes, and
  `podssh ts` says so.
- `--ts-ephemeral`: the node logs out at the end of the run, also after an
  error, in 5 s at most: a register request with its key and an expiry in
  the past (patch 0016), and the control server deletes the node. A node
  that is not ephemeral never logs out: its key, and its allowlist entry,
  must stay. A logout that fails is said, and the control server removes
  the offline node later.

## Rules

- A new `--ts-state` file makes a new node key: a new device and a new
  allowlist entry. Use one state file again and again.
- It is not measured whether the proxy of a sandbox allows
  `tcp.ts.relay.ajam.dev:443`.
- The `derpMap` runbook of the relay is still open.
- To signal the end of a stream, call `shutdown()`. Dropping a split write
  half did not always signal it.
