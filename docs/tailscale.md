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
- More open defects: C2, C3 and C9 in [defects.md](defects.md).

## Rules

- A new `--ts-state` file makes a new node key: a new device and a new
  allowlist entry. Use one state file again and again.
- It is not measured whether the proxy of a sandbox allows
  `tcp.ts.relay.ajam.dev:443`.
- The `derpMap` runbook of the relay is still open.
- To signal the end of a stream, call `shutdown()`. Dropping a split write
  half did not always signal it.
