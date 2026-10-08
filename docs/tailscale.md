# Tailscale (milestone 8)

`podssh ts` (cargo feature `ts`) joins a tailnet through a vendored fork of
tailscale-rs (`vendor/tailscale-rs`, local patches in `vendor/patches/`), with
DERP carried over a WebSocket relay so it works on hosts whose only egress is
HTTPS. It is built only with `--features ts`; see [development.md](development.md).

## State on 2026-10-07

- Probe nodes registered with the tailnet (the control login works) but got
  no network map within 60 s.
- The fork does not pass the relay's `1008 "not authorized"` up through its
  `Device` API, so a node key missing from the relay's allowlist looks like a
  network map that has not arrived yet. Surfacing that close is the first fix.
- Adding node keys to the allowlist is the operator's job (it needs a Tailscale
  admin token and a deployment credential for the relay).
- The two-node live acceptance test has never passed.

## Things to know

- A new `--ts-state` file means a new node key, which is a new device and a new
  allowlist entry. Reuse one state file.
- Whether a sandbox's proxy allows `tcp.ts.relay.ajam.dev:443` is not measured.
- The relay's `derpMap` runbook is still open.
- Dropping a split write half did not reliably signal end of stream; call
  `shutdown()` explicitly.
