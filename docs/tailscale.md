# Tailscale (milestone M8)

`podssh ts` (cargo feature `ts`) joins a tailnet through a fork of
tailscale-rs (`vendor/tailscale-rs`, with local patches in `vendor/patches/`).
DERP goes over a WebSocket relay, so it works on hosts whose only egress is
HTTPS. Build it only with `--features ts`; see [development.md](development.md).

## State (measured 2026-10-07)

- Probe nodes registered with the tailnet (the control login works), but no
  network map arrived within 60 s.
- 2026-10-07: the fork did not give the relay's `1008 "not authorized"` to
  its `Device` API, so a node key that is not in the relay's allowlist looked
  like a network map that had not arrived yet. Since T-105 (2026-10-10), the
  fork keeps the newest state of each link (patch 0021): `podssh ts` exits 77
  at the relay's refusal and says what the key needs, at once, or at the end
  of `--ts-wait-allowlist`, which dials the relay again while the node waits
  for its key's admission. In `relay` mode, the status line and `-W` wait,
  within the same limit, for the relay's DERP link to come up.
- The operator adds node keys to the allowlist. This needs a Tailscale admin
  token and a deployment credential for the relay.
- The live test with two nodes has never passed.
- The open work of `podssh ts`: T-106, the live test with two nodes, which
  waits for the relay's operator ([TODO/ts.md](../TODO/ts.md)).

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
  `podssh ts` says so. The fork reads `no_proxy` by podssh-ws's rules, a
  block `ADDR/BITS` too (T-316, patch 0023); a test holds the two equal.
- The proxy can be SOCKS5 (`socks5://`, `socks5h://`, port 1080; T-281,
  patch 0022), as for each other podssh command: each connection of the
  node sends the host's name to it (the address type 3), with the user and
  password of RFC 1929, reads its reply to exactly its end, and tries once
  more with an address of the system resolver when the proxy takes no
  names. The checks before the start go through it with podssh-ws's SOCKS5.

## Connecting again (T-104, 2026-10-10)

- Each link of the node is dialled again after a drop: the connection to the
  control server, and the DERP link of each region (patch 0019). The wait is
  podssh's backoff: 1 s, 2 s, 4 s … up to 30 s, each scaled by a random
  factor in [0.5, 1.5), and from 1 s again after a link that lasted 60 s.
  Before, a DERP link ended at its first error for good, and the control
  connection was not dialled again at all while the node started.
- A DERP link that answered a ping and then sends nothing for three pings
  in a row, 10 s apart, is dead, as for podssh's own relay.
- The relay's close 1008 "not authorized" ends the link: the node key is not
  in the relay's allowlist. With `--ts-wait-allowlist`, the link is dialled
  again instead, while the node waits for its key's admission.
- With a pin (`relay` mode) one link serves each region, the relay's: the
  relay closes the older of two sockets with one key, so a link for each
  region would replace the others' for as long as they were active.
- `podssh ts` writes one stderr line for each drop, with the wait before the
  next attempt, one for each link that comes back, and one for a refusal,
  from the start of the node on. Measured through `scripts/fake-proxy.py`
  as `HTTPS_PROXY`, refusing the control server: an attempt after 1.3 s,
  2.1 s, 5.4 s and 6.1 s, each said. The live drop test is T-106.
- `--ts-ephemeral`: the node logs out at the end of the run, also after an
  error, in 5 s at most: a register request with its key and an expiry in
  the past (patch 0016), and the control server deletes the node. A node
  that is not ephemeral never logs out: its key, and its allowlist entry,
  must stay. A logout that fails is said, and the control server removes
  the offline node later.

## Another control server, and a stand-in tailnet (T-334)

- `--ts-control-url https://HOST[:PORT]` names the tailnet's control server,
  such as headscale, in place of Tailscale's. `podssh ts` refuses `http://`
  (the node takes the server's key over checked TLS alone), a path (the node
  asks for `/key` and `/ts2021` at the root of the host), and a user or a
  password (the list of processes shows them), each with 64 before any
  network.
- With it, the check of `tcp` asks that server for its key, `/key?v=N` with
  the capability version of the fork's node, as the node does first; then for
  its DERP map at `/derpmap/default`, where Tailscale publishes one, and makes
  a handshake with up to three of its servers. headscale publishes none there
  (its router at `v0.29.7`, `juanfont/headscale:hscontrol/app.go`, serves
  `/key`, `/ts2021`, `/derp` and no map): a node reads its DERP servers in its
  own map response, after it registers. A 404 there passes the check on the
  key.
- `--ts-relay HOST[:PORT]` takes a port, 443 when none is given: `relay` mode
  can then pin a DERP server on another port, as headscale's embedded one,
  which serves DERP over a WebSocket at `/derp` with the subprotocol `derp`,
  the same that the fork dials.
- `PODSSH_TS_TEST_CA_FILE` names a PEM file whose certificates the node's
  fork adds to its roots (patch 0027): a test's control server of a CA of its
  own is then reached with TLS checked. Only a test sets it, and `podssh ts`
  says when it is set. The checks before the start trust podssh's own store,
  which takes a `podssh-ca.pem` beside the binary.

`scripts/ts-headscale.sh` is the stand-in of the operator's ruling of
2026-10-31 (`docs/decisions.md`): it runs the live parts of the Tailscale
entries that waited for the operator's tailnet, with no account of
Tailscale's. In Podman, else Docker, on the host's network so that
`127.0.0.1` names headscale for each node:

| Part | What it is |
| --- | --- |
| headscale | `images/headscale/Dockerfile`, with its embedded DERP server as the only region (999), TLS of a CA made for the run (openssl, P-256, two days), and a policy that lets each node of the user `podssh` reach the others and log in to them as root over Tailscale SSH |
| The target | tailscaled of `images/tailscale/Dockerfile` in user space, with `--ssh` |
| The peer | a second tailscaled in user space, with a SOCKS5 server: OpenSSH's path to the target (`tailscale nc`), `podssh ssh --direct`'s through `HTTPS_PROXY`, and a SOCKS5 proxy that podssh did not write |
| The keys | two pre-auth keys made in headscale for the run, reusable, one of them ephemeral; each goes from headscale's stdout into a file, and to podssh and tailscale by its path alone |

Its runs, each a line of `scripts/interop-lib.sh` with an id of
`scripts/interop-baseline.txt`:

| Id | Run | Entry |
| --- | --- | --- |
| `ts.tcp.status`, `ts.tcp.jsonl` | `--ts-mode auto` takes `tcp` on headscale's key; the status line, and its JSON object, with home region 999 | T-100, T-102, T-240 |
| `ts.tcp.banner` | `-W TARGET:22`: a version line up, the server's down, after the end of input | T-101 |
| `ts.tcp.ssh`, `ts.relay.ssh` | OpenSSH over `podssh ts -W`: 1 MiB each way with equal digests, in `tcp` mode and in `relay` mode pinned to headscale's DERP server | T-106's runs with two nodes |
| `ts.relay.status` | `relay` mode: the DERP link over a WebSocket up, then the status line | T-105 |
| `ts.bound` | `relay` pinned to a TLS server that speaks no WebSocket: registered, no DERP link, exit 78 within the bound of `--timeout 20s`, each failed attempt said | T-100, T-104 |
| `ts.ephemeral` | `--ts-ephemeral` with the ephemeral key: the node leaves headscale's list within 60 s of its end; the node of `ts.tcp.status` stays | T-102 |
| `ts.exit7` | `exit 7` typed into a login shell through `podssh ssh --direct -tt` and OpenSSH's `ssh -v -tt`: podssh's code is OpenSSH's when the server sent an `exit-status`, else 255 | T-026 |
| `ts.live.refused`, `ts.live.proxy`, `ts.live.socks5` | a fresh node in `relay` mode to the live relay, through `scripts/fake-proxy.py` and through the peer's SOCKS5: registered with headscale, refused with 1008, exit 77; the proxy saw the check's CONNECT and the node's own; `env` where this host has no route to the relay | T-103, T-105, T-281 |
| `ts.relay.drop` | headscale stopped for 45 s during a session in `relay` mode: the DERP link drops and comes back, said on stderr, and 1 MiB arrives whole | T-104 |
| `ts.key` | neither pre-auth key in any output of the run | T-241 |

`TS_HS_PLANT=unknown-key` gives podssh a pre-auth key that headscale does not
know: the registration fails, `ts.tcp.status` fails, and the harness says so
and exits 1. Results: `docs/STATUS.md` (T-334). Tailscale's own control plane
and DERP servers stay unmeasured (the ruling).

## Rules

- A new `--ts-state` file makes a new node key: a new device and a new
  allowlist entry. Use one state file again and again.
- It is not measured whether the proxy of a sandbox allows
  `tcp.ts.relay.ajam.dev:443`.
- The `derpMap` runbook of the relay is still open.
- To signal the end of a stream, call `shutdown()`. Dropping a split write
  half did not always signal it.
