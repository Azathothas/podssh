# Target environment

podssh is built for hosts that are far more restricted than a normal Linux box.
This page records what one such host actually allowed, and the design rules
that follow. The rules matter more than the specific host: tool presence and
policy differ between sessions and images, so **podssh probes at runtime and
assumes nothing**.

## One measured host

Measured 2026-10-04 by the operator's sandbox probe (sandprobe 1.0.0) on an AI
agent's Linux sandbox, kernel 7.2, running as uid 0 inside the sandbox.

| area | result |
| --- | --- |
| egress | **only** an HTTP CONNECT proxy, advertised as `HTTPS_PROXY`/`https_proxy` (a link-local address); `NO_PROXY` lists the proxy itself |
| proxy policy | `CONNECT` to public hosts on **443, 80, 8443** → `200`; on **22, 25** → `403 not on the egress allowlist`; to private or metadata addresses → `403 not a public host` |
| direct TCP | every direct `connect()` failed: `EACCES` for ports 53 and 22 and for loopback, silently dropped for 80, 443 and 8443 — including to IP literals |
| UDP | `EPERM` |
| DNS | the system resolver fails for every name (port 53 is denied); the proxy resolves names given to `CONNECT`, so a client that uses it needs no DNS |
| listening | not measured by the probe; the operator reports that binding sockets is not allowed |
| terminal | no `/dev/ptmx`, no `/dev/pts`; `TERM=xterm-256color` is set anyway |
| other devices | no `/dev/net/tun` |
| isolation | seccomp filter active, `NoNewPrivs=1`; `unshare`, `mount` and `chroot` are denied |
| writable | `/tmp`, `/dev/shm`, `$HOME`, the workspace; `/etc/ssl` is mounted read-only |
| tools | that image had `ssh`, `curl`, `openssl`, `python3`, compilers and `cargo` — other images do not, and the same image has changed between sessions |

`scripts/test_in_box.sh` builds a Podman box with these properties and
checks the box against the report before it measures podssh; see
[development.md](development.md#a-box-like-the-target-sandbox).

## Other hosts of the same kind

- **No user database.** podbox issue #114 describes a host running as uid 966
  with no `/etc/passwd` entry, where `/state/home` is writable but refuses to
  execute programs while `/tmp` and `/workspace` allow it, and namespaces,
  mount, chroot and ptrace are all denied. In a sandssh sandbox with no passwd
  entry, OpenSSH 10.5p1's `ssh`, `ssh-keygen` and `scp` all exited 255 with
  `No user exists for uid 0` (measured by sandssh). So podssh takes the user
  name and home directory from `user@`, `$USER`, `$LOGNAME` and `$HOME`, never
  from `getpwuid`.
- **Writable is not executable, and `/proc` may be missing.** Install
  instructions say `/tmp` or the workspace. A related host had no `/proc`, so
  `current_exe()` (used to find a CA file beside the binary) can fail and is
  then skipped.
- **Proxies differ per name.** One CONNECT proxy answered `200` for one relay
  hostname and `504` for another in the same second. podssh passes the name
  unresolved and reports a proxy's 5xx as the proxy's answer; another relay
  hostname is a cheap fallback.
- **No proxy and no DNS** leaves only a configured (hostname, address) pair:
  the relay's hostnames share Cloudflare anycast addresses, and TLS to a bare IP
  fails. A DNS-over-HTTPS resolver would have to be reachable by IP literal.

Server-side faults that look like key failures, worth naming in podssh's
authentication errors: an unknown login name gives `Permission denied
(publickey)`; Dropbear refuses a user whose shell is not in `/etc/shells`; a
shell that does not exist lets authentication succeed and then ends the
session at once.

## Rules that follow

1. **Reach the relay through `HTTPS_PROXY` when one is set** (`HTTP CONNECT
   tcp.ssh.relay.ajam.dev:443`, by hostname so the proxy resolves it). Honour
   `https_proxy`, `ALL_PROXY` and `NO_PROXY`. Connect directly only when no proxy
   is configured. Never require working DNS.
2. **Use port 443.** Port 22 is usually the first thing a proxy allowlist drops;
   that is why the relay exists.
3. **One outbound connection, never a listener.** No `bind()`, no `listen()`,
   no loopback services. Features that need a local listening socket (`ssh -L`,
   `-D`, `ControlMaster`) cannot work on such hosts and must fail with a clear
   message.
4. **No pty required.** A remote pty needs nothing local, and when there is no
   pty anywhere podssh can supply the line discipline (echo, editing, history)
   itself, in-process; [terminal.md](terminal.md) says when. No `LD_PRELOAD`,
   no helper processes: a preload shim fails silently against a static binary
   and looks like an authentication failure.
5. **Depend on nothing installed.** Not `ssh`, not `curl`, not a CA bundle, not
   a writable `$HOME`. Ship one static binary with embedded trust roots, and
   walk a fallback chain for anything written to disk (token cache: config dir,
   then `$TMPDIR`, then `/dev/shm`, then the working directory).
6. **Probe, don't assume.** A capability is used only after it has been checked
   on the running host, and a failed probe produces an actionable error, not a
   silent fallback that changes behaviour.
