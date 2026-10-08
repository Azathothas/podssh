# Target environment

podssh is for hosts with much stronger limits than a normal Linux host. This
page gives what one such host allowed, and the design rules that follow. The
rules are more important than the specific host: the tools and the policy
change between sessions and images. Thus **podssh probes at runtime and
assumes nothing**.

## One measured host

The operator's sandbox probe (sandprobe 1.0.0) measured this host on
2026-10-04: the Linux sandbox of an AI agent, kernel 7.2, uid 0 in the
sandbox. The report is `.work/sandprobe-run1.txt`, which is not in the
repository.

| Area | Result |
| --- | --- |
| Identity | uid 0 with no name: `whoami` fails, and there is no `/etc/group` |
| Privileges | no capabilities; `NoNewPrivs=1`; a seccomp filter. `unshare`, `mount` and `chroot` are refused. |
| Egress | **Only** an HTTP CONNECT proxy, given as `HTTPS_PROXY` and `https_proxy` (a link-local address). `NO_PROXY` lists the proxy itself. |
| Proxy policy | `CONNECT` to public hosts on ports **443, 80, 8443**: `200`. On ports **22, 25**: `403 not on the egress allowlist`. To private or metadata addresses: `403 not a public host`. |
| Direct TCP | Each direct `connect()` failed: `EACCES` for ports 53 and 22 and for loopback; dropped with no answer for ports 80, 443 and 8443, also for IP literals. |
| UDP | `EPERM` |
| DNS | The system resolver fails for each name (port 53 is refused). The proxy resolves the names that `CONNECT` gives, so a client that uses the proxy needs no DNS. |
| Listening | The probe did not measure it. The operator reports that binding sockets is not allowed. |
| Terminal | No `/dev/ptmx` and no `/dev/pts`. `TERM=xterm-256color` is set. |
| Other devices | No `/dev/net/tun`. |
| Writable | `/tmp`, `/dev/shm`, `$HOME`, the workspace. `/etc/ssl` is read-only. |
| Tools | That image had `ssh`, `curl`, `openssl`, `python3`, compilers and `cargo`. Other images do not, and the same image changed between sessions. |

`scripts/test_in_box.sh` builds a Podman box with these properties. It checks
the box against the report before it measures podssh. See
[development.md](development.md#a-box-like-the-target-sandbox).

## Other hosts of the same kind

- **No user database.** podbox issue #114 describes a host that ran as uid
  966 with no `/etc/passwd` entry. There, `/state/home` was writable but did
  not run programs, `/tmp` and `/workspace` did, and namespaces, `mount`,
  `chroot` and `ptrace` were refused. In a sandssh sandbox with no passwd
  entry, the `ssh`, `ssh-keygen` and `scp` of OpenSSH 10.5p1 exited 255 with
  `No user exists for uid 0`. Thus podssh takes the user name and the home
  directory from `user@`, `$USER`, `$LOGNAME` and `$HOME`, never from
  `getpwuid`.
- **A writable directory may not run programs, and `/proc` may be
  missing.** Install podssh in `/tmp` or in the workspace. A related host had
  no `/proc`, so `current_exe()` can fail. podssh then does not look for a
  CA file next to the binary.
- **A proxy can answer differently for each name.** One CONNECT proxy
  answered `200` for one relay host name and `504` for another in the same
  second. podssh gives the name to the proxy unresolved, reports a proxy's
  5xx as the proxy's answer, and tries the next relay host.
- **No proxy and no DNS.** The relay's host names share Cloudflare anycast
  addresses, and TLS to a bare IP fails. podssh pins an address to a name
  (`--relay-addr HOST=IP`) and checks TLS against the name, and it asks DNS
  over HTTPS to resolvers that it reaches by IP literal.

Some server faults look like key failures. podssh's authentication errors
should name them:

- An unknown login name gives `Permission denied (publickey)`.
- Dropbear refuses a user whose shell is not in `/etc/shells`.
- A shell that does not exist lets the authentication succeed, then ends the
  session at once.

## Rules that follow

1. **Reach the relay through `HTTPS_PROXY` when it is set:**
   `CONNECT tcp.ssh.relay.ajam.dev:443` with the host name, so that the proxy
   resolves it. Use `https_proxy`, `ALL_PROXY` and `NO_PROXY`. Connect
   directly only when no proxy is set. Never require working DNS.
2. **Use port 443.** A proxy's allowlist usually drops port 22 first. That
   is why the relay exists.
3. **One outbound connection, and no listener unless the user asks for it
   and a probe allows it.** No `bind()`, no `listen()`, no loopback services
   by default. Features that need a local listening socket (`ssh -L`, `-D`,
   `ControlMaster`) probe first. Where the bind is refused, they fail with a
   clear message ([decisions.md](decisions.md), 2026-10-08).
4. **No pty required.** A remote pty needs nothing local. When there is no
   pty anywhere, podssh can supply the line discipline (echo, editing,
   history) in its own process, or a tty in user space for a child of
   `podssh serve` (T-248); [terminal.md](terminal.md) tells when. No
   `LD_PRELOAD` and no helper processes: a preload shim fails silently
   against a static binary and looks like an authentication failure.
5. **Depend on nothing installed:** not `ssh`, not `curl`, not a CA bundle,
   not a writable `$HOME`. Ship one static binary with trust roots in it.
   For each file that podssh writes, use a fallback chain (the token cache:
   the configuration directory, then `$TMPDIR`, then `/dev/shm`, then the
   working directory).
6. **Probe; do not assume.** Use a capability only after a check on the
   running host. A failed probe gives an error that tells what to do, never a
   silent fallback that changes the behaviour.
