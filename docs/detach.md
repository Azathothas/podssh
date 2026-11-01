# Going to the background: `--detach`

The study behind T-380 and T-381, of 2026-11-01, at the operator's request: a
native way to send a run of podssh into the background, as resilient as the
hosts where podssh runs allow, where users wrote `&` or `nohup`. Each claim
names its source: [src] code read that day, [doc] a primary document, [exp]
an experiment in a Claude Code cloud container (a Firecracker VM, kernel
6.18), UNVERIFIED where neither was possible. The web was read through
web.pkgforge.dev.

## 1. What ends a background process, and whether a native detach survives it

"Survives" is the design of section 4; the last column is `podssh session
start` (T-186) as it was before T-380.

| Environment | What ends or hangs `&`, `nohup` or `setsid(1)` | Native survives | How, or why not | T-186 |
|---|---|---|---|---|
| A terminal or pty closes | SIGHUP to the foreground group when the controlling process exits, and bash's to its jobs [doc] POSIX `_exit`. Measured: a plain `&` killed; `nohup`, `setsid`, `trap '' HUP` and `disown` survived [exp] | yes | `setsid()` at ready, SIGHUP ignored | yes |
| A background job touches the terminal | SIGTTIN stopped a reader (state `T`, measured); SIGTTOU stops writers under `tostop` | yes, after ready | a prompt refuses when the terminal's foreground group is not podssh's | cannot prompt |
| `nohup` in a directory it cannot write; busybox with no `nohup` or `setsid` | `nohup.out` fails; the tools may be missing | yes | no other program; the log goes to the cache | yes |
| Claude Code's Bash tool, a call | Waits for no pipe: stdout and stderr are a file, stdin `/dev/null`, job control on. Each of five `&` forms survived, adopted by PID 1 [exp] | yes | nothing needed | yes |
| Claude Code's TaskStop of a background task | SIGTERM then SIGKILL to each descendant by parent pid, a new session's child of a living parent included; one already adopted by PID 1 survived [exp] | yes, once the parent exited | the parent exits at ready | yes |
| Codex CLI (`openai/codex:codex-rs`) | Reads the pipes; open 2 s after the shell exits, it kills the process group; the shell has `PR_SET_PDEATHSIG` [src] `core/src/exec.rs`, `spawn.rs` | yes | the pipes released, then `setsid()` | yes |
| Codex cloud, Devin, Replit, Gitpod | The VM or container ends with the task (UNVERIFIED) | no, at the end | cannot be escaped | same |
| Cursor and VS Code terminals (node-pty) | Unix: SIGHUP to the shell; Windows: each process of the console (`GetConsoleProcessList`) is killed [src] `microsoft/node-pty:src/windowsPtyAgent.ts` | yes | `setsid()`; `FreeConsole()` | yes |
| Jupyter `!cmd &` | Refused ("Background processes not supported"); `!cmd` runs on a pty, read to its end [src] ipykernel `zmqshell.py` | yes | the pty released and `setsid()` before the parent exits | yes |
| Cloud Shell; Codespaces | Sessions end after their idle times and at 12 h [doc] | no | a line before the detach | same |
| `ssh host 'podssh ...'` with no pty, or any caller that reads to the end | A descendant that holds a pipe keeps the reader waiting. Measured: an extra fd 5 held it [exp]. Rust's standard library closes no inherited descriptor in a child (`std/src/sys/process/unix/unix.rs` has no `close_range`) [src] | yes | descriptors 3 and up closed at the child's start; 0 to 2 replaced before ready | 0 to 2 only |
| No init; `docker exec` or `kubectl exec` ends | Adopted by the container's PID 1 | yes, while the container runs | nothing needed | yes |
| podssh is PID 1 of its namespace | The namespace ends with PID 1 | no | refused, 69 | not seen |
| A systemd service (`KillMode=control-group`) | A stop kills the whole cgroup [doc] `systemd.kill(5)` | no, by design | a line before the detach | same |
| logind `KillUserProcesses=yes` (the default upstream; Debian sets no) | The session's scope ends at logout [doc] `logind.conf(5)` | yes, if podssh moves itself | a transient scope of the user's manager, as tmux does [src] `tmux/tmux:compat/systemd.c` (T-381) | no |
| GitHub Actions, between steps | Waits for the step's process, its pipes up to 5 s, then kills its tree [src] `actions/runner:src/Runner.Sdk/ProcessInvoker.cs` | yes | the pipes released | yes |
| GitHub Actions, the end of a job | Each new process whose environment holds the job's `RUNNER_TRACKING_ID` is killed at "Complete job" [src] `actions/runner:src/Runner.Worker/JobExtension.cs` | no, by design | never evaded (section 4) | same |
| Jenkins | Kills processes whose environment holds `BUILD_ID` or `JENKINS_NODE_COOKIE` [doc] ProcessTreeKiller | no, by design | never evaded | same |
| GitLab's shell executor | Unix: a cancel kills the process group; Windows: `taskkill /T`, or a job with `BREAKAWAY_OK` [src] `gitlab-runner:helpers/process` | yes | `setsid()`; breakaway | Unix only |
| SSH into Windows (Win32-OpenSSH) | Each session's job has `KILL_ON_JOB_CLOSE` and `BREAKAWAY_OK` [src] `PowerShell/openssh-portable:contrib/win32/win32compat/w32-doexec.c` | yes | breakaway from the job | no |
| A Windows console closes | `CTRL_CLOSE_EVENT`, then the end after 5 s [doc] | yes | `FreeConsole()` at ready | yes |
| A Windows job that kills on close and allows no breakaway | Breakaway is refused with `ERROR_ACCESS_DENIED` | no | a retry without it, and a line | no |
| macOS: a Terminal closes; a launchd job ends | SIGHUP; launchd kills the job's group unless `AbandonProcessGroup` [doc] `launchd.plist(5)` | yes | `setsid()` | yes |
| Termux on Android 12 and later | The phantom process limit, 32 for all apps [doc] | no | a line before the detach | same |
| WSL 2 | `instanceIdleTimeout` (whether a background process counts is UNVERIFIED) [doc] | no | a line before the detach | same |

## 2. The techniques, ranked

1. **This binary again, started early.** A fork once tokio runs is unsafe,
   and Windows has none; Go does the same (golang/go#227; go-daemon starts
   itself again with `Setsid`). The binary: `/proc/self/exe` first, which runs
   the running image even after `podssh update` replaced its file (measured:
   its link reads "(deleted)", and an exec of it runs the old image [exp]);
   then `std::env::current_exe()`; then `argv[0]`.
2. **`setsid()` in the child, at ready.** It fails only for a group's leader,
   which a new child is not, so it can come after the prompts (measured: a
   prompt, then `setsid()`, then the pty closed; the child lived [exp]).
   Windows: `FreeConsole()`.
3. **Each inherited descriptor released.** `close_range(3, ...)`, else each
   of `/proc/self/fd`, else up to `RLIMIT_NOFILE`, at the child's start
   (daemon(7), and OpenSSH's `closefrom(3)`); stdin, stdout and stderr
   replaced before ready.
4. **The signal state reset.** A child inherits the mask; the child empties
   it and sets INT, TERM and QUIT to their defaults.
5. **A channel of ready, and the parent watched.** daemon(7)'s steps 14 and
   15, OpenSSH's fork after the login or after the forwards.
6. **Windows: breakaway from a job, retried without.** `CREATE_BREAKAWAY_FROM_JOB`
   needs the job's `BREAKAWAY_OK`; a refusal is `ERROR_ACCESS_DENIED`.
7. **Linux: leaving the session's scope** through the user's systemd, natively
   over D-Bus, as tmux does (T-381, Q61).
8. **Not done:** a transient service (it loses the prompts and the channel of
   ready); removing a CI's tracking variables; a fork before the runtime.

## 3. Prior art

OpenSSH's `-f`: `daemon(1,1)` after the login, or after the replies of `-R`
with `ExitOnForwardFailure`; refused with no command unless `-N` [src]
`openssh/openssh-portable:ssh.c`. autossh's `-f` forks before ssh, so "ssh
will be unable to ask for passwords" [doc]. tmux moves itself into a scope
of systemd [src]. conmon: a double fork, `setsid`, a pipe of ready, and its
stdio closed, as "the parent is waiting for the stdout to end" [src].
cloudflared, chisel, frp, gost, websocat and tailscaled leave it to a
service manager (UNVERIFIED).

## 4. The design

- `--detach` on `ssh`, `pipe` (with a listening side) and `node`; `-f` and
  `ForkAfterAuthentication yes` on `ssh`, as OpenSSH, with a command or `-N`.
- The parent refuses what needs no network first (64, 78), refuses as PID 1
  (69), says the hazards that it finds (a systemd service, WSL, Termux, a
  short-lived init), then starts this binary again with `--detach-child` in
  place of `--detach` or `-f`, its stdout a pipe to the parent, its stdin
  and stderr the caller's, and waits.
- The child closes each descriptor from 3 up and resets its signals, then
  runs the command as in the foreground, its prompts on the caller's
  terminal. At ready: stdin to the null device, stderr to its log, then
  `setsid()` and SIGHUP ignored (Unix), `FreeConsole()` (Windows); then the
  line of ready on stdout; then stdout to the null device.
- Ready: `ssh` once its request went (`podssh_ssh::retry::Phase::Requested`:
  after the login, `-L` and `-D` bound before it); `pipe` once its listener is
  bound; `node` at its line `online`.
- The parent prints the child's pid and log, and exits 0; or the child's own
  code when it ended first, as its lines went to the caller's stderr; or
  128+N for a signal before ready, which reached the child too.
- The log: `detached/VERB-PID.log` in the cache (mode 0600), cut back to its
  last part past 1 MiB; none with `PODSSH_CACHE_DIR=none`.
- Windows: the child out of the caller's job when the job allows it, else
  in it, with a line; the caller's console shared until ready, so that
  Ctrl-C before ready reaches it too, and freed before the line of ready;
  with no console window, `CREATE_NO_WINDOW` for each console program that
  it starts, as Windows would open a window for it (T-383).
- `--restart` (T-390): a supervisor between the parent and the child,
  which starts the child again after each end but 64, 77 and 78 and its
  own stop, with the relay's backoff, never giving up; no PDEATHSIG, and no
  restart before the first ready (`docs/cli.md`).
- A line that fails to write is dropped, never the run's end: after ready
  stderr is the log, and its disk may fill or, under systemd, the journal
  go away. `eprintln!` panics on such a failure and the release aborts on a
  panic, so podssh's lines go through `podssh_ssh::err_line!`, and
  `scripts/check-repo.py` refuses the print macros of std in the sources
  (T-389, from the study of a daemonizer, d-mon, on 2026-11-01).
- Never: another program (`nohup`, `setsid(1)`, `systemd-run`, `tmux`); a
  CI's tracking variable removed (`RUNNER_TRACKING_ID`, `BUILD_ID`,
  `JENKINS_NODE_COOKIE`): the user asked to outlive the caller, not the job,
  and a tunnel that outlives a shared runner's job is a way back into
  another's network.

## 5. Tests

Each fails on the defect planted against it:

- a node of `--restart` killed with SIGKILL comes back and serves a login,
  and SIGTERM to its supervisor ends both (no restart); a supervisor killed
  with SIGKILL leaves its node serving (`tests/node_detach.rs`);
- a node whose stderr fails (a pipe with no reader, `/dev/full`) goes on
  serving two logins (`tests/node_detach.rs`; an `eprintln!` in the node's
  lines);

- the caller sees the end of its pipes at once, an extra descriptor
  included (the close of descriptors from 3 up removed);
- a kill of the parent's process group after ready leaves the child, in a
  session of its own (no `setsid`);
- a pty closed after ready leaves the child (no `setsid`);
- a failure before ready gives the parent the child's code (the parent
  exits 0 at the start);
- PID 1 refuses with 69;
- on Windows, in a job with `KILL_ON_JOB_CLOSE` and `BREAKAWAY_OK`, the
  child outlives the job (no breakaway), and in one without, the retry and
  its line.
