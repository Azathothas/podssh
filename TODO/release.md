The first stable release, `v1.0.0` (milestone M9): its publication, and the
check of its published assets from end to end, with no human.

# T-250: Publish v1.0.0, the first stable release

**Source:** the operator's rulings of 2026-10-08 (`docs/decisions.md`): one
release only, `v1.0.0`, after every entry except the relay's; no beta, no
release between entries, and one tag, checked before and after.
**Category:** release
**Milestone:** M9
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

podssh has no release. Testers use the CI artifact of a push, and the work
of M3 to M8 and of the backlog reaches users only with a release.

## Premise

Read: `.github/workflows/release.yml` builds and checks the binaries, and
publishes them for a tag (`docs/development.md`, section "Release builds").
A release run is long, and it takes CI from the work: the operator wants one
release, at the end. Provenance (T-210), signed checksums (T-211) and the
new targets (T-218) are inputs.

## Approach

1. Inputs: each entry of `TODO/` is done, except the entries that wait for
   the relay's operator (`TODO/PROGRESS.md`); T-210, T-211 and T-218 are
   done; the gate is green; the check of T-251 passed before the tag.
2. Set the version to `1.0.0` in `Cargo.toml`. Write docs/releases/v1.0.0.md:
   what works, the targets, how to check a download, and the entries that
   wait for the relay. The draft notes of the dropped beta can help
   (`git show b1b111b:docs/releases/v0.1.0-beta.1.md`).
3. Tag `v1.0.0` once, and push the tag. Do not tag a candidate first: one
   release run only.
4. Run the check of T-251 on the published files. A defect found then is a
   new entry: repair it, and publish `v1.0.1` by the same steps.
5. Comment on and close each GitHub issue whose entries are done
   (`TODO/RULES.md`). Update the install lines of `README.md`,
   `docs/STATUS.md` and `TODO/PROGRESS.md`.

## Decision

The operator ruled on 2026-10-08: tag `v1.0.0` directly, checked before the
tag on the gate's artifact and a local build, and after it on the published
files; a defect found then goes into `v1.0.1`. A release candidate lost: it
costs one more release run.

## Prove

```sh
gh release view v1.0.0 -R Azathothas/podssh --json isPrerelease,assets --jq '.isPrerelease, (.assets | length)'
sh scripts/release-check.sh v1.0.0; echo "exit=$?"
```

The release is not a prerelease, and has a binary for each target,
`SHA256SUMS` and the signatures. The check of T-251 exits 0 on the published
files, and its result is in `docs/STATUS.md`.

## Start condition

Each entry of `TODO/` is done, except the entries that wait for the relay's
operator, the entries that the operator holds (Q32) and the work parked
behind them (`TODO/PROGRESS.md`), and the check of T-251 passed before the
tag.

# T-251: The check of a release from end to end, with no human

**Source:** the operator's rulings of 2026-10-08 (`docs/decisions.md`): what
"verified end to end" means, and that it runs before the tag and after it.
**Category:** measurement
**Milestone:** M9
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

The release workflow checks each binary's links and builds, and runs no
session. Nothing runs the binaries of a release against real servers before
users do.

## Premise

Read: the release workflow checks `NEEDED` and the interpreter with
`readelf`, and the C runtime with `dumpbin` (`.github/workflows/release.yml`).
The gate runs the binary against OpenSSH and Dropbear in a container, and
CI keeps the static binary of each push as an artifact (`scripts/gate.sh`).
The box models the target sandbox (`scripts/test_in_box.sh`).
`scripts/sandbox-check.sh` measures one host (T-006).

## Approach

1. A script, scripts/release-check.sh, with two sources of binaries: before
   the tag, the artifact of the gate's last push and a local Windows build
   (`--local`); after the tag, the published files of a tag (`TAG`), with
   `SHA256SUMS`, the Sigstore signatures (T-211) and the provenance (T-210)
   verified first. Each check has a time limit; read each exit code
   directly.
2. The checks:
   - the commands of `README.md`, and `podssh doctor` (exit 0);
   - `podssh proxy github.com 22`: GitHub's banner through the live relay;
   - `podssh ssh -T git@github.com` with a throwaway key: `Permission denied
     (publickey)` through the relay;
   - a session with a pty, and an exec, to railway.new through the relay, and
     to a tailnet host with `--direct` (throwaway keys);
   - the reverse road: two sessions at once from one box to a node in another
     box (the script of T-085);
   - `podssh serve` in the box: `vi`, `less` and Ctrl-C (the route of T-248);
   - `podssh cp` of 200 MiB each way, with equal digests;
   - a session that survives a killed relay connection (T-156);
   - `podssh pipe` with `stdio`, `exec:` and `unix-connect:`.
   - the live parts that the entries left to this check, each named in its
     `## Done`: among them the throughput run of T-157 with
     `PODSSH_THROUGHPUT_MIB=100` (500 MiB a direction in each cell, n0's iroh
     relays and the operator's SSH host: the operator, 2026-10-10, Q38), the
     IRC runs on undernet, libera and OFTC (Q39), the Tailscale runs with the
     auth key file of `.env/` (Q40), `scripts/chat-in-boxes.sh` (T-099), and
     `scripts/irc-in-image.sh` with its plant (T-252), whose step then joins
     the gate, and the exit status of an interactive login shell on a
     tailnet host with `--direct` (T-026): `exit 7` through `podssh ssh -tt`
     and through OpenSSH's `ssh -v -tt`, whose log names each `exit-status`
     request; its result corrects that row of `docs/STATUS.md`.
3. Hosts: this Windows host (the Windows binary, natively), a fresh Linux
   container, and the box like the target sandbox. The other targets: the
   short form (`--version`, `man --no-pager`, `keygen`, `proxy github.com
   22`) in the release run, on their own runners (T-218).
4. Record each result, with its source and the date, in `docs/STATUS.md`
   (a section "The release check").

## Prove

```sh
sh scripts/release-check.sh --local; echo "exit=$?"
```

The script exits 0 only when each check passes on each host. Planted
defect: change one byte of a checked binary; the checksum step must fail,
and nothing runs. T-250 runs the same script on the published files.

## Start condition

Each entry of `TODO/` is done, except the entries that wait for the relay's
operator, the entries that the operator holds (Q32) and the work parked
behind them (`TODO/PROGRESS.md`).

## Correction

2026-10-09 (the operator's decision of that day, `docs/decisions.md`):
from T-136 on, an entry closes with the native tests, and the other parts
of its Prove wait for this entry. Before the release check, run them: the
whole gate in the build image (`sh scripts/dev.sh check`, the interop
against OpenSSH and Dropbear with it), then each planted defect that the
`## Done` of such an entry names as waiting. A failure is repaired, and its
entry gets a `## Correction`, before the tag.

# T-309: Publish the rolling betas `v1.0.0-beta.N`

**Source:** the operator, 2026-10-30 (`docs/decisions.md`, "Betas before
`v1.0.0`"): the testers in real sandboxes filed the issues from a beta, and
they test the current code only when a beta has it.
**Category:** release
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** partial

## Problem

GitHub has no release and no tag since the history was replaced
(`docs/decisions.md`, "The repository is public"). The testers are agents in
real sandboxes that download a binary: with no release, none of the work
since 2026-10-08 reaches them.

## Premise

- Read: `.github/workflows/release.yml` builds static musl binaries for
  x86_64 and aarch64 and a Windows binary, and publishes them with
  `SHA256SUMS` for a tag `vX.Y.Z[-pre]`, as a prerelease when the tag has a
  suffix. Its job `publish` has never run: each run so far was by hand.
- Read: the body of a release is the notes file and git-cliff's list of the
  commits since the previous tag (`cliff.toml`). With no previous tag the
  list is the whole history: 342 commits, whose first lines hold about
  118,000 characters, and GitHub refuses a body of more than 125,000.
- Read: nothing compares the tag with the version of the crates (`Cargo.toml`,
  `version = "0.1.0"`), which `podssh --version` prints.
- Read: the SSH banner carries the version
  (`crates/podssh-ssh/src/run.rs:454`), and RFC 4253, section 4.2, allows no
  `-` in its software version.

## Approach

1. The version `1.0.0-beta.N` in `Cargo.toml` and the lock files; the banner
   with `_` for each `-`.
2. The workflow: each commit's line cut to 200 characters (`cliff.toml`), a
   check that the body is under GitHub's limit, and a check that the binary
   of a tag names the tag's version.
3. The notes, docs/releases/v1.0.0-beta.N.md: what works, the assets, how
   to check a download, and what a beta does not have yet (T-210, T-211,
   T-218, T-251).
4. Before the tag: the gate green on the commit, the release workflow and the
   changelog workflow by hand on it, and the local checks of its binary
   (`--version`, static, `man`, `doctor`, `proxy` and `ssh` through the
   relay).
5. The tag once; then the same checks on the published files, and the result
   in `docs/STATUS.md`.

## Prove

```sh
gh release view v1.0.0-beta.1 -R Azathothas/podssh --json isPrerelease,assets --jq '.isPrerelease, [.assets[].name]'
```

The release is a prerelease with the three binaries, `SHA256SUMS` and
`THIRD-PARTY-LICENSES.md`. Each sum checks; the x86_64 binary prints
`podssh 1.0.0-beta.1`, has no dynamic dependency, and passes `doctor` and a
login attempt through the relay.

## Done

So far, 2026-10-30 (the entry stays `partial` until the first beta is
published and checked):

- The version `1.0.0-beta.1` in `Cargo.toml`; `cargo update -w` wrote it in
  `Cargo.lock` and `fuzz/Cargo.lock`, which also took tokio 1.54.1 and the
  `libc` of podssh-ws that it lacked.
- The banner is `SSH-2.0-podssh_1.0.0_beta.1`
  (`crates/podssh-ssh/src/run.rs:454`). `cargo test -p podssh-ssh --lib
  run::tests`: 6 passed, and the new test of the banner failed planted (the
  `-` kept: `SSH-2.0-podssh_1.0.0-beta.1`). `scripts/sandbox-check.sh:113`
  sent a `-` in its software version too: `podssh_sandbox_check` now.
- `cliff.toml`: each subject cut to 200 characters; after the cut, a name
  after `@` becomes code (the subjects hold `@NAME`, `@GROUP` and
  `@cert-authority`, which GitHub would read as mentions), then `#N` links.
  git-cliff 2.9.1, its release binary checked against its SHA-512: 343 of
  343 commits in 50,475 bytes, no mention outside code.
- `.github/workflows/release.yml`: each binary prints the version of
  `Cargo.toml`, and a tag must name it; the job `publish` runs by hand too,
  each step but `gh release create`, and keeps the files and the body as
  the artifact `release-dry-run`; the body stays under 120,000 bytes, else
  the list is cut at a line and is whole in `CHANGES.md`; git-cliff from
  `taiki-e/install-action`; `--verify-tag`. The comment on NASM said that
  aws-lc falls back without it: aws-lc-sys 0.45 stops (`builder/main.rs`,
  `use_prebuilt_nasm`) unless `AWS_LC_SYS_PREBUILT_NASM=1`. actionlint 1.7.7
  with shellcheck: clean. The body, made as the step makes it: 54,029 bytes;
  with the list three times, planted, 119,794 bytes and `CHANGES.md`.
- The notes: docs/releases/v1.0.0-beta.1.md.

Next: CI green on the commit, the release workflow by hand on it, the local
checks of its binary, the tag, and the checks of the published files.
