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

2026-10-30 (T-218): the short form of item 3 is `scripts/release-short.sh
BINARY --net`, and each job of the release runs it on the binary's own
platform. The script of item 1 keeps the name scripts/release-check.sh.

2026-10-31, the operator's rulings of that day (`docs/decisions.md`) and the
study of stand-ins. The check runs from a cloud session, where item 3's
Windows host is not:

- the Windows and macOS parts run on GitHub's runners (windows-2025,
  macos-15), where the console checks already run (`.github/workflows/build.yml`),
  and the container parts (a fresh container, the box, `chat-in-boxes.sh`,
  `irc-in-image.sh`) with Podman here or on an ubuntu runner, from a workflow
  started by hand;
- the Tailscale runs and T-026's exit status run against T-334's headscale,
  in place of the operator's tailnet and the key of `.env/`;
- the throughput run's forward cell goes through the relay's loop of Q42 at
  100 MiB a direction, as a lower bound, and the direct cell is named as not
  run; T-335's repair comes first, so that the relay cells cross a relay;
- T-062 runs with the loop.

# T-309: Publish the rolling betas `v1.0.0-beta.N`

**Source:** the operator, 2026-10-30 (`docs/decisions.md`, "Betas before
`v1.0.0`"): the testers in real sandboxes filed the issues from a beta, and
they test the current code only when a beta has it.
**Category:** release
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

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
  (`crates/podssh-ssh/src/run_config.rs:62`), and RFC 4253, section 4.2, allows no
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

## Decision

2026-10-30: a Claude Code cloud session's git may push branches and not
tags: `git push origin v1.0.0-beta.1` got HTTP 403 five times, where each
push of `main` passed. The release workflow therefore takes the tag as an
input of a run by hand (`publish`), checks it against the version and that
it does not exist, and publishes with `gh release create --target`, which
makes the tag at the commit that the run built and checked. Lost: the
operator pushing the tag from a machine (a person in the loop, for each
beta); a run by hand that checks out another commit than its own (the
workflow and the code it releases apart).

## Prove

```sh
gh release view v1.0.0-beta.1 -R Azathothas/podssh --json isPrerelease,assets --jq '.isPrerelease, [.assets[].name]'
```

The release is a prerelease with the three binaries, `SHA256SUMS` and
`THIRD-PARTY-LICENSES.md`. Each sum checks; the x86_64 binary prints
`podssh 1.0.0-beta.1`, has no dynamic dependency, and passes `doctor` and a
login attempt through the relay.

## Done

2026-10-30: `v1.0.0-beta.1` is published, a prerelease at `5c8d423`
(https://github.com/Azathothas/podssh/releases/tag/v1.0.0-beta.1, run
41054194363, at 12:26 UTC), and its files pass the Prove. The steps:

- The version `1.0.0-beta.1` in `Cargo.toml`; `cargo update -w` wrote it in
  `Cargo.lock` and `fuzz/Cargo.lock`, which also took tokio 1.54.1 and the
  `libc` of podssh-ws that it lacked.
- The banner is `SSH-2.0-podssh_1.0.0_beta.1`
  (`crates/podssh-ssh/src/run_config.rs:62`). `cargo test -p podssh-ssh --lib
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

- At `f5e06ca`: each job of the gate green (build, deny, secrets); by hand,
  the release workflow (run 41048945680: the three binaries, each printing
  `podssh 1.0.0-beta.1`; the job publish made `SHA256SUMS`,
  `THIRD-PARTY-LICENSES.md` and a body of 54,245 bytes, and its dry run's
  files), changelog and fuzz (10 s a target), each green. The x86_64 binary
  of that run, here: its sum, static-pie with no `NEEDED` and no `INTERP`,
  9,702,752 bytes, the manual (3701 lines, and the roff page), `doctor` 31
  ok, 0 FAIL, GitHub's banner through `podssh proxy` and the relay, and a
  login with a throwaway key refused (publickey, 255) after GitHub's Ed25519
  key was recorded.
- The tag was refused (HTTP 403; the Decision). The beta is published from
  a run by hand of the next commit, which carries T-316 as well.

- At `5c8d423`: each job of the gate green (build 16 of 16, deny, secrets);
  by hand, the release workflow's dry run (run 41051568231) and changelog,
  each green; its x86_64 binary passed the same local checks.
- The run that publishes (`publish=v1.0.0-beta.1`, run 41054194363) made the
  tag at `5c8d423` and the prerelease, with the three binaries, `SHA256SUMS`
  and `THIRD-PARTY-LICENSES.md`, and a body of 54,692 characters.
- The published files, by their public URLs, here: each of the five
  downloads; each sum checks; the x86_64 binary prints `podssh 1.0.0-beta.1`,
  is static-pie with no dynamic dependency, writes its manual (3702 lines),
  passes `doctor` (31 ok, 0 FAIL), carries GitHub's banner through `podssh
  proxy` and the relay, and a login with a throwaway key is refused
  (publickey, 255).
- The two Linux binaries of the run that publishes are the dry run's, byte
  for byte (equal sums); the Windows binary is not.
- The next betas follow the same steps (`docs/development.md`, "Release
  builds"), each after a batch of repairs that the testers should test
  again, at most one a day.

2026-10-31: `v1.0.0-beta.2` is published, a prerelease at `f7f97a5`
(https://github.com/Azathothas/podssh/releases/tag/v1.0.0-beta.2, the tag's run 41147977814),
with eight binaries, their provenance and the signature of `SHA256SUMS` (T-210, T-211). `main`
held newer commits by then, so the run by hand with `publish` ran on a branch at `f7f97a5`
(`beta/v1.0.0-beta.2`): the job `tag` tags the commit of its run, whatever its branch. Its
files pass the Prove, and the proofs of `.github/workflows/release-proofs.yml` (`docs/STATUS.md`).

2026-11-01: `v1.0.0-beta.3` is published, a prerelease at `54d89a0`
(https://github.com/Azathothas/podssh/releases/tag/v1.0.0-beta.3), by the run by hand with
`publish` on `main` (41261205053), whose job `tag` made the tag, and the tag's run (41261215707,
01:28 to 01:44 UTC), after the gate (run 41259529444), the dry run (41259544441) and the local
checks of its binary (`scripts/release-short.sh --net`) passed on that commit. Newer commits went
to `main` only once the dispatch was taken. Eight binaries, their provenance and the signature of
`SHA256SUMS`; iroh's road and WARP's in each (T-348, Q59). Its files pass the Prove. Here, by their
public URLs: the sums of the three that this host fetched; the x86_64 binary names `54d89a0`, is
static-pie, writes its manual (4850 lines), passes `doctor` (47 ok, 0 FAIL; the edge road waits for
`--full`), carries GitHub's banner through `podssh proxy` and the relay, and a login with a
throwaway key is refused (publickey, 255). Its `podssh update --check` names it the newest release,
and `podssh update --version v1.0.0-beta.2` on a copy checked beta.2's signed `SHA256SUMS` (the
workflow at the tag, Rekor's entry) and replaced the copy with beta.2's binary, byte for byte.
The proofs of `.github/workflows/release-proofs.yml` on a fresh runner (run 41262486970): `SHA256SUMS`
against each of the eight binaries; the provenance of each binary, and a changed copy refused
through the API and with `provenance.sigstore.json`; `SHA256SUMS` signed by the release workflow
at `refs/tags/v1.0.0-beta.3` (cosign 3.1.4 and 2.6.5; Rekor entry 3617465347), a changed copy and a
branch's identity refused; the short form on the published x86_64 binary; and that binary's
`podssh update` to its own release, which replaced it with its download.

# T-375: `podssh update`: the release for its own target, checked, in place of the binary

**Source:** the operator, 2026-10-31: "we will add self update soon", as an explicit command.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A binary that was copied into a sandbox is never updated (Q48): a fix such as russh 0.65.0's
(T-356) reaches no binary in the field until its user copies a new one by hand.

## Premise

- Read: the operator's decision of 2026-10-31: an explicit command that fetches the release for
  its own target through the proxy, checks the signed `SHA256SUMS` and the binary's sum, and
  replaces itself at once; it never runs on its own (`docs/decisions.md:23`).
- Inferred: the release publishes each binary with its provenance and a signed `SHA256SUMS`
  (T-210, T-211), which a client can check before it runs anything that it fetched.

## Approach

1. `podssh update`, and `podssh update --check`, which only says what it would do: the latest
   release (or `--version TAG`), through the proxy, with its `SHA256SUMS`, its signature and the
   asset of the binary's own target, named as `podssh --version` names its target.
2. The check, before anything is written: the signature of `SHA256SUMS`, then the asset's SHA-256
   against its line. The Decision chooses how the signature is checked with no C in the binary's
   path: Sigstore's bundle of the release (T-211), or a second signature by an Ed25519 key whose
   public half is compiled in.
3. The replacement: the new binary beside the old one, its mode copied, then a rename over the
   running file; on Windows, the running file is renamed aside first, and removed at the next run.
   A failure at any step leaves the old binary as it was.
4. Never on its own: no run of another command checks or installs a release.

## Decision

2026-10-31: Sigstore's bundle of the release (T-211), checked in podssh with no network and no C.
The release publishes it already, and it needs nothing of the operator; podssh checks, in
`crates/podssh-cli/src/update/sigstore.rs`: the digest of `SHA256SUMS`; the leaf's ECDSA signature
of the file; the leaf's chain to Fulcio's root, compiled in from Sigstore's trusted root
(`trust/fulcio.pem`), at the time that Rekor gives; the leaf's identity (code signing, the URI of
`release.yml` at the tag, and GitHub Actions as its token's issuer); Rekor's signed entry timestamp
with Rekor's key (`trust/rekor.pem`); and the entry's body against the file, the signature and the
leaf. The signatures are podssh-ws's own ECDSA; x509-parser reads the certificates, with no
feature, so no ring.

The alternative that lost: a second signature by an Ed25519 key whose public half is compiled in.
It needs a key that the operator makes and keeps as a secret of the workflow, whose loss stops each
update and whose leak signs any binary, and a second scheme beside Sigstore's. What Sigstore's
choice risks: when Sigstore rotates Fulcio's CA, or moves cosign to Rekor v2 (with no signed entry
timestamp), the binaries of before refuse the new releases; the refusal says to download by hand,
and the release workflow checks each published release with its own `podssh update --check`, so
the change shows on the day it comes.

The release: `--version TAG`, else the newest of GitHub's API, else of the releases' Atom feed
(redundancy: the API allows 60 calls an hour to an address with no token); a prerelease only when
this binary is one, as the tag says (`-` in it, which is how the workflow marks one); never older
than this build unless `--version` names it. The binary of the target: the release's for this
build's architecture and system, the musl one on Linux whatever this build's libc.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib update::
cargo test -p podssh-cli --test update
```

Against a stand-in release on the loopback: a binary replaced and run; a planted sum, a planted
signature and a binary of another target are each refused, the old binary left as it was. Live, in
Actions: a beta's binary updated to the next beta.

## Correction

2026-10-31: no release before `v1.0.0-beta.3` has `podssh update`, so the Prove's live form, a
beta's binary updated to the next beta, can run first in the proofs of the release after beta.3:
`release-proofs.yml` runs it for each release from then on (the published binary updated to its own
release, and the binary of the release before updated to it). Until then, the live test in Actions
is `update-live.yml`: a build of the commit replaces itself with a published release's binary on
Linux, macOS and Windows, where the running file is renamed aside.

## Done

2026-10-31, commits `5877a00` and `1a46970`: `podssh update`, `--check` and `--version TAG`; the
check of the release's Sigstore bundle with roots compiled in (`update/sigstore.rs`); the fetch
through the proxy with bounded redirects (`update/fetch.rs`); the release from GitHub's API, else
its Atom feed, in semver's order (`update/release.rs`); and the replacement by a rename, on
Windows with the running file renamed aside (`update/replace.rs`). `cargo test -p podssh-cli --lib
update::` passed 19 and `cargo test -p podssh-cli --test update` passed 9: beta.2's own bundle
verifies and each tampered copy is refused; against the stand-in, a file replaced with its mode
and a new inode, which ran, and each planted sum, signature, leaf (tag, issuer, time, use,
Fulcio), Rekor and target refused, the old binary as it was. Five planted defects each failed a
test; the first plant of the chain did not, as its test read a later check's words, and now reads
the chain's own. Live on this host through its proxy: a copy of the build replaced itself with
v1.0.0-beta.2's published binary, which ran. In Actions, `update-live.yml` run 41199118452: on
Linux, macOS and Windows a build of `1a46970` checked the release's signature with its own roots
and replaced itself with v1.0.0-beta.2's binary for its target (7.9 MiB on Windows, where the
running `podssh.exe` was renamed aside to `podssh.exe.old`; 6.2 MiB on macOS), which ran as
`podssh 1.0.0-beta.2 (f7f97a58...)`. Its first run (41197067974) found that macOS has no
`timeout(1)`, and the build's first run at `5877a00` that a Windows checkout turned the fixture's
LF into CRLF; each is repaired in `1a46970`. The beta-to-beta form runs in `release-proofs.yml`
from the release after `v1.0.0-beta.3` (the Correction).
