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
operator, and the check of T-251 passed before the tag.

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
     auth key file of `.env/` (Q40), and `scripts/chat-in-boxes.sh` (T-099).
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
operator.

## Correction

2026-10-09 (the operator's decision of that day, `docs/decisions.md`):
from T-136 on, an entry closes with the native tests, and the other parts
of its Prove wait for this entry. Before the release check, run them: the
whole gate in the build image (`sh scripts/dev.sh check`, the interop
against OpenSSH and Dropbear with it), then each planted defect that the
`## Done` of such an entry names as waiting. A failure is repaired, and its
entry gets a `## Correction`, before the tag.
