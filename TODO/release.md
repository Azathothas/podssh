The first stable release, `v1.0.0` (milestone M9): its publication, and the
check of its published assets from end to end, with no human.

# T-250: Publish v1.0.0, the first stable release

**Source:** the operator's ruling of 2026-10-08 (`docs/decisions.md`):
`v1.0.0` after every entry except the relay's, verified from end to end with
no human.
**Category:** release
**Milestone:** M9
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

podssh has no stable release. Users and testers have the beta of M3 (T-002)
at best, and the work of M4 to M8 and of the backlog is in no release.

## Premise

Read: `.github/workflows/release.yml` builds and checks the binaries, and a
tag with a suffix makes a prerelease (`docs/development.md`, section
"Release builds"). The beta is T-002. Provenance (T-210), signed checksums
(T-211) and the new targets (T-218) are inputs.

## Approach

1. Inputs: each entry of `TODO/` is done, except the entries that wait for
   the relay's operator (`TODO/PROGRESS.md`); T-210, T-211 and T-218 are
   done; the gate is green.
2. Set the version to `1.0.0-rc.1` in `Cargo.toml`. Write
   docs/releases/v1.0.0-rc.1.md: what works, and the entries that wait for
   the relay. Tag `v1.0.0-rc.1` and push it: a prerelease.
3. Run the check of T-251 on the published assets of the candidate. Repair
   each failure in its own entry, then publish `rc.2`, and so on.
4. When a candidate passes: set the version to `1.0.0`, write
   docs/releases/v1.0.0.md, tag `v1.0.0` on that commit, and push the tag.
5. Check the published assets of `v1.0.0` again: the checksums, the
   signatures, and the short form of T-251 on each platform.
6. Comment on and close each GitHub issue whose entries are done
   (`TODO/RULES.md`). Update the install lines of `README.md`,
   `docs/STATUS.md` and `TODO/PROGRESS.md`.

## Decision

Recommendation: a candidate first. The check of T-251 reads published
assets, and a stable tag that fails its check cannot be taken back. A
direct tag of `v1.0.0` lost for that reason.

## Prove

```sh
gh release view v1.0.0 -R Azathothas/podssh --json isPrerelease,assets --jq '.isPrerelease, (.assets | length)'
sh scripts/release-check.sh v1.0.0; echo "exit=$?"
```

The release is not a prerelease, and has a binary for each target,
`SHA256SUMS` and the signatures. The check of T-251 exits 0 for `v1.0.0`,
and its result is in `docs/STATUS.md`.

## Start condition

Each entry of `TODO/` is done, except the entries that wait for the relay's
operator, and the gate is green.

# T-251: The check of a release from end to end, with no human

**Source:** the operator's ruling of 2026-10-08 (`docs/decisions.md`): what
"verified end to end" means for `v1.0.0`.
**Category:** measurement
**Milestone:** M9
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

The release workflow checks each binary's links and builds, and runs no
session. Nothing runs the published assets against real servers before
users do.

## Premise

Read: the release workflow checks `NEEDED` and the interpreter with
`readelf`, and the C runtime with `dumpbin` (`.github/workflows/release.yml`).
The gate runs the binary against OpenSSH and Dropbear in a container
(`scripts/gate.sh`). The box models the target sandbox
(`scripts/test_in_box.sh`). `scripts/sandbox-check.sh` measures one host
(T-006).

## Approach

1. A script, scripts/release-check.sh TAG: download the assets of TAG into
   an empty directory, verify `SHA256SUMS`, the Sigstore signatures (T-211)
   and the provenance (T-210), then run the checks below with the binary of
   each host's platform. Each check has a time limit; read each exit code
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
3. Hosts: this Windows host (the Windows binary, natively), a fresh Linux
   container, and the box like the target sandbox. The macOS and other
   binaries: the short form (`--version`, `man --no-pager`, `keygen`, and
   `proxy github.com 22`) in CI on their own runners.
4. Record each result, with the tag and the date, in `docs/STATUS.md`
   (a section "The release check").

## Prove

```sh
sh scripts/release-check.sh v1.0.0-rc.1; echo "exit=$?"
```

The script exits 0 only when each check passes on each host. Planted
defect: change one byte of a downloaded binary; the checksum step must fail,
and nothing runs.

## Start condition

T-250 has published a release candidate.
