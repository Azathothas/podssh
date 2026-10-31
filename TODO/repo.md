The work on the repository, CI and the releases: the work record,
Dependabot, the build image, the developer script, the changelog, secret
scanning, the provenance and signatures of releases, parallel CI, the box and
Windows in CI, formatting and lints, the checks of the dependencies, the
minimum Rust versions, more release targets, and the gate's own checks. It is
not milestone work (milestone `none`). The main sources are GitHub #27 and
GitHub #33.

# T-204: Adopt the todo model, with a Rust checker in the gate

**Source:** the operator, 2026-10-08: turn the GitHub issues and the sandbox
reports into trackable entries with the todo model of the operator's template
(`Azathothas/TEMPLATE:docs/methodology/work-todo.md`), with the checker in
Rust and in the gate, and no shell script for it. The floors of the reader
follow GitHub #33.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The work was in three places: the open checkboxes of `docs/ROADMAP.md`, the
rows of a defects page (`git show 3ee70dc:docs/defects.md`), and 28 GitHub
issues. There was no single order,
and nothing compared two of them. A count or a status could disagree between
files with no failure.

## Premise

Read: the template asks for a writer that moves a status and derives each
count from the rows, and a reader that asserts that the counts agree with the
rows, that no status disagrees between the index and the entry, that each row
has an entry and each entry a row, that each reference resolves, and that
each cited path and line exists. The reader runs as a gate.

## Approach

1. `crates/podssh-todo` (no dependencies): `check` (the reader), `set
   T-NNN STATUS` (the writer, which refuses `done` without dated evidence and
   `blocked` without a blocker), `counts` and `next`. The alias `cargo todo`
   is in `.cargo/config.toml`.
2. The reader also checks the form of each entry, the work order (no done
   entry), the questions that blocked entries wait for, and `docs/ROADMAP.md`
   (no open checkbox; each id under a milestone has that milestone). It fails
   when the index has no rows or the roadmap is missing.
3. Two gate steps in `scripts/gate.sh`: the checker's tests, then `check`.
   `scripts/check-repo.py` also checks the links of `TODO/`.
4. The record: `TODO/INDEX.md`, `TODO/PROGRESS.md`, `TODO/RULES.md`,
   `TODO/issues.md` and the area files. The rows of the defects page became
   entries, and the page was removed. The open items of `docs/ROADMAP.md`
   name their entries. `AGENTS.md` starts each session at
   `TODO/PROGRESS.md`.

## Prove

```sh
cargo test -p podssh-todo
cargo todo check
python scripts/check-repo.py
```

The tests include 29 plants, each a disagreement that the reader must find,
and the control record, which must pass. Two plants are floors (GitHub #33):
an index with no rows, and a missing roadmap. A reader that finds nothing to
check fails; it does not pass. `check` prints the counts that the rows give.

## Done

2026-10-08, in the commit that adds `TODO/INDEX.md` (`git log --diff-filter=A
-- TODO/INDEX.md`). Results on Windows: see `docs/STATUS.md`, "Build, tests,
CI", the row of the work record.

# T-205: Dependabot for cargo, GitHub Actions and the build image (GitHub #27)

**Source:** GitHub #27 (the operator, 2026-10-08), which asks for proper
Dependabot.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

Nothing tells the operator that a dependency has a new release or a fix. A
fix in russh, rustls or tokio reaches podssh only when someone runs
`cargo update` by hand. The actions of the workflows and the build image do
not change either.

## Premise

Read:

- `.github/` holds only `workflows/`: there is no Dependabot configuration.
- Measured with grep on `HEAD`: `Cargo.lock` holds 478 packages, 438 of them
  from crates.io, and no git source.
- The workflows use four actions, each by a major tag:
  `actions/checkout@v5` (`.github/workflows/build.yml` line 30 at `7c70aa7`),
  `actions/upload-artifact@v7` (`.github/workflows/build.yml` line 89 at `1a3e7b6`),
  `actions/download-artifact@v8` (`.github/workflows/release.yml` line 405 at `1a3e7b6`) and
  `ilammy/setup-nasm@v1` (`.github/workflows/release.yml` line 345 at `1a3e7b6`, "uses: ilammy/setup-nasm@v1").
- The build image is a variable in two workflows and in a shell script
  (`.github/workflows/build.yml` line 15 at `19ca632`, `.github/workflows/release.yml` line 23 at `19ca632` and
  `scripts/dev.sh` line 60 at `e1ba5ba`). Dependabot's docker ecosystem reads the `FROM` lines
  of Dockerfiles, not such variables (from GitHub's documentation as known;
  to verify).
- `vendor/tailscale-rs` has its own `Cargo.lock`, and its patches apply to a
  fixed upstream state (`vendor/patches/`). The build resolves the fork's
  dependencies in the root `Cargo.lock`.

## Approach

1. Add .github/dependabot.yml, version 2, with a weekly schedule:
   - `cargo` at the root: one group for minor and patch updates, one pull
     request for each major update, at most 5 open pull requests;
   - `github-actions` at the root: one group;
   - `docker`: the directory that T-206 makes the one source of the build
     image. Do this item after T-206;
   - no entry for `vendor/tailscale-rs`.
2. Each pull request of Dependabot runs the whole CI: the gate, the plant and
   the live check. The no-C steps of the gate (`scripts/gate.sh:154-166`) judge
   each update of a library crate's dependencies.
3. Dependabot alerts and security updates: on since 2026-10-08, turned on
   with `gh api` and the operator's approval (`gh api
   repos/Azathothas/podssh/automated-security-fixes` gives `enabled: true`).
4. An update can need a newer Rust than a declared minimum: the job of T-217
   refuses it.
5. docs/development.md: how an update is judged and merged.

## Decision

A merged pull request of Dependabot makes a commit that names the bot (to
confirm at the first merge). `docs/decisions.md` attributes each commit to
the operator only. Recommendation: the operator applies a judged update as
the operator's own commit (`git cherry-pick`, then close the pull request), so
the rule stays as it is. Accepting the bot as an author lost: it changes a
standing decision, which only the operator can do.

## Prove

```sh
pipx run check-jsonschema --builtin-schema vendor.dependabot .github/dependabot.yml
test "$(gh pr list -R Azathothas/podssh --author app/dependabot --state all --json number --jq length)" -gt 0
```

The first command shows that the file is valid. The second, a week later,
shows that Dependabot opened pull requests, each with a CI run. Planted
defect: write `package-ecosystem: cargoo`; the schema check must fail.

## Correction

2026-10-09: this machine has neither `pipx` nor `check-jsonschema`, and the
work does not install a tool from PyPI on it. The first command runs in CI
instead, where the runner has `pipx`: a step of `.github/workflows/build.yml`
checks `.github/dependabot.yml` against the schema, then a copy with
`package-ecosystem: cargoo`, which must fail. The step itself fails if the
planted copy passes.

The state (partial), 2026-10-09: `.github/dependabot.yml` (cargo, one group
for minor and patch, at most 5 pull requests; the actions, one group; the
three images of `images/`, then under `.github/`, after T-206), the CI step, and the section
"Updates" of `docs/development.md` are written. Next: the step's result in
CI, then Dependabot's first pull requests.

## Done

2026-10-09, in the commit "Dependabot for the crates, the actions and the
pinned images", and closed in the commit "Secret scanning of the history".

- `.github/dependabot.yml`: the crates, weekly, minor and patch updates in
  one group, each major update alone, at most 5 pull requests open; the
  actions, in one group; the images of `images/`, then under `.github/`
  (since T-209 also the scanner's).
- The step "dependabot's configuration is valid" of
  `.github/workflows/build.yml` passed in run 37875200107: "ok -- validation
  done", then "the planted ecosystem failed, as it must".
- Dependabot opened 6 pull requests within minutes, each with a CI run:
  #37 (actions/checkout 5 to 7), #38 (the group of minor and patch updates,
  3 crates), #39 (cipher 0.4.4 to 0.5.2), #40 (blake2 0.10.6 to 0.11.0), #41
  (itertools 0.14.0 to 0.15.0) and #42 (chacha20 0.9.1 to 0.10.2).
  `gh pr list -R Azathothas/podssh --author app/dependabot --state all`
  gives 6. Each is judged and applied as `docs/development.md` ("Updates")
  says.

# T-206: B7: the build image is not pinned to a digest

**Source:** row B7 of the former defects page
(`git show 3ee70dc:docs/defects.md`), severity low.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The gate, CI and the release build in `docker.io/library/rust:1-alpine`. That
tag moves with each release of Rust and of Alpine. Two runs of the same commit
can use two compilers, and a release can differ from the gate run that judged
it. A new toolchain can also turn the gate red on a tree that did not change,
for example with new lints (T-215).

## Premise

Read:

- The reference is written in three places: `.github/workflows/build.yml` line 15 at `e1ba5ba`
  (line 14 says that it must equal the one in `scripts/dev.sh`),
  `.github/workflows/release.yml` line 23 and `scripts/dev.sh` line 60, both at `e1ba5ba`. No check makes
  them equal.
- The release builds aarch64 on an arm64 runner
  (`.github/workflows/release.yml:97-98`). So the pin must be the digest of
  the multi-platform index, not the digest of one platform's image.
- The box uses two more moving tags, `alpine:3.20` and `python:3.12-alpine`
  (`scripts/test_in_box.sh` lines 39-40 at `e1ba5ba`).
- `scripts/gate.sh:117-120` prints the toolchain of each run, so the logs show
  the drift.

## Approach

1. Read the digest of the index:
   `docker buildx imagetools inspect docker.io/library/rust:1-alpine`. Check
   that the index lists linux/amd64 and linux/arm64.
2. Keep the reference in one file: a Dockerfile of one line (proposed:
   .github/build-image/Dockerfile, a `FROM` line with the reference and its
   `@sha256:` digest). The two workflows and `scripts/dev.sh` read it from
   there. The docker ecosystem of T-205 then updates the digest.
3. A check in `scripts/check-repo.py`: the reference has `@sha256:` and 64 hex
   digits, and no workflow or script holds a second literal of the image.
4. Pin the two images of the box the same way.
5. Measure that wsl-toolkit takes a reference with a digest
   (`scripts/dev-wsl.sh:82` passes it to `--image`): `sh scripts/dev.sh images`.
6. Record the pinned toolchain in docs/STATUS.md ("Build, tests, CI"), and
   name the file in docs/development.md.

## Decision

2026-10-09: the three images live in one directory, each in its own
Dockerfile of one `FROM` line: `images/build/Dockerfile`,
`images/box/Dockerfile` and `images/box-proxy/Dockerfile` (under
`.github/` until T-308).
Dependabot's docker ecosystem (T-205) then takes one directory for each.
Lost: .github/build-image/Dockerfile alone, as step 2 proposed, with the
box's two images elsewhere: three places for one kind of fact.

The scripts read the `FROM` line with a small function (`image_of`, in
`scripts/dev.sh` and `scripts/test_in_box.sh`), which drops a CR and refuses
a reference with no digest (exit 78); `PODSSH_BUILD_IMAGE` still overrides
it. The workflows read it in a step of their own. `check-repo.py` skips
comment lines, so the notes that name `rust:1-alpine` as where a fact was
measured stay; a line that runs or pulls an image cannot name it by its tag.

## Prove

```sh
python scripts/check-repo.py               # the image is pinned, in one place
sh scripts/dev.sh images                   # the pinned image runs and prints its rustc
sh scripts/dev.sh check                    # the gate is green in the pinned image
```

Each command exits 0. The release workflow reads the same pin; its build is
checked once, in the run by hand of M9 before the tag (T-251), not before:
a release run takes CI from the work (the operator, 2026-10-08). Planted
defect: write the literal `rust:1-alpine` back into
`.github/workflows/release.yml`; `check-repo.py` must exit 1 and name the
file.

## Done

2026-10-09, in the commit "The build and box images, pinned to digests in
one place".

- The digests of the three multi-platform indexes, read from Docker Hub's
  registry on 2026-10-09: `rust:1-alpine` `sha256:0cce0a5e…` (linux/amd64,
  linux/arm64/v8, ppc64le, riscv64), `alpine:3.20` `sha256:d9e853e8…` and
  `python:3.12-alpine` `sha256:1b668429…` (each with linux/amd64 and
  linux/arm64/v8).
- `.github/workflows/build.yml` and `.github/workflows/release.yml` have no
  `BUILD_IMAGE` literal; a step reads the Dockerfile into `$GITHUB_ENV`.
  `scripts/dev.sh` and `scripts/test_in_box.sh` read their images the same
  way; the help of `dev.sh` and a message of `scripts/ts-derp-prove.sh` name
  the Dockerfile. `.gitattributes` keeps the Dockerfiles LF.
- `scripts/check-repo.py`, check 5: each Dockerfile holds one `FROM` pinned
  to `@sha256:` and 64 hex digits, at least one exists, and no workflow or
  shell script names an image by its tag outside a comment.
- Prove: `python scripts/check-repo.py`: ok, 5 checks. `sh scripts/dev.sh
  images`: exit 0; wsl-toolkit pulled `rust@sha256:0cce0a5e…` and printed
  rustc 1.99.0 (b940084d7 2026-09-28), cargo 1.99.0, musl. `sh scripts/dev.sh check`: green in the pinned image, 13 min 49 s: each build and test step, interop 103 of 103, the man page in groff and mandoc.
  `sh scripts/test_in_box.sh` with the gate's binary of `b082b83`: the box built from the pinned `alpine:3.20`, its proxy in the pinned `python:3.12-alpine`; each property of the probe matched, `podssh doctor --full` 30 ok, `scripts/sandbox-check.sh` 7 ok, 0 FAIL, 1 skip; exit 0.
- Plants, each restored: the literal `docker.io/library/rust:1-alpine`
  appended to `.github/workflows/release.yml`: check 5 failed and named
  that file at the appended line (144), exit 1; the digest removed from the
  build image's Dockerfile: it failed and named that file, exit 1; no
  Dockerfile at all: it failed ("no image is pinned"), exit 1. The reader of
  the scripts, on a file with no digest and on a missing file: exit 1 with a
  message; on a CRLF file: the reference without the CR.
- The release workflow reads the same pin; its build is checked in the run by
  hand of M9 (T-251), as the Prove says.

# T-207: B8: `scripts/dev.sh` has about 600 lines

**Source:** row B8 of the former defects page
(`git show 3ee70dc:docs/defects.md`), severity low; the 500-line rule
(`docs/decisions.md`).
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

`scripts/dev.sh` has 592 lines, more than the 500 that a source file may
have. The size check reads only the Rust files under `crates/`, so the script
grew with no warning, and another script can do the same. Its help also
describes steps of the gate that no longer exist.

## Premise

Measured: `wc -l scripts/dev.sh` gives 592.

Read:

- `scripts/check-repo.py` lines 100-110 at `912acd0` check only the Rust files under `crates/`.
- `scripts/dev.sh` lines 318-329 at `912acd0` define `step`, which nothing calls.
- The help (`scripts/dev.sh` lines 331-366 at `912acd0`) says that the gate builds the default
  members with `CC=/nonexistent`, and the release too (lines 339-342). The
  gate builds the library crates with `CC` and `CXX` set to `/nonexistent`,
  and the release with neither (`scripts/gate.sh:154-166`,
  `scripts/gate.sh:299-301`). The help omits the work record, interop, the man
  page, the C++ plant, and the subcommand `gate` (line 602 at `912acd0`).
- Stale comments, at `912acd0`: `scripts/dev.sh` lines 69-73 ("the default
  build"), lines 397-404 ("links the fork since 4b", "steps 4-5") and line
  462.
- CI parses `scripts/*.sh` with dash (`.github/workflows/build.yml:183-189`);
  `scripts/check-scripts.py:53-57` finds the scripts under `scripts/` at any
  depth.

## Approach

1. Remove the unused `step`.
2. Move the Windows transport into one file that `scripts/dev.sh` sources
   (proposed: scripts/dev-wsl.sh, directly in `scripts/`): the tool settings,
   `EXCLUDES` with its comments, `run_in_image`, the PowerShell bridge, `b64`,
   `preflight`, `wt`, `win_path` and `scratch_file` (lines 48-300 at `22c3b88` and
   352-377). Source it after the self-location (lines 37-46 at `22c3b88`). Keep each
   comment. Invariant: the text of the bridge does not change by one byte;
   compare the old and the new text with `cmp`.
3. Correct the help and the stale comments to the gate as it is
   (`scripts/gate.sh:135-353`).
4. Extend the size check of `scripts/check-repo.py` to the shell and Python
   files under `scripts/`, with a floor (T-223).
5. Drop the sentence on the exception from `docs/decisions.md`, and move it
   to Superseded: this work changes that fact (the operator's ruling of 2026-10-08).
   The decision itself stays.

Pitfalls: keep the new file directly in `scripts/`, so the dash loop of CI
reads it. `.gitattributes` gives it LF. The lock and its trap stay in
`scripts/dev.sh` (lines 540-559 at `22c3b88`).

## Prove

```sh
wc -l scripts/dev.sh scripts/dev-wsl.sh   # each 500 lines or fewer
python scripts/check-repo.py              # the size check now reads scripts/ too
python scripts/check-scripts.py           # both files are LF and parse under dash
sh scripts/dev.sh help                    # the help names the real steps of the gate, and gate
sh scripts/dev.sh check                   # the whole gate through the split script, green
```

Each command exits 0. Planted defect: a copy of a script in `scripts/` with
501 lines; `check-repo.py` must exit 1 and name it.

## Correction

2026-10-09: `wc -l scripts/dev.sh` gave 608, after T-206 and T-246. Like
`step`, the setting `PODSSH_PS_SCRIPT` was set and read nowhere; it went
too.

## Done

2026-10-09, in the commit "scripts/dev.sh in two files, each under 500
lines, and the size check reads the scripts".

- `scripts/dev-wsl.sh` (239 lines), which `scripts/dev.sh` sources after its
  self-location: the tool's settings, `EXCLUDES` and its comments,
  `run_in_image`, the PowerShell bridge, `b64`, the preflight, `wt`,
  `win_path` and `scratch_file`, each with its comments. `cmp` of the
  bridge's text, before and after: the same 1,438 bytes.
- `scripts/dev.sh` (386 lines): `step` and `PODSSH_PS_SCRIPT` removed. The
  help names each subcommand, `gate` too, says what `check` and `plant` run
  now, and prints the gate's steps from `scripts/gate.sh --list`, so that it
  cannot name a step that the gate does not have. The stale comments name
  the library crates, the step `libs` and the gate's one file.
- `scripts/check-repo.py`: the size check reads the shell and Python scripts
  under `scripts/` (28 today), with a floor of 15.
- `docs/decisions.md`: the exception moved to "Superseded". `docs/development.md`
  and the map of `AGENTS.md` name `scripts/dev-wsl.sh`; `docs/STATUS.md`.
- Prove: `wc -l`: 386 and 239. `python scripts/check-repo.py`: exit 0, "265
  Rust files under crates/ and 28 scripts under scripts/ read". `python
  scripts/check-scripts.py`: 14 scripts, LF, and each parses under dash. `sh
  scripts/dev.sh help`: the subcommands, and "The steps of the gate: lint
  libs msrv msrv_ssh msrv_ts record ssh ts release". `sh scripts/dev.sh
  check` through the split script, in 18 min 34 s: each step passed but
  `record`, whose checker found the four citations of `scripts/dev.sh`
  that ran past its new end, before their remap; after it, `sh
  scripts/dev.sh run -- 'sh /work/scripts/gate.sh record'`: green. Interop
  103 of 103. Plant, removed: a script of 501 lines in `scripts/`:
  `check-repo.py` exited 1 and named it.

# T-208: A changelog from the commits, and release notes from it (GitHub #27)

**Source:** GitHub #27 (the operator, 2026-10-08), which asks for automated
changelog generators.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A release has hand-written notes only. Nothing lists the commits since the
previous release, so a change that the notes forget is invisible to a user.

## Premise

Read:

- The job `publish` reads the notes from `docs/releases/`, and fails without
  them (`.github/workflows/release.yml:572-576`).
  No notes file exists yet; T-250 writes the first. The notes drafted for a
  beta that the operator dropped are in git:
  `git show b1b111b:docs/releases/v0.1.0-beta.1.md`.
- `actions/checkout@v5` fetches one commit by default
  (`.github/workflows/release.yml` line 121 at `7c70aa7`), which hides the history from a
  generator.
- Measured: `git rev-list --count HEAD` gives 27, and `git tag -l` gives no
  tag. The subjects are "scope: text" ("podssh ssh: ...", "gate: ...") or
  plain text ("Fix -4/-6, ..."); none is a Conventional Commit.
- `docs/decisions.md` (the documents in ASD-STE100): the documents give the
  current state, not history; git keeps the history.

## Approach

1. Add cliff.toml at the root, for git-cliff (a Rust tool). Parse the
   subjects with the patterns of this repository: `podssh COMMAND:` to
   "Commands"; `gate:`, `Workflows:` and a script's path to "Build and CI";
   `Docs` and `docs:` to "Documents"; `Fix` to "Repairs"; a last group,
   "Other", for the rest. Invariant: no commit is dropped (no `skip`, and the
   commits that are not conventional are kept).
2. In `.github/workflows/release.yml`, the job `publish`: fetch the whole
   history (`fetch-depth: 0`); install a pinned git-cliff; make the list of
   the commits since the previous tag; publish the notes file, then the list,
   as the body of the release.
3. On a run by hand, make the list of the commits since the last tag as an
   artifact, so that it can be read before a tag.
4. Link each "Fixes #N" of a commit to its issue in the list.
5. docs/development.md, "Release builds" (`docs/development.md:671-768`): the
   body is the notes file and the generated list.

No new shell script: each step is a step of the workflow.

## Decision

Recommendation: make the list at release time, into the body of the release
and an artifact, and commit no CHANGELOG.md. A committed changelog copies the
history of git into a document, which `docs/decisions.md` rules out, and a
bot commit to update it breaks the rule that each commit is the operator's
(`docs/decisions.md`). A CHANGELOG.md that a workflow commits lost for these
two reasons.

## Prove

```sh
git cliff --config cliff.toml --unreleased --strip all > /tmp/changes.md
test "$(grep -c '^- ' /tmp/changes.md)" -eq "$(git rev-list --count HEAD)"   # no commit dropped
```

The count test exits 0. The release workflow's artifact is checked once, in
the run by hand of M9 before the tag (T-251), not before: a release run
takes CI from the work (the operator, 2026-10-08). After the first tag, compare with
`git rev-list --count TAG..HEAD` instead. Planted defect: give the
"Documents" parser `skip = true`; the count test must fail.

## Correction

2026-10-09: git-cliff is not installed on this machine, and the work does
not install a new tool here. The Prove's two commands run on a GitHub
runner instead, in `.github/workflows/changelog.yml`, which installs a
pinned git-cliff (2.9.1, which declares Rust 1.85 as the workspace does),
makes the list as an artifact (step 3, without a run of the release
workflow), compares the count with the commits since the last tag, and plants
a skipped group. The plant skips "Other", which is never empty: the
"Documents" group of the Prove can be empty between two tags, and its plant
would then prove nothing. Measured: 83 commits, no tag, no merge; the
groups take 7 (Commands), 4 (Build and CI), 5 (Documents), 1 (Repairs) and
66 (Other).

The state (partial), 2026-10-09: `cliff.toml`, the workflow, the release's
body (the notes file, then the list; `fetch-depth: 0` in the job `publish`)
and the section "Release builds" of `docs/development.md` are written.
Next: the first run of the workflow, by hand.

## Done

2026-10-09, in the commit "The list of the commits, for the body of each
release", and closed in the commit "Secret scanning of the history".

- `cliff.toml`, `.github/workflows/changelog.yml`, the job `publish` of
  `.github/workflows/release.yml` (the whole history; a pinned git-cliff;
  the body is the notes file, then the list) and `docs/development.md`.
- Prove, on a GitHub runner (the Correction): run 37876270327 of
  `changelog.yml` gave "listed 84 of the 84 commits since the first"; the
  planted skip of "Other" listed 17 of the 84, so the count can fail; the
  artifact `changes` holds the list (2949 bytes).
- The list in the body of a release is checked in the run by hand of M9,
  before the tag (T-251).

# T-209: Secret scanning with TruffleHog in CI (GitHub #27)

**Source:** GitHub #27 (the operator, 2026-10-08), which asks for TruffleHog.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The repository is public, with its whole history. Only three shapes of
credentials are checked, and only in the files of the current tree. A key of
another service (GitHub, Cloudflare, a cloud provider) in a commit, or a
credential that a later commit removed, is not found.

## Premise

Read:

- `scripts/check-repo.py:53-66` defines the shapes (a relay token, a Tailscale
  key, a private key block); `scripts/check-repo.py:241-262` scans the tracked
  files outside `vendor/`. It reads no history.
- `docs/decisions.md` (the repository is public): its history was
  replaced by one commit on 2026-10-08, so a scan of the whole history is
  cheap now.
- `.env/` holds the operator's live credentials. git ignores it, and
  AGENTS.md forbids to read or print it.
- TruffleHog prints the raw secret of a finding in its normal output (to
  verify with the pinned version). The CI logs of a public repository are
  public.

## Approach

1. A job `secrets` in `.github/workflows/build.yml`, beside the gate:
   `fetch-depth: 0`, and TruffleHog pinned by digest or by commit SHA.
2. The `git` mode only: the commits of the push or the pull request, and the
   whole history on `main` and on a weekly schedule. Never the `filesystem`
   mode: on a developer's machine it reads `.env/`.
3. JSON output into a file, with `--fail`; read the exit code directly. Then
   print only the detector, the file, the line, the commit, and whether the
   result was verified. Never print the raw fields.
4. Keep `check_secrets` of `scripts/check-repo.py`: it owns the shapes of
   podssh, which TruffleHog does not know (the relay token `ephm1.`).
5. docs/development.md: what to do on a finding. Revoke the credential first,
   because the history is public; then remove it. Never rewrite published
   history (AGENTS.md, section 6).
6. Fail on verified and unknown results; list unverified results as notes.
   The operator can choose to fail on them too.

## Decision

2026-10-09:

1. Its own workflow, `.github/workflows/secrets.yml` (each push to `main`,
   each pull request, each week, and by hand), not a job of
   `.github/workflows/build.yml`: a weekly scan there would run the gate too.
2. The scanner is pinned by the digest of its index, in
   `images/trufflehog/Dockerfile`: the one place of T-206, which
   Dependabot updates and check 5 of `scripts/check-repo.py` checks.
3. Each run scans the whole history, not only the commits of the push: the
   history is short since its rewrite on 2026-10-08.
4. The plant runs in the workflow, before each scan, in a repository of its
   own under the runner's temporary directory: a key that `ssh-keygen` makes
   there (`podssh keygen` would need a build first), scanned with no
   verification and with unverified results. TruffleHog must exit 183, its
   code for results found, and `scripts/secrets-report.py --expect
   PrivateKey` must find the detector. Lost: a plant run once by hand, which
   proves the scan once and not after each update of the image.
5. The scan does not run on this machine: the scanner's container would
   have the working tree, with `.env/`, mounted.
6. The first scan found 9 values that its URI detector could not verify:
   proxy URLs with a made-up user and password, at `proxy.example` or the
   loopback, in tests of the proxy parsers and in the fork. They are listed
   in `.github/secrets-allow.txt`, each by detector, file and line, and the
   commit that added it, with the reason; the same value in another commit
   is a new finding. Lost: no verification for the URI detector, or no scan
   of the tests, which would let a real proxy password through.

## Prove

```sh
test "$(gh run list -R Azathothas/podssh --workflow build.yml -b main -L 1 --json conclusion --jq '.[0].conclusion')" = success
```

The last run on `main`, with the job `secrets`, passed. Planted defect, in a
temporary repository outside the tree: commit a throwaway key that
`podssh keygen` made, run TruffleHog on it in `git` mode with no verification
and with unverified results, and check that it exits non-zero and names the
detector for private keys. Then delete the directory. The key is used nowhere
and never printed.

## Correction

2026-10-09: the scan is a workflow of its own (Decision 1), so the Prove's
command reads its last run on `main`: `--workflow secrets.yml` in place of
`--workflow build.yml`.

The state (partial), 2026-10-09: the workflow, the pinned image,
`scripts/secrets-report.py` (tested on synthetic findings: a verified or
unknown finding exits 1, an unverified one is a note, `--expect` tells a hit
from a miss, a missing file exits 2, and no raw, redacted or extra value is
printed) and the section "Checks" of `docs/development.md` are written.
Next: the first run of the workflow.

## Done

2026-10-09, in the commits "Secret scanning of the history", "The secret
scan reads the scanner's exit code under bash -e" and "The test values that
look like credentials, listed for the secret scan"; closed in the commit
"Advisories, licenses and sources of the dependencies, and the notices".

- `.github/workflows/secrets.yml`, `images/trufflehog/Dockerfile`
  (TruffleHog 3.97.9, by the digest of its index), `scripts/secrets-report.py`,
  `.github/secrets-allow.txt` (9 test values, Decision 6), and the section
  "Checks" of `docs/development.md`.
- The first run failed for a reason of the workflow itself: the runner's
  shell is `bash -e`, so the planted key's exit 183 ended the step before its
  code was read. Repaired with `|| rc=$?`.
- Prove: run 37876982750 of `secrets.yml` on `main`: success. The planted key
  was found ("unverified PrivateKey key:1", "a finding of PrivateKey"); the
  history gave 9 findings, each an allowed test value, and "0 verified or
  unknown". `gh run list --workflow secrets.yml -b main -L 1` gives
  `success`.

# T-210: Build provenance for each release binary

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for provenance of
released binaries; the csshw report in GitHub #24
(`whme/csshw:.github/workflows/release.yml`), read in the report, not
verified here.
**Category:** release
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A downloaded binary carries no proof of its origin. `SHA256SUMS` comes from
the same job as the binaries, so it shows that a download is complete, not who
built it or from which commit. `podssh --version` names no commit, so a tester
cannot tie a binary to its source.

## Premise

Measured: `target/debug/podssh.exe --version` prints `podssh 0.1.0`, exit 0.

Read:

- The jobs `linux` and `windows` build the binaries, and `publish` adds
  `SHA256SUMS` and publishes them (`.github/workflows/release.yml:53-615`).
  The workflow has `contents: read` (`:45-46`); `publish` adds
  `contents: write` (`:469-470`).
- The KTM tester could not tell from an artifact which commit made it, and
  moved the checkout one commit ahead (the KTM report, section 1a; read in
  the report).
- `crates/podssh-cli/src/man/facts/tests.rs:74-95`: the drift test of the manual
  counts each quoted upper-case name with `_` in the sources as a variable
  (except `CARGO_` names).

## Approach

1. In the jobs `linux` and `windows`, after the checks of the binary, attest
   each binary with `actions/attest-build-provenance`, pinned by commit SHA,
   for a tag `v*` only. Give these jobs `id-token: write` and
   `attestations: write`. A run by hand makes no attestation.
2. Tell the user how to check, in `README.md` (`:58-59`) and in the
   release notes: `gh attestation verify FILE --repo Azathothas/podssh`.
3. Let `podssh --version` name the commit: the workflows set a variable at
   compile time (`option_env!`, no build script, no `git` call); a local build
   prints the version alone. In the same commit, add the name to the facts of
   the manual, or teach the drift test about names read at compile time.
4. One paragraph in the release notes on the Windows binary, which is not
   signed (SmartScreen warns about it).
5. Do this before T-250, so that the one release is attested.

## Decision

2026-10-30, a call of the research (the operator may change it): attest in the job `publish`, once,
for all the binaries (`subject-path: dist/podssh-*`), not in each of `linux` and `windows` as item 1
says. It satisfies the Prove, makes one attestation that names every subject, and keeps
`id-token: write` out of the jobs that run the project's build scripts. The job `publish` builds no
crate: `cargo-about` and `git-cliff` come as release binaries
(`.github/workflows/release.yml` line 414 at `1a3e7b6`, "tool: cargo-about@0.9.2"). Lost: attesting in each build
job, with its own `id-token: write` where the build scripts of every dependency run, and one
attestation for each binary. The attest step runs on a tag only (`if: startsWith(github.ref,
'refs/tags/v')`), as item 1 says, so that a run by hand makes none; and it comes before `gh release
create`, so that a failure stops before anything is published. The action is `actions/attest`, not
`actions/attest-build-provenance` (see the Correction).

2026-10-30, the calls of the session that wrote it:

- The tag's own run makes the proofs. A session whose git may not push a tag releases by a run by
  hand with the input `publish`; that run now only makes the tag (the job `tag`) and starts the
  workflow by hand on the tag (`gh workflow run release.yml --ref TAG`), as a tag that the job's
  token pushes starts no workflow, and a dispatch does (GitHub's documentation of `GITHUB_TOKEN`).
  The run on the tag builds, attests and publishes, so that each proof names the workflow at the
  tag. Lost: the proofs in the run on `main`, whose identity names `refs/heads/main`, which T-211's
  item 3 forbids; and a personal token that pushes the tag, a long-term credential in the
  repository's secrets.
- The attestation's bundle is published beside the files, as `provenance.sigstore.json`, for a
  check with `--bundle` (the Correction left it to this entry).
- `actions/attest` and `sigstore/cosign-installer` are pinned by commit, as item 1 asks; the
  other actions keep their major tags, as the workflow does.
- The steps run first in a trial workflow by hand on a throwaway file (`sigstore-trial.yml`), as
  T-218 tried each target: a first failure at a tag would leave a tag with no release, and a tag
  never moves.

## Prove

```sh
gh release download TAG -R Azathothas/podssh -p 'podssh-*'
gh attestation verify podssh-x86_64-unknown-linux-musl --repo Azathothas/podssh
gh attestation verify podssh-x86_64-pc-windows-msvc.exe --repo Azathothas/podssh
./podssh-x86_64-unknown-linux-musl --version     # names the commit of the tag
```

Each command exits 0, and each verification names the release workflow and
the commit of the tag. Planted defect: change one byte of a copy of a binary;
`gh attestation verify` must fail.

## Correction

2026-10-30, the research of that day (Read in the sources named; nothing was run, and the public
page for each action was read through a mirror of GitHub's API, so check each commit below against
github.com when the workflow is written). The Approach names `actions/attest-build-provenance`.

- `actions/attest-build-provenance` is a wrapper now: its README (v4.2.2) says "As of version 4,
  `actions/attest-build-provenance` is simply a wrapper on top of `actions/attest`", and that new
  implementations should use `actions/attest`. GitHub's own page shows `actions/attest@v4`. Use
  `actions/attest` v4.2.2 (commit `1e69f48acb82d1966a394da916b4c1698aa569d6`), pinned by that commit,
  as item 1 asks. (The wrapper is at commit `4d101475d8b20a2381f78447822ac1eab6504dd8`.)
- Permissions for a binary (GitHub documentation): `id-token: write`, `contents: read` and
  `attestations: write`. `publish` has `contents: write` today (`.github/workflows/release.yml:470`
  says "contents: write"), which includes the read. The README of `actions/attest` also lists
  `artifact-metadata: write`, "necessary to create the artifact storage record"; that record needs
  `push-to-registry: true`, which is for images, so a file subject does not need it (Inferred): add
  it only if the first run warns.
- Several files: `subject-path` "May contain a glob pattern or list of paths (total subject count
  cannot exceed 1024)", and one attestation then names all the subjects; `subject-checksums` takes a
  checksums file; the output `bundle-path` is the Sigstore bundle as JSON. In a public repository
  the attestation is free for every plan, and it is signed with the public-good Sigstore.
- To check (https://cli.github.com/manual/gh_attestation_verify): `--repo` or `--owner` is needed;
  the default predicate is `https://slsa.dev/provenance/v1`; stricter, `--signer-workflow
  Azathothas/podssh/.github/workflows/release.yml`, `--source-ref refs/tags/vX`, `--source-digest SHA`
  and `--deny-self-hosted-runners`. Item 2 and the Prove should name the first two, so that a
  verification "names the release workflow and the commit of the tag". Offline: `gh attestation
  download FILE -R OWNER/REPO` writes `sha256-<digest>.jsonl`; then `--bundle FILE.jsonl
  --custom-trusted-root trusted_root.jsonl` (the root from `gh attestation trusted-root`). With
  `--bundle` the repository name is checked against the certificate only, so a renamed repository is
  not caught. The job can copy `bundle-path` into `dist/` for the user (this entry decides).
- `actions/download-artifact@v8`, already in the job (`.github/workflows/release.yml` line 405 at `1a3e7b6`), fails by
  default when the digest of a file differs from what the build job uploaded ("Hash mismatches will
  now error by default", v8.0.0): that is a gain for the chain of custody here, with no change.
- Optional, and the operator's call: immutable releases (a setting of the repository) lock the tag
  and the assets and add a release attestation that `gh release verify TAG` checks. With rolling
  betas, a tag becomes permanent at its first release.
- Commits that the research found for the actions of this workflow, for the day it pins them
  (Read at the release API of each repository): `actions/checkout` v7.0.1
  `3d3c42e5aac5ba805825da76410c181273ba90b1`, `actions/upload-artifact` v7.0.2
  `cf430e030ddbb5b0abf93d22962f4752f3646cd9`, `actions/download-artifact` v8.0.2
  `9000827ccba6bdab643e8b6fd33ac0654aef8333`, `taiki-e/install-action` v2.88.0
  `86f7a0ffb25f40114606501a311ebcfaf882ea32` (it knows `git-cliff@2.9.1` and `cargo-about@0.9.2`),
  `ilammy/setup-nasm` v1.5.2 `72793074d3c8cdda771dba85f6deafe00623038b`. The workflow pins these by
  major tag today; whether to pin them by commit is a choice of this entry's session. All of them but
  `setup-nasm` run on Node 24 (Node 20 left the runners on 2026-09-23); `setup-nasm` declares Node 20
  and its issues 45 and 46 ask for Node 24, and the Windows job of `build.yml` still passed with it
  on 2026-10-13 (run 38435776219, read through the runs API).
- The snippet of the step, as the research drafted it (not run): `uses:
  actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6` with `id: attest`, `with: subject-path:
  dist/podssh-*`, after the step "checksums" and before `gh release create`.

## Done

2026-10-30, partial. Item 3: `podssh --version` names the commit of a release build. The
workflow gives the commit to the compiler as `PODSSH_BUILD_COMMIT`, read with `option_env!` in
`crates/podssh-cli/src/version.rs` (no build script, no `git` call), and `--version` prints
`podssh VERSION (COMMIT)`, as rustc names its own; doctor's header carries the same line. A local
build names none and prints `podssh VERSION` as before, and a value that is not a hex digest of 7
to 64 characters is no commit. The drift test of the manual skips a name that the compiler reads
(`env!`, `option_env!`), which is no variable of a run; the help of `-V` says that a release build
names its commit.

- Here: with `PODSSH_BUILD_COMMIT=$(git rev-parse HEAD)`, `cargo build` built again (cargo
  tracks the variable) and `--version` printed `podssh 1.0.0-beta.1 (224ccd272f7c...)`, doctor's
  second line the same with `, linux x86_64`; without it, `podssh 1.0.0-beta.1`.
- `cargo test -p podssh-cli --lib`: 372 passed; the integration tests `doctor`, `man_page`,
  `tree`, `plants`, `error_program` and `upgrade` passed (the upgrade and doctor read only the
  prefix `podssh `). clippy `-D warnings` and rustfmt clean.
- Planted: any value taken as a commit, and the test of the digest failed; the compile-time
  names read as variables, and both tests of the drift reader failed (`PODSSH_BUILD_COMMIT`
  "read but not in ENVIRONMENT").

The workflow's part (2026-10-30): `release.yml` gives `PODSSH_BUILD_COMMIT: ${{ github.sha }}`
to each build (a container with `-e`), the linux job requires `podssh VERSION (COMMIT)`, and
`scripts/release-short.sh` requires the commit where the variable names it, and else takes a
version with or without one. Here, on a build with the commit and one without: the five cases
(no commit and none named; the same commit named; a commit and none named; planted, no commit
where one is named, and another commit named) gave ok, ok, ok, fail, fail. The job `publish`
attests `dist/podssh-*` on a tag (`actions/attest` v4.2.2, pinned by commit) and publishes the
bundle as `provenance.sigstore.json`; the README tells how to check it (`gh attestation verify
--signer-workflow ... --source-ref refs/tags/TAG`) and that the Windows binaries are not signed
(item 4). actionlint clean.

- The trial (`sigstore-trial.yml`, run 41091530130): `actions/attest` attested a throwaway file
  and gave its bundle; `gh attestation verify` with the signer workflow and the ref passed, with
  the API and with `--bundle`, and failed for a changed copy and for another ref. So `publish` now
  checks each binary the same way after the attestation, before anything is published.
- The dry run at `758c691` (run 41091534313): each of the seven builds required `podssh VERSION
  (COMMIT)` and passed; the job `tag` was skipped, and `publish` passed with no proof, as a run
  on a branch makes none.

The Prove at the tag (2026-10-31). This host's `gh` has no valid token and no cosign, so
`.github/workflows/release-proofs.yml` runs it on a fresh runner (`docs/development.md`).

- `v1.0.0-beta.2` is published at `f7f97a5` (the tag's run 41147977814), which attested and
  checked each binary before `gh release create`.
- The proofs' run 41149070555, on the published files: `gh attestation verify` of each of the
  eight binaries, the Windows ones among them, with `--signer-workflow
  Azathothas/podssh/.github/workflows/release.yml`, `--source-ref refs/tags/v1.0.0-beta.2`,
  `--source-digest f7f97a5...` and `--deny-self-hosted-runners`, through the API and with
  `provenance.sigstore.json`: each passed. Planted, a copy of the x86_64 binary with one byte
  more: it failed both ways. The published x86_64 binary printed `podssh 1.0.0-beta.2
  (f7f97a58c5bc4940a886f7bc64ea3976798d0b7b)`.
- Here, on its public URL: its line of `SHA256SUMS` checks, it is static-pie, and `--version`
  names the same commit.


# T-211: Signed checksums for each release

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for provenance of
released binaries (checksums).
**Category:** release
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`SHA256SUMS` is not signed. A person who can replace a binary on the release
page can replace the sums too. A user cannot check that the sums come from
the release workflow of podssh.

## Premise

Read:

- `.github/workflows/release.yml:490-495` writes `SHA256SUMS` with
  `sha256sum`, and the job published it with the binaries (lines 370-382 at
  `cdf9308`). No signature was published.
- The notes drafted for the dropped beta told the user that `SHA256SUMS`
  holds the sums (`git show b1b111b:docs/releases/v0.1.0-beta.1.md`, line 81 at `b1b111b`). `README.md:58-59` gives no step to check a download.
- AGENTS.md, section 4: a private key is a credential. The repository has no
  signing key today.

## Approach

1. In the job `publish`, after the sums: sign `SHA256SUMS` with the keyless
   signing of Sigstore (`cosign sign-blob` with a bundle; cosign installed by
   an action pinned by commit SHA) and `id-token: write`. Publish the bundle
   with the release.
2. Verify in the same job, before the release is published, with
   `cosign verify-blob`. Run the check once on a changed copy too, so that it
   is seen to fail.
3. The identity: the release workflow at a tag ref (`refs/tags/v`), never a
   branch, so that a run by hand on `main` cannot make a valid signature.
4. Tell the user how to check, in `README.md` and the release notes: first
   `sha256sum -c`, then `cosign verify-blob` with the identity and the issuer.
5. With T-210: the two proofs name the same commit; the notes say so.

## Decision

Recommendation: the keyless signing of Sigstore. No long-term key exists, so
no key can leak or need rotation, and the signature names the workflow and
the tag. minisign lost: its private key would be a long-term credential in
the secrets of the repository, although its check works offline with one
small tool. GPG lost for the same reason, and for its weight.

2026-10-30: the signature is made in the run on the tag, as T-210's Decision of that day says, so
that its identity is `https://github.com/Azathothas/podssh/.github/workflows/release.yml@refs/tags/TAG`
and a run by hand on `main` signs nothing. The README gives the exact identity of a tag, not the
regexp: a user checks one release.

## Prove

```sh
gh release download TAG -R Azathothas/podssh -p 'SHA256SUMS*' -p 'podssh-x86_64-unknown-linux-musl'
sha256sum -c SHA256SUMS --ignore-missing
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Azathothas/podssh/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
```

Each command exits 0. Planted defect: change one hex digit in a copy of
`SHA256SUMS`; `cosign verify-blob` must fail.

## Correction

2026-10-30: the Premise's "`README.md:58-59` gives no step to check a
download" no longer holds: the README's first step now checks a download of
a beta against `SHA256SUMS` (T-309). The signatures of this entry are still
missing; that step gains their check when they exist.

2026-10-30, the research of that day (Read in the sources named; nothing was run). It adds to the
Approach, and disproves no Premise.

- The tool. cosign v3.1.4 is the latest (2026-10-20); v2.6.5 is still released.
  `sigstore/cosign-installer` v4.1.2 (commit `6f9f17788090df1f26f669e9d70d6ae9567deba6`, 2026-05-07)
  defaults to cosign v3.0.6, verifies what it installs, and accepts any `cosign-release`; pin one
  (v3.1.4 is the draft's). The commit was read through a mirror of GitHub's API: check it at github.com
  when the workflow is written.
- The flags (cosign's documents at v3.1.4, v3.0.6 and v2.6.5). `sign-blob --bundle FILE` is required in
  v3 ("moved from optional to required"); `--new-bundle-format` is on by default in v3.0.x and a
  deprecated, hidden flag in v3.1.4: do not pass it with v3 (it is needed only with v2.6.x). `--yes`
  skips the prompts, and CI needs it. The keyless signing takes the job's own OIDC token, so the job
  needs `id-token: write`; give `publish` that and `attestations: write` for T-210, beside
  `contents: write` (`.github/workflows/release.yml:470` says "contents: write"). The convention for
  the bundle's name is `*.sigstore.json` (https://docs.sigstore.dev/cosign/signing/signing_with_blobs/).
- The identity. The certificate's subject alternative name is `https://github.com/{job_workflow_ref}`
  (https://github.com/sigstore/fulcio/blob/main/docs/oidc.md), so for a tag
  `https://github.com/Azathothas/podssh/.github/workflows/release.yml@refs/tags/v1.0.0-beta.1`; the
  issuer is `https://token.actions.githubusercontent.com`. `verify-blob` needs `--bundle`, one of
  `--certificate-identity` or `--certificate-identity-regexp` (Go's RE2), and one of
  `--certificate-oidc-issuer` or its regexp; `--trusted-root` is for a check offline. A beta tag has a
  suffix, so a regexp for users must allow it, for example
  `@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`; the Prove's regexp ends at `refs/tags/v`
  and needs no change.
- The order in `publish`: checksums, attest (T-210), sign and verify, then `gh release create`, so
  that a failure stops before anything is published. In the step, verify at once with the exact
  identity (item 2), and plant two failures that must both fail: a changed copy of `SHA256SUMS`
  (`sed 's/^./0/'`), and the identity of a branch (`@refs/heads/main`), which item 3 asks for. The
  step runs on a tag only, or a run by hand would sign a ref that is no tag. Copy the bundle of T-210
  into `dist/` for the user, so that the files and the proofs name one commit and one tag.
- What the user types (README and the notes, tags only): `gh attestation verify
  podssh-x86_64-unknown-linux-musl --repo Azathothas/podssh --signer-workflow
  Azathothas/podssh/.github/workflows/release.yml --source-ref refs/tags/v1.0.0-beta.1`, then
  `sha256sum -c --ignore-missing SHA256SUMS`, then `cosign verify-blob --bundle
  SHA256SUMS.sigstore.json` with the identity regexp and the issuer above.
- Cosign v3 writes the new protobuf bundle and uses Rekor v2 and the signing configuration by default
  (https://blog.sigstore.dev/cosign-3-0-available/, Read). Which verifier versions can check it was
  not tested: a user with cosign 2.x may need `--new-bundle-format` or an upgrade. Say "cosign 3.x" in
  the notes until a test says more; the first run of this entry tests it with cosign 2.6.5 if it can.
- Open: whether `actions/attest` needs `artifact-metadata: write` for file subjects (T-210's
  Correction reads that it does not); and whether to switch on immutable releases, the operator's call.

## Done

2026-10-30, partial. The job `publish` of `release.yml`, on a tag only: after the sums, cosign
v3.1.4 (installed by `sigstore/cosign-installer` v4.1.2, pinned by commit) signs `SHA256SUMS`
with Sigstore's keyless signing and the job's token (`cosign sign-blob --yes --bundle
SHA256SUMS.sigstore.json`), then checks it with the identity of the workflow at the tag, and
fails unless a copy with one hex digit changed and the identity of `refs/heads/main` are both
refused; all before `gh release create`, which publishes the bundle with the files. The README
gives the check (`cosign verify-blob` with the identity and the issuer), after `sha256sum -c`;
`docs/development.md` tells the release's steps. actionlint clean.

- The trial (`sigstore-trial.yml`, run 41091530130), the same steps on a throwaway file with
  this branch's identity: cosign v3.1.4 signed and "Verified OK"; a copy with one hex digit
  changed failed ("invalid signature when validating ASN.1 encoded signature"); the identity of
  another ref failed ("expected SAN value ...@refs/tags/v0.0.0-none, got ...@refs/heads/main").
  cosign 2.6.5 checked the bundle of cosign 3, with no flag and with `--new-bundle-format`: the
  notes say both.

The Prove at the tag (2026-10-31), in the proofs' run 41149070555 on the published files of
`v1.0.0-beta.2`.

- `sha256sum -c SHA256SUMS`: each of the eight binaries OK.
- `cosign verify-blob` with the identity
  `https://github.com/Azathothas/podssh/.github/workflows/release.yml@refs/tags/v1.0.0-beta.2`
  and GitHub's issuer: "Verified OK" with cosign 3.1.4 and with 2.6.5. This entry's regular
  expression form: "Verified OK".
- Planted, a copy of `SHA256SUMS` with one hex digit changed: it failed. The identity of
  `refs/heads/main`: it failed.


# T-212: Parallel CI, with the gate as the one source

**Source:** GitHub #27 (the operator, 2026-10-08), which asks for parallel CI.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

CI runs the whole gate in one job, one step after the other: the library
crates, the work record, the SSH client and the CLI, the Tailscale tests, the
static release, interop and the man page; then the plant and the live check
of the relay. A failure late in that list shows only after each earlier step,
and the job takes the sum of all the steps.

## Premise

Read:

- `.github/workflows/build.yml` lines 16-128 at `dacbf4a`: one job, `gate`,
  with a limit of 45 min. The gate is one `docker run`; the plant and the
  live check follow it.
- `.github/workflows/build.yml:3-7`: CI implements nothing of the gate again.
- `scripts/gate.sh` lines 5-6 at `dacbf4a`: the gate takes no argument. Its
  steps are at lines 80-184 there.
- `scripts/gate.sh:48-59`: one cargo job for each 3 GiB of free memory.
- AGENTS.md, section 4: on the operator's machine, one build at a time
  (`scripts/dev.sh:376-395` holds a lock).

Not measured: the wall time of a CI run. Measure it with `gh run list` before
the change.

## Approach

1. `scripts/gate.sh` takes optional step names: `libs`, `record`, `ssh`, `ts`
   and `release` (the static build, the check of the artefact, interop and the
   man page, which share one binary). With no name, it runs each step in
   order, as now; `--list` prints the names. Each step keeps `run`
   (`scripts/gate.sh:64-78`) and its rule for exit codes.
2. `.github/workflows/build.yml`: a matrix over the step names, each job
   `docker run ... sh scripts/gate.sh STEP`; the jobs `checks` (the
   repository checks and the live check) and `plant` run beside it. A last
   job, `all`, needs each job, and is the one required status.
3. A drift check in CI: the matrix equals the output of `--list`, so that a
   new step cannot miss CI.
4. Caches: the cargo registry (mounted into the container) and `target/`,
   with a key from the build image (T-206), the step and the hash of
   `Cargo.lock`. No cache for `ts` if it passes the size limit of the cache.
5. The jobs of T-213 to T-217 join this workflow as parallel jobs.
6. Record the wall time before and after in docs/STATUS.md; update the gate
   in docs/development.md.

Pitfall: `sh scripts/dev.sh check` stays sequential under its lock. Parallel
runs are for CI runners only.

## Decision

Recommendation: a matrix of the gate's own steps, so that CI runs exactly
what a developer runs. Jobs with their own cargo commands lost: they copy the
gate, and a copy drifts (`.github/workflows/build.yml:3-7`).

2026-10-09. The matrix: a first job, `plan`, reads the build image and `sh
scripts/gate.sh --list`, and the job `gate` takes its matrix from that list.
CI has no list of its own, so it cannot drift from the gate. The drift check
of step 3 is therefore on the gate's one list: `python
scripts/check-scripts.py` fails when a function `step_NAME` is not in
`STEPS`, or a name in `STEPS` has no function, and two planted copies of the
gate (one of each) must fail it at each run. A matrix written in the
workflow, with a check that it equals `--list`, lost: it is a second copy,
kept equal by a check, where one copy needs none.

The caches of step 4: none. With no cache, a run takes 6 min 10 s from start
to end, against 10 to 15.5 min before; the longest job is `release` (5 min
52 s: the static build, interop and the man page). A cache of each step's
`target/` would have to share the 10 GB of the repository's caches between
seven steps and each branch of a pull request, and a restore that misses
costs its download. Caches lost while the run is this short; a slow run
brings the question back. The downloads of crates are short: the job
`record` takes 29 s, its downloads included.

`all` needs each job, and fails when one did not pass, also when one was
skipped or cancelled. `main` has no protection today; requiring `all` there
is the operator's choice (`TODO/PROGRESS.md`, "Operator actions").

## Prove

```sh
sh scripts/dev.sh run -- 'sh scripts/gate.sh --list'    # the step names, in the build image
gh run list -R Azathothas/podssh --workflow build.yml -L 1 --json conclusion,createdAt,updatedAt
```

The list equals the matrix, and the last run passed in less wall time than
before. Planted defect: remove `ts` from the matrix; the drift check must
fail.

## Correction

2026-10-09: since `cc386ce`, `.github/workflows/build.yml` also has the job
`windows` (T-214). Measured before the change, with `gh run list`: the last
12 runs of `build` on `main`, from `a9c9c2f` to `cc386ce`, took 10 min 3 s
to 15 min 27 s from start to end; 7 of them took more than 14 min. The
matrix comes from `--list` (Decision), so the plant of the
Prove (`ts` removed from the matrix) has no matrix to remove it from; its
two plants are in `scripts/check-scripts.py`.

## Done

2026-10-09, in the commit "CI runs each step of the gate in a job of its
own, at the same time".

- `scripts/gate.sh`: the steps `lint`, `libs`, `msrv`, `record`, `ssh`, `ts`
  and `release`, each a function, in `STEPS`. With no argument, each step,
  in order; with names, those, in the order given; `--list` prints them; a
  name that is not a step exits 64.
- `.github/workflows/build.yml`: the jobs `plan` (the image and the list),
  `gate` (a matrix over the list, `fail-fast: false`; the job `release`
  uploads the static binary), `plant`, `checks` (the repository checks, the
  configuration of Dependabot, the scripts, the live relay check), `windows`
  and `all`.
- `scripts/check-scripts.py`: the check of the steps, and its two plants at
  each run.
- `docs/development.md`: the steps, the one-step run in the container, and
  the jobs of CI.
- Prove: `sh scripts/dev.sh run -- 'sh scripts/gate.sh --list'`: the seven
  names, exit 0. `sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh
  record'`: that step alone, green; `nosuch`: exit 64. `sh scripts/dev.sh
  check` with the new gate: green in 14 min 44 s, each step, interop 103 of
  103. CI run 37883856054, dispatched on a branch before the commit: each
  job passed, 6 min 10 s from start to end (`release` 5 min 52 s, `windows`
  5 min 31 s, `ts` 4 min 33 s, `ssh` 2 min 56 s, `lint` 2 min 39 s, `libs`
  1 min 57 s, `msrv` 1 min 8 s, `plant` 1 min, `record` 29 s). Plants: a
  function `step_extra` added to the gate: `check-scripts.py` exits 1 and
  names it; restored, exit 0.

# T-213: CI runs the box like the target sandbox

**Source:** GitHub #27 (the operator, 2026-10-08), which asks for a proper CI
test in a box replica.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** blocked

## Problem

The box like the target sandbox runs only by hand, on the operator's Podman
machine; its last record is for the binary of `aa9cfaa`. A change that breaks
podssh in the sandbox's profile (no DNS, no way out but a CONNECT proxy,
`bind` and UDP refused, no pty, no user entry) can reach `main`, and no run
sees it.

## Premise

Read:

- `docs/STATUS.md:251-265`: the box, measured by hand on 2026-10-08.
- `scripts/test_in_box.sh:192-195`: the box runs `probe.sh`, then
  `sandbox-check.sh` (or, with `BOX_RUN=tt`, the session of T-004), and the
  script exits with the code of the second.
  `scripts/sandbox-check.sh:85-242` prints the exit code of each step and does
  not fail on it (T-006). So today the box exits 0 when podssh fails in it.
- `scripts/box/probe.sh:122-127` exits 1 when the box differs from the sandbox
  in a required property (17 properties, `docs/STATUS.md:258`).
- The box needs a static binary; CI uploads one
  (`.github/workflows/build.yml:88-93`).
- The box uses `--disable-dns` (`scripts/test_in_box.sh:112`) and a mask on
  `/dev/pts` (`scripts/test_in_box.sh:180`). Nobody measured the Podman of a
  GitHub runner with them.
- The box reaches the live relay and `github.com` through its proxy.

## Approach

1. T-006 first: `scripts/sandbox-check.sh` must exit non-zero when a step
   fails.
2. A job `box` in `.github/workflows/build.yml`: it needs the job that builds
   the static binary, and downloads it; it prints `podman version` and fails
   when there is no Podman; it runs `sh scripts/test_in_box.sh` with the
   binary and a limit of 45 min; it keeps the log as an artifact.
3. A faithful box or no result: the job fails unless the probe printed 17
   `match` lines. Count them in the saved log, and read each exit code
   directly.
4. Pin the images of the box with the build image (T-206).
5. Credentials: the box mints a token and never prints it
   (`scripts/sandbox-check.sh:2-4`). Before the job is required, scan its
   first log with the token pattern of `scripts/check-repo.py:57`.
6. docs/STATUS.md (the box section) cites the CI run; docs/development.md says
   that CI runs the box.

Pitfall: the live path can drop a session (179 of 180 short sessions,
`docs/STATUS.md:288`). Run a failure again by hand and record it. Never retry
inside the job.

## Decision

Recommendation: the job is required. The box measures the properties of M3,
and a silent break in a sandbox costs more than a second run. A job that only
informs lost: a check that cannot fail the run is not a check.

## Prove

```sh
gh run download RUN_ID -R Azathothas/podssh -n box-log      # the log of the job box
test "$(grep -c '^match ' box.log)" -eq 17                  # the box was faithful
```

The run passed, with the job `box`, and its log has 17 `match` lines.
Planted defect: run the job by hand with the seccomp option removed (an input
of `workflow_dispatch`); the probe must exit 1, as in `docs/STATUS.md:259`,
and the job must fail.

## Blocker

The operator: on hold since 2026-10-09 (`docs/decisions.md`, "Entries on
hold"). A session skips this entry until the operator lifts the hold.

## Correction

2026-10-08, counted in the probe of `HEAD` and in the log of the box: the
probe had 16 required properties, not 17, until the commit "The box has the
sandbox's dead /dev/tty; T-005 measured there". That commit added the 17th
(`/dev/tty`), so the count of 17 holds from then on. Since that commit, the
step "a prompt with nobody to answer it" fails the run of
`scripts/sandbox-check.sh`; since T-006, each step does. The dead
tty needs Python 3 and `setsid` on the Podman host (`scripts/box/deadtty.py`),
so the job of this entry must have both; nobody measured a runner for them.

# T-214: CI on Windows

**Source:** the triage of GitHub #27 (2026-10-08). Windows is a released
platform (`.github/workflows/release.yml:323-410`).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

No CI run executes the tests of podssh on Windows. The release workflow
builds the Windows binary only for a tag or by hand, and runs no test. The
code for Windows only (the console, prompts through `CONIN$`, the branches of
the token cache that are not Unix) is measured only on the operator's
machine.

## Premise

Read:

- `.github/workflows/build.yml` lines 17-19 at `e892b0f`: one job, on `ubuntu-latest`.
- `.github/workflows/release.yml:323-410`: the Windows job installs NASM
  (line 76), builds, and checks for C runtime DLLs (lines 86-101); it runs no
  test.
- `docs/STATUS.md` line 230 at `9966ed4`: the default tests pass on Windows,
  run by hand.
  `docs/STATUS.md:98`: `scripts/interop-conpty.py` passes 14 of 14 against a
  Tailscale SSH server, by hand.
- `scripts/interop-conpty.py:219-275` needs a server with a POSIX shell,
  `stty`, `vi`, `less`, `top`, `seq`, `sed` and `/tmp`.
- The code for Windows: `crates/podssh-ssh/src/terminal/windows.rs`,
  `crates/podssh-ssh/src/prompt.rs:97`, and the `cfg(not(unix))` branches of
  `crates/podssh-relay/src/cache.rs:330-447`.

## Approach

1. A job `windows` on `windows-2025` (pinned, not `windows-latest`):
   checkout, NASM as in the release, `cargo test --locked --no-fail-fast` with
   `CARGO_BUILD_JOBS=4`, and `python scripts/check-repo.py`.
2. An SSH server on the runner for `scripts/interop-conpty.py`, on
   127.0.0.1, with a throwaway key that `podssh keygen` makes and the job
   deletes (see Decision). Run the script with `--direct`; 14 of 14 must pass.
3. With T-199: score the output with the Windows part of the baseline.
4. The plant: a podssh that does not restore the mode of the console must
   fail the three restore checks (as measured by hand, `docs/STATUS.md:98`).
   Run it once in CI, and record it.
5. docs/STATUS.md cites the CI run for the rows of Windows;
   docs/development.md names the job.

## Decision

The server for the console checks. Recommendation: the OpenSSH server of
MSYS2, if the runner image has MSYS2 (to verify), with vim, less and procps
(for `top`) from its package manager: one POSIX environment with each program
that the script uses. The OpenSSH server of Windows lost: it needs a POSIX
shell as its default shell, and it puts a second pseudo console between the
script and the shell. Checks by hand only lost: the restore checks guard a
defect of Windows that no Linux test reaches.

Step 3 (2026-10-09): T-199 brings the scorer and the baseline, and it is a
`backlog` entry, after M8; this entry is `none` work. So T-199 adds the ids
of `scripts/interop-conpty.py` to its baseline and scores this job's output.
Until then, `scripts/interop-conpty-msys2.py` scores its own run: each of the
14 checks must print `ok` (a deleted check fails the count), and with the
plant exactly the three restore checks must fail. Keeping this entry
`partial` until T-199 lost: the job and its plant run at each push, and
nothing of this entry would be left to do but the step that T-199 owns.

## Prove

```sh
cargo test --locked --no-fail-fast       # in the job windows: each default test passes
python scripts/interop-conpty.py target/debug/podssh.exe podtest@127.0.0.1 --direct -p 2222 -i KEY -o StrictHostKeyChecking=accept-new
```

The tests pass, and the console script prints 14 `ok` lines and exits 0. The
plant of step 4 must fail the three restore checks.

## Correction

2026-10-09: the job is a second job of `.github/workflows/build.yml`, beside
the gate, so that each push and each pull request runs it. The release's
Windows job still runs on `windows-latest`; this one is pinned to
`windows-2025`, as step 1 says.

The server of step 2 is in a script, `scripts/interop-conpty-msys2.py`,
which the job and a developer with MSYS2 run the same way. Its port is a
free one of 127.0.0.1, not 2222, so that two runs on one machine do not
collide. `-o UserKnownHostsFile` keeps the host key in the run's directory.
The image `windows-2025` has MSYS2 at `C:\msys64`, not on `PATH` (its
readme, and the run).

## Done

2026-10-09, in the commits "Each repository check has a floor, and fails on
an empty tree" (the job, step 1) and "CI runs the console checks on Windows,
against MSYS2's sshd" (steps 2, 4 and 5).

- `.github/workflows/build.yml`: the job `windows` on `windows-2025`: NASM,
  the default tests, `python scripts/check-repo.py`, the console checks
  against MSYS2's sshd, and the same with the plant.
- `scripts/interop-conpty-msys2.py`: installs openssh, vim, less and
  procps-ng with pacman (`--install`), makes a user key with `podssh keygen`
  and a host key, starts MSYS2's sshd on a free port of 127.0.0.1 for one
  run, runs `scripts/interop-conpty.py` with `--direct`, stops the server
  and deletes the keys. `--plant` builds a podssh whose restore of the
  console finds nothing to restore, runs the checks with it, then puts the
  source back and builds again.
- `docs/development.md`: the job and the script. `docs/STATUS.md`: the rows
  of Windows cite the CI run.
- Step 3 goes to T-199 (Decision).
- Prove, CI run 37882386744: `python scripts/interop-conpty-msys2.py --install
  target/debug/podssh.exe`: 14 of 14 (33 s, pacman included); `--plant`: the
  three restore checks failed and no other (46 s, both builds included); the
  keys were deleted after each run. The default tests: 814 passed, 0 failed,
  19 ignored. The run was dispatched on a branch before the commit; `main`
  runs the same job at each push.

# T-215: rustfmt and clippy in the gate

**Source:** the triage of GitHub #27 (2026-10-08).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The gate runs neither `cargo fmt --check` nor `cargo clippy`. The format of
the code is not consistent, and nobody knows the lints that clippy gives. A
lint that points at a defect (an unused result, a wrong comparison) is never
seen.

## Premise

Measured with awk over `git ls-files 'crates/*.rs'` (216 files, comment lines
not counted): 686 lines are longer than 100 characters, the default
`max_width` of rustfmt, in 114 files; 119 lines are longer than 120. So the
code is not in the default style of rustfmt.

Read:

- `scripts/gate.sh` lines 55-166 at `528bb64` have no step for rustfmt or clippy. There is no
  rustfmt.toml and no clippy.toml.
- One `allow` for clippy exists (`crates/podssh-ws/src/client.rs:338`).
- Files near 500 lines: `crates/podssh-cli/src/flags.rs` (469),
  crates/podssh-transport/src/socket.rs at `e8bbd4d` (458),
  `crates/podssh-cli/src/tree.rs` (454). Formatting can make a file longer.

Not measured (no build here): the changes of rustfmt, the warnings of clippy,
and whether `rust:1-alpine` has the components rustfmt and clippy.

## Approach

1. Measure first, and record in docs/STATUS.md: `cargo fmt --all --check`
   with the default style and with `max_width = 120`; `cargo clippy` with
   `--all-targets`, for the default members and with
   `--features podssh-cli/ts`.
2. Choose the style (see Decision), and write it in rustfmt.toml. Keep
   `wrap_comments = false`: comments must not change.
3. One commit that only formats. Then run `python scripts/check-repo.py`, and
   split each file that went over 500 lines, in the same commit.
4. Repair each warning of clippy, or allow it at the item with a comment that
   says why. Never allow a lint for a whole crate.
5. Two steps at the start of `scripts/gate.sh` (they are fast):
   `cargo fmt --all --check`, and clippy with `-D warnings`. When the image
   lacks a component, add it with `rustup component add`.
6. T-206 first. With a moving toolchain, a new release of Rust adds lints and
   turns the gate red on a tree that did not change.

## Decision

Recommendation: the `max_width` with the smallest measured change that keeps
each file at 500 lines or fewer, written in rustfmt.toml. The default style
lost if it rewrites most files or pushes files over 500 lines; the
measurement of step 1 decides.

2026-10-09, measured with `cargo fmt` on the packages of the workspace (not
`--all`, which would also format the fork in `vendor/`), each run on a
clean tree and then undone:

| Style | Files changed | Lines added / removed | Files over 500 lines |
| --- | --- | --- | --- |
| the default (`max_width = 100`) | 242 | 12,460 / 3,197 | 14 |
| `max_width = 120` | 235 | 8,040 / 2,530 | 7 |
| `max_width = 140` | 228 | 5,897 / 2,585 | 4 |
| `max_width = 160` | 219 | 4,232 / 2,955 | 3 |
| 120, `use_small_heuristics = "Max"` | 202 | 2,265 / 2,718 | 1 (`flags.rs`, 684) |
| 140, the same | 195 | 1,886 / 3,924 | 1 (`flags.rs`, 672) |
| 160, the same | 211 | 1,802 / 4,800 | 1 (`flags.rs`, 510) |

Chosen: `max_width = 120` with `use_small_heuristics = "Max"`, the smallest
change in all (lines added and removed). `flags.rs` is tables, one flag to a
row, which rustfmt spreads over many lines: its module is skipped
(`#[rustfmt::skip]` on `pub mod flags;`), and so are the table of closes
and the tables of `-o` keywords, each at its constant. After that: 201 files
(1,678 lines added, 2,540 removed), and no file over 500 lines (`pair.rs`
has 500). Lost: a wider line, which joins more lines (more removed than
added) for long lines to read; the default style, which puts 14 files over
500 lines.

The state (partial), 2026-10-09: the format is one commit. Of the citations
of the formatted files in the record, `cargo todo remap` moved 555 and moved
167 more by their ends (only lines inside them were reflowed); the 44 that
named a reflowed line were moved by their tokens (the characters other than
whitespace of each file before and after, aligned), and four of them read
again by hand. `cargo test --no-fail-fast`: 814 passed, 0 failed, as before.
Next: clippy, then the two steps of the gate.

## Prove

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
python scripts/check-repo.py     # no file over 500 lines after the format
sh scripts/dev.sh check          # the fmt and clippy steps of the gate pass
```

Each command exits 0. Planted defects: `if v.len() == 0 {}` in a test must
fail clippy (`len_zero`); two spaces before an `=` must fail the fmt step.

## Correction

2026-10-09, `wc -l`: the files near 500 lines changed after the Premise was
read. `crates/podssh-cli/src/tree.rs` is 358 lines (T-051 moved `Parsed` to
`parsed.rs`); `crates/podssh-cli/src/flags.rs` is 482;
crates/podssh-transport/src/socket.rs at `e8bbd4d` is 480 (T-071);
`crates/podssh-cli/src/dispatch.rs` is 480; `crates/podssh-ws/tests/rfc6455.rs`
is 486. Measure again before the format.

2026-10-09: the gate of CI failed at its step of clippy on the push of this
entry (runs 37879663510 and 37880012628). The Prove ran clippy on the
Windows host only, with Rust 1.98. clippy 1.99 of the build image found a
loop over one element (`single_element_loop`) in
`crates/podssh-probe/tests/relay_facts.rs`, which clippy 1.98 passed, and
three clones made into a slice (`cloned_ref_to_slice_refs`) in
`crates/podssh-relay/tests/cache.rs`, in a test for Unix only, which clippy
on Windows does not compile. Repaired in the commit "clippy 1.99 of the build
image gives no warning": the copies are a named list, filtered;
`std::slice::from_ref`, as in the rest of that file. clippy 1.99 in the build
image, with `--keep-going` over each target: no other warning.
`docs/development.md` now says that the gate's clippy is the one that
counts.

## Done

2026-10-09, in the commits "The code in one format: rustfmt, 120
characters, short items on one line" (the format alone) and "clippy gives no
warning, and the gate checks the format and the lints".

- clippy, measured on each target of the packages of the workspace: 47
  warnings. `cargo clippy --fix` repaired 32 (copies of a slice, `mem::take`,
  `div_ceil`, `then_some` on cheap values, a byte string, an elided
  lifetime); by hand: a loop over pairs, a `while let`, two type aliases, a
  guard that a test held across an `await` (now in a block of its own), an
  `async fn` for the timed signer, a doc comment that was a plain comment,
  and three assertions on constants, which a `const` block now checks when
  the tests compile. Allowed at the item, with the reason: `KeyFile`, read
  once for each run (`large_enum_variant`), and two functions of the live
  IRC example, whose arguments are its knobs (`too_many_arguments`). With
  the feature `ts`: no warning.
- `scripts/gate.sh`: the components rustfmt and clippy, then `cargo fmt
  -- --check` for each package, then clippy with `-D warnings`, for each
  target and with the feature `ts`, before the builds.
- Prove: `cargo fmt -- --check` (each package): exit 0. `cargo clippy
  --locked --all-targets -- -D warnings`: exit 0; with `--features
  podssh-cli/ts`: exit 0. `python scripts/check-repo.py`: exit 0, no file
  over 500 lines. `cargo test --no-fail-fast`: 814 passed, 0 failed, 19
  ignored. Plants, restored: `if v.len() == 0 {}` in a test of
  `podssh-probe`: clippy exits 101 (`len_zero`); `PLANTED  : u8` with two
  spaces: the format check exits 1. The gate's run is in CI, on the push.

# T-216: Advisories and licenses of the dependencies, checked in CI

**Source:** the triage of GitHub #27 (2026-10-08); the advisories of iroh
(`docs/design.md:944-946`) show that a dependency can get one.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

No check reads the dependencies for security advisories, licenses or sources.
A dependency with a known vulnerability, a license that podssh cannot ship, or
a crate from an unknown source can come in with an update of the lockfile.
The release binaries also ship with no license notices.

## Premise

Measured with grep on `HEAD`: `Cargo.lock` holds 478 packages, 438 from
crates.io; the others are crates of the workspace and of the fork. There is no
git source.

Read:

- The licenses that the release binary links, as the manifests in the local
  cargo registry declare them: aws-lc-sys 0.45.0 "ISC AND (Apache-2.0 OR ISC)
  AND Apache-2.0 AND MIT AND BSD-3-Clause AND ..."; webpki-roots 1.0.9
  CDLA-Permissive-2.0; russh 0.64.1 Apache-2.0.
- BSD-3-Clause and Apache-2.0 ask that a binary copy carries the notices. The
  release publishes the binaries and `SHA256SUMS` only (lines 108-136 at
  `22c3b88`).
- The fork already has a configuration for cargo-deny
  (`vendor/tailscale-rs/deny.toml:1-35`): an allow list of licenses, one
  ignored advisory with its reason, crates.io only.
- podssh is 0BSD (`LICENSE`).

## Approach

1. deny.toml at the root: allow each license that `cargo deny list` reports,
   by name; crates.io as the only source, with unknown git sources and
   registries denied; duplicate versions as a warning; each ignored advisory
   with a reason and a date, as the fork does.
2. A job `deny` in `.github/workflows/build.yml`, with cargo-deny pinned, on
   each push, each pull request and a daily schedule, because an advisory can
   appear when the tree does not change. Check the default graph and the graph
   with all features (the fork comes with `ts`).
3. Notices: make a file of third-party licenses for each release (cargo-about,
   a Rust tool), publish it with the binaries, and name it in the notes.
4. docs/development.md, the section "Checks" (`docs/development.md`): the command.
   `SECURITY.md`: how an advisory is handled.

## Decision

Recommendation: cargo-deny. One configuration checks advisories, licenses,
duplicates and sources, and the fork already uses it. cargo-audit lost: it
checks advisories only.

## Prove

```sh
cargo deny --locked check advisories licenses bans sources
cargo deny --locked --all-features check licenses sources
```

Both exit 0, and the next release has a file of notices. Planted defect:
remove `CDLA-Permissive-2.0` from the allow list; the license check must fail
on webpki-roots.

## Correction

2026-10-09, the Decision's details:

1. Its own workflow, `.github/workflows/deny.yml` (each push to `main`, each
   pull request, each day, and by hand), not a job of
   `.github/workflows/build.yml`: a daily schedule there would run the gate
   each day. cargo-deny 0.20.2 comes as a release binary checked against its
   checksum (`taiki-e/install-action`), not built on each run.
2. The allow list has the licenses that the graph needs, by name, but not
   LGPL-2.1-or-later: its one crate (r-efi) is offered under MIT too, and a
   crate under LGPL alone would not fit a static binary. MPL-2.0 is an
   exception for one crate, dyn-eq, which only the Tailscale fork (feature
   `ts`) brings. Duplicate versions are a warning; path dependencies are
   allowed as wildcards, as the workspace and the fork are paths.
3. The notices: `about.toml` and `about.hbs` make `THIRD-PARTY-LICENSES.md`
   for the graph of `podssh-cli` with its default features, as the release
   binaries are built; the job `publish` makes it with cargo-about 0.9.2 and
   names it in the body of the release.

The state (partial), 2026-10-09: `cargo deny --locked --offline check
licenses bans sources`: exit 0 ("bans ok, licenses ok, sources ok"), and with
`--all-features check licenses sources`: exit 0. Plant, restored: without
`CDLA-Permissive-2.0`, the license check exits 4 and rejects webpki-roots.
`cargo about generate` made the notices here: 321,621 bytes, 60 sections,
aws-lc-sys, russh and webpki-roots among them. The advisories need the
RustSec database, which the first run in CI reads. That run (37877273469)
found RUSTSEC-2023-0071, the Marvin timing attack on the private-key
operations of `rsa`, which has no fixed version: `podssh-ws` only verifies
RSA signatures, but an RSA user key signs through it. The advisory is
ignored in `deny.toml` with that reason, the gap is in `SECURITY.md`, and
T-257 moves RSA signing to aws-lc-rs. Next: the run with the ignore.

## Done

2026-10-09, in the commits "Advisories, licenses and sources of the
dependencies, and the notices", "An advisory of rsa, read and ignored with
its reason; RSA signing is an entry" and "An unmaintained proc-macro of the
Tailscale fork, ignored with its reason"; closed in the commit "The
repository check finds a listener outside its allowance".

- `deny.toml`, `.github/workflows/deny.yml` (cargo-deny 0.20.2, each push,
  each pull request, each day), `about.toml` and `about.hbs` (cargo-about
  0.9.2 in the job `publish`, `THIRD-PARTY-LICENSES.md` named in the body of
  each release), `docs/development.md` ("Checks") and `SECURITY.md` (how an
  advisory is handled; the gap of RSA signing).
- The advisories read in CI: RUSTSEC-2023-0071 (Marvin, `rsa`; no fixed
  version; T-257) and RUSTSEC-2024-0436 (`paste` unmaintained; a build-time
  proc-macro of the Tailscale fork), each ignored with its reason and date.
- Prove: run 37877656949 of `deny.yml`: "advisories ok, bans ok, licenses ok,
  sources ok", and with every feature "licenses ok, sources ok". Here, the
  same license, ban and source checks: exit 0. Plant, restored: without
  `CDLA-Permissive-2.0` the license check exits 4 and rejects webpki-roots.
- The notices: made here from the graph of the release binary (321,621
  bytes, 60 sections); the first release publishes them (T-251 checks the
  release's files).

# T-217: The declared minimum Rust versions, checked in CI

**Source:** the minimum versions that the manifests declare
(`docs/development.md:8-11`), measured by hand on 2026-10-08 (the note beside
`rust-version` in `Cargo.toml`).
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The manifests declare minimum Rust versions, but the gate builds only with the
newest stable Rust of its image. An update of a dependency, or a new call of
the standard library, can break a declared minimum, and no run sees it. A user
who builds from source with that Rust then gets a compile error.

## Premise

Read:

- `Cargo.toml`, the workspace's package table: `rust-version = "1.88"`, with
  the note that the library crates passed `cargo check --all-targets` on
  Rust 1.88.0 (measured 2026-10-08).
- `crates/podssh-ssh/Cargo.toml:6-8` and `crates/podssh-cli/Cargo.toml:6-8`:
  1.89, the minimum of russh 0.64.1. `crates/podssh-ts/Cargo.toml:5-6`: 1.92,
  the minimum of the fork.
- `scripts/gate.sh:117-120` prints the one toolchain of the gate.
- The workspace uses the resolver "2", which ignores `rust-version` when it
  picks versions.

## Approach

1. A job `msrv` in `.github/workflows/build.yml`, one entry for each declared
   version: 1.88 for the library crates and each crate that takes the
   workspace's value (podssh-todo too); 1.89 for podssh-ssh and podssh-cli;
   1.92 for podssh-ts with its feature. Run `cargo check --locked
   --all-targets`, so that the committed lockfile is what is checked.
2. Read the versions from the manifests in the job; do not write them again
   in the workflow.
3. Build in `rust:1.88-alpine` and the same family for each version, so that
   the C toolchain for aws-lc is the gate's.
4. `incompatible-rust-versions = "fallback"` in the
   resolver table of `.cargo/config.toml`, so that `cargo update` prefers
   versions that keep the minimums. The updates of T-205 then fail less often.
5. docs/STATUS.md, "Build, tests, CI": one row for each version, with the date
   and the run.

## Decision

2026-10-09: steps of the gate, not a job of the workflow. `msrv_ssh` and
`msrv_ts` join `msrv` in `scripts/gate.sh`, so that a developer's gate runs
them too, and CI runs each in a job of its own (T-212). rustup fetches each
toolchain into the build image, so the C toolchain of aws-lc is the gate's:
step 3 asked for the image family of each version for that reason, and one
image gives it with no second pin. An image for each version lost: three
more pins, and C toolchains that differ from the gate's by their dates. Two
steps rather than one: the check of the fork takes minutes, and alone it
would be the longest job of CI.

## Prove

```sh
cargo +1.88.0 check --locked --all-targets -p podssh-ws -p podssh-relay -p podssh-transport -p podssh-core -p podssh-terminal -p podssh-probe -p podssh-todo
cargo +1.89.0 check --locked --all-targets -p podssh-ssh -p podssh-cli
cargo +1.92.0 check --locked --all-targets -p podssh-ts -p podssh-cli --features podssh-cli/ts
```

Each command exits 0, and the job runs the same three. Planted defect: call
`std::fs::File::lock` (stable since Rust 1.89; confirm in its release notes)
in a library crate; the check with 1.88 must fail.

## Correction

2026-10-09 (T-081): the workspace declares Rust 1.85 now, not 1.88. The library crates and
podssh-todo passed `cargo check --locked --all-targets` on 1.85.0, and two steps of
`scripts/gate.sh` check them on the declared version at each run. Step 1 keeps the checks of 1.89
(podssh-ssh, podssh-cli) and 1.92 (podssh-ts); the job may take the check of the library crates
over from the gate. The plant for 1.85: a call stable since 1.86 (`Vec::pop_if`) fails it with
`E0658`.

The checks of 1.89 and 1.92 are steps of the gate (Decision). So the Prove
runs as `sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh msrv msrv_ssh
msrv_ts'`, and the plant of 1.89 is a call stable since 1.90, as `File::lock`
is stable on 1.89.

## Done

2026-10-09, in the commit "The gate checks each crate on the minimum Rust
that it declares".

- `scripts/gate.sh`: `rust_version` reads each manifest's version in the
  gate's shell, and fails on one that is not 1.x. The step `msrv_ssh` checks
  `podssh-ssh` and `podssh-cli` on their versions (1.89); `msrv_ts` checks
  `podssh-ts` and the CLI with the feature `ts` on the adapter's (1.92).
- `.cargo/config.toml`: `incompatible-rust-versions = "fallback"`.
- `docs/development.md`: the three versions, their steps, and the policy of
  updates. `docs/STATUS.md`: a row for each version.
- Prove: `sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh msrv msrv_ssh
  msrv_ts'`: each check exited 0 (1.85, 1.89 twice, 1.92), green in 6 min
  37 s. Plants, together, then restored: `u32::checked_sub_signed` called in
  `podssh-ssh`: both checks on 1.89 exited 101 with `E0658`
  (`mixed_integer_ops_unsigned_sub`); `podssh-ts` declaring 1.91: the check
  exited 101, as cargo names each crate of the fork that requires rustc
  1.92.0. CI runs the two new steps as jobs from the push of this commit.

# T-218: More release targets: macOS, Linux armv7 and riscv64, and Windows aarch64

**Source:** the iroh-ssh report in GitHub #18 (static musl binaries for more
architectures; its issues 51 and 57), read in the report, not verified here.
The operator's ruling of 2026-10-08: v1.0.0 ships these targets
(`docs/decisions.md`).
**Category:** release
**Milestone:** M9
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A release has three binaries: static Linux for x86_64 and aarch64, and
Windows for x86_64. A Raspberry Pi with a 32-bit system, a Mac, a Windows
machine on ARM and a FreeBSD host get none. Their users must build podssh,
with a C toolchain for aws-lc.

## Premise

Read:

- `.github/workflows/release.yml:94-98`: x86_64 and aarch64 musl, each on a
  native runner in `rust:1-alpine`. `.github/workflows/release.yml:323-410`:
  Windows x86_64 with a static C runtime.
- The check of each platform: `readelf` for `NEEDED` and `INTERP`
  (`.github/workflows/release.yml:120-127`), `dumpbin /dependents` on Windows
  (`:377-402`).
- The binary needs a C compiler for aws-lc (`docs/development.md:12-15`); the
  library crates need none.
- Some code reads facts of Linux. The terminal check reads `tty_nr` from
  `/proc/self/stat` when it can (`crates/podssh-ssh/src/terminal/ctty.rs:24`),
  and does without it when it cannot (`crates/podssh-ssh/src/terminal/ctty.rs:37-38`).
  `doctor` reads `/proc` too. These need a run on each new system.

## Approach

One target for each commit, each with a build, a check of its links, and a run
of the binary:

1. `armv7-unknown-linux-musleabihf` (a Raspberry Pi with 32 bits): static, the
   `readelf` check, and a run under QEMU (`--version`, `man --no-pager`,
   `keygen`, then `keygen -y`).
2. `aarch64-apple-darwin` and `x86_64-apple-darwin` on macOS runners:
   `otool -L` lists system libraries only. Run the default tests there first.
3. `aarch64-pc-windows-msvc` on a Windows runner for ARM: the `dumpbin` check;
   aws-lc on Windows for ARM64, to measure.
4. `riscv64gc-unknown-linux-musl`, where the gate's image family builds it.
   `x86_64-unknown-freebsd` stays for later.
5. For each target: a row in the table of binaries of the release notes,
   the README, and the attestation of T-210. The draft notes of the dropped
   beta have such a table (`git show b1b111b:docs/releases/v0.1.0-beta.1.md`).

Invariant: no target ships that no run executed.

## Decision

Recommendation: build each new Linux target in the image family of the gate
under QEMU, where that image exists for the platform, so that there is one
toolchain. `cross` and `cargo-zigbuild` lost: each brings a second C
toolchain that the gate never judged. Measure the build time first: QEMU is
slow, and the job limit is 60 min (`.github/workflows/release.yml:100`).

2026-10-30, the calls of this entry's session:

- armv7 builds with Alpine's own rust in a `linux/arm/v7` container, as the
  Correction's plan A says: the gate's image has no `arm/v7`, and Alpine is
  the same family of musl and toolchain. The arm64 runner ran the container
  natively, so the probe keeps QEMU as the fallback only.
- Each target first runs in a trial workflow of its own (`targets.yml`, by
  hand), and moves into `release.yml` only when it passed there; the trial
  then goes, as each of its jobs lives on in the release. Lost: trying each
  target in `release.yml` at once, which would leave the release red while
  a target failed, as each did at first.
- Each binary runs the short form of T-251's check on its own platform
  (`scripts/release-short.sh`): T-251 names it, and one script serves each
  system. Lost: a step written again for each job.
- The default tests run on the arm64 Mac in the gate (`build.yml`, job
  `macos`) on each push, as they run on Windows; the release builds and runs
  both Mac binaries. Lost: the tests in the release only, which would find a
  defect of macOS at a release, as the trial found three; and both Macs in
  the gate, as the Intel image is the last of its kind and slower, and the
  arm64 Mac reaches the same code.

2026-10-30, the operator (`docs/decisions.md`): riscv64 is cross-compiled
with `cargo-zigbuild`, and only its run is under QEMU. This overrides, for
riscv64, the first recommendation above (one toolchain, `cargo-zigbuild`
lost): the build under QEMU passed, but in 88 minutes, which each release
would wait for. The cross build runs in the gate's own image on a native
runner (its rustc and `rustup target add`), with zig 0.16.0 from
ziglang.org, checked by the sum of its download index, and `cargo-zigbuild`
0.23.4, built from crates.io with `--locked`; versions under two weeks old
lost (zig 0.17.0, `cargo-zigbuild` 0.24.0). The binary runs on the runner
through the handler of binfmt that QEMU registers, as the pull of a second
platform of one image fails ("cannot overwrite digest").

## Prove

```sh
gh workflow run release.yml --ref main      # builds and checks each target, publishes nothing
gh run download RUN_ID -R Azathothas/podssh -n podssh-armv7-unknown-linux-musleabihf
```

The run passes for each target, and each artifact ran under its check.
Planted defect: build one target without `+crt-static`; its static check must
fail.

## Correction

2026-10-30, the research of that day (Read in the sources named, through a mirror of GitHub's API for
repository pages; nothing was built; Inferred is marked). It changes the Decision's reach and gives
a plan for each target. The workflow keeps the names `podssh-<target>` for its artifacts (a build
job of artifact v4 or later may not repeat a name), so `subject-path: dist/podssh-*` of T-210 and the
sums of the job `publish` take each new file with no change; the job `publish` then lists each
new job in `needs`.

**What aws-lc needs.** `Cargo.lock` has aws-lc-sys 0.45.0 and aws-lc-rs 1.18.1 (1.19.0 was released
on 2026-10-28). A build without FIPS needs a C compiler and nothing else: the requirements pages
(https://aws.github.io/aws-lc-rs/requirements/index.html) say "CMake: Never required", and Go and
bindgen are not needed ("universal pre-generated bindings"; since 1.15.0, 2025-11-12, which removed
the bindgen need for armv7 and riscv64: issues 890 and 874 of `aws/aws-lc-rs`). On main, not on 0.45.0
itself (so it holds there only by Inference), the builder compiles assembly for arm, aarch64, x86,
x86_64 and ppc64le, and for another architecture such as riscv64 it warns "No target-specific source
found" and compiles the portable C. Windows on ARM64 needs a C compiler, clang-cl, and no NASM.
macOS needs the Xcode command line tools only.

**The Decision's reach.** `images/build/Dockerfile:4` says "linux/amd64 and linux/arm64",
and the comment is stale for riscv64: the pinned digest is an index, and the index read through
`mirror.gcr.io` lists linux/amd64, linux/arm64, linux/ppc64le and linux/riscv64. So the same image
runs `--platform linux/riscv64` under QEMU. There is no `linux/arm/v7` variant of `rust:1-alpine`
(the official image has amd64, arm64v8, ppc64le and riscv64 for Alpine), so "where that image exists"
leaves armv7 out of the Decision; the plan below takes Alpine's own toolchain for it.

**One commit for each target** (the plans are drafts; none ships without a run):

- `aarch64-apple-darwin`: `runs-on: macos-15`, a native `cargo build --locked --release --target
  aarch64-apple-darwin -p podssh-cli`; no cmake, Go or NASM. Check that `otool -L` lists paths under
  `/usr/lib/` and `/System/Library/` only, then run `--version`, `man --no-pager`, `keygen` and
  `keygen -y`.
- `x86_64-apple-darwin`: `runs-on: macos-15-intel`, native, and the runner runs the binary. Read:
  `macos-15-intel` is "the last available x86_64 image from Actions" and lasts until August 2027
  (`actions/runner-images`, issue 13046), so a release after that needs a cross build from arm64 (the
  Rosetta need of a run is untested). Do not use `macos-14`, which retires on 2026-11-02 (issue
  13518 there); `macos-13` retired on 2025-12-04. The labels `macos-26` and `macos-26-intel` exist.
- `aarch64-pc-windows-msvc`: `runs-on: windows-11-arm`, no NASM step, `RUSTFLAGS:
  -Ctarget-feature=+crt-static`, `cargo build --locked --release -p podssh-cli`. The image has LLVM
  22.1.8, Visual Studio 2022 with `VC.Llvm.Clang`, Rust 1.99.0, CMake and Ninja; aws-lc needs clang-cl,
  found in PATH or in Visual Studio; if it is not found, set `CC: clang-cl`. The `dumpbin` step of
  the Windows job looks only under `Hostx64\x64`
  (`.github/workflows/release.yml` said "Hostx64\x64\dumpbin.exe", line 126 at `ae8447f`): for ARM search
  `bin\Hostarm64\arm64\dumpbin.exe` first, then any `bin\Host*\*\dumpbin.exe` (the layout of the
  ARM image is Inferred). aws-lc-rs's own CI builds this target on an x64 runner and runs cargo-xwin
  on `windows-11-arm`. Add a Windows ARM row to `build.yml` later.
- `armv7-unknown-linux-musleabihf`: Rust tier 2 with no host tools, so there is no rustup toolchain
  to run on 32-bit ARM; aws-lc-rs tests `arm-unknown-linux-musleabihf` and
  `armv7-unknown-linux-gnueabihf` with `cross`, not this target. Plan A: `runs-on:
  ubuntu-24.04-arm`; probe `docker run --rm --platform linux/arm/v7 alpine:3.24 uname -m`, and where
  it fails use `docker/setup-qemu-action` (v4.2.0 `96fe6ef7f33517b61c61be40b68a1882f3264fb8`; v4.4.0
  exists). The arm runners' CPU, Neoverse N2, "supports AArch32 at EL0" (Arm's TRM 102099) and
  projects run armv7 containers on it, but another project says that is not guaranteed: probe at run
  time. Inside the container: `apk add --no-cache build-base rust cargo` (Alpine 3.24 `main/armv7` has
  rust and cargo 1.96.1) and a host build with `RUSTFLAGS=-Ctarget-feature=+crt-static`; the output is
  `target/release/podssh`, and Alpine's triple is `armv7-alpine-linux-musleabihf`, so name the
  artifact by hand. Check with the same `readelf` step as x86_64, and run the binary in an armv7
  container. Plan B, which the Decision rejected, for native speed: `ghcr.io/cross-rs/armv7-unknown-
  linux-musleabihf:main`, or `cargo-zigbuild` (its CI covers x86_64, aarch64 and Apple, not armv7).
  The release profile is `opt-level = "z"`, `lto = true`, `codegen-units = 1`
  (`Cargo.toml:198` says "opt-level"; the profile is at the lines around it): the link on a 32-bit
  rustc may run out of address space, and under QEMU it is slow. Measure first.
- `riscv64gc-unknown-linux-musl`: Rust tier 2 with host tools. Plan A: `runs-on: ubuntu-24.04`,
  `docker/setup-qemu-action` with `platforms: riscv64`, `docker run --platform linux/riscv64
  "$BUILD_IMAGE"` with the image that the job already reads from the Dockerfile, a host build with no
  `--target`. There is no hosted riscv64 runner. aws-lc-rs's own CI covers riscv64 with glibc, and
  needs `-Wno-string-compare` with GCC 11; Alpine's GCC is newer (not needed: Inferred). Plan B:
  `ghcr.io/cross-rs/riscv64gc-unknown-linux-musl:main` (musl GCC and qemu inside).
- The job's own limit. `timeout-minutes: 60` is the repository's choice
  (`.github/workflows/release.yml:100` says "timeout-minutes: 60"); GitHub's limit for a hosted job is 6
  hours. Set the QEMU jobs up to 360 for the first measurement, and lower it to the measured time.
- Public repositories: the standard hosted runners are free and unlimited; the Linux and Windows arm64
  runners (4 vCPU) are generally available for them (changelog of 2025-08-07).

Not measured, and the first runs answer them: whether the arm runner runs `linux/arm/v7` containers
natively today; whether aws-lc-sys 0.45.0 (not main) builds on armv7 musl and riscv64 musl with no
cmake and no bindgen; the time of the riscv64 build under QEMU and the memory of the armv7 link;
Intel macOS after August 2027 (cross build with Rosetta, or drop the target).

## Done

2026-10-30, partial. The workflow release targets (`targets.yml`, by hand only, publishing
nothing; it went once each of its jobs moved into `release.yml`) builds each new target on its own platform, checks its links (`otool -L` on
macOS, `dumpbin` on Windows, `readelf` on Linux), and runs it with `scripts/release-short.sh`, the
short form of T-251's check: `--version` against `Cargo.toml`, the whole manual, `keygen` with no
passphrase, then `keygen -y`, which must give the same key, and with `--net` GitHub's SSH banner
through the live relay (`podssh proxy github.com 22`). macOS runs the default tests first. armv7
builds with Alpine's own rust in a `linux/arm/v7` container of `images/armv7/Dockerfile` (alpine
3.24, pinned to the digest of its index, which has `arm/v7`), on an arm64 runner, natively where a
probe finds 32-bit ARM, else under QEMU. riscv64 builds in the gate's own image under QEMU.

- The script, here on a debug build: four ok, with and without `timeout(1)` (macOS has none, and a
  killer in the background stands in); with four planted binaries (another version, another key
  from `keygen -y`, a manual of one line, a proxy that gives no banner), each run failed and left
  no scratch directory.
- `aarch64-pc-windows-msvc`, run 41074530703: built in 286 s with no NASM; the native ARM64
  `dumpbin` (Visual Studio 18, MSVC 14.44.35207) reads `AA64 machine (ARM64)`, and the binary
  needs only the system's DLLs (bcrypt, bcryptprimitives, crypt32, kernel32, ntdll, secur32,
  advapi32, user32, oleaut32, ws2_32 and one `api-ms-win-core-synch`), no C runtime; the short
  form passed. The build warned of six items of `node_install/text.rs` unused on Windows,
  repaired under T-121.
- armv7 and riscv64, runs 41074530703 and 41075369345: the pull of the image held the runner's
  own platform, and `docker run --platform` stopped with "cannot overwrite digest";
  `scripts/pull-image.sh` now pulls the platform that `PULL_PLATFORM` names. Then each build
  stopped at "cannot produce proc-macro for `clap_derive`": `+crt-static` with no `--target`
  reaches the proc-macros of a musl host. Each build now names its host triple as `--target`
  (Alpine's is `armv7-alpine-linux-musleabihf`). The arm64 runner ran the `linux/arm/v7` container
  natively: the probe passed, and no QEMU was set up.

- The repaired jobs, run 41076578398: armv7 built natively in 344 s, `ELF 32-bit LSB pie
  executable, ARM, EABI5 version 1 (SYSV), static-pie linked` (`hard-float ABI`), no `NEEDED`
  and no `INTERP`; in the `linux/arm/v7` container the short form passed (`--version`, 3795 lines
  of the manual, `keygen -y` with the same `ssh-ed25519` key, and `SSH-2.0-` from GitHub through
  the live relay). Windows on ARM passed again (build 284 s, the short form 42 s).
- macOS, run 41080813567, after the repairs of T-034 and T-146: on `macos-15` (arm64) the default
  tests passed in 414 s and the build took 199 s; on `macos-15-intel` the tests took 1400 s and the
  build 571 s. `file` reads `Mach-O 64-bit executable arm64` and `x86_64`, and `otool -L` lists
  CoreFoundation, `/usr/lib/libiconv.2.dylib` and `/usr/lib/libSystem.B.dylib` only, on both. The
  short form passed on both; `wc -l` of macOS pads its count with spaces, which the script now
  strips.
- So `release.yml` builds these four, each with its check and the short form, beside the three
  of before, whose jobs now run the short form too: the job `linux-armv7`, the matrix `macos`, and
  the job `windows`, now a matrix of x86_64 (NASM) and aarch64 (no NASM; `dumpbin` of
  `Hostarm64\arm64` first, then any host's; `/headers` checks the machine). The job `publish` needs
  each. Their jobs left the trial, which keeps riscv64 alone. `build.yml` runs the default tests
  on the arm64 Mac at each push (the job `macos`, in `all`'s needs). The README names the new
  files and how a Mac fetches one with no quarantine; `docs/development.md` lists the binaries
  and the checks. The release notes' table of binaries comes with the notes of beta.2 (T-309), and
  the attestation of T-210 takes `dist/podssh-*`, each new file with it.

- riscv64 under QEMU, run 41076578398: the build in the gate's image took 5287 s (88 min),
  and the binary passed the short form under QEMU in 41 s. So the operator's call: the cross
  build of `cargo-zigbuild` (the Decision), tried in `targets.yml` first.
- The Prove's dry run of `release.yml` at `224ccd2` (run 41087466860): each of the seven jobs and
  `publish` passed; the files of the artifact `release-dry-run` hold the seven binaries
  (`file`: Mach-O arm64 and x86_64, PE32+ Aarch64 and x86-64, ELF aarch64 static, ELF armv7
  static-pie, ELF x86-64 static-pie), `SHA256SUMS` (each sum checks), the licenses and the body.
  The x86_64 binary passed the short form here with `--net`.

- The cross build of riscv64 in the trial: the first run stopped at "cannot produce proc-macro"
  in the install of `cargo-zigbuild` (run 41091523632), as `+crt-static` with no `--target`
  reached the musl host's proc-macros; the install now clears RUSTFLAGS. The second stopped at
  `cargo zigbuild --version`, which the subcommand does not take (run 41093257619). The third,
  run 41093657124: zig 0.16.0's download matched its sum, `cargo-zigbuild` 0.23.4 built in about a
  minute, and the build took 305 s in all, where QEMU took 5287 s; the binary is static (no
  `NEEDED`, no `INTERP`), and on the runner, through QEMU's handler of binfmt, it passed the short
  form: `podssh 1.0.0-beta.1 (4fb1728...)`, 3795 lines of the manual, `keygen -y` with the same
  key, and GitHub's banner through the live relay.
- So `release.yml` builds riscv64 as the job `linux-riscv64`, and `publish` needs it; the trial
  workflow `targets.yml` goes, as each of its jobs now lives in the release. The README, the
  notes of beta.2 and `docs/development.md` name the binary.

- The Prove's dry run at `3992dc3` (run 41095138291): each of the eight builds passed, and
  `publish`; its artifacts hold the eight binaries, each of which ran under its check on its own
  platform, and `release-dry-run` the files that a tag publishes.

Waits for T-251: the planted build without `+crt-static`, whose static check must fail.

# T-219: The no-C gate also stops C++

**Source:** the operator's commit `a378863` (2026-10-08).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The gate built the library crates with `CC=/nonexistent` only. The `cc` crate
reads `CXX` for a C++ file, so a library crate with a C++ dependency passed
the gate on any host that has a C++ compiler. The no-C rule held only because
`rust:1-alpine` has no C++ compiler (the commit message says so).

## Premise

Read, in the tree as it is now:

- `scripts/gate.sh:127-166`: the library crates build and test with
  `CC=/nonexistent` and `CXX=/nonexistent`.
- `scripts/plant.sh:100-145`: a crate in a temporary path whose build script
  compiles one C++ file with the `cc` crate. With both variables set, the
  build must fail at `/nonexistent`; the control, with `CC` alone, must not
  stop there.
- `docs/development.md:250-252` states the rule with `CXX`, and
  `docs/STATUS.md:637` records the measurement. Rule 4 of
  `docs/architecture.md` named `CC=/nonexistent` only; it was repaired in the
  same change as the record.
- `.github/workflows/build.yml:103-111` runs the plant on each push.

## Approach

Done in commit `a378863`:

1. `scripts/gate.sh` sets `CXX=/nonexistent` beside `CC` for the build and the
   tests of the library crates.
2. `scripts/plant.sh` plants the C++ crate and checks that the build fails at
   `/nonexistent`. Then it runs the control with `CC` alone, and checks that
   the build does not stop there. This shows that `CXX` is what stops it.
3. docs/development.md and docs/STATUS.md record the rule and the measurement.

## Prove

```sh
sh scripts/dev.sh plant     # C twice, C++ at CXX=/nonexistent, the C++ control, the clean tree
```

The plant prints its verdict (`scripts/plant.sh:148`) and exits 0. CI runs
the same script in its step "the no-C rule is load-bearing".

## Done

2026-10-08, commit `a378863` ("gate: the no-C rule also stops C++
(CXX=/nonexistent)"). Measured with `sh scripts/dev.sh plant` in
`rust:1-alpine`: the C plant failed twice for the right reason, the C++ plant
failed at `CXX=/nonexistent`, the control with `CC` alone was not stopped
there, and the clean tree built (`docs/STATUS.md:637`). The CI run of
`eacd94e`, which contains `a378863`, passed, with its step "the no-C rule is
load-bearing".

# T-223: `scripts/check-repo.py` passes when it finds nothing to check (GitHub #33)

**Source:** GitHub #33 (2026-10-08), part 1; reproduced here on 2026-10-08.
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Each check of `scripts/check-repo.py` reports `ok` when it finds no problem,
also when it found no file to check. With no `crates/` directory the 500-line
rule passes; with no Markdown the link check passes; with no tracked file the
credential check passes. A guard that scanned nothing must fail, not pass.

## Premise

Measured: a verbatim copy of `scripts/check-repo.py` in an empty git
repository (one `README.md`, no `crates/`) printed four `ok` lines and exited
0. With a planted file crates/x/src/big.rs of 501 lines, the same copy exited
1 and named the file. Each exit code was read directly.

Read:

- `scripts/check-repo.py:180`: the size check walks `crates/` with `rglob`; a
  missing directory yields nothing. (#33 cites line 56 at `22c3b88`; the walk is at 57
  now.)
- `scripts/check-repo.py` lines 100-129, 132-153 and 156-161 at `e892b0f`: the links, the credentials and the line
  endings have no floor either.
- `scripts/check-repo.py` lines 230-249 at `e892b0f`: `main` passes when each list of problems is
  empty.
- The model of a floor: `crates/podssh-relay/tests/default_relay.rs:54`
  asserts that the sweep read more than 20 files.
  `scripts/check-scripts.py:152-155` already fails when it finds no script.
- The counts today: 216 tracked Rust files under `crates/`, 24 live Markdown
  files on disk, 827 tracked files, 11 shell scripts.

## Approach

1. Each scan counts the files that it read, and its check fails below a
   floor, with a message that names the count and the floor: Rust files under
   `crates/`, at least 100; Markdown files, at least 10; tracked files, at
   least 300; shell scripts, at least 5. Each floor is far below today's count
   and far above zero.
2. The floor is judged before the problems, so that a check cannot report
   `ok` for a scan that did not happen.
3. A plant in the same script: a mode `--plant-empty` runs the checks on an
   empty temporary directory and must exit 1. The control is the real tree,
   which must exit 0. CI runs both, as it does for the relay check
   (`.github/workflows/build.yml:196-221`).
4. With T-207: the size check also reads `scripts/`, with its own floor.
5. The checker of `TODO/` gets its own floor in its own change; this entry
   does not plan it.
6. docs/development.md, "Checks": one line on the floors.

## Prove

```sh
python scripts/check-repo.py                  # the real tree: each check reads its files, exit 0
python scripts/check-repo.py --plant-empty    # an empty tree: exit 1, each check names its floor
```

The first command exits 0 and prints each count; the second must exit 1.
Planted defect: set one floor to 0; `--plant-empty` then exits 0, and the CI
step must fail on that.

## Correction

2026-10-09: the credential check reads the tracked files outside `vendor/`,
377 of them today, not the 827 of the whole tree: a floor of 300 would be
close to the count, so it is 150. Since T-206 and T-224 the script has two
more checks, the pinned images (at least one Dockerfile) and the listeners
(at least 100 Rust files); each has its floor too.

## Done

2026-10-09, in the commit "Each repository check has a floor, and fails on
an empty tree".

- `scripts/check-repo.py`: each check counts the files that it read, judges
  its floor before its problems (100 Rust files, 10 Markdown files, 150
  tracked files, 5 shell scripts), and prints the count. `--plant-empty` runs
  the six checks on an empty git repository: it exits 1 when each failed, and
  0, naming the check, when one passed.
- `.github/workflows/build.yml`: a step after the checks, which fails unless
  `--plant-empty` exits 1. `docs/development.md`, "Checks": the floors.
- Prove: `python scripts/check-repo.py`: exit 0, with 265 Rust files, 43
  Markdown files, 377 tracked files and 13 shell scripts read.
  `python scripts/check-repo.py --plant-empty`: "each of the 6 checks failed
  on an empty tree", exit 1. Plant, restored: `MIN_SHELL_SCRIPTS = 0`:
  `--plant-empty` exited 0 and named "shell scripts are LF".

# T-224: The gate finds a listener in the source: a scan with an allow-list (GitHub #33)

**Source:** GitHub #33 (2026-10-08), part 2; a scan of this kind in
`willykeenan/warren:tests/network_audit.rs` and floors in
`l0ng-ai/tty7:.github/scripts/check-host-boundary.sh` (read in the report).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A rule of podssh for the client is: no listener, unless the user asks for it
and a probe at run time allows the bind. No step of the gate checks it. A
change that adds a `TcpListener::bind` to a crate passes each check, and only
a reviewer can see it.

## Premise

Read: the rule as written is rule 3 of `docs/architecture.md:132-145` (the
bind check of `podssh doctor` is the one exception), rule 3 of
`docs/target-environment.md:84-88`, and rule 2 of AGENTS.md, section 5. The
operator ruled on 2026-10-08 (`docs/decisions.md`): Q1 allows a local
listener when the user asks for it and a probe at run time allows the bind
(T-038, T-039, T-124, T-186, and `podssh agent` in T-034); Q10 allows a race
of relay hosts (T-220), more than one outbound connection for a moment, which
is not a listener.
`scripts/check-repo.py` lines 133-138 at `e1ba5ba` has four checks, and none reads a socket
call; `scripts/plant.sh` plants C and C++ only.

Measured with grep over `git ls-files 'crates/*'`: three files hold a
listener or a bind. `crates/podssh-cli/src/doctor/unix.rs:151` and line 226 at `22c3b88`
are the bind probes of `doctor`, which close at once and never listen
(`crates/podssh-cli/src/doctor/mod.rs:15-16`). The test servers are in
`crates/podssh-ws/tests/dial.rs:129` and
`crates/podssh-ws/tests/hostname_verification.rs:55`. No file uses
`UdpSocket`, `UnixListener` or `socket2`. The model of a sweep with a floor
that skips comments and test modules is
`crates/podssh-relay/tests/default_relay.rs:21-56`.

## Approach

1. A table, each row with a pattern, the rule that it protects ("no listener
   unless the user asks for it and a probe allows it"), and the files
   allowed: `TcpListener`, `UnixListener`, `UdpSocket`, `bind(` (with
   `libc::bind`), `listen(` and `socket2`. Allowed today: `bind(` in
   `crates/podssh-cli/src/doctor/unix.rs` only, and each pattern in the
   `tests/` directory of a crate (servers on 127.0.0.1 for tests). `listen(`
   is allowed in no source file today.
2. The scan reads each `.rs` file under `crates/` and skips comment lines
   (`crates/podssh-cli/src/doctor/mod.rs:15` names `bind()` in a comment). A
   floor comes first: the scan fails when it read fewer than 100 files (T-223).
3. A plant at each run: the same scan over a temporary tree with one
   `TcpListener::bind` in the `src/` of a library crate must report it, or the
   check fails as vacuous. The control: the real tree passes, with exactly the
   allowed hits.
4. Each listener that the ruling on Q1 allows joins the allow-list in the
   commit that adds it (T-038, T-039, T-124, T-186, T-034). Its row names the
   flag that asks for it and the probe that allows it. No such file exists
   yet. The scan reads no outbound call, so T-220 needs no row.
5. docs/development.md, "Checks": the scan and its table. A rule that still
   says "never a listener" (in docs/architecture.md, docs/target-environment.md
   or AGENTS.md) changes to the rule as ruled, in the same commit.

## Decision

Recommendation: a fifth check in `scripts/check-repo.py`, as #33 proposes. It
runs before any build, on the host and in the first step of CI, beside the
floors of T-223. A Rust test beside
`crates/podssh-relay/tests/default_relay.rs` lost: it runs only after a build,
and its sweep and its floor are easy to repeat in Python.

## Prove

```sh
python scripts/check-repo.py     # the floor, the plant found, the real tree with the allowed hits only
```

It exits 0 and prints the count of files read and the allowed hits. Planted
defect: add `let _l = std::net::TcpListener::bind("127.0.0.1:0");` to a file
under `crates/podssh-ws/src/`; the check must exit 1 and name the file and the
rule.

## Correction

2026-10-09: the measurement is older than the reverse road. Measured again
with `git grep` over the Rust files under `crates/` (265): outside a crate's
`tests/`, only `bind(` in `crates/podssh-cli/src/doctor/unix.rs` (twice);
in `tests/`, six files hold a server on the loopback (`podssh-ws`: `dial.rs`,
`hostname_verification.rs`, `caller_tls.rs`, `plain_loopback.rs`;
`podssh-relay`: `blocking_plain.rs` and `stand_in/mod.rs`). No file uses
`UnixListener`, `UdpSocket`, `listen(` or `socket2`. `scripts/check-repo.py`
had five checks before this one.

## Done

2026-10-09, in the commit "The repository check finds a listener outside its
allowance".

- `scripts/check-repo.py`, check 6: the table of patterns with the files that
  each may stand in outside `tests/`, the rule it protects, the floor of 100
  files, and a plant at each run (one `TcpListener::bind` in
  `crates/podssh-ws/src` of a temporary tree must be found). It prints the
  files read and the uses within the allowance.
- The documents already state the rule as ruled (`docs/architecture.md:132-145`,
  `docs/target-environment.md:84-88`, `AGENTS.md`, section 5): nothing to
  change there. `docs/development.md`, "Checks": the scan.
- Prove: `python scripts/check-repo.py`: exit 0, "265 Rust files read; 32
  uses of a listener's pattern within the allowance". Plant, restored:
  `std::net::TcpListener::bind("127.0.0.1:0")` appended to
  `crates/podssh-ws/src/lib.rs`: exit 1, and the check named the file, the
  line, each pattern (`TcpListener`, `bind(`) and the rule.

# T-244: Code comments break `AGENTS.md` rule 6, and some name files and facts that are wrong

**Source:** the reports of the writers of the record (2026-10-08), measured
again here; rule 6 of AGENTS.md, section 5.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Rule 6 forbids stop-sign markers, session history and line numbers of
documents in the code. The code has thousands of each kind. Some comments
also name files that do not exist, or state wrong facts, and a reader who
trusts them acts on a wrong fact.

## Premise

Measured with Python over the tracked files outside `vendor/`:

- The stop-sign marker (U+26D4) is on 3608 lines of 130 of the 227 Rust files
  (4694 times). It is also in `Cargo.toml` (13), three crate manifests,
  `crates/podssh-probe/facts/relay-facts.toml` (11), the comment lines of
  `crates/podssh-core/tests/fixtures/grammar.txt` (8), `scripts/dev.sh` (34),
  `scripts/ts-derp-prove.sh` (4), `scripts/check-scripts.py` (7),
  `scripts/check-relay-spec.py` (2) and `.gitattributes` (6). Other markers:
  U+26A0 (7, in podssh-transport), U+2B50 (3, in podssh-terminal), U+1F6D8
  (`scripts/dev-wsl.sh:130-139`).
- 340 markers are in string literals: 326 in tests, 14 in `src`, one of them
  in a message for users (crates/podssh-transport/src/backpressure/mod.rs line 157 at `e8bbd4d`).
- 266 lines in 42 code files hold a line number of a document; 188 lines in
  63 files name a work item of an earlier session (E02, E16).

Read, names of files that do not exist, at `f32334c`: docs/spec/06-cli.md
(`crates/podssh-cli/src/flags.rs` lines 3, 12 and 404-406, and four more
files); docs/TODO/cli/surface.md (`crates/podssh-cli/src/flags.rs` line 103,
`crates/podssh-cli/src/suggest.rs` line 9); docs/TODO/protocol/ssh-core.md
(`crates/podssh-terminal/src/window.rs` lines 42-44); docs/spec/01-relay-protocol.md
(`crates/podssh-core/src/irc/limits.rs` line 8,
`crates/podssh-probe/facts/relay-facts.toml` lines 3-5); a root RULES.md with lines
138-142 (crates/podssh-transport/src/lib.rs line 4 at `e8bbd4d`); check-todo.py
(`scripts/check-scripts.py` lines 12 and 25). The link to `SCP_FLAGS`
(`crates/podssh-cli/src/flags.rs` line 110) names a constant that does not exist.

Read, wrong facts:

- crates/podssh-transport/src/error.rs lines 18-25 at `e8bbd4d` and lines 38-78 cite rows of the
  relay's document by line, each 35 lower than the row in the pinned copy
  (line 135 there is line 170 of
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`).
- crates/podssh-transport/src/backpressure/mod.rs lines 4-22 at `e8bbd4d` gives the reverse
  path's backpressure (1011, 1 MiB, the frame dropped: line 185 of that copy)
  as the forward path's. For the forward path, `docs/relay.md:266-278` says
  1013 at 2 MiB, with no frame dropped. The comment on the SSH window said
  the same as `backpressure/mod.rs` (`crates/podssh-ssh/src/run.rs` lines
  25-28 at `80f20bf`); T-024 corrected it.
- The comment "THE BUILD RULE" in `Cargo.toml` lists the no-C crates without
  `podssh-relay`; `crates/podssh-cli/Cargo.toml` line 3 at `f32334c` names a `--doctor` flag.

## Approach

1. Remove the four markers, each with its space, from the code, the
   manifests, the scripts, `.gitattributes` and the IRC fixture's comments.
   Remove no word and no line, so each comment keeps its meaning and each
   file its length (rule 5). Change the test messages with the code.
2. Replace each line number of a document with its section's name or the
   fact, and each name of an earlier work item with what it means.
3. Replace each missing file with the document that holds the fact now
   (`docs/cli.md`, `docs/relay.md`, `docs/terminal.md`, `TODO/RULES.md`).
   `SCP_FLAGS` becomes plain text until `scp` has flags (T-139).
4. Correct the wrong facts: the forward path's backpressure (with T-201),
   `podssh-relay` in the list of `Cargo.toml`, `doctor` as a command.
5. A check in `scripts/check-repo.py` refuses, in each code file (`.rs`,
   `.toml`, `.sh`, `.py`, `.gitattributes`, fixture comments), the four
   markers, a line number of a document (`NAME.md:N`), and a path under
   docs/spec/ or docs/TODO/. A floor first (100 code files, as in T-223), and
   a plant at each run. Documents stay out: `AGENTS.md` names the marker.
6. Work crate by crate; each commit passes the gate.

Pitfalls: `crates/podssh-core/tests/fixtures/grammar.txt` keeps its CRLF
bytes (git stores it with `-text`); edit it as bytes. Change the line endings
of no file.

## Prove

```sh
python scripts/check-repo.py      # the new check: the floor, the plant found, no marker in code
RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links' cargo doc --no-deps --locked
sh scripts/dev.sh check           # the gate, with the changed messages
```

Each command exits 0; the second shows no link to a missing item. Planted
defect: put one U+26D4 into a comment of `crates/podssh-ws/src/frame.rs`;
`check-repo.py` must exit 1 and name the file and the line.

## Correction

2026-10-09, measured again after T-082 removed `podssh-transport`: 3,301
markers on 2,727 lines of 117 code files; 47 lines with a line number of a
document, 147 with the name of an earlier work item, and 18 with a path under
docs/spec/ or docs/TODO/, 201 lines in all, 132 of them in `podssh-cli`. The
U+26A0 markers went with `podssh-transport`. The tests of the record's
checker (`crates/podssh-todo`) hold Markdown locations such as
"TODO/INDEX.md:3" as data: the check of step 5 leaves that crate out.

"THE BUILD RULE" of `Cargo.toml` names `podssh-relay` already. Three
declarations of `[workspace.dependencies]`, `chacha20`, `cipher` and
`poly1305`, served the SSH client that was written by hand before russh, and
no crate uses them: they went with their comment, which named a file that is
gone.

## Done

2026-10-09, in the commits "The code carries no stop-sign markers" (step 1)
and "Code comments name what they mean, and a check keeps the rule"
(steps 2 to 5).

- Step 1: the 3,301 markers, as the state above says.
- Steps 2 and 3: 291 lines of 59 files. In `podssh-cli`, 207 lines: 200
  drafted by a helper that read the code and the documents, each draft checked
  against the current line and each cited section and quote against the
  document, and 7 more here; 84 lines of the other crates and the scripts were
  written here. A line number of a document became its section (`docs/cli.md`,
  "Exit codes"; `docs/architecture.md`, "Design rules"; `docs/development.md`,
  "Rules for tests"; `docs/decisions.md`, "Product"), or the fact; each name
  of an earlier work item became what it meant (the exit codes, the relay's
  facts, the TLS connector, the manual, the `--timeout` gate, IRC,
  Tailscale...); each missing file became the document that holds the fact
  now. No line of a comment was added or removed.
- Step 4: the forward path's backpressure went with `podssh-transport`
  (T-082); `podssh-cli`'s description names the command `doctor`, and the
  comments that named `--doctor` and `doctor --exit-codes`, neither of which
  exists, name `Fault::name` and the table; `SCP_FLAGS` is plain text; the
  three unused declarations of `Cargo.toml` are gone. The review found more:
  the remedies of two prompts named `--accept-new` and `--relay`, which are
  not flags of podssh (now `-o StrictHostKeyChecking=accept-new`, and
  `--relay-host` or `PODSSH_RELAY`); `podssh ts HOST` said that the SSH
  client is not built (it is; an SSH session over the tailnet is not); and
  the Prove's `cargo doc` found eight intra-doc links to items that do not
  exist or are ambiguous, in `podssh-core`, `podssh-relay`, `podssh-ssh` and
  `podssh-terminal`, two of them stating wrong facts (`Replies::Unknown`,
  `PayloadPlan::due`).
- Step 5: `scripts/check-repo.py`, check 7: no code file holds a marker, a
  line number of a document, or a path under docs/spec/ or docs/TODO/; the
  record's checker, one test of `podssh-probe` and `check-repo.py` itself may
  name the last two. 334 code files read (floor 100); three planted lines,
  one of each kind, must be found at each run.
- `docs/development.md`: the check. `docs/STATUS.md`: the repository checks.
- Prove: `python scripts/check-repo.py`: exit 0, "334 code files read; 3
  planted lines found". Plant, removed: one U+26D4 in a comment of
  `crates/podssh-ws/src/frame.rs`: exit 1, naming the file and the line.
  `RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links' cargo doc --no-deps
  --locked`: no broken link. `sh scripts/dev.sh check`: green in 18 min, each
  of the nine steps, interop 103 of 103. `cargo test --no-fail-fast`: 823
  passed before the remap of the record.

# T-245: The box refuses each bind, but sandbox A allows an AF_UNIX bind

**Source:** the report of the writer of `TODO/pipe.md` (2026-10-08); the
measurement of sandbox A (T-001); the operator's ruling on Q1
(`docs/decisions.md`).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** blocked

## Problem

The box like the target sandbox refuses each bind, of each family. Sandbox A,
where podssh was measured, refuses a bind of AF_INET and allows one of
AF_UNIX. The ruling on Q1 lets podssh listen when a probe allows the bind, so
the box must show both cases: a probe that allows the bind, and one that
refuses it. Today it shows only the second.

## Premise

Read:

- `scripts/box/seccomp.json:5-10`: `bind` fails with EACCES for each socket,
  whatever its family.
- `docs/STATUS.md:279`: in sandbox A, `bind` is refused for AF_INET and
  allowed for AF_UNIX. In the KTM report (read there), `doctor` printed
  `Permission denied (os error 13)` for AF_INET, and "bound" for an AF_UNIX
  path and for the abstract namespace.
- `docs/target-environment.md:25`: for listening, "The probe did not measure
  it".
- `scripts/box/probe.sh:86-92` checks an AF_INET listen only, and expects the
  refusal. `doctor` probes both families
  (`crates/podssh-cli/src/doctor/host.rs:20-21`).
- A seccomp filter compares the arguments of a call as numbers. It cannot read
  the address that `bind` gets through a pointer, so it cannot refuse AF_INET
  and allow AF_UNIX.

## Approach

1. Two profiles of the box. `sandbox-a`, the new default: an AF_INET bind
   fails with EACCES; an AF_UNIX bind (a path, and the abstract namespace)
   succeeds. `strict`, the box of today: each bind fails.
2. For `sandbox-a`: drop the `bind` rule from that profile's seccomp file, and
   refuse a TCP bind with Landlock (its TCP bind right, Linux 6.7 or later; to
   confirm), set by a small helper of the box before podssh starts. The helper
   belongs to the box, not to podssh. UDP stays refused at `socket`, as now.
3. Probe the host kernel for the Landlock version first. When it is too old,
   stop with a message: no silent fall back to `strict`.
4. `scripts/box/probe.sh`: one more property, an AF_UNIX bind (a path and the
   abstract namespace), bound in `sandbox-a` and refused in `strict`. The
   AF_INET check stays.
5. `scripts/test_in_box.sh` takes the profile (default `sandbox-a`). Both
   profiles run `scripts/sandbox-check.sh`, and the two bind lines of
   `doctor` must match the profile.
6. The entries that listen after a probe (T-038, T-039, T-124, T-186, T-034)
   test both profiles: the listener works in one, and the refusal is clear in
   the other. T-213 runs both profiles in CI.
7. `docs/target-environment.md` (the row "Listening") and the box section of
   `docs/development.md` state the measured facts and the two profiles.

Pitfall: do not set the Landlock scope for abstract sockets; sandbox A allows
them.

## Decision

Recommendation: Landlock for the AF_INET refusal. It refuses a TCP bind with
EACCES, as sandbox A does, and leaves AF_UNIX alone. A seccomp filter with a
supervisor that reads the address (user notification) lost: it needs a
process outside the box. A box with no bind rule lost: it allows the AF_INET
bind that sandbox A refuses.

## Prove

```sh
sh scripts/test_in_box.sh --profile sandbox-a path/to/podssh   # AF_UNIX bound, AF_INET refused
sh scripts/test_in_box.sh --profile strict path/to/podssh      # each bind refused
```

Each run exits 0, and the probe prints `match` for both bind properties of
its profile. Planted defect: run `sandbox-a` with the Landlock rule removed;
the probe must report `DIFFERS` for the AF_INET bind, and exit 1.

## Blocker

The operator: on hold since 2026-10-09 (`docs/decisions.md`, "Entries on
hold"). A session skips this entry until the operator lifts the hold.

# T-246: `scripts/dev.sh` excludes each file named `agents.md` from the container copy, with no reason given

**Source:** a finding of the writer of `TODO/robustness.md` (2026-10-08),
while reading `scripts/dev.sh`.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

`sh scripts/dev.sh check` copies the tree into a container without the files
named `agents.md`, and no comment says why. On Windows, where file names have
no case, the pattern can also match the root `AGENTS.md`. Then the gate in the
container reads another tree than CI does: a citation of `AGENTS.md` in
`TODO/` fails only there, and the ids that `AGENTS.md` names go unchecked
there.

## Premise

Read:

- `scripts/dev.sh` line 115 at `188f327` puts `agents.md` in `EXCLUDES`. The comments above it
  (lines 66-98) give a reason for each other pattern, not for this one. The
  line is in the first public commit, `9a03102`.
- `.gitignore` (lines 16-18) keeps a root `/agents.md` out of git, as "a
  lowercase duplicate of AGENTS.md created by the filesystem".
- The record's checker reads `AGENTS.md` for ids, and drops a missing file
  with no word (`crates/podssh-todo/src/refs.rs:43-48`). It accepts
  `AGENTS.md` as a cited root file (line 20). The gate runs the checker in the
  container (`scripts/gate.sh:250-257`). 22 lines of `TODO/` cite `AGENTS.md`.
- The area file that was TODO/agents.md is `TODO/machine.md` now.

Not known: whether `wsl-toolkit run --exclude` matches a pattern at any depth,
and with or without case.

## Approach

1. Measure: `sh scripts/dev.sh run -- 'ls -la /work/AGENTS.md /work/TODO'`.
   Plant a file docs/agents.md for one run, and see whether it reaches
   `/work`. Read the rules of `--exclude` in the help of `wsl-toolkit run`.
2. Remove `agents.md` from `EXCLUDES`: git already keeps a lowercase copy out,
   and the container must see the tree that CI sees.
3. If a pattern must stay, anchor it to the root, and give the reason in the
   comment above it.
4. In `scripts/gate.sh`, before the record's checker runs: fail when
   `/work/AGENTS.md` is missing, so a missing root file fails loudly.
5. `docs/development.md` lines 192-193 at `188f327` list what the containers do not get; name
   each excluded pattern there.

## Prove

```sh
sh scripts/dev.sh run -- 'test -f /work/AGENTS.md && test -f /work/TODO/machine.md'
sh scripts/dev.sh check     # the record's checker passes in the container too
```

Both exit 0. Planted defect: add `AGENTS.md` to `EXCLUDES`; the new step of
the gate must fail before the record's checker runs.

## Correction

2026-10-09, measured with `sh scripts/dev.sh run`: the pattern did not take
the root `AGENTS.md`, which reached `/work` (13,848 bytes); it matches a file
named `agents.md` in lower case at any depth, as a planted docs/agents.md
did not reach `/work`. So the gate read the same `AGENTS.md` as CI; the
pattern could only hide a lower-case `agents.md`, which this file system
cannot hold beside `AGENTS.md`, and which git ignores at the root.

## Done

2026-10-09, in the commit "The container gets the tree that CI gets, and the
gate needs AGENTS.md".

- `scripts/dev.sh`: `agents.md` is no longer in `EXCLUDES`.
- `scripts/gate.sh`: the step "the tree has AGENTS.md" (`test -f
  AGENTS.md`) before the record's checker.
- `docs/development.md`: each excluded pattern, with its reason.
- Prove: `sh scripts/dev.sh run -- 'cd /work && test -f AGENTS.md && test -f
  TODO/machine.md'`: exit 0. `sh scripts/dev.sh check` on this tree: each step
  exited 0 but the one of clippy, which the image's clippy 1.99 failed on a
  loop over one element in a test of `podssh-probe` (repaired in the commit
  "clippy 1.99 of the build image gives no warning"); the new step "the tree
  has AGENTS.md" exited 0, before the record's checker; interop 103 of 103.
  Plant, restored: `AGENTS.md` added to `EXCLUDES`: the same test in the
  container exited 1, as the gate's new step would.

# T-247: `podssh-cli` declares dependencies that it does not use

**Source:** the reports of the writers of the record (2026-10-08), measured
again here.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The binary crate declares four library crates that its code does not use, or
uses in an example only. Each one is built with the binary, enters each check
of the dependency graph (T-216, T-217), and tells a reader that `podssh` uses
it. Nothing stops the list from growing.

## Premise

Measured with grep over the `src`, `tests` and `examples` of `podssh-cli`:

- `podssh-terminal` (`crates/podssh-cli/Cargo.toml` line 33 at `cc386ce`) and `podssh-probe`
  (line 31): no use at all.
- `podssh-core` (line 30) and `podssh-transport` (line 34): used only by the
  example `crates/podssh-cli/examples/live_irc.rs` and its module
  `crates/podssh-cli/examples/live_irc/support.rs`.
- The crate has no build script, and no check in the repository looks for
  unused dependencies.

Read: `libc` (line 44) is used only in code under `cfg(unix)`
(`crates/podssh-cli/src/ssh/tokens.rs:237`, `crates/podssh-cli/src/ssh/tokens.rs:254`,
`crates/podssh-cli/src/ssh/resolve.rs:140`,
the module of `crates/podssh-cli/src/doctor/unix.rs`). T-060 decides whether a
command uses `podssh-probe`.

## Approach

1. Remove `podssh-terminal` and `podssh-probe` from the dependencies. The
   commit that uses one again (M5, T-060) adds it back.
2. Move `podssh-core` and `podssh-transport` to the dev-dependencies: an
   example can use a dev-dependency, and the binary does not declare them.
3. Move `libc` to the dependencies for Unix only, as
   `crates/podssh-relay/Cargo.toml:60` does; else the lint of step 4 fails on
   Windows.
4. The check: `#![cfg_attr(not(test), deny(unused_crate_dependencies))]` in
   `crates/podssh-cli/src/lib.rs`. rustc then refuses a dependency that the
   library does not use, in each build, with no new tool.
5. Update `Cargo.lock` in the same commit; the gate builds with `--locked`.

## Decision

Recommendation: the lint of rustc. It runs in each build and each test run,
on Linux and Windows, and the gate already builds this crate. cargo-machete
lost: it is one more tool, and it reads text, so it can miss a use through a
macro. cargo-udeps lost: it needs nightly Rust.

## Prove

```sh
cargo build --locked -p podssh-cli              # the lint passes: each dependency is used
cargo build --locked -p podssh-cli --examples   # the example builds from the dev-dependencies
cargo tree -p podssh-cli -e normal --depth 1    # none of the four crates is a normal dependency
```

Each command exits 0, also on Windows. Planted defect: add `podssh-terminal`
back to the dependencies; the first build must fail with
`unused_crate_dependencies`.

## Correction

2026-10-09: `podssh-transport` went with T-082, and the IRC example uses
`podssh-core`, `podssh-relay` and `podssh-ws`. Measured again over `src`:
`podssh-probe`, `podssh-terminal` and `serde` have no use (`serde_json` needs
no `serde` beside it), `podssh-core` serves the example only, and `libc`
serves code for Unix only, also in `crates/podssh-cli/tests/keygen.rs`,
under `cfg(unix)`.

## Done

2026-10-09, in the commit "podssh-cli declares only the dependencies that it
uses".

- `crates/podssh-cli/Cargo.toml`: `podssh-probe`, `podssh-terminal` and
  `serde` removed; `podssh-core` a dev-dependency (the example); `libc` a
  dependency for Unix only. `Cargo.lock`: three lines fewer.
- `crates/podssh-cli/src/lib.rs`: `#![cfg_attr(not(test),
  deny(unused_crate_dependencies))]`.
- Prove: `cargo build --locked -p podssh-cli`: exit 0. `cargo build --locked
  -p podssh-cli --examples`: exit 0. `cargo tree -p podssh-cli -e normal
  --depth 1`: none of the removed crates. `cargo test --no-fail-fast`: 814
  passed, 0 failed. `cargo clippy --all-targets -p podssh-cli -- -D
  warnings`: exit 0. Plant, restored: `podssh-terminal` added back: the build
  failed (exit 101) with "extern crate `podssh_terminal` is unused in crate
  `podssh_cli`". Windows is this machine; the Windows job of CI builds it too.

# T-249: A cited line that moved still exists, so the checker does not see a stale citation

**Source:** the session of 2026-10-08 that wrote this record (T-204). One
pass of edits to ten documents moved 255 citations of `TODO/`, and 12
citations of `docs/ROADMAP.md` were already one or two lines off, with no
failure.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

An entry cites a document or a source file at a line. When a line is added
above the cited line, the citation names another line, and
`cargo todo check` still passes. A reader then reads the wrong lines, and
starts the work from a false premise.

## Premise

- Read: `citations` (`crates/podssh-todo/src/refs.rs:94-137`) tests that the
  path exists with its exact case, and that the last line is not past the end
  of the file. It does not test what the line says.
- Measured on 2026-10-08: a script outside the repository moved the
  citations of `TODO/` after edits to ten documents, by a line diff of each
  document. It moved 255 citations, and listed the ones inside a changed
  block for review. Before that pass, 12 citations of the roadmap were stale
  from an earlier insertion; only a reading of each cited line found them.

## Approach

1. `cargo todo remap FILE...`: compare each file with its version in `HEAD`
   (`git show HEAD:FILE`), make a line diff with no new dependency, and move
   each `FILE:N` and `FILE:N-M` in `TODO/` by it. List a citation inside a
   changed block for review, and do not move it. Say so when `git` is
   missing; `check` does not need `git`.
2. A quote check in `check`: when an entry quotes the cited line in the same
   sentence (`` `FILE:N` says "TEXT" ``), the text must occur in the cited
   lines. Writers quote the lines that a claim depends on.
3. `TODO/RULES.md`: after an edit of a document or a file that entries cite,
   run `cargo todo remap` on it in the same change.
4. Plants for both in `crates/podssh-todo/tests/`, as for each other check.

## Decision

Recommendation: the remap writer and the quote check. The remap removes the
work by hand that left the 12 citations stale; the quote check guards the
claims that matter. A hash of each cited line, written into the entry, lost:
it makes the entries hard to read and to write.

The session that built it (2026-10-08) made these calls:

- **When.** Done after T-005 and before the other entries of M3: the work
  order puts the `none` entries between milestone entries, and each later
  change needs its citations moved. T-005 alone moved 69 by hand, and a
  second edit after a first remap moved some of them twice.
- **A second run is safe.** A line of a document is rebuilt from the same
  line in `HEAD` (the same text with the numbers of each citation set aside,
  also of the files that the run does not move), so a run after a second
  edit starts from `HEAD`'s numbers, not from the numbers of the first run. Moving from the numbers in the working tree lost: it moves a citation
  again on each run. A citation that cannot move keeps the numbers that it
  has now, so a citation that a person moved by hand stays.
- **All documents, and the bare `:N`.** The remap moves citations in `docs/`
  and the root documents too, and a bare `:N` that follows a citation of the
  file in its paragraph (the record writes `` `FILE:12` and `:40` ``). Only
  `TODO/`, as the Approach says, lost: a stale citation in `docs/` misleads
  as much.
- **A line diff of its own** (`crates/podssh-todo/src/diff.rs`): the longest
  common subsequence after the common head and tail, with no dependency.

## Prove

```sh
cargo test -p podssh-todo --test remap   # a line added above a cited line moves the citation; a change inside a cited range is listed
cargo test -p podssh-todo --test plants  # a quote that the cited line does not hold is found
cargo todo remap docs/ROADMAP.md         # on a clean tree: nothing moves
```

Planted defects: add a line above a cited line and skip the remap, then
change a quoted line; each test that guards it fails.

## Done

2026-10-08, in the commit "podssh-todo: remap moves the citations of an
edited file; a quote must hold". Measured on Windows:

- `cargo test -p podssh-todo`: 60 passed: 11 unit tests (4 of the line
  diff), 32 plant tests (the control and 31 plants, among them a quote that
  its line does not hold, and a quote over two lines), 9 tests of the
  remap, 7 tests of the writer, and the test of this record.
  `cargo clippy -p podssh-todo --all-targets -- -D warnings`: no warning.
- Planted: a remap that never moves fails 7 of the 9 remap tests (the two
  that pass expect no move); a quote check that never fires fails both quote
  tests; a key that sets aside only the numbers of the moved file fails the
  test of a line that cites two files.
- On the real edits of `d272ebb`, in a worktree at its parent with only the
  edited files taken from it, one run of `cargo todo remap` with the six
  files moved 67 citations and listed 11 for review. The result is the same
  as the citations of `d272ebb` except for those 11, where `d272ebb` has the
  moves made by hand. (One run moves each file of a line at once, so this
  measurement does not depend on the key of the two-file test.)
- `cargo todo remap docs/ROADMAP.md`: "moved 0 citations; 0 to review".
- `TODO/RULES.md`, `AGENTS.md` (rule 11) and `docs/development.md` name the
  command.
- 2026-10-08, later, found while T-007 used it: 54 citations were listed for
  review, most of them long ranges with one changed line inside, and their
  numbers were left stale. Now a range moves by its ends, and is listed for
  review when a line inside it changed; only a changed single line or end
  stays where it was. Also, the common tail of a diff took the closing `}`
  of a cited test for the `}` of tests added after it; each unchanged line
  now takes the earliest place that the same text allows. Each repair has a
  test that fails on the old code (`cargo test -p podssh-todo`: 12 unit
  tests, 10 remap tests).

# T-254: `cargo todo check` passes when a cited file was edited and `remap` was not run

**Source:** the session of 2026-10-09 (T-063). 45 citations of `docs/STATUS.md` named the wrong
rows, one or two lines off, with no failure.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

T-249 gave the record `cargo todo remap`, which moves the citations of an edited file. It runs
only when the writer remembers it. When it is forgotten, each citation of the file still names a
line that exists, so `cargo todo check` passes, and the citations name other lines from then on.

## Premise

Measured on 2026-10-09: rows were inserted into `docs/STATUS.md` by earlier changes (the command
table, then a row of the doctor) without a remap of that file. 45 citations of it named a
neighbouring row: the entries of IRC named the row of `podssh-cli` instead of `podssh-core`, and
those of Tailscale the row of `podssh-core`. Each one was found by tracing its line through the
history of its file to the row that it named when it was written. The check of a cited line
(`crates/podssh-todo/src/refs.rs`) tests that the line exists; a quote is checked only where an
entry quotes.

## Approach

1. `cargo todo check` asks git for the files that differ from `HEAD` (`git diff --name-only
   HEAD`), runs `remap` on them without writing, and reports each citation that would still move,
   with the command that moves it.
2. A citation that `remap` lists for review is not a failure: only a person can decide it, and
   `remap` lists it already.
3. With no git, no repository or no `HEAD`, the check is skipped, and the rest of `check` needs no
   git, as before.
4. A test with the texts of `HEAD` given, as the tests of `remap` do; a plant on this repository.
5. Refuse a range that ends before it starts, and a line 0: the repair of this entry once left
   `155-154`, which the check of a cited line passed.

## Decision

2026-10-09: `check` uses git when it can, which T-249 kept out of `check`. A check that runs only
when a writer remembers to run it is the defect itself, and `check` is what the procedure runs
before each commit. Lost: a hook before each commit, which a fresh clone does not install; a
second command, which is as easy to forget as `remap`. In CI the committed tree equals `HEAD`, so
the check finds nothing there; it guards the change before its commit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-todo --test remap -- an_edit_with_no_remap_is_found_by_the_check
cargo test -p podssh-todo
cargo clippy -p podssh-todo --all-targets -- -D warnings
```

Plant on this repository: one line added at the top of a cited file, with no remap; `cargo todo
check` must exit 1 and name each citation of it, and exit 0 again when the file is restored.

## Done

2026-10-09, in the commit "cargo todo check finds a citation that a forgotten remap left".

- `crates/podssh-todo/src/remap.rs`: `changed_since_head` (the files that differ from `HEAD` and
  exist; `None` when git cannot say). `crates/podssh-todo/src/check.rs`: `check` passes them to
  `check_with`, which runs `remap` without writing and reports each citation that would move:
  "cites FILE N -> M, as FILE changed since HEAD: run `cargo todo remap FILE`".
- `crates/podssh-todo/src/refs.rs`: a citation whose range ends before it starts, or that names
  line 0 at `4e817d7`, is a problem; two plant tests.
- `TODO/RULES.md` (citations), `docs/development.md` (checks) and the rows of `podssh-todo` and of
  the work record in `docs/STATUS.md` say so.
- Prove: `cargo test -p podssh-todo --test remap -- an_edit_with_no_remap_is_found_by_the_check`:
  1 passed (three citations found with the command; none with no git; none after the remap).
  `cargo test -p podssh-todo`: 65 passed. `cargo clippy -p podssh-todo --all-targets -- -D
  warnings`: no warning. `cargo test --no-fail-fast`: 795 passed, 0 failed, 7 ignored.
- Plants: a range `4-2` and a line `0`, planted in the record of
  `crates/podssh-todo/tests/plants.rs`, are found.
  `// planted` added at the top of `crates/podssh-ws/src/names.rs` with no remap: `cargo
  todo check` exited 1 with 6 problems, one for each citation of the file, each naming `cargo todo
  remap crates/podssh-ws/src/names.rs`; restored, it exited 0. While this entry was written, the
  check found its own missing remap of `crates/podssh-todo/src/refs.rs`.

# T-258: Line numbers written as plain text in the record are not moved

**Source:** the format of the code in T-215 (2026-10-09): `cargo todo remap`
moved each citation in backticks, and none written as plain text.
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The record moves a citation `FILE:N` and a bare `:N` after one when FILE
changes (`TODO/RULES.md`, "Citations move with their documents"). A line
number written as plain text after a citation ("line 179", "lines 178 and
334") is neither moved nor checked, so it can name a line that holds other
code. Some of them are readings at a commit that the entry names, and are
right for that commit only.

## Premise

Measured on 2026-10-09 with a scan of `TODO/` and `docs/`: 42 numbers
written as plain text follow a citation of a Rust file that the format of
T-215 changed. `crates/podssh-todo/src/refs.rs` reads citations in backticks
only.

## Approach

1. A check in `cargo todo check`: a plain "line N" or "lines N-M" after a
   citation of a file of the tree, with no "at `COMMIT`" after it, is a
   problem that asks for the bare `:N` form, which `remap` moves and `check`
   reads.
2. Rewrite the 42 and any others that the check finds: a reading at a named
   commit becomes a history form ("lines N-M at `COMMIT`"); a reference to
   the current tree becomes a bare `:N`, its number read again at the line.
3. A plant: a plain "line 3" after a citation must be found.

## Prove

```sh
cargo test -p podssh-todo
cargo todo check
```

Both pass, and the plant is found.

## Correction

2026-10-09: over the whole of `TODO/`, the check finds 119 numbers in plain
text after a citation, not 42; the scan of the Premise read the Rust files
that T-215 changed only. And a bare `:N` was moved by `remap` but read by
no check: `citation` takes a span that starts with `:` for no citation. The
check reads it now, in the file that the last citation of its paragraph
names, as `remap` does.

## Done

2026-10-09, in the commit "The record's checker finds a line number in plain
text after a citation, and reads each bare :N".

- `crates/podssh-todo/src/numbers.rs`: in each paragraph of `TODO/`, a
  "line N" or "lines N-M" (also "lines 3 and 5") outside code spans and
  quotes, after a citation, with no "at `COMMIT`" after it and no reading at
  a named commit before it, is a problem that names the two forms. Each
  bare `:N` names a line of the file that the last citation of its
  paragraph names. Code spans are read as CommonMark reads them, so a span
  of two backticks that shows a citation cites nothing.
- The 119 numbers, rewritten by a script: each became the history form
  "at `COMMIT`" of the commit that wrote it (the first commit whose file
  holds its text: 92), or a bare `:N` at today's line (27), when its entry is
  not done, its paragraph cites that one file, and each of its lines is the
  same now as then. By hand: the four call sites of T-220, written as bare
  numbers, are bare citations now beside the lines that moved with them.
- `TODO/RULES.md`: the rule, with its two forms. `docs/development.md`,
  `docs/STATUS.md` and `TODO/PROGRESS.md`: the check, and the count of the
  checker's tests.
- Prove: `cargo test -p podssh-todo`: 71 passed (15 unit tests, 37 plant
  tests). `cargo todo check`: the record agrees; before the rewrite, 119
  problems, the same 119 as the script's own scan, less one that a quote
  over two lines holds. Plants: "line 5" after a citation is found; `:9`
  after a citation of a file of 5 lines is found; "line 9 at `0123abc`" and
  `:4` pass. A character of more than one byte before a number made the
  first version panic; a test holds it now. `cargo clippy --all-targets -p
  podssh-todo -- -D warnings`: no warning.

# T-259: One dropped connection fails a live TLS test, and with it the gate

**Source:** the gate's run of 2026-10-09 after the markers of T-244: the step
`libs` failed once, and passed when it ran again with no change.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The live tests of `crates/podssh-ws/tests/live_handshake.rs` run in the gate
and in CI, each with one TCP connection and one handshake to the relay. The
relay's side drops connections at random (T-255), so one drop fails the
test, the step `libs`, and the whole gate, for no defect of podssh.

## Premise

Measured on 2026-10-09: in `sh scripts/dev.sh check`, the test
`the_negotiated_parameters_are_ones_this_provider_implements` failed with
"tls handshake eof" (`crates/podssh-ws/tests/live_handshake.rs` line 172 at `e3ea638`); the
step `libs` alone, run again at once, passed. Each live test of the file
opens its own connection, with no second attempt
(`crates/podssh-ws/tests/live_handshake.rs:31`, `live_enabled`).

## Approach

1. One helper in the file connects and shakes hands: up to three attempts,
   each bounded, when an attempt ends in an I/O error before the handshake
   reached a verdict (EOF, reset, a time limit); each failed attempt is
   printed.
2. A verdict is never retried: a refused certificate, a wrong name, or a
   suite that the provider does not offer fails at once, as now. So the
   plants still fail the first time.
3. `docs/STATUS.md`: the live TLS tests, and their attempts.

## Prove

```sh
cargo test -p podssh-ws --test live_handshake
cargo test -p podssh-ws --test hostname_verification
```

Each passes. Planted defect: a helper that retries a refused certificate
must make the wrong-hostname plant pass on its third attempt; the test that
counts the attempts on a verdict must fail.

## Done

2026-10-09, in the commit "A live TLS test tries a dropped connection again,
and never a verdict".

- `crates/podssh-ws/tests/live_handshake.rs`: `dial`, the one way that each
  live test connects: TCP and the handshake, each bounded, in up to three
  attempts (`with_attempts`), with a pause of 1 s; an attempt that ended in
  EOF, a reset, an abort, a refusal of the connection, a broken pipe or a
  time limit is printed and tried again; `InvalidData`, the form in which a
  refused certificate or name arrives, is a verdict and is returned at once.
- `only_an_attempt_that_broke_is_tried_again`, with no network: a verdict
  is tried once, and each kind of break three times.
- `docs/STATUS.md`: the row of `podssh-ws`.
- Prove: `cargo test -p podssh-ws --test live_handshake`: 6 passed (the five
  live tests against the relay, and the offline one). `cargo test -p
  podssh-ws --test hostname_verification`: 3 passed. Plant, restored:
  `InvalidData` made a break: the offline test failed ("InvalidData: 3
  attempts"). In the build image, the steps `lint` and `libs`: green.

# T-260: The open pull requests of Dependabot, #37 to #42

**Source:** the pull requests of Dependabot (T-205), open on 2026-10-09.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Six pull requests of Dependabot waited: none was applied or closed, so the
updates they carry went nowhere, and two of them would change the fork in
`vendor/tailscale-rs`, which follows its own patches.

## Premise

Read on 2026-10-09 with `gh pr list` and `gh pr diff`:

- #37: `actions/checkout` from 5 to 7, in each workflow (12 uses). The notes
  of v7 change the checkout of a fork's pull request for
  `pull_request_target` and `workflow_run`, which no workflow here uses.
- #38: the group of minor and patch updates: `libc` 0.2.190, `tokio`
  1.53.2, `zerocopy` 0.8.62, in `Cargo.lock` only. Each check of its CI
  passed, the steps of each declared minimum Rust too.
- #39 (`cipher` 0.5) and #42 (`chacha20` 0.10): declarations of
  `[workspace.dependencies]` that no crate used, which T-244 removed.
- #40 (`blake2` 0.11) and #41 (`itertools` 0.15): `vendor/tailscale-rs/Cargo.toml`.

## Approach

1. Apply #38 and #37 as the operator's own commit (`docs/development.md`,
   "Updates"), and run the tests and CI.
2. Close #39 and #42: what they update is gone. Close #40 and #41: the fork
   takes no update of Dependabot's. Each with a comment that says why.

## Decision

The fork's major updates are closed by hand, as they come. A rule in
`.github/dependabot.yml` that leaves `vendor/` out lost for now: whether
Dependabot honours one for cargo is not measured here, and a rule that
does nothing reads as a guard.

## Prove

```sh
cargo test --no-fail-fast --locked
gh pr list -R Azathothas/podssh --state open --author app/dependabot
```

The tests pass, CI passes on the push, and none of the six is open.

## Done

2026-10-09, in the commit "Dependabot's updates of the crates and of the
checkout action".

- `Cargo.lock`: #38, applied with `git cherry-pick --no-commit`.
- `.github/workflows/*.yml`: `actions/checkout@v7`, each of the 12 uses.
- Prove: `cargo test --no-fail-fast --locked`: 824 passed, 0 failed, 20
  ignored. The six pull requests are closed after the push, each with its
  reason; #37 and #38 name the commit that applied them.

# T-266: The vi check of the Windows console job fails at random

**Source:** CI, the run of `cce8dce` (2026-10-09): the job `windows` failed
one check of `scripts/interop-conpty-msys2.py`, with a change that touched
no code of the client.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The check "vi edits and saves a file" of `scripts/interop-conpty.py` failed
once in CI (13 of 14 checks), and passed in the runs before and after with
the same client. A check that fails at random hides a real failure.

## Premise

Read: the check sends `vi FILE`, waits a fixed 2 s, then types its text,
Escape and `:wq` (`scripts/interop-conpty.py:231-237` at `cce8dce`). The
failed run's screen shows the typed text on the line after the command, as a
shell's echo shows it, and no output of the `cat` and the marker after it:
vi was not ready when the keys came, on a runner where it started in more
than 2 s.

## Approach

Wait for vi's own screen, its status line of a new file (`[New]`, or `[New
File]` in an older vim), up to 30 s, before typing; and fail the check,
with the screen, when it never comes.

## Prove

```sh
python scripts/interop-conpty-msys2.py --install
```

CI's job `windows` passes the check at the push of the repair, and at the
pushes after it.

## Done

2026-10-10. `scripts/interop-conpty.py`: the check waits for vi's status
line of a new file, up to 30 s, before it types, and fails with the screen
when the line never comes. The script runs only on Windows, in CI's job
`windows` (`scripts/interop-conpty-msys2.py` installs MSYS2's sshd and vim
on the runner), so the Prove is CI's: the run of the repair's push, and of
the pushes after it, recorded in `docs/STATUS.md`.
- CI, the run of `de847e1` (37979652921): the job `windows`, 14 of 14, and
  its planted podssh fails the three restore checks and no other; the whole
  run passed.


# T-268: A pull that Docker Hub refuses fails a job of CI before its check

**Source:** CI, the runs of `a6ef7ba` and `b932993` (2026-10-09): the
workflow `secrets` failed before its scan, also when run again, as Docker
Hub refused the pull of the scanner: "toomanyrequests: You have reached
your unauthenticated pull rate limit".
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

Each job of CI that runs an image pulls it from Docker Hub with no account:
the scanner of `secrets`, and the build image of each step of the gate, of
`plant` and of the release. Docker Hub limits such pulls for each address,
and a runner shares its address with others: past the limit, the job fails
before its check runs, and the run is red for a reason that is not in the
code. A run of the release can fail in the same way.

## Premise

Read: each image is pinned to a digest in its Dockerfile
(`images/trufflehog/Dockerfile:3`,
`images/build/Dockerfile:6`), and at `b932993` each workflow gave
the reference to `docker run`, which pulls from Docker Hub (now
`.github/workflows/secrets.yml:70`, `.github/workflows/secrets.yml:84`,
`.github/workflows/build.yml:75-79`, `.github/workflows/build.yml:108-111`
and `.github/workflows/release.yml:116-119`). Measured on 2026-10-09, each
manifest asked for by its digest: Google's mirror of Docker Hub
(`mirror.gcr.io`) serves both images, the GitHub registry serves the
scanner, and Amazon's gallery of the official images
(`public.ecr.aws/docker/library`) serves the build image (HTTP 200 each).

## Approach

1. `scripts/pull-image.sh REF`: pull REF from its registry; else the same
   digest from `mirror.gcr.io`; else from `public.ecr.aws/docker/library`
   (an official image) or `ghcr.io` (another); two rounds, 30 s apart, each
   pull within 15 minutes; print the reference that served it.
2. Each workflow pulls through it, and gives the printed reference to
   `docker run`.
3. `secrets` shows that the mirrors work before they are needed: the
   scanner's digest, asked of a registry that does not exist, must come from
   a mirror.

## Decision

A mirror is safe: a pull by digest checks the digest of the manifest and of
each layer, so another registry gives the same bytes or none. Lost: an
account for Docker Hub (a secret in CI, and one more account to keep);
copies of the images in this repository's registry (a second place that
names each image, and work at each new digest); retries alone (the limit
lasts longer than a job, and a retry meets it again).

## Prove

```sh
PULL_DRY=1 sh scripts/pull-image.sh "$(sed -n 's/^FROM //p' images/build/Dockerfile)"
shellcheck -s sh scripts/pull-image.sh
python scripts/check-repo.py
```

The dry run prints the three references in order. At the push of the
repair, `secrets` passes its check of the mirrors and its scan, and each job
of `build` pulls its image.

## Done

2026-10-10. `scripts/pull-image.sh` pulls a pinned image from its registry,
else the same digest from `mirror.gcr.io`, else from
`public.ecr.aws/docker/library` (an official image) or `ghcr.io`, and
prints the reference that served it. The steps of the gate, `plant`, the
builds of the release and `secrets` pull through it, and run that
reference; `secrets` asks a registry that does not exist for the scanner,
and a mirror must serve it.
- Native: the dry run of each pinned image prints its three references in
  order, a bare name goes to `docker.io/library`, and a reference with no
  digest exits 64; `shellcheck -s sh scripts/pull-image.sh` and
  `python scripts/check-repo.py` pass.
- CI: the run of the push of the repair, recorded in `docs/STATUS.md`.
- CI, the runs of `5557c62`: Docker Hub refused each pull again, and
  `mirror.gcr.io` served the same digests: the scanner in `secrets`
  (37992185086), whose check of the mirrors passed, and the build image in
  each of the 11 steps of the gate and in `plant` (37992184997). Each
  workflow passed.

# T-272: The tests leave their scratch directories in the temporary directory

**Source:** The operator, 2026-10-10: the system disk of the developer machine was nearly full.
Measured the same day: 5245 entries named `podssh-*` in its temporary directory, 633 MB in all,
the oldest of 2026-09-28.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

Each run of the tests leaves directories in the temporary directory, and nothing removes them.
On a developer machine they fill the disk, run after run.

## Premise

Read on `c0cdd2b`: `file` (`crates/podssh-ssh/tests/known_hosts.rs:32-39`) makes
`podssh-kh-PID-NAME` and never removes it; `scratch` (`crates/podssh-relay/tests/cache.rs:19-25`)
removes its directory before a test, not after it; `scratch`
(`crates/podssh-cli/tests/pair_harness/mod.rs:26-33`) makes a new name for each test, and nothing
removes it. Measured on 2026-10-10 in the temporary directory of the developer machine: 1097
directories `podssh-kh-*`, 164 for each test of the token cache, about 104 for each test of the
pair harness; 5245 entries `podssh-*` in all.

## Approach

1. A scratch directory that removes itself when it is dropped, also when its test fails, as a
   panic unwinds through the drop: one small type for each harness, as `Home` of
   `crates/podssh-cli/tests/ssh_config_file.rs`.
2. Each test that makes a directory or a file under `std::env::temp_dir()`, in each crate, takes
   the type, or removes its path at its end where the path must outlive a helper.
3. A check that fails when a run of the tests leaves a new `podssh-*` entry in the temporary
   directory: a step that counts the entries before and after `cargo test`, in the gate.

## Decision

Decision (2026-10-10): each helper hands its directory to `cleanup::at_test_end`
(`tests/cleanup/mod.rs` of its crate), which keeps it in a list local to the thread; the list
is dropped when the test's thread ends, and removes each directory then. libtest runs each test
on a thread of its own and joins it, so the removal is done before the test counts as done,
also for a test that failed. Lost: the guard of the Approach, a value whose drop removes the
directory. It changes each place that hands the path on, and in `scratch("x").join("y")` the
guard is a temporary, dropped at the end of the statement: the directory would go before the
test used it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test --workspace --no-fail-fast
```

The entries `podssh-*` of the temporary directory: as many after the run as before it. Planted:
a scratch type that does not remove its directory; the check fails.

## Done

2026-10-10, in the commit that closes this entry. Measured first: after one run of the tests,
72 entries `podssh-*` in the temporary directory, from seven helpers: the files of
`crates/podssh-ssh/tests/known_hosts.rs`, the token cache (`crates/podssh-relay/tests/cache.rs`),
the keys, relays and tickets of podssh-iroh, `crates/podssh-cli/tests/iroh_cli.rs` and the pairs'
harness (`crates/podssh-cli/tests/pair_harness/mod.rs`). Each hands its directory to
`cleanup::at_test_end`. In the gate, `tests` runs each step's tests as `run` does, lists the
entries `podssh-*` of the temporary directory before and after, and fails with each entry that
the run left (`scripts/gate.sh`).

Native, Windows 11: `cargo test --workspace --no-fail-fast`, 1164 passed, 0 failed, 38
ignored, and no entry `podssh-*` left in the temporary directory. Planted, the token cache's
helper without the call: 9 entries left, one for each of its tests that makes a directory. clippy
with `-D warnings` on the four crates' targets: no warning. Waits for T-251: the planted run of
the gate's check.

In CI at `84df12a` (run 38034478102), the check failed the step `iroh`: the run left
`/tmp/podssh-iroh-road-e2e-PID`, from `crates/podssh-cli/tests/iroh_road.rs`, whose tests need
the feature `iroh-test`, which the native run did not build. Its helper takes
`cleanup::at_test_end` too, in the commit after `a5a6c6f`; with the feature, natively, the test
passes and leaves nothing.

# T-276: The fork's own clippy warns, and no podssh build shows it

**Source:** T-104 (2026-10-10): clippy with the fork's own manifest.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

podssh builds the Tailscale fork as a path dependency outside its workspace, and cargo caps the
lints of such a package, so no podssh build shows a warning of the fork. With the fork's own
manifest, clippy warns in the crates that podssh's patches change, and T-102 and T-103 said "no
warning" for them from podssh's builds.

## Premise

Read, at `ade87b9`: `cargo clippy --manifest-path vendor/tailscale-rs/Cargo.toml -p ts_derp -p
ts_runtime -p ts_http_util -p ts_tls_util -p ts_control -p tailscale --tests`: the `Err` of
`ts_derp::Error` is very large, on each function that returns it
(`vendor/tailscale-rs/ts_derp/src/client.rs` line 117, twelve more), from its WebSocket variant of
patch 0003; the variants of `DefaultIo` differ in size (`vendor/tailscale-rs/ts_derp/src/client.rs`
line 46, patch 0009); an `if` can be collapsed (`vendor/tailscale-rs/ts_runtime/src/lib.rs` line
135, patch 0011); and the proxy tests hold a mutex guard across awaits, six times
(`vendor/tailscale-rs/ts_http_util/tests/proxy.rs` line 80, patches 0013 and 0017).

## Approach

1. Box the WebSocket error in `ts_derp::Error`, with its `From`, and the WebSocket stream in
   `DefaultIo`.
2. Collapse the `if` in `ts_runtime`.
3. Give the proxy tests' `SERIAL` an async lock, as `crates/podssh-ts/tests/derp_proxy.rs` has.
4. Run that clippy with `-D warnings` in `scripts/ts-derp-prove.sh`, so the build image checks it.
   Add the patch and its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo clippy --manifest-path vendor/tailscale-rs/Cargo.toml -p ts_derp -p ts_runtime -p ts_http_util -p ts_tls_util -p ts_control -p tailscale --tests -- -D warnings
cargo test --manifest-path vendor/tailscale-rs/Cargo.toml -p ts_derp -p ts_runtime -p ts_http_util -p ts_control
```

Plant: the WebSocket variant unboxed again; the clippy run must fail.

## Done

2026-10-10, in the commit that closes this entry. Patch `vendor/patches/0020-clippy.patch`, with
its row in `vendor/tailscale-rs/LOCAL-PATCHES.md`: `ts_derp::Error::WebSocket` boxes its error,
with a `From` for the unboxed one, and `DefaultIo::Ws` its stream; the example `ws_handshake`, which
matched through the error, reads the upgrade's status through the box; the netmon gate is one
`if`; the proxy tests' `SERIAL` is an async lock; two lines of patch 0019 are formatted.
`scripts/ts-derp-prove.sh` runs the clippy with `-D warnings` as step M0, and step M1d runs T-104's
fork tests, `reconnect` and `ping`, which T-104's Prove named and its commit did not add.
- Native, Windows 11: `cargo clippy --manifest-path vendor/tailscale-rs/Cargo.toml -p ts_derp -p
  ts_runtime -p ts_http_util -p ts_tls_util -p ts_control -p tailscale --all-targets -- -D
  warnings`: exit 0. Planted, the WebSocket variant unboxed again: exit 101, the large `Err` on each
  function of `ts_derp`. The fork's suites of the touched crates: 58 passed. `cargo test -p
  podssh-ts -p podssh-cli --features podssh-cli/ts --no-fail-fast`: 486 passed, 0 failed,
  25 ignored; clippy with `-D warnings` on podssh's crates: no warning. The twenty patches
  give the vendored tree byte for byte on all 41 touched paths.
- Waits for T-251: `scripts/ts-derp-prove.sh` in the build image.

# T-277: The record's check sees no citation that a commit left unmoved

**Source:** 2026-10-10: commit `dddcc8e` moved three cited lines of the doctor tests, and no check saw it.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

`cargo todo check` finds a citation that an edit left behind only until the edit is committed:
it compares the tree with `HEAD`. A commit made despite its failure leaves the citations naming
other lines, and from then on no check sees it, the gate's in CI included, whose checkout equals
`HEAD`; `remap` cannot repair it either, as it too diffs against `HEAD` alone. On 2026-10-10,
commit `dddcc8e` moved the lines of `crates/podssh-cli/tests/doctor.rs` by seven, and three
citations in `TODO/machine.md` and `TODO/ws.md` named the wrong lines until `832149e` moved them
by hand. A second hole of the same check: a changed file that is not UTF-8 text, as a binary
fixture, made the remap fail, and the check passed over the failure, so that a change with such a
file was checked for no file.

## Premise

Read, at `832149e`: `crates/podssh-todo/src/check.rs` lines 80-83 give the check the files
changed since `HEAD` and their texts there, from `crates/podssh-todo/src/remap.rs` lines 51-67
(`git show HEAD:FILE`) and lines 72-84 (`git diff --name-only HEAD`). The check's `unmoved`
returns with no problem when the remap fails (`check.rs` line 114), and the remap fails on a file
that `fs::read_to_string` cannot read (`remap.rs` line 94). The gate runs the check on its
checkout (`scripts/gate.sh` line 235), where no file differs from `HEAD`.

## Approach

1. A global option `--base REV` of `podssh-todo`: `check` and `remap` read the texts before the
   edit from REV, and the files changed from `git diff --name-only REV`. `HEAD` stays the
   default. A base that is named and that git cannot read is a problem, not a check skipped.
2. A changed file that is not UTF-8 text is passed over with a note, and a remap that fails in
   the check is a problem.
3. CI's job `checks` fetches the last commit's parent and runs `cargo todo check --base HEAD~1`.
4. `TODO/RULES.md` and `docs/development.md` say how to repair a commit made without the remap.

## Decision

Decided in the work (2026-10-10):
- CI checks the last commit of a push against its parent, not the whole push against the commit
  before it: a diff over several commits can align repeated lines otherwise than each commit's
  own diff did, and would then fail on citations that each commit moved right. Each push here
  carries one commit. Lost: the push's whole range, for that reason; a check of each commit of
  the push in a worktree of its own, for its cost in each run.
- The step runs in the job `checks`, on the runner, not in the gate: the build image has no git,
  and in a developer's tree the gate's check against `HEAD` is the right one, as the tree holds
  the change that is not committed yet.
- A named base that git cannot read fails the check; the default base keeps its old leniency, as
  the build image has no git to ask.
- The tests with a real repository run git with no global or system configuration, so that no
  hook, signing key or line-end rule of the machine reaches them; with no git on PATH they say
  so and pass, as the gate's image has none, and the Windows job of CI runs them.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-todo
cargo todo check --root WORKTREE --base HEAD~1
```

The second, in a worktree at `dddcc8e`, must exit 1 and name the three citations; at `832149e`,
against `HEAD~1` and against `HEAD~2`, it must exit 0. Plants: `--base` ignored; a base that git
cannot read let pass; a changed binary file failing the remap again; a failed remap passed over.
Each must fail its test.

## Done

2026-10-10, in the commit that closes this entry. `podssh-todo --base REV`
(`crates/podssh-todo/src/lib.rs`): `check::check` and `remap` read the base through
`remap::git_at` and `remap::changed_since`; a named base that git cannot read is the problem
`--base: git cannot compare the tree with ...`, and the command that a problem names is
`cargo todo remap --base REV FILE`. A changed file that is not UTF-8 text is a note of the remap,
and a remap that fails in the check is a problem. CI's job `checks` checks out two commits and
runs `cargo todo check --base HEAD~1` (`.github/workflows/build.yml`). `TODO/RULES.md` and
`docs/development.md` say how to repair a commit made without the remap.
- Native, Windows 11: `cargo test -p podssh-todo`: 15 unit tests, 2 tests with a real repository
  (`crates/podssh-todo/tests/base.rs`), 37 plant tests, 13 tests of the remap, the test of this
  record and 7 tests of the writer: all pass. Planted, each fails its test: `--base` ignored
  (`HEAD` used); a base that git cannot read let pass; a changed binary file failing the remap
  again; a failed remap passed over.
- On this repository's history, in worktrees: at `dddcc8e`, `podssh-todo check` against `HEAD`
  exits 0, and with `--base HEAD~1` exits 1 and names the three citations, each with the move
  that `832149e` made by hand; `podssh-todo remap --base HEAD~1 crates/podssh-cli/tests/doctor.rs`
  there gives `TODO/machine.md` and `TODO/ws.md` byte for byte as `832149e` has them. At
  `832149e`, against `HEAD~1` and against `HEAD~2`: exit 0.
- `cargo test --workspace --no-fail-fast`: 1221 passed, 0 failed, 39 ignored.
- CI runs the new step from the push of this commit on.

# T-278: CI's `ubuntu-latest` moves to Ubuntu 26 from 2026-10-19: name the runners' systems through `v1.0.0`

**Source:** the notice of GitHub Actions on each Linux job of run 38076724277
(2026-10-11), "The ubuntu-latest label will migrate to Ubuntu 26 beginning
October 19, 2026" (`actions/runner-images:issues/14748`, read in the run's
annotations, not opened).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

Most jobs ran on `ubuntu-latest`, and the Windows release build on
`windows-latest`. From 2026-10-19 the first label means Ubuntu 26: each
runner's system would change during M9, and the checks of T-251 and the
release of T-250 would run on a system that no passing run of the gate met.
The builds run in the build image, pinned to a digest (T-206), so they do not
change; but the runner gives Docker, Python and the tools of each step, and a
change there can fail a step when each run belongs to the release.

## Premise

Read on `cafcdb4`:

- `.github/workflows/build.yml`: five jobs on `ubuntu-latest`, and the job
  `windows` on `windows-2025`, a named system.
- `.github/workflows/release.yml`: `ubuntu-latest` for x86_64 and
  `ubuntu-24.04-arm` for aarch64 in the matrix, `windows-latest` for the
  Windows build, and `ubuntu-latest` for the publishing job.
- `.github/workflows/changelog.yml`, `.github/workflows/deny.yml`,
  `.github/workflows/reverse-drops.yml` and `.github/workflows/secrets.yml`:
  `ubuntu-latest`.
- The last green run (38073235063, at `14f6cde`) ran its Linux jobs on the
  image `ubuntu-24.04` (version 20261004.327.1, in the job's log) and its
  Windows job on Windows Server 2025.

## Approach

1. Name `ubuntu-24.04` for each `ubuntu-latest`, and `windows-2025` for
   `windows-latest`: the systems of the last green run.
2. Dependabot (T-205) updates the actions, not the runners. After `v1.0.0`,
   a later move of the runners is a change of its own, with a run of the gate.
3. `docs/STATUS.md`, "Build, tests, CI": the runners, and the run that passed
   on them.

## Decision

Name the systems through `v1.0.0`. The alternative, to let the label move,
lost: a failure that the new system causes would come during M9, when each
CI run belongs to the release checks (`AGENTS.md`, section 2), and the
gate's result would mean another system from one push to the next. podssh's
users are not on the runner's system: the binaries are static, built in the
pinned image.

## Prove

```sh
grep -rn "ubuntu-latest\|windows-latest" .github/workflows/
```

No line. The next push's run passes each job, and each Linux job's log names
the image `ubuntu-24.04`.

## Done

2026-10-11. Each workflow names `ubuntu-24.04` or `windows-2025` (`0804e38`),
and the grep of the Prove finds no line. Run 38081754484, at `4dd52f8`, the
first push that carries the change, passed each job; its Linux jobs ran on
the image `ubuntu-24.04`. After `v1.0.0`, a move of the runners is a change
of its own, with a run of the gate.

# T-283: The console checks type into `less` and `top` before they have drawn

**Source:** CI, the run of `88493e3` (2026-10-11, run 38130453481): the job `windows` failed
`conpty.less` of `scripts/interop-conpty.py` against MSYS2's sshd, a check that passed in each run
before it.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The console checks typed `G` and `q` into `less`, and `q` into `top`, after a pause of a fixed
length, not after the program had drawn. On a slow runner the keys reached the shell's line
discipline before `less` had set its own modes, and `less` then read the first key of the next
command as its own: the shell ran `cho LESS-$((6+6))`. A check that fails at random hides a real
failure.

## Premise

Read, at `88493e3`: the check of `less` sends `seq 1 500 | less`, then `G` 1.5 s later and `q`
0.5 s after that (`scripts/interop-conpty.py`, lines 242-245); the check of `top` sends `q` 2 s
after `top` (lines 246-248). The check of `vi` waits for vi's status line before it types, for the
same reason (lines 232-236). The failed run's screen: `seq 1 500 | less`, then
`Gqecho LESS-$((6+6))` on the shell's line, then `-bash: cho: command not found`.

## Approach

Wait for what each program draws before each key: each line of `less` says `LINE-N`
(`sed 's/^/LINE-/'`), which the typed command does not hold, and `LINE-500` comes only after `G`;
`top` draws its load average. A workflow started by hand runs the console checks run after run on
`windows-2025`, the one runner that has the server, for the 20 runs of Q36.

## Prove

```sh
gh workflow run conpty-repeat.yml -f runs=20
```

The workflow passes 20 runs in a row, and the job `windows` of the push passes.

## Done

2026-10-11. `scripts/interop-conpty.py:242-256`: the check of `less` sends `seq` through
`sed 's/^/LINE-/'`, waits for `LINE-2`, sends `G`, waits for `LINE-500`, then sends `q`; the check
of `top` waits for its load average before `q`. The workflow `conpty-repeat`
(`.github/workflows/conpty-repeat.yml`), started by hand at `ff75425` (run 38131561933): 20 of 20
runs passed, each 14 of 14 checks, and the job `windows` of that push passed them too.

# T-286: Two tests of the record's interop share one scratch tree, and one removes it under the other

**Source:** the whole workspace's tests on Windows, 2026-10-11, during T-274:
`each_way_that_a_run_misses_the_baseline_is_named` of `crates/podssh-todo/tests/interop.rs` failed
once, and passed three times alone.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A test of the record failed at random. A check that fails at random hides a real failure.

## Premise

Read, at `262c7c0`: the scratch tree of a test is `podssh-todo-PID-NAME` in the temporary
directory (`crates/podssh-todo/tests/common/mod.rs`, lines 151-153), so two trees of one name in
one run are one directory, which each removes as it starts and when it drops (lines 194-197).
`scored` makes its tree under the name `score` (`crates/podssh-todo/tests/interop.rs:169-174`), and
two tests that run at once call it. Measured: 30 runs of the test binary, six at once, failed 5
times, each in a write of the tree, or with a baseline that a removal had taken away.

## Approach

Each tree gets a directory of its own: a count of the calls in the process in its name. The drop
of one test's tree then removes nothing of another's.

## Prove

```sh
cargo test -p podssh-todo --test interop
```

60 runs of the test binary, six at once, all pass; and 20 runs of the crate's tests in a row.

## Done

2026-10-11. `crates/podssh-todo/tests/common/mod.rs:153-156`: the name of each tree has a count of
the calls in the process. 60 runs of the test binary, six at once: 60 passed, where 5 of 30 failed
before; 20 runs of `cargo test -p podssh-todo` in a row: 20 passed.

# T-308: Dependabot's updates of the images fail: GitHub refuses each pull request it makes

**Source:** the run of 2026-10-13 at `922f1aa`: the job "docker in /.github/images/box, ..." of
the workflow "Dependabot Updates" failed, as it did on 2026-10-09 (twice).
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The digests of the images (`.github/images/*/Dockerfile`) are to move with their tags through
Dependabot (T-205). Each run of its docker ecosystem fails, so no image gets an update: the box's
Alpine 3.20 stays, where 3.24 exists.

## Premise

- Read in the log of the run (job 1624369194): each manifest request gets 401 and then, with
  the token of `auth.docker.io`, 200; that is Docker Hub's usual challenge, not the failure.
  Dependabot found `library/alpine` 3.24 for 3.20, and its `create_pull_request` got 400, "The
  request contains invalid or unauthorized changes"; the job then said
  `dependency_file_not_supported` and failed.
- Read, at `0b760dd`: the ecosystem's directories were `/.github/images/build`, `box`,
  `box-proxy` and `trufflehog` (`.github/dependabot.yml`, lines 32-38 at `0b760dd`). The jobs of
  cargo and of GitHub Actions passed in the same run.
- Inferred, not verified: GitHub refuses a change that Dependabot's docker job makes under
  `.github/`, as it refuses a change of `.github/workflows` to a job with no right to write them.

## Approach

1. Find the cause: the documentation of Dependabot and its issues for that message; a test with
   one image in a directory outside `.github/` (a branch, its own Dependabot run).
2. Repair it: move the images to a place where the job may change them, with each reader of
   their paths (`scripts/pull-image.sh`, `scripts/dev.sh`, `scripts/check-repo.py`, the
   workflows, the documents), or the change that the cause names.
3. Record a run of the job that passes, and the pull request it makes.

## Decision

The images move to `images/` at the root of the repository, with each
reader of their paths: the workflows `build`, `release` and `secrets`,
`scripts/dev.sh`, `dev-native.sh`, `dev-wsl.sh`, `cloud-setup.sh`,
`test_in_box.sh`, `chat-in-boxes.sh` and `ts-derp-prove.sh`, check 5 of
`scripts/check-repo.py`, `.gitattributes`, `.github/dependabot.yml` and
`docs/development.md`. Lost: one image as a probe outside `.github/` first,
a second place of an image that check 5 refuses, for a week of waiting;
`docker/` or `ci/images/`, as the images also serve the box and the scripts
on a developer's host, and `images/` is the shortest name that says what
they are.

## Prove

```sh
gh run list --workflow "Dependabot Updates" --limit 5
python scripts/check-repo.py   # each image is pinned, in one place
```

The docker job passes and opens a pull request that moves the box's Alpine. Planted: the old
directory again; the job fails as before.

## Correction

2026-10-30. The inference of the Premise has support, not proof: two reports
meet the same 400 in `create_pull_request`. In dependabot-core issue 11320
the service refuses a base image's update in a `Containerfile` and takes the
same file named `Dockerfile`, so it checks the paths that a change touches;
in composure-labs/dynamodb-guard issue 15 a uv update under .github/zizmor of that repository
gets the 400, and its author's theory, not verified, is that the service
refuses a change under `.github/` from an ecosystem other than
`github_actions`. Each Dockerfile here is named `Dockerfile`, so that check
of names passes, and the path is what is left. The move is the test.

## Done

2026-10-30. The images are in `images/` (`git mv`), and each reader names
them there; the docker job of Dependabot now opens its pull requests.

- Run 41067611245 of Dependabot's docker job, which the change of
  `.github/dependabot.yml` started, passed for `/images/box`,
  `/images/box-proxy`, `/images/build` and `/images/trufflehog`, and opened
  two pull requests: "Bump library/alpine from 3.20 to 3.24 in /images/box"
  (Azathothas/podssh#57) and "Bump trufflesecurity/trufflehog from 3.97.9 to
  3.99.7 in /images/trufflehog" (Azathothas/podssh#58). They wait for the
  operator, as the other pull requests of Dependabot do.
- The control: the same job on the same files under .github/images
  failed each week with the 400 (runs 38671632510, 39712028349 and
  40807131057, 2026-10-15 to 2026-10-29). A planted run, the files moved
  back, waits for the checks of the release (T-251).
- check 5 of `scripts/check-repo.py` passes, actionlint 1.7.7 is clean on
  `build`, `release` and `secrets`, each script parses under dash, and the
  dry pull of the build image names its three mirrors.

# T-310: The gate on a Linux host with no wsl-toolkit, and a cloud session made ready

**Source:** the operator, 2026-10-30: the dev scripts account for a Claude
Code cloud session, and make it ready for work hermetically and
idempotently (a Docker daemon, Podman, the other prerequisites).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

`scripts/dev.sh` reaches the build image only through wsl-toolkit from Git
Bash (`scripts/dev-wsl.sh`); on a Linux host its preflight stops each
container run with 127. A cloud container has Docker installed and not
running (it has no init system), and no Podman, OpenSSH, Dropbear, groff or
mandoc: there the gate, the box and the interop checks cannot run.

## Premise

Measured on 2026-10-30 in a Claude Code cloud container (Ubuntu 24.04, root,
4 CPUs, 15 GiB, PID 1 not systemd, cgroups v1 with a v2 mount):

- `dockerd` started by hand answers. A container on the host's network
  reaches crates.io, Alpine's mirrors and static.rust-lang.org through the
  session's proxy, once the host's CA bundle is in the image's store
  (`update-ca-certificates`), and keeps it after `apk add`.
- Podman 4.9.3 from apt: crun refuses each container ("cgroups in hybrid mode
  not supported"); with runc, cgroupfs and events in a file, it runs, with a
  bridge network.
- The host's Rust was 1.97.0; the gate's is 1.99.0.

## Approach

1. `scripts/dev-native.sh`: the transport of `scripts/dev.sh` for a host with
   Docker or Podman, with the contract of `scripts/dev-wsl.sh`: an ephemeral
   container of the pinned image, a copy of the tree without the excluded
   paths, and the run's own exit code; the host's network when its proxy is on
   the loopback, and the host's CA for the image's tools only.
2. `scripts/dev.sh` chooses the transport (`PODSSH_TRANSPORT`), and its
   `setup` runs `scripts/cloud-setup.sh`: each step probes first and changes
   nothing that is ready (the packages, the Docker daemon, Podman's settings,
   the pinned images, the gate's Rust, the repository's git identity);
   `--check` reports only.
3. `.claude/settings.json`: each tool allowed, `CARGO_BUILD_JOBS=4`, and no
   line of attribution; `.gitignore` for the worktrees and the local
   settings.
4. `docs/development.md` (section "A Linux host, or a cloud session") and
   `AGENTS.md` say it.

## Prove

```sh
sh scripts/cloud-setup.sh; echo "exit=$?"    # ready
sh scripts/cloud-setup.sh; echo "exit=$?"    # again: no step changes anything
sh scripts/dev.sh images; echo "exit=$?"
sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh record'; echo "exit=$?"
python scripts/check-scripts.py
```

The second setup changes nothing; `images` prints the gate's toolchain; the
step `record` passes in the image through the native transport.

## Done

2026-10-30, in a Claude Code cloud container (Ubuntu 24.04, root, 4 CPUs).
`scripts/dev-native.sh` is the transport of `scripts/dev.sh` on Linux;
`scripts/dev.sh` chooses it by `PODSSH_TRANSPORT`, or by the host (`wsl` with
wsl-toolkit or a Windows shell, else `native`), and its `setup` runs
`scripts/cloud-setup.sh`. `.claude/settings.json` allows each tool, sets
`CARGO_BUILD_JOBS=4` and adds no attribution; `.gitignore` leaves out
`.claude/worktrees/` and `.claude/settings.local.json`. `docs/development.md`
("A Linux host, or a cloud session"), `AGENTS.md` (sections 3, 4, 6 and 7)
and `docs/decisions.md` ("Cloud sessions") say it.

- The steps were first done by hand in the container, then written as the
  script. Its first run wrote Podman's settings (cgroupfs, file events,
  runc), pulled the image of the box's proxy, and found the rest ready:
  exit 0. Its second run changed nothing: exit 0.
- `sh scripts/dev.sh images`: Linux x86_64, rustc 1.99.0, cargo 1.99.0,
  musl, cc present; exit 0, with no copy left in `.work/native/`.
- `sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh record'`: gate green
  (record), in 14 s.
- `python scripts/check-scripts.py`: 56 scripts are LF and parse under dash;
  shellcheck finds nothing in the three scripts but SC1007, the repository's
  own `CDPATH= cd`.
- Not measured yet: a first run on a new container (the next cloud session
  measures it), a whole gate through the native transport, and the box
  (`scripts/test_in_box.sh`) with this Podman; the last two wait for T-251.

# T-312: The job `deny` fails from 2026-10-15: advisories against rustls, rustls-webpki, webpki-roots, tokio, crypto-bigint and ctutils

**Source:** CI, the workflow `deny` on `main`, each day from 2026-10-15 (run
40866539483 of 2026-10-29: "advisories FAILED, bans ok, licenses ok,
sources ok"); found at the start of the session of 2026-10-30.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`cargo deny --locked check advisories` fails on RUSTSEC-2026-0346 to 0349
(rustls 0.23.45), RUSTSEC-2026-0382 (rustls-webpki 0.103.15),
RUSTSEC-2026-0381 (webpki-roots 1.0.9), RUSTSEC-2026-0386 (tokio 1.53.2),
RUSTSEC-2026-0387 (crypto-bigint 0.5.5 and 0.7.5, and 0.7.5 is yanked) and
RUSTSEC-2026-0385 (ctutils 0.4.3). podssh is a TLS tool: a beta must not
ship with these.

## Premise

Read in the advisories and in podssh's code (the research of 2026-10-30):

- rustls: podssh's client sets no ECH, has no session store, no brotli, and
  offers only X25519 and secp256r1 (`crates/podssh-ws/src/crypto/suites.rs`):
  not affected; 0.23.46 adds no crate.
- rustls-webpki builds the chains, and webpki-roots is the compiled-in
  trust: affected. 1.0.11 drops the emSign roots; the test of the roots
  compares `ROOTS_VERSION` and `ROOTS_PUBLISHED` (`crates/podssh-ws/src/tls.rs`)
  with `Cargo.lock`.
- tokio: `AsyncFd::new` and `try_new` are unsound and deprecated in 1.53.3;
  the replacement is the unsafe `AsyncFd::register`, whose error gives the
  descriptor back. podssh calls them in `crates/podssh-ssh/src/mux/afd.rs`
  and `crates/podssh-cli/src/pipe/serial.rs`, and clippy with `-D warnings`
  refuses a deprecated call.
- crypto-bigint 0.7.x and ctutils: podssh-ssh's RSA keys use them (Rust 1.87
  for the patched releases; podssh-ssh needs 1.89): affected, fixed by
  0.7.10 and 0.4.7.
- crypto-bigint 0.5.5 comes only through p256 and p384 0.13 in podssh-ws: an
  ephemeral ECDHE secret used once per handshake, and ECDSA checks of public
  data. No 0.5.x is patched, and the curves' 0.14 needs Rust 1.87, above
  podssh-ws's 1.85 (podbox's minimum), which only the operator raises.

## Approach

1. `cargo update` of rustls, rustls-webpki, webpki-roots, tokio,
   crypto-bigint 0.7 and ctutils; the workspace asks for tokio 1.53.3 or
   later.
2. `AsyncFd::register` at the two call sites, with a SAFETY comment each.
3. `ROOTS_VERSION` and `ROOTS_PUBLISHED` for 1.0.11.
4. `deny.toml`: RUSTSEC-2026-0387 ignored with its reason and the date read,
   for the copy of 0.5.5 only that the curves of podssh-ws bring.

## Prove

```sh
cargo deny --locked check advisories licenses bans sources; echo "exit=$?"
cargo test -p podssh-ws --test roots_version
cargo test -p podssh-ssh --lib mux::
cargo test -p podssh-cli --lib pipe::serial
cargo clippy --locked --all-targets -p podssh-ssh -p podssh-cli -p podssh-ws -- -D warnings
```

`deny` passes; the tests pass; clippy has no warning. Planted: the old
webpki-roots in the lock; the roots test and `deny` fail.

## Done

2026-10-30. `Cargo.lock`: rustls 0.23.46, rustls-webpki 0.103.16,
webpki-roots 1.0.11, tokio 1.54.1 (1.54.0 is yanked), crypto-bigint 0.7.10
and ctutils 0.4.7; the last two need Rust 1.87, and `cargo tree -i` finds
neither in a library crate. The workspace asks for tokio 1.53.3 or later.
`AsyncFd::register` in `crates/podssh-ssh/src/mux/afd.rs` and
`crates/podssh-cli/src/pipe/serial.rs`, each with its SAFETY comment;
`ROOTS_VERSION` 1.0.11 and `ROOTS_PUBLISHED` 2026-10-23 (crates.io's date);
`deny.toml` ignores RUSTSEC-2026-0387 with its reason, for the copy 0.5.5
that p256 and p384 0.13 bring to podssh-ws.

- `cargo deny --locked check advisories licenses bans sources` with
  cargo-deny 0.20.2, CI's: advisories ok, bans ok, licenses ok, sources ok;
  with `--all-features`: licenses ok, sources ok.
- `cargo test --no-fail-fast` on Linux: 2069 passed, 55 ignored, and 1 failed,
  the record's own test before the remap of this commit's documents; after
  it, `cargo test -p podssh-todo` passed. `cargo clippy --locked
  --all-targets` of each package but podssh-ts, `-D warnings`, clippy 1.99:
  no warning. `cargo fmt --check`: clean.
- Planted: `ROOTS_VERSION` back to 1.0.9; `the_recorded_roots_are_the_ones_built`
  failed. The old lock: CI's `deny` failed on it each day from 2026-10-15.
- For CI: the gate in the build image on these versions.

# T-330: Dependabot's major updates: sha1 0.11, vt100 0.16, x25519-dalek 3, aes-gcm 0.11

**Source:** Azathothas/podssh#44 (sha1 0.10.7 to 0.11.0), #45 (vt100 0.15.2
to 0.16.2), #46 (x25519-dalek 2.0.1 to 3.0.0) and #47 (aes-gcm 0.10.3 to
0.11.1), Dependabot, 2026-10-13; the operator's ruling of 2026-10-30
(`docs/decisions.md`): a session repairs what an update breaks, and commits
the update with the repair.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

Four updates of a major version wait since 2026-10-13. Each may change an
API (Inferred from the majors; the work reads each). Three of them carry
podssh's own cryptography: the hashed
names of `known_hosts` and the cache's tokens (sha1, `podssh-ssh` and
`podssh-cli`), the key exchange of the end to end layer and of the
identities (x25519-dalek, `podssh-ws` and `podssh-relay`), and its AEAD
(aes-gcm, `podssh-ws`).

## Premise

- Read: `crates/podssh-ssh/Cargo.toml:26` and `crates/podssh-cli/Cargo.toml:58`
  ask for `sha1` 0.10.7, and the root `Cargo.toml:139` for `hmac` 0.12;
  `Cargo.lock` holds `sha1` 0.10.7 and 0.11.0, `hmac` 0.12.1 and 0.13.0,
  and `digest` 0.10.7 and 0.11.3, as russh 0.64.1 (vendor/russh/Cargo.toml)
  builds on the newer line, so the binary holds both lines today. podssh's `sha1`
  moves with its `hmac`, where the two meet (the hashed names of
  `known_hosts`): Inferred.
- Read: the root `Cargo.toml:141` asks for `aes-gcm` 0.10 and
  `Cargo.toml:147` for `x25519-dalek` 2;
  `crates/podssh-ws/src/crypto/aead.rs` and `crates/podssh-ws/src/crypto/kx.rs`
  hold the calls, with `crates/podssh-relay/src/identity/mod.rs` and
  `crates/podssh-relay/src/session/secret.rs`, and
  `crates/podssh-ws/tests/crypto_vectors.rs` their vectors.
- Read: `vt100` 0.15 (`Cargo.toml:113`) is the model of the terminal
  oracle (T-200) and of `podssh session` (T-186).

## Approach

1. One update at a time, each in its own commit, with its tests and its
   vectors: aes-gcm and x25519-dalek first (the vectors of
   `crypto_vectors.rs` must still hold byte for byte), then vt100 (the
   oracle's calibration against tmux), then sha1 with `hmac` 0.13, the
   line that russh builds on, which takes one line of `digest` out of the
   binary.
2. The minimum Rust of each crate against the gate's (1.85 for the library
   crates).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test crypto_vectors
cargo test --no-fail-fast
```

Each vector holds; each test passes. Planted: one byte of a key of the
vectors changed; its test fails.

## Correction

2026-10-30. Two facts that the Approach did not have. `crypto/aead.rs`
calls aes-gcm and chacha20poly1305 through one set of `aead` traits, and
aes-gcm 0.11 is on `aead` 0.6, so chacha20poly1305 moves with it, to 0.11
(on `aead` 0.6 too; Rust 1.85, Apache-2.0 or MIT), which Dependabot did not
ask for: it is the first step's. And Dependabot moved #45 from vt100 0.16.2
to 0.18.1 (2026-10-30): the second step takes 0.18.1.

2026-10-30, after the close and before the push. The gate's step `msrv`,
run here on Rust 1.85.1 (`cargo +1.85 check --locked` of the library
crates and podssh-todo), refuses the first step at resolution: aes 0.9.3
needs Rust 1.89 and ctutils 0.4.7 needs 1.87, and aes-gcm 0.11 and
chacha20poly1305 0.11 bring both into podssh-ws. The Done read the minimum
of each new crate, not of the crates that they bring. aes 0.9.2 and ctutils
0.4.2 hold 1.85, but ctutils before 0.4.7 has RUSTSEC-2026-0385 (T-312),
and the lock that russh's aes-gcm 0.11 shares would take the repair out of
each binary. So podssh-ws keeps aes-gcm 0.10 and chacha20poly1305 0.10,
`crates/podssh-ws/src/crypto/aead.rs` as before the first step, and
x25519-dalek 3 stays; #47 goes to T-333, which waits for the operator
(Q48). T-312's fact holds again: no library crate has ctutils.

## Done

2026-10-30, in three steps.

- aes-gcm 0.11.1 and chacha20poly1305 0.11.0 (`aead` 0.6), and
  x25519-dalek 3.0.0, in the root `Cargo.toml`. `crypto/aead.rs`: the nonce
  as an `Array` from its 12 bytes (`from_slice` is deprecated in `aead`
  0.6). `crypto/kx.rs`: x25519-dalek 3 no longer gives `StaticSecret` the
  trait `Zeroize`, but marks it `ZeroizeOnDrop`, which says the wipe on
  drop itself, so the guard that does not compile without the feature
  `zeroize` asks for that trait now; and its comment said that 2.0 clamps
  on construction, where both versions keep the bytes and clamp at each
  use (`mul_clamped`). The lock loses x25519-dalek 2.0.1; aes-gcm 0.10 and
  chacha20poly1305 0.10 stay, for the crates that still ask for them.
- `cargo test -p podssh-ws --test crypto_vectors`: 18 passed (RFC 7748
  6.1's X25519, each AEAD's round trip and its flipped bit). `cargo test -p
  podssh-ws -p podssh-relay --features podssh-relay/quick`: 427 passed, 0
  failed, in 75 binaries, of them the TLS 1.2 suites against OpenSSL
  3.0.13's `s_server`, each AES-GCM and ChaCha20-Poly1305 suite with
  records both ways, and TLS 1.3 with X25519 (`tls12.rs`, 9 passed); the
  CLI's lib 413; clippy `-D warnings`: clean; `cargo deny check licenses
  bans sources`: ok. Planted, one byte of the RFC's X25519 key: its test
  failed, and passed again without the plant.
- The second step: vt100 0.18.1 (Dependabot's #45), on vte 0.15. The size
  is a `NonZero<u16>` there, both ways: the model of the oracle
  (`crates/podssh-terminal/tests/screen/mod.rs`) and `podssh session`'s
  (`crates/podssh-cli/src/session/model.rs`) give it a row and a column at
  least, and read it back as numbers. The lock loses vt100 0.15.2, vte
  0.11.1 and `vte_generate_state_changes`, and unicode-width 0.1.14.
  `cargo test -p podssh-terminal`: each test passed, of them the
  calibration against tmux 3.4 (3, the corpus through both: the same rows
  and cursor), the oracle's 10, and the plants of the oracle's checks
  (8, each defect caught); the oracle's tests of podssh-ws (3) and
  podssh-ssh (5), `podssh-ssh --test silent_notice` (4), `podssh-cli --test
  session --test session_log` (8) and its lib's tests of `session` (31);
  the four ignored notice tests of `podssh-cli --test silent_notice`, which
  compare screens with the model: 4 passed. clippy `-D warnings` and `cargo
  deny check licenses bans sources`: clean.
- The third step: sha1 0.11.0 (Dependabot's #44) in podssh-ssh and
  podssh-cli, with hmac 0.13.0 in podssh-ssh, where the two meet (the
  hashed names of `known_hosts`, HMAC-SHA1), which takes `KeyInit` for its
  key now. The workspace's hmac 0.12 stays with sha2 0.10 in podssh-ws and
  podssh-relay (the TLS provider's HMAC and HKDF, the session secret's MAC),
  as p256 0.13, p384, rsa 0.9 and ed25519-dalek 2 still take sha2 0.10:
  the Approach's "one line of digest out of the binary" holds for the
  fuzz build only (it loses sha1 0.10.7), not for the release, where both
  lines stay until sha2 can move. `Cargo.lock` does not change: sha1 0.11
  and hmac 0.13 were in it through russh. `cargo test -p podssh-ssh`: 297
  passed, 0 failed, the hashed names among them, two lines that OpenSSH
  hashed and one name hashed as OpenSSH hashes it; planted, one character
  of that hash: its test failed, and passed again without it. `cargo test
  -p podssh-cli --test keygen_known_hosts --test ssh_config_file --test
  keygen` (29 passed, `%C` among them) and `--lib tokens`; against this
  host's OpenSSH 9.6p1: a file of two hosts hashed by `podssh keygen -H`,
  and `ssh-keygen -F` found each of them, `[alt.example.org]:2222` too, and
  no third. clippy `-D warnings` and `cargo deny check licenses bans
  sources`: clean.
- The minimum Rust of each new crate (crates.io, 2026-10-30): aes-gcm
  0.11.1, chacha20poly1305 0.11.0, x25519-dalek 3.0.0, vt100 0.18.1, sha1
  0.11.0 and hmac 0.13.0 1.85, vte 0.15.0 1.62.1: none above the library
  crates' 1.85, or podssh-ssh's and podssh-cli's 1.89. The gate's steps
  `msrv` and `msrv_ssh` run them on the push (this host has Rust 1.99 alone).
  Not so for the crates that they bring: the second Correction.
- The first step's aes-gcm 0.11.1 and chacha20poly1305 0.11.0, undone (the
  second Correction): the root `Cargo.toml` asks for the 0.10 line again,
  with its reason. `Cargo.lock` loses chacha20poly1305 0.11.0, and both
  locks hold the AEAD crates of `main` before T-330. On Rust 1.85.1 the
  library crates and podssh-todo check (`cargo +1.85 check --locked
  --all-targets`, as the gate's `msrv`), and on Rust 1.89.0 podssh-ssh and
  podssh-cli (`msrv_ssh`); `cargo test -p podssh-ws -p podssh-relay
  --features podssh-relay/quick` with `PODSSH_TEST_OPENSSL=1`: 427 passed, 0
  failed, the vectors and the TLS 1.2 suites against OpenSSL's `s_server`
  among them.
- Dependabot closes #44 to #46 once `main` holds the updates; #47 is T-333's.

# T-333: aes-gcm 0.11 and chacha20poly1305 0.11 in `podssh-ws`

**Source:** Azathothas/podssh#47 (aes-gcm 0.10.3 to 0.11.1), Dependabot;
T-330's second Correction (2026-10-30): the gate's step `msrv` refuses it.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Dependabot's #47 waits: aes-gcm 0.11.1, and chacha20poly1305 0.11 with it,
as `crates/podssh-ws/src/crypto/aead.rs` calls both through one set of
`aead` traits. Until then the binary holds two lines of AES and of GHASH:
0.10 for podssh's TLS provider and the layer's AEAD, 0.11 for russh's.

## Premise

- Measured (2026-10-30, Rust 1.85.1, the gate's `msrv`): with aes-gcm
  0.11.1 in podssh-ws, `cargo +1.85 check --locked` of the library crates
  stops at resolution: "aes@0.9.3 requires rustc 1.89", "ctutils@0.4.7
  requires rustc 1.87".
- Read (crates.io's index, 2026-10-30): aes 0.9.2 and ctutils 0.4.2 are
  the last of each line on Rust 1.85; ctutils before 0.4.7 has
  RUSTSEC-2026-0385 (T-312), so no lock of podssh takes an older one.
- Read: the library crates declare Rust 1.85, podbox's minimum
  (`docs/design.md:465-468`).

## Approach

1. Once the library crates may need Rust 1.89 (Q48): their `rust-version`,
   the gate's `msrv`, `docs/design.md` and `docs/development.md`.
2. Then aes-gcm 0.11 and chacha20poly1305 0.11, as T-330's first step had
   them: the nonce from its 12 bytes (`.into()`, as `from_slice` is
   deprecated in `aead` 0.6).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws --test crypto_vectors
sh scripts/gate.sh msrv
```

Each vector holds, and the library crates check on their declared minimum.
Planted: one byte of a key of the vectors; its test fails.

## Correction

2026-10-31. The blocker cleared: the operator ruled on Q48 that podssh is a
client first, and that no legacy constraint, such as podbox's older minimum
Rust, holds a dependency back (`docs/decisions.md`). The library crates
declare Rust 1.89.

## Done

2026-10-31.

- The root `Cargo.toml`: `rust-version` 1.89 for the library crates and
  podssh-todo, its comment the ruling's reason; aes-gcm 0.11 and
  chacha20poly1305 0.11 (`aead` 0.6). `crates/podssh-ws/src/crypto/aead.rs`
  as T-330's first step had it: the nonce an `Array` from its 12 bytes.
  `Cargo.lock` and `fuzz/Cargo.lock` take chacha20poly1305 0.11.0 again,
  and podssh-ws the line of 0.11 that russh already brought.
- The lints of Rust 1.89 that clippy now applies to the library crates:
  `is_multiple_of` in the bundle's and the IRC transfer's base64, and
  `as_chunks` in the bundle's decoder and the SHA-1 of the WebSocket
  handshake; the same behaviour, each length checked first.
- `docs/design.md`, `docs/development.md`: the library crates' minimum is
  Rust 1.89, with the ruling.
- `cargo test -p podssh-ws --test crypto_vectors`: 18 passed (planted, one
  byte of RFC 7748's key: its test failed). `PODSSH_TEST_OPENSSL=1 cargo
  test -p podssh-ws -p podssh-relay --features podssh-relay/quick`: 437
  passed, the TLS 1.2 suites against OpenSSL's `s_server` among them;
  planted, a constant nonce for AES-GCM: 6 of the 9 suites against
  OpenSSL failed, as the round trip cannot see it. `cargo test -p
  podssh-ws -p podssh-core`: 354 passed; the CLI's lib 414. The gate's
  `msrv` as it runs: `cargo +1.89 check --locked` of the library crates
  and podssh-todo, `--all-targets`, with no C compiler: it passed.
  `cargo deny check`: advisories, bans, licenses and sources ok. clippy
  `-D warnings` over the gate's packages and with the features `ts` and
  `iroh-test`: clean.
- Dependabot closes Azathothas/podssh#47 once `main` holds aes-gcm 0.11.1.

# T-337: The publish job runs actions by tags that can move, before it attests the binaries

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 3 (and finding 8 for the
fallback of NASM).
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

The README says that the release workflow proves where each binary comes from: the provenance of
each binary names the workflow and the commit of the tag. The job that attests and signs runs a
third-party action by a major tag after it downloads the binaries and before it attests them,
with the rights to write the release and to ask for an OIDC token. A tag that moves to an
attacker's commit could change `dist/` before the attestation, and the provenance would then
verify a binary that no build job made. Each other workflow takes its actions by tags too, and
two jobs of the release run an image of Docker Hub by the tag `latest`, with no mirror.

## Premise

- Read: `README.md:82-85` says "the release workflow also proves where each binary comes from".
- Read: the job `publish` needs each build job (`.github/workflows/release.yml` at `1a3e7b6`, lines 393-394) and holds
  `contents: write`, `id-token: write` and `attestations: write` (lines 396-399). After it downloads
  the binaries (line 405), it runs `taiki-e/install-action@v2` for cargo-about (lines 412-414), then
  the checksums (lines 421-426) and the attestation (lines 431-436). It runs the same action by its
  tag again for git-cliff (lines 492-494): after the signature of the checksums, and before
  `gh release create` (lines 546-554). The audit put both runs before the attestation; the second
  is after it.
- Read: the actions of the attestation and of cosign are pinned by commit
  (`.github/workflows/release.yml` lines 434 and 469 at `1a3e7b6`; `.github/workflows/release-proofs.yml:95`, `:98`).
  Each other `uses:` names a tag: `actions/checkout@v7`, `actions/upload-artifact@v7` and
  `actions/download-artifact@v8` in each workflow; `taiki-e/install-action@v2` also in
  `.github/workflows/deny.yml` line 27 and `.github/workflows/fuzz.yml` line 32; `ilammy/setup-nasm@v1`
  (`.github/workflows/release.yml` line 345, `.github/workflows/build.yml` line 222,
  `.github/workflows/conpty-repeat.yml` line 30); and `docker/setup-qemu-action@v4`
  (`.github/workflows/release.yml` lines 175 and 263), each at `1a3e7b6`.
- Read, through fetch.web.pkgforge.dev on 2026-10-31
  (https://github.com/docker/setup-qemu-action/blob/v4/action.yml): the action's `image` defaults
  to `docker.io/tonistiigi/binfmt:latest`. The riscv64 job runs it each time, and the armv7 job
  when the runner does not run 32-bit ARM (`.github/workflows/release.yml` lines 166-177 at `1a3e7b6`). No file of
  `images/` names the image, so the check of images (`scripts/check-repo.py:275-300`) does not
  see it, and its pull gets none of the mirrors of `scripts/pull-image.sh:9-13`.
- Read: T-210 found the commit of each action, and `TODO/repo.md:786-787` says "whether to pin
  them by commit is a choice of this entry's session"; no entry took it. `setup-nasm` declares
  Node 20 (`TODO/repo.md:788-790`); with no NASM, `AWS_LC_SYS_PREBUILT_NASM=1` asks aws-lc for its
  prebuilt objects (`.github/workflows/release.yml` lines 341-343 at `1a3e7b6`).
- Read: Dependabot updates the actions each week, in one group (`.github/dependabot.yml:23-30`).
  Inferred: it moves a pin by commit, and the version in its comment, as it moves a tag.
- Inferred (the audit's reading, with no source kept): the compromise of tj-actions/changed-files
  (CVE-2025-30066) was a tag moved to an attacker's commit. Each step of a job with
  `id-token: write` can ask for the job's OIDC token, so an action that runs in `publish` could
  sign other files as this workflow.

## Approach

1. Each `uses:` of each workflow names a commit of 40 hexadecimal digits, with its tag in a
   comment, as `actions/attest` is pinned (`.github/workflows/release.yml:503`): the commits of
   T-210's list, read again at each release's API on the day of the change.
2. A check in `scripts/check-repo.py`: each `uses:` under `.github/workflows/` names a commit. A
   copy with a planted `@v7` fails it, and its floor fails on an empty tree.
3. binfmt: `images/binfmt/Dockerfile` names `tonistiigi/binfmt` by its tag and its digest, and
   Dependabot's list of directories takes it (`.github/dependabot.yml:35-41`). The two jobs read it
   as the armv7 job reads its image (`.github/workflows/release.yml:164-171`), pull it through
   `scripts/pull-image.sh`, and run `docker run --privileged --rm IMAGE --install riscv64` (`arm`
   for armv7) in the place of the action. The step then checks that the kernel lists the handler
   (`/proc/sys/fs/binfmt_misc/qemu-riscv64`, or `qemu-arm`) before the binary runs.
4. The job `publish` installs no tool: a job `notes`, with `contents: read` only, installs
   cargo-about and git-cliff, writes `THIRD-PARTY-LICENSES.md` and the list of commits, and
   uploads them; `publish` downloads them with the binaries, and runs only actions pinned by
   commit (GitHub's own, and Sigstore's installer of cosign). The checksums cover the same files
   as today.
5. NASM: `setup-nasm` pinned by commit. The workflow's comment names `AWS_LC_SYS_PREBUILT_NASM=1`
   as its fallback, and one run by hand with it proves that the Windows x86-64 build passes with
   no NASM.
6. `docs/development.md` ("Release builds") says which actions each job runs, and why `publish`
   installs no tool.

## Decision

`docker run` of the pinned image won over the action with its `image` input set to the pinned
reference: one third-party action fewer, and the pull gets the mirrors. Pins by commit won over
tags with a review of each update: a tag can move after the review, and a commit cannot.

## Prove

```sh
python scripts/check-repo.py
python scripts/check-repo.py --plant-empty   # exits 1
gh workflow run release.yml --ref main       # a dry run by hand
```

The check fails on a copy of a workflow with one planted `uses: actions/checkout@v7`, and passes
on the tree. The dry run passes: `notes` runs with `contents: read`, `publish` installs no tool
and runs actions pinned by commit only, and the riscv64 and armv7 jobs register QEMU from the
pinned image.

## Done

2026-10-31. Each action that a workflow runs is named by its commit, and the
job that attests, signs and publishes runs no tool of a third party:

- The commits, read again at each repository's release API through
  forge.web.pkgforge.dev, each the commit of its major tag that day:
  `actions/checkout` v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1`,
  `actions/upload-artifact` v7.0.2 `cf430e030ddbb5b0abf93d22962f4752f3646cd9`,
  `actions/download-artifact` v8.0.2
  `9000827ccba6bdab643e8b6fd33ac0654aef8333`, `taiki-e/install-action`
  v2.88.1 `68a389c788b2cd04016ce8c80ee23b80d2ab3d68` (T-210 read v2.88.0),
  `ilammy/setup-nasm` v1.5.2 `72793074d3c8cdda771dba85f6deafe00623038b` (an
  annotated tag). 43 uses pinned in the 13 workflows, each with its tag in a
  comment.
- `scripts/check-repo.py` fails a `uses:` that names no commit: 47 read, all
  pinned; the copy of `deny.yml` with `actions/checkout@v7` failed it with its
  line; `python scripts/check-repo.py --plant-empty` exit 1, each of the 8
  checks failing on an empty tree.
- binfmt: `images/binfmt/Dockerfile` (`qemu-v10.2.3`, index
  `sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0`,
  Docker Hub's `latest` that day), in Dependabot's list, and
  `scripts/binfmt.sh`, which mounts `binfmt_misc` where no init system did:
  on this host a handler registered with none mounted lived only in its
  container. Here, from a clean state, it registered `qemu-riscv64` from the
  pinned image (Docker Hub answered 429; `mirror.gcr.io` served the same
  digest), and beta.2's published riscv64 binary then ran on this x86-64 host
  (`podssh 1.0.0-beta.2 (f7f97a58c5bc4940a886f7bc64ea3976798d0b7b)`).
  Planted, an install of another architecture: the script failed, exit 1,
  "the kernel lists no /proc/sys/fs/binfmt_misc/qemu-riscv64".
- The job `notes` (`contents: read`) installs cargo-about and git-cliff and
  uploads `THIRD-PARTY-LICENSES.md` and the list of the commits; `publish`
  downloads them, and runs `actions/checkout`, `actions/download-artifact`,
  `actions/attest`, Sigstore's `cosign-installer` and
  `actions/upload-artifact`, each pinned, and no other tool. The checksums
  cover the binaries, as before.
- NASM: when `setup-nasm` cannot set it up, aws-lc takes its prebuilt objects
  (`AWS_LC_SYS_PREBUILT_NASM=1`), with a warning, in the release and in CI's
  Windows jobs; the release's input `nasm=prebuilt` asks for them.
- `docs/development.md` ("Release builds") says which actions each job runs,
  and why `publish` runs no other tool.
- The Prove: the release workflow by hand with `nasm=prebuilt` at `33d8253`
  (run 41166843026, 04:01 to 04:15 UTC), each job passed: `notes` made
  `THIRD-PARTY-LICENSES.md` (400,567 bytes) and the list of 29 commits;
  `publish` downloaded them, ran no tool, and kept the files and the body as
  the artifact `release-dry-run`; the riscv64 job's "QEMU for riscv64" ran
  `scripts/binfmt.sh`, and the binary ran under it; the Windows x86-64 job
  skipped `setup-nasm`, built with the prebuilt objects, and its binary needs
  no C runtime DLL and ran its release check. The armv7 runner ran 32-bit ARM
  itself, so that job's QEMU step did not run (its own branch of the script is
  the riscv64 one with `arm`).

# T-341: Nothing watches the upstreams of the vendored crates

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 6.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

russh, which parses each byte that a server sends, is a copy in vendor/russh with a patch; so
are iroh's relay client and the Tailscale fork. Dependabot moves none of them, and no test shows
that `cargo deny` matches an advisory to a crate that comes from a path. The next fix of russh
would get no pull request, and maybe no red job.

## Premise

- Read: `[patch.crates-io]` puts vendor/russh and `vendor/iroh-relay` in the place of their
  releases (`Cargo.toml` lines 218-220 at `80e26fc`); russh's entries of the lock files have no source and no
  checksum, as a path package has none (`vendor/README.md` lines 133-134 at `80e26fc`); Dependabot's file says that
  an update of russh moves the patch by hand (`.github/dependabot.yml` lines 7-9 at `80e26fc`).
- Read: the copy of russh is the release 0.64.1 (`vendor/README.md` lines 90-92 at `80e26fc`), iroh-relay is 1.4.1
  (`vendor/README.md:90-94`), and the Tailscale fork is upstream's commit `f4781c4` of
  2026-09-29 with podssh's patch set (`vendor/README.md:12-19`).
- Read, through fetch.web.pkgforge.dev on 2026-10-31
  (https://github.com/rustsec/advisory-db/blob/main/crates/russh/RUSTSEC-2026-0154.md):
  RUSTSEC-2026-0154, an allocation whose size a peer sets, in russh's agent client and server
  (CVSS: availability high), dated 2026-05-15, patched from 0.60.3; 0.64.1 has the fix. The audit
  gave its date as 2026-06-02.
- Read: `cargo deny` checks the advisories of the lock on each push and each day
  (`.github/workflows/deny.yml:7-13`, `:31-32`).
- Inferred: cargo-deny matches an advisory to a package of crates.io's source, and may pass over
  a path package. Not measured.

## Approach

1. A job in the weekly workflow `upstream.yml` (T-339), with `contents: read`: crates.io's newest
   release of `russh` and of `iroh-relay` (its API's `max_stable_version`), and the head of the
   default branch of `tailscale/tailscale-rs`, each against what `vendor/README.md` names. Each
   section of `vendor/README.md` gets a line "Upstream read: VERSION on DATE", the newest upstream
   that a session judged. The job fails when the upstream differs from both, and names each.
2. The plant: a test makes a copy of advisory-db's layout in a scratch directory, with one
   advisory for `russh` whose `patched` is `>= 0.64.2`, and runs `cargo deny check advisories`
   against it (`db-path`, no fetch). The run must fail and name russh; a control with `>= 0.64.1`
   passes.
3. If cargo-deny passes over the path package (the plant passes), the job reads cargo-deny's copy
   of advisory-db for each vendored crate itself, and fails on an advisory whose `patched` leaves
   out the vendored version; the plant then runs against that check.
4. `vendor/README.md` and `docs/development.md` ("Updates") say what each watch reads, and what a
   session does when one fails.

## Decision

The line "Upstream read" won over a job that stays red until the copy moves: a session reads the
new upstream, judges it (a release that does not touch what podssh uses can wait), records it,
and the job is green again. A watch of each commit of the fork's upstream lost to the same line:
the head of the fork's upstream moves often (Inferred).

## Prove

```sh
export CARGO_BUILD_JOBS=4
gh workflow run upstream.yml
cargo deny --locked check advisories   # with the planted db-path: exit 1; the control: exit 0
```

Planted: the weekly job's "Upstream read" line set to an old version; the job fails and names
the crate. The plant of the advisory fails as step 2 says.

## Correction

The Premise's guess was right: cargo-deny passes over a path package. An advisory planted for
russh with `patched = [">= 0.64.2"]`, in a scratch advisory-db at the directory that cargo-deny
names for its database, passed `cargo deny --locked --offline check advisories` with 0.64.1 in
vendor/russh, and the same advisory for base64 failed it; so Approach item 3 holds, and the
plant of item 2 runs against its check. Approach item 1 named the head of tailscale-rs: the watch
reads its latest release, as tailscale-rs publishes releases (v0.6.1 of 2026-09-18 is the newest;
the vendored commit of 2026-09-29 is past it) and its head moved on 2026-10-31 again. The first
reading found russh 0.65.0 of 2026-10-25, which T-356 judges and moves to.

## Done

2026-10-31. Live in Actions at `80e26fc`: `upstream.yml`, run 41172620958, the job `vendored`
read russh 0.65.0, iroh-relay 1.4.1 and tailscale-rs 0.6.1 from the APIs and passed, and its
plant exited 1 naming russh; `deny.yml`, run 41172617035, passed with both new steps. Here:

- `scripts/check-vendored.py`: crates.io's `max_stable_version` of russh and iroh-relay, and
  tailscale-rs's latest release on GitHub, against each copy's manifest and the line "Upstream
  read" of its section of `vendor/README.md`; a section and its copy go together, or the run
  exits 2. Offline, on the answers read through fetch.web.pkgforge.dev and forge.web.pkgforge.dev
  (russh 0.65.0, iroh-relay 1.4.1, tailscale-rs v0.6.1): exit 0; `--plant-read first`, the
  line of russh as 0.0.0, exit 1 naming russh; iroh-relay at 1.5.0, exit 1 naming it; an answer
  missing, exit 2. `.github/workflows/upstream.yml` has the job `vendored`, each Monday and by
  hand, with its plant.
- `scripts/check-vendored-advisories.py`: cargo-deny's copy of advisory-db, for each package of
  `Cargo.lock` and `fuzz/Cargo.lock` with no source but podssh's own (russh, iroh-relay and the
  33 packages of the Tailscale fork today), with deny.toml's ignores and Cargo's reading of each
  requirement. On the database of 2026-10-30: exit 0. On the scratch database, the advisory of
  russh patched from 0.64.2: exit 1 naming RUSTSEC-2099-0001 and russh 0.64.1; patched from
  0.64.1: exit 0. `--self-test`: 17 requirements, and planted databases on a planted lock
  (patched past the version: 1; at it: 0; unaffected: 0; withdrawn: 0; no patched release: 1;
  ignored in deny.toml: 0; no database: 2), each as it must; its own plant, an ignore of the wrong
  id, failed it. `.github/workflows/deny.yml` runs both after cargo-deny, on each push and each
  day.
- `vendor/README.md` has the lines "Upstream read" (russh 0.65.0, judged for T-356; iroh-relay
  1.4.1; tailscale-rs v0.6.1) and says what each watch reads; `docs/development.md` ("Updates")
  says what a session does when one is red.


# T-343: The release takes Zig from one site, builds armv7 with an unchecked rust, and runs an unpinned schema check

**Source:** the audit of hardcoded assumptions of 2026-10-31, finding 8.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The riscv64 job downloads Zig from ziglang.org alone, a site that gives no uptime guarantee. The
armv7 job builds with the rust that Alpine ships, while the minimum Rust of the crates may rise
(Q48). The check of Dependabot's file runs whichever `check-jsonschema` PyPI serves that day.
Each can stop a release, or the gate, for a reason outside podssh.

## Premise

- Read: the riscv64 job pins Zig's version and SHA-256 and downloads it from ziglang.org
  (`.github/workflows/release.yml:218-223`, `:243-245`).
- Read, through read.web.pkgforge.dev on 2026-10-31
  (https://ziglang.org/download/community-mirrors/): "The ziglang.org website does not offer any
  uptime or speed guarantees, meaning that your CI will sporadically fail or have slower runs if
  it hardcodes it as a download URL." The mirrors that
  https://ziglang.org/download/community-mirrors.txt lists serve the same file names, and each
  download must be checked; the pinned SHA-256 checks the exact bytes.
- Read: the armv7 job installs Alpine's own `rust` and `cargo` (`.github/workflows/release.yml:184-190`),
  in Alpine 3.24 (`images/armv7/Dockerfile`); the CLI declares Rust 1.89
  (`crates/podssh-cli/Cargo.toml:8`), and Q48 lets the minimum rise (`docs/decisions.md:19`).
  Inferred: Alpine 3.24's rust is 1.89 or later, as the job built `v1.0.0-beta.2`.
- Read: `pipx run check-jsonschema` names no version (`.github/workflows/build.yml:175`, `:177`).
- Read: the signatures use Sigstore's public instance (`.github/workflows/release.yml:533-558`).
  Inferred (the audit): an outage delays a release, and a run again repairs it.

## Approach

1. Zig: a copy of the list of mirrors in `scripts/` (a text file), read in a random order; from
   each mirror `zig-x86_64-linux-VERSION.tar.xz?source=podssh-release`, checked by `ZIG_SHA256`;
   ziglang.org last. A mirror that gives other bytes is named and passed over. The weekly watch of
   T-341 compares the copy with ziglang.org's list.
2. armv7: before the build, the job compares `rustc -V` with the highest `rust-version` of the
   crates that the binary builds (from `cargo metadata`), and stops with both named when Alpine's
   is lower.
3. check-jsonschema: a pinned version (`pipx run check-jsonschema==VERSION`); the weekly watch of
   T-341 reads PyPI's newest.
4. Sigstore: no change; `docs/development.md` ("Release builds") says that a signing step that
   failed is run again.

## Prove

```sh
python scripts/check-repo.py
gh workflow run release.yml --ref main   # a dry run by hand
```

The dry run passes with ziglang.org's address planted as a name that does not resolve: a mirror
served Zig, with the same SHA-256. A planted `rust-version` above Alpine's stops the armv7 job
with both versions named.

# T-355: Dependabot's updates of 2026-10-30 and 2026-10-31, and the curves' 0.14

**Source:** Azathothas/podssh#57 (Alpine 3.20 to 3.24 for the box,
2026-10-30), #64 (h2, proptest, rcgen and unicode-width), #65 (base64 0.22 to
0.23), #66 (toml 0.9 to 1.1), #67 (chacha20poly1305 0.10 to 0.11 in the
vendored tailscale-rs) and #68 (p384 0.13 to 0.14), Dependabot, 2026-10-31;
the operator's ruling of 2026-10-30 (`docs/decisions.md`): a session repairs
what an update breaks, and commits the update with the repair.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Six updates wait, two of them of a major version that may change an API, and
one of them the curves of podssh's own TLS provider. The curves' 0.13 line
brings crypto-bigint 0.5.5, whose advisory `deny.toml` ignores only because
the curves' 0.14 once needed a newer Rust than the library crates allowed.

## Premise

- Read: the root `Cargo.toml` asks for `p256` 0.13 and `p384` 0.13 for
  podssh-ws's provider; `deny.toml` ignores RUSTSEC-2026-0387 for the
  crypto-bigint 0.5.5 that they bring (`TODO/repo.md:3880-3883` says why:
  the curves' 0.14 needed Rust 1.87, above the library crates' 1.85 then).
  T-333 raised the library crates to 1.89 (the operator's ruling of Q48).
- Read: #68 moves `p384` alone; `p256` stays at 0.13 in the PR, so the copy
  of crypto-bigint 0.5.5 would stay. #66 moves `toml` (the facts file's
  parser, podssh-probe) to the 1.1 line that iroh already takes, and drops
  the copies of toml 0.9 and winnow 0.7 from the lock. #65 moves `base64` in
  the root `Cargo.toml` and in `vendor/tailscale-rs/Cargo.toml`; #67
  `chacha20poly1305` in `vendor/tailscale-rs/Cargo.toml`, a fork with local
  patches (`vendor/patches/`). #64 changes the lock only. #57 changes
  `images/box/Dockerfile`.
- Inferred: each pull request is closed by Dependabot once `main` holds its
  version, as T-330's were.

## Approach

1. One update at a time, each built and tested with the crates that it
   reaches, each repair beside it: #64; #66 (the facts' tests and
   `podssh relay spec`); #65 (each crate that encodes base64, and the build
   with the feature `ts`); #67 with the feature `ts`; #57 (the box's run,
   `scripts/test_in_box.sh`, or its build where the run waits for T-251).
2. The curves: `p256` and `p384` 0.14 together in podssh-ws's provider (the
   key exchange and the checks of ECDSA signatures), against the provider's
   tests and the TLS of the live relay; then crypto-bigint 0.5.5 leaves the
   tree, and its line leaves `deny.toml`.
3. `cargo deny --locked check` with each feature; `docs/STATUS.md` records
   each version.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ws -p podssh-probe
cargo test --workspace
cargo deny --locked check advisories licenses bans sources
cargo tree -i crypto-bigint@0.5.5   # no such package
```

Each test passes; `deny` passes with no ignore of RUSTSEC-2026-0387.
Planted: a P-384 signature of the relay's chain with one byte changed; the
provider refuses it on 0.14 as on 0.13.
