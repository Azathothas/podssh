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
  `actions/checkout@v5` (`.github/workflows/build.yml:22`),
  `actions/upload-artifact@v7` (`.github/workflows/build.yml:113`),
  `actions/download-artifact@v8` (`.github/workflows/release.yml:125`) and
  `ilammy/setup-nasm@v1` (`.github/workflows/release.yml:82`).
- The build image is a variable in two workflows and in a shell script
  (`.github/workflows/build.yml` line 15, `.github/workflows/release.yml` line 23 and
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
   the live check. The no-C steps of the gate (`scripts/gate.sh:63-71`) judge
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
three images of `.github/images/`, after T-206), the CI step, and the section
"Updates" of `docs/development.md` are written. Next: the step's result in
CI, then Dependabot's first pull requests.

## Done

2026-10-09, in the commit "Dependabot for the crates, the actions and the
pinned images", and closed in the commit "Secret scanning of the history".

- `.github/dependabot.yml`: the crates, weekly, minor and patch updates in
  one group, each major update alone, at most 5 pull requests open; the
  actions, in one group; the images of `.github/images/` (since T-209 also
  the scanner's).
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
  (`.github/workflows/release.yml:31-32`). So the pin must be the digest of
  the multi-platform index, not the digest of one platform's image.
- The box uses two more moving tags, `alpine:3.20` and `python:3.12-alpine`
  (`scripts/test_in_box.sh` lines 39-40 at `e1ba5ba`).
- `scripts/gate.sh:50-53` prints the toolchain of each run, so the logs show
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
   (`scripts/dev.sh:147` passes it to `--image`): `sh scripts/dev.sh images`.
6. Record the pinned toolchain in docs/STATUS.md ("Build, tests, CI"), and
   name the file in docs/development.md.

## Decision

2026-10-09: the three images live in one directory, each in its own
Dockerfile of one `FROM` line: `.github/images/build/Dockerfile`,
`.github/images/box/Dockerfile` and `.github/images/box-proxy/Dockerfile`.
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
**Status:** open

## Problem

`scripts/dev.sh` has 592 lines, more than the 500 that a source file may
have. The size check reads only the Rust files under `crates/`, so the script
grew with no warning, and another script can do the same. Its help also
describes steps of the gate that no longer exist.

## Premise

Measured: `wc -l scripts/dev.sh` gives 592.

Read:

- `scripts/check-repo.py:87-97` checks only the Rust files under `crates/`.
- `scripts/dev.sh:318-329` defines `step`, which nothing calls.
- The help (`scripts/dev.sh:331-366`) says that the gate builds the default
  members with `CC=/nonexistent`, and the release too (lines 339-342). The
  gate builds the library crates with `CC` and `CXX` set to `/nonexistent`,
  and the release with neither (`scripts/gate.sh:63-71`,
  `scripts/gate.sh:117-120`). The help omits the work record, interop, the man
  page, the C++ plant, and the subcommand `gate` (`scripts/dev.sh:602`).
- Stale comments: `scripts/dev.sh:69-73` ("the default build"),
  `scripts/dev.sh:397-404` ("links the fork since 4b", "steps 4-5"),
  `scripts/dev.sh:462`.
- CI parses `scripts/*.sh` with dash (`.github/workflows/build.yml:69-75`);
  `scripts/check-scripts.py:45-49` finds the scripts under `scripts/` at any
  depth.

## Approach

1. Remove the unused `step`.
2. Move the Windows transport into one file that `scripts/dev.sh` sources
   (proposed: scripts/dev-wsl.sh, directly in `scripts/`): the tool settings,
   `EXCLUDES` with its comments, `run_in_image`, the PowerShell bridge, `b64`,
   `preflight`, `wt`, `win_path` and `scratch_file` (lines 48-300 and
   352-377). Source it after the self-location (lines 37-46). Keep each
   comment. Invariant: the text of the bridge does not change by one byte;
   compare the old and the new text with `cmp`.
3. Correct the help and the stale comments to the gate as it is
   (`scripts/gate.sh:55-166`).
4. Extend the size check of `scripts/check-repo.py` to the shell and Python
   files under `scripts/`, with a floor (T-223).
5. Drop the sentence on the exception from `docs/decisions.md`, and move it
   to Superseded: this work changes that fact (the operator's ruling of 2026-10-08).
   The decision itself stays.

Pitfalls: keep the new file directly in `scripts/`, so the dash loop of CI
reads it. `.gitattributes` gives it LF. The lock and its trap stay in
`scripts/dev.sh` (lines 540-559).

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
  them (`.github/workflows/release.yml:143-153`).
  No notes file exists yet; T-250 writes the first. The notes drafted for a
  beta that the operator dropped are in git:
  `git show b1b111b:docs/releases/v0.1.0-beta.1.md`.
- `actions/checkout@v5` fetches one commit by default
  (`.github/workflows/release.yml:121`), which hides the history from a
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
5. docs/development.md, "Release builds" (`docs/development.md:350-395`): the
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

- `scripts/check-repo.py:40-53` defines the shapes (a relay token, a Tailscale
  key, a private key block); `scripts/check-repo.py:132-153` scans the tracked
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
   `.github/images/trufflehog/Dockerfile`: the one place of T-206, which
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

- `.github/workflows/secrets.yml`, `.github/images/trufflehog/Dockerfile`
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
**Status:** open

## Problem

A downloaded binary carries no proof of its origin. `SHA256SUMS` comes from
the same job as the binaries, so it shows that a download is complete, not who
built it or from which commit. `podssh --version` names no commit, so a tester
cannot tie a binary to its source.

## Premise

Measured: `target/debug/podssh.exe --version` prints `podssh 0.1.0`, exit 0.

Read:

- The jobs `linux` and `windows` build the binaries, and `publish` adds
  `SHA256SUMS` and publishes them (`.github/workflows/release.yml:23-169`).
  The workflow has `contents: read` (lines 19-20); `publish` adds
  `contents: write` (lines 112-113).
- The KTM tester could not tell from an artifact which commit made it, and
  moved the checkout one commit ahead (the KTM report, section 1a; read in
  the report).
- `crates/podssh-cli/src/man/facts.rs:275-291`: the drift test of the manual
  counts each quoted upper-case name with `_` in the sources as a variable
  (except `CARGO_` names).

## Approach

1. In the jobs `linux` and `windows`, after the checks of the binary, attest
   each binary with `actions/attest-build-provenance`, pinned by commit SHA,
   for a tag `v*` only. Give these jobs `id-token: write` and
   `attestations: write`. A run by hand makes no attestation.
2. Tell the user how to check, in `README.md` (lines 46-47) and in the
   release notes: `gh attestation verify FILE --repo Azathothas/podssh`.
3. Let `podssh --version` name the commit: the workflows set a variable at
   compile time (`option_env!`, no build script, no `git` call); a local build
   prints the version alone. In the same commit, add the name to the facts of
   the manual, or teach the drift test about names read at compile time.
4. One paragraph in the release notes on the Windows binary, which is not
   signed (SmartScreen warns about it).
5. Do this before T-250, so that the one release is attested.

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

# T-211: Signed checksums for each release

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for provenance of
released binaries (checksums).
**Category:** release
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`SHA256SUMS` is not signed. A person who can replace a binary on the release
page can replace the sums too. A user cannot check that the sums come from
the release workflow of podssh.

## Premise

Read:

- `.github/workflows/release.yml:140-145` writes `SHA256SUMS` with
  `sha256sum`, and `.github/workflows/release.yml:153-169` publishes it with
  the binaries. No signature is published.
- The notes drafted for the dropped beta told the user that `SHA256SUMS`
  holds the sums (`git show b1b111b:docs/releases/v0.1.0-beta.1.md`, line 81). `README.md:46-47` gives no step to check a download.
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

# T-212: Parallel CI, with the gate as the one source

**Source:** GitHub #27 (the operator, 2026-10-08), which asks for parallel CI.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

CI runs the whole gate in one job, one step after the other: the library
crates, the work record, the SSH client and the CLI, the Tailscale tests, the
static release, interop and the man page; then the plant and the live check
of the relay. A failure late in that list shows only after each earlier step,
and the job takes the sum of all the steps.

## Premise

Read:

- `.github/workflows/build.yml:16-117`: one job, `gate`, with a limit of
  45 min (line 24). The gate is one `docker run` (lines 58-65); the plant
  (lines 67-73) and the live check (lines 75-92) follow it.
- `.github/workflows/build.yml:3-5`: CI implements nothing of the gate again.
- `scripts/gate.sh:5-6`: the gate takes no argument. Its steps are at
  `scripts/gate.sh:65-166`.
- `scripts/gate.sh:18-29`: one cargo job for each 3 GiB of free memory.
- AGENTS.md, section 4: on the operator's machine, one build at a time
  (`scripts/dev.sh:556-575` holds a lock).

Not measured: the wall time of a CI run. Measure it with `gh run list` before
the change.

## Approach

1. `scripts/gate.sh` takes optional step names: `libs`, `record`, `ssh`, `ts`
   and `release` (the static build, the check of the artefact, interop and the
   man page, which share one binary). With no name, it runs each step in
   order, as now; `--list` prints the names. Each step keeps `run`
   (`scripts/gate.sh:34-48`) and its rule for exit codes.
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
gate, and a copy drifts (`.github/workflows/build.yml:3-5`).

## Prove

```sh
sh scripts/dev.sh run -- 'sh scripts/gate.sh --list'    # the step names, in the build image
gh run list -R Azathothas/podssh --workflow build.yml -L 1 --json conclusion,createdAt,updatedAt
```

The list equals the matrix, and the last run passed in less wall time than
before. Planted defect: remove `ts` from the matrix; the drift check must
fail.

# T-213: CI runs the box like the target sandbox

**Source:** GitHub #27 (the operator, 2026-10-08), which asks for a proper CI
test in a box replica.
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The box like the target sandbox runs only by hand, on the operator's Podman
machine; its last record is for the binary of `aa9cfaa`. A change that breaks
podssh in the sandbox's profile (no DNS, no way out but a CONNECT proxy,
`bind` and UDP refused, no pty, no user entry) can reach `main`, and no run
sees it.

## Premise

Read:

- `docs/STATUS.md:122-136`: the box, measured by hand on 2026-10-08.
- `scripts/test_in_box.sh:192-195`: the box runs `probe.sh`, then
  `sandbox-check.sh` (or, with `BOX_RUN=tt`, the session of T-004), and the
  script exits with the code of the second.
  `scripts/sandbox-check.sh:85-188` prints the exit code of each step and does
  not fail on it (T-006). So today the box exits 0 when podssh fails in it.
- `scripts/box/probe.sh:122-127` exits 1 when the box differs from the sandbox
  in a required property (17 properties, `docs/STATUS.md:129`).
- The box needs a static binary; CI uploads one
  (`.github/workflows/build.yml:113-117`).
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
   first log with the token pattern of `scripts/check-repo.py:44`.
6. docs/STATUS.md (the box section) cites the CI run; docs/development.md says
   that CI runs the box.

Pitfall: the live path can drop a session (179 of 180 short sessions,
`docs/STATUS.md:159`). Run a failure again by hand and record it. Never retry
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
of `workflow_dispatch`); the probe must exit 1, as in `docs/STATUS.md:130`,
and the job must fail.

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
platform (`.github/workflows/release.yml:71-112`).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

No CI run executes the tests of podssh on Windows. The release workflow
builds the Windows binary only for a tag or by hand, and runs no test. The
code for Windows only (the console, prompts through `CONIN$`, the branches of
the token cache that are not Unix) is measured only on the operator's
machine.

## Premise

Read:

- `.github/workflows/build.yml:17-19`: one job, on `ubuntu-latest`.
- `.github/workflows/release.yml:71-112`: the Windows job installs NASM
  (line 76), builds, and checks for C runtime DLLs (lines 86-101); it runs no
  test.
- `docs/STATUS.md:230`: the default tests pass on Windows, run by hand.
  `docs/STATUS.md:69`: `scripts/interop-conpty.py` passes 14 of 14 against a
  Tailscale SSH server, by hand.
- `scripts/interop-conpty.py:217-261` needs a server with a POSIX shell,
  `stty`, `vi`, `less`, `top`, `seq` and `/tmp`.
- The code for Windows: `crates/podssh-ssh/src/terminal/windows.rs`,
  `crates/podssh-ssh/src/prompt.rs:95`, and the `cfg(not(unix))` branches of
  `crates/podssh-relay/src/cache.rs:293-352`.

## Approach

1. A job `windows` on `windows-2025` (pinned, not `windows-latest`):
   checkout, NASM as in the release, `cargo test --locked --no-fail-fast` with
   `CARGO_BUILD_JOBS=4`, and `python scripts/check-repo.py`.
2. An SSH server on the runner for `scripts/interop-conpty.py`, on
   127.0.0.1, with a throwaway key that `podssh keygen` makes and the job
   deletes (see Decision). Run the script with `--direct`; 14 of 14 must pass.
3. With T-199: score the output with the Windows part of the baseline.
4. The plant: a podssh that does not restore the mode of the console must
   fail the three restore checks (as measured by hand, `docs/STATUS.md:69`).
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

## Prove

```sh
cargo test --locked --no-fail-fast       # in the job windows: each default test passes
python scripts/interop-conpty.py target/debug/podssh.exe podtest@127.0.0.1 --direct -p 2222 -i KEY -o StrictHostKeyChecking=accept-new
```

The tests pass, and the console script prints 14 `ok` lines and exits 0. The
plant of step 4 must fail the three restore checks.

# T-215: rustfmt and clippy in the gate

**Source:** the triage of GitHub #27 (2026-10-08).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** M
**Status:** open

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

- `scripts/gate.sh:55-166` has no step for rustfmt or clippy. There is no
  rustfmt.toml and no clippy.toml.
- One `allow` for clippy exists (`crates/podssh-ws/src/client.rs:315`).
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

# T-216: Advisories and licenses of the dependencies, checked in CI

**Source:** the triage of GitHub #27 (2026-10-08); the advisories of iroh
(`docs/design.md:291-293`) show that a dependency can get one.
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
  release publishes the binaries and `SHA256SUMS` only
  (`.github/workflows/release.yml:140-169`).
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
(`docs/development.md:8-10`), measured by hand on 2026-10-08 (the note beside
`rust-version` in `Cargo.toml`).
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** open

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
- `scripts/gate.sh:50-53` prints the one toolchain of the gate.
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

# T-218: More release targets: macOS, Linux armv7 and riscv64, and Windows aarch64

**Source:** the iroh-ssh report in GitHub #18 (static musl binaries for more
architectures; its issues 51 and 57), read in the report, not verified here.
The operator's ruling of 2026-10-08: v1.0.0 ships these targets
(`docs/decisions.md`).
**Category:** release
**Milestone:** M9
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A release has three binaries: static Linux for x86_64 and aarch64, and
Windows for x86_64. A Raspberry Pi with a 32-bit system, a Mac, a Windows
machine on ARM and a FreeBSD host get none. Their users must build podssh,
with a C toolchain for aws-lc.

## Premise

Read:

- `.github/workflows/release.yml:28-32`: x86_64 and aarch64 musl, each on a
  native runner in `rust:1-alpine`. `.github/workflows/release.yml:71-112`:
  Windows x86_64 with a static C runtime.
- The check of each platform: `readelf` for `NEEDED` and `INTERP`
  (`.github/workflows/release.yml:52-59`), `dumpbin /dependents` on Windows
  (lines 86-101).
- The binary needs a C compiler for aws-lc (`docs/development.md:11-13`); the
  library crates need none.
- Some code reads facts of Linux. The terminal check reads `tty_nr` from
  `/proc/self/stat` when it can (`crates/podssh-ssh/src/terminal/ctty.rs:27`),
  and does without it when it cannot (`crates/podssh-ssh/src/terminal/ctty.rs:40-41`).
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
slow, and the job limit is 60 min (`.github/workflows/release.yml:34`).

## Prove

```sh
gh workflow run release.yml --ref main      # builds and checks each target, publishes nothing
gh run download RUN_ID -R Azathothas/podssh -n podssh-armv7-unknown-linux-musleabihf
```

The run passes for each target, and each artifact ran under its check.
Planted defect: build one target without `+crt-static`; its static check must
fail.

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

- `scripts/gate.sh:55-71`: the library crates build and test with
  `CC=/nonexistent` and `CXX=/nonexistent`.
- `scripts/plant.sh:100-145`: a crate in a temporary path whose build script
  compiles one C++ file with the `cc` crate. With both variables set, the
  build must fail at `/nonexistent`; the control, with `CC` alone, must not
  stop there.
- `docs/development.md:139-141` states the rule with `CXX`, and
  `docs/STATUS.md:237` records the measurement. Rule 4 of
  `docs/architecture.md` named `CC=/nonexistent` only; it was repaired in the
  same change as the record.
- `.github/workflows/build.yml:86-92` runs the plant on each push.

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
there, and the clean tree built (`docs/STATUS.md:237`). The CI run of
`eacd94e`, which contains `a378863`, passed, with its step "the no-C rule is
load-bearing".

# T-223: `scripts/check-repo.py` passes when it finds nothing to check (GitHub #33)

**Source:** GitHub #33 (2026-10-08), part 1; reproduced here on 2026-10-08.
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** open

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

- `scripts/check-repo.py:89`: the size check walks `crates/` with `rglob`; a
  missing directory yields nothing. (#33 cites line 56; the walk is at 57
  now.)
- `scripts/check-repo.py:100-129`, `scripts/check-repo.py:132-153` and
  `scripts/check-repo.py:156-161`: the links, the credentials and the line
  endings have no floor either.
- `scripts/check-repo.py:230-249`: `main` passes when each list of problems is
  empty.
- The model of a floor: `crates/podssh-relay/tests/default_relay.rs:54`
  asserts that the sweep read more than 20 files.
  `scripts/check-scripts.py:112-115` already fails when it finds no script.
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
   (`.github/workflows/build.yml:99-111`).
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

Read: the rule as written is rule 3 of `docs/architecture.md:101-108` (the
bind check of `podssh doctor` is the one exception), rule 3 of
`docs/target-environment.md:74-78`, and rule 2 of AGENTS.md, section 5. The
operator ruled on 2026-10-08 (`docs/decisions.md`): Q1 allows a local
listener when the user asks for it and a probe at run time allows the bind
(T-038, T-039, T-124, T-186, and `podssh agent` in T-034); Q10 allows a race
of relay hosts (T-220), more than one outbound connection for a moment, which
is not a listener.
`scripts/check-repo.py:230-238` has four checks, and none reads a socket
call; `scripts/plant.sh` plants C and C++ only.

Measured with grep over `git ls-files 'crates/*'`: three files hold a
listener or a bind. `crates/podssh-cli/src/doctor/unix.rs:151` and line 226
are the bind probes of `doctor`, which close at once and never listen
(`crates/podssh-cli/src/doctor/mod.rs:15-16`). The test servers are in
`crates/podssh-ws/tests/dial.rs:80` and
`crates/podssh-ws/tests/hostname_verification.rs:63`. No file uses
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
- The documents already state the rule as ruled (`docs/architecture.md:101-108`,
  `docs/target-environment.md:74-78`, `AGENTS.md`, section 5): nothing to
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
**Status:** open

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
  (`scripts/dev.sh:195-205`).
- 340 markers are in string literals: 326 in tests, 14 in `src`, one of them
  in a message for users (crates/podssh-transport/src/backpressure/mod.rs line 157 at `e8bbd4d`).
- 266 lines in 42 code files hold a line number of a document; 188 lines in
  63 files name a work item of an earlier session (E02, E16).

Read, names of files that do not exist: docs/spec/06-cli.md
(`crates/podssh-cli/src/flags.rs:3`, lines 12 and 372-374, and four more
files); docs/TODO/cli/surface.md (`crates/podssh-cli/src/flags.rs:103`,
`crates/podssh-cli/src/suggest.rs:9`); docs/TODO/protocol/ssh-core.md
(`crates/podssh-terminal/src/window.rs:42-44`); docs/spec/01-relay-protocol.md
(`crates/podssh-core/src/irc/limits.rs:8`,
`crates/podssh-probe/facts/relay-facts.toml:3-5`); a root RULES.md with lines
138-142 (crates/podssh-transport/src/lib.rs line 4 at `e8bbd4d`); check-todo.py
(`scripts/check-scripts.py:12`, line 25). The link to `SCP_FLAGS`
(`crates/podssh-cli/src/flags.rs:110`) names a constant that does not exist.

Read, wrong facts:

- crates/podssh-transport/src/error.rs lines 18-25 at `e8bbd4d` and lines 38-78 cite rows of the
  relay's document by line, each 35 lower than the row in the pinned copy
  (line 135 there is line 170 of
  `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`).
- crates/podssh-transport/src/backpressure/mod.rs lines 4-22 at `e8bbd4d` gives the reverse
  path's backpressure (1011, 1 MiB, the frame dropped: line 185 of that copy)
  as the forward path's. For the forward path, `docs/relay.md:169-173` says
  1013 at 2 MiB, with no frame dropped. The comment on the SSH window said
  the same as `backpressure/mod.rs` (`crates/podssh-ssh/src/run.rs` lines
  25-28 at `80f20bf`); T-024 corrected it.
- The comment "THE BUILD RULE" in `Cargo.toml` lists the no-C crates without
  `podssh-relay`; `crates/podssh-cli/Cargo.toml:3` names a `--doctor` flag.

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

# T-245: The box refuses each bind, but sandbox A allows an AF_UNIX bind

**Source:** the report of the writer of `TODO/pipe.md` (2026-10-08); the
measurement of sandbox A (T-001); the operator's ruling on Q1
(`docs/decisions.md`).
**Category:** chore
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** open

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
- `docs/STATUS.md:150`: in sandbox A, `bind` is refused for AF_INET and
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

# T-246: `scripts/dev.sh` excludes each file named `agents.md` from the container copy, with no reason given

**Source:** a finding of the writer of `TODO/robustness.md` (2026-10-08),
while reading `scripts/dev.sh`.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`sh scripts/dev.sh check` copies the tree into a container without the files
named `agents.md`, and no comment says why. On Windows, where file names have
no case, the pattern can also match the root `AGENTS.md`. Then the gate in the
container reads another tree than CI does: a citation of `AGENTS.md` in
`TODO/` fails only there, and the ids that `AGENTS.md` names go unchecked
there.

## Premise

Read:

- `scripts/dev.sh:115` puts `agents.md` in `EXCLUDES`. The comments above it
  (lines 66-98) give a reason for each other pattern, not for this one. The
  line is in the first public commit, `9a03102`.
- `.gitignore` (lines 16-18) keeps a root `/agents.md` out of git, as "a
  lowercase duplicate of AGENTS.md created by the filesystem".
- The record's checker reads `AGENTS.md` for ids, and drops a missing file
  with no word (`crates/podssh-todo/src/refs.rs:42-47`). It accepts
  `AGENTS.md` as a cited root file (line 20). The gate runs the checker in the
  container (`scripts/gate.sh:104-107`). 22 lines of `TODO/` cite `AGENTS.md`.
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
5. `docs/development.md:177-178` lists what the containers do not get; name
   each excluded pattern there.

## Prove

```sh
sh scripts/dev.sh run -- 'test -f /work/AGENTS.md && test -f /work/TODO/machine.md'
sh scripts/dev.sh check     # the record's checker passes in the container too
```

Both exit 0. Planted defect: add `AGENTS.md` to `EXCLUDES`; the new step of
the gate must fail before the record's checker runs.

# T-247: `podssh-cli` declares dependencies that it does not use

**Source:** the reports of the writers of the record (2026-10-08), measured
again here.
**Category:** chore
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The binary crate declares four library crates that its code does not use, or
uses in an example only. Each one is built with the binary, enters each check
of the dependency graph (T-216, T-217), and tells a reader that `podssh` uses
it. Nothing stops the list from growing.

## Premise

Measured with grep over the `src`, `tests` and `examples` of `podssh-cli`:

- `podssh-terminal` (`crates/podssh-cli/Cargo.toml:33`) and `podssh-probe`
  (line 31): no use at all.
- `podssh-core` (line 30) and `podssh-transport` (line 34): used only by the
  example `crates/podssh-cli/examples/live_irc.rs` and its module
  `crates/podssh-cli/examples/live_irc/support.rs`.
- The crate has no build script, and no check in the repository looks for
  unused dependencies.

Read: `libc` (line 44) is used only in code under `cfg(unix)`
(`crates/podssh-cli/src/ssh/tokens.rs:119`, `crates/podssh-cli/src/ssh/tokens.rs:136`,
`crates/podssh-cli/src/ssh/resolve.rs:83`,
the module of `crates/podssh-cli/src/doctor/unix.rs`). T-060 decides whether a
command uses `podssh-probe`.

## Approach

1. Remove `podssh-terminal` and `podssh-probe` from the dependencies. The
   commit that uses one again (M5, T-060) adds it back.
2. Move `podssh-core` and `podssh-transport` to the dev-dependencies: an
   example can use a dev-dependency, and the binary does not declare them.
3. Move `libc` to the dependencies for Unix only, as
   `crates/podssh-relay/Cargo.toml:32` does; else the lint of step 4 fails on
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

- Read: `citations` (`crates/podssh-todo/src/refs.rs:92-126`) tests that the
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
  line 0, is a problem; two plant tests.
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
