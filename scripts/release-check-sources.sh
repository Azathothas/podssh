# The sources of the release check (T-251), sourced by
# scripts/release-check.sh: the binaries, and their checks before any of
# them runs. A row that fails here stops the run with "no check ran".

# The targets of .github/workflows/release.yml (T-218): a new target there
# shows here as a name of SHA256SUMS that sums.names does not know.
TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf
riscv64gc-unknown-linux-musl aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-msvc
aarch64-pc-windows-msvc"

binary_of() {
    case $1 in *-windows-*) echo "podssh-$1.exe" ;; *) echo "podssh-$1" ;; esac
}

# The target of this host's Linux binary, from the machine's name.
host_target() {
    case $(uname -m) in
        x86_64 | amd64) echo x86_64-unknown-linux-musl ;;
        aarch64 | arm64) echo aarch64-unknown-linux-musl ;;
        armv7*) echo armv7-unknown-linux-musleabihf ;;
        riscv64) echo riscv64gc-unknown-linux-musl ;;
        *) echo none ;;
    esac
}

# The machine that readelf names for each Linux target.
machine_of() {
    case $1 in
        x86_64-*) echo 'X86-64$' ;;
        aarch64-*) echo 'AArch64$' ;;
        armv7-*) echo '[[:space:]]ARM$' ;;
        riscv64gc-*) echo 'RISC-V$' ;;
    esac
}

# The version of the workspace, as scripts/release-short.sh reads it.
cargo_version() {
    tr -d '\r' <"$REPO/Cargo.toml" | sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p'
}

# static_rows LABEL=FILE:TARGET...: one row for the static Linux binaries.
static_rows() {
    if ! command -v readelf >/dev/null 2>&1; then
        row FAIL static - 0 "readelf is not on PATH (binutils), so no binary was read"
        return
    fi
    _bad= _n=0
    for _s in "$@"; do
        _f=${_s%:*} _t=${_s##*:}
        _n=$((_n + 1))
        readelf -d "$_f" >"$W/dyn" 2>&1 && readelf -l "$_f" >"$W/phdr" 2>&1 && readelf -h "$_f" >"$W/head" 2>&1
        _rc=$?
        if [ "$_rc" != 0 ]; then
            _bad="$_bad ${_f##*/}: not read by readelf;"
        elif grep -q NEEDED "$W/dyn"; then
            _bad="$_bad ${_f##*/}: dynamic dependencies;"
        elif grep -q INTERP "$W/phdr"; then
            _bad="$_bad ${_f##*/}: a program interpreter;"
        elif ! grep -Eq "Machine:.*$(machine_of "$_t")" "$W/head"; then
            _bad="$_bad ${_f##*/}: not a binary of $_t;"
        fi
    done
    if [ -z "$_bad" ]; then
        row PASS static - 0 "$_n of $_n: static, each of its machine"
    else
        row FAIL static - 0 "$_bad"
    fi
}

sources_local() {
    _head=$(git -C "$REPO" rev-parse HEAD 2>/dev/null)
    COMMIT=${COMMIT:-$_head}
    _dirty=$(git -C "$REPO" status --porcelain --untracked-files=no 2>/dev/null)
    if [ -z "$_head" ]; then
        row FAIL src.checkout - 0 "git names no HEAD here: the commit under check is unknown"
    elif [ "$_head" != "$COMMIT" ]; then
        row FAIL src.checkout - 0 "the tree is at $(printf '%.7s' "$_head"), the artifact's commit is $(printf '%.7s' "$COMMIT"): check it out"
    elif [ -n "$_dirty" ]; then
        row FAIL src.checkout - 0 "the tree has changes, so a build here is not $(printf '%.7s' "$COMMIT")'s"
    else
        row PASS src.checkout - 0 "clean at $(printf '%.7s' "$COMMIT"), version $(cargo_version)"
    fi

    cp "$BINARY" "$W/bin/artifact" && chmod 755 "$W/bin/artifact"
    _art=$(digest "$W/bin/artifact")
    if [ -n "$SUMS" ]; then
        # The line of the binary's own name, checked where it lies.
        _name=${BINARY##*/}
        grep " \*\{0,1\}$_name\$" "$SUMS" >"$W/one.sums"
        _dir=$(CDPATH= cd -- "$(dirname -- "$BINARY")" && pwd -P)
        if [ ! -s "$W/one.sums" ]; then
            row FAIL sums.check artifact 0 "--sums has no line for $_name"
        else
            timed 120 "$LOGS/sums.log" sh -c 'cd "$1" && sha256sum -c "$2"' sh "$_dir" "$W/one.sums"
            by_rc sums.check artifact 0 "$LOGS/sums.log" "sha256 $_art"
            # The copy that the checks run is the bytes that were checked.
            [ "$(digest "$_dir/$_name")" = "$_art" ] || row FAIL sums.check artifact 0 "the copy differs from the checked file"
        fi
    else
        row SKIP sums.check artifact 0 "no SHA256SUMS before the tag; sha256 $_art recorded; T-250 checks the published sums"
    fi
    DIGESTS="The artifact: sha256 \`$_art\`."
    static_rows "$W/bin/artifact:x86_64-unknown-linux-musl"

    if [ -n "$BUILD" ]; then
        cp "$BUILD" "$W/bin/build" && chmod 755 "$W/bin/build"
        timed 30 "$LOGS/build.log" "$W/bin/build" --version
        by_rc build.local build 0 "$LOGS/build.log" "given by --build: $(head -n 1 "$LOGS/build.log")"
    else
        # The features of the release's builds, from the one place that names them.
        _features=$(sed -n 's/^  RELEASE_FEATURES: *\([a-z,]*\).*/\1/p' "$REPO/.github/workflows/release.yml")
        _features=${_features:-iroh,warp}
        timed 3600 "$LOGS/build.log" env CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
            cargo build --locked --release -p podssh-cli --features "$_features"
        _built=${CARGO_TARGET_DIR:-$REPO/target}/${CARGO_BUILD_TARGET:+$CARGO_BUILD_TARGET/}release/podssh
        if [ "$RC" = 0 ] && [ -f "$_built" ]; then
            cp "$_built" "$W/bin/build" && chmod 755 "$W/bin/build"
            row PASS build.local build "$SECS" "cargo build --release --features $_features: $("$W/bin/build" --version 2>&1)"
        else
            row FAIL build.local build "$SECS" "$(why): cargo build --release --features $_features"
            show "$LOGS/build.log"
        fi
    fi
    [ ! -f "$W/bin/build" ] || DIGESTS="$DIGESTS The build of this host: sha256 \`$(digest "$W/bin/build")\`."
    PRIMARY=artifact
    HERE_BINS="artifact build"
}

sources_tag() {
    D=$W/release
    mkdir -p "$D"
    _files="SHA256SUMS SHA256SUMS.sigstore.json provenance.sigstore.json THIRD-PARTY-LICENSES.md"
    for _t in $TARGETS; do _files="$_files $(binary_of "$_t")"; done
    _miss= _secs=0
    if [ -z "$DIR" ] && ! command -v curl >/dev/null 2>&1; then
        _miss="curl is not on PATH"
    else
        for _f in $_files; do
            if [ -n "$DIR" ]; then
                cp "$DIR/$_f" "$D/$_f" 2>"$LOGS/download.log"
                RC=$? SECS=0
            else
                timed 300 "$LOGS/download.$_f.log" curl -fsSL --retry 2 -o "$D/$_f" \
                    "https://github.com/$SLUG/releases/download/$TAG/$_f"
            fi
            _secs=$((_secs + SECS))
            [ "$RC" = 0 ] && [ -s "$D/$_f" ] || _miss="$_miss $_f"
        done
    fi
    if [ -z "$_miss" ]; then
        row PASS src.files - "$_secs" "each of the $(echo $_files | wc -w | tr -d ' ') files${DIR:+, from --dir}"
    else
        row FAIL src.files - "$_secs" "missing: $_miss"
    fi

    PUBLISHED=
    timed 60 "$LOGS/api.release.log" python3 -I "$HERE/release-check-api.py" release "$SLUG" "$TAG"
    _rel=$(grep "^release$TAB" "$LOGS/api.release.log")
    if [ "$RC" = 0 ] && [ -n "$_rel" ]; then
        _pre=$(printf '%s' "$_rel" | cut -f2) _draft=$(printf '%s' "$_rel" | cut -f3)
        PUBLISHED=$(printf '%s' "$_rel" | cut -f4)
        _want=false
        case $TAG in *-*) _want=true ;; esac
        if [ "$_draft" = false ] && [ "$_pre" = "$_want" ]; then
            row PASS src.kind - "$SECS" "prerelease $_pre, as the tag's form wants; published $PUBLISHED"
        else
            row FAIL src.kind - "$SECS" "draft $_draft, prerelease $_pre; the tag $TAG wants prerelease $_want"
        fi
    else
        row FAIL src.kind - "$SECS" "the public API gave no release: $(why)"
        show "$LOGS/api.release.log"
    fi

    # The tag's commit: the API's, and git's beside it where git has the tag.
    timed 60 "$LOGS/api.commit.log" python3 -I "$HERE/release-check-api.py" commit "$SLUG" "$TAG"
    COMMIT=$(grep "^commit$TAB" "$LOGS/api.commit.log" | cut -f2)
    _git=$(git -C "$REPO" rev-parse -q --verify "refs/tags/$TAG^{commit}" 2>/dev/null)
    if [ -z "$COMMIT" ] && [ -z "$_git" ]; then
        row FAIL src.commit - "$SECS" "neither the API nor git names the commit of $TAG"
    elif [ -n "$COMMIT" ] && [ -n "$_git" ] && [ "$COMMIT" != "$_git" ]; then
        row FAIL src.commit - "$SECS" "the API names $(printf '%.7s' "$COMMIT"), git $(printf '%.7s' "$_git"): a tag never moves"
    else
        COMMIT=${COMMIT:-$_git}
        row PASS src.commit - "$SECS" "$TAG is $(printf '%.7s' "$COMMIT")${_git:+, as git says}"
    fi

    # The scripts of the tag check the tag's version (release-short.sh).
    if [ "$(cargo_version)" = "${TAG#v}" ]; then
        row PASS src.checkout - 0 "Cargo.toml has ${TAG#v}"
    else
        row FAIL src.checkout - 0 "Cargo.toml has $(cargo_version), not ${TAG#v}: run from a checkout of $TAG (git worktree add .work/rc $TAG)"
    fi

    if [ -f "$D/SHA256SUMS" ]; then
        awk '{ n = $2; sub(/^\*/, "", n); print n }' "$D/SHA256SUMS" | sort >"$W/sums.names"
        for _t in $TARGETS; do binary_of "$_t"; done | sort >"$W/want.names"
        if cmp -s "$W/sums.names" "$W/want.names"; then
            row PASS sums.names - 0 "the 8 binaries, each once"
        else
            row FAIL sums.names - 0 "unknown or twice: $(comm -23 "$W/sums.names" "$W/want.names" | tr '\n' ' ')missing: $(comm -13 "$W/sums.names" "$W/want.names" | tr '\n' ' ')"
        fi
    else
        row FAIL sums.names - 0 "no SHA256SUMS"
    fi

    if ! command -v cosign >/dev/null 2>&1; then
        row FAIL sums.signature - 0 "cosign is not on PATH: install cosign 3 (release-proofs.yml takes v3.1.4)"
    else
        timed 120 "$LOGS/cosign.log" cosign verify-blob --bundle "$D/SHA256SUMS.sigstore.json" \
            --certificate-identity "https://github.com/$SLUG/.github/workflows/release.yml@refs/tags/$TAG" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com "$D/SHA256SUMS"
        by_rc sums.signature - 0 "$LOGS/cosign.log" "signed by release.yml at refs/tags/$TAG"
    fi

    timed 120 "$LOGS/sums.log" sh -c 'cd "$1" || exit 66
        if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi' sh "$D"
    by_rc sums.check - 0 "$LOGS/sums.log" "$(grep -c ': OK$' "$LOGS/sums.log") binaries match SHA256SUMS"

    if ! command -v gh >/dev/null 2>&1; then
        row FAIL provenance - 0 "gh is not on PATH: gh attestation verify checks the provenance"
    else
        _bad= _secs=0
        for _t in $TARGETS; do
            _f=$(binary_of "$_t")
            timed 120 "$LOGS/provenance.$_f.log" gh attestation verify "$D/$_f" --repo "$SLUG" \
                --bundle "$D/provenance.sigstore.json" --signer-workflow "$SLUG/.github/workflows/release.yml" \
                --source-ref "refs/tags/$TAG" --source-digest "${COMMIT:-unknown}" --deny-self-hosted-runners
            _secs=$((_secs + SECS))
            [ "$RC" = 0 ] || _bad="$_bad $_f ($(why))"
        done
        if [ -z "$_bad" ]; then
            row PASS provenance - "$_secs" "8 of 8: release.yml at refs/tags/$TAG, $(printf '%.7s' "$COMMIT")"
        else
            row FAIL provenance - "$_secs" "not proven:$_bad"
        fi
    fi

    _st=
    for _t in $TARGETS; do
        case $_t in *-linux-*) _st="$_st $D/$(binary_of "$_t"):$_t" ;; esac
    done
    # shellcheck disable=SC2086  # a list of FILE:TARGET, with no space in each
    static_rows $_st

    _mine=$(host_target)
    if [ "$_mine" = none ] || [ ! -f "$D/$(binary_of "$_mine")" ]; then
        row FAIL src.files - 0 "no published binary for this host's machine, $(uname -m)"
    else
        cp "$D/$(binary_of "$_mine")" "$W/bin/published" && chmod 755 "$W/bin/published"
        DIGESTS="The published $(binary_of "$_mine"): sha256 \`$(digest "$W/bin/published")\`."
    fi
    PRIMARY=published
    HERE_BINS=published
}
