# The rows of the release check (T-251), sourced by scripts/release-check.sh:
# one place for each check's ID, the modes that run it (local, tag, both),
# its entry, where it runs, its limit in seconds (0: none of its own) and
# what makes it pass. A row that the run owed and did not make fails, so a
# check cannot drop out of the run unseen. `--list` prints this.
#
# A SKIP names the entry or the operator's question that holds it, and an
# ACTIONS row names the workflow that runs it on GitHub's runners.

catalog() {
    cat <<'EOF'
src.files|tag|T-250|here|300|each file of the release downloads: the 8 binaries of release.yml, SHA256SUMS, its bundle, the provenance's bundle, THIRD-PARTY-LICENSES.md
src.kind|tag|T-250|here|60|the public API: the release is no draft, and a prerelease only when the tag has a suffix
src.commit|tag|T-210|here|60|the tag's commit from the public API, the same as git's when git has the tag
src.checkout|both|T-251|here|10|local: the tree is clean at the artifact's commit; tag: Cargo.toml has the tag's version
sums.names|tag|T-211|here|10|SHA256SUMS names each of the 8 binaries once, and nothing else
sums.signature|tag|T-211|here|120|cosign verify-blob: SHA256SUMS signed by release.yml at the tag (a missing cosign fails)
sums.check|both|T-211|here|120|each binary against SHA256SUMS (local: against --sums; with none, the digest is recorded and the published sums wait for T-250)
provenance|tag|T-210|here|900|gh attestation verify of each binary with the bundle: release.yml at the tag and its commit (a missing gh fails)
static|both|T-218|here|60|each Linux binary: no NEEDED, no INTERP, and the machine of its name (readelf)
build.local|local|T-251|here|3600|cargo build --release with release.yml's RELEASE_FEATURES, or --build PATH, and its --version runs
short|both|T-218|here|300|scripts/release-short.sh BINARY --net exits 0 (the tag: its commit in --version)
sandbox|both|T-006|here|900|scripts/sandbox-check.sh BINARY exits 0: doctor --full, ping, proxy github.com 22, ssh -T and -tt to GitHub's refusal, the prompts, a listener, OpenSSH with podssh as its ProxyCommand
readme|both|T-251|here|240|README's first steps: man ssh, keygen -t ed25519 -N '', keygen -l, and status, each exit 0 with its output
pipe|both|T-176|here|240|pipe stdio exec:cat, and stdio unix-connect: to a server of Python's, each carry 5,000,000 bytes back with an equal SHA-256
railway|both|T-084|here|240|ssh -tt and ssh -T to railway.new through the relay, a throwaway key: exit 3 of 'exit 3' each; no output is shown; SKIP on railway.new's own limit for an anonymous visitor (T-422)
reverse.two|both|T-083|here|300|a node of the live relay in front of this host's sshd: one session, then two at once, exit 3 of 'exit 3' each
cp.200mib|both|T-155|here|3600|cp of 200 MiB up and down through that node: exit 0 each, and three equal SHA-256
iroh.n0|both|T-163|here|600|node --iroh through n0's relays (Q50): a client key refused and named, then let in, and exit 3 of 'exit 3'
container.short|both|T-218|a fresh container|600|the static binary in the box's Alpine image, on this host's network: release-short.sh --net exits 0
container.sandbox|both|T-006|a fresh container|900|the same container: sandbox-check.sh exits 0
update.check|tag|T-375|here|300|podssh update --check --version TAG exits 0: the binary checks its own release's signature
irc.live|both|T-252|here|700|chat --irc --send to a throwaway channel with a throwaway nick (Q39): OFTC (three tries), else libera, else undernet, exit 0
irc.image|both|T-252|the build image|3600|scripts/irc-in-image.sh exits 0: ngircd, plain text and TLS (scripts/dev.sh run)
headscale|both|T-334|here|5400|scripts/ts-headscale.sh exits 0, or 3 when only the live relay's runs are left to actions.headscale (T-026's exit 7 is one of its runs)
throughput|both|T-157|here|7200|throughput_live with PODSSH_THROUGHPUT_MIB=100 and n0's relay use1-1 (Q38) exits 0
throughput.loop|both|T-157|here|0|that run has a cell of the forward road through the relay's loop (the decision of 2026-10-31)
throughput.direct|both|T-157|none|0|SKIP: the direct cell needs the operator's SSH host (Q38; the decision of 2026-10-31 names it as not run)
serve.box|both|T-248|none|0|SKIP: podssh serve with vi, less and Ctrl-C in the box: T-248 is held by the operator (Q32)
reverse.boxes|both|T-085|none|0|SKIP: two sessions from one box to a node in another box: T-085 is held by the operator (Q32)
tailnet|both|T-334|none|0|SKIP: the operator's tailnet and the key of .env/ (Q40): headscale stands in (the decision of 2026-10-31)
actions.gate|both|T-251|GitHub Actions|0|build.yml at the commit: its job all, so each step of the gate in the build image, the plant, the checks, windows, macos and tor-net
actions.resume|both|T-156|GitHub Actions|0|build.yml at the commit: the job gate (m6), a session that survives a killed relay connection, a new address and a stall
actions.windows|both|T-218|GitHub Actions|0|build.yml at the commit: the job windows, the tests and the console checks on windows-2025
actions.macos|both|T-218|GitHub Actions|0|build.yml at the commit: the job macos, the tests on macos-15
actions.plants|both|T-251|GitHub Actions|0|plants.yml at the commit: each job, so each planted defect failed its check
actions.release|both|T-218|GitHub Actions|0|release.yml at the commit (local: by hand; tag: the tag's run): the 8 targets built and run, the notes, publish
actions.proofs|tag|T-211|GitHub Actions|0|release-proofs.yml after the publication: the proofs as a user checks them, and podssh update (T-375)
actions.update|both|T-375|GitHub Actions|0|update-live.yml: podssh update on Linux, macOS and Windows
actions.box|both|T-006|GitHub Actions|0|box.yml at the commit: the box like the target sandbox, default, nolisten (T-358) and tt (T-004)
actions.chat|both|T-099|GitHub Actions|0|box.yml at the commit: chat between two boxes (scripts/chat-in-boxes.sh)
actions.headscale|both|T-334|GitHub Actions|0|ts-headscale.yml at the commit: each run, the live relay's three among them
actions.node|both|T-155|GitHub Actions|0|relay-live.yml at the commit with test=node_live: 10 minutes idle and 200 MiB each way through a node (T-154)
actions.backpressure|both|T-062|GitHub Actions|0|relay-live.yml at the commit with test=live_backpressure: through the relay's loop (Q42)
actions.warp|both|T-352|GitHub Actions|0|warp-live.yml at the commit, confirm=Q52: WARP's road from GitHub's network
actions.quick|both|T-300|GitHub Actions|0|quick-tunnel-live.yml at the commit, confirm=Q43: Cloudflare's edge from GitHub's network
actions.forwarders|both|T-370|GitHub Actions|0|forwarder-live.yml at the commit: the public forwarders of GitHub #59 (Q56)
actions.hop|both|T-371|GitHub Actions|0|hop-live.yml at the commit: a -J hop on port 443
actions.doh|both|T-344|GitHub Actions|0|doh-live.yml at the commit: DNS over HTTPS by address and by name
actions.service|both|T-121|GitHub Actions|0|service-live.yml at the commit: a node as a unit of systemd
actions.deny|both|T-341|GitHub Actions|0|deny.yml at the commit: advisories, licenses, sources
EOF
}

# The ACTIONS rows: ID|NAME of --actions-run|workflow|jobs|commit rule|how
# to start the run. Jobs: GLOB:N, a glob of the job's name and the least
# number of jobs that match it, each of which must have passed; *:all is
# each job of the run. The rule: commit, the run is at the commit under
# check; after, at the tag's commit or started after the publication. REF is
# main at the commit, or the tag.
actions_spec() {
    cat <<'EOF'
actions.gate|build|build.yml|all:1|commit|the push of the commit starts it: gh run list -w build.yml -c COMMIT
actions.resume|build|build.yml|gate (m6):1|commit|the same run of build.yml
actions.windows|build|build.yml|windows:1|commit|the same run of build.yml
actions.macos|build|build.yml|macos:1|commit|the same run of build.yml
actions.plants|plants|plants.yml|*:all|commit|gh workflow run plants.yml --ref REF
actions.release|release|release.yml|linux *:4;macos *:2;windows *:2;notes:1;publish:1|commit|local: gh workflow run release.yml --ref REF; tag: the tag's own run
actions.proofs|proofs|release-proofs.yml|proofs:1|after|gh workflow run release-proofs.yml --ref REF -f tag=TAG
actions.update|update|update-live.yml|update (*):3|after|gh workflow run update-live.yml --ref REF (tag: -f tag=TAG)
actions.box|box|box.yml|box (default):1;box (nolisten):1;box (tt):1|commit|gh workflow run box.yml --ref REF
actions.chat|box|box.yml|box (chat):1|commit|the same run of box.yml
actions.headscale|headscale|ts-headscale.yml|live:1|commit|gh workflow run ts-headscale.yml --ref REF
actions.node|relay-node|relay-live.yml|live:1|commit|gh workflow run relay-live.yml --ref REF -f test=node_live
actions.backpressure|relay-backpressure|relay-live.yml|live:1|commit|gh workflow run relay-live.yml --ref REF -f test=live_backpressure
actions.warp|warp|warp-live.yml|live:1|commit|gh workflow run warp-live.yml --ref REF -f confirm=Q52
actions.quick|quick|quick-tunnel-live.yml|live:1|commit|gh workflow run quick-tunnel-live.yml --ref REF -f confirm=Q43
actions.forwarders|forwarders|forwarder-live.yml|live:1|commit|gh workflow run forwarder-live.yml --ref REF
actions.hop|hop|hop-live.yml|live:1|commit|gh workflow run hop-live.yml --ref REF
actions.doh|doh|doh-live.yml|live:1|commit|gh workflow run doh-live.yml --ref REF
actions.service|service|service-live.yml|unit:1|commit|gh workflow run service-live.yml --ref REF
actions.deny|deny|deny.yml|deny:1|commit|the push of the commit starts it: gh run list -w deny.yml -c COMMIT
EOF
}

# list_catalog [MODE]: each row of MODE (or each row), and for an ACTIONS
# row the NAME of --actions-run and how to start its run.
list_catalog() {
    printf '%-20s %-5s %-6s %-17s %-6s %s\n' ID MODES ENTRY WHERE LIMIT "PASSES WHEN"
    catalog | while IFS='|' read -r _id _modes _entry _where _limit _pass; do
        case ${1:-}/$_modes in /* | */both | local/local | tag/tag) ;; *) continue ;; esac
        printf '%-20s %-5s %-6s %-17s %-6s %s\n' "$_id" "$_modes" "$_entry" "$_where" "$_limit" "$_pass"
        _spec=$(actions_spec | awk -F'|' -v id="$_id" '$1 == id')
        [ -z "$_spec" ] || printf '%-20s --actions-run %s=RUN; %s\n' "" \
            "$(printf '%s' "$_spec" | cut -d'|' -f2)" "$(printf '%s' "$_spec" | cut -d'|' -f6)"
    done
}
