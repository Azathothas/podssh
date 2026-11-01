#!/bin/sh
# The static podssh for the box (T-251), at target/TARGET/release/podssh: built
# in the build image, as release.yml builds it, from the tree with the plant
# in place, if any. No LTO and 16 units: the box tests behaviour, not the shipped
# binary, and its rebuild then takes minutes rather than ten or more.
#
#   sh scripts/box/build-podssh.sh        (box.yml, and the SETUP of a box plant)
#   FEATURES=iroh,warp sh scripts/box/build-podssh.sh   (the release's features,
#                                         for scripts/release-check.sh --binary)

set -u
cd "$(dirname "$0")/../.." || exit 71
TARGET=${TARGET:-x86_64-unknown-linux-musl}
ref=$(tr -d '\r' <images/build/Dockerfile | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
image=$(sh scripts/pull-image.sh "$ref") || { echo "box-build: no build image" >&2; exit 1; }
# The crates that cargo downloads stay between the plants of one job.
mkdir -p .work/plant-cargo || exit 71
# A host behind a TLS-intercepting proxy (a cloud session) names its CA in
# SSL_CERT_FILE, and cargo and git in the image need it and the proxy too, as
# scripts/dev-native.sh passes them; a proxy on the host's loopback needs
# the host's network.
set --
ca=${PODSSH_HOST_CA-${SSL_CERT_FILE:-}}
if [ -n "$ca" ] && [ -r "$ca" ]; then
    set -- "$@" -v "$ca:/podssh-host-ca.crt:ro" -e CARGO_HTTP_CAINFO=/podssh-host-ca.crt -e SSL_CERT_FILE=/podssh-host-ca.crt
fi
for v in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy ALL_PROXY all_proxy; do
    eval "val=\${$v:-}"
    if [ -n "$val" ]; then
        set -- "$@" -e "$v"
    fi
done
case ${HTTPS_PROXY:-${https_proxy:-}} in
    *://127.*|*://localhost*|*://\[::1\]*) set -- "$@" --network host ;;
esac
timeout 3000 docker run --rm -v "$PWD:/work" -w /work "$@" \
    -v "$PWD/.work/plant-cargo:/usr/local/cargo/registry" \
    -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" -e RUSTFLAGS=-Ctarget-feature=+crt-static \
    -e CARGO_PROFILE_RELEASE_LTO=false -e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    "$image" cargo build --locked --release --target "$TARGET" -p podssh-cli ${FEATURES:+--features "$FEATURES"}
rc=$?
[ "$rc" = 0 ] || { echo "box-build: cargo build exited $rc" >&2; exit 1; }
[ -f "target/$TARGET/release/podssh" ] || { echo "box-build: no target/$TARGET/release/podssh" >&2; exit 1; }
