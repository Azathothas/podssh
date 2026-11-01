#!/bin/sh
# The static podssh for the box (T-251), at target/TARGET/release/podssh: built
# in the build image, as release.yml builds it, from the tree with the plant
# in place, if any. No LTO and 16 units: the box tests behaviour, not the shipped
# binary, and its rebuild then takes minutes rather than ten or more.
#
#   sh scripts/box/build-podssh.sh        (box.yml, and the SETUP of a box plant)

set -u
cd "$(dirname "$0")/../.." || exit 71
TARGET=${TARGET:-x86_64-unknown-linux-musl}
ref=$(tr -d '\r' <images/build/Dockerfile | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
image=$(sh scripts/pull-image.sh "$ref") || { echo "box-build: no build image" >&2; exit 1; }
# The crates that cargo downloads stay between the plants of one job.
mkdir -p .work/plant-cargo || exit 71
timeout 3000 docker run --rm -v "$PWD:/work" -w /work \
    -v "$PWD/.work/plant-cargo:/usr/local/cargo/registry" \
    -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" -e RUSTFLAGS=-Ctarget-feature=+crt-static \
    -e CARGO_PROFILE_RELEASE_LTO=false -e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    "$image" cargo build --locked --release --target "$TARGET" -p podssh-cli
rc=$?
[ "$rc" = 0 ] || { echo "box-build: cargo build exited $rc" >&2; exit 1; }
[ -f "target/$TARGET/release/podssh" ] || { echo "box-build: no target/$TARGET/release/podssh" >&2; exit 1; }
