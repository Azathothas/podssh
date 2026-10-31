#!/bin/sh
# The fixtures of T-300's Cap'n Proto (crates/podssh-relay/tests/fixtures/quick/):
# bytes that the reference tool `capnp encode` (Cap'n Proto 1.0) writes from
# the text form beside each, with the schemas of cloudflared at 2026.10.6
# (commit 35b379a, tunnelrpc/proto/tunnelrpc.capnp and, for QUIC (T-301),
# quic_metadata_protocol.capnp, Apache-2.0) and of
# capnproto2 at v2.18.0, the version cloudflared pins (std/capnp/rpc.capnp,
# MIT). Nothing here runs in the tests: they read the bytes. Run it again
# after a change of a text form; it needs git, capnp and network.
#
#   sh scripts/quick-fixtures.sh [WORKDIR]
#
# A method's parameters and results are implicit structs, which capnp cannot
# name: params.capnp writes them out with the same fields in the same order,
# which gives the same layout. The RPC's content is an AnyPointer, which the
# text form cannot write: rpc-call.capnp and rpc-return.capnp are rpc.capnp
# with that one field typed, in the same pointer, so the same layout.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out="$here/crates/podssh-relay/tests/fixtures/quick"
work=${1:-$(mktemp -d)}
mkdir -p "$work"
command -v capnp >/dev/null || { echo "quick-fixtures: no capnp tool" >&2; exit 69; }
get() { # repository tag directory
    [ -d "$work/$3" ] || git clone -q --depth 1 --branch "$2" "https://github.com/$1.git" "$work/$3"
}
get cloudflare/cloudflared 2026.10.6 cloudflared
get capnproto/go-capnproto2 v2.18.0 go-capnproto2
proto="$work/cloudflared/tunnelrpc/proto"
[ "$(git -C "$work/cloudflared" rev-parse --short=7 HEAD)" = 35b379a ] || { echo "quick-fixtures: not 35b379a" >&2; exit 1; }
cat >"$proto/params.capnp" <<'EOF'
@0xd5c2a4f1b3e79a01;
using T = import "tunnelrpc.capnp";
struct RegisterConnectionParams {
  auth @0 :T.TunnelAuth;
  tunnelId @1 :Data;
  connIndex @2 :UInt8;
  options @3 :T.ConnectionOptions;
}
struct RegisterConnectionResults {
  result @0 :T.ConnectionResponse;
}
struct UpdateLocalConfigurationParams {
  config @0 :Data;
}
struct UnregisterConnectionParams {
}
EOF
rpc="$work/go-capnproto2/std/capnp/rpc.capnp"
grep -q '^  content @0 :AnyPointer;' "$rpc" || { echo "quick-fixtures: rpc.capnp changed" >&2; exit 1; }
# Each mirror: another file id, and the one field typed.
sed -e 's/^@0xb312981b2552a250;/@0xd5c2a4f1b3e79a02;/' -e 's/^using Cxx = import.*//' -e 's/^\$Cxx.*//' -e 's/^\$Go.*//' \
    -e 's/^using Go = import.*//' \
    -e 's/^  content @0 :AnyPointer;/  content @0 :import "params.capnp".RegisterConnectionParams;/' "$rpc" >"$proto/rpc-call.capnp"
sed -e 's/^@0xb312981b2552a250;/@0xd5c2a4f1b3e79a03;/' -e 's/^using Cxx = import.*//' -e 's/^\$Cxx.*//' -e 's/^\$Go.*//' \
    -e 's/^using Go = import.*//' \
    -e 's/^  content @0 :AnyPointer;/  content @0 :import "params.capnp".RegisterConnectionResults;/' "$rpc" >"$proto/rpc-return.capnp"
sed -e 's/^@0xb312981b2552a250;/@0xd5c2a4f1b3e79a04;/' -e 's/^using Cxx = import.*//' -e 's/^\$Cxx.*//' -e 's/^\$Go.*//' \
    -e 's/^using Go = import.*//' \
    -e 's/^  content @0 :AnyPointer;/  content @0 :import "params.capnp".UnregisterConnectionParams;/' "$rpc" >"$proto/rpc-unregister.capnp"
enc() { # schema type name
    (cd "$proto" && capnp encode "$1" "$2" <"$out/$3.txt" >"$out/$3.bin")
    echo "quick-fixtures: $3.bin, $(wc -c <"$out/$3.bin") bytes"
}
enc params.capnp RegisterConnectionParams register-params
enc params.capnp RegisterConnectionResults register-results-details
enc params.capnp RegisterConnectionResults register-results-error
enc params.capnp UpdateLocalConfigurationParams update-configuration-params
enc rpc-call.capnp Message rpc-bootstrap
enc rpc-call.capnp Message rpc-call-register
enc rpc-call.capnp Message rpc-finish
enc rpc-unregister.capnp Message rpc-call-unregister
enc rpc-return.capnp Message rpc-return-details
enc rpc-return.capnp Message rpc-return-refused
enc rpc-return.capnp Message rpc-return-exception
enc rpc-return.capnp Message rpc-abort
enc rpc-return.capnp Message rpc-return-unimplemented
# The request and the answers of a QUIC stream (T-301).
enc quic_metadata_protocol.capnp ConnectRequest quic-connect-request
enc quic_metadata_protocol.capnp ConnectRequest quic-connect-http
enc quic_metadata_protocol.capnp ConnectResponse quic-connect-response
enc quic_metadata_protocol.capnp ConnectResponse quic-connect-refusal
