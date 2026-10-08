#!/bin/sh
# The binary never enables the feature `plain-ws` of podssh-ws (T-068): a
# plain WebSocket would carry a token over TCP with no TLS. `cargo tree` gives
# the features that the build of podssh-cli resolves. Its exit code is read on
# its own, not through a pipe, so a failure of cargo is not a pass.
tree=$(cargo tree --locked -p podssh-cli -e features 2>&1)
rc=$?
if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$tree"
    echo "FAIL cargo tree exited $rc"
    exit 1
fi
case "$tree" in
    *plain-ws*)
        printf '%s\n' "$tree" | grep plain-ws
        echo "FAIL the binary enables plain-ws"
        exit 1
        ;;
esac
echo "ok   the binary does not enable plain-ws"
