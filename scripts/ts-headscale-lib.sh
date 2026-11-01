# scripts/ts-headscale-lib.sh - the stand-in tailnet of scripts/ts-headscale.sh
# (T-334): a CA made for the run, headscale's configuration and policy, its
# container, the user and the pre-auth keys, and the nodes of tailscaled.
# Sourced by the harness; alone it runs nothing. Its functions read W, ENGINE,
# PORT and the names and images that the harness sets, and print no result
# line. Each wait has a bound, and each exit code is read directly.
#
# Each container runs on this host's network, so that one address, 127.0.0.1,
# names headscale for each node: for podssh on this host and for tailscaled in
# the containers alike. The ports: PORT (headscale, its DERP server too),
# PORT+1 (its metrics), PORT+2 (its gRPC), PORT+3 (its STUN), PORT+4 (the
# peer's SOCKS5) and PORT+5 (a TLS server that speaks no WebSocket).

# image_of DOCKERFILE: the image that its FROM line pins to a digest, the one
# place that names it. A CR is dropped, as a checkout on Windows can add one.
image_of() {
    _ref=$(tr -d '\r' <"$1" 2>/dev/null | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in
        *@sha256:*) printf '%s\n' "$_ref" ;;
        *)
            echo "ts-headscale: $1 names no image pinned to a digest" >&2
            return 1
            ;;
    esac
}

# hs_engine: PODSSH_ENGINE, else the first of podman and docker that answers
# `info`, as scripts/dev-native.sh chooses, but Podman first: the operator's
# ruling names it.
hs_engine() {
    if [ -n "${PODSSH_ENGINE:-}" ]; then
        timeout 60 "$PODSSH_ENGINE" info >/dev/null 2>&1 || return 1
        printf '%s' "$PODSSH_ENGINE"
        return 0
    fi
    for _e in podman docker; do
        command -v "$_e" >/dev/null 2>&1 || continue
        if timeout 60 "$_e" info >/dev/null 2>&1; then
            printf '%s' "$_e"
            return 0
        fi
    done
    return 1
}

# hs_pull DOCKERFILE: the image of DOCKERFILE in ENGINE, through
# scripts/pull-image.sh and its mirrors; prints the reference that served it.
hs_pull() {
    _want=$(image_of "$1") || return 1
    PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_want"
}

# hs_ca: a CA of the run, and headscale's certificate for 127.0.0.1 signed by
# it, P-256 keys for two days. Its key stays in $W, which the run removes.
hs_ca() {
    printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' \
        '[dn]' 'CN = podssh headscale stand-in' \
        '[ca_ext]' 'basicConstraints = critical,CA:TRUE' 'keyUsage = critical,keyCertSign,cRLSign' \
        'subjectKeyIdentifier = hash' >"$W/ca.cnf"
    printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = 127.0.0.1' \
        '[leaf_ext]' 'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' \
        'extendedKeyUsage = serverAuth' 'subjectAltName = IP:127.0.0.1,DNS:localhost' \
        'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 >"$W/openssl.log" 2>&1 || return 1
    timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/hs/tls.key" -out "$W/tls.csr" >>"$W/openssl.log" 2>&1 || return 1
    timeout 60 openssl x509 -req -in "$W/tls.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
        -days 2 -extfile "$W/leaf.cnf" -extensions leaf_ext -out "$W/hs/tls.crt" >>"$W/openssl.log" 2>&1 ||
        return 1
    # headscale reads its key as the container's user, whom a rootless
    # Podman maps to this one.
    chmod 600 "$W/ca.key" "$W/hs/tls.key"
}

# hs_config: headscale's configuration, its embedded DERP server the only
# region (999), no map from Tailscale; and its policy: each node of the user
# reaches each other, and Tailscale SSH lets a node of the user in as root.
hs_config() {
    cat >"$W/hs/config.yaml" <<EOF
server_url: https://127.0.0.1:$PORT
listen_addr: 127.0.0.1:$PORT
metrics_listen_addr: 127.0.0.1:$((PORT + 1))
grpc_listen_addr: 127.0.0.1:$((PORT + 2))
grpc_allow_insecure: false
tls_cert_path: /etc/headscale/tls.crt
tls_key_path: /etc/headscale/tls.key
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: podssh
    region_name: podssh stand-in
    verify_clients: true
    stun_listen_addr: 127.0.0.1:$((PORT + 3))
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
log:
  level: info
  format: text
policy:
  mode: file
  path: /etc/headscale/policy.json
dns:
  magic_dns: false
  base_domain: ts.podssh.test
  override_local_dns: false
  nameservers:
    global: []
unix_socket: /var/lib/headscale/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
EOF
    cat >"$W/hs/policy.json" <<'EOF'
{
  "acls": [{ "action": "accept", "src": ["*"], "dst": ["*:*"] }],
  "ssh": [
    {
      "action": "accept",
      "src": ["autogroup:member"],
      "dst": ["autogroup:self"],
      "users": ["root", "autogroup:nonroot"]
    }
  ]
}
EOF
}

# hs_cli ARGS...: headscale's own command line, in its container.
hs_cli() {
    timeout 60 "$ENGINE" exec "$HS_NAME" headscale "$@"
}

# hs_start: headscale in its container, its state in a tmpfs; ready when its
# TLS answers /health, within 60 s.
hs_start() {
    timeout 120 "$ENGINE" run -d --name "$HS_NAME" --network=host --tmpfs /var/lib/headscale \
        -v "$W/hs:/etc/headscale:ro,Z" "$HS_IMAGE" serve >"$W/hs-run.log" 2>&1 || return 1
    _tries=0
    until curl -fsS --noproxy '*' --max-time 2 --cacert "$W/ca.pem" \
        "https://127.0.0.1:$PORT/health" >/dev/null 2>&1; do
        _tries=$((_tries + 1))
        [ "$_tries" -ge 60 ] && return 1
        sleep 1
    done
}

# hs_keys: the user `podssh`, and two pre-auth keys of it for two hours,
# reusable: a.key for the nodes that stay, e.key for ephemeral ones. Each
# goes from headscale's stdout into its file, never to a terminal or into an
# argument; trimmed, with no line end.
hs_keys() {
    hs_cli users create podssh >"$W/hs-cli.log" 2>&1 || return 1
    hs_cli users list -o json >"$W/users.json" 2>>"$W/hs-cli.log" || return 1
    _uid=$(python3 -I -c 'import json, sys
print(next(int(u["id"]) for u in json.load(open(sys.argv[1])) if u["name"] == "podssh"))' "$W/users.json") ||
        return 1
    hs_cli preauthkeys create --user "$_uid" --reusable --expiration 2h >"$W/keys/a.raw" 2>>"$W/hs-cli.log" ||
        return 1
    hs_cli preauthkeys create --user "$_uid" --reusable --ephemeral --expiration 2h \
        >"$W/keys/e.raw" 2>>"$W/hs-cli.log" || return 1
    for _k in a e; do
        tr -d ' \r\n' <"$W/keys/$_k.raw" >"$W/keys/$_k.key" || return 1
        rm -f "$W/keys/$_k.raw"
        chmod 600 "$W/keys/$_k.key"
        [ -s "$W/keys/$_k.key" ] || return 1
    done
}

# hs_unknown_key FILE: a pre-auth key that headscale does not know, for the
# planted run: random, of the shape of one.
hs_unknown_key() {
    od -An -tx1 -N24 /dev/urandom >"$W/keys/random.hex" || return 1
    printf 'hskey-auth-' >"$1"
    tr -d ' \n' <"$W/keys/random.hex" >>"$1" || return 1
    rm -f "$W/keys/random.hex"
    chmod 600 "$1"
}

# ts_cli NAME ARGS...: the tailscale command of the node NAME, on its socket.
ts_cli() {
    _node=$1
    shift
    timeout 120 "$ENGINE" exec "$_node" tailscale --socket=/run/podssh/ts.sock "$@"
}

# ts_node NAME HOST SSH [FLAG...]: tailscaled in user space in the container
# NAME, its state in a tmpfs, the run's CA its only roots (Go reads
# SSL_CERT_FILE), no log sent to Tailscale; logged in to the stand-in as HOST
# with a.key, by its path, and Tailscale SSH on when SSH is --ssh. Each FLAG
# goes to tailscaled. `up` is tried until the daemon answers, 10 times.
ts_node() {
    _name=$1
    _host=$2
    _ssh=$3
    shift 3
    timeout 120 "$ENGINE" run -d --name "$_name" --network=host --tmpfs /var/lib/tailscale --tmpfs /run/podssh \
        -v "$W/ca.pem:/etc/podssh-hs/ca.pem:ro,z" -v "$W/keys/a.key:/etc/podssh-hs/a.key:ro,z" \
        -e SSL_CERT_FILE=/etc/podssh-hs/ca.pem --entrypoint /usr/local/bin/tailscaled "$TS_IMAGE" \
        --tun=userspace-networking --statedir=/var/lib/tailscale --socket=/run/podssh/ts.sock --port=0 \
        --no-logs-no-support "$@" >"$W/$_name-run.log" 2>&1 || return 1
    _tries=0
    until ts_cli "$_name" up --login-server="https://127.0.0.1:$PORT" --authkey=file:/etc/podssh-hs/a.key \
        --hostname="$_host" --accept-dns=false "$_ssh" --timeout=90s >>"$W/$_name-up.log" 2>&1; do
        _tries=$((_tries + 1))
        [ "$_tries" -ge 10 ] && return 1
        sleep 2
    done
}

# hs_has_node PREFIX: whether headscale's list of nodes names a node key
# that begins with PREFIX; 2 when the list is not read.
hs_has_node() {
    hs_cli nodes list -o json >"$W/nodes.json" 2>>"$W/hs-cli.log" || return 2
    grep -q "nodekey:$1" "$W/nodes.json"
}
