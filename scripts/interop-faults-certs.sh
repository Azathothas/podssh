# The certificates of scripts/interop-faults.sh, which sources this file: a
# test CA, the stand-in relays' leaf for each name of $SAN, and the same leaf
# expired (T-345). Uses its $FK, $SAN, ok and bad.

printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
    "$SAN" >"$FK/ext"
# A config of its own, so no host's default openssl.cnf adds extensions (Git
# for Windows' adds one its own openssl cannot parse).
printf '[req]\ndistinguished_name = dn\n[dn]\n' >"$FK/req.cnf"
if openssl req -config "$FK/req.cnf" -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
        -subj /CN=podssh-test-ca -addext basicConstraints=critical,CA:TRUE \
        -addext keyUsage=critical,keyCertSign,cRLSign -keyout "$FK/ca.key" -out "$FK/ca.pem" >"$FK/openssl.log" 2>&1 \
    && openssl req -config "$FK/req.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=relay.test \
        -keyout "$FK/relay.key" -out "$FK/relay.csr" >>"$FK/openssl.log" 2>&1 \
    && openssl x509 -req -in "$FK/relay.csr" -CA "$FK/ca.pem" -CAkey "$FK/ca.key" -CAcreateserial \
        -days 2 -extfile "$FK/ext" -out "$FK/relay.pem" >>"$FK/openssl.log" 2>&1; then
    ok faults.certs "the test certificates are made"
else
    bad faults.certs "the test certificates could not be made" "$FK/openssl.log"
fi
# T-345: the same leaf, valid on 2020-01-01 alone, as a host whose clock is
# wrong sees each certificate. `openssl ca` takes the dates in each OpenSSL,
# where `x509 -days -1` is refused from 3.5 on ("end date before start
# date"). A step of its own, so that its failure is faults.clock's alone; the
# names are relative to $FK, as OpenSSL reads a path in its config with
# escapes, and Windows' paths have backslashes.
printf '[ca]\ndefault_ca = fake\n[fake]\ndatabase = index.txt\nnew_certs_dir = .\nserial = serial\n' >"$FK/ca.cnf"
printf 'default_md = sha256\npolicy = any\n[any]\ncommonName = supplied\n' >>"$FK/ca.cnf"
: >"$FK/index.txt"
echo 1000 >"$FK/serial"
(cd "$FK" && openssl ca -batch -config ca.cnf -cert ca.pem -keyfile ca.key -in relay.csr \
    -startdate 20200101000000Z -enddate 20200102000000Z -extfile ext -notext -out relay-expired.pem) \
    >"$FK/openssl-expired.log" 2>&1
