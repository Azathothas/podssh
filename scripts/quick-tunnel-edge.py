#!/usr/bin/env python3
"""What the edge of Cloudflare's quick tunnels takes (T-299), measured by the
workflow quick-tunnel-edge.yml with the operator's leave (Q43). Each step is
a subcommand, and prints one line for each thing that it tried:

  roots GO_FILE OUT_PEM   the three roots of cloudflared's tlsconfig/cloudflare_ca.go
  discover                the SRV record of the edge, and the A records of its regions,
                          over DNS over HTTPS
  matrix ROOTS ADDR...    TCP and TLS to each address, by port, name, group and ALPN
                          (openssl s_client, 10 s each), and the first HTTP/2 frame
  api [PROXY]             POST https://api.trycloudflare.com/tunnel, directly or
                          through an HTTP CONNECT proxy: the status, the time, and
                          the names and types of the reply's fields
  through PROXY ROOTS NAME:PORT...
                          CONNECT to each target through the proxy, then TLS
  run LOG [OUT]           a cloudflared log, each tunnel's name redacted, and
                          into OUT the same lines, for the upload

No tunnel's secret is printed, kept or written: the reply's values are
replaced by their kinds, and a log line that holds "secret" or "credential"
is left out.
"""

import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

DOH = "https://cloudflare-dns.com/dns-query"
SRV = "_v2-origintunneld._tcp.argotunnel.com"
REGIONS = ["region1.v2.argotunnel.com", "region2.v2.argotunnel.com"]
API = "https://api.trycloudflare.com/tunnel"
AGENT = "podssh-measurement/T-299"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes([0, 0, 0, 4, 0, 0, 0, 0, 0])
FRAMES = {0: "DATA", 1: "HEADERS", 3: "RST_STREAM", 4: "SETTINGS", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE"}


def roots(go_file, out_pem):
    text = open(go_file, encoding="utf-8").read()
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    if len(blocks) != 3:
        sys.exit(f"roots: {len(blocks)} certificates in {go_file}, not 3")
    with open(out_pem, "w", encoding="utf-8") as f:
        f.write("\n".join(b.replace("\t", "") for b in blocks) + "\n")
    print(f"roots: {len(blocks)} certificates")


def doh(name, kind):
    req = urllib.request.Request(f"{DOH}?name={name}&type={kind}", headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return [a["data"] for a in json.load(r).get("Answer", []) if a.get("type") in (1, 33)]


def discover():
    records = doh(SRV, "SRV")
    for record in records:
        print(f"SRV {SRV}: {record}")
    for region in REGIONS:
        print(f"A {region}: {' '.join(doh(region, 'A')) or 'none'}")
    # The first target of the SRV answer, by its first address, for the matrix.
    target = records[0].split()[-1].rstrip(".") if records else ""
    first = doh(target, "A")[:1] if target else []
    print(f"FIRST {first[0] if first else ''}")


def s_client(addr, port, name, groups, alpn, roots_pem):
    """One cell of the matrix, as openssl s_client sees it."""
    cmd = ["timeout", "10", "openssl", "s_client", "-connect", f"{addr}:{port}", "-CAfile", roots_pem,
           "-verify_return_error"]
    cmd += ["-servername", name] if name else ["-noservername"]
    if groups:
        cmd += ["-groups", groups]
    if alpn:
        cmd += ["-alpn", alpn]
    started = time.monotonic()
    ran = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace")
    took = int((time.monotonic() - started) * 1000)
    out = ran.stdout + ran.stderr
    if "CONNECTED(" not in out:
        why = "timeout" if ran.returncode == 124 else (re.search(r"connect:errno=\d+", out) or [""])[0] or "refused"
        return f"tcp={why} ({took} ms)"
    proto = re.search(r"(?:Protocol\s*:|New, )\s*(TLSv[\d.]+|SSLv\d)", out)
    if not proto or "Cipher is (NONE)" in out:
        alert = re.search(r"alert (\w[\w ]*)|(wrong version number)|(unexpected eof)", out)
        return f"tcp=ok tls=failed ({alert.group(0) if alert else 'no handshake'}; {took} ms)"
    group = re.search(r"(?:Negotiated TLS1.3 group|Server Temp Key): ([^\n,]+(?:, [^\n,]+)?)", out)
    chosen = re.search(r"ALPN protocol: (\S+)", out)
    verify = re.search(r"Verify return code: (\d+) \(([^)]*)\)", out)
    leaf = re.search(r"^\s*0 s:(.*)$", out, re.M)
    issuers = [i.strip() for i in re.findall(r"^\s+i:(.*)$", out, re.M)]
    after = re.search(r"NotAfter: ([^;\n]+)", out)
    return (f"tcp=ok tls={proto.group(1)} group={group.group(1).replace(' ', '') if group else '?'} "
            f"alpn={chosen.group(1) if chosen else 'none'} verify={verify.group(1) + ' ' + verify.group(2) if verify else '?'} "
            f"subject={leaf.group(1).strip() if leaf else '?'!r} issuer={issuers[-1] if issuers else '?'!r} "
            f"notAfter={after.group(1).strip() if after else '?'} ({took} ms)")


def first_frame(addr, port, name, roots_pem):
    """The first frame that the edge sends after an HTTP/2 client's preface."""
    ctx = ssl.create_default_context(cafile=roots_pem)
    ctx.set_alpn_protocols(["h2"])
    try:
        with socket.create_connection((addr, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=name) as tls:
                tls.sendall(PREFACE)
                head = tls.recv(9)
                if len(head) < 9:
                    return "first frame: none (the edge closed)"
                length, kind = int.from_bytes(head[:3], "big"), head[3]
                return f"first frame: {FRAMES.get(kind, kind)}, {length} bytes"
    except (OSError, ssl.SSLError) as e:
        return f"first frame: {type(e).__name__}: {e}"


def matrix(roots_pem, addrs):
    for addr in addrs:
        for port in (7844, 443, 8443, 80):
            print(f"{addr}:{port} h2.cftunnel.com default h2 | {s_client(addr, port, 'h2.cftunnel.com', '', 'h2', roots_pem)}")
        for name in ("probe.cftunnel.com", "region1.v2.argotunnel.com", ""):
            print(f"{addr}:7844 {name or '(no name)'} default h2 | {s_client(addr, 7844, name, '', 'h2', roots_pem)}")
        for groups in ("X25519", "P-256"):
            print(f"{addr}:7844 h2.cftunnel.com {groups} h2 | {s_client(addr, 7844, 'h2.cftunnel.com', groups, 'h2', roots_pem)}")
        print(f"{addr}:7844 h2.cftunnel.com default none | {s_client(addr, 7844, 'h2.cftunnel.com', '', '', roots_pem)}")
        print(f"{addr}:7844 h2.cftunnel.com {first_frame(addr, 7844, 'h2.cftunnel.com', roots_pem)}")


def kinds(value):
    """A value replaced by its kind: the record keeps the shape, never a value."""
    if isinstance(value, dict):
        return {k: kinds(v) for k, v in value.items()}
    if isinstance(value, list):
        return [kinds(v) for v in value[:3]]
    if isinstance(value, str):
        return f"str({len(value)})"
    return type(value).__name__


def api(proxy=None):
    handlers = [urllib.request.ProxyHandler({"https": proxy})] if proxy else [urllib.request.ProxyHandler({})]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(API, method="POST", data=b"",
                                 headers={"Content-Type": "application/json", "User-Agent": AGENT})
    started = time.monotonic()
    try:
        with opener.open(req, timeout=20) as r:
            status, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    except OSError as e:
        print(f"api{' through ' + proxy if proxy else ''}: {type(e).__name__}: {e}")
        return
    took = int((time.monotonic() - started) * 1000)
    try:
        doc = json.loads(body)
        shape = json.dumps(kinds(doc), sort_keys=True)
        result = doc.get("result") if isinstance(doc, dict) else None
        host = result.get("hostname", "") if isinstance(result, dict) else ""
        form = re.sub(r"[a-z0-9]+", "WORD", host.split(".")[0]) + "." + ".".join(host.split(".")[1:]) if host else "none"
    except ValueError:
        # A refusal ("error code: 1015") is short and holds no secret; a
        # tunnel's reply is JSON, so a body that is not is never one.
        said = body[:60].decode("latin-1") if status != 200 and b"secret" not in body else ""
        shape, form = f"not JSON ({len(body)} bytes{': ' + repr(said) if said else ''})", "none"
    print(f"api{' through ' + proxy if proxy else ''}: HTTP {status}, {took} ms; hostname {form}; fields {shape}")


def through(proxy, roots_pem, targets):
    host, port = proxy.rsplit(":", 1)
    for target in targets:
        name, tport = target.rsplit(":", 1)
        try:
            with socket.create_connection((host, int(port)), timeout=10) as s:
                s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                head = b""
                while b"\r\n\r\n" not in head and len(head) < 4096:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    head += chunk
                status = head.split(b"\r\n", 1)[0].decode("latin-1")
                if " 200 " not in status + " ":
                    print(f"through {proxy} to {target}: {status}")
                    continue
                ctx = ssl.create_default_context(cafile=roots_pem)
                ctx.set_alpn_protocols(["h2"])
                try:
                    with ctx.wrap_socket(s, server_hostname="h2.cftunnel.com") as tls:
                        print(f"through {proxy} to {target}: {status}; TLS {tls.version()}, ALPN "
                              f"{tls.selected_alpn_protocol()}, verified")
                except (OSError, ssl.SSLError) as e:
                    print(f"through {proxy} to {target}: {status}; TLS failed: {e}")
        except OSError as e:
            print(f"through {proxy} to {target}: {type(e).__name__}: {e}")


def redact(line):
    """A line of cloudflared's: no colour, and no tunnel's name, which serves
    the page while the tunnel runs."""
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    return re.sub(r"[a-z0-9-]+\.trycloudflare\.com", "NAME.trycloudflare.com", line)


def run(log, out=None):
    """The log of one run, each line redacted; a line that names a secret is
    left out. With OUT, the same lines go to that file, for the upload."""
    try:
        lines = open(log, encoding="utf-8", errors="replace").read().splitlines()
    except FileNotFoundError:
        print(f"run: no log at {log}")
        return
    kept = []
    for line in lines:
        if re.search(r"secret|credential", line, re.I):
            # Worded so that the check before the upload passes over it.
            kept.append("(a line is left out here)")
        else:
            kept.append(redact(line)[:400])
    print("\n".join(kept))
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(kept) + "\n")


def main(argv):
    if not argv:
        sys.exit(__doc__)
    cmd, args = argv[0], argv[1:]
    if cmd == "roots" and len(args) == 2:
        roots(*args)
    elif cmd == "discover" and not args:
        discover()
    elif cmd == "matrix" and len(args) >= 2:
        matrix(args[0], args[1:])
    elif cmd == "api" and len(args) <= 1:
        api(*args)
    elif cmd == "through" and len(args) >= 3:
        through(args[0], args[1], args[2:])
    elif cmd == "run" and len(args) in (1, 2):
        run(*args)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
