"""scripts/fuzz-seeds.py: the seeds of the fuzz targets of fuzz/ (T-198).

Each seed is bytes that podssh did not make: the frames of RFC 6455's
section 5.7, the IRC lines that crates/podssh-core/tests/fixtures/grammar.txt
recorded from the RFCs and from real servers, the relay hosts that the
relay's own document names, and the answers of DNS over HTTPS that three
resolvers sent (crates/podssh-ws/tests/fixtures/doh/, T-344). They go into
fuzz/corpus/TARGET/, which libFuzzer reads first and adds to. scripts/fuzz.sh
runs this before each run.
"""
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "fuzz" / "corpus"

# RFC 6455, section 5.7: a text frame unmasked and masked, a fragmented one,
# a Ping and a masked Pong, and the heads of a 256-byte and a 64 KiB binary
# frame (the second cut short, as a stream gives it).
HELLO = bytes([0x48, 0x65, 0x6C, 0x6C, 0x6F])
MASKED_HELLO = bytes([0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58])
FRAMES = [
    bytes([0x81, 0x05]) + HELLO,
    bytes([0x81, 0x85]) + MASKED_HELLO,
    bytes([0x01, 0x03, 0x48, 0x65, 0x6C]) + bytes([0x80, 0x02, 0x6C, 0x6F]),
    bytes([0x89, 0x05]) + HELLO,
    bytes([0x8A, 0x85]) + MASKED_HELLO,
    bytes([0x82, 0x7E, 0x01, 0x00]) + bytes(256),
    bytes([0x82, 0x7F, 0, 0, 0, 0, 0, 0x01, 0, 0]) + bytes(64),
]


def put(target, seed):
    """Write `seed` under its digest, as libFuzzer names a corpus file."""
    directory = CORPUS / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / hashlib.sha1(seed).hexdigest()).write_bytes(seed)


def irc_lines():
    """The wire lines of the grammar fixture, each with its CRLF."""
    text = (ROOT / "crates/podssh-core/tests/fixtures/grammar.txt").read_bytes()
    for line in text.split(b"\r\n"):
        if line.startswith(b"#") or b" ||| " not in line:
            continue
        yield line.split(b" ||| ", 1)[0] + b"\r\n"


def relay_hosts():
    """The relay hosts that the relay's document names, once each."""
    spec = (ROOT / "crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt").read_text("utf-8")
    return sorted(set(re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.ajam\.dev\b", spec)))


def main():
    for frame in FRAMES:
        put("ws_frame", frame)
    lines = list(irc_lines())
    if not lines:
        sys.exit("fuzz-seeds.py: the grammar fixture gave no line")
    for line in lines:
        put("irc_message", line)
    # The first byte of an input of irc_framing is where it is cut in two.
    put("irc_framing", bytes([7]) + b"".join(lines))
    hosts = relay_hosts()
    if not hosts:
        sys.exit("fuzz-seeds.py: the relay's document named no host")
    for host in hosts:
        put("relay_list", host.encode())
        put("relay_list", f"{host}:443".encode())
    put("relay_list", ",".join(hosts).encode())
    pool = ",".join('{"host":"%s"}' % host for host in hosts)
    put("relay_pool", ('{"pool":[%s]}' % pool).encode())
    answers = sorted((ROOT / "crates/podssh-ws/tests/fixtures/doh").glob("*.bin"))
    if not answers:
        sys.exit("fuzz-seeds.py: no answer of DNS over HTTPS in crates/podssh-ws/tests/fixtures/doh")
    for answer in answers:
        put("dns_wire", answer.read_bytes())
    print(
        f"fuzz-seeds.py: {len(FRAMES)} frames, {len(lines)} IRC lines, {len(hosts)} relay hosts, "
        f"{len(answers)} DNS answers"
    )


if __name__ == "__main__":
    main()
