"""scripts/fuzz-seeds.py: the seeds of the fuzz targets of fuzz/ (T-198).

Each seed is bytes that podssh did not make: the frames of RFC 6455's
section 5.7, the IRC lines that crates/podssh-core/tests/fixtures/grammar.txt
recorded from the RFCs and from real servers, the relay hosts that the
relay's own document names, the answers of DNS over HTTPS that three
resolvers sent (crates/podssh-ws/tests/fixtures/doh/, T-344), the messages of
Cap'n Proto that the reference encoder wrote for the quick tunnel
(crates/podssh-relay/tests/fixtures/quick/, T-403), and the capsules and
variable-length integers of connect-ip-go's tests and of RFC 9000. They go
into fuzz/corpus/TARGET/, which libFuzzer reads first and adds to.
scripts/fuzz.sh runs this before each run.
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

# connect-ip-go's TestH2DatagramStreamSendDatagram (a capsule of type 0, the
# packet 45 00 00 14) and TestH2DatagramStreamReceiveDatagram (a capsule of
# type 7, "ignore", then a packet), and RFC 9000's examples of its
# variable-length integers (Appendix A.1), as podssh-warp's tests hold them.
CAPSULES = [
    bytes([0x00, 0x04, 0x45, 0x00, 0x00, 0x14]),
    bytes([0x07, 0x06]) + b"ignore" + bytes([0x00, 0x04, 0x60, 0x00, 0x00, 0x00]),
    bytes([0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C]),
    bytes([0x9D, 0x7F, 0x3E, 0x7D]),
    bytes([0x7B, 0xBD]),
    bytes([0x25]),
    bytes([0x40, 0x25]),
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
    messages = sorted((ROOT / "crates/podssh-relay/tests/fixtures/quick").glob("*.bin"))
    if not messages:
        sys.exit("fuzz-seeds.py: no message of Cap'n Proto in crates/podssh-relay/tests/fixtures/quick")
    for message in messages:
        frame = message.read_bytes()
        put("capnp_message", frame)
        if message.name.startswith("quic-connect-"):
            put("quick_connect_request", frame)
        if message.name.startswith("rpc-"):
            # The first byte of an input of quick_control is where it is cut.
            put("quick_control", bytes([min(len(frame) // 2, 255)]) + frame)
    # The first byte of an input of warp_capsule is where it is cut.
    for capsule in CAPSULES:
        put("warp_capsule", bytes([3]) + capsule)
    put("warp_capsule", bytes([5]) + b"".join(CAPSULES[:2]))
    print(
        f"fuzz-seeds.py: {len(FRAMES)} frames, {len(lines)} IRC lines, {len(hosts)} relay hosts, "
        f"{len(answers)} DNS answers, {len(messages)} messages of Cap'n Proto, {len(CAPSULES)} capsules"
    )


if __name__ == "__main__":
    main()
