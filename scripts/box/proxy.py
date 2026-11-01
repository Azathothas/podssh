#!/usr/bin/env python3
"""The egress proxy of the test box: an HTTP CONNECT proxy with the policy
the target sandbox's proxy was measured to have (sandprobe report,
2026-10-04, docs/target-environment.md):

  CONNECT to ports 443, 80 and 8443        -> 200 Connection Established
  any other port                           -> 403 not on the egress allowlist
  an address that is not public            -> 403 not a public host
  anything but CONNECT                     -> 405

It resolves names itself, so a client behind it needs no DNS. Each request
is logged to stdout as one line: the status, then the request line.

`--allow NAME:PORT=HOST:PORT` lets one test target through, by the exact
name and port that the client asks for: an SSH server next to the box
(T-004). Every other request meets the policy above.

`--take names` refuses an address literal with 403 not on the allowlist,
as a proxy that allows listed names only does; `--take addresses` refuses
a name with 403 names are not allowed; `--take both`, the default, takes
each (T-366).

`--carry COMMAND` carries each CONNECT that the policy takes through a
process of COMMAND, its last word with HOST:PORT appended, whose stdin
and stdout are the stream: `--carry 'podssh proxy warp://'` puts each one
inside WARP's tunnel, for a live test of a client that honours HTTPS_PROXY
(T-398). The process resolves the name, so the proxy does not.

Usage: proxy.py [--listen HOST:PORT] [--allow NAME:PORT=HOST:PORT ...] [--take names|addresses|both]
                [--carry COMMAND]
"""

import argparse
import asyncio
import ipaddress
import shlex
import socket
import sys

ALLOWED_PORTS = {443, 80, 8443}
# NAME:PORT -> (HOST, PORT): the test targets of --allow.
TARGETS = {}
# What a CONNECT may name: names, addresses, or both (--take).
TAKE = {"mode": "both"}
# The words of --carry's command, or none.
CARRY = {"argv": None}


def is_literal(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def log(line):
    print(line, flush=True)


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def answer(writer, status, reason, request_line):
    log(f"{status} {request_line}")
    writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n".encode())
    await writer.drain()
    writer.close()


async def carried(reader, writer, host, port, request_line):
    """The CONNECT to HOST:PORT through a process of --carry's command."""
    argv = list(CARRY["argv"])
    shown = f"[{host}]" if ":" in host else host
    argv[-1] = f"{argv[-1]}{shown}:{port}"
    try:
        child = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
        )
    except OSError:
        await answer(writer, 502, "Bad Gateway", request_line)
        return
    log(f"200 {request_line} (carried)")
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    await asyncio.gather(pipe(reader, child.stdin), pipe(child.stdout, writer))
    try:
        child.terminate()
    except ProcessLookupError:
        pass
    # Bounded: a process that does not end at its signal is left.
    try:
        await asyncio.wait_for(child.wait(), 10)
    except asyncio.TimeoutError:
        pass


async def handle(reader, writer):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, OSError):
        writer.close()
        return
    request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = request_line.split()
    if len(parts) != 3 or parts[0] != "CONNECT":
        await answer(writer, 405, "Method Not Allowed", request_line)
        return
    host, _, port_text = parts[1].rpartition(":")
    host = host.strip("[]")
    target = TARGETS.get(f"{host}:{port_text}")
    if target is not None:
        try:
            up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(*target), 15)
        except (OSError, asyncio.TimeoutError):
            await answer(writer, 502, "Bad Gateway", request_line)
            return
        log(f"200 {request_line} (the test target)")
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        return
    if not port_text.isdigit() or int(port_text) not in ALLOWED_PORTS:
        await answer(writer, 403, "not on the egress allowlist", request_line)
        return
    if TAKE["mode"] == "names" and is_literal(host):
        await answer(writer, 403, "not on the allowlist", request_line)
        return
    if TAKE["mode"] == "addresses" and not is_literal(host):
        await answer(writer, 403, "names are not allowed", request_line)
        return
    port = int(port_text)
    if CARRY["argv"]:
        await carried(reader, writer, host, port, request_line)
        return
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        await answer(writer, 502, "Bad Gateway", request_line)
        return
    addresses = [info[4][0] for info in infos]
    if not addresses or not all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses):
        await answer(writer, 403, "not a public host", request_line)
        return
    try:
        up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(addresses[0], port), 15)
    except (OSError, asyncio.TimeoutError):
        await answer(writer, 502, "Bad Gateway", request_line)
        return
    log(f"200 {request_line}")
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0:45331")
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--take", choices=["names", "addresses", "both"], default="both")
    parser.add_argument("--carry", default=None)
    args = parser.parse_args()
    TAKE["mode"] = args.take
    if args.carry:
        CARRY["argv"] = shlex.split(args.carry)
    for item in args.allow:
        name, target = item.split("=", 1)
        target_host, target_port = target.rsplit(":", 1)
        TARGETS[name] = (target_host, int(target_port))
    host, port = args.listen.rsplit(":", 1)
    server = await asyncio.start_server(handle, host, int(port))
    log(f"listening on {args.listen}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
