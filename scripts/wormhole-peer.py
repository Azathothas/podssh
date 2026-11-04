#!/usr/bin/env python3
"""A peer of magic-wormhole's own Python library, for the tests of the
pairing by a short code (T-086): software that podssh did not write.

    wormhole-peer.py URL APPID give
    wormhole-peer.py URL APPID take    (the code on one line of stdin)

`give` allocates a code of three words and prints `code CODE`; `take` reads
the code from stdin, never from argv. Each then prints `versions JSON` (the
other end's app_versions), sends `from python` as its first message, prints
`got HEX` of the other end's first message, and closes. A code that does not
match prints `wrong`. Each line is flushed as it is printed.

    python3 -m pip install magic-wormhole
"""

import json
import sys

from twisted.internet import defer, task

import wormhole
from wormhole.errors import WrongPasswordError


def say(*words):
    print(*words, flush=True)


@defer.inlineCallbacks
def main(reactor, url, appid, mode):
    w = wormhole.create(appid, url, reactor, versions={"podssh-test": 1})
    if mode == "give":
        w.allocate_code(3)
        code = yield w.get_code()
        say("code", code)
    else:
        w.set_code(sys.stdin.readline().strip())
    try:
        versions = yield w.get_versions()
    except WrongPasswordError:
        say("wrong")
        try:
            yield w.close()
        except Exception:
            pass
        return
    say("versions", json.dumps(versions, sort_keys=True))
    w.send_message(b"from python")
    message = yield w.get_message()
    say("got", message.hex())
    try:
        yield w.close()
    except Exception as e:
        say("close", type(e).__name__)
    say("done")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[3] not in ("give", "take"):
        sys.exit(__doc__)
    task.react(main, sys.argv[1:])
