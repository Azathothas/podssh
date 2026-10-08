#!/usr/bin/env python3
"""Hold a pty pair open with nobody at its master, and write the path of
its slave to PATHFILE.

scripts/test_in_box.sh binds the slave at /dev/tty in the box. Then
/dev/tty opens, is a terminal, is the controlling terminal of no process,
and never answers. The target sandbox has such a /dev/tty: its sandprobe
report says "opened but no byte available within 10s; it blocked rather
than refused", and a prompt that trusted the open waited there for ever
(GitHub #15).

    python3 deadtty.py SECONDS PATHFILE

It stops after SECONDS, or within a second after PATHFILE is removed, so a
run that stops early leaves no holder behind for long.
"""

import os
import sys
import time


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    seconds = float(sys.argv[1])
    pathfile = sys.argv[2]
    master, slave = os.openpty()
    path = os.ttyname(slave)
    # The box is uid 0 with no capabilities, so it has no DAC override, and a
    # rootless podman maps its uid 0 to another uid: anyone may open it.
    os.chmod(path, 0o666)
    # Written whole, then renamed, so a reader never sees half a path.
    with open(pathfile + ".tmp", "w", encoding="ascii") as f:
        f.write(path + "\n")
    os.rename(pathfile + ".tmp", pathfile)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and os.path.exists(pathfile):
        time.sleep(1)
    # Both ends stay open until here; nothing is ever written to the master.
    os.close(slave)
    os.close(master)
    return 0


if __name__ == "__main__":
    sys.exit(main())
