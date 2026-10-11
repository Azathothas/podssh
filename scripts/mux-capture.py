#!/usr/bin/env python3
"""A relay on an OpenSSH control socket that logs each message (T-039).

    python3 scripts/mux-capture.py LISTEN_PATH MASTER_PATH LOG

Listens on LISTEN_PATH; for each client, connects to the master at
MASTER_PATH and copies both ways, passing file descriptors through
(SCM_RIGHTS), and writes one line to LOG for each read: the direction, the
bytes in hex and the number of descriptors. The tests of podssh's control
protocol hold bytes that this relay captured between OpenSSH's own client
and master.
"""
import os
import socket
import sys
import threading

listen_path, master_path, log_path = sys.argv[1:4]
lock = threading.Lock()


def log(line):
    with lock, open(log_path, "a") as f:
        f.write(line + "\n")


def pump(name, src, dst):
    while True:
        try:
            data, fds, _flags, _addr = socket.recv_fds(src, 65536, 8)
        except OSError:
            break
        if not data and not fds:
            break
        log(f"{name} {data.hex()} fds={len(fds)}")
        try:
            if fds:
                socket.send_fds(dst, [data], fds)
                for fd in fds:
                    os.close(fd)
            else:
                dst.sendall(data)
        except OSError:
            break
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def serve(client):
    master = socket.socket(socket.AF_UNIX)
    master.connect(master_path)
    log("-- connection")
    a = threading.Thread(target=pump, args=("c>m", client, master), daemon=True)
    b = threading.Thread(target=pump, args=("m>c", master, client), daemon=True)
    a.start()
    b.start()
    a.join()
    b.join()
    client.close()
    master.close()


server = socket.socket(socket.AF_UNIX)
server.bind(listen_path)
server.listen(8)
while True:
    conn, _ = server.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
