#!/bin/bash
# sshd already listens on 22. Something must listen on 3389 too, or a probe can't tell
# "blocked by the network" from "nothing there". It accepts a connection and closes it.
cat > /usr/local/bin/listen.py <<'PY'
import socket
import sys

server = socket.create_server(("", int(sys.argv[1])))
while True:
    conn, _ = server.accept()
    conn.close()
PY
nohup python3 /usr/local/bin/listen.py 3389 >/dev/null 2>&1 &
