"""Attempt 2 — reach something over TCP, without asking DNS first.

Straight to an IP address, so that a blocked resolver is not mistaken for a blocked
network. 1.1.1.1 and 8.8.8.8 answer from essentially everywhere that has a route.
"""

from __future__ import annotations

import socket
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import blocked, succeeded  # noqa: E402

for address, port in (("1.1.1.1", 443), ("8.8.8.8", 53), ("169.254.169.254", 80)):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((address, port))
    except OSError as exc:
        blocked("tcp", f"{address}:{port}: {type(exc).__name__}")
    else:
        succeeded("tcp", f"connected to {address}:{port}")
    finally:
        sock.close()
