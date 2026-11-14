"""Attempt 1 — resolve a name.

The first thing exfiltration does is a DNS lookup, because a hostname is smaller than
a payload and a resolver is usually reachable even when nothing else is. With no
network namespace there is no resolver, no route, and no interface to try.
"""

from __future__ import annotations

import socket
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import blocked, succeeded  # noqa: E402

for host in ("example.com", "api.github.com", "attacker.invalid"):
    try:
        socket.setdefaulttimeout(5)
        address = socket.gethostbyname(host)
    except OSError as exc:
        blocked("dns", f"{host}: {type(exc).__name__}")
    else:
        succeeded("dns", f"{host} resolved to {address}")
