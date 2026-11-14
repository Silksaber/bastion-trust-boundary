"""Attempt 3 — read things that would tell us about the host.

The cloud metadata service is the single most valuable thing to reach from a
compromised workload, and `egress_http` already tries it. This one looks locally
instead.

The distinction that matters here is between *the container's* files and *the host's*.
The sandbox has its own PID namespace, so `/proc/1` is the sandbox entrypoint and
`/proc/1/root` is the container's own root filesystem — reading things there is not an
escape, it is reading ourselves. What must not be reachable is a host resource that
leaked inside: a bind-mounted filesystem, a Docker socket, a credential file. And what
must not be *readable* is a file that only root may read, because the process is not
root.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import blocked, succeeded  # noqa: E402

# Present inside the sandbox ⇒ a host resource crossed the boundary.
FORBIDDEN = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/host",
    "/hostfs",
    "/etc/kubernetes",
    "/root/.aws/credentials",
    "/var/lib/kubelet",
]

for candidate in FORBIDDEN:
    path = Path(candidate)
    try:
        exists = path.exists()
    except OSError as exc:
        blocked("host-path", f"{candidate}: {type(exc).__name__}")
        continue
    if exists:
        succeeded("host-path", f"{candidate} is present inside the sandbox")
    else:
        blocked("host-path", f"{candidate} is absent")

# Root-only files. These exist in any Linux image; the question is whether a process
# that is not root can read them.
for restricted in ("/etc/shadow", "/proc/1/root/etc/shadow"):
    try:
        Path(restricted).read_bytes()
    except OSError as exc:
        blocked("root-only-file", f"{restricted}: {type(exc).__name__}")
    else:
        succeeded("root-only-file", f"read {restricted}")

# PID 1's environment. In our own PID namespace this is the sandbox entrypoint, whose
# environment we already know; what must never appear in it is a credential.
try:
    environ = Path("/proc/1/environ").read_bytes().decode("utf-8", "replace")
except OSError as exc:
    blocked("proc-1-environ", type(exc).__name__)
else:
    leaked = [
        token
        for token in ("GITHUB_", "CREDENTIAL_", "SESSION_SECRET", "DATABASE_URL", "ghs_", "AWS_")
        if token in environ
    ]
    if leaked:
        succeeded("proc-1-environ", f"credential-shaped variables present: {leaked}")
    else:
        blocked("proc-1-environ", "readable, and carries nothing sensitive")
