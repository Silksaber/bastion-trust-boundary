"""Attempt 7 — become root.

Not root in the container, not root on the host, not by way of a setuid binary. The
runtime forces a non-zero uid, drops every capability, and sets `no-new-privileges`,
so there is no ladder to climb.
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404
import sys
from pathlib import Path

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import blocked, succeeded  # noqa: E402

if os.getuid() == 0:
    succeeded("non-root", "the sandbox is running as uid 0")
else:
    blocked("non-root", f"uid={os.getuid()} gid={os.getgid()}")

try:
    os.setuid(0)
except OSError as exc:
    blocked("setuid", type(exc).__name__)
else:
    succeeded("setuid", "setuid(0) returned success")

# CapEff is a bitmask of the capabilities the process actually holds. All dropped
# means the field is zero.
try:
    status = Path("/proc/self/status").read_text()
except OSError as exc:
    blocked("capabilities", type(exc).__name__)
else:
    effective = next(
        (line.split(":")[1].strip() for line in status.splitlines() if line.startswith("CapEff")),
        "unknown",
    )
    if effective.strip("0") == "":
        blocked("capabilities", f"CapEff={effective}")
    else:
        succeeded("capabilities", f"CapEff={effective}")

# Setuid helpers. A setuid bit on a binary is not itself an escape — the point is
# whether running it actually confers privilege. `no-new-privileges` is what makes the
# answer no, so the check runs the thing and looks at who it became.
for helper, argv in (
    ("/bin/su", ["/bin/su", "root", "-c", "id -u"]),
    ("/usr/bin/sudo", ["/usr/bin/sudo", "-n", "id", "-u"]),
    ("/bin/mount", ["/bin/mount", "-t", "proc", "proc", "/work"]),
):
    if not Path(helper).exists():
        blocked("setuid-helper", f"{helper} is absent")
        continue
    try:
        completed = subprocess.run(  # noqa: S603
            argv, capture_output=True, timeout=10, check=False, text=True
        )
    except (OSError, subprocess.SubprocessError) as exc:
        blocked("setuid-helper", f"{helper}: {type(exc).__name__}")
        continue

    if completed.returncode == 0 and completed.stdout.strip() in {"0", ""}:
        succeeded("setuid-helper", f"{helper} succeeded: {completed.stdout.strip()!r}")
    else:
        blocked("setuid-helper", f"{helper} exited {completed.returncode}")
