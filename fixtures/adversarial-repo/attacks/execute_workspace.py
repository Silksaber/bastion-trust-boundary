"""Attempt 5 — execute a file out of the checkout.

The classic shape of a malicious repository: ship a binary, mark it executable, run it.
The workspace tmpfs is mounted `noexec`, so the kernel refuses regardless of the mode
bits — which is the difference between hoping no scanner shells out into the workspace
and it not being possible.
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404
import sys
from pathlib import Path

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import blocked, succeeded  # noqa: E402

payload = Path("/work/payload.sh")
try:
    payload.write_text("#!/bin/sh\necho owned\n")
    os.chmod(payload, 0o755)
except OSError as exc:
    blocked("exec-workspace", f"could not even stage the payload: {type(exc).__name__}")
    raise SystemExit(0) from None

try:
    subprocess.run([str(payload)], check=True, capture_output=True, timeout=10)  # noqa: S603
except (OSError, subprocess.SubprocessError) as exc:
    blocked("exec-workspace", f"{type(exc).__name__}")
else:
    succeeded("exec-workspace", "a file in the workspace executed")
