"""Attempt 4 — write anywhere that is not the workspace.

A read-only root filesystem is what stops a scan from leaving anything behind, and
what stops one job from planting something for the next one to execute.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import blocked, succeeded  # noqa: E402

TARGETS = [
    "/etc/bastion-owned",
    "/usr/local/bin/bastion-owned",
    "/opt/bastion/entrypoint.py",
    "/bastion-owned",
    "/var/bastion-owned",
    "/home/sandbox/.bashrc",
]

for target in TARGETS:
    try:
        Path(target).write_text("owned")
    except OSError as exc:
        blocked("write-outside", f"{target}: {type(exc).__name__}")
    else:
        succeeded("write-outside", f"wrote {target}")
