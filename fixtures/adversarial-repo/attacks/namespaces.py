"""Attempt 6 — build a namespace to manoeuvre in, and drop the seccomp filter.

Almost every container escape starts by acquiring a namespace: `unshare(CLONE_NEWUSER)`
to become root somewhere, then `CLONE_NEWNS` to mount something. The seccomp profile
permits `clone` only with no `CLONE_NEW*` flag and denies `unshare`, `setns`, `mount`,
`pivot_root`, and `ptrace` outright.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import blocked, succeeded  # noqa: E402

CLONE_NEWUSER = 0x10000000
CLONE_NEWNS = 0x00020000
CLONE_NEWNET = 0x40000000

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

for name, flag in (
    ("unshare-user", CLONE_NEWUSER),
    ("unshare-mount", CLONE_NEWNS),
    ("unshare-net", CLONE_NEWNET),
):
    result = libc.unshare(flag)
    if result == 0:
        succeeded(name, "unshare() returned success")
    else:
        blocked(name, f"errno {ctypes.get_errno()}")

# mount(2) directly, in case unshare was the only thing filtered.
result = libc.mount(b"proc", b"/work/mnt", b"proc", 0, None)
if result == 0:
    succeeded("mount", "mount() returned success")
else:
    blocked("mount", f"errno {ctypes.get_errno()}")

# ptrace(PTRACE_ATTACH) against PID 1.
result = libc.ptrace(16, 1, 0, 0)
if result == 0:
    succeeded("ptrace", "attached to pid 1")
else:
    blocked("ptrace", f"errno {ctypes.get_errno()}")
