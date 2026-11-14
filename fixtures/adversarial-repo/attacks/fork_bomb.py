"""Attempt 8 — exhaust the host's process table.

Bounded on purpose: it stops at the moment `fork()` starts failing, which is what a
working pid cgroup limit looks like from the inside. An unbounded bomb would prove the
same thing and take the developer's laptop with it if the limit were ever missing —
and a test that is dangerous when it fails is a test people disable.

The parent reaps its children before returning. Without that, a few hundred zombies
would sit in the pid cgroup holding slots, and every attack that ran after this one
would fail to start for a reason that has nothing to do with the sandbox.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from common import blocked, succeeded  # noqa: E402

CEILING = 4096
children = 0
hit_the_limit = False

while children < CEILING:
    try:
        pid = os.fork()
    except OSError as exc:
        hit_the_limit = True
        blocked("fork-bomb", f"fork failed after {children} children: {type(exc).__name__}")
        break

    if pid == 0:
        # A child: stay alive long enough to be counted, then leave immediately.
        time.sleep(2)
        os._exit(0)
    children += 1

while True:
    try:
        os.wait()
    except ChildProcessError:
        break
    except OSError:
        break

if not hit_the_limit:
    succeeded("fork-bomb", f"forked {CEILING} processes without hitting a limit")
