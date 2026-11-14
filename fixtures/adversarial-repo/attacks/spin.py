"""Attempt 9 — never finish.

Ten minutes of pure CPU, against a wall clock the test sets much lower. The host kills
the container; nothing inside it is asked to cooperate, because the whole premise is
that it will not.

This attack never prints a `BLOCKED` line and that is correct: being killed is the
result, and the test asserts on the job's own status rather than on anything this
process claims about itself. An attack that can report its own defeat is an attack
that was allowed to keep running.
"""

from __future__ import annotations

import time

print("bastion-escape-check spin STARTED entering a ten-minute busy loop", flush=True)

deadline = time.time() + 600
value = 0
while time.time() < deadline:
    value = (value * 31 + 7) % 1_000_003

print("bastion-escape-check spin SUCCEEDED ran to completion", flush=True)
