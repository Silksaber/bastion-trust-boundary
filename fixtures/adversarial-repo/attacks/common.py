"""Reporting helper shared by every attack.

Deliberately trivial and deliberately structured: the test parses these lines, and an
attack that crashed before printing anything is a *missing* result rather than a
passing one.

A success does **not** stop the script. An early exit would hide every check after the
first one that got through, which is the wrong trade for the one test whose whole job
is telling you what is broken. The exit code still carries the signal — an `atexit`
hook turns any success into a non-zero exit — so a caller that only looks at the
status still sees it.
"""

from __future__ import annotations

import atexit
import os
import sys

_ESCAPED = False


def blocked(name: str, why: object) -> None:
    print(f"bastion-escape-check {name} BLOCKED {why}", flush=True)


def succeeded(name: str, what: object) -> None:
    global _ESCAPED
    _ESCAPED = True
    print(f"bastion-escape-check {name} SUCCEEDED {what}", flush=True)


@atexit.register
def _fail_loudly() -> None:
    if _ESCAPED:
        sys.stderr.write("an escape attempt succeeded\n")
        sys.stderr.flush()
        os._exit(9)
