#!/usr/bin/env python3
"""The only process the sandbox starts.

**This file does not know what a scanner is**, and that is its most important
property. It reads a plan of commands, runs them, and hands back what they printed.
Registering Semgrep and registering a tool nobody has written yet look identical from
in here, which is what makes Stage 3's promise — *adding an adapter requires no
changes outside ``packages/scanners/``* — actually true rather than aspirational.

The protocol is three sentences:

* **stdin** is a tar stream containing ``plan.json`` and a ``repo/`` directory.
* **stdout** is a tar stream of the output directory, and nothing else, ever.
* **stderr** is the log, and is read by a human, not parsed.

stdout carries a tar rather than JSON because scanner output is large, sometimes
binary-ish, and often written to a file rather than a stream. One framing that handles
all of it beats three special cases.

There is no network namespace in here, no host mount, no root, and no writable root
filesystem. If this file ever appears to need one of those, the answer is that it does
not — see ``infra/sandbox/README.md``.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess  # noqa: S404 - running untrusted tools is this file's entire job
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

WORK = Path("/work")
REPO_DIR = WORK / "repo"
OUT_DIR = WORK / "out"
PLAN_PATH = WORK / "plan.json"

# Per-stream ceiling on what one step may print. A tool that emits a gigabyte of
# progress output is a tool that would otherwise fill the tmpfs and take the whole
# scan down with it; truncating is recorded on the step rather than hidden.
MAX_STREAM_BYTES = 32 * 1024 * 1024

# The environment every step starts from. Explicit rather than inherited: a variable
# that arrives here by accident is a variable a customer's repository might read.
BASE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
    "TMPDIR": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    # Nothing in here can reach a proxy, and a tool that believes it can spends its
    # timeout finding out. Stated so the discovery is instant instead of slow.
    "no_proxy": "*",
    "NO_PROXY": "*",
}


def log(message: str) -> None:
    print(f"[sandbox] {message}", file=sys.stderr, flush=True)


def unpack_input() -> None:
    """Extract the job tar from stdin into the workspace.

    ``filter="data"`` refuses absolute paths, parent-directory traversal, symlinks
    pointing outside the archive, and device nodes. We build this tar ourselves, so it
    is not the customer's input — but the whole point of the sandbox is that it holds
    even when something upstream is wrong, and an extractor that trusts its archive is
    the classic way that stops being true.
    """
    WORK.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
        archive.extractall(path=WORK, filter="data")  # noqa: S202 - filtered above

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPO_DIR.mkdir(parents=True, exist_ok=True)


def substitute(value: str) -> str:
    return value.replace("{REPO_DIR}", str(REPO_DIR)).replace("{OUT_DIR}", str(OUT_DIR))


def prepare(step: dict[str, Any]) -> None:
    """Create the writable directories and symlinks a step declared it needs."""
    for raw in step.get("dirs") or []:
        Path(substitute(str(raw))).mkdir(parents=True, exist_ok=True)

    for pair in step.get("links") or []:
        target, link_name = (substitute(str(part)) for part in pair)
        link = Path(link_name)
        if link.exists() or link.is_symlink():
            continue
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target)
        except OSError as exc:
            log(f"could not link {link_name} -> {target}: {exc}")

    for pair in step.get("writes") or []:
        raw_path, content = (str(part) for part in pair)
        destination = Path(substitute(raw_path))
        # The content is an adapter's, not a repository's, and the plan is built by us
        # — but a writer that trusts its plan is the same mistake `unpack_input`
        # refuses to make, and it is cheaper to refuse than to reason about. Anything
        # that resolves outside the workspace is dropped and said out loud.
        try:
            resolved = destination.resolve()
            resolved.relative_to(WORK.resolve())
        except (OSError, ValueError):
            log(f"refusing to write outside the workspace: {raw_path}")
            continue
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(content, encoding="utf-8")
        except OSError as exc:
            log(f"could not write {raw_path}: {exc}")


def working_dir(step: dict[str, Any]) -> Path:
    """Where this step runs: the checkout, or a directory inside it.

    The default is the checkout root and always was. A step that names something else
    is a repository whose test suite lives in a subdirectory — the shape that used to
    arrive as ``cd python && python -m pytest -q`` and be looked up as an executable
    called ``cd``.

    Refused rather than corrected if it points outside the workspace, and refused if it
    is not a directory: the plan is ours, but a plan carrying a path that resolves
    somewhere unexpected is exactly the input this file is not allowed to trust. The
    fallback is the checkout root, which is where the command would have run anyway,
    and the refusal is logged rather than silent.
    """
    raw = str(step.get("cwd") or "").strip()
    if not raw:
        return REPO_DIR
    candidate = Path(substitute(raw))
    if not candidate.is_absolute():
        candidate = REPO_DIR / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(WORK.resolve())
    except (OSError, ValueError):
        log(f"refusing a working directory outside the workspace: {raw}")
        return REPO_DIR
    if not resolved.is_dir():
        log(f"working directory does not exist: {raw}")
        return REPO_DIR
    return resolved


def run_step(step: dict[str, Any]) -> dict[str, Any]:
    """Run one command, bounded by its own timeout, and record what happened."""
    step_id = str(step["id"])
    argv = [substitute(str(part)) for part in step["argv"]]
    timeout = int(step.get("timeout_seconds") or 300)

    env = dict(BASE_ENV)
    env.update({str(k): substitute(str(v)) for k, v in (step.get("env") or {}).items()})

    prepare(step)
    cwd = working_dir(step)

    where = "" if cwd == REPO_DIR else f" (in {cwd.relative_to(WORK)})"
    log(f"{step_id}:{where} {' '.join(argv)}")
    started = time.monotonic()
    timed_out = False

    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell, by design
            argv,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            timeout=timeout,
            check=False,
            # A new process group, so a tool that spawns children can be killed with
            # its children rather than leaving them behind holding the tmpfs open.
            start_new_session=True,
        )
        stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or b""
        stderr = (exc.stderr or b"") + b"\n[sandbox] step exceeded its timeout\n"
        exit_code = 124
    except (OSError, ValueError) as exc:
        stdout, stderr, exit_code = b"", f"[sandbox] could not start: {exc}".encode(), 127

    duration_ms = int((time.monotonic() - started) * 1000)
    truncated = len(stdout) > MAX_STREAM_BYTES or len(stderr) > MAX_STREAM_BYTES
    stdout, stderr = stdout[:MAX_STREAM_BYTES], stderr[:MAX_STREAM_BYTES]

    (OUT_DIR / f"{step_id}.stdout").write_bytes(stdout)
    (OUT_DIR / f"{step_id}.stderr").write_bytes(stderr)

    log(f"{step_id}: exit={exit_code} timed_out={timed_out} {duration_ms}ms")
    return {
        "id": step_id,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "timed_out": timed_out,
        "truncated": truncated,
    }


def emit_output(steps: list[dict[str, Any]]) -> None:
    """Write the output directory to stdout as a tar stream.

    Built in memory and written in one go: a partially-written tar on a stream the
    caller is already parsing is indistinguishable from a corrupt one, and the caller
    would have no way to tell a crash from a truncation.
    """
    (OUT_DIR / "steps.json").write_text(json.dumps({"steps": steps}), encoding="utf-8")

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path in sorted(OUT_DIR.iterdir()):
            if path.is_file():
                archive.add(path, arcname=path.name)

    sys.stdout.buffer.write(buffer.getvalue())
    sys.stdout.buffer.flush()


def main() -> int:
    log(f"uid={os.getuid()} gid={os.getgid()} cwd={Path.cwd()}")
    unpack_input()

    plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    steps = plan.get("steps") or []
    log(f"plan has {len(steps)} step(s)")

    results = [run_step(step) for step in steps]

    # The checkout is deleted before the results leave. The tmpfs dies with the
    # container either way; doing it explicitly means a bug in the tar-building code
    # below cannot turn into customer source code on somebody's stdout.
    shutil.rmtree(REPO_DIR, ignore_errors=True)

    emit_output(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
