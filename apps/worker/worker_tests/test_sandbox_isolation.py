"""**The adversarial sandbox test. Required green in CI from Stage 3 forever (ADR-009).**

A repository crafted to escape is executed inside the real sandbox profile, and every
attempt must fail. Configuration review catches what you thought of; an adversarial
test catches regressions in what you forgot — and for the component that decides
whether we leak customers' source code, that difference is the whole thing.

**Why the repository's own code is executed.** Semgrep and Checkov parse files, they do
not run them, so a malicious repository cannot attack us through them today. It can
from Stage 4, where the validator agent executes customer code deliberately to confirm
a finding is real. This test models that threat now, because the boundary has to hold
before the thing that leans on it arrives — not after.

**The image is a parameter.** By default the test uses a small stock Python image,
because what is being tested is the *profile* — the same
:func:`~bastion_worker.sandbox.profile.docker_run_argv` that the scanner image runs
under, from the same single source of truth. Point ``BASTION_SANDBOX_TEST_IMAGE`` at
``bastion-sandbox:latest`` to run it against the real thing; the assertions are
identical and so is the result. Keeping the default small is what lets this run on
every commit rather than nightly, and a test that runs on every commit is the one that
catches the regression.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
from pathlib import Path

import pytest

from bastion_scanners import SandboxStep
from bastion_worker.sandbox import SandboxLimits, SandboxRuntime, build_plan

from .conftest import FIXTURES, ensure_minimal_sandbox_image, needs_docker

pytestmark = [pytest.mark.sandbox, needs_docker]

ADVERSARY = FIXTURES / "adversarial-repo"


def image() -> str:
    """The image to run the attacks in.

    Defaults to the minimal sandbox image, built on demand. Override with
    ``BASTION_SANDBOX_TEST_IMAGE=bastion-sandbox:latest`` to run the identical
    assertions against the full scanner image.
    """
    return os.environ.get("BASTION_SANDBOX_TEST_IMAGE") or ensure_minimal_sandbox_image()


# Every attack, and the check names it is expected to report. Listing the names is what
# turns "no attack succeeded" into a real assertion: an attack that crashed before
# printing anything would otherwise look exactly like an attack that was blocked.
ATTACKS: dict[str, tuple[str, ...]] = {
    "egress_dns": ("dns",),
    "egress_http": ("tcp",),
    "read_host": ("host-path", "root-only-file", "proc-1-environ"),
    "write_outside": ("write-outside",),
    "execute_workspace": ("exec-workspace",),
    "namespaces": ("unshare-user", "unshare-mount", "unshare-net", "mount", "ptrace"),
    "privileges": ("non-root", "setuid", "capabilities", "setuid-helper"),
    "fork_bomb": ("fork-bomb",),
}

RESULT_LINE = re.compile(r"^bastion-escape-check (?P<name>\S+) (?P<verdict>\S+) (?P<detail>.*)$")


def attack_steps() -> list[SandboxStep]:
    """One step per attack, invoked through the interpreter.

    ``python3 <file>`` rather than executing the file: the workspace is mounted
    ``noexec``, and the point of ``execute_workspace`` is that it stays that way.
    """
    return [
        SandboxStep(
            id=name,
            argv=("python3", f"{{REPO_DIR}}/attacks/{name}.py"),
            timeout_seconds=120,
            env={"PYTHONDONTWRITEBYTECODE": "1"},
            # Every one of these is expected to fail in some way. The verdict comes
            # from the printed lines, not from the exit code — except that a script
            # reporting SUCCEEDED deliberately exits 9, which is asserted below.
            ok_exit_codes=tuple(range(0, 130)),
        )
        for name in ATTACKS
    ]


async def run_attacks(**limit_overrides: object) -> object:
    limits = SandboxLimits(
        cpus=1.0,
        memory_mb=1024,
        pids=256,
        workspace_mb=256,
        tmp_mb=256,
        wall_clock_seconds=300,
        **limit_overrides,  # type: ignore[arg-type]
    )
    runtime = SandboxRuntime(image=image(), limits=limits)
    return await runtime.run(
        container_name=f"bastion-escape-{os.getpid()}",
        plan=build_plan(attack_steps()),
        workspace=ADVERSARY,
    )


@pytest.fixture(scope="module")
def outcome() -> object:
    """One sandbox run, shared by the assertions below.

    Starting eight containers to make eight assertions would triple this test's cost
    for no additional coverage: the attacks are independent and the boundary is the
    same for all of them.
    """
    return asyncio.run(run_attacks())


def verdicts(outcome: object) -> list[tuple[str, str, str]]:
    lines: list[tuple[str, str, str]] = []
    for step in outcome.steps.values():  # type: ignore[attr-defined]
        for line in step.stdout.decode("utf-8", "replace").splitlines():
            match = RESULT_LINE.match(line.strip())
            if match:
                lines.append((match["name"], match["verdict"], match["detail"]))
    return lines


# ---------------------------------------------------------------------------
# The assertions
# ---------------------------------------------------------------------------


def test_every_escape_attempt_was_blocked(outcome: object) -> None:
    """Nothing got out. The single assertion this whole stage is arranged around."""
    succeeded = [entry for entry in verdicts(outcome) if entry[1] == "SUCCEEDED"]
    assert not succeeded, "\n".join(f"{name}: {detail}" for name, _, detail in succeeded)


def test_every_expected_check_actually_ran(outcome: object) -> None:
    """An attack that never ran is not an attack that was blocked.

    Without this, deleting a fixture file — or breaking it with a syntax error — would
    turn the test above green while removing its coverage entirely.
    """
    reported = {name for name, _, _ in verdicts(outcome)}
    expected = {name for names in ATTACKS.values() for name in names}
    missing = expected - reported
    assert not missing, f"these checks produced no result at all: {sorted(missing)}"


def test_the_sandbox_ran_as_a_non_root_user(outcome: object) -> None:
    assert "uid=0 " not in outcome.log, outcome.log[:500]  # type: ignore[attr-defined]
    assert re.search(r"uid=\d+", outcome.log)  # type: ignore[attr-defined]


def test_no_container_from_this_test_is_still_running() -> None:
    """The host is unaffected, checked from the host rather than from inside.

    A fork bomb and a ten-minute spin are only contained if nothing survives them.

    Filtered by **this test's own container names**, not by the sandbox label. The
    label is on every sandbox the product starts, so a label-wide check fails whenever
    a legitimate scan happens to be running — which it did, the first time this suite
    ran on a machine with a live worker. A test that goes red because the product is
    working is a test people learn to ignore.
    """
    completed = subprocess.run(  # noqa: S603
        [
            os.environ.get("DOCKER_BINARY", "docker"),
            "ps",
            "--all",
            "--filter",
            f"name=bastion-escape-{os.getpid()}",
            "--format",
            "{{.Names}} {{.Status}}",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert completed.stdout.strip() == "", completed.stdout


def test_a_deliberate_spin_is_killed_at_the_wall_clock() -> None:
    """The ninth attack: never finish.

    Ten minutes of CPU against a wall clock set far lower. The kill is performed by the
    *host* — a sandbox trusted to time itself out is not a sandbox — so this asserts on
    the run's own status rather than on anything the process inside claims about
    itself. An attack that can report its own defeat is one that was allowed to keep
    running.
    """

    async def spin() -> object:
        runtime = SandboxRuntime(
            image=image(),
            limits=SandboxLimits(
                cpus=1.0,
                memory_mb=1024,
                workspace_mb=256,
                tmp_mb=256,
                wall_clock_seconds=20,
            ),
        )
        return await runtime.run(
            container_name=f"bastion-escape-spin-{os.getpid()}",
            plan=build_plan(
                [
                    SandboxStep(
                        id="spin",
                        argv=("python3", "{REPO_DIR}/attacks/spin.py"),
                        # Deliberately longer than the wall clock, so that what stops
                        # it is the host's cap and not the step's own timeout.
                        timeout_seconds=600,
                    )
                ]
            ),
            workspace=ADVERSARY,
        )

    result = asyncio.run(spin())
    assert result.timed_out is True  # type: ignore[attr-defined]
    assert b"SUCCEEDED" not in b"".join(
        step.stdout
        for step in result.steps.values()  # type: ignore[attr-defined]
    )


def test_the_adversarial_fixture_is_present_and_complete() -> None:
    """The fixture is product infrastructure, so its absence is a failure, not a skip."""
    for name in ATTACKS:
        assert (ADVERSARY / "attacks" / f"{name}.py").is_file(), name
    assert (ADVERSARY / "attacks" / "spin.py").is_file()
    assert (Path(ADVERSARY) / "README.md").is_file()


# ---------------------------------------------------------------------------
# `writes`: a file placed into the workspace before a step runs
# ---------------------------------------------------------------------------


async def _run_writes(writes: tuple[tuple[str, str], ...], argv: tuple[str, ...]) -> object:
    """One step, with files declared, in the real sandbox profile."""
    runtime = SandboxRuntime(
        image=image(),
        limits=SandboxLimits(
            cpus=1.0,
            memory_mb=512,
            pids=128,
            workspace_mb=64,
            tmp_mb=64,
            wall_clock_seconds=120,
        ),
    )
    step = SandboxStep(
        id="writes",
        argv=argv,
        timeout_seconds=60,
        ok_exit_codes=tuple(range(0, 130)),
        writes=writes,
    )
    return await runtime.run(
        container_name=f"bastion-writes-{os.getpid()}",
        plan=build_plan([step]),
        workspace=ADVERSARY,
    )


def test_a_declared_file_is_written_into_the_workspace() -> None:
    """Semgrep's coverage policy arrives this way, and nothing else can deliver it.

    There is no supported flag that replaces Semgrep's built-in ignore list — the file
    at the project root is the mechanism — so this is the path that decides whether the
    scanner reads a repository's test tree. If it silently stopped working, coverage
    would silently shrink back, which is the exact failure Stage 3 exists to end.
    """
    run = asyncio.run(
        _run_writes(
            (("{REPO_DIR}/.semgrepignore", "node_modules/\n"),),
            ("cat", "{REPO_DIR}/.semgrepignore"),
        )
    )
    step = run.steps["writes"]  # type: ignore[attr-defined]
    assert step.exit_code == 0, step.stderr.decode("utf-8", "replace")
    assert step.stdout.decode() == "node_modules/\n"


def test_a_write_outside_the_workspace_is_refused() -> None:
    """The plan is ours, not a repository's — and that is exactly why this is checked.

    `unpack_input` already refuses to trust its own tar for the same reason. A writer
    that trusts its own plan is one upstream bug away from writing into the image, and
    it is cheaper to refuse than to reason about. The step still runs; only the write
    is dropped, and the sandbox log says so.
    """
    run = asyncio.run(
        _run_writes(
            (("{REPO_DIR}/../../etc/passwd", "root::0:0::/:/bin/sh\n"),),
            ("head", "-1", "/etc/passwd"),
        )
    )
    step = run.steps["writes"]  # type: ignore[attr-defined]
    assert step.exit_code == 0
    assert not step.stdout.decode().startswith("root::0:0")
    assert "refusing to write outside the workspace" in run.log  # type: ignore[attr-defined]
