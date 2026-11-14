"""Worker test fixtures."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "fixtures"


def docker_available() -> bool:
    """Whether a usable container runtime is on this machine.

    Checked by running it, not by looking for the binary: a Docker CLI with no daemon
    behind it is the common local case, and a test that skips for the right reason is
    worth more than one that fails for a confusing one.
    """
    binary = shutil.which(os.environ.get("DOCKER_BINARY", "docker"))
    if binary is None:
        return False
    try:
        completed = subprocess.run(  # noqa: S603
            [binary, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


needs_docker = pytest.mark.skipif(
    not docker_available(), reason="no container runtime is available on this machine"
)

#: What the minimal image is built from. The tag is derived from these, so editing
#: either one builds a new image instead of reusing the last one.
_MINIMAL_SOURCES = (
    ROOT / "infra" / "sandbox" / "minimal.Dockerfile",
    ROOT / "infra" / "sandbox" / "entrypoint.py",
)


def _minimal_image_tag() -> str:
    """A tag that changes when the entrypoint or its Dockerfile changes.

    **This was a constant tag, and that made the boundary test lie.** The image is
    built only when absent, so a machine that already had one kept running the
    *previous* entrypoint against the current test suite — indefinitely, and silently.
    Stage 3 hit it directly: two new tests for a new entrypoint feature failed against
    an image built before the feature existed, and the failure looked like a bug in the
    feature rather than a stale image.

    An adversarial test required green in CI forever is worth exactly as much as its
    guarantee that it ran against the code being shipped. Hashing the sources into the
    tag is what makes "the image is present" mean "the *right* image is present".
    """
    digest = hashlib.sha256()
    for path in _MINIMAL_SOURCES:
        digest.update(path.read_bytes())
    return f"bastion-sandbox-minimal:{digest.hexdigest()[:12]}"


#: The image the isolation test runs under by default. Built on demand from
#: ``infra/sandbox/minimal.Dockerfile``: the same entrypoint and the same profile as
#: the real scanner image, without the four gigabytes of analysers that the boundary
#: test does not exercise. See that file for why.
MINIMAL_IMAGE = _minimal_image_tag()


def ensure_minimal_sandbox_image(binary: str | None = None) -> str:
    """Build the minimal sandbox image if this machine does not already have it.

    Building inside the test rather than in a Makefile target is deliberate: the
    adversarial test is required green in CI forever, and a required test with a
    manual prerequisite is a required test that somebody eventually skips.

    "Does not already have it" is answered by :func:`_minimal_image_tag`, which folds
    the entrypoint's contents into the tag — see there for what went wrong when it did
    not.
    """
    docker = binary or os.environ.get("DOCKER_BINARY", "docker")
    present = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", MINIMAL_IMAGE],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if present.returncode == 0:
        return MINIMAL_IMAGE

    built = subprocess.run(  # noqa: S603
        [
            docker,
            "build",
            "-f",
            str(ROOT / "infra" / "sandbox" / "minimal.Dockerfile"),
            "-t",
            MINIMAL_IMAGE,
            str(ROOT / "infra" / "sandbox"),
        ],
        capture_output=True,
        check=False,
        timeout=900,
    )
    if built.returncode != 0:
        raise RuntimeError(
            "could not build the minimal sandbox image:\n"
            + built.stderr.decode("utf-8", "replace")[-2000:]
        )
    return MINIMAL_IMAGE
