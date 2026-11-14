"""The sandbox: the trust boundary Stage 3 exists to build.

:mod:`~bastion_worker.sandbox.profile` is the isolation itself and is the file to read
first. :mod:`~bastion_worker.sandbox.runtime` is the mechanics of getting a job in and
its results out through the only two channels that remain once the boundary is in
place.
"""

from __future__ import annotations

from bastion_worker.sandbox.profile import (
    SANDBOX_UID,
    SandboxLimits,
    docker_run_argv,
    seccomp_profile_path,
)
from bastion_worker.sandbox.runtime import (
    SandboxError,
    SandboxRun,
    SandboxRuntime,
    build_input_tar,
    build_plan,
)

__all__ = [
    "SANDBOX_UID",
    "SandboxError",
    "SandboxLimits",
    "SandboxRun",
    "SandboxRuntime",
    "build_input_tar",
    "build_plan",
    "docker_run_argv",
    "seccomp_profile_path",
]
