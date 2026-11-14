"""Running one sandboxed job, and getting its output back out.

The container has no network, no mount, and no writable root filesystem, which leaves
exactly two channels: **stdin carries a tar in, stdout carries a tar out.** Everything
below is the mechanics of those two pipes and of killing the container when it will
not stop on its own.

The wall clock is enforced here, on the host, and not by the entrypoint. A timeout the
sandbox applies to itself is a timeout the sandbox can decline to apply.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import re
import tarfile
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import IO

from bastion_scanners import SandboxStep, StepResult
from bastion_worker.sandbox.profile import SandboxLimits, docker_run_argv, seccomp_profile_path
from bastion_worker.work_measurements import measure_work

logger = logging.getLogger(__name__)

__all__ = ["SandboxError", "SandboxRun", "SandboxRuntime", "build_plan"]

# Docker's own failure modes, kept out of the scanner error paths so a broken host is
# never reported to a customer as a broken repository.
_DOCKER_MISSING_EXIT = 127


class SandboxError(RuntimeError):
    """The sandbox itself failed — not a scanner inside it.

    Distinguished from an adapter failure on purpose. An adapter that crashes degrades
    one scanner and the scan continues; the sandbox failing to start means nothing was
    examined, and reporting that as a completed scan would be a lie about coverage.
    """


@dataclass(slots=True)
class SandboxRun:
    """Everything one container produced."""

    steps: dict[str, StepResult]
    log: str
    timed_out: bool
    exit_code: int
    duration_ms: int
    files: dict[str, bytes] = field(default_factory=dict)


def build_plan(steps: list[SandboxStep]) -> bytes:
    """Serialise the plan the entrypoint will execute."""
    return json.dumps({"steps": [step.to_json() for step in steps]}).encode("utf-8")


def build_input_tar(*, plan: bytes, workspace: Path) -> bytes:
    """The input tar as bytes. For tests and small inputs only; :meth:`run` spools it.

    A checkout with its history and a few demo GIFs is 250 MB, and building that in
    memory once per sandbox ratcheted a validation worker to 4.6 GB over 62 runs until
    the kernel killed it mid-pass (2026-11-11). See :func:`write_input_tar`.
    """
    buffer = io.BytesIO()
    write_input_tar(plan=plan, workspace=workspace, fileobj=buffer)
    return buffer.getvalue()


def write_input_tar(*, plan: bytes, workspace: Path, fileobj: IO[bytes]) -> None:
    """Pack the plan and the checkout into ``fileobj``, the tar that goes in over stdin.

    Written to a file rather than built in memory, so a worker's footprint does not
    scale with the size of the repository it happens to be validating. The tmpfs the
    sandbox unpacks into is still where an oversized repository is refused — see
    :class:`SandboxLimits` — but the worker is no longer the first thing to fall over.
    """
    with tarfile.open(fileobj=fileobj, mode="w") as archive:
        info = tarfile.TarInfo("plan.json")
        info.size = len(plan)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(plan))

        # ``recursive=True`` on the directory, with a filter that strips ownership.
        # The uids in a tar built on the worker mean nothing inside the container, and
        # leaving them in means files the sandbox user cannot read.
        archive.add(str(workspace), arcname="repo", recursive=True, filter=_own_by_sandbox)


def _own_by_sandbox(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    # Readable and writable by everyone inside a container that has exactly one user.
    # Never executable: the workspace tmpfs is mounted ``noexec`` anyway, and a tar
    # that grants +x is a tar that disagrees with the mount about what is possible.
    info.mode = 0o777 if info.isdir() else 0o666
    return info


class SandboxRuntime:
    """Starts sandboxes. Holds no state between runs, on purpose."""

    def __init__(
        self,
        *,
        image: str,
        limits: SandboxLimits,
        seccomp_path: Path | None = None,
        docker_binary: str = "docker",
    ) -> None:
        self._image = image
        self._limits = limits
        self._seccomp_path = seccomp_path
        self._docker = docker_binary

    async def pinned(self) -> SandboxRuntime:
        """Resolve an image once and use that immutable identity for all experiments."""
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self._image):
            return self
        process = await asyncio.create_subprocess_exec(
            self._docker,
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            self._image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=30)
        except BaseException:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        identity = stdout.decode().strip()
        if process.returncode or re.fullmatch(r"sha256:[0-9a-f]{64}", identity) is None:
            raise SandboxError(
                "cannot resolve the validation sandbox image to an immutable identity"
            )
        return SandboxRuntime(
            image=identity,
            limits=self._limits,
            seccomp_path=self._seccomp_path,
            docker_binary=self._docker,
        )

    def identity(self) -> dict[str, object]:
        """Settings that can change experiment outcomes, excluding host paths."""
        import hashlib

        return {
            "image": self._image,
            "limits": asdict(self._limits),
            "seccomp": hashlib.sha256(
                (self._seccomp_path or seccomp_profile_path()).read_bytes()
            ).hexdigest(),
        }

    async def run(self, *, container_name: str, plan: bytes, workspace: Path) -> SandboxRun:
        """Run one sandbox to completion, or kill it at the wall clock.

        Raises :class:`SandboxError` if the container could not be started or produced
        output that is not a tar. Everything a *scanner* did wrong comes back inside
        the result instead, because that is a scan finding out something, not a scan
        failing.
        """
        argv = docker_run_argv(
            image=self._image,
            container_name=container_name,
            limits=self._limits,
            seccomp_path=self._seccomp_path,
        )
        argv[0] = self._docker

        # Spooled to disk and handed to ``docker run`` as its stdin file: the kernel
        # feeds the container and the archive never passes through this process.
        with tempfile.TemporaryFile(prefix="bastion-sandbox-input-") as spool:
            async with measure_work("archive") as metrics:
                await asyncio.to_thread(
                    write_input_tar, plan=plan, workspace=workspace, fileobj=spool
                )
                input_bytes = spool.tell()
                spool.seek(0)
                metrics["input_bytes"] = input_bytes
            logger.info(
                "sandbox starting",
                extra={
                    "container": container_name,
                    "image": self._image,
                    "input_bytes": input_bytes,
                    "wall_clock_seconds": self._limits.wall_clock_seconds,
                },
            )

            async with measure_work("sandbox") as metrics:
                started = asyncio.get_running_loop().time()
                try:
                    process = await asyncio.create_subprocess_exec(
                        *argv,
                        stdin=spool,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                except FileNotFoundError as exc:
                    raise SandboxError(
                        f"the container runtime {self._docker!r} is not available on this host"
                    ) from exc

                timed_out = False
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=self._limits.wall_clock_seconds
                    )
                except TimeoutError:
                    timed_out = True
                    stdout, stderr = await self._kill(process, container_name)
                except asyncio.CancelledError:
                    # The job was cancelled. Killing the `docker run` client would leave
                    # the container running — the client is a remote control, not the
                    # process — so the container is addressed directly before the
                    # cancellation is allowed to propagate.
                    await self._kill(process, container_name)
                    raise

                duration_ms = int((asyncio.get_running_loop().time() - started) * 1000)
                exit_code = process.returncode if process.returncode is not None else -1
                log = stderr.decode("utf-8", errors="replace")

                if exit_code == _DOCKER_MISSING_EXIT and not stdout:
                    raise SandboxError(
                        f"the container runtime could not start the sandbox: {log[-500:]}"
                    )

                metrics["output_bytes"] = len(stdout)
                files = _unpack_output(stdout) if stdout else {}
                if not timed_out and exit_code != 0 and not files:
                    raise SandboxError(
                        f"sandbox exited {exit_code} without producing output: {log[-500:]}"
                    )

                return SandboxRun(
                    steps=_step_results(files),
                    log=log,
                    timed_out=timed_out,
                    exit_code=exit_code,
                    duration_ms=duration_ms,
                    files=files,
                )

    async def _kill(
        self, process: asyncio.subprocess.Process, container_name: str
    ) -> tuple[bytes, bytes]:
        """Kill the container, then the client, in that order.

        Killing the ``docker run`` client alone leaves the container running: the
        client is a remote control, not the process. ``docker kill`` addresses the
        thing that is actually consuming the host.
        """
        logger.warning("killing sandbox container", extra={"container": container_name})
        killer = await asyncio.create_subprocess_exec(
            self._docker,
            "kill",
            "--signal",
            "KILL",
            container_name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await killer.wait()

        try:
            return await asyncio.wait_for(process.communicate(), timeout=30)
        except TimeoutError:
            process.kill()
            return b"", b"sandbox did not exit after being killed"


def _unpack_output(payload: bytes) -> dict[str, bytes]:
    """Read the output tar the entrypoint wrote to stdout.

    A truncated archive is normal after a kill: the container died mid-write. What
    survived is kept, because a partial result honestly labelled is worth more than
    nothing, and the caller already knows the run timed out.
    """
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                handle = archive.extractfile(member)
                if handle is not None:
                    files[Path(member.name).name] = handle.read()
    except tarfile.TarError as exc:
        logger.warning("sandbox output was not a readable tar", extra={"reason": str(exc)})
    return files


def _step_results(files: dict[str, bytes]) -> dict[str, StepResult]:
    """Rebuild each step's result from the output directory.

    ``steps.json`` carries the metadata; the streams are separate files, and anything
    else in the directory is a report a tool wrote and is handed to whichever step
    might want it. Attribution of those extra files is left to the adapters: they know
    the names they asked their tool to write, and the sandbox does not.
    """
    metadata = files.get("steps.json")
    if metadata is None:
        return {}

    try:
        document = json.loads(metadata)
    except json.JSONDecodeError as exc:
        raise SandboxError("sandbox produced an unreadable step manifest") from exc

    stream_names = {
        name
        for step in document.get("steps", [])
        for name in (f"{step['id']}.stdout", f"{step['id']}.stderr")
    }
    extra = {
        name: content
        for name, content in files.items()
        if name != "steps.json" and name not in stream_names
    }

    results: dict[str, StepResult] = {}
    for step in document.get("steps", []):
        step_id = str(step["id"])
        results[step_id] = StepResult(
            id=step_id,
            exit_code=int(step.get("exit_code", -1)),
            stdout=files.get(f"{step_id}.stdout", b""),
            stderr=files.get(f"{step_id}.stderr", b""),
            duration_ms=int(step.get("duration_ms", 0)),
            timed_out=bool(step.get("timed_out")),
            truncated=bool(step.get("truncated")),
            files=extra,
        )
    return results
