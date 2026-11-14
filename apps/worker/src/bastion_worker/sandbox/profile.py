"""The isolation profile — one place, so there is one thing to review.

**This module is the trust boundary.** Everything else in Stage 3 is plumbing; this is
the file that decides whether running a stranger's repository on our infrastructure is
safe. It is deliberately short, deliberately declarative, and deliberately the only
place any of these flags appear — a second call site with a slightly different flag
list is how a boundary quietly stops being one.

The controls, and why each is here rather than a nearby weaker alternative:

``--network none``
    No network namespace at all. Not a firewall rule, not an egress policy, not a
    blocked DNS server — there is simply no interface to misconfigure and no rule to
    get wrong. ADR-004 chose this over Docker with a network policy for exactly that
    reason. It is also why every scanner's threat data is baked into the image.

``--read-only`` with ``--tmpfs`` for ``/work`` and ``/tmp``
    Nothing the container writes survives it, and nothing it writes lands on a disk we
    share with anything else. The workspace is memory, so it is bounded by the memory
    cap rather than by whatever free space the host happened to have.

``noexec`` on both tmpfs mounts
    The cloned repository lands in ``/work``. A repository is data, not a program:
    even if something persuaded a scanner to execute a file out of the checkout, the
    kernel refuses. This is the mount option that turns "we hope no adapter shells out
    into the workspace" into "it cannot".

``--cap-drop ALL`` and ``--security-opt no-new-privileges``
    No capabilities, and no path to acquiring any — a setuid binary inside the image
    cannot raise privileges, so a packaging mistake in a scanner image is not an
    escape.

``--user 65532:65532``
    Never root, even inside the namespace. Combined with the read-only root filesystem
    there is nothing writable that a uid-0 process would have been able to reach.

``--security-opt seccomp=…``
    An explicit allow-list, defaulting to ``EPERM``. ``mount``, ``unshare``, ``setns``,
    ``pivot_root``, ``ptrace``, ``bpf``, ``perf_event_open``, ``keyctl`` and the module
    loaders are absent, and ``clone`` is permitted only with no ``CLONE_NEW*`` flag —
    so the sandboxed process cannot construct a namespace of its own to manoeuvre in.

``--pids-limit``, ``--memory``, ``--cpus``, wall clock
    A fork bomb hits the pid ceiling, a memory hog hits the cgroup limit, and a
    deliberate spin hits the wall clock and is killed. All three are caps on our own
    infrastructure, not politeness.

What is deliberately **not** here:

* **No bind mount of any kind.** Not the repository, not a results directory, not
  ``docker-init``. The checkout goes in over stdin as a tar and the results come back
  over stdout as a tar, which is why ``--init`` is absent too: it would bind-mount an
  init binary from the host, and "no host mount" is a rule worth keeping literally
  true rather than nearly true.
* **No credential.** The installation token is used by the worker to clone and never
  enters the container — ARCHITECTURE.md's trust-boundary table, stated as code by the
  fact that this function takes no secret to pass on.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = ["SANDBOX_UID", "SandboxLimits", "docker_run_argv", "seccomp_profile_path"]

#: The uid the image creates and the runtime insists on. Never 0.
SANDBOX_UID = 65532


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    """Every resource ceiling a scan runs under.

    Defaults are sized for a small-to-medium repository on a modest worker. They are
    configuration (see ``.env.example``) because the right numbers depend on the host,
    but they are never *absent*: there is no code path that runs a sandbox uncapped.
    """

    cpus: float = 2.0
    memory_mb: int = 2048
    #: Hard ceiling on processes. A fork bomb reaches it in milliseconds and stops.
    pids: int = 256
    #: The tmpfs holding the checkout. Counts against ``memory_mb``.
    workspace_mb: int = 1024
    #: The tmpfs holding scratch space and caches.
    tmp_mb: int = 512
    #: Enforced by the *host*, not by anything inside the container. A sandbox that
    #: was trusted to time itself out would be a sandbox trusting the thing it exists
    #: to contain.
    wall_clock_seconds: int = 1800
    open_files: int = 4096

    def __post_init__(self) -> None:
        if self.memory_mb <= self.workspace_mb + self.tmp_mb:
            raise ValueError(
                "sandbox memory must exceed its tmpfs mounts: both are memory-backed, "
                f"and {self.workspace_mb} + {self.tmp_mb} MB of tmpfs cannot fit in "
                f"{self.memory_mb} MB"
            )


def seccomp_profile_path() -> Path:
    """The checked-in seccomp profile.

    Read from the repository rather than embedded in this module, because it is a
    document that gets reviewed: ``infra/sandbox/seccomp.json`` is meant to be read in
    a diff, the same way ``infra/github/app-manifest.json`` is.
    """
    return Path(__file__).resolve().parents[5] / "infra" / "sandbox" / "seccomp.json"


def docker_run_argv(
    *,
    image: str,
    container_name: str,
    limits: SandboxLimits,
    seccomp_path: Path | None = None,
) -> list[str]:
    """The complete command line for one sandboxed scan.

    Returned as a list rather than run here, so a test can assert on the flags
    directly — the adversarial test proves the boundary holds, and this makes the
    profile itself reviewable without starting a container.
    """
    profile = seccomp_path or seccomp_profile_path()
    if not profile.is_file():
        raise FileNotFoundError(f"seccomp profile not found at {profile}")

    tmpfs = "rw,nosuid,nodev,noexec,mode=1777,size="

    return [
        "docker",
        "run",
        "--rm",
        "--interactive",
        "--name",
        container_name,
        # -- the boundary ---------------------------------------------------
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        f"/work:{tmpfs}{limits.workspace_mb}m",
        "--tmpfs",
        # S108 flags "/tmp" as an insecure temporary path. Here it is the opposite:
        # this is the mount that makes the container's /tmp a private, capped, noexec
        # tmpfs that dies with the job, rather than a directory shared with anything.
        f"/tmp:{tmpfs}{limits.tmp_mb}m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        f"seccomp={profile}",
        "--user",
        f"{SANDBOX_UID}:{SANDBOX_UID}",
        # Its own cgroup namespace, so the host's cgroup hierarchy is not readable
        # from inside — one of the more informative things a container can look at.
        "--cgroupns",
        "private",
        # -- the caps -------------------------------------------------------
        "--pids-limit",
        str(limits.pids),
        "--memory",
        f"{limits.memory_mb}m",
        # Equal to --memory: swap would let a memory-hungry scan escape its cap by
        # making the host slow instead.
        "--memory-swap",
        f"{limits.memory_mb}m",
        "--cpus",
        str(limits.cpus),
        "--ulimit",
        f"nofile={limits.open_files}:{limits.open_files}",
        # -- cosmetics that are not cosmetic --------------------------------
        # A fixed hostname, so nothing inside can learn the host's name.
        "--hostname",
        "sandbox",
        "--label",
        "bastion.sandbox=1",
        "--workdir",
        "/work",
        image,
    ]
