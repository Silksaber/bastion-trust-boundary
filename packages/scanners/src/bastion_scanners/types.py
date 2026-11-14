"""The vocabulary every adapter speaks.

Three shapes cross the boundary between an adapter and everything else:

* :class:`SandboxStep` — a command the sandbox should run. Built by the adapter,
  executed by the sandbox, understood by neither in the other's terms.
* :class:`StepResult` — what came back: exit code, streams, duration, and any file
  the tool wrote into the output directory.
* :class:`RawFinding` — one issue, in the adapter's own words, before fingerprinting.

Nothing here imports a framework, a database, or a network client. That is what lets
the same objects be built in a worker, serialised into a container with no network
namespace, and asserted against in a golden-file test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

__all__ = [
    "MAX_DIFF_TARGETS",
    "Category",
    "RawFinding",
    "SandboxStep",
    "StepResult",
    "Workspace",
]


#: Above this many changed files, a diff-scoped adapter stops naming targets and
#: scans the repository instead. Command lines have a length limit, and a pull request
#: touching more files than this is one where the diff has stopped being small.
MAX_DIFF_TARGETS = 300


class Category(StrEnum):
    """What kind of problem a finding is, independent of which tool found it.

    This is the *only* classification an adapter is allowed to assert. It is not a
    severity, not a band, and not an ordering — those are Stage 5's, computed by a
    deterministic function from facts, never chosen by a tool or a model (ADR-003).

    The set is closed at the four things the beta scan engine actually looks for. A
    scanner that finds something outside it does not exist yet, and inventing the
    member before the adapter would be reserving a name for work nobody has done.
    """

    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"
    IAC = "iac"


@dataclass(frozen=True, slots=True)
class Workspace:
    """What an adapter is allowed to know about a checkout before it plans.

    Deliberately a summary rather than a path. An adapter runs on the worker, where
    the clone is a real directory — but it will build a command that executes in a
    sandbox where the paths are different, so letting it read the filesystem would
    invite it to depend on a layout that will not exist when the command runs.

    ``relative_paths`` is every tracked file, relative to the repository root, which
    is enough to answer "is there any Terraform here" without a second traversal.

    **``changed_paths`` is Stage 6's addition, and it is the whole of diff-scoping's
    presence in this package.** ``None`` means "look at the repository" — every full
    scan, and the behaviour every adapter had before. A tuple means "look at these
    files", which is what a pull request asks for, and the three predicates below then
    answer about *those* files. An adapter that skips a repository with no Terraform in
    it therefore skips a pull request that changed no Terraform, without one line of
    adapter code knowing that pull requests exist.

    The remaining narrowing is per-adapter, because only the adapter knows how its tool
    takes a target list. ``diff_base_sha`` sits here beside the paths rather than being
    derived from them because Gitleaks does not take paths at all: a secret introduced
    by a pull request is a fact about a range of commits, not about a set of lines.
    """

    repository_full_name: str
    commit_sha: str
    relative_paths: tuple[str, ...]
    #: The files this analysis is scoped to, or ``None`` for the whole repository.
    changed_paths: tuple[str, ...] | None = None
    #: The commit the diff is measured from. Set only when ``changed_paths`` is.
    diff_base_sha: str | None = None

    @property
    def diff_scoped(self) -> bool:
        """Whether this analysis is scoped to a diff rather than to a repository."""
        return self.changed_paths is not None

    @property
    def considered(self) -> tuple[str, ...]:
        """The files an adapter should decide about — the diff's, or all of them."""
        return self.relative_paths if self.changed_paths is None else self.changed_paths

    def has_suffix(self, *suffixes: str) -> bool:
        return any(path.endswith(suffixes) for path in self.considered)

    def has_basename(self, *names: str) -> bool:
        lowered = {name.lower() for name in names}
        return any(path.rsplit("/", 1)[-1].lower() in lowered for path in self.considered)

    def paths_with_suffix(self, *suffixes: str) -> tuple[str, ...]:
        return tuple(path for path in self.considered if path.endswith(suffixes))

    def targets(self, *, limit: int = MAX_DIFF_TARGETS) -> tuple[str, ...]:
        """Explicit paths to hand a tool, or ``()`` meaning "the whole repository".

        Empty for a full scan, and empty again for a diff so large that naming every
        file would be worse than scanning everything: a command line is bounded, and a
        pull request touching a thousand files is not one where listing each path buys
        anything. An adapter that reads ``()`` does exactly what it always did, which
        is why this is the only shape diff-scoping takes inside an adapter.
        """
        if self.changed_paths is None or not self.changed_paths or len(self.changed_paths) > limit:
            return ()
        return self.changed_paths


@dataclass(frozen=True, slots=True)
class SandboxStep:
    """One command to run inside the sandbox.

    ``argv`` is a list, never a string: there is no shell in this path, so a filename
    a customer chose cannot become a command a customer chose.

    Paths are expressed in the sandbox's own terms — ``REPO_DIR`` for the checkout and
    ``OUT_DIR`` for anything the tool should write — and are substituted by the
    sandbox at execution time. An adapter that hard-codes ``/work`` has coupled itself
    to a layout it does not own.
    """

    id: str
    argv: tuple[str, ...]
    timeout_seconds: int
    env: dict[str, str] = field(default_factory=dict)
    # Non-zero exits are normal for these tools: several use the exit code to signal
    # "findings present" rather than "something went wrong". An adapter lists the codes
    # that still mean a usable result, and anything else is a failed run.
    ok_exit_codes: tuple[int, ...] = (0,)

    #: Writable directories to create before the step runs. The sandbox root
    #: filesystem is read-only and only the tmpfs mounts can be written to, so a tool
    #: that insists on a cache directory says so here.
    dirs: tuple[str, ...] = ()

    #: ``(target, link_name)`` symlinks to create before the step runs.
    #:
    #: This exists for one recurring shape: a tool that needs a large read-only data
    #: set (a vulnerability database) inside a directory it also wants to write to.
    #: Copying gigabytes into a tmpfs on every scan would be absurd, so the baked data
    #: is linked into the writable path instead. It is expressed as data rather than
    #: as code in the sandbox, because the sandbox knowing what a "vulnerability
    #: database" is would be the sandbox knowing what a scanner is.
    links: tuple[tuple[str, str], ...] = ()

    #: ``(path, content)`` files to write before the step runs.
    #:
    #: This exists for the other recurring shape: a tool whose behaviour is configured
    #: by a file at a fixed location rather than by a flag. Semgrep's ignore list is
    #: the case in hand — there is no supported command-line way to replace its
    #: built-in one, and its built-in one silently drops test trees and vendored code.
    #:
    #: The content comes from an adapter, never from the repository, and it is written
    #: into the sandbox's own copy of the checkout — a tmpfs that lives for one scan.
    #: Nothing here touches the customer's repository. The sandbox refuses a path
    #: outside its workspace; see ``infra/sandbox/entrypoint.py``.
    writes: tuple[tuple[str, str], ...] = ()

    #: Where to run, relative to the checkout. ``""`` is the repository root, which is
    #: where every step ran before this existed and where nearly all of them still do.
    #:
    #: **It exists because of one measured failure and it is not a convenience.** A
    #: repository whose tests live in a subdirectory declares them as ``cd python &&
    #: python -m pytest -q``, and there is no shell on this path — deliberately, so a
    #: repository cannot smuggle a pipeline into a command we run — so ``cd`` was looked
    #: up as an executable, was not found, and the patch verification answered *"the
    #: suite could not be run"*. Across both corpus passes of Operation SAST that was
    #: **117 of 117 patches**, every one of them offered to a customer on the strength
    #: of ``git apply`` alone.
    #:
    #: A directory is the right shape for that fact and a shell is not: it says where,
    #: it cannot say *and then*, and the sandbox can refuse one that points outside the
    #: workspace. Which it does — see ``infra/sandbox/entrypoint.py``.
    cwd: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "env": dict(self.env),
            "dirs": list(self.dirs),
            "links": [list(pair) for pair in self.links],
            "writes": [list(pair) for pair in self.writes],
            "cwd": self.cwd,
        }


@dataclass(frozen=True, slots=True)
class StepResult:
    """The result of one :class:`SandboxStep`.

    ``files`` holds anything the step wrote into the sandbox's output directory, keyed
    by file name. Tools that insist on writing a report to a path rather than to
    stdout are collected here rather than being special-cased in the sandbox.
    """

    id: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool
    truncated: bool = False
    files: dict[str, bytes] = field(default_factory=dict)

    @property
    def stderr_tail(self) -> str:
        """The last few lines of stderr, for an honest error message on a failed run."""
        text = self.stderr.decode("utf-8", errors="replace").strip()
        lines = text.splitlines()[-5:]
        return "\n".join(lines)[:2000]


@dataclass(frozen=True, slots=True)
class RawFinding:
    """One issue, in the adapter's own words.

    ``fingerprint_parts`` is the load-bearing field and the reason this type exists
    separately from the persisted one. Each adapter decides which facts identify *its*
    kind of finding across scans — and every one of them excludes line numbers, so an
    edit somewhere else in the file does not resurface a finding as new.

    ``metadata`` is free-form and is rendered, so it must never carry a secret. The
    secrets adapter in particular is under standing orders to hash rather than store.
    """

    rule_id: str
    title: str
    category: Category
    fingerprint_parts: tuple[str, ...]
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    severity_raw: str | None = None
    cve_id: str | None = None
    package: str | None = None
    version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
