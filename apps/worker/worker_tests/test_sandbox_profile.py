"""The isolation profile, asserted as a document.

ADR-009 proves the boundary adversarially, and that test needs a container runtime.
This one needs nothing: it reads the flags the runtime would pass and fails if any of
them go missing. It exists because the adversarial test can only catch a regression on
a machine that can run containers, and a pull request that quietly drops
``--network none`` should go red everywhere.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bastion_worker.sandbox import SANDBOX_UID, SandboxLimits, docker_run_argv, seccomp_profile_path


def argv() -> list[str]:
    return docker_run_argv(
        image="bastion-sandbox:test",
        container_name="bastion-scan-test",
        limits=SandboxLimits(),
    )


def flag_value(flag: str) -> list[str]:
    parts = argv()
    return [parts[i + 1] for i, part in enumerate(parts) if part == flag]


def test_the_sandbox_has_no_network_namespace() -> None:
    """ADR-004: removing the namespace beats firewalling it.

    There is no interface to misconfigure and no egress rule to get wrong, which is
    also why every scanner's threat data is baked into the image.
    """
    assert flag_value("--network") == ["none"]


def test_the_root_filesystem_is_read_only_and_the_writable_parts_are_tmpfs() -> None:
    parts = argv()
    assert "--read-only" in parts

    mounts = flag_value("--tmpfs")
    assert any(mount.startswith("/work:") for mount in mounts)
    assert any(mount.startswith("/tmp:") for mount in mounts)
    # noexec on both. The checkout lands in /work, and a repository is data, not a
    # program — this is what makes that a kernel guarantee rather than a hope.
    assert all("noexec" in mount for mount in mounts), mounts
    assert all("nosuid" in mount and "nodev" in mount for mount in mounts), mounts


def test_there_is_no_bind_mount_of_any_kind() -> None:
    """A non-negotiable, stated as an assertion.

    The checkout goes in over stdin and the results come back over stdout precisely so
    that this can be true. ``--init`` is absent for the same reason: it would
    bind-mount an init binary from the host.
    """
    parts = argv()
    assert "--volume" not in parts and "-v" not in parts
    assert "--mount" not in parts
    assert "--init" not in parts


def test_the_process_is_never_root_and_holds_no_capabilities() -> None:
    assert flag_value("--user") == [f"{SANDBOX_UID}:{SANDBOX_UID}"]
    assert SANDBOX_UID != 0
    assert flag_value("--cap-drop") == ["ALL"]
    assert "no-new-privileges" in flag_value("--security-opt")


def test_every_resource_ceiling_is_set() -> None:
    """There is no code path that runs a sandbox uncapped."""
    limits = SandboxLimits()
    assert flag_value("--pids-limit") == [str(limits.pids)]
    assert flag_value("--memory") == [f"{limits.memory_mb}m"]
    # Swap equal to memory: otherwise a memory-hungry scan escapes its cap by making
    # the host slow instead.
    assert flag_value("--memory-swap") == [f"{limits.memory_mb}m"]
    assert flag_value("--cpus") == [str(limits.cpus)]


def test_tmpfs_that_cannot_fit_in_memory_is_refused_at_construction() -> None:
    """Both tmpfs mounts are memory-backed and count against the memory cgroup."""
    with pytest.raises(ValueError, match="tmpfs"):
        SandboxLimits(memory_mb=512, workspace_mb=1024, tmp_mb=512)


def test_the_seccomp_profile_denies_by_default_and_blocks_the_escape_syscalls() -> None:
    """The profile is a reviewed document, so this asserts on the document."""
    profile = json.loads(seccomp_profile_path().read_text())
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"

    allowed: set[str] = set()
    for rule in profile["syscalls"]:
        if rule["action"] == "SCMP_ACT_ALLOW" and not rule.get("args"):
            allowed.update(rule["names"])

    forbidden = {
        "mount",
        "umount2",
        "pivot_root",
        "chroot",
        "unshare",
        "setns",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "bpf",
        "perf_event_open",
        "keyctl",
        "add_key",
        "request_key",
        "init_module",
        "finit_module",
        "delete_module",
        "kexec_load",
        "reboot",
        "swapon",
        "settimeofday",
        "clock_settime",
        "open_by_handle_at",
        "userfaultfd",
    }
    assert not (allowed & forbidden), sorted(allowed & forbidden)

    # clone is permitted, but never with a CLONE_NEW* flag: the sandboxed process must
    # not be able to build a namespace of its own to manoeuvre in.
    clone = next(rule for rule in profile["syscalls"] if rule["names"] == ["clone"])
    assert clone["args"][0]["op"] == "SCMP_CMP_MASKED_EQ"
    assert clone["args"][0]["valueTwo"] == 0

    # And the profile is passed to the runtime, not merely present in the tree.
    assert any(option.startswith("seccomp=") for option in flag_value("--security-opt")), (
        flag_value("--security-opt")
    )
    assert Path(flag_value("--security-opt")[-1].split("=", 1)[1]).is_file()


# ---------------------------------------------------------------------------
# The profile, pinned whole — Operation SAST, Stage 11
# ---------------------------------------------------------------------------
#
# The tests above assert that each control is present. Neither they nor the adversarial
# suite say that **nothing was added**, and the regression Stage 11 has to be safe
# against is exactly that shape: the stage put a JavaScript runtime into the image so
# the validator could confirm a JavaScript finding, and the tempting next step — when a
# finding still will not reproduce — is to give the container the one thing it is
# missing. A network for the SSRF case. A bind mount so the repository's real
# `node_modules` is there. `--cap-add` for something that wants a raw socket.
#
# So the whole command line is pinned as a document, the way the scanner goldens are.
# Changing the profile is allowed; changing it invisibly is not.


def test_the_whole_command_line_is_the_reviewed_one() -> None:
    """Every flag the sandbox runs under, as one literal list.

    If this fails, the profile changed. That is not automatically wrong — a new cap or
    a new tmpfs may well be right — but it has to be *decided*, in the same commit,
    with this list updated to match and the reason in the message. A boundary that can
    move without a diff somebody reads is not a boundary.
    """
    limits = SandboxLimits()
    profile = seccomp_profile_path()

    assert argv() == [
        "docker",
        "run",
        "--rm",
        "--interactive",
        "--name",
        "bastion-scan-test",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        f"/work:rw,nosuid,nodev,noexec,mode=1777,size={limits.workspace_mb}m",
        "--tmpfs",
        f"/tmp:rw,nosuid,nodev,noexec,mode=1777,size={limits.tmp_mb}m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        f"seccomp={profile}",
        "--user",
        f"{SANDBOX_UID}:{SANDBOX_UID}",
        "--cgroupns",
        "private",
        "--pids-limit",
        str(limits.pids),
        "--memory",
        f"{limits.memory_mb}m",
        "--memory-swap",
        f"{limits.memory_mb}m",
        "--cpus",
        str(limits.cpus),
        "--ulimit",
        f"nofile={limits.open_files}:{limits.open_files}",
        "--hostname",
        "sandbox",
        "--label",
        "bastion.sandbox=1",
        "--workdir",
        "/work",
        "bastion-sandbox:test",
    ]


@pytest.mark.parametrize(
    "flag",
    [
        "--privileged",
        "--cap-add",
        "--device",
        "--pid",
        "--ipc",
        "--userns",
        "--add-host",
        "--dns",
        "--publish",
        "-p",
        "--sysctl",
        "--group-add",
    ],
)
def test_no_flag_hands_back_something_the_profile_dropped(flag: str) -> None:
    """Named one by one, so the failure says which door was opened.

    Each of these is a way to return a capability the profile removes: a device, a
    shared namespace, a route to the network, a sysctl. The pinned list above would
    already catch them; this exists so that when it does, the message is the name of
    the thing that came back rather than a hundred-line diff.
    """
    assert flag not in argv()


def test_the_runtime_takes_no_argument_that_could_carry_a_credential() -> None:
    """A non-negotiable stated as a signature, and then as the command line.

    ``docker_run_argv`` has no parameter through which a token could arrive, so there
    is no ``--env`` and no ``--env-file`` on the line either. A customer's credential
    never enters a sandbox — ARCHITECTURE.md's trust boundary, kept true by the shape
    of the function rather than by everyone remembering.
    """
    parts = argv()
    assert "--env" not in parts and "-e" not in parts
    assert "--env-file" not in parts


def test_adding_a_runtime_to_the_image_changed_nothing_on_this_line() -> None:
    """Stage 11's own invariant, written where a later session will read it.

    The image gained ``node``. The profile did not gain anything, and it is the profile
    rather than the absence of interpreters that contains what runs in there — the
    image has shipped a full CPython since Stage 3. An interpreter is not a boundary.
    """
    parts = argv()
    assert flag_value("--network") == ["none"]
    assert "--read-only" in parts
    assert all("noexec" in mount for mount in flag_value("--tmpfs"))
    assert flag_value("--cap-drop") == ["ALL"]
    assert flag_value("--user") == [f"{SANDBOX_UID}:{SANDBOX_UID}"]
    assert any(option.startswith("seccomp=") for option in flag_value("--security-opt"))
