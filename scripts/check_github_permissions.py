#!/usr/bin/env python3
"""CI guard: the GitHub App asks for exactly the access a shipped stage uses.

Through Stage 3 this file said something simpler — *the App asks for no write access* —
and that sentence is no longer true. Stage 4's output is a pull request, so the App now
pushes a branch and opens one. The rule did not get deleted to make room for that; it
changed shape. A write is legal only when it appears in **both** ``ALLOWED`` and
``WRITE_PERMISSIONS``, the second of which records what bounds it. An unlisted write
still fails the build. ``admin`` fails everywhere. The names in ``FORBIDDEN`` are never
granted at any level by any stage.

What the App can do after Stage 4: create a branch, commit a patch that already applied
cleanly and passed the repository's own tests in the sandbox, and open a **draft** pull
request. Stage 6 adds one permission — ``checks: write`` — and reuses ``pull_requests``
to post inline review comments. **Stage 8 adds no permission and changes one bound**: at
``autonomous`` code autonomy, off by default, the App may mark its *own* draft ready and
squash-merge it at the exact sha its own check concluded success on, for a
``trivial``-impact fix. What it still cannot do: merge a pull request it did not author,
merge one whose check is not green, merge a commit other than the analysed one, change
branch protection, alter a workflow, read a secret, or administer anything. A red check
is a signal, and whether it is a *wall* is still decided by branch-protection settings
this App cannot read or change.

The suggestion blocks Stage 6 posts are worth naming here, because they look like write
access and are not. A GitHub suggestion is markdown in a comment; committing it is an
action the maintainer takes in their own UI, under their own account. This App cannot
apply one.

A convention nobody checks is a convention that decays, and a permission is a
one-character edit away from being widened by accident. So this runs in CI, in the same
spirit as the tighten-only policy check that Stage 8 will add for the cloud remediate
role: what the platform is *able* to do is a property worth asserting, not a comment
worth trusting. Note that the two are separate controls on separate credentials — the
tighten-only invariant does not relax because this one changed shape.

A stage that needs a new permission adds it here in the same commit that adds it to the
manifest, which makes the widening visible in the diff rather than invisible in a JSON
file nobody re-reads.

Run: ``python scripts/check_github_permissions.py``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "infra" / "github" / "app-manifest.json"

# Everything the App is permitted to request, and the stage that justifies it.
ALLOWED: dict[str, tuple[str, str]] = {
    "metadata": ("read", "Stage 2 — list repositories, names, visibility, default branches"),
    "contents": (
        "write",
        "Stage 4 — push a branch carrying a verified patch. Widened from read, which "
        "Stage 2 held; see WRITE_PERMISSIONS below for what bounds it",
    ),
    "pull_requests": (
        "write",
        "Stage 4 — open the draft pull request that carries the fix. Stage 6 uses the "
        "same grant to post and remove inline review comments on a pull request",
    ),
    "checks": (
        "write",
        "Stage 6 — post the pass/fail check run on a pull request's head commit",
    ),
}

#: Write access, listed separately and deliberately.
#:
#: Until Stage 4 this script refused *any* write outright. That blanket refusal could
#: not survive the stage whose entire output is a pull request — the brief's second
#: consequence is "every remediation is merge-ready or already done", and a product
#: that cannot author a branch cannot do that. So the rule changed shape rather than
#: being deleted: a write permission is now legal only if it is named here, with what
#: bounds it. An unlisted write still fails the build, and so does ``admin`` anywhere.
#:
#: What bounds these two, so the reviewer does not have to go looking:
#:
#: * The App can push branches and open pull requests. **Through Stage 7 it could not
#:   merge them at all**, and the draft was the boundary. Stage 8 moves that boundary by
#:   one setting, off by default: at `autonomous` code autonomy it may mark its own
#:   draft ready and merge it, for a `trivial`-impact fix whose check run is green. The
#:   sentence changed and the manifest did not — `pull_requests: write` already covered
#:   the call — which is precisely why this file records the *bound* separately from the
#:   grant. A widening that needs no manifest edit is the one that would otherwise be
#:   invisible in a diff.
#: * It holds no ``administration``, no ``workflows``, no ``secrets``, and no
#:   ``actions`` permission, so it cannot change branch protection, alter CI, read a
#:   repository secret, or run a workflow.
#: * Nothing is pushed that has not applied cleanly and passed the repository's own
#:   tests inside the sandbox first.
#:
#: This is not the tighten-only cloud invariant (ADR-015), which is a different
#: control on a different credential and does not relax here or ever.
WRITE_PERMISSIONS: dict[str, str] = {
    "contents": (
        "creates a branch and a commit, and deletes a branch it created. Cannot merge; "
        "cannot touch protection. From the release refactor it writes **only** when a "
        "person presses release — validation stores a verified patch and pushes "
        "nothing, so a repository holds no branch this platform created that nobody "
        "asked for. `delete_branch` needs no manifest edit and is bounded to "
        "`bastion/` refs we cut ourselves: it cleans up after a release whose pull "
        "request could not be opened, and removes the per-finding branches the old "
        "publish-during-validation design left behind."
    ),
    "pull_requests": (
        "opens a draft PR, posts inline review comments, and — from Stage 8, only when "
        "an organization has explicitly set code autonomy to `autonomous` — marks its "
        "*own* draft ready and squash-merges it at the exact sha its own check run "
        "concluded success on. Default off. It cannot merge a pull request it did not "
        "author, cannot merge one whose check is not green, and cannot merge a commit "
        "other than the analysed one: the merge call names the sha and GitHub refuses "
        "it if the branch has moved. A suggestion block is still a button *they* press."
    ),
    "checks": (
        "posts a check run on a commit. A red check is a signal. Whether it is a wall "
        "is decided by the repository's own branch-protection settings, which this App "
        "holds no permission to read or change — `administration` is in FORBIDDEN."
    ),
}

#: Never granted, at any level, by any stage. Each one converts "can propose a change"
#: into "can approve, bypass, or execute one", which is the boundary the draft PR is.
FORBIDDEN = {
    "administration",
    "workflows",
    "secrets",
    "actions",
    "members",
    "organization_administration",
}

# Events subscribed to. Listed for the same reason: an event is an access decision.
ALLOWED_EVENTS = {"installation", "installation_repositories", "push", "pull_request"}


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    permissions: dict[str, str] = manifest.get("default_permissions", {})
    events: list[str] = manifest.get("default_events", [])

    problems: list[str] = []

    for name, level in sorted(permissions.items()):
        if name not in ALLOWED:
            problems.append(
                f"permission {name!r} is not in the allowed set. If a stage needs it, add it "
                "to ALLOWED in this script in the same commit, with the reason."
            )
            continue
        expected, reason = ALLOWED[name]
        if level != expected:
            problems.append(
                f"permission {name!r} is {level!r}, expected {expected!r} ({reason}). "
                "Widening a permission is a deliberate act; make it one."
            )

    # Stated separately so it survives an edit to ALLOWED: a write must be justified
    # in WRITE_PERMISSIONS as well as permitted in ALLOWED. Two lists have to agree
    # before this App can change anything in a customer's repository.
    for name, level in sorted(permissions.items()):
        if level == "admin":
            problems.append(
                f"permission {name!r} grants 'admin'. No stage grants admin on a customer "
                "repository, ever. Admin can bypass the review a draft pull request exists "
                "to require."
            )
        elif level == "write" and name not in WRITE_PERMISSIONS:
            problems.append(
                f"permission {name!r} grants 'write' but is not in WRITE_PERMISSIONS. A write "
                "is a deliberate, reviewed change — record what bounds it, in the same commit."
            )

    for name in sorted(FORBIDDEN & set(permissions)):
        problems.append(
            f"permission {name!r} is never granted, at any level. It converts 'can propose a "
            "change' into 'can approve, bypass, or execute one'."
        )

    for event in sorted(set(events) - ALLOWED_EVENTS):
        problems.append(
            f"event {event!r} is subscribed but not in the allowed set. Subscribing to an "
            "event is an access decision; record it here."
        )

    if problems:
        sys.stderr.write(f"{MANIFEST.relative_to(ROOT)} requests access it should not:\n\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        return 1

    granted = ", ".join(f"{name}:{level}" for name, level in sorted(permissions.items()))
    sys.stdout.write(f"github app permission check passed: {granted}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
