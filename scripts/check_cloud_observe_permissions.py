#!/usr/bin/env python3
"""CI guard: the observe role can only read, at all, ever.

Stage 7's analogue of ``scripts/check_github_permissions.py``, applied to the AWS
observe role instead of the GitHub App: a permission is one character away from being
widened by accident, and a policy file nobody re-reads is where that goes unnoticed.

This checks a narrower, stronger property than the GitHub script does. That one
allows *some* writes, each named and bounded in ``WRITE_PERMISSIONS``. This one allows
**none** — every action in the observe policy must be a read verb (``Get``, ``List``,
``Describe``), or appear in the small, named exception list below with a reason its
effect is still read-only despite the verb. This is a different, additional control
from the Stage 8 tighten-only invariant, which will apply to the separate
``remediate`` grant and permits a bounded set of *closing* writes; this script never
will, because the observe role has no reason to write anything at all.

Cross-format agreement between this JSON document, the CloudFormation template, and
the Terraform snippet is a separate check —
``cloud_tests/test_policy_document.py`` — because that comparison needs to parse YAML
and HCL, dependencies this standalone script does not carry.

Run: ``python scripts/check_cloud_observe_permissions.py``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "infra" / "aws" / "observe-policy.json"

_READ_VERBS = ("Get", "List", "Describe")

#: Actions whose verb is not literally Get/List/Describe, with the reason each is
#: still read-only. Must match ``bastion_cloud.policy.READ_VERB_EXCEPTIONS`` — the
#: cross-format test asserts that agreement too.
READ_VERB_EXCEPTIONS: dict[str, str] = {
    "iam:GenerateCredentialReport": (
        "starts an async report AWS already maintains; changes nothing in the account"
    ),
}


def main() -> int:
    document = json.loads(POLICY.read_text(encoding="utf-8"))
    problems: list[str] = []

    for statement in document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        for action in statement.get("Action", []):
            if action in READ_VERB_EXCEPTIONS:
                continue
            verb = _verb(action)
            if verb not in _READ_VERBS:
                problems.append(
                    f"action {action!r} is not a read verb ({', '.join(_READ_VERBS)}) and is "
                    "not in READ_VERB_EXCEPTIONS. The observe role may never write, create, "
                    "delete, or modify anything — if this action is genuinely read-only "
                    "despite its verb, add it to READ_VERB_EXCEPTIONS with the reason."
                )
        resource = statement.get("Resource")
        if resource not in ("*", ["*"]):
            # Not a violation by itself, but worth surfacing: a scoped resource on a
            # read-only action is unusual enough to be worth a human's attention.
            sys.stdout.write(
                f"note: statement {statement.get('Sid', '?')!r} scopes Resource to "
                f"{resource!r} rather than '*' — confirm that is deliberate.\n"
            )

    if problems:
        sys.stderr.write(f"{POLICY.relative_to(ROOT)} requests access it should not:\n\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        return 1

    actions = [
        action
        for statement in document.get("Statement", [])
        for action in statement.get("Action", [])
    ]
    sys.stdout.write(f"cloud observe permission check passed: {len(actions)} read-only actions\n")
    return 0


def _verb(action: str) -> str:
    _, _, name = action.partition(":")
    for verb in _READ_VERBS:
        if name.startswith(verb):
            return verb
    return name


if __name__ == "__main__":
    raise SystemExit(main())
