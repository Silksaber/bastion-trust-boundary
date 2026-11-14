#!/usr/bin/env python3
"""CI guard: the remediate role can only tighten. Forever.

**This is the load-bearing control of the entire product** (ADR-015, CLAUDE.md). The
remediate role's policy may hold actions that close, revoke, delete, detach, or
encrypt. It may hold **no** action that grants access, widens a policy, opens a port,
or creates an identity. That single property is what bounds a total compromise of this
platform at *making every connected customer's infrastructure more restrictive* — a
recoverable outage, categorically different from account takeover — and it is the
sentence that gets through a customer's own security review: we can close things in
your account, we cannot open them.

A convention nobody checks is a convention that decays, and a permission is a
one-character edit away from being widened by accident. So this runs in CI on every
commit, forever, and **it never relaxes**. If a remediation needs a grant-type action,
the remediation falls back to a pull request or guided steps — that fallback path exists
precisely so this check never has to bend.

Three properties, and the third is what makes the first two more than naming:

1. **No forbidden verb, ever.** ``Create``, ``Attach``, ``Authorize``, ``Add``,
   ``Enable``, ``Grant`` and their relatives are refused outright. This is checked
   *before* the exception list and cannot be waived: an exception may explain a
   ``Put``, it can never explain an ``Authorize``.
2. **Every action is a tightening verb, or a named exception** carrying the reason its
   effect is restrictive as this product uses it and the exact catalogue step permitted
   to use it.
3. **The policy and the step catalogue agree in both directions.** Every action is used
   by a declared step, and every step's action is in the policy. A permission nothing
   uses is a permission nobody reviewed; a step whose action is missing would fail at
   4am in a customer's account rather than here.

This is a **different, additional** control from ``check_cloud_observe_permissions.py``
(the observe role may not write at all) and from ``check_github_permissions.py`` (the
App may not administer anything). Three credentials, three checks, and none of them
relaxes because another one changed shape.

Run: ``python scripts/check_remediate_policy.py``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "infra" / "aws" / "remediate-policy.json"
sys.path.insert(0, str(ROOT / "packages" / "cloud" / "src"))

from bastion_cloud.remediate.policy import (  # noqa: E402
    FORBIDDEN_VERB_FRAGMENTS,
    TIGHTEN_VERB_EXCEPTIONS,
    TIGHTEN_VERBS,
)
from bastion_cloud.remediate.steps import StepKind, catalogue  # noqa: E402


def main() -> int:
    document = json.loads(POLICY.read_text(encoding="utf-8"))
    problems: list[str] = []
    actions: list[str] = []

    for statement in document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            problems.append(
                f"statement {statement.get('Sid', '?')!r} is not an Allow. The remediate "
                "policy is an allowlist; a Deny here would be describing something else."
            )
            continue
        actions.extend(statement.get("Action", []))

    for action in actions:
        problems.extend(_check_action(action))

    problems.extend(_check_catalogue_agreement(actions))

    if problems:
        sys.stderr.write(
            f"{POLICY.relative_to(ROOT)} violates the tighten-only invariant (ADR-015):\n\n"
        )
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        sys.stderr.write(
            "\nThis check does not relax. If a remediation needs an action that grants, "
            "widens, opens, or creates, it falls back to a pull request or guided steps "
            "— that path exists so this invariant never has to bend.\n"
        )
        return 1

    sys.stdout.write(
        f"remediate policy check passed: {len(actions)} tighten-only actions, "
        f"{len(catalogue())} declared steps, no forbidden verb\n"
    )
    return 0


def _check_action(action: str) -> list[str]:
    _, _, name = action.partition(":")
    problems: list[str] = []

    forbidden = _forbidden_fragment(name)
    if forbidden is not None:
        return [
            f"action {action!r} contains the forbidden verb {forbidden!r}. Actions that "
            "grant, widen, open, or create are refused outright and cannot be waived by "
            "an exception — this is the invariant, not a default."
        ]

    if name.startswith(TIGHTEN_VERBS):
        return []

    entry = TIGHTEN_VERB_EXCEPTIONS.get(action)
    if entry is None:
        problems.append(
            f"action {action!r} does not start with a tightening verb "
            f"({', '.join(TIGHTEN_VERBS)}) and is not in TIGHTEN_VERB_EXCEPTIONS. If its "
            "effect really is restrictive as this product uses it, add it there with the "
            "reason and the step that uses it — in the same commit."
        )
        return problems

    if not entry.get("reason"):
        problems.append(f"exception for {action!r} carries no reason. An unexplained waiver.")
    step_name = entry.get("step", "")
    try:
        kind = StepKind(step_name)
    except ValueError:
        problems.append(
            f"exception for {action!r} names step {step_name!r}, which is not in "
            "bastion_cloud.remediate.steps.StepKind."
        )
        return problems
    spec = catalogue()[kind]
    if spec.action != action:
        problems.append(
            f"exception for {action!r} names step {step_name!r}, but that step's action is "
            f"{spec.action!r}. An exception has to point at the step it is excusing."
        )
    return problems


def _check_catalogue_agreement(actions: list[str]) -> list[str]:
    problems: list[str] = []
    permitted = set(actions)
    specs = catalogue()

    used: set[str] = set()
    for kind, spec in specs.items():
        used.add(spec.action)
        # A platform rollback's inverse action is *used* too — ``s3:DeleteBucketEncryption``
        # is in the policy for no other reason than being the way back from enabling it.
        if spec.rollback == "platform":
            used.update(spec.inverse_actions)
        if spec.action not in permitted:
            problems.append(
                f"step {kind} uses {spec.action!r}, which is not in the policy. It would "
                "fail with AccessDenied in a customer's account rather than here."
            )
        for inverse in spec.inverse_actions:
            if spec.rollback == "platform" and inverse not in permitted:
                problems.append(
                    f"step {kind} claims a platform rollback but its inverse {inverse!r} is "
                    "not in the policy. A rollback this platform cannot apply is not a "
                    "platform rollback."
                )
            if spec.rollback != "platform" and inverse in permitted:
                problems.append(
                    f"step {kind} claims rollback mode {spec.rollback!r} while its inverse "
                    f"{inverse!r} *is* in the policy. Either the mode is wrong or the "
                    "policy grew an action nothing needs."
                )

    for action in sorted(permitted - used):
        problems.append(
            f"action {action!r} is in the policy and no declared step uses it. A permission "
            "nothing uses is a permission nobody reviewed — remove it, or add the step."
        )
    return problems


def _forbidden_fragment(name: str) -> str | None:
    for fragment in FORBIDDEN_VERB_FRAGMENTS:
        if fragment in name:
            return fragment
    # ``Put``/``Update`` are only ever acceptable through the exception list, and never
    # on a *policy* — an action that writes a policy document can always widen one.
    if ("Put" in name or "Update" in name) and "Policy" in name:
        return "PutPolicy"
    return None


if __name__ == "__main__":
    raise SystemExit(main())
