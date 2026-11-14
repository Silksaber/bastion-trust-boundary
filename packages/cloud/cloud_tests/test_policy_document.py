"""The observe policy document: internally consistent, and agreed on across formats.

``infra/aws/observe-policy.json``, ``observe-role.cfn.yaml``, and ``observe-role.tf``
all restate ``bastion_cloud.policy.ACTIONS``. Nothing can literally import a JSON file
from a CloudFormation template or a Terraform snippet at author time, so this is the
test that catches a slip between the three the way ``scripts/check_cloud_observe_permissions.py``
catches a read-verb violation in the checked-in JSON alone.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from bastion_cloud.policy import ACTIONS, READ_VERB_EXCEPTIONS, document, trust_policy

ROOT = Path(__file__).resolve().parents[3]
INFRA = ROOT / "infra" / "aws"

_READ_VERBS = ("Get", "List", "Describe")


def test_document_is_one_statement_of_exactly_the_curated_actions() -> None:
    doc = document()
    assert doc["Version"] == "2012-10-17"
    statements = doc["Statement"]
    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert statements[0]["Resource"] == "*"
    assert statements[0]["Action"] == list(ACTIONS)


def test_every_action_is_a_read_verb_or_a_named_exception() -> None:
    for action in ACTIONS:
        if action in READ_VERB_EXCEPTIONS:
            continue
        _, _, name = action.partition(":")
        assert name.startswith(_READ_VERBS), (
            f"{action!r} is not a read verb and is not in READ_VERB_EXCEPTIONS"
        )


def test_trust_policy_requires_the_external_id() -> None:
    policy = trust_policy(principal_arn="arn:aws:iam::111111111111:role/bastion", external_id="x")
    statement = policy["Statement"][0]
    assert statement["Action"] == "sts:AssumeRole"
    assert statement["Condition"]["StringEquals"]["sts:ExternalId"] == "x"


def test_checked_in_json_matches_the_python_source_of_truth() -> None:
    on_disk = json.loads((INFRA / "observe-policy.json").read_text(encoding="utf-8"))
    assert on_disk == document(), (
        "infra/aws/observe-policy.json has drifted from bastion_cloud.policy.document() "
        "— regenerate it and check both in together"
    )


def test_cloudformation_template_names_the_same_actions() -> None:
    template = yaml.safe_load((INFRA / "observe-role.cfn.yaml").read_text(encoding="utf-8"))
    statement = template["Resources"]["BastionObserveRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]["Statement"][0]
    assert statement["Action"] == list(ACTIONS)


def _unquote(value: str) -> str:
    """This version of ``python-hcl2`` leaves literal quotes on every string it
    parsed from source — block labels and string values alike."""
    return value[1:-1] if len(value) >= 2 and value[0] == '"' and value[-1] == '"' else value


def test_terraform_snippet_names_the_same_actions() -> None:
    import hcl2

    document_hcl = hcl2.loads((INFRA / "observe-role.tf").read_text(encoding="utf-8"))
    actions: list[str] | None = None
    for block in document_hcl["data"]:
        for raw_type, named in block.items():
            if _unquote(raw_type) != "aws_iam_policy_document":
                continue
            for raw_name, body in named.items():
                if _unquote(raw_name) != "bastion_observe_read_only":
                    continue
                raw_actions = body["statement"][0]["actions"]
                actions = [_unquote(a) for a in raw_actions]
    assert actions == list(ACTIONS)


# --- the one-stack template (ADR-048) ---------------------------------------
#
# `bastion-connect.cfn.yaml` and `bastion-connect.tf` create both roles in one go, so
# they restate this action set a fourth and fifth time. Same reasoning as above: no
# format can import another at author time, so the test is what stops a slip.


def test_one_stack_cloudformation_names_the_same_observe_actions() -> None:
    template = yaml.safe_load((INFRA / "bastion-connect.cfn.yaml").read_text(encoding="utf-8"))
    statement = template["Resources"]["BastionObserveRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]["Statement"][0]
    assert statement["Action"] == list(ACTIONS)


def test_one_stack_terraform_names_the_same_observe_actions() -> None:
    import hcl2

    parsed = hcl2.loads((INFRA / "bastion-connect.tf").read_text(encoding="utf-8"))
    actions: list[str] | None = None
    for block in parsed["data"]:
        for raw_type, named in block.items():
            if _unquote(raw_type) != "aws_iam_policy_document":
                continue
            for raw_name, body in named.items():
                if _unquote(raw_name) != "bastion_observe_read_only":
                    continue
                actions = [_unquote(a) for a in body["statement"][0]["actions"]]
    assert actions == list(ACTIONS)
