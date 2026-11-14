"""The remediate role's policy document — the invariant the whole stage rests on.

**The remediate role can only tighten** (ADR-015, CLAUDE.md). Its policy holds actions
that close, revoke, delete, detach, or encrypt, and **no** action that grants access,
widens a policy, opens a port, or creates an identity. That single property bounds a
total compromise of this platform at *making every connected customer's infrastructure
more restrictive* — a recoverable outage, categorically different from account takeover.

This module is the single source of truth, the same relationship
:mod:`bastion_cloud.policy` has to the observe role.
``infra/aws/remediate-policy.json``, ``remediate-role.cfn.yaml`` and
``remediate-role.tf`` are renderings of it, and ``cloud_tests/test_remediate_policy.py``
fails the build if any of the four disagree.

Three properties are enforced in CI by ``scripts/check_remediate_policy.py``, and the
third is the one that makes the other two more than a naming convention:

1. **Every action is a tightening verb**, or a named exception below carrying the
   reason its effect is restrictive as this product uses it.
2. **No action matches a forbidden verb**, ever, exception or not. ``Create``,
   ``Attach``, ``Authorize``, ``Add``, ``Enable``, ``Grant``, ``Put*Policy`` and their
   relatives are refused outright — an exception cannot buy them in.
3. **Every action is used by a declared step in** :mod:`bastion_cloud.remediate.steps`
   **and every step's action is in this document.** A permission nothing uses is a
   permission nobody reviewed, and a step whose action is missing would fail at 3am in
   a customer's account rather than in CI.

Note what this role does **not** hold: any read action at all. Verification re-reads
the account through the *observe* role, which is a separate grant with a separate
policy and a separate revocation. Splitting them means every action in this document is
a mutation, so "every action tightens" is a property of the whole document rather than
of a subset of it — and a customer can revoke the ability to change things while
keeping the ability to be told about them.
"""

from __future__ import annotations

from typing import Any, Final

__all__ = [
    "ACTIONS",
    "FORBIDDEN_VERB_FRAGMENTS",
    "SERVICES",
    "TIGHTEN_VERBS",
    "TIGHTEN_VERB_EXCEPTIONS",
    "document",
    "trust_policy",
]

#: Every action the remediate role may take. Six, curated, each one used by a declared
#: step. Grouped by service for readability; the service set is open question 7's
#: decided answer, narrowed by what actually survives the tighten-only test — see
#: ``infra/aws/README.md`` for the services that answer named and this document does not
#: carry, and why each one is absent rather than forgotten.
ACTIONS: Final[tuple[str, ...]] = (
    # S3 — close a bucket, and encrypt what is written to it.
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketEncryption",
    "s3:DeleteBucketEncryption",
    # EC2 — close a security-group rule open to the entire internet.
    "ec2:RevokeSecurityGroupIngress",
    # IAM — delete a stale access key, detach an over-broad policy.
    "iam:DeleteAccessKey",
    "iam:DetachUserPolicy",
)

#: The services this policy touches at all. Derived rather than written twice — the
#: Connections page explains the role per service, and a service that appeared here
#: without an action would be a sentence describing access nobody granted.
SERVICES: Final[tuple[str, ...]] = tuple(sorted({action.partition(":")[0] for action in ACTIONS}))

#: Verbs whose effect is to remove, close, or restrict. An action starting with one of
#: these needs no exception.
TIGHTEN_VERBS: Final[tuple[str, ...]] = (
    "Delete",
    "Revoke",
    "Detach",
    "Remove",
    "Disable",
    "Deactivate",
    "Block",
    "Stop",
    "Reject",
)

#: Fragments that mark an action as widening. Checked **before** the exception list and
#: never waivable: an action containing one of these is refused outright, whatever
#: reason somebody attached to it. This is the list that makes the exception mechanism
#: safe — an exception can explain a ``Put``, it can never explain an ``Authorize``.
#:
#: ``Policy`` is here in combination with ``Put``/``Update`` rather than alone, because
#: ``DetachUserPolicy`` is a tightening action whose name contains it. The check that
#: reads this list handles that pairing explicitly.
FORBIDDEN_VERB_FRAGMENTS: Final[tuple[str, ...]] = (
    "Create",
    "Attach",
    "Authorize",
    "Add",
    "Enable",
    "Grant",
    "Allow",
    "Assume",
    "Import",
    "Restore",
    "Open",
    "Share",
    "Invite",
    "Accept",
)

#: Actions whose verb is not in :data:`TIGHTEN_VERBS`, with the reason each is
#: restrictive as this product uses it and the exact step permitted to use it. Two
#: entries, both ``Put``, both bounded by a constant in the step catalogue rather than
#: by trust.
#:
#: This list is deliberately hard to grow. An entry has to name a step, and
#: ``scripts/check_remediate_policy.py`` fails if the named step does not exist, does
#: not use the action, or builds its apply-time parameters from anything but the
#: constants it declares.
TIGHTEN_VERB_EXCEPTIONS: Final[dict[str, dict[str, str]]] = {
    "s3:PutBucketPublicAccessBlock": {
        "step": "s3_block_public_access",
        "reason": (
            "the only thing this API writes is the four public-access block flags. The "
            "catalogue's apply direction is the constant all-true — the most restrictive "
            "value the API accepts — and the only other parameters the executor can "
            "construct are the flags captured from the account before the change, which "
            "is the rollback. It cannot touch an ACL, a policy, or an object."
        ),
    },
    "s3:PutBucketEncryption": {
        "step": "s3_enable_default_encryption",
        "reason": (
            "encrypting is one of the four effects ADR-015 names as permitted (close, "
            "revoke, delete, encrypt). The catalogue's apply direction is the constant "
            "AES256 and there is no parameter an executor may vary; the rollback uses "
            "s3:DeleteBucketEncryption, which is a delete."
        ),
    },
}


def document() -> dict[str, Any]:
    """The IAM policy document, as shown to the customer before they grant it.

    Rendered literally by the API and by ``infra/aws/remediate-role.cfn.yaml`` /
    ``remediate-role.tf``. Never summarized as "can only tighten" in prose without the
    document beside it — the sentence is the claim and the document is the evidence,
    and this is the screen where a security-conscious buyer decides whether to believe
    a security company.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BastionRemediateTightenOnly",
                "Effect": "Allow",
                "Action": list(ACTIONS),
                "Resource": "*",
            }
        ],
    }


def trust_policy(*, principal_arn: str, external_id: str) -> dict[str, Any]:
    """The trust policy the customer's remediate role must have.

    Identical in shape to the observe role's and deliberately so — but bound to a
    *different* external id, derived under the ``remediate`` label. Two grants that
    shared one external id would be one grant with two names: revoking observe would
    leave a working credential for a role that can change things.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BastionRemediateTrust",
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }
