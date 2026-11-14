"""The observe role's policy document — a curated read allowlist, not ``ReadOnlyAccess``.

**This module is the single source of truth.** ``infra/aws/observe-policy.json`` is a
checked-in rendering of :func:`document`, the same relationship ``openapi.json`` has
to the API that generates it — ``cloud_tests/test_policy_document.py`` fails the build
if they drift, the same way ``make openapi-check`` does for the API schema.
``infra/aws/observe-role.cfn.yaml`` and ``observe-role.tf`` restate the same actions in
their own syntax (neither format can literally import a JSON file at author time), and
the same test asserts all three name an identical action set.

Every action is a read verb: ``Get``/``List``/``Describe``, or one of the small,
explicitly-named exceptions below whose *effect* is still read-only despite the verb
(``iam:GenerateCredentialReport`` starts an async report; it changes nothing in the
account). ``scripts/check_cloud_observe_permissions.py`` enforces this in CI —
Stage 7's analogue of ``scripts/check_github_permissions.py``, and a different,
additional control from the Stage 8 tighten-only invariant.
"""

from __future__ import annotations

from typing import Any, Final

__all__ = ["ACTIONS", "READ_VERB_EXCEPTIONS", "document", "trust_policy"]

#: Every action the observe role may take, grouped by service for readability. Nothing
#: outside this list is requested — this is the whole of what "curated, not
#: ReadOnlyAccess" means in code.
ACTIONS: Final[tuple[str, ...]] = (
    # IAM — who exists, what they can do, and how well-kept their credentials are.
    "iam:ListUsers",
    "iam:ListRoles",
    "iam:ListPolicies",
    "iam:GetAccountSummary",
    "iam:ListAccessKeys",
    "iam:GetAccessKeyLastUsed",
    "iam:ListAttachedUserPolicies",
    "iam:ListAttachedRolePolicies",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListMFADevices",
    "iam:GenerateCredentialReport",
    "iam:GetCredentialReport",
    # S3 — bucket-level access posture.
    "s3:ListAllMyBuckets",
    "s3:GetBucketAcl",
    "s3:GetBucketPolicy",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    # The account-wide Block Public Access setting, which AWS combines with each
    # bucket's own. Without it a bucket the account already protects reads as public
    # (Operation Cloud Stage 6, REPRO-F). A role granted before this lacks it; those
    # buckets are still reported from their own settings, with the claim left unknown.
    "s3:GetAccountPublicAccessBlock",
    "s3:GetBucketLocation",
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketVersioning",
    # EC2 — network exposure.
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeInstances",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeNetworkInterfaces",
    # Which regions the account has enabled, so a poll reads all of them and names the
    # ones it does not (Operation Cloud Stage 5, issue C09). A role granted before this
    # lacks it; that poll reads one region and says so rather than calling it complete.
    "ec2:DescribeRegions",
    # RDS — data-store exposure and encryption.
    "rds:DescribeDBInstances",
    "rds:DescribeDBSnapshots",
    "rds:ListTagsForResource",
    # Lambda — function-level access posture.
    "lambda:ListFunctions",
    "lambda:GetFunction",
    "lambda:GetPolicy",
    # KMS — key access posture.
    "kms:ListKeys",
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
    "kms:ListAliases",
    # CloudTrail — is anything watching this account at all.
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    # System understanding (ADR-067). Inventory only, and a role granted before this
    # lacks them: those reads report "not granted" and the connection stays healthy.
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth",
    "cloudfront:ListDistributions",
    "route53:ListHostedZones",
    "route53:ListResourceRecordSets",
    "ecs:ListClusters",
    "ecs:ListServices",
    "ecs:DescribeServices",
    "ecs:DescribeTaskDefinition",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:ListInstanceProfiles",
    "ce:GetCostAndUsage",
)

#: Actions in ``ACTIONS`` whose verb is not literally ``Get``/``List``/``Describe``,
#: with the reason each is still read-only. Referenced by
#: ``scripts/check_cloud_observe_permissions.py`` so the exception list — not a
#: blanket waiver — is what a reviewer sees change.
READ_VERB_EXCEPTIONS: Final[dict[str, str]] = {
    "iam:GenerateCredentialReport": (
        "starts an async report AWS already maintains; changes nothing in the account"
    ),
}


def document() -> dict[str, Any]:
    """The IAM policy document, as shown to the customer before they grant it.

    Rendered literally by the API and by ``infra/aws/observe-role.cfn.yaml`` /
    ``observe-role.tf`` — never summarized as "read-only" in prose (Stage 7 scope).
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BastionObserveReadOnly",
                "Effect": "Allow",
                "Action": list(ACTIONS),
                "Resource": "*",
            }
        ],
    }


def trust_policy(*, principal_arn: str, external_id: str) -> dict[str, Any]:
    """The trust policy the customer's role must have, binding it to us and to the
    external id we generated for their organization.

    The external-id condition is what stops the confused-deputy attack ADR-013's
    "external-ID-protected cross-account trust" names: without it, anyone who learns
    the role ARN — which is not secret — could ask their own account to assume it.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BastionObserveTrust",
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }
