# Both roles in one apply — the Terraform equivalent of bastion-connect.cfn.yaml.
#
# Same two roles, same two action sets, same two separate external IDs as
# observe-role.tf and remediate-role.tf create individually. The roles are not merged
# and never will be: the tighten-only role holds no read permission, which is what makes
# "it can only tighten" checkable rather than a claim about our intentions (ADR-015).
# What is merged is the asking — see ADR-048.
#
# cloud_tests parses this file and asserts both action sets match
# bastion_cloud.policy.ACTIONS and bastion_cloud.remediate.policy.ACTIONS exactly.
#
# bastion_principal_arn and the two external IDs are shown on the Connections page,
# immediately above this snippet.

variable "bastion_principal_arn" {
  description = "The Bastion platform's own AWS principal, shown on the Connections page."
  type        = string
}

variable "bastion_observe_external_id" {
  description = "The per-organization external ID for the read role, shown on the Connections page."
  type        = string
}

variable "bastion_remediate_external_id" {
  description = "The per-organization external ID for the tighten-only role. A different value from the observe one, on purpose."
  type        = string
}

variable "bastion_observe_role_name" {
  description = "The name the read role will have. The Connections page derives its ARN from your account ID and this name."
  type        = string
  default     = "BastionObserveRole"
}

variable "bastion_remediate_role_name" {
  description = "The name the tighten-only role will have."
  type        = string
  default     = "BastionRemediateRole"
}

# -- Read. Every action is a Get, a List, or a Describe. ----------------------

data "aws_iam_policy_document" "bastion_observe_trust" {
  statement {
    sid     = "BastionObserveTrust"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.bastion_principal_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.bastion_observe_external_id]
    }
  }
}

data "aws_iam_policy_document" "bastion_observe_read_only" {
  statement {
    sid    = "BastionObserveReadOnly"
    effect = "Allow"
    actions = [
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
      "s3:ListAllMyBuckets",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetAccountPublicAccessBlock",
      "s3:GetBucketLocation",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketVersioning",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeRegions",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSnapshots",
      "rds:ListTagsForResource",
      "lambda:ListFunctions",
      "lambda:GetFunction",
      "lambda:GetPolicy",
      "kms:ListKeys",
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:ListAliases",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
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
      "ce:GetCostAndUsage"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "bastion_observe" {
  name               = var.bastion_observe_role_name
  assume_role_policy = data.aws_iam_policy_document.bastion_observe_trust.json
}

resource "aws_iam_role_policy" "bastion_observe_read_only" {
  name   = "BastionObserveReadOnly"
  role   = aws_iam_role.bastion_observe.id
  policy = data.aws_iam_policy_document.bastion_observe_read_only.json
}

# -- Change. Six actions, and every one of them closes something. -------------

data "aws_iam_policy_document" "bastion_remediate_trust" {
  statement {
    sid     = "BastionRemediateTrust"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.bastion_principal_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.bastion_remediate_external_id]
    }
  }
}

data "aws_iam_policy_document" "bastion_remediate_tighten_only" {
  statement {
    sid    = "BastionRemediateTightenOnly"
    effect = "Allow"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketEncryption",
      "s3:DeleteBucketEncryption",
      "ec2:RevokeSecurityGroupIngress",
      "iam:DeleteAccessKey",
      "iam:DetachUserPolicy",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "bastion_remediate" {
  name               = var.bastion_remediate_role_name
  assume_role_policy = data.aws_iam_policy_document.bastion_remediate_trust.json
}

resource "aws_iam_role_policy" "bastion_remediate_tighten_only" {
  name   = "BastionRemediateTightenOnly"
  role   = aws_iam_role.bastion_remediate.id
  policy = data.aws_iam_policy_document.bastion_remediate_tighten_only.json
}

output "bastion_aws_account_id" {
  description = "Paste this back into the Connections page. It is the only thing we need."
  value       = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}
