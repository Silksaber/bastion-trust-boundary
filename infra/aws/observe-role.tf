# Terraform snippet for the observe role — the alternative to launching
# observe-role.cfn.yaml, for a customer who manages their account as code.
#
# Restates infra/aws/observe-policy.json's actions in Terraform's own syntax.
# cloud_tests/test_policy_document.py parses this file and asserts its action set
# matches the JSON and the CloudFormation template exactly — edit all three together.
#
# bastion_principal_arn and bastion_external_id are shown on the Connections page,
# immediately above this snippet, before the customer copies it into their own
# configuration.

variable "bastion_principal_arn" {
  description = "The Bastion platform's own AWS principal, shown on the Connections page."
  type        = string
}

variable "bastion_external_id" {
  description = "The per-organization external ID shown on the Connections page."
  type        = string
}

variable "bastion_role_name" {
  description = "The name this role will have in your account."
  type        = string
  default     = "BastionObserveRole"
}

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
      values   = [var.bastion_external_id]
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
  name               = var.bastion_role_name
  assume_role_policy = data.aws_iam_policy_document.bastion_observe_trust.json
}

resource "aws_iam_role_policy" "bastion_observe_read_only" {
  name   = "BastionObserveReadOnly"
  role   = aws_iam_role.bastion_observe.id
  policy = data.aws_iam_policy_document.bastion_observe_read_only.json
}

output "bastion_observe_role_arn" {
  description = "Paste this back into the Connections page."
  value       = aws_iam_role.bastion_observe.arn
}
