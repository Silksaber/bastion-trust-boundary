# Terraform snippet for the remediate role — the alternative to launching
# remediate-role.cfn.yaml, for a customer who manages their account as code.
#
# Restates infra/aws/remediate-policy.json's actions in Terraform's own syntax.
# cloud_tests/test_remediate_policy.py parses this file and asserts its action set
# matches the JSON and the CloudFormation template exactly — edit all three together.
#
# Six actions. Every one closes, revokes, deletes, detaches, or encrypts. None grants,
# widens, opens, or creates. See infra/aws/README.md for what is deliberately absent
# and why, including the services this policy does not touch at all.
#
# bastion_principal_arn and bastion_external_id are shown on the Connections page,
# immediately above this snippet. The external ID is a *different* value from the
# observe role's.

variable "bastion_principal_arn" {
  description = "The Bastion platform's own AWS principal, shown on the Connections page."
  type        = string
}

variable "bastion_external_id" {
  description = "The per-organization external ID for the remediate grant, shown on the Connections page."
  type        = string
}

variable "bastion_role_name" {
  description = "The name this role will have in your account."
  type        = string
  default     = "BastionRemediateRole"
}

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
      values   = [var.bastion_external_id]
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
  name               = var.bastion_role_name
  assume_role_policy = data.aws_iam_policy_document.bastion_remediate_trust.json
}

resource "aws_iam_role_policy" "bastion_remediate_tighten_only" {
  name   = "BastionRemediateTightenOnly"
  role   = aws_iam_role.bastion_remediate.id
  policy = data.aws_iam_policy_document.bastion_remediate_tighten_only.json
}

output "bastion_remediate_role_arn" {
  description = "Paste this back into the Connections page."
  value       = aws_iam_role.bastion_remediate.arn
}
