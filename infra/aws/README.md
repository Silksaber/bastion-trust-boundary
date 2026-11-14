# The observe role

The document in [`observe-policy.json`](observe-policy.json) is the literal policy
Bastion asks to be granted, rendered as-is on the Connections page — not "read-only"
in prose. [`observe-role.cfn.yaml`](observe-role.cfn.yaml) and
[`observe-role.tf`](observe-role.tf) restate the same actions for a customer who
provisions by launch-stack or by Terraform respectively; all three are checked for
agreement by `cloud_tests/test_policy_document.py` and by
`scripts/check_cloud_observe_permissions.py`, the same way `openapi.json` is checked
against the API that generates it.

`bastion_cloud.policy` (`packages/cloud/src/bastion_cloud/policy.py`) is the single
Python source of truth these files restate — if you change one, change all three, and
let the tests catch a slip.

## Why a curated policy, not `ReadOnlyAccess`

AWS's own `ReadOnlyAccess` managed policy grants read access to essentially every
service in the account. This is exactly the screen where a security-conscious founder
is being asked to trust a security company with access to their infrastructure
(ARCHITECTURE.md), and "we could read anything, but we only look at these seven
services" is a materially different claim than "we hold AWS's broadest read grant."
The curated list is what makes that claim literally true rather than a policy of
restraint nobody can verify.

## What the seven services are for

| Service | Why Stage 7 reads it |
|---|---|
| **IAM** | Stale access keys, missing MFA, administrator policies attached directly to a user rather than assumed through a role. |
| **S3** | Public bucket ACLs and policies, the account-level public-access safety net, default encryption. |
| **EC2** | Security groups open to the entire internet on sensitive ports. |
| **RDS** | Publicly accessible database instances, unencrypted storage. |
| **Lambda** | Function resource policies that allow unauthenticated public invocation. |
| **KMS** | Customer-managed key policies granting access to any principal with no restricting condition. |
| **CloudTrail** | Whether anything is watching the account at all. |

This is a curated, high-signal set — not exhaustive CSPM coverage. Adding a service is
a new poller module in `packages/cloud/src/bastion_cloud/aws/`, one line in
`aws/registry.py`, and the corresponding actions added to all three files above and to
`ACTIONS` in `bastion_cloud/policy.py` — the same "adding a scanner needs no change
outside `packages/scanners/`" shape Stage 3 established, applied to a poller instead
of a tool.

## Regions (Operation Cloud Stage 5)

Every region the account has enabled is read on every check. The list comes from
`ec2:DescribeRegions`, which was added to all three observe documents above in Stage 5;
before that every check read `us-east-1` alone and said nothing about the rest (issue
C09). A region the account has not enabled is named as such. A customer who does not use
some regions — typically because a service control policy denies them — can choose the
regions to read on the Connections page (`PUT .../cloud/aws/regions`, admin only); the
rest are shown as not chosen, and nothing found in them is ever treated as fixed.

**A role created before Stage 5 lacks `ec2:DescribeRegions`.** It keeps working: each
check then reads `us-east-1` (or the chosen regions) and the card says the region list
could not be read, with the fix — update the stack from the current template. Updating
adds exactly one read action; it grants nothing else.

A region that refuses the role, a list longer than one check reads, and a resource that
refuses one of its reads (a KMS key whose key policy does not allow the role is the usual
one) are each reported by name as not read. What was read stays accurate; what was not
is unknown, not clear.

## Block Public Access (Operation Cloud Stage 6)

A bucket's public ACL or public policy is judged against Block Public Access as AWS
enforces it: each flag is on if the bucket **or** the account turns it on. The account-wide
setting is read once per check with `s3:GetAccountPublicAccessBlock`, added in Stage 6 to
all three observe documents above and to both one-stack templates. Before it, a bucket the
account already protected was reported as public and reachable from the internet.

**A role created before Stage 6 lacks `s3:GetAccountPublicAccessBlock`.** It keeps working:
buckets are still reported from their own settings, and the card says that whether AWS
enforces the grant is unknown until the stack is updated from the current template. Nothing
is reported clean because the read is missing. Updating adds exactly one read action.

An `AuthenticatedUsers` grant is reported as open to any AWS account holder, not as
anonymous access; object ACLs and access points are not read, and the card says so.

## Every action is a read verb

`Get`, `List`, or `Describe`, with one narrow exception documented in
`READ_VERB_EXCEPTIONS` (`iam:GenerateCredentialReport` starts an async report AWS
already maintains; it changes nothing). `scripts/check_cloud_observe_permissions.py`
enforces this in CI — a different, additional control from the Stage 8 tighten-only
invariant (`scripts/check_remediate_policy.py`), which applies to the separate
`remediate` grant and permits a bounded set of *closing* writes. Neither check relaxes
because the other changed shape.

## The external ID

`BastionExternalId` (CloudFormation) / `bastion_external_id` (Terraform) is generated
deterministically per organization —
`bastion_api.services.cloud_connection.derive_external_id` — and shown on the
Connections page before either template is used. It is what stops a confused-deputy
attack: without it, anyone who learned the role's ARN (not a secret) could ask their
own AWS account to assume it.

## The second grant — `remediate-*` (Stage 8)

`remediate-policy.json`, `remediate-role.cfn.yaml` and `remediate-role.tf` are the
observe role's three files again, for a role that can **change** things. Same
relationship to one Python source of truth (`bastion_cloud.remediate.policy`), same
cross-format test, same trust-ratchet flow on the Connections page — and a separate
IAM role, a separate external ID, and an independent revocation. A customer may hold
observe alone, indefinitely.

**Six actions, and every one closes, revokes, deletes, detaches, or encrypts:**

| Action | What it is for |
|---|---|
| `s3:PutBucketPublicAccessBlock` | Close a bucket. Answers all three S3 public-access findings at once — a fully enabled block makes a public ACL *and* a public bucket policy inert, so this platform needs no permission that writes either. |
| `s3:PutBucketEncryption` / `s3:DeleteBucketEncryption` | Turn on default encryption, and turn it off again. The second is how the first is undone. |
| `ec2:RevokeSecurityGroupIngress` | Close an ingress rule open to the internet — narrowed to the world CIDRs only, so a rule that also admits your VPN keeps your VPN. |
| `iam:DeleteAccessKey` | Delete a stale access key. |
| `iam:DetachUserPolicy` | Detach an administrator-equivalent policy attached directly to a user. |

**What is deliberately absent, and why it matters more than what is present:**
`ec2:AuthorizeSecurityGroupIngress`, `iam:AttachUserPolicy`, `iam:CreateAccessKey`,
`s3:PutBucketPolicy`, `s3:PutBucketAcl`, `cloudtrail:CreateTrail`, `kms:PutKeyPolicy`,
and anything else that grants, widens, opens, or creates. Three of those are the
inverses of three actions in the table above — which is exactly the point, and exactly
what it costs: for those changes we record the rollback command and **you** run it.
`scripts/check_remediate_policy.py` fails the build if any of them ever appears, and it
refuses them outright rather than allowing a documented exception.

**The role holds no read action either.** Verification re-reads the account through the
*observe* role. That is why remediation needs observe to be connected, and why revoking
observe stops us verifying rather than leaving a write-capable credential doing the
reading.

Its external ID is derived under a **different** secret from the observe role's
(`bastion_api.services.remediation.derive_remediate_external_id`). Two grants sharing
one value would be one grant with two names.

## Both roles in one stack — `bastion-connect.*` (ADR-048)

[`bastion-connect.cfn.yaml`](bastion-connect.cfn.yaml) and
[`bastion-connect.tf`](bastion-connect.tf) create **both** of the roles above in one
go. This is what the single "Connect AWS" button on the Connections page launches, with
the principal ARN and both external IDs pre-filled.

They are not a third policy. They restate the same two action sets a fourth and fifth
time, and `cloud_tests` asserts both against `bastion_cloud.policy.ACTIONS` and
`bastion_cloud.remediate.policy.ACTIONS` — so there are now five files to keep in step
and a test for each.

**Still two roles.** The read role holds no write action; the write role holds no read
action. `test_one_stack_keeps_the_two_roles_separate` is the test that fails if anyone
ever merges them into one role carrying both policies to make the stack shorter. That
would be the end of the tighten-only invariant, whatever the button looked like.

**Still two external IDs**, so the API can still revoke either grant on its own — the
per-grant routes are unchanged and a customer who wants observation alone can still have
it.

**The only thing that travels back is the account number.** A role's ARN is fixed by the
account and the role name (`CLOUD_OBSERVE_ROLE_NAME` / `CLOUD_REMEDIATE_ROLE_NAME`), so
the page derives both rather than asking for either. Rename a role and the derivation
stops matching — the manual path on the same screen takes the ARNs directly.

**The launch link needs the template hosted somewhere CloudFormation can fetch it**
(`CLOUD_LAUNCH_STACK_TEMPLATE_URL`, in practice an S3 object URL — the console's
quick-create link accepts nothing else). Unset, the page shows the template to create a
stack from by hand, and says why. A dead button on the screen where trust is being
decided is worse than an honest absence.

## Rehearsed against a real account (Operation Cloud Stage 10, 2026-09-14)

Evidence: `docs/evidence/operation-cloud/stage-10/`. What a real account showed that the
templates and tests could not:

- **The command path works as shipped.** With no launch link configured, the template was
  downloaded through the page's own button (byte-identical to the API's copy) and the
  rendered command run verbatim. It passes no `--region`, so the stack is created in the
  customer's CLI default region. The roles are IAM and global, so nothing depends on it —
  but that is the region to look in when deleting the stack.
- **Verified in AWS, not in the template.** Each role has one trust statement naming only
  the platform principal, conditioned on `sts:ExternalId` alone, with the value the page
  showed; the two external IDs differ; one inline policy each, `Allow` only, no managed
  policy. The observe role's live actions equal `observe-policy.json` (40) and the
  remediate role's equal `remediate-policy.json` (6).
- **Connect proves both roles** in about four seconds (CloudTrail sessions
  `bastion-observe-test` and `bastion-connect-test`), and every check afterwards assumes
  the observe role once (session `bastion-observe`, 900 s).
- **The default role names are per account, not per organization.** An account another
  organization had already connected still held that organization's
  `BastionObserveRole`/`BastionRemediateRole`, so the button's stack could not create
  them until the older stack was deleted. Once recreated under the new organization's
  external IDs, the older organization's checks were refused by AWS (`assume_denied`) —
  the external ID doing its job — while its connection stayed listed until somebody
  disconnects it. To move an account between organizations: disconnect in the old one,
  delete its stack, then connect in the new one.
- **Timing.** A full check with Prowler enabled read 38 resources across 17 regions in
  320–325 seconds.
