"""The step catalogue: every change this platform knows how to make, and its inverse.

A step is not a description of a fix. It is **the literal AWS API call**, with the
literal parameters, alongside the literal call that undoes it and the state that was
read before either ran. That is what makes the plan the evidence behind the impact
score rather than a paraphrase of it, and it is why the plan can be rendered in full on
a card before anybody accepts anything.

Three rules hold for every entry here, and ``scripts/check_remediate_policy.py``
enforces all three in CI:

**The apply direction is built from constants declared in this module.** No caller
passes a parameter that decides how far a step tightens. ``s3_block_public_access``
writes :data:`FULLY_BLOCKED` and nothing else; ``s3_enable_default_encryption`` writes
:data:`AES256_ENCRYPTION` and nothing else. Where a step must name a resource, the name
comes from what the *observe* role read, not from a request.

**The inverse and the prior state are built at plan time, before anything executes.**
After the change the prior state is gone, and a rollback derived afterwards is a guess
(CLAUDE.md). Both travel with the step from the moment it is created.

**Every step declares who can apply its inverse**, as :class:`RollbackMode`. This is
the taxonomy the tighten-only invariant forces into existence: the inverse of closing
something is opening it, and this platform will never hold an action that opens
anything. So a step is one of three kinds, and the kind decides what may run unattended:

* :attr:`RollbackMode.PLATFORM` — the inverse uses an action already in the remediate
  policy, so we can put the account back ourselves. Only these may auto-execute.
* :attr:`RollbackMode.CUSTOMER` — the inverse is known exactly and is stored exactly,
  but applying it needs an action the tighten-only role will never hold
  (``ec2:AuthorizeSecurityGroupIngress``, ``iam:AttachUserPolicy``). Never
  auto-executes at any level; a human approving it is shown the exact command they
  would run to undo it.
* :attr:`RollbackMode.NONE` — no inverse exists for anybody. Deleting an access key
  destroys key material nobody can restore. Never auto-executes; a human approving it
  is told, in those words, that it cannot be undone.

See ADR-031 for why the middle kind exists rather than being collapsed into either
neighbour.

**Every kind also declares how to read it back** (Operation Cloud Stage 8, ADR-057). The
executor never believes an API response about what happened in an account: it reads the
resource through the observe role and asks the kind's own :attr:`StepSpec.observe` which
of four things is true — see :class:`StepObservation`. Before Stage 8 verification was a
subset match against one ``expected_state`` for the whole resource, so detaching one of
two administrator policies — exactly what the plan said it would do — was reported as a
change that did not land and could not be put back (REPRO E8, E9).
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "AES256_ENCRYPTION",
    "FULLY_BLOCKED",
    "WORLD_CIDRS",
    "ApiCall",
    "PlanStep",
    "RollbackMode",
    "StepKind",
    "StepObservation",
    "StepSpec",
    "allowed_operations",
    "catalogue",
    "observe_step",
    "spec_for",
]


class RollbackMode(StrEnum):
    """Who, if anybody, can put the account back. See the module docstring."""

    PLATFORM = "platform"
    CUSTOMER = "customer"
    NONE = "none"


class StepKind(StrEnum):
    """The changes this platform knows how to make. Five, curated.

    A sixth arrives by adding a :class:`StepSpec` below and an action to
    :data:`bastion_cloud.remediate.policy.ACTIONS` in the same commit — the CI check
    refuses either one without the other.
    """

    S3_BLOCK_PUBLIC_ACCESS = "s3_block_public_access"
    S3_ENABLE_DEFAULT_ENCRYPTION = "s3_enable_default_encryption"
    EC2_REVOKE_WORLD_INGRESS = "ec2_revoke_world_ingress"
    IAM_DELETE_ACCESS_KEY = "iam_delete_access_key"
    IAM_DETACH_USER_POLICY = "iam_detach_user_policy"


class StepObservation(StrEnum):
    """What a fresh read of the account says about one step (Operation Cloud Stage 8).

    Four answers, because the executor asks four different questions of a read and each
    question needs a different one of them before it proceeds:

    * before applying, the resource must still be :attr:`NOT_APPLIED` — exactly the state
      the plan was built from;
    * after applying, :attr:`APPLIED` is verification;
    * before a rollback, :attr:`APPLIED` again — still what this platform set. Anything
      else means something changed it since, and applying the inverse would overwrite
      that change (REPRO E10);
    * after a rollback, :attr:`NOT_APPLIED` — the prior state, observed rather than
      assumed from an API response that returned.

    :attr:`CHANGED_ELSEWHERE` is neither what this step sets nor what was there before.
    :attr:`UNREADABLE` is "the read that would tell us did not happen", and is never
    taken as either of the first two.
    """

    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    CHANGED_ELSEWHERE = "changed_elsewhere"
    UNREADABLE = "unreadable"


#: The most restrictive value ``s3:PutBucketPublicAccessBlock`` accepts. A constant,
#: declared here, because the tighten-only exception for that action rests on the apply
#: direction never being anything else.
FULLY_BLOCKED: Final[dict[str, bool]] = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

#: The constant ``s3:PutBucketEncryption`` writes. SSE-S3 rather than SSE-KMS: KMS
#: needs a key this role cannot create and a key policy it cannot write, and a
#: remediation that half-works is worse than one that says what it does.
AES256_ENCRYPTION: Final[dict[str, Any]] = {
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
}

#: The ranges that make an ingress rule "open to the world". The only ranges a
#: security-group step may ever revoke.
WORLD_CIDRS: Final[frozenset[str]] = frozenset({"0.0.0.0/0", "::/0"})


@dataclass(frozen=True, slots=True)
class ApiCall:
    """One literal AWS call.

    ``action`` is the IAM action, and is what the policy check matches against.
    ``operation`` is the boto3 method name — the two are named separately because IAM
    and boto3 spell the same call differently, and a plan a customer reads against
    their own CloudTrail needs the IAM spelling.
    """

    action: str
    operation: str
    params: dict[str, Any] = field(default_factory=dict)
    #: The region the call is sent to — the resource's own (Operation Cloud Stage 5).
    #: ``None`` for a global service (IAM) and for every plan stored before Stage 5,
    #: which is exactly what those plans meant: the session's region, ``us-east-1``,
    #: the only region anything was observed in then. Recorded in the plan the customer
    #: reviews, so where a change will land is part of what is accepted.
    region: str | None = None

    @property
    def service(self) -> str:
        return self.action.partition(":")[0]

    def as_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "action": self.action,
            "operation": self.operation,
            "params": self.params,
        }
        # Omitted rather than ``null`` when absent, so a plan without one serializes
        # exactly as it did before and its stored revision is unchanged.
        if self.region is not None:
            payload["region"] = self.region
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> ApiCall:
        region = payload.get("region")
        return cls(
            action=str(payload["action"]),
            operation=str(payload["operation"]),
            params=dict(payload.get("params", {})),
            region=str(region) if region else None,
        )


@dataclass(frozen=True, slots=True)
class PlanStep:
    """One step of a plan: what will be called, what it will undo, and what was there.

    ``expected_state`` is what the account shows once the change lands, expressed in the
    *poller's* vocabulary rather than the API's, and rendered on the plan a customer
    accepts. Since Stage 8 it is a description: the executor decides whether a step
    landed with its kind's :attr:`StepSpec.observe`, which reads the resource the same
    way and can tell "not yet" from "changed by somebody else".
    """

    kind: StepKind
    resource_id: str
    description: str
    call: ApiCall
    inverse: ApiCall | None
    rollback: RollbackMode
    prior_state: dict[str, Any] = field(default_factory=dict)
    expected_state: dict[str, Any] = field(default_factory=dict)
    #: What a customer would run to undo this themselves, when we cannot. Empty for
    #: ``PLATFORM`` (we do it) and for ``NONE`` (nobody can).
    manual_rollback: str = ""

    def as_payload(self) -> dict[str, Any]:
        return {
            "kind": str(self.kind),
            "resource_id": self.resource_id,
            "description": self.description,
            "call": self.call.as_payload(),
            "inverse": self.inverse.as_payload() if self.inverse else None,
            "rollback": str(self.rollback),
            "prior_state": self.prior_state,
            "expected_state": self.expected_state,
            "manual_rollback": self.manual_rollback,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> PlanStep:
        inverse = payload.get("inverse")
        return cls(
            kind=StepKind(payload["kind"]),
            resource_id=str(payload["resource_id"]),
            description=str(payload["description"]),
            call=ApiCall.from_payload(payload["call"]),
            inverse=ApiCall.from_payload(inverse) if inverse else None,
            rollback=RollbackMode(payload["rollback"]),
            prior_state=dict(payload.get("prior_state", {})),
            expected_state=dict(payload.get("expected_state", {})),
            manual_rollback=str(payload.get("manual_rollback", "")),
        )


@dataclass(frozen=True, slots=True)
class StepSpec:
    """What one kind of step is, declared once.

    ``build`` is the only thing that constructs a :class:`PlanStep` of this kind, and it
    takes the resource's *observed* state — never a caller's parameters. That is the
    property the CI check is asserting when it says a step's apply direction comes from
    constants: there is no argument here through which a step could be made to tighten
    less, or to widen. :mod:`bastion_cloud.remediate.integrity` holds a stored plan to
    the same property by rebuilding every step from its recorded prior state.
    """

    kind: StepKind
    action: str
    rollback: RollbackMode
    #: The other actions this step's inverse needs. Empty for ``NONE``; for
    #: ``PLATFORM`` every entry is in the policy; for ``CUSTOMER`` none of them are, and
    #: none of them ever will be.
    inverse_actions: tuple[str, ...]
    summary: str
    build: Callable[[str, dict[str, Any]], PlanStep | None]
    #: The boto3 method ``action`` is performed through — the only one. The remediate
    #: provider refuses a call naming this action with any other (Stage 8, REPRO E11).
    operation: str
    #: The boto3 method of the inverse, where one exists.
    inverse_operation: str | None
    #: What a fresh read of the resource says about a step of this kind.
    observe: Callable[[PlanStep, Mapping[str, Any]], StepObservation]


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------


def _bucket_name(provider_id: str) -> str:
    return provider_id.rsplit(":", 1)[-1]


def _block_flags(value: Mapping[str, Any]) -> dict[str, bool]:
    return {key: bool(value.get(key, False)) for key in FULLY_BLOCKED}


def _build_block_public_access(provider_id: str, state: dict[str, Any]) -> PlanStep | None:
    """Switch every public-access block flag on.

    This one step answers all three of the S3 public-access rules, and that is not a
    convenience — it is the correct fix. A bucket with ``IgnorePublicAcls`` and
    ``RestrictPublicBuckets`` on does not grant the public anything, whatever its ACL
    and its bucket policy say, so closing the account-level safety net neutralizes a
    public ACL and a public policy *without* this platform ever holding a permission
    that writes an ACL or a policy. The alternative — ``s3:PutBucketAcl`` — would put an
    ACL-writing action in a role whose whole claim is that it cannot widen anything.
    """
    prior = dict(state.get("public_access_block") or {})
    if prior and all(prior.get(key) is True for key in FULLY_BLOCKED):
        return None  # Already fully blocked; there is nothing to change.

    name = _bucket_name(provider_id)
    # Any flag the account did not report is restored as False, which is what an absent
    # public-access-block configuration means. Guessing True here would "restore" the
    # bucket to a state it was never in.
    captured = _block_flags(prior)

    return PlanStep(
        kind=StepKind.S3_BLOCK_PUBLIC_ACCESS,
        resource_id=provider_id,
        description=(
            f"Switch on all four public-access block flags for S3 bucket {name}. Any "
            "public ACL grant or public bucket policy on it stops being effective; "
            "neither is edited or deleted."
        ),
        call=ApiCall(
            action="s3:PutBucketPublicAccessBlock",
            operation="put_public_access_block",
            params={"Bucket": name, "PublicAccessBlockConfiguration": dict(FULLY_BLOCKED)},
        ),
        inverse=ApiCall(
            action="s3:PutBucketPublicAccessBlock",
            operation="put_public_access_block",
            params={"Bucket": name, "PublicAccessBlockConfiguration": captured},
        ),
        rollback=RollbackMode.PLATFORM,
        prior_state={"public_access_block": captured},
        expected_state={"public_access_block": dict(FULLY_BLOCKED)},
    )


def _observe_block_public_access(step: PlanStep, state: Mapping[str, Any]) -> StepObservation:
    current = state.get("public_access_block")
    if not isinstance(current, Mapping):
        return StepObservation.UNREADABLE
    flags = _block_flags(current)
    if flags == _block_flags(step.call.params.get("PublicAccessBlockConfiguration") or {}):
        return StepObservation.APPLIED
    if flags == _block_flags(step.prior_state.get("public_access_block") or {}):
        return StepObservation.NOT_APPLIED
    return StepObservation.CHANGED_ELSEWHERE


def _build_enable_default_encryption(provider_id: str, state: dict[str, Any]) -> PlanStep | None:
    """Turn on default encryption with SSE-S3."""
    if state.get("default_encryption") is True:
        return None

    name = _bucket_name(provider_id)
    return PlanStep(
        kind=StepKind.S3_ENABLE_DEFAULT_ENCRYPTION,
        resource_id=provider_id,
        description=(
            f"Enable default server-side encryption (AES256) on S3 bucket {name}. "
            "Objects already in the bucket are not rewritten; everything written after "
            "this is encrypted at rest."
        ),
        call=ApiCall(
            action="s3:PutBucketEncryption",
            operation="put_bucket_encryption",
            params={
                "Bucket": name,
                "ServerSideEncryptionConfiguration": dict(AES256_ENCRYPTION),
            },
        ),
        inverse=ApiCall(
            action="s3:DeleteBucketEncryption",
            operation="delete_bucket_encryption",
            params={"Bucket": name},
        ),
        rollback=RollbackMode.PLATFORM,
        prior_state={"default_encryption": False},
        expected_state={"default_encryption": True},
    )


def _observe_default_encryption(step: PlanStep, state: Mapping[str, Any]) -> StepObservation:
    """``default_encryption_algorithm`` tells our AES256 from a KMS key set since.

    Without it, rolling back would delete whatever encryption the bucket has — including
    a customer-managed key somebody configured after this change. A state read before the
    poller reported the algorithm (it is absent, not ``None``) is taken at its boolean.
    """
    enabled = state.get("default_encryption")
    if not isinstance(enabled, bool):
        return StepObservation.UNREADABLE
    if not enabled:
        return StepObservation.NOT_APPLIED
    if "default_encryption_algorithm" not in state:
        return StepObservation.APPLIED
    if state.get("default_encryption_algorithm") == "AES256":
        return StepObservation.APPLIED
    return StepObservation.CHANGED_ELSEWHERE


# ---------------------------------------------------------------------------
# EC2
# ---------------------------------------------------------------------------


def _covers_every_port(permission: Mapping[str, Any]) -> bool:
    first, last = permission.get("FromPort"), permission.get("ToPort")
    protocol = str(permission.get("IpProtocol", "-1"))
    return protocol == "-1" or first is None or last is None or (first == 0 and last == 65535)


def _build_revoke_world_ingress(provider_id: str, state: dict[str, Any]) -> PlanStep | None:
    """Revoke exactly the internet-facing CIDR ranges the finding names, and nothing else.

    The permissions this revokes were narrowed by the poller to contain only
    ``0.0.0.0/0`` and ``::/0``: a rule that admits the world *and* the office VPN loses
    the world and keeps the office. Revoking the whole rule would be a wider change than
    the finding describes, and the customer would find out about it in production.

    A world rule is revoked only when it is one the finding is about: an all-traffic rule
    (the finding's ``all``), or a port range made up entirely of the sensitive ports the
    finding names. A public web rule beside them is left alone — before Stage 8 an
    all-traffic rule took every other world rule with it, an explicit public HTTPS rule
    included (REPRO E15). A range that mixes a named port with others needs splitting,
    which is an authorize call this role cannot make, so there is no step.
    """
    observed_permissions = list(state.get("world_open_permissions") or [])
    open_ports = set(state.get("open_ports") or [])
    permissions = []
    for permission in observed_permissions:
        if _covers_every_port(permission):
            if "all" in open_ports:
                permissions.append(permission)
            continue
        first, last = permission.get("FromPort"), permission.get("ToPort")
        if not isinstance(first, int) or not isinstance(last, int):
            return None
        # Revoke only the ports this finding actually names. A shared range needs
        # to be split with an authorize call, which the remediate role cannot make.
        covered = {port for port in open_ports if isinstance(port, int) and first <= port <= last}
        if not covered:
            continue
        if last - first + 1 != len(covered):
            return None
        permissions.append(permission)
    if not permissions:
        return None

    name = state.get("group_name") or provider_id
    ports = ", ".join(str(port) for port in state.get("open_ports", [])) or "the listed rules"
    inverse = ApiCall(
        action="ec2:AuthorizeSecurityGroupIngress",
        operation="authorize_security_group_ingress",
        params={"GroupId": provider_id, "IpPermissions": permissions},
    )

    return PlanStep(
        kind=StepKind.EC2_REVOKE_WORLD_INGRESS,
        resource_id=provider_id,
        description=(
            f"Revoke the internet-facing ingress rules on security group {name} "
            f"(port(s) {ports}). Rules admitting any other CIDR range, and public rules "
            "for other ports, are untouched."
        ),
        call=ApiCall(
            action="ec2:RevokeSecurityGroupIngress",
            operation="revoke_security_group_ingress",
            params={"GroupId": provider_id, "IpPermissions": permissions},
        ),
        inverse=inverse,
        rollback=RollbackMode.CUSTOMER,
        prior_state={
            "world_open_permissions": observed_permissions,
            "open_ports": state.get("open_ports"),
        },
        expected_state={"open_ports": []},
        # Rendered from the stored inverse, never described (Operation Cloud Stage 10,
        # L3). The customer runs this command, not us: it must be the exact rules this
        # plan removes, pasteable as-is, and it cannot drift from ``inverse`` because it
        # is built from it.
        manual_rollback=(
            "aws ec2 authorize-security-group-ingress"
            f" --group-id {shlex.quote(str(inverse.params['GroupId']))}"
            f" --ip-permissions {_cli_json(inverse.params['IpPermissions'])}"
        ),
    )


def _cli_json(value: Any) -> str:
    """One shell-quoted JSON argument, stable across runs so a plan renders one way."""
    return shlex.quote(json.dumps(value, separators=(",", ":"), sort_keys=True))


def _grants(permissions: Any) -> set[tuple[str, Any, Any, str]]:
    """Each (protocol, from, to, range) one rule list admits, so two lists compare exactly."""
    found: set[tuple[str, Any, Any, str]] = set()
    if not isinstance(permissions, list):
        return found
    for permission in permissions:
        if not isinstance(permission, Mapping):
            continue
        key = (
            str(permission.get("IpProtocol", "-1")),
            permission.get("FromPort"),
            permission.get("ToPort"),
        )
        for entry in permission.get("IpRanges") or []:
            found.add((*key, str(entry.get("CidrIp"))))
        for entry in permission.get("Ipv6Ranges") or []:
            found.add((*key, str(entry.get("CidrIpv6"))))
    return found


def _observe_revoke_world_ingress(step: PlanStep, state: Mapping[str, Any]) -> StepObservation:
    current = state.get("world_open_permissions")
    if not isinstance(current, list):
        return StepObservation.UNREADABLE
    targeted = _grants(step.call.params.get("IpPermissions"))
    present = targeted & _grants(current)
    if not present:
        return StepObservation.APPLIED
    if present == targeted:
        return StepObservation.NOT_APPLIED
    return StepObservation.CHANGED_ELSEWHERE


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------


def _build_delete_access_key(provider_id: str, state: dict[str, Any]) -> PlanStep | None:
    """Delete a stale access key.

    ``iam:DeleteAccessKey`` and not ``iam:UpdateAccessKey`` with ``Status=Inactive``,
    which would be reversible and is deliberately not used. ``UpdateAccessKey`` is the
    same call in both directions: holding it would mean a compromised platform could
    re-*activate* every deactivated key in every connected account, which is granting
    access — the one thing the remediate role must never be able to do. The reversible
    option costs the invariant; the invariant wins, and the price is that this step is
    irreversible and can therefore never run unattended.

    **One key per step.** A user with two stale keys gets a plan for the first; the
    finding stays open and the next poll plans the second. Verification therefore asks
    whether *this* key is gone, never whether the user has no stale keys left.
    """
    keys = list(state.get("stale_access_key_ids") or [])
    user = state.get("user_name") or provider_id.rsplit("/", 1)[-1]
    named = state.get("access_key_id")
    if named:
        # An identity finding names its own key: a leaver's key is often *active*, so it
        # is not in ``stale_access_key_ids`` at all. The step is otherwise identical —
        # the same call, the same irreversibility, one key per step.
        key_id = str(named)
    else:
        if not keys:
            return None
        key_id = str(keys[0])

    return PlanStep(
        kind=StepKind.IAM_DELETE_ACCESS_KEY,
        resource_id=provider_id,
        description=(
            f"Delete access key {key_id} belonging to IAM user {user}. Anything still "
            "using this key stops working immediately, and the key material cannot be "
            "recovered — a replacement has to be issued by somebody with permission to "
            "create one, which this role does not have."
        ),
        call=ApiCall(
            action="iam:DeleteAccessKey",
            operation="delete_access_key",
            params={"UserName": user, "AccessKeyId": key_id},
        ),
        inverse=None,
        rollback=RollbackMode.NONE,
        # The named key has to travel in the prior state: the plan is re-built from it
        # before it may start, and a leaver's key is in no stale list, so dropping it
        # here would rebuild to "nothing to do" and the press would be refused.
        prior_state={
            "user_name": user,
            "stale_access_key_ids": keys,
            **({"access_key_id": key_id} if named else {}),
        },
        expected_state={"access_key_ids": {"excludes": [key_id]}},
    )


def _observe_delete_access_key(step: PlanStep, state: Mapping[str, Any]) -> StepObservation:
    key = step.call.params.get("AccessKeyId")
    if state.get("user_name") not in (None, step.call.params.get("UserName")):
        return StepObservation.CHANGED_ELSEWHERE
    details = state.get("access_key_details")
    if isinstance(details, list):
        # The detail list is the only place that can answer this for a key that was not
        # stale: an identity finding deletes a leaver's *active* key, which the stale
        # list by definition does not name. Present and active means the deletion has
        # not happened; present and inactive means somebody else changed it between the
        # plan and the press, which is not the change that was authorized; absent means
        # it was deleted.
        entry = next(
            (item for item in details if isinstance(item, dict) and item.get("key_id") == key),
            None,
        )
        if entry is None:
            return StepObservation.APPLIED
        if str(entry.get("status") or "").strip().lower() == "active":
            return StepObservation.NOT_APPLIED
        return StepObservation.CHANGED_ELSEWHERE
    stale = state.get("stale_access_key_ids")
    if not isinstance(stale, list):
        return StepObservation.UNREADABLE
    if key in stale:
        return StepObservation.NOT_APPLIED
    every_key = state.get("access_key_ids")
    if not isinstance(every_key, list):
        # Not listed as stale any more, but a read from before the poller reported every
        # key cannot tell a deleted key from a deactivated one.
        return StepObservation.UNREADABLE
    return StepObservation.APPLIED if key not in every_key else StepObservation.CHANGED_ELSEWHERE


def _build_detach_user_policy(provider_id: str, state: dict[str, Any]) -> PlanStep | None:
    """Detach an administrator-equivalent policy attached directly to a user.

    One policy per step, the first the poller read — the same reason as a key: a user
    with two gets a plan for one, and verification asks about that one.
    """
    arns = list(state.get("admin_policy_arns") or [])
    user = state.get("user_name") or provider_id.rsplit("/", 1)[-1]
    if not arns:
        return None
    policy_arn = str(arns[0])

    return PlanStep(
        kind=StepKind.IAM_DETACH_USER_POLICY,
        resource_id=provider_id,
        description=(
            f"Detach {policy_arn} from IAM user {user}. The policy itself is not "
            "deleted and nothing else that uses it is affected; this user stops "
            "carrying that policy's administrator permissions directly."
        ),
        call=ApiCall(
            action="iam:DetachUserPolicy",
            operation="detach_user_policy",
            params={"UserName": user, "PolicyArn": policy_arn},
        ),
        inverse=ApiCall(
            action="iam:AttachUserPolicy",
            operation="attach_user_policy",
            params={"UserName": user, "PolicyArn": policy_arn},
        ),
        rollback=RollbackMode.CUSTOMER,
        prior_state={"user_name": user, "admin_policy_arns": arns},
        expected_state={"attached_policy_arns": {"excludes": [policy_arn]}},
        manual_rollback=(
            f"aws iam attach-user-policy --user-name {user} --policy-arn {policy_arn}"
        ),
    )


def _observe_detach_user_policy(step: PlanStep, state: Mapping[str, Any]) -> StepObservation:
    policy = step.call.params.get("PolicyArn")
    if state.get("user_name") not in (None, step.call.params.get("UserName")):
        return StepObservation.CHANGED_ELSEWHERE
    attached = state.get("attached_policy_arns")
    admin = state.get("admin_policy_arns")
    if isinstance(attached, list):
        if policy not in attached:
            return StepObservation.APPLIED
        if isinstance(admin, list) and policy in admin:
            return StepObservation.NOT_APPLIED
        # Still attached, no longer administrator-equivalent: its document changed.
        return StepObservation.CHANGED_ELSEWHERE
    if isinstance(admin, list) and policy in admin:
        return StepObservation.NOT_APPLIED
    return StepObservation.UNREADABLE


# ---------------------------------------------------------------------------
# The catalogue
# ---------------------------------------------------------------------------

_CATALOGUE: Final[dict[StepKind, StepSpec]] = {
    StepKind.S3_BLOCK_PUBLIC_ACCESS: StepSpec(
        kind=StepKind.S3_BLOCK_PUBLIC_ACCESS,
        action="s3:PutBucketPublicAccessBlock",
        rollback=RollbackMode.PLATFORM,
        inverse_actions=("s3:PutBucketPublicAccessBlock",),
        summary="Switch on every S3 public-access block flag.",
        build=_build_block_public_access,
        operation="put_public_access_block",
        inverse_operation="put_public_access_block",
        observe=_observe_block_public_access,
    ),
    StepKind.S3_ENABLE_DEFAULT_ENCRYPTION: StepSpec(
        kind=StepKind.S3_ENABLE_DEFAULT_ENCRYPTION,
        action="s3:PutBucketEncryption",
        rollback=RollbackMode.PLATFORM,
        inverse_actions=("s3:DeleteBucketEncryption",),
        summary="Enable default AES256 encryption on an S3 bucket.",
        build=_build_enable_default_encryption,
        operation="put_bucket_encryption",
        inverse_operation="delete_bucket_encryption",
        observe=_observe_default_encryption,
    ),
    StepKind.EC2_REVOKE_WORLD_INGRESS: StepSpec(
        kind=StepKind.EC2_REVOKE_WORLD_INGRESS,
        action="ec2:RevokeSecurityGroupIngress",
        rollback=RollbackMode.CUSTOMER,
        inverse_actions=("ec2:AuthorizeSecurityGroupIngress",),
        summary="Revoke the internet-facing ingress rules on a security group.",
        build=_build_revoke_world_ingress,
        operation="revoke_security_group_ingress",
        inverse_operation="authorize_security_group_ingress",
        observe=_observe_revoke_world_ingress,
    ),
    StepKind.IAM_DELETE_ACCESS_KEY: StepSpec(
        kind=StepKind.IAM_DELETE_ACCESS_KEY,
        action="iam:DeleteAccessKey",
        rollback=RollbackMode.NONE,
        inverse_actions=(),
        summary="Delete a stale IAM access key.",
        build=_build_delete_access_key,
        operation="delete_access_key",
        inverse_operation=None,
        observe=_observe_delete_access_key,
    ),
    StepKind.IAM_DETACH_USER_POLICY: StepSpec(
        kind=StepKind.IAM_DETACH_USER_POLICY,
        action="iam:DetachUserPolicy",
        rollback=RollbackMode.CUSTOMER,
        inverse_actions=("iam:AttachUserPolicy",),
        summary="Detach an administrator-equivalent policy from an IAM user.",
        build=_build_detach_user_policy,
        operation="detach_user_policy",
        inverse_operation="attach_user_policy",
        observe=_observe_detach_user_policy,
    ),
}


def _operations() -> dict[str, frozenset[str]]:
    table: dict[str, set[str]] = {}
    for spec in _CATALOGUE.values():
        table.setdefault(spec.action, set()).add(spec.operation)
        if spec.inverse_operation is not None:
            for inverse in spec.inverse_actions:
                table.setdefault(inverse, set()).add(spec.inverse_operation)
    return {action: frozenset(operations) for action, operations in table.items()}


_OPERATIONS: Final[dict[str, frozenset[str]]] = _operations()


def catalogue() -> dict[StepKind, StepSpec]:
    """Every step this platform knows how to make. Read by the CI check and the UI."""
    return dict(_CATALOGUE)


def spec_for(kind: StepKind) -> StepSpec:
    return _CATALOGUE[kind]


def allowed_operations(action: str) -> frozenset[str]:
    """The boto3 operations a call naming ``action`` may use: the catalogue's, no other."""
    return _OPERATIONS.get(action, frozenset())


def observe_step(step: PlanStep, state: Mapping[str, Any] | None) -> StepObservation:
    """What a complete read of the step's resource says about the step.

    ``state`` is the resource as that read found it, or ``None`` when the read covered
    the place the resource lives and no longer lists it — which is neither the change
    nor the state before it. Whether the read was complete is the caller's question: an
    incomplete one is :attr:`StepObservation.UNREADABLE` before this is ever asked.
    """
    if state is None:
        return StepObservation.CHANGED_ELSEWHERE
    return _CATALOGUE[step.kind].observe(step, state)
