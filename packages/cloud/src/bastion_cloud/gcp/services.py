"""The five supported Google Cloud services, as one catalogue.

Before Stage 3 the five lived in three places that had to be kept in step by hand:
the poller tuple in :mod:`bastion_cloud.gcp.pollers`, the flat permission list in
:mod:`bastion_cloud.gcp.policy`, and the API/permission lists written out literally in
``infra/gcp/observe.tf``. A customer selecting a subset makes that arrangement
untenable — three lists cannot be filtered consistently by three different pieces of
code — so this module is the single definition and the other three are derived from
it.

**A service is the unit a customer selects**, which is why the identity here is the
poller's own ``gcp:<name>`` key rather than a Google API name: one service can need
two APIs (IAM needs Cloud Resource Manager as well), and the thing the customer
excludes is "check my Cloud SQL instances", not "the sqladmin endpoint".

Nothing here is a claim about what a *selected* service found. Exclusion is recorded
and rendered separately from failure for the reason the operation brief gives: a
service nobody asked us to read and a service we could not read are different
sentences, and only one of them is a gap in the account.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "ALWAYS_REQUIRED_APIS",
    "BASE_PERMISSIONS",
    "SERVICES",
    "GcpService",
    "apis_for",
    "default_selection",
    "normalise_selection",
    "permissions_for",
    "service",
    "supported_ids",
]


@dataclass(frozen=True, slots=True)
class GcpService:
    """One selectable check source.

    ``permissions`` is exactly what the custom role needs for this service and
    nothing else, so a customer who selects one service grants one service's worth of
    read access. ``apis`` are the Google APIs that must be enabled in the project for
    those reads to succeed — enabled by the customer's own Terraform, never by the
    observe token, which holds no permission that could.
    """

    id: str
    name: str
    #: What this service actually looks at, in the customer's words. Rendered in the
    #: setup panel beside the checkbox, so the choice is informed rather than a name.
    checks: tuple[str, ...]
    apis: tuple[str, ...]
    permissions: tuple[str, ...]


#: Needed whatever is selected: the Terraform creates a service account, a custom role
#: and an IAM binding, and the platform impersonates through a delegate. Removing a
#: service never removes these, and ``disable_on_destroy = false`` means removing the
#: configuration never disables them either — a shared API this customer enabled for
#: their own workloads must not go away because they stopped checking a service.
ALWAYS_REQUIRED_APIS: Final = (
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudresourcemanager.googleapis.com",
)

#: Granted whatever is selected. ``projects.get`` is what lets a read confirm it is
#: talking to the project the customer named; it exposes no resource configuration.
BASE_PERMISSIONS: Final = ("resourcemanager.projects.get",)

SERVICES: Final[tuple[GcpService, ...]] = (
    GcpService(
        id="gcp:storage",
        name="Cloud Storage",
        checks=(
            "Buckets granting public access through IAM",
            "Buckets that still permit object-level ACLs",
        ),
        apis=("storage.googleapis.com",),
        permissions=(
            "storage.buckets.list",
            "storage.buckets.get",
            "storage.buckets.getIamPolicy",
        ),
    ),
    GcpService(
        id="gcp:compute",
        name="VPC firewall",
        checks=("Firewall rules allowing the world into administrative or database ports",),
        apis=("compute.googleapis.com",),
        permissions=("compute.firewalls.list",),
    ),
    GcpService(
        id="gcp:sql",
        name="Cloud SQL",
        checks=(
            "Instances authorising every source network alongside a public IP",
            "Instances accepting connections without TLS",
            "Instances with automated backups turned off",
        ),
        apis=("sqladmin.googleapis.com",),
        permissions=("cloudsql.instances.list",),
    ),
    GcpService(
        id="gcp:iam",
        name="Project IAM",
        checks=(
            "Project-level grants to the public",
            "Broad Owner or Editor grants",
            "Service accounts with active user-managed keys",
        ),
        # Cloud Resource Manager is always enabled anyway; naming it here keeps the
        # per-service requirement true on its own terms rather than by coincidence.
        apis=("cloudresourcemanager.googleapis.com", "iam.googleapis.com"),
        permissions=(
            "resourcemanager.projects.getIamPolicy",
            "iam.serviceAccounts.list",
            "iam.serviceAccountKeys.list",
        ),
    ),
    GcpService(
        id="gcp:run",
        name="Cloud Run",
        checks=("Services the internet may invoke with no Google credential",),
        apis=("run.googleapis.com",),
        permissions=(
            "run.locations.list",
            "run.services.list",
            "run.services.getIamPolicy",
        ),
    ),
)

_BY_ID: Final = {item.id: item for item in SERVICES}


def supported_ids() -> tuple[str, ...]:
    """Every selectable service id, in the order the setup panel shows them."""
    return tuple(_BY_ID)


def default_selection() -> tuple[str, ...]:
    """All five. A customer who expresses no preference is checked completely."""
    return supported_ids()


def service(service_id: str) -> GcpService:
    if service_id not in _BY_ID:
        raise ValueError(f"Unknown Google Cloud service: {service_id}")
    return _BY_ID[service_id]


def normalise_selection(selected: Iterable[str] | None) -> tuple[str, ...]:
    """Canonical, deduplicated, catalogue-ordered selection.

    ``None`` means "all five" — the default, and what a connection written before this
    stage carries. An empty selection is refused rather than silently treated as the
    default: connecting a project and checking nothing in it is not a state this
    product should be able to reach by accident, and a customer who wanted it would
    disconnect instead.

    Canonical order matters beyond tidiness: the selection is persisted, rendered into
    a policy document and compared against what was granted, and two orderings of one
    selection would look like two different grants.
    """
    if selected is None:
        return default_selection()
    requested = set(selected)
    unknown = sorted(requested - set(_BY_ID))
    if unknown:
        raise ValueError(f"Unknown Google Cloud service: {', '.join(unknown)}")
    chosen = tuple(item for item in _BY_ID if item in requested)
    if not chosen:
        raise ValueError("Select at least one Google Cloud service to check.")
    return chosen


def permissions_for(selected: Sequence[str]) -> tuple[str, ...]:
    """The exact custom-role permissions for one selection.

    Deduplicated across services and kept in a stable order, because this list is
    shown to the customer literally, rendered into their Terraform, and stored on the
    connection as the document they agreed to.
    """
    ordered: list[str] = list(BASE_PERMISSIONS)
    for service_id in normalise_selection(selected):
        for permission in _BY_ID[service_id].permissions:
            if permission not in ordered:
                ordered.append(permission)
    return tuple(ordered)


def apis_for(selected: Sequence[str]) -> tuple[str, ...]:
    """The Google APIs one selection needs enabled, including the always-required."""
    ordered: list[str] = list(ALWAYS_REQUIRED_APIS)
    for service_id in normalise_selection(selected):
        for api in _BY_ID[service_id].apis:
            if api not in ordered:
                ordered.append(api)
    return tuple(ordered)
