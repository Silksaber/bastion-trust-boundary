"""Literal read allowlist shown at connection time and rendered into Terraform.

Both artifacts are derived from :mod:`bastion_cloud.gcp.services` rather than written
out twice. That is not tidiness: the customer reviews the policy document in the panel
and applies the Terraform in their own project, and a permission present in one and
absent from the other means one of the two screens is lying about what is being
granted. The golden test in ``cloud_tests/test_gcp.py`` pins the two together for
every selection, which is the check that keeps them honest as services are added.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from bastion_cloud.gcp.services import (
    apis_for,
    default_selection,
    normalise_selection,
    permissions_for,
    service,
)

__all__ = ["PERMISSIONS", "document", "render_terraform"]

#: Every permission, for the default selection. Kept as a module constant because the
#: deployment's own permission audit and several tests ask "what is the widest thing
#: this role can ever be", and the answer should not require choosing a selection.
PERMISSIONS: Final = permissions_for(default_selection())

#: Replaced when the personalised configuration is rendered. Each is a *quoted string*
#: in the checked-in template so that file stays valid Terraform on its own and
#: ``terraform validate`` means something before any substitution has happened.
_DELEGATE_PLACEHOLDER: Final = "BASTION_DELEGATE_EMAIL"
_APIS_PLACEHOLDER: Final = '"BASTION_REQUIRED_APIS"'
_PERMISSIONS_PLACEHOLDER: Final = '"BASTION_PERMISSIONS"'
_SELECTION_PLACEHOLDER: Final = "# BASTION_SELECTED_SERVICES"


def document(selected: Sequence[str] | None = None) -> dict[str, Any]:
    """The custom role exactly as the customer sees it, for one selection."""
    services = normalise_selection(selected)
    return {
        "title": "Bastion Observe",
        "description": "Read security configuration only; no workload data or write permissions.",
        "stage": "GA",
        "includedPermissions": list(permissions_for(services)),
    }


def _quoted(values: Sequence[str]) -> str:
    return ", ".join(f'"{value}"' for value in values)


def render_terraform(template: str, *, delegate: str, selected: Sequence[str] | None) -> str:
    """Personalise the checked-in template for one organization and one selection.

    Substitution rather than generation, deliberately. A generated configuration would
    drift from the file an operator reads and a reviewer diffs; this way there is one
    Terraform configuration in the repository, it is valid on its own, and what varies
    between customers is three literal lists.

    Raises if any token is missing — a template edited so that a placeholder no longer
    matches must fail loudly here rather than hand a customer a configuration whose
    permissions are still the placeholder string.
    """
    services = normalise_selection(selected)
    excluded = [item for item in default_selection() if item not in services]
    lines = [
        "# Selected checks: " + ", ".join(service(item).name for item in services) + ".",
    ]
    if excluded:
        lines.append(
            "# Not selected, and therefore not granted or checked: "
            + ", ".join(service(item).name for item in excluded)
            + "."
        )
    else:
        lines.append("# Every supported service is selected.")
    for token in (
        _DELEGATE_PLACEHOLDER,
        _APIS_PLACEHOLDER,
        _PERMISSIONS_PLACEHOLDER,
        _SELECTION_PLACEHOLDER,
    ):
        if token not in template:
            raise ValueError(f"The Google Cloud template no longer contains {token!r}.")
    # Everything above the selection token is a note to whoever reads the checked-in
    # template — it explains placeholders — and is dropped from the customer's copy,
    # where those placeholders no longer exist and the note would describe nothing.
    _, _, body = template.partition(_SELECTION_PLACEHOLDER)
    header = [
        "# Bastion read-only access for one Google Cloud project, generated for your",
        "# organization. Apply it in its own Terraform directory and keep the state:",
        "# destroying it later removes the service account, its role and our grant.",
        *lines,
    ]
    return (
        ("\n".join(header) + body)
        .replace(_APIS_PLACEHOLDER, _quoted(apis_for(services)))
        .replace(_PERMISSIONS_PLACEHOLDER, _quoted(permissions_for(services)))
        .replace(_DELEGATE_PLACEHOLDER, delegate)
    )
