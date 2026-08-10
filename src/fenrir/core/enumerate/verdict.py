from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from fenrir.exploit.arm_enum import INTERESTING_ROLE_NAMES, NOTABLE_ROLE_NAMES

# Resource types the exploit phase can actually impersonate an MI through
# (mirrors orchestrator.exploit_resource_types).
MI_TARGET_TYPES = {
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Web/sites",
    "Microsoft.ContainerInstance/containerGroups",
    "Microsoft.Logic/workflows",
    "Microsoft.Automation/automationAccounts",
}

UAI_TYPE = "Microsoft.ManagedIdentity/userAssignedIdentities"

# Roles granting Microsoft.Authorization/roleAssignments/write at scope —
# holders can grant themselves (or others) extra roles.
ROLE_ASSIGNMENT_WRITE_ROLES = {
    "Owner",
    "User Access Administrator",
    "Role Based Access Control Administrator",
}

# Roles letting the holder attach an existing UAI to a compute host
# (Microsoft.ManagedIdentity/userAssignedIdentities/assign/action).
UAI_ASSIGN_ROLES = {
    "Owner",
    "Contributor",
    "Managed Identity Operator",
    "Managed Identity Contributor",
}

# Control-plane roles granting write/action on at least one MI-capable host.
HOST_WRITE_ROLES = {
    "Owner",
    "Contributor",
    "Virtual Machine Contributor",
    "Website Contributor",
    "Logic App Contributor",
    "Automation Contributor",
    "Automation Operator",
    "Azure Container Instances Contributor Role",
}

# Data-plane roles worth granting yourself via the self role-assignment
# opportunity to reach Storage / Key Vault / ACR data directly.
SELF_ROLE_ASSIGNMENT_TARGETS = [
    "Storage Account Key Operator Service Role",
    "Storage Blob Data Contributor",
    "Storage Blob Data Owner",
    "Storage Blob Data Reader",
    "Key Vault Administrator",
    "Key Vault Secrets User",
    "Key Vault Reader",
    "AcrPush",
    "AcrPull",
    "AcrDelete",
]


class VerdictStatus(str, Enum):
    READY = "READY"
    UNVERIFIED = "UNVERIFIED"
    BLOCKED_NO_RIGHTS = "BLOCKED_NO_RIGHTS"
    BLOCKED_NO_TARGETS = "BLOCKED_NO_TARGETS"


@dataclass
class ReadinessVerdict:
    status: VerdictStatus
    reasons: list[str] = field(default_factory=list)
    interesting_roles: dict[str, list[str]] = field(default_factory=dict)
    subscription_roles: dict[str, list[str]] = field(default_factory=dict)
    notable_roles: dict[str, list[str]] = field(default_factory=dict)
    opportunities: list[dict[str, Any]] = field(default_factory=list)
    mi_targets: list[dict[str, str]] = field(default_factory=list)
    mi_target_count: int = 0
    target_count: int = 0
    uai_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reasons": self.reasons,
            "interesting_roles": self.interesting_roles,
            "subscription_roles": self.subscription_roles,
            "notable_roles": self.notable_roles,
            "opportunities": self.opportunities,
            "mi_targets": self.mi_targets,
            "mi_target_count": self.mi_target_count,
            "target_count": self.target_count,
            "uai_count": self.uai_count,
            "next_command": "fenrir exploit" if self.status == VerdictStatus.READY else None,
        }


def _opportunities_for_group(
    interesting: list[str],
    notable: list[str],
    scope: str,
    has_uai: bool,
    has_host: bool,
) -> list[dict[str, Any]]:
    """Enumerate privilege-escalation opportunities for one resource group."""
    held = set(interesting) | set(notable)
    opps: list[dict[str, Any]] = []

    assign_writers = held & ROLE_ASSIGNMENT_WRITE_ROLES
    if assign_writers:
        targets = ", ".join(SELF_ROLE_ASSIGNMENT_TARGETS)
        opps.append({
            "kind": "self_role_assignment",
            "summary": (
                f"Self role-assignment: {', '.join(sorted(assign_writers))} grants "
                "roleAssignments/write at this scope."
            ),
            "detail": (
                f"At {scope}, assign yourself data-plane roles such as {targets} to "
                "reach Storage, Key Vault, and ACR data directly instead of through a "
                "managed identity."
            ),
        })

    can_assign_uai = held & UAI_ASSIGN_ROLES
    can_write_host = held & HOST_WRITE_ROLES
    if can_assign_uai and can_write_host and has_uai:
        detail = (
            f"At {scope}, attach an existing UAI to a host you control and request a "
            "token from it via the IMDS endpoint to impersonate the identity."
        )
        if not has_host:
            detail = (
                f"At {scope}, no existing MI-capable host is present — create one "
                "(e.g. a VM) to attach the UAI to."
            )
        opps.append({
            "kind": "auto_attach_uai",
            "summary": (
                f"Auto-attach UAI: {', '.join(sorted(can_assign_uai))} + "
                f"{', '.join(sorted(can_write_host))} can attach a user-assigned "
                "identity to a host you control."
            ),
            "detail": detail,
        })

    return opps


def assess_exploit_readiness(result: Any, resources_collected: bool = True) -> ReadinessVerdict:
    """Judge whether the current user can impersonate a managed identity.

    Mirrors exploit's discovery: only role assignments at the resource-group
    scope (direct, no inheritance expansion) are considered, intersected with
    the interesting-role set the exploit phase acts on. A group is a target
    when it contains any MI-bearing resource of a type exploit can act on.
    """
    if not resources_collected:
        return ReadinessVerdict(
            status=VerdictStatus.UNVERIFIED,
            reasons=[
                "Resource-group enumeration was skipped (--no-resources), "
                "so RG-level role assignments are unknown.",
                "Re-run `fenrir enumerate` without --no-resources to assess exploit readiness.",
            ],
        )

    subs = getattr(result, "subscriptions", None) or []
    interesting_roles: dict[str, list[str]] = {}
    notable_roles: dict[str, list[str]] = {}
    subscription_roles: dict[str, list[str]] = {}
    opportunities: list[dict[str, Any]] = []
    mi_targets: list[dict[str, str]] = []
    target_count = 0
    mi_target_count = 0
    uai_count = 0
    non_control_mi: list[dict[str, str]] = []

    for sub in subs:
        for role in getattr(sub, "roles", None) or []:
            subscription_roles.setdefault(role, []).append(getattr(sub, "display_name", sub.id))

        for rg in getattr(sub, "resource_groups", None) or []:
            rg_roles = getattr(rg, "roles", None) or []
            interesting = [r for r in rg_roles if r in INTERESTING_ROLE_NAMES]
            notable = [r for r in rg_roles if r in NOTABLE_ROLE_NAMES]
            scope = f"{getattr(sub, 'display_name', sub.id)}/{getattr(rg, 'name', rg.id)}"
            rg_has_uai = False
            rg_has_host = False

            for res in getattr(rg, "resources", None) or []:
                rtype = getattr(res, "type", "") or ""
                if rtype == UAI_TYPE:
                    uai_count += 1
                    rg_has_uai = True
                    continue
                if rtype not in MI_TARGET_TYPES:
                    continue
                rg_has_host = True
                entry = {"type": rtype, "name": getattr(res, "name", "?"), "resource_group": getattr(rg, "name", rg.id)}
                if interesting:
                    target_count += 1
                    if getattr(res, "has_managed_identity", False):
                        mi_target_count += 1
                        mi_targets.append(entry)
                elif rg_roles and getattr(res, "has_managed_identity", False):
                    non_control_mi.append(entry)

            for role in notable:
                notable_roles.setdefault(role, []).append(scope)
            for role in interesting:
                interesting_roles.setdefault(role, []).append(scope)

            opportunities.extend(
                _opportunities_for_group(interesting, notable, scope, rg_has_uai, rg_has_host)
            )

    if not interesting_roles:
        reasons = [
            "No exploit-relevant role found at any resource-group scope (requires "
            "Owner, Contributor, User Access Administrator, Virtual Machine Contributor, "
            "Managed Identity Operator, Managed Identity Contributor, Website Contributor, "
            "Logic App Contributor, Automation Contributor, Automation Operator, or Azure "
            "Container Instances Contributor Role).",
        ]
        if notable_roles:
            note = ", ".join(sorted(notable_roles))
            reasons.append(
                f"Note: you hold non-MI roles at RG scope ({note}) — data/credential "
                "access only, cannot impersonate managed identities from there."
            )
        if non_control_mi:
            listed = ", ".join(f"{m['name']} ({m['resource_group']})" for m in non_control_mi[:5])
            reasons.append(
                f"Note: MI-bearing resource(s) exist in RGs where you only hold "
                f"non-exploit roles ({listed}) — exploit cannot act on those."
            )
        if subscription_roles:
            note = ", ".join(f"{r} ({', '.join(s)})" for r, s in sorted(subscription_roles.items()))
            reasons.append(
                f"Note: interesting roles exist at subscription scope only ({note}) — "
                "the exploit phase only checks RG-scope assignments, so they would not be used."
            )
        else:
            reasons.append("No need to continue the attack: exploit would find no targets.")
        return ReadinessVerdict(
            status=VerdictStatus.BLOCKED_NO_RIGHTS,
            reasons=reasons,
            interesting_roles=interesting_roles,
            subscription_roles=subscription_roles,
            notable_roles=notable_roles,
            opportunities=opportunities,
            uai_count=uai_count,
        )

    if mi_target_count == 0:
        reasons = []
        if target_count:
            reasons.append(
                "Exploitable roles exist at RG scope, but none of the MI-capable "
                "resources in those groups currently carries a managed identity."
            )
        else:
            reasons.append(
                "Exploitable roles exist at RG scope, but no MI-capable resource "
                "(VM, App Service, Logic App, Container Group, Automation Account) "
                "was found in those groups."
            )
        if uai_count:
            reasons.append(
                f"{uai_count} user-assigned identit(y/ies) present — dumpable only "
                "once assigned to a VM/App/Logic App host in a controlled group."
            )
        return ReadinessVerdict(
            status=VerdictStatus.BLOCKED_NO_TARGETS,
            reasons=reasons,
            interesting_roles=interesting_roles,
            subscription_roles=subscription_roles,
            notable_roles=notable_roles,
            opportunities=opportunities,
            target_count=target_count,
            uai_count=uai_count,
        )

    roles_str = ", ".join(sorted(interesting_roles))
    return ReadinessVerdict(
        status=VerdictStatus.READY,
        reasons=[
            f"Hold exploit-relevant roles ({roles_str}) at resource-group scope.",
            f"{mi_target_count} MI-bearing resource(s) reachable in those groups — "
            "managed identity tokens can be impersonated.",
        ],
        interesting_roles=interesting_roles,
        subscription_roles=subscription_roles,
        notable_roles=notable_roles,
        opportunities=opportunities,
        mi_targets=mi_targets,
        mi_target_count=mi_target_count,
        target_count=target_count,
        uai_count=uai_count,
    )
