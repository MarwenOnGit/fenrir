from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fenrir.exploit.arm_enum import (
    AppService,
    AutomationAccount,
    ContainerGroup,
    LogicApp,
    ResourceInRG,
    ServicePrincipalInfo,
    Subscription,
    UserAssignedIdentity,
    VirtualMachine,
)
from fenrir.exploit.orchestrator import ExploitResult

log = logging.getLogger(__name__)

STATE_VERSION = 1
DEFAULT_STATE_DIR = Path.home() / ".config" / "fenrir"

_GROUP_KEYS = (
    "subscription",
    "sub_id",
    "resource_group",
    "roles",
)


def state_path() -> Path:
    """Return the exploit state path (overridable via FENRIR_STATE)."""
    override = os.environ.get("FENRIR_STATE")
    if override:
        return Path(override)
    return DEFAULT_STATE_DIR / "state.json"


def _group_to_dict(group: dict) -> dict:
    out = {k: group.get(k) for k in _GROUP_KEYS}
    out["managed_identities"] = [mi.to_dict() for mi in group.get("managed_identities", [])]
    out["virtual_machines"] = [vm.to_dict() for vm in group.get("virtual_machines", [])]
    out["app_services"] = [a.to_dict() for a in group.get("app_services", [])]
    out["container_groups"] = [cg.to_dict() for cg in group.get("container_groups", [])]
    out["logic_apps"] = [la.to_dict() for la in group.get("logic_apps", [])]
    out["automation_accounts"] = [aa.to_dict() for aa in group.get("automation_accounts", [])]
    out["service_principals"] = [sp.to_dict() for sp in group.get("service_principals", [])]
    out["all_resources"] = [r.to_dict() for r in group.get("all_resources", [])]
    return out


def _group_from_dict(data: dict) -> dict:
    return {
        "subscription": data.get("subscription", ""),
        "sub_id": data.get("sub_id", ""),
        "resource_group": data.get("resource_group", ""),
        "roles": data.get("roles", []),
        "managed_identities": [
            UserAssignedIdentity.from_dict(x) for x in data.get("managed_identities", [])
        ],
        "virtual_machines": [
            VirtualMachine.from_dict(x) for x in data.get("virtual_machines", [])
        ],
        "app_services": [
            AppService.from_dict(x) for x in data.get("app_services", [])
        ],
        "container_groups": [
            ContainerGroup.from_dict(x) for x in data.get("container_groups", [])
        ],
        "logic_apps": [
            LogicApp.from_dict(x) for x in data.get("logic_apps", [])
        ],
        "automation_accounts": [
            AutomationAccount.from_dict(x) for x in data.get("automation_accounts", [])
        ],
        "service_principals": [
            ServicePrincipalInfo.from_dict(x) for x in data.get("service_principals", [])
        ],
        "all_resources": [
            ResourceInRG.from_dict(x) for x in data.get("all_resources", [])
        ],
    }


def save_state(result: ExploitResult, path: Path | None = None, principal_id: str | None = None) -> Path:
    """Persist an ExploitResult to disk for later reuse by the exploit phase."""
    path = path or state_path()
    payload = {
        "version": STATE_VERSION,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "principal_id": principal_id,
        "subscriptions": [s.to_dict() for s in result.subscriptions],
        "interesting_groups": [_group_to_dict(g) for g in result.interesting_groups],
        "errors": result.errors,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str))
    tmp.replace(path)
    log.info("Saved exploit state to %s", path)
    return path


def load_state(path: Path | None = None) -> dict[str, Any] | None:
    """Read a previously saved state file, or None when absent/unreadable."""
    path = path or state_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Failed to read state %s: %s", path, e)
        return None
    if not isinstance(data, dict):
        return None
    return data


def build_exploit_input(state: dict[str, Any]) -> ExploitResult:
    """Reconstruct an ExploitResult from a saved state dict."""
    result = ExploitResult()
    result.subscriptions = [
        Subscription.from_dict(s) for s in state.get("subscriptions", [])
    ]
    result.interesting_groups = [
        _group_from_dict(g) for g in state.get("interesting_groups", [])
    ]
    result.errors = list(state.get("errors") or [])
    return result


def from_enumeration_result(result: Any) -> ExploitResult:
    """Convert an enumerate EnumerationResult into an ExploitResult for saving.

    Rich exploit groups are only present on resource groups that intersect the
    interesting-role set, collected during enumeration.
    """
    exploit = ExploitResult()
    for sub in getattr(result, "subscriptions", None) or []:
        exploit.subscriptions.append(Subscription(
            id=sub.id,
            subscription_id=sub.subscription_id,
            display_name=sub.display_name,
            state=sub.state,
        ))
        for rg in getattr(sub, "resource_groups", None) or []:
            if getattr(rg, "exploit_group", None):
                exploit.interesting_groups.append(rg.exploit_group)
    exploit.errors = list(getattr(result, "errors", None) or [])
    return exploit
