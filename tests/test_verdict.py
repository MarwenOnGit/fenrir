from fenrir.core.enumerate.models import (
    EnumerationResult,
    Resource,
    ResourceGroup,
    Subscription,
)
from fenrir.core.enumerate.verdict import (
    MI_TARGET_TYPES,
    VerdictStatus,
    assess_exploit_readiness,
)

VM_TYPE = "Microsoft.Compute/virtualMachines"
SITES_TYPE = "Microsoft.Web/sites"
LOGIC_TYPE = "Microsoft.Logic/workflows"
AUTOMATION_TYPE = "Microsoft.Automation/automationAccounts"
CG_TYPE = "Microsoft.ContainerInstance/containerGroups"
UAI_TYPE = "Microsoft.ManagedIdentity/userAssignedIdentities"


def _subscription_with_rg(rg_roles, resources=None):
    rg = ResourceGroup(
        name="rg-prod",
        id="/subscriptions/sub-1/resourceGroups/rg-prod",
        location="eastus",
        roles=rg_roles,
        resources=resources or [],
    )
    sub = Subscription(
        id="/subscriptions/sub-1",
        subscription_id="sub-1",
        display_name="Prod Sub",
        state="Enabled",
        roles=[],
        resource_groups=[rg],
    )
    return sub


def _resource(name, rtype, mi=False, identity_type=None):
    return Resource(
        id=f"/subscriptions/sub-1/resourceGroups/rg-prod/providers/{rtype}/{name}",
        name=name,
        type=rtype,
        has_managed_identity=mi,
        identity_type=identity_type,
    )


def _result_with(*subs):
    result = EnumerationResult()
    result.subscriptions = list(subs)
    return result


def test_ready_when_vm_with_mi():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Virtual Machine Contributor"],
            resources=[_resource("vm-1", VM_TYPE, mi=True, identity_type="SystemAssigned")],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.READY
    assert verdict.mi_target_count == 1
    assert verdict.target_count == 1
    assert "Virtual Machine Contributor" in verdict.interesting_roles
    assert verdict.mi_targets[0]["name"] == "vm-1"


def test_ready_when_app_service_with_mi():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Contributor"],
            resources=[_resource("func-app", SITES_TYPE, mi=True, identity_type="SystemAssigned")],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.READY
    assert verdict.mi_target_count == 1
    assert verdict.mi_targets[0]["name"] == "func-app"


def test_ready_with_owner_role():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Owner"],
            resources=[_resource("vm-1", VM_TYPE, mi=True)],
        )
    )
    assert assess_exploit_readiness(result).status == VerdictStatus.READY


def test_blocked_no_rights():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Reader"],
            resources=[_resource("vm-1", VM_TYPE, mi=True)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.BLOCKED_NO_RIGHTS
    assert verdict.interesting_roles == {}


def test_blocked_no_rights_empty():
    verdict = assess_exploit_readiness(_result_with())
    assert verdict.status == VerdictStatus.BLOCKED_NO_RIGHTS


def test_blocked_no_targets_when_no_mi():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Virtual Machine Contributor"],
            resources=[_resource("vm-1", VM_TYPE, mi=False)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.BLOCKED_NO_TARGETS
    assert verdict.target_count == 1
    assert verdict.mi_target_count == 0


def test_blocked_no_targets_uai_without_host():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Contributor"],
            resources=[_resource("playaround_MI", UAI_TYPE)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.BLOCKED_NO_TARGETS
    assert verdict.uai_count == 1


def test_unverified_when_resources_not_collected():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Virtual Machine Contributor"],
            resources=[_resource("vm-1", VM_TYPE, mi=True)],
        )
    )
    verdict = assess_exploit_readiness(result, resources_collected=False)
    assert verdict.status == VerdictStatus.UNVERIFIED


def test_non_interesting_resource_types_ignored():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Virtual Machine Contributor"],
            resources=[
                Resource(
                    id="/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/sa1",
                    name="sa1",
                    type="Microsoft.Storage/storageAccounts",
                    has_managed_identity=True,
                    identity_type="SystemAssigned",
                )
            ],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.BLOCKED_NO_TARGETS
    assert verdict.target_count == 0
    assert verdict.mi_target_count == 0


def test_mi_target_types_cover_exploit_hosts():
    assert {
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Web/sites",
        "Microsoft.ContainerInstance/containerGroups",
        "Microsoft.Logic/workflows",
        "Microsoft.Automation/automationAccounts",
    } == MI_TARGET_TYPES


def test_ready_when_website_contributor():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Website Contributor"],
            resources=[_resource("app-1", SITES_TYPE, mi=True)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.READY
    assert "Website Contributor" in verdict.interesting_roles
    assert verdict.mi_targets[0]["name"] == "app-1"


def test_ready_when_logic_app_contributor():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Logic App Contributor"],
            resources=[_resource("wf-1", LOGIC_TYPE, mi=True)],
        )
    )
    assert assess_exploit_readiness(result).status == VerdictStatus.READY


def test_ready_when_automation_contributor():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Automation Contributor"],
            resources=[_resource("aa-1", AUTOMATION_TYPE, mi=True)],
        )
    )
    assert assess_exploit_readiness(result).status == VerdictStatus.READY


def test_ready_when_aci_contributor():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Azure Container Instances Contributor Role"],
            resources=[_resource("cg-1", CG_TYPE, mi=True)],
        )
    )
    assert assess_exploit_readiness(result).status == VerdictStatus.READY


def test_self_role_assignment_opportunity_when_owner():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Owner"],
            resources=[_resource("vm-1", VM_TYPE, mi=True)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.READY
    kinds = [o["kind"] for o in verdict.opportunities]
    assert "self_role_assignment" in kinds


def test_self_role_assignment_opportunity_with_rbac_admin_only():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Role Based Access Control Administrator"],
            resources=[_resource("vm-1", VM_TYPE, mi=True)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.BLOCKED_NO_RIGHTS
    assert "Role Based Access Control Administrator" in verdict.notable_roles
    kinds = [o["kind"] for o in verdict.opportunities]
    assert "self_role_assignment" in kinds
    assert "auto_attach_uai" not in kinds


def test_auto_attach_uai_opportunity():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Contributor"],
            resources=[_resource("uai-1", UAI_TYPE), _resource("vm-1", VM_TYPE)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.BLOCKED_NO_TARGETS
    kinds = [o["kind"] for o in verdict.opportunities]
    assert "auto_attach_uai" in kinds


def test_no_auto_attach_without_uai_assign_role():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Virtual Machine Contributor"],
            resources=[_resource("uai-1", UAI_TYPE), _resource("vm-1", VM_TYPE)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.opportunities == []


def test_notable_roles_collected():
    result = _result_with(
        _subscription_with_rg(
            rg_roles=["Storage Blob Data Contributor"],
            resources=[_resource("vm-1", VM_TYPE, mi=True)],
        )
    )
    verdict = assess_exploit_readiness(result)
    assert verdict.status == VerdictStatus.BLOCKED_NO_RIGHTS
    assert verdict.interesting_roles == {}
    assert "Storage Blob Data Contributor" in verdict.notable_roles
    assert verdict.opportunities == []
