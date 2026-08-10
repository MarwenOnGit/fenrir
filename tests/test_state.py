from unittest.mock import Mock, PropertyMock, patch

from typer.testing import CliRunner

from fenrir.core.enumerate.models import (
    EnumerationResult,
    ResourceGroup as EnumResourceGroup,
    Subscription as EnumSubscription,
)
from fenrir.exploit.arm_enum import (
    AppService,
    AutomationAccount,
    ContainerGroup,
    LogicApp,
    ResourceInRG,
    RoleAssignment,
    ServicePrincipalInfo,
    Subscription,
    UserAssignedIdentity,
    VirtualMachine,
)
from fenrir.exploit.orchestrator import ExploitResult
from fenrir.state import (
    build_exploit_input,
    from_enumeration_result,
    load_state,
    save_state,
    state_path,
)

runner = CliRunner()


def _sample_result() -> ExploitResult:
    sub = Subscription(
        id="/subscriptions/s1",
        subscription_id="s1",
        display_name="Prod",
        state="Enabled",
    )
    mi = UserAssignedIdentity(
        id="/s1/rg1/mi1", name="mi-1", resource_group="rg1", subscription_id="s1",
        principal_id="p1", client_id="c1", tenant_id="t1",
        role_assignments=[
            RoleAssignment(role_name="Owner", role_id="/x/owner", scope="/s1", principal_id="p1")
        ],
    )
    vm = VirtualMachine(
        id="/s1/rg1/vm1", name="vm1", resource_group="rg1", subscription_id="s1",
        location="eastus", os_type="Linux", has_system_assigned_identity=True,
    )
    group = {
        "subscription": "Prod",
        "sub_id": "s1",
        "resource_group": "rg1",
        "roles": ["Owner"],
        "managed_identities": [mi],
        "virtual_machines": [vm],
        "app_services": [
            AppService(id="a", name="app1", resource_group="rg1", subscription_id="s1", kind="app")
        ],
        "container_groups": [
            ContainerGroup(id="c", name="cg1", resource_group="rg1", subscription_id="s1", location="eastus")
        ],
        "logic_apps": [
            LogicApp(id="l", name="la1", resource_group="rg1", subscription_id="s1")
        ],
        "automation_accounts": [
            AutomationAccount(id="aa", name="aa1", resource_group="rg1", subscription_id="s1")
        ],
        "service_principals": [
            ServicePrincipalInfo(principal_id="sp1", display_name="sp", app_id="appid")
        ],
        "all_resources": [
            ResourceInRG(
                id="/s1/rg1/r1", name="r1",
                type="Microsoft.Storage/storageAccounts", user_can_read=True,
            )
        ],
    }
    result = ExploitResult(subscriptions=[sub])
    result.interesting_groups = [group]
    return result


def test_state_round_trip(tmp_path):
    result = _sample_result()
    path = save_state(result, tmp_path / "state.json", principal_id="user-1")

    assert path.exists()
    data = load_state(path)
    assert data["version"] == 1
    assert data["principal_id"] == "user-1"

    restored = build_exploit_input(data)
    assert restored.subscriptions == result.subscriptions
    assert len(restored.interesting_groups) == 1
    g = restored.interesting_groups[0]
    assert g["roles"] == ["Owner"]
    assert g["managed_identities"][0].role_assignments[0].role_name == "Owner"
    assert g["virtual_machines"][0].os_type == "Linux"
    assert g["virtual_machines"][0].has_system_assigned_identity is True
    assert g["app_services"][0].kind == "app"
    assert g["container_groups"][0].location == "eastus"
    assert g["logic_apps"][0].state == "Enabled"
    assert g["automation_accounts"][0].sku == "Basic"
    assert g["service_principals"][0].principal_id == "sp1"
    assert g["all_resources"][0].user_can_read is True


def test_state_round_trip_plain_dict_group(tmp_path):
    result = ExploitResult()
    result.subscriptions = [Subscription(id="/s", subscription_id="s", display_name="S", state="Enabled")]
    result.interesting_groups = [{
        "subscription": "S", "sub_id": "s", "resource_group": "rg", "roles": ["Contributor"],
        "managed_identities": [], "virtual_machines": [], "app_services": [],
        "container_groups": [], "logic_apps": [], "automation_accounts": [],
        "service_principals": [], "all_resources": [],
    }]
    path = save_state(result, tmp_path / "state.json")
    restored = build_exploit_input(load_state(path))
    g = restored.interesting_groups[0]
    assert g["roles"] == ["Contributor"]
    assert g["managed_identities"] == []


def test_load_state_missing_returns_none(tmp_path):
    assert load_state(tmp_path / "nope.json") is None


def test_state_path_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("FENRIR_STATE", str(tmp_path / "custom.json"))
    assert state_path() == tmp_path / "custom.json"


def test_from_enumeration_result():
    esub = EnumSubscription(id="/s", subscription_id="s1", display_name="Prod", state="Enabled")
    erg = EnumResourceGroup(name="rg1", id="/s/rg1", location="eastus", roles=["Owner"])
    erg.exploit_group = _sample_result().interesting_groups[0]
    esub.resource_groups = [erg]

    enum = EnumerationResult()
    enum.subscriptions = [esub]
    enum.errors = ["boom"]

    exploit = from_enumeration_result(enum)
    assert exploit.subscriptions[0].subscription_id == "s1"
    assert len(exploit.interesting_groups) == 1
    assert exploit.errors == ["boom"]


def test_from_enumeration_result_skips_non_interesting_rg():
    esub = EnumSubscription(id="/s", subscription_id="s1", display_name="Prod", state="Enabled")
    erg = EnumResourceGroup(name="rg1", id="/s/rg1", location="eastus", roles=["Reader"])
    esub.resource_groups = [erg]

    enum = EnumerationResult()
    enum.subscriptions = [esub]

    exploit = from_enumeration_result(enum)
    assert exploit.interesting_groups == []


def test_exploit_cli_loads_state_skips_discovery(tmp_path):
    from fenrir.cli import app
    from fenrir.exploit.orchestrator import ExploitOrchestrator

    state_file = tmp_path / "state.json"
    save_state(_sample_result(), state_file, principal_id="user-1")

    auth_instance = Mock()
    auth_instance.get_token_for_scopes.return_value = Mock(
        success=True, token={"access_token": "tok"}, username="test@example.com"
    )

    with patch("fenrir.commands.exploit.AzureAuthenticator", return_value=auth_instance), \
         patch("fenrir.exploit.discovery.get_current_principal_id", return_value="user-1"), \
         patch.object(ExploitOrchestrator, "graph_token", new_callable=PropertyMock, return_value=None), \
         patch.object(ExploitOrchestrator, "discover", side_effect=AssertionError("discover must not run")):
        res = runner.invoke(
            app, ["exploit", "--state", str(state_file), "--skip-run-command", "-f", "json"]
        )

    assert res.exit_code == 0
    assert "Loaded 1 interesting resource group(s)" in res.stderr
    import json
    data = json.loads(res.stdout)
    assert data["interesting_resource_groups"][0]["virtual_machines"][0]["name"] == "vm1"


def test_exploit_cli_missing_explicit_state_exits_3(tmp_path):
    from fenrir.cli import app

    auth_instance = Mock()
    auth_instance.get_token_for_scopes.return_value = Mock(
        success=True, token={"access_token": "tok"}, username="test@example.com"
    )

    with patch("fenrir.commands.exploit.AzureAuthenticator", return_value=auth_instance):
        res = runner.invoke(
            app, ["exploit", "--state", str(tmp_path / "missing.json"), "--skip-run-command"]
        )

    assert res.exit_code == 3
    assert "fenrir enumerate" in res.stderr
