from pathlib import Path
from unittest.mock import Mock, patch, PropertyMock

from typer.testing import CliRunner

from fenrir.cli import app

runner = CliRunner()


def test_enumerate_help():
    result = runner.invoke(app, ["enumerate", "--help"])
    assert result.exit_code == 0
    assert "Enumerate" in result.stdout


def test_enumerate_not_authenticated():
    with patch("fenrir.commands.enumerate.AzureAuthenticator") as MockAuth:
        instance = Mock()
        instance.get_token.return_value = Mock(
            success=False,
            error="Not logged in",
            token=None,
        )
        MockAuth.return_value = instance

        result = runner.invoke(app, ["enumerate"])
        assert result.exit_code == 3


def test_enumerate_bad_format():
    result = runner.invoke(app, ["enumerate", "--format", "xml"])
    assert result.exit_code == 2


def test_enumerate_json_output():
    with patch("fenrir.commands.enumerate.AzureAuthenticator") as MockAuth:
        instance = Mock()
        instance.get_token.return_value = Mock(
            success=True,
            token={"access_token": "fake"},
            username="test@example.com",
            tenant_id="tenant-id",
        )

        mock_collector = Mock()

        result_data = Mock()
        result_data.me = {
            "userPrincipalName": "test@example.com",
            "displayName": "Test User",
            "id": "user-id",
        }
        result_data.domains = []
        result_data.directory_roles = []
        result_data.pim_roles = []
        result_data.groups = []
        result_data.owned_applications = []
        result_data.owned_service_principals = []
        result_data.managed_devices = []
        result_data.subscriptions = []
        result_data.management_groups = []
        result_data.errors = []

        mock_collector.result = result_data
        MockAuth.return_value = instance

        with patch("fenrir.commands.enumerate.EnumerateCollector") as MockCollector:
            MockCollector.return_value = mock_collector

            result = runner.invoke(app, ["enumerate", "--format", "json"])
            assert result.exit_code == 0


def test_enumerate_tree_output():
    with patch("fenrir.commands.enumerate.AzureAuthenticator") as MockAuth, \
         patch("fenrir.commands.enumerate.EnumerateCollector") as MockCollector:

        instance = Mock()
        instance.get_token.return_value = Mock(
            success=True,
            token={"access_token": "fake"},
            username="test@example.com",
            tenant_id="tenant-id",
        )
        MockAuth.return_value = instance

        collector_instance = Mock()
        result_data = Mock()
        result_data.me = {"userPrincipalName": "test@example.com"}
        result_data.domains = []
        result_data.directory_roles = []
        result_data.pim_roles = []
        result_data.groups = []
        result_data.owned_applications = []
        result_data.owned_service_principals = []
        result_data.managed_devices = []
        result_data.subscriptions = []
        result_data.management_groups = []
        result_data.errors = []
        collector_instance.result = result_data
        MockCollector.return_value = collector_instance

        result = runner.invoke(app, ["enumerate"])
        assert result.exit_code == 0


def test_enumerate_with_output_file(tmp_path):
    out = tmp_path / "enumerate.txt"

    with patch("fenrir.commands.enumerate.AzureAuthenticator") as MockAuth, \
         patch("fenrir.commands.enumerate.EnumerateCollector") as MockCollector:

        instance = Mock()
        instance.get_token.return_value = Mock(
            success=True,
            token={"access_token": "fake"},
        )
        MockAuth.return_value = instance

        collector_instance = Mock()
        result_data = Mock()
        result_data.me = {"userPrincipalName": "test@example.com"}
        result_data.domains = []
        result_data.directory_roles = []
        result_data.pim_roles = []
        result_data.groups = []
        result_data.owned_applications = []
        result_data.owned_service_principals = []
        result_data.managed_devices = []
        result_data.subscriptions = []
        result_data.management_groups = []
        result_data.errors = []
        collector_instance.result = result_data
        MockCollector.return_value = collector_instance

        result = runner.invoke(app, ["enumerate", "--output", str(out)])
        assert result.exit_code == 0


def test_enumerate_no_resources():
    with patch("fenrir.commands.enumerate.AzureAuthenticator") as MockAuth, \
         patch("fenrir.commands.enumerate.EnumerateCollector") as MockCollector:

        instance = Mock()
        instance.get_token.return_value = Mock(
            success=True,
            token={"access_token": "fake"},
        )
        MockAuth.return_value = instance

        collector_instance = Mock()
        result_data = Mock()
        result_data.me = {"userPrincipalName": "test@example.com"}
        result_data.domains = []
        result_data.directory_roles = []
        result_data.pim_roles = []
        result_data.groups = []
        result_data.owned_applications = []
        result_data.owned_service_principals = []
        result_data.managed_devices = []
        result_data.subscriptions = []
        result_data.management_groups = []
        result_data.errors = []
        collector_instance.result = result_data
        MockCollector.return_value = collector_instance

        result = runner.invoke(app, ["enumerate", "--no-resources"])
        assert result.exit_code == 0


def test_build_tree_renders_rg_roles_and_mi_badges():
    from fenrir.commands.enumerate import _build_tree
    from fenrir.core.enumerate.models import (
        EnumerationResult,
        Resource,
        ResourceGroup,
        Subscription,
    )

    result = EnumerationResult()
    result.me = {"userPrincipalName": "alice@contoso.com"}
    sub = Subscription(
        id="/subscriptions/sub-1",
        subscription_id="sub-1",
        display_name="Prod Sub",
        state="Enabled",
        roles=["Reader"],
    )
    rg = ResourceGroup(
        name="rg-prod",
        id="/subscriptions/sub-1/resourceGroups/rg-prod",
        location="eastus",
        roles=["Virtual Machine Contributor"],
    )
    rg.resources.append(
        Resource(
            id="/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1",
            name="vm-1",
            type="Microsoft.Compute/virtualMachines",
            roles=["Reader"],
            has_managed_identity=True,
            identity_type="SystemAssigned",
        )
    )
    sub.resource_groups.append(rg)
    result.subscriptions.append(sub)

    from io import StringIO
    from rich.console import Console
    buf = StringIO()
    Console(file=buf, width=120).print(_build_tree(result))
    rendered = buf.getvalue()
    assert "rg-prod" in rendered
    assert "Virtual Machine Contributor" in rendered
    assert "vm-1" in rendered
    assert "MI (SystemAssigned)" in rendered
