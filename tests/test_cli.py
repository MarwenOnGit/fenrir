from pathlib import Path
from unittest.mock import Mock, patch

import json
import pytest
from typer.testing import CliRunner

from fenrir.cli import app

runner = CliRunner()


def test_help_succeeds():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "authenticator" in result.stdout.lower()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "cmd",
    [
        ["login"],
        ["logout"],
        ["status"],
        ["token"],
        ["enumerate"],
        ["exploit"],
        ["post-exploit"],
    ],
)
def test_verbose_flag_accepted(cmd):
    result = runner.invoke(app, cmd + ["--help"])
    assert result.exit_code == 0
    result = runner.invoke(app, cmd + ["-v", "--help"])
    assert result.exit_code == 0


def test_login_bad_auth_flow():
    result = runner.invoke(app, ["login", "--auth-flow", "nope"])
    assert result.exit_code == 2


@patch("fenrir.commands.login.AzureAuthenticator")
def test_login_device_code_success(MockAuth):
    instance = Mock()
    instance.authenticate.return_value = Mock(
        success=True,
        token={"access_token": "fake"},
        username="test@example.com",
        tenant_id="tenant-id",
    )
    MockAuth.return_value = instance

    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert "Authenticated" in result.stderr


@patch("fenrir.commands.login.AzureAuthenticator")
def test_login_ropc_success(MockAuth):
    instance = Mock()
    instance.authenticate.return_value = Mock(
        success=True,
        token={"access_token": "fake"},
        username="test@example.com",
        tenant_id="tenant-id",
    )
    MockAuth.return_value = instance

    result = runner.invoke(
        app,
        ["login", "--auth-flow", "ropc", "--username", "test@example.com", "--password", "hunter2"],
    )
    assert result.exit_code == 0
    assert "Authenticated" in result.stderr


def test_login_ropc_missing_password():
    result = runner.invoke(
        app,
        ["login", "--auth-flow", "ropc", "--username", "test@example.com"],
    )
    assert result.exit_code == 2


@patch("fenrir.commands.login.AzureAuthenticator")
def test_login_with_password_file(MockAuth):
    pf = Path("/tmp/test_password_file.txt")
    pf.write_text("supersecret\n")

    instance = Mock()
    instance.authenticate.return_value = Mock(
        success=True,
        token={"access_token": "fake"},
        username="test@example.com",
        tenant_id="tenant-id",
    )
    MockAuth.return_value = instance

    result = runner.invoke(
        app,
        [
            "login",
            "--auth-flow", "ropc",
            "--username", "test@example.com",
            "--password-file", str(pf),
        ],
    )
    pf.unlink(missing_ok=True)
    assert result.exit_code == 0


@patch("fenrir.commands.login.AzureAuthenticator")
def test_login_failure(MockAuth):
    instance = Mock()
    instance.authenticate.return_value = Mock(
        success=False,
        error="Invalid credentials",
        token=None,
    )
    MockAuth.return_value = instance

    result = runner.invoke(app, ["login"])
    assert result.exit_code == 3
    assert "Invalid" in result.stderr


def test_logout_help():
    result = runner.invoke(app, ["logout", "--help"])
    assert result.exit_code == 0


def test_status_help():
    result = runner.invoke(app, ["status", "--help"])
    assert result.exit_code == 0


def test_token_help():
    result = runner.invoke(app, ["token", "--help"])
    assert result.exit_code == 0


def test_post_exploit_help():
    result = runner.invoke(app, ["post-exploit", "--help"])
    assert result.exit_code == 0
    assert "--mi" in result.stdout
    assert "--dump-blobs" in result.stdout
    assert "--dump-images" in result.stdout
    assert "--acr-token" in result.stdout
    assert "--dump-dir" in result.stdout
    assert "--max-size" in result.stdout
    assert "--yes" in result.stdout


@patch("fenrir.commands.post_exploit.load_tokens", return_value=[])
def test_post_exploit_no_cached_tokens(mock_load):
    result = runner.invoke(app, ["post-exploit"])
    assert result.exit_code == 1
    assert "No cached MI tokens" in result.stderr


def test_post_exploit_dump_blobs_requires_confirm():
    from fenrir.exploit.storage import StorageHarvestResult

    token_entry = {
        "mi_name": "mi-1", "identity_kind": "UserAssigned", "client_id": "c-1",
        "principal_id": "p-1", "source_resource": "vm-1",
        "access_token": "tok-1", "expires_on": "2099-01-01T00:00:00+00:00",
    }
    result = Mock(
        identity={},
        subscriptions=[],
        role_assignments=[],
        storage_accounts=[],
        errors=[],
    )
    instance = Mock()
    instance.enumerate.return_value = result

    with patch("fenrir.commands.post_exploit.load_tokens", return_value=[token_entry]), \
         patch("fenrir.commands.post_exploit.PostExploitEnumerator", return_value=instance), \
         patch("fenrir.commands.post_exploit.Confirm.ask", return_value=False), \
         patch("fenrir.commands.post_exploit.harvest_storage_account",
               return_value=StorageHarvestResult(account_name="acct1", account_id="/x")) as mock_harvest:
        res = runner.invoke(app, ["post-exploit", "--index", "1", "--dump-blobs", "-f", "json"])

    assert res.exit_code == 0
    mock_harvest.assert_not_called()


def test_post_exploit_dump_blobs_yes_harvests(tmp_path):
    from fenrir.exploit.storage import StorageHarvestResult

    token_entry = {
        "mi_name": "mi-1", "identity_kind": "UserAssigned", "client_id": "c-1",
        "principal_id": "p-1", "source_resource": "vm-1",
        "access_token": "tok-1", "expires_on": "2099-01-01T00:00:00+00:00",
        "tokens": {"https://storage.azure.com": {"access_token": "storage-tok"}},
    }
    result = Mock(
        identity={},
        role_assignments=[],
        errors=[],
        storage_accounts=[{
            "id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/acct1",
            "name": "acct1",
            "capabilities": [
                {"capability_id": "storage.read_blobs", "granted": True},
                {"capability_id": "storage.list_keys", "granted": False},
            ],
        }],
        subscriptions=[{
            "resource_groups": [{
                "resources": [{
                    "type": "Microsoft.Storage/storageAccounts",
                    "id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/acct1",
                    "capabilities": [
                        {"capability_id": "storage.read_blobs", "granted": True},
                        {"capability_id": "storage.list_keys", "granted": False},
                    ],
                }],
            }],
        }],
    )
    instance = Mock()
    instance.enumerate.return_value = result

    harvested = StorageHarvestResult(
        account_name="acct1",
        account_id="/subscriptions/s/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/acct1",
        files=[{"path": "acct1/cont1/secret.txt", "container": "cont1",
                "name": "secret.txt", "size": 5, "downloaded_bytes": 5, "truncated": False}],
        downloaded=1,
        bytes_downloaded=5,
    )

    with patch("fenrir.commands.post_exploit.load_tokens", return_value=[token_entry]), \
         patch("fenrir.commands.post_exploit.PostExploitEnumerator", return_value=instance), \
         patch("fenrir.commands.post_exploit.harvest_storage_account",
               return_value=harvested) as mock_harvest:
        res = runner.invoke(
            app,
            ["post-exploit", "--index", "1", "--dump-blobs", "--dump-dir",
             str(tmp_path), "--max-size", "1024", "--yes", "-f", "json"],
        )

    assert res.exit_code == 0
    mock_harvest.assert_called_once()
    kwargs = mock_harvest.call_args.kwargs
    assert kwargs["account_id"].endswith("/storageAccounts/acct1")
    assert kwargs["storage_token"] == "storage-tok"
    assert kwargs["max_size"] == 1024
    assert kwargs["list_keys"] is False

    manifest = tmp_path / "manifest.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text())
    assert data["files"] == 1
    assert data["accounts"][0]["account_name"] == "acct1"


@patch("fenrir.commands.post_exploit.load_tokens")
@patch("fenrir.commands.post_exploit.PostExploitEnumerator")
def test_post_exploit_by_index(MockEnum, mock_load):
    mock_load.return_value = [
        {
            "mi_name": "mi-1", "identity_kind": "UserAssigned", "client_id": "c-1",
            "principal_id": "p-1", "source_resource": "vm-1",
            "access_token": "tok-1", "expires_on": "2099-01-01T00:00:00+00:00",
        },
        {
            "mi_name": "mi-2", "identity_kind": "SystemAssigned", "client_id": None,
            "principal_id": "p-2", "source_resource": "vm-2",
            "access_token": "tok-2", "expires_on": "2099-01-01T00:00:00+00:00",
        },
    ]
    instance = Mock()
    instance.enumerate.return_value = Mock(
        identity={},
        subscriptions=[],
        role_assignments=[],
        errors=[],
    )
    MockEnum.return_value = instance

    result = runner.invoke(app, ["post-exploit", "--index", "2", "-f", "json"])
    assert result.exit_code == 0
    MockEnum.assert_called_once_with(token="tok-2", principal_id="p-2", client_id=None)


@patch("fenrir.commands.token.AzureAuthenticator")
def test_token_missing_token(MockAuth):
    instance = Mock()
    instance.get_token.return_value = Mock(
        success=False,
        error="No cached token",
        token=None,
    )
    MockAuth.return_value = instance

    result = runner.invoke(app, ["token"])
    assert result.exit_code != 0


@patch("fenrir.commands.token.AzureAuthenticator")
def test_token_raw(MockAuth):
    instance = Mock()
    instance.get_token.return_value = Mock(
        success=True,
        token={"access_token": "abc123", "expires_on": "1234567890"},
        username="test@example.com",
        tenant_id="tenant-id",
    )
    MockAuth.return_value = instance

    result = runner.invoke(app, ["token", "--raw"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "abc123"


def _storage_account_entry():
    return {
        "id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/acct1",
        "name": "acct1",
        "capabilities": [
            {"capability_id": "storage.read_blobs", "granted": True},
            {"capability_id": "storage.list_keys", "granted": False},
        ],
    }


@patch("fenrir.commands.post_exploit.load_tokens")
@patch("fenrir.commands.post_exploit.PostExploitEnumerator")
def test_post_exploit_injected_access_token(MockEnum, mock_load):
    instance = Mock()
    instance.enumerate.return_value = Mock(
        identity={}, subscriptions=[], role_assignments=[], storage_accounts=[], errors=[],
    )
    MockEnum.return_value = instance

    result = runner.invoke(app, [
        "post-exploit",
        "--access-token", "injected-arm",
        "--storage-token", "injected-storage",
        "--principal-id", "pid-9",
        "-f", "json",
    ])
    assert result.exit_code == 0
    mock_load.assert_not_called()
    MockEnum.assert_called_once_with(token="injected-arm", principal_id="pid-9", client_id=None)


@patch("fenrir.commands.post_exploit.load_tokens")
@patch("fenrir.commands.post_exploit.PostExploitEnumerator")
def test_post_exploit_injected_acr_token(MockEnum, mock_load):
    instance = Mock()
    instance.enumerate.return_value = Mock(
        identity={}, subscriptions=[], role_assignments=[], storage_accounts=[], registries=[], errors=[],
    )
    MockEnum.return_value = instance

    result = runner.invoke(app, [
        "post-exploit",
        "--access-token", "injected-arm",
        "--storage-token", "injected-storage",
        "--acr-token", "injected-acr",
        "--principal-id", "pid-9",
        "-f", "json",
    ])
    assert result.exit_code == 0
    mock_load.assert_not_called()
    MockEnum.assert_called_once_with(token="injected-arm", principal_id="pid-9", client_id=None)
    entry = instance.enumerate.return_value.identity
    assert entry["tokens"]["https://containerregistry.azure.net"]["access_token"] == "injected-acr"


def _registry_entry():
    return {
        "id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.ContainerRegistry/registries/acct1",
        "name": "acct1",
        "capabilities": [
            {"capability_id": "registry.read_images", "granted": True},
            {"capability_id": "registry.admin_creds", "granted": False},
        ],
    }


def test_post_exploit_dump_images_yes_harvests(tmp_path):
    from fenrir.exploit.acr import RegistryHarvestResult

    token_entry = {
        "mi_name": "mi-1", "identity_kind": "UserAssigned", "client_id": "c-1",
        "principal_id": "p-1", "source_resource": "vm-1",
        "access_token": "tok-1", "expires_on": "2099-01-01T00:00:00+00:00",
        "tokens": {"https://containerregistry.azure.net": {"access_token": "acr-tok"}},
    }
    result = Mock(
        identity={},
        role_assignments=[],
        errors=[],
        registries=[_registry_entry()],
        subscriptions=[],
    )
    instance = Mock()
    instance.enumerate.return_value = result

    harvested = RegistryHarvestResult(
        registry_name="acct1",
        registry_id=_registry_entry()["id"],
        repos=["app"],
        images=[{"repository": "app", "tag": "v1", "layers": []}],
        downloaded=1,
        bytes_downloaded=10,
    )

    with patch("fenrir.commands.post_exploit.load_tokens", return_value=[token_entry]), \
         patch("fenrir.commands.post_exploit.PostExploitEnumerator", return_value=instance), \
         patch("fenrir.commands.post_exploit.harvest_container_registry",
               return_value=harvested) as mock_harvest:
        res = runner.invoke(
            app,
            ["post-exploit", "--index", "1", "--dump-images", "--dump-dir",
             str(tmp_path), "--max-size", "1024", "--yes", "-f", "json"],
        )

    assert res.exit_code == 0
    mock_harvest.assert_called_once()
    kwargs = mock_harvest.call_args.kwargs
    assert kwargs["registry_id"].endswith("/registries/acct1")
    assert kwargs["registry_token"] == "acr-tok"
    assert kwargs["max_size"] == 1024
    assert kwargs["list_admin"] is False

    manifest = tmp_path / "manifest.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text())
    assert data["bytes"] == 10
    assert data["registries"][0]["registry_name"] == "acct1"


def test_post_exploit_dump_images_requires_confirm():
    from fenrir.exploit.acr import RegistryHarvestResult

    token_entry = {
        "mi_name": "mi-1", "identity_kind": "UserAssigned", "client_id": "c-1",
        "principal_id": "p-1", "source_resource": "vm-1",
        "access_token": "tok-1", "expires_on": "2099-01-01T00:00:00+00:00",
        "tokens": {"https://containerregistry.azure.net": {"access_token": "acr-tok"}},
    }
    result = Mock(
        identity={},
        subscriptions=[],
        role_assignments=[],
        registries=[_registry_entry()],
        errors=[],
    )
    instance = Mock()
    instance.enumerate.return_value = result

    with patch("fenrir.commands.post_exploit.load_tokens", return_value=[token_entry]), \
         patch("fenrir.commands.post_exploit.PostExploitEnumerator", return_value=instance), \
         patch("fenrir.commands.post_exploit.Confirm.ask", return_value=False), \
         patch("fenrir.commands.post_exploit.harvest_container_registry",
               return_value=RegistryHarvestResult(registry_name="acct1", registry_id="/x")) as mock_harvest:
        res = runner.invoke(app, ["post-exploit", "--index", "1", "--dump-images", "-f", "json"])

    assert res.exit_code == 0
    mock_harvest.assert_not_called()


def test_post_exploit_dump_images_dry_run_no_confirm(tmp_path):
    from fenrir.exploit.acr import RegistryHarvestResult

    token_entry = {
        "mi_name": "mi-1", "identity_kind": "UserAssigned", "client_id": "c-1",
        "principal_id": "p-1", "source_resource": "vm-1",
        "access_token": "tok-1", "expires_on": "2099-01-01T00:00:00+00:00",
        "tokens": {"https://containerregistry.azure.net": {"access_token": "acr-tok"}},
    }
    result = Mock(
        identity={},
        role_assignments=[],
        errors=[],
        registries=[_registry_entry()],
        subscriptions=[],
    )
    instance = Mock()
    instance.enumerate.return_value = result

    harvested = RegistryHarvestResult(
        registry_name="acct1",
        registry_id=_registry_entry()["id"],
        repos=["app"],
        images=[],
        downloaded=0,
        bytes_downloaded=0,
    )

    with patch("fenrir.commands.post_exploit.load_tokens", return_value=[token_entry]), \
         patch("fenrir.commands.post_exploit.PostExploitEnumerator", return_value=instance), \
         patch("fenrir.commands.post_exploit.Confirm.ask",
               side_effect=AssertionError("dry-run must not prompt")), \
         patch("fenrir.commands.post_exploit.harvest_container_registry",
               return_value=harvested) as mock_harvest:
        res = runner.invoke(
            app,
            ["post-exploit", "--index", "1", "--dump-images", "--dry-run",
             "--dump-dir", str(tmp_path), "-f", "json"],
        )

    assert res.exit_code == 0
    kwargs = mock_harvest.call_args.kwargs
    assert kwargs["dry_run"] is True
    manifest = tmp_path / "manifest.json"
    assert manifest.exists()
    assert json.loads(manifest.read_text())["dry_run"] is True


def test_post_exploit_dry_run_no_confirm_and_inventory_only(tmp_path):
    from fenrir.exploit.storage import StorageHarvestResult

    token_entry = {
        "mi_name": "mi-1", "identity_kind": "UserAssigned", "client_id": "c-1",
        "principal_id": "p-1", "source_resource": "vm-1",
        "access_token": "tok-1", "expires_on": "2099-01-01T00:00:00+00:00",
        "tokens": {"https://storage.azure.com": {"access_token": "storage-tok"}},
    }
    result = Mock(
        identity={},
        role_assignments=[],
        errors=[],
        storage_accounts=[_storage_account_entry()],
        subscriptions=[],
    )
    instance = Mock()
    instance.enumerate.return_value = result

    harvested = StorageHarvestResult(
        account_name="acct1",
        account_id="/subscriptions/s/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/acct1",
        files=[{"path": "acct1/cont1/a.txt", "container": "cont1", "name": "a.txt",
                "size": 5, "downloaded_bytes": 0, "downloaded": False}],
        downloaded=0,
        bytes_downloaded=0,
    )

    with patch("fenrir.commands.post_exploit.load_tokens", return_value=[token_entry]), \
         patch("fenrir.commands.post_exploit.PostExploitEnumerator", return_value=instance), \
         patch("fenrir.commands.post_exploit.Confirm.ask",
               side_effect=AssertionError("dry-run must not prompt")), \
         patch("fenrir.commands.post_exploit.harvest_storage_account",
               return_value=harvested) as mock_harvest:
        res = runner.invoke(
            app,
            ["post-exploit", "--index", "1", "--dump-blobs", "--dry-run",
             "--dump-dir", str(tmp_path), "-f", "json"],
        )

    assert res.exit_code == 0
    kwargs = mock_harvest.call_args.kwargs
    assert kwargs["dry_run"] is True
    assert not (tmp_path / "acct1").exists()
    manifest = tmp_path / "manifest.json"
    assert manifest.exists()
    assert json.loads(manifest.read_text())["dry_run"] is True
