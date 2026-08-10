from datetime import datetime, timedelta, timezone

import pytest

from fenrir.exploit.token_cache import (
    build_entry,
    entry_key,
    find_by_client_id,
    find_by_name,
    get_audience_token,
    is_expired,
    load_tokens,
    remove_entry,
    save_entry,
)


@pytest.fixture
def cache_path(tmp_path, monkeypatch):
    path = tmp_path / "mi_tokens.json"
    monkeypatch.setenv("FENRIR_MI_TOKEN_CACHE", str(path))
    return path


def _entry(**overrides):
    base = {
        "mi_name": "mi-1",
        "identity_kind": "UserAssigned",
        "client_id": "client-1",
        "principal_id": "principal-1",
        "source_resource": "vm-1",
        "source_type": "VirtualMachine",
        "subscription_id": "sub-1",
        "resource_group": "rg-1",
        "tenant_id": "tenant-1",
        "resource": "https://management.azure.com",
        "access_token": "token-1",
        "expires_on": "2026-01-01T00:00:00+00:00",
        "cached_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


def test_build_entry_requires_token():
    with pytest.raises(ValueError):
        build_entry(
            mi_name="x", identity_kind=None, client_id=None, principal_id=None,
            source_resource="v", source_type="VirtualMachine",
            subscription_id="s", resource_group="r", tenant_id=None,
            imds_token={"expires_on": "123"},
        )


def test_build_entry_expires_on_iso():
    entry = build_entry(
        mi_name="mi-1", identity_kind="UserAssigned", client_id="c1",
        principal_id="p1", source_resource="vm-1", source_type="VirtualMachine",
        subscription_id="s1", resource_group="rg1", tenant_id="t1",
        imds_token={"access_token": "tok", "expires_on": "1750000000"},
    )
    assert entry["access_token"] == "tok"
    assert entry["expires_on"] == datetime.fromtimestamp(1750000000, tz=timezone.utc).isoformat()


def test_save_and_load(cache_path):
    save_entry(_entry())
    entries = load_tokens()
    assert len(entries) == 1
    assert entries[0]["client_id"] == "client-1"


def test_dedup_replaces_same_client(cache_path):
    save_entry(_entry(access_token="token-1"))
    save_entry(_entry(access_token="token-2"))
    entries = load_tokens()
    assert len(entries) == 1
    assert entries[0]["access_token"] == "token-2"


def test_entry_key_fallback():
    assert entry_key({"client_id": "a"}) == "client:a"
    assert entry_key({"principal_id": "b"}) == "principal:b"
    assert entry_key({"identity_kind": "SystemAssigned", "source_resource": "v"}) == "SystemAssigned:v"


def test_find(cache_path):
    save_entry(_entry())
    assert find_by_client_id("client-1")["access_token"] == "token-1"
    assert find_by_name("mi-1")["access_token"] == "token-1"
    assert find_by_client_id("nope") is None


def test_remove_entry(cache_path):
    save_entry(_entry())
    assert remove_entry(_entry()) is True
    assert load_tokens() == []
    assert remove_entry(_entry()) is False


def test_is_expired(cache_path):
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    assert is_expired(_entry(expires_on=future)) is False
    assert is_expired(_entry(expires_on=past)) is True
    assert is_expired(_entry(expires_on=None)) is False


def test_build_entry_tokens_map():
    entry = build_entry(
        mi_name="mi-1", identity_kind="UserAssigned", client_id="c1",
        principal_id="p1", source_resource="vm-1", source_type="VirtualMachine",
        subscription_id="s1", resource_group="rg1", tenant_id="t1",
        imds_token={"access_token": "arm-tok", "expires_on": "1750000000"},
        tokens={
            "https://management.azure.com": {"access_token": "arm-tok"},
            "https://storage.azure.com": {"access_token": "storage-tok"},
        },
    )
    assert entry["access_token"] == "arm-tok"
    assert entry["tokens"]["https://storage.azure.com"]["access_token"] == "storage-tok"


def test_get_audience_token_from_map():
    entry = _entry(
        tokens={
            "https://management.azure.com/": {"access_token": "arm-tok"},
            "https://storage.azure.com": {"access_token": "storage-tok"},
        }
    )
    assert get_audience_token(entry, "https://storage.azure.com") == "storage-tok"
    # trailing-slash tolerant both ways
    assert get_audience_token(entry, "https://storage.azure.com/") == "storage-tok"
    assert get_audience_token(entry, "https://vault.azure.net") is None


def test_get_audience_token_falls_back_to_arm():
    entry = _entry(access_token="arm-tok", resource="https://management.azure.com")
    assert get_audience_token(entry, "https://management.azure.com") == "arm-tok"
    assert get_audience_token(entry, "https://management.azure.com/") == "arm-tok"
    assert get_audience_token(entry, "https://storage.azure.com") is None


def test_tokens_map_roundtrip(cache_path):
    entry = _entry(
        tokens={
            "https://management.azure.com": {"access_token": "arm-tok"},
            "https://storage.azure.com": {"access_token": "storage-tok"},
        }
    )
    save_entry(entry)
    loaded = load_tokens()[0]
    assert loaded["tokens"]["https://storage.azure.com"]["access_token"] == "storage-tok"
    assert get_audience_token(loaded, "https://storage.azure.com") == "storage-tok"


def test_tokens_map_absent_for_legacy_entries():
    entry = _entry()
    assert "tokens" not in entry
    assert get_audience_token(entry, "https://management.azure.com") == "token-1"
