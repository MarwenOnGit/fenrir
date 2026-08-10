from fenrir.exploit.capabilities import (
    DATA,
    MANAGEMENT,
    action_granted,
    granted_capability_ids,
    match_action,
    resolve_capabilities,
)


def test_match_action_exact():
    assert match_action(
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )
    assert not match_action(
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
    )


def test_match_action_global_wildcard():
    assert match_action("*", "Microsoft.Storage/storageAccounts/listKeys/action")


def test_match_action_resource_star():
    assert match_action(
        "Microsoft.Storage/storageAccounts/*/read",
        "Microsoft.Storage/storageAccounts/blobServices/read",
    )
    assert match_action(
        "Microsoft.Storage/storageAccounts/*/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    )


def test_match_action_mid_wildcard():
    assert match_action(
        "Microsoft.Storage/*/listKeys/action",
        "Microsoft.Storage/storageAccounts/listKeys/action",
    )


def test_action_granted_buckets():
    merged = {
        "actions": ["Microsoft.Storage/storageAccounts/listKeys/action"],
        "notActions": [],
        "dataActions": [
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
        ],
        "notDataActions": [],
    }
    assert action_granted(merged, MANAGEMENT, "Microsoft.Storage/storageAccounts/listKeys/action")
    assert action_granted(
        merged, DATA, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    )
    # dataActions must not satisfy a management action
    assert not action_granted(
        merged, MANAGEMENT, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    )


def test_action_granted_deny_wins():
    merged = {
        "actions": ["*"],
        "notActions": ["Microsoft.Storage/storageAccounts/listKeys/action"],
        "dataActions": [],
        "notDataActions": [],
    }
    assert not action_granted(merged, MANAGEMENT, "Microsoft.Storage/storageAccounts/listKeys/action")
    assert action_granted(merged, MANAGEMENT, "Microsoft.Compute/virtualMachines/read")


def test_action_granted_wildcard_allows():
    merged = {
        "actions": ["*"],
        "notActions": [],
        "dataActions": ["*"],
        "notDataActions": [],
    }
    assert action_granted(merged, MANAGEMENT, "Microsoft.Storage/storageAccounts/listKeys/action")
    assert action_granted(merged, DATA, "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")


def test_resolve_capabilities_blob_data_owner():
    merged = {
        "actions": [],
        "notActions": [],
        "dataActions": [
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
        ],
        "notDataActions": [],
    }
    resolved = resolve_capabilities("Microsoft.Storage/storageAccounts", merged)
    by_id = {c["capability_id"]: c for c in resolved}
    # listKeys requires a management action the identity does not hold
    assert by_id["storage.list_keys"]["granted"] is False
    assert by_id["storage.read_blobs"]["granted"] is True
    assert by_id["storage.write_blobs"]["granted"] is True
    assert by_id["storage.delete_blobs"]["granted"] is True


def test_resolve_capabilities_requires_all_actions():
    # containers/read granted but blobs/read not -> read_blobs not granted
    merged = {
        "actions": [],
        "notActions": [],
        "dataActions": [
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        ],
        "notDataActions": [],
    }
    resolved = resolve_capabilities("Microsoft.Storage/storageAccounts", merged)
    by_id = {c["capability_id"]: c for c in resolved}
    assert by_id["storage.read_blobs"]["granted"] is False
    assert "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" in \
        by_id["storage.read_blobs"]["missing"]


def test_resolve_capabilities_read_files_requires_data_actions():
    merged = {
        "actions": [],
        "notActions": [],
        "dataActions": [
            "Microsoft.Storage/storageAccounts/fileServices/shares/read",
        ],
        "notDataActions": [],
    }
    resolved = resolve_capabilities("Microsoft.Storage/storageAccounts", merged)
    by_id = {c["capability_id"]: c for c in resolved}
    assert by_id["storage.read_files"]["granted"] is False
    assert any(
        "fileServices/shares/files/read" in m for m in by_id["storage.read_files"]["missing"]
    )

    merged["dataActions"].append(
        "Microsoft.Storage/storageAccounts/fileServices/shares/files/read"
    )
    resolved = resolve_capabilities("Microsoft.Storage/storageAccounts", merged)
    by_id = {c["capability_id"]: c for c in resolved}
    assert by_id["storage.read_files"]["granted"] is True
    # a management-only grant of shares/read must NOT satisfy the data capability
    merged = {
        "actions": ["Microsoft.Storage/storageAccounts/fileServices/shares/read"],
        "notActions": [],
        "dataActions": [],
        "notDataActions": [],
    }
    resolved = resolve_capabilities("Microsoft.Storage/storageAccounts", merged)
    by_id = {c["capability_id"]: c for c in resolved}
    assert by_id["storage.read_files"]["granted"] is False


def test_resolve_capabilities_unknown_resource_empty():
    assert resolve_capabilities("Microsoft.Compute/virtualMachines", {}) == []


def test_granted_capability_ids():
    caps = [
        {"capability_id": "storage.read_blobs", "granted": True},
        {"capability_id": "storage.write_blobs", "granted": False},
        {"capability_id": "storage.list_keys", "granted": True},
    ]
    assert granted_capability_ids(caps) == {"storage.read_blobs", "storage.list_keys"}
    assert granted_capability_ids(None) == set()
